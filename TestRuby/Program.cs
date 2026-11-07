// Tests of the Ruby client of DistricutedCryptographyLib.
//
//   dotnet run -- offline                 CBOR, ECDH-AES and the software utility keys (no device)
//   dotnet run -- tcp:127.0.0.1:30131     + the emulator (DEBUG + CI firmware: auto-confirms the screens)
//   dotnet run -- COM5                    + a real Ruby with a DEBUG firmware (confirm on the device)
//
// The device tests load a test mnemonic with debug_set_mnemonic: never run them on a Ruby holding real funds.

using System.Security.Cryptography;
using DistricutedCryptographyLib;
using NBitcoin;

const string TestMnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";

var failures = 0;
void Check(string name, bool ok, string detail = "")
{
	Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}{(detail.Length > 0 ? "  " + detail : "")}");
	if (!ok)
		failures++;
}

void Throws<T>(string name, Action action) where T : Exception
{
	try
	{
		action();
		Check(name, false, "no exception");
	}
	catch (T e)
	{
		Check(name, true, e.Message);
	}
	catch (Exception e)
	{
		Check(name, false, $"{e.GetType().Name}: {e.Message}");
	}
}

OfflineTests();
OracleOfflineTests();
var device = args.Length > 0 ? args[0] : "offline";
if (device != "offline")
{
	DeviceTests(device);
	KbFlowTests.Run(device, TestMnemonic, Check); // after DeviceTests closed its connection
}

Console.WriteLine(failures == 0 ? "ALL PASS" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;

void OfflineTests()
{
	Console.WriteLine("== offline");

	// CBOR round trip of a request-like message
	var msg = new Dictionary<string, object?>
	{
		["id"] = "123456",
		["method"] = "get_xpub",
		["params"] = new Dictionary<string, object?>
		{
			["network"] = "localtest",
			["path"] = new List<object?> { 0x80000000UL + 86, 0x80000001UL, 0x80000000UL },
			["bytes"] = new byte[300],
			["neg"] = -1000000L,
			["flag"] = true,
			["none"] = null
		}
	};
	var encoded = RubyCbor.Encode(msg);
	var decoded = RubyCbor.Decode(encoded) as IDictionary<string, object?>;
	var p = decoded?["params"] as IDictionary<string, object?>;
	Check("cbor round trip",
		decoded?["id"] as string == "123456" && p?["network"] as string == "localtest"
		&& (p?["path"] as List<object?>)?[0] is long l0 && l0 == 0x80000056
		&& (p?["bytes"] as byte[])?.Length == 300 && p?["neg"] is long n && n == -1000000
		&& p?["flag"] is true && p.ContainsKey("none") && p["none"] == null);
	Check("cbor incomplete data waits for more",
		!RubyCbor.TryDecode(encoded, 0, encoded.Length - 1, out _, out var next) && next == 0);
	// known vector (RFC 8949 appendix A): {"a": 1, "b": [2, 3]}
	Check("cbor RFC 8949 vector",
		Convert.ToHexString(RubyCbor.Encode(new Dictionary<string, object?> { ["a"] = 1, ["b"] = new List<object?> { 2, 3 } }))
		== "A26161016162820203");

	// ECDH-AES as libwally: both sides get the same keys, a wrong key or a changed byte is rejected
	var hostKey = new Key();
	var deviceKey = new Key();
	var label = "ruby_utility_keys"u8.ToArray();
	var secret = RandomNumberGenerator.GetBytes(468);
	var payload = RubyEcdhAes.Encrypt(deviceKey, hostKey.PubKey, secret, label);
	Check("ecdh-aes length", payload.Length == 16 + 480 + 32, payload.Length.ToString());
	Check("ecdh-aes round trip", RubyEcdhAes.Decrypt(hostKey, deviceKey.PubKey, payload, label).SequenceEqual(secret));
	Throws<CryptographicException>("ecdh-aes wrong key", () => RubyEcdhAes.Decrypt(new Key(), deviceKey.PubKey, payload, label));
	var altered = (byte[])payload.Clone();
	altered[40] ^= 1;
	Throws<CryptographicException>("ecdh-aes altered", () => RubyEcdhAes.Decrypt(hostKey, deviceKey.PubKey, altered, label));
	Throws<CryptographicException>("ecdh-aes wrong label",
		() => RubyEcdhAes.Decrypt(hostKey, deviceKey.PubKey, payload, "other"u8.ToArray()));

	// Software utility keys = the paths of the wallet (BIP86 account + hardened children), no passphrase
	foreach (var net in new[] { Network.Main, Network.TestNet, Network.RegTest })
	{
		var keys = RubyUtilityKeys.FromMnemonic(TestMnemonic, net);
		var account = new Mnemonic(TestMnemonic).DeriveExtKey()
			.Derive(new KeyPath(net == Network.Main ? "86'/0'/0'" : "86'/1'/0'"));
		Check($"software utility keys {net}",
			keys.Login == account.Derive(new KeyPath("1000'/0'")).GetWif(net).ToString()
			&& keys.Hsm == account.Derive(new KeyPath("6000'")).GetWif(net).ToString()
			&& keys.ExtendedPrivateKeys.Count == 6
			&& keys.ExtendedPrivateKeys.Distinct().Count() == 6);
	}
}

void DeviceTests(string dev)
{
	Console.WriteLine($"== device {dev}");
	using var ruby = RubyClient.Connect(dev);

	var info = ruby.GetVersionInfo();
	Check("get_version_info", info.ContainsKey("JADE_VERSION"),
		$"{info["JADE_VERSION"]} {info["JADE_STATE"]} {info["JADE_NETWORKS"]}");

	// The debug mnemonic unlocks Ruby without the PIN (the PIN + local oracle flow is tested with the oracle)
	foreach (var net in new[] { Network.Main, Network.TestNet, Network.RegTest })
	{
		Check($"debug_set_mnemonic ({net})", ruby.DebugSetMnemonic(TestMnemonic));

		var expected = RubyUtilityKeys.FromMnemonic(TestMnemonic, net);
		var fromRuby = ruby.GetUtilityKeys(net);
		Check($"utility keys from Ruby = from the words ({net})", fromRuby.SameAs(expected),
			fromRuby.Login[..12] + "...");

		var master = new Mnemonic(TestMnemonic).DeriveExtKey();
		Check($"master fingerprint ({net})",
			ruby.GetMasterFingerprint(net) == master.GetPublicKey().GetHDFingerPrint());
		Check($"account xpub ({net})",
			ruby.GetAccountXpub(net).ToString(net)
			== master.Derive(RubyUtilityKeys.AccountPath(net)).Neuter().ToString(net));
	}

	// A different mnemonic gives different keys (the keys really come from the device seed)
	ruby.DebugSetMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
	Check("other mnemonic, other keys",
		!ruby.GetUtilityKeys(Network.RegTest).SameAs(RubyUtilityKeys.FromMnemonic(TestMnemonic, Network.RegTest)));

	SignPsbtTest(ruby);

	// Errors come back as RubyException with the firmware code (while unlocked: a locked unit answers HW_LOCKED)
	try
	{
		ruby.Call("no_such_method");
		Check("unknown method error", false);
	}
	catch (RubyException e)
	{
		Check("unknown method error", e.Code == RubyException.UnknownMethod, $"{e.Code} {e.Message}");
	}

	// Last: it wipes the unit (three wrong PINs)
	OracleDeviceTests(ruby);
}

void SignPsbtTest(RubyClient ruby)
{
	var net = Network.RegTest;
	ruby.DebugSetMnemonic(TestMnemonic);
	var fingerprint = ruby.GetMasterFingerprint(net);
	var accountPath = RubyUtilityKeys.AccountPath(net);
	var accountXpub = ruby.GetAccountXpub(net); // watch-only: what a Ruby wallet keeps

	// Two coins of the wallet (receive 0 and 3) in a fake funding transaction
	BitcoinAddress Addr(uint chain, uint index) =>
		accountXpub.Derive(chain).Derive(index).PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, net);
	var funding = net.CreateTransaction();
	funding.Inputs.Add(new OutPoint(RandomUtils.GetUInt256(), 0));
	funding.Outputs.Add(Money.Coins(0.5m), Addr(0, 0));
	funding.Outputs.Add(Money.Coins(0.3m), Addr(0, 3));
	var coins = funding.Outputs.AsCoins().ToArray();

	// Pay 0.6 to somebody else, change to change/2
	var destination = new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, net);
	var builder = net.CreateTransactionBuilder();
	builder.AddCoins(coins)
		.Send(destination, Money.Coins(0.6m))
		.SetChange(Addr(1, 2))
		.SendFees(Money.Satoshis(3000));
	var psbt = builder.BuildPSBT(false);
	var marked = RubyPsbt.AddBip86AccountKeyPaths(psbt, accountXpub, fingerprint, accountPath, 20);
	Check("psbt key paths added", marked == 3, $"{marked} (2 inputs + change)");

	var signed = ruby.SignPsbt(psbt);
	Check("ruby signed every input", signed.Inputs.All(i => i.TaprootKeySignature != null));
	Check("psbt finalizes", signed.TryFinalize(out var errors), errors == null ? "" : string.Join("; ", errors));
	var tx = signed.ExtractTransaction();
	Check("signatures valid (TransactionBuilder.Verify)", builder.Verify(tx, out var policyErrors),
		policyErrors.Length == 0 ? "" : string.Join("; ", policyErrors.Select(e => e.ToString())));
	Check("same transaction as built", tx.GetHash() == psbt.GetGlobalTransaction().GetHash());

	// A PSBT of another wallet (other fingerprint) gets no signature from Ruby
	var other = builder.BuildPSBT(false);
	RubyPsbt.AddBip86AccountKeyPaths(other, accountXpub, new HDFingerprint(0x01020304), accountPath, 20);
	try
	{
		var notSigned = ruby.SignPsbt(other);
		Check("other wallet's psbt not signed", notSigned.Inputs.All(i => i.TaprootKeySignature == null));
	}
	catch (RubyException e)
	{
		Check("other wallet's psbt not signed", true, $"rejected: {e.Message}");
	}
}

void OracleOfflineTests() => OracleTests.Offline(Check);

void OracleDeviceTests(RubyClient ruby) => OracleTests.Device(ruby, TestMnemonic, Check);
