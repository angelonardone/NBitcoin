using System.Security.Cryptography;
using DistricutedCryptographyLib;
using NBitcoin;

// Tests of the blind PIN oracle (RubyPinOracle): offline against a simulated device, and against Ruby.
internal static class OracleTests
{
	private const string Label = "blind_oracle_";

	// What the firmware does (main/process/pinclient.c): a software "Ruby" asking the oracle
	public static byte[] SimRequest(byte[] oraclePub, Key pinKey, uint counter, byte[] pinSecret, bool setPin,
		out Func<byte[], byte[]> decryptReply)
	{
		var cke = new Key();
		var replay = BitConverter.GetBytes(counter); // little-endian
		var ske = RubyPinOracle.SessionPublicKey(oraclePub, cke.PubKey.ToBytes(), replay);
		var entropy = setPin ? RandomNumberGenerator.GetBytes(32) : Array.Empty<byte>();
		var signed = SHA256.HashData(cke.PubKey.ToBytes().Concat(replay).Concat(pinSecret).Concat(entropy).ToArray());
		var compact = pinKey.SignCompact(new uint256(signed));
		var sig = new[] { (byte)(31 + compact.RecoveryId) }.Concat(compact.Signature).ToArray();
		var payload = pinSecret.Concat(entropy).Concat(sig).ToArray();
		var encrypted = RubyEcdhAes.Encrypt(cke, ske, payload, System.Text.Encoding.ASCII.GetBytes(Label + "request"));
		decryptReply = reply => RubyEcdhAes.Decrypt(cke, ske, reply, System.Text.Encoding.ASCII.GetBytes(Label + "response"));
		return cke.PubKey.ToBytes().Concat(replay).Concat(encrypted).ToArray();
	}

	public static Key Tweak(Key key, byte[] merkle) =>
		(Key)typeof(RubyPinOracle).GetMethod("Bip341TweakPrivate",
			System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
			.Invoke(null, new object[] { key, merkle })!;

	public static void Offline(Action<string, bool, string> check)
	{
		Console.WriteLine("== oracle (offline, simulated device)");

		// BIP341 tweak of the private key matches NBitcoin's taproot output key
		for (var i = 0; i < 20; i++)
		{
			var k = new Key();
			var merkle = RandomNumberGenerator.GetBytes(32);
			var full = k.PubKey.TaprootInternalKey.GetTaprootFullPubKey(new uint256(merkle));
			var tweakedPub = Tweak(k, merkle).PubKey;
			var ok = tweakedPub.TaprootInternalKey.ToBytes().SequenceEqual(full.ToBytes())
				&& (tweakedPub.ToBytes()[0] == 0x03) == full.OutputKeyParity;
			if (!ok || i == 19)
			{
				check("bip341 private tweak = public tweak (20 keys)", ok, "");
				break;
			}
		}

		var oracle = RubyPinOracle.Create();
		var pinKey = new Key();
		var secret = RandomNumberGenerator.GetBytes(32);
		uint counter = 0;
		byte[] Ask(RubyPinOracle o, byte[] pinSecret, bool set, uint c)
		{
			var req = SimRequest(o.PublicKey, pinKey, c, pinSecret, set, out var dec);
			return dec(o.Handle(set, req));
		}

		var k1 = Ask(oracle, secret, true, counter);
		check("set_pin", oracle.LastResult == "set_pin" && oracle.RecordCount == 1 && k1.Length == 32, oracle.LastResult);
		check("get_pin right PIN = same key", Ask(oracle, secret, false, ++counter).SequenceEqual(k1) && oracle.LastResult == "get_pin", oracle.LastResult);
		check("replayed counter gets a random key", !Ask(oracle, secret, false, counter).SequenceEqual(k1), oracle.LastResult);

		// The state survives export / import (the wallet saves it after each unlock)
		var reopened = RubyPinOracle.FromState(oracle.ExportState());
		check("state round trip", Ask(reopened, secret, false, ++counter).SequenceEqual(k1)
			&& reopened.PublicKeyHex == oracle.PublicKeyHex, reopened.LastResult);

		var wrong = RandomNumberGenerator.GetBytes(32);
		check("wrong PIN 1", !Ask(reopened, wrong, false, ++counter).SequenceEqual(k1) && reopened.LastResult == "bad_pin 1/3", reopened.LastResult);
		check("right PIN resets the attempts", Ask(reopened, secret, false, ++counter).SequenceEqual(k1), reopened.LastResult);
		Ask(reopened, wrong, false, ++counter);
		Ask(reopened, wrong, false, ++counter);
		check("wrong PIN 2", reopened.LastResult == "bad_pin 2/3", reopened.LastResult);
		Ask(reopened, wrong, false, ++counter);
		check("third wrong PIN erases the record", reopened.LastResult == "erased" && reopened.RecordCount == 0, reopened.LastResult);
		check("after erase the right PIN no longer works", !Ask(reopened, secret, false, ++counter).SequenceEqual(k1), reopened.LastResult);

		// Another oracle can not even read the request
		try
		{
			var req = SimRequest(oracle.PublicKey, pinKey, ++counter, secret, false, out _);
			RubyPinOracle.Create().Handle(false, req);
			check("other oracle rejects the request", false, "no exception");
		}
		catch (CryptographicException e)
		{
			check("other oracle rejects the request", true, e.Message);
		}

		// A changed record is detected
		var state = oracle.ExportState();
		using var doc = System.Text.Json.JsonDocument.Parse(state);
		var recordHex = doc.RootElement.GetProperty("Records").EnumerateObject().First().Value.GetString()!;
		var flipped = recordHex[..100] + (recordHex[100] == '0' ? '1' : '0') + recordHex[101..];
		var tampered = RubyPinOracle.FromState(state.Replace(recordHex, flipped));
		check("altered record gives a random key", !Ask(tampered, secret, false, ++counter).SequenceEqual(k1), tampered.LastResult);
	}

	public static void Device(RubyClient ruby, string mnemonic, Action<string, bool, string> check)
	{
		Console.WriteLine("== oracle (device)");
		const int Pin = 234567;
		string State() => ruby.GetVersionInfo()["JADE_STATE"] as string ?? "";

		var oracle = RubyPinOracle.Create();
		check("debug_clean_reset", ruby.DebugCleanReset(), "");
		ruby.DebugSetPin(Pin);
		// A remote oracle (a URL) is refused unless the user chose it on Ruby (Options > Blind Oracle)
		try
		{
			ruby.UpdatePinServer("http://remote-oracle.example", RubyPinOracle.Create().PublicKey);
			check("remote oracle refused unless chosen on Ruby", false, "");
		}
		catch (RubyException e)
		{
			check("remote oracle refused unless chosen on Ruby", e.Message.Contains("Remote Oracle"), e.Message);
		}
		check("pairing with the wallet oracle (update_pinserver with only the key)", ruby.PairWalletOracle(oracle.PublicKey), "");
		check("pairing again with the same key is accepted", ruby.PairWalletOracle(oracle.PublicKey), "");
		ruby.DebugSetMnemonic(mnemonic);
		string? oracleUrl = null;
		ruby.PinOracle = p =>
		{
			oracleUrl = p.TryGetValue("urls", out var u) && u is System.Collections.Generic.List<object?> l && l.Count == 1 ? l[0] as string : "?";
			return oracle.HandleRequest(p);
		};
		check("first auth_user sets the PIN through the oracle",
			ruby.AuthUser(Network.TestNet) && oracle.LastResult == "set_pin" && oracle.RecordCount == 1, oracle.LastResult);
		check("state READY", State() == "READY", State());
		check("Ruby asks the wallet oracle (one url, no server)", oracleUrl == RubyClient.WalletOracleUrl + "/set_pin", oracleUrl ?? "");

		ruby.Logout();
		check("logout locks", State() == "LOCKED", State());
		check("unlock with the PIN (get_pin)", ruby.AuthUser(Network.TestNet) && oracle.LastResult == "get_pin", oracle.LastResult);
		var master = new Mnemonic(mnemonic).DeriveExtKey();
		check("the persisted wallet is the mnemonic",
			ruby.GetMasterFingerprint(Network.TestNet) == master.GetPublicKey().GetHDFingerPrint(), "");
		check("utility keys after PIN unlock",
			ruby.GetUtilityKeys(Network.TestNet).SameAs(RubyUtilityKeys.FromMnemonic(mnemonic, Network.TestNet)), "");

		// The wallet is closed and opened again: the oracle comes back from its saved state
		oracle = RubyPinOracle.FromState(oracle.ExportState());
		ruby.PinOracle = oracle.HandleRequest;
		ruby.Logout();
		check("unlock with the oracle restored from its state", ruby.AuthUser(Network.TestNet), oracle.LastResult);

		// The key of the oracle can not be changed on a unit with a PIN
		try
		{
			ruby.PairWalletOracle(RubyPinOracle.Create().PublicKey);
			check("oracle key locked once there is a PIN", false, "");
		}
		catch (RubyException e)
		{
			check("oracle key locked once there is a PIN", e.Message.Contains("initialized"), e.Message);
		}

		// No oracle / another oracle: a clear error, and Ruby is still usable afterwards
		ruby.Logout();
		ruby.PinOracle = null;
		try
		{
			ruby.AuthUser(Network.TestNet);
			check("no oracle: error", false, "");
		}
		catch (RubyException e)
		{
			check("no oracle: error", e.Message.Contains("oracle", StringComparison.OrdinalIgnoreCase), e.Message);
		}
		ruby.PinOracle = RubyPinOracle.Create().HandleRequest;
		try
		{
			ruby.AuthUser(Network.TestNet);
			check("another oracle: error", false, "");
		}
		catch (RubyException e)
		{
			check("another oracle: error", true, e.Message);
		}
		ruby.PinOracle = oracle.HandleRequest;
		check("right oracle works again", ruby.AuthUser(Network.TestNet), oracle.LastResult);

		// Wrong PIN: locked, the oracle counts it; the right PIN resets the count
		ruby.Logout();
		ruby.DebugSetPin(999999);
		check("wrong PIN refused", !ruby.AuthUser(Network.TestNet) && oracle.LastResult == "bad_pin 1/3", oracle.LastResult);
		check("still LOCKED", State() == "LOCKED", State());
		ruby.DebugSetPin(Pin);
		check("right PIN after a wrong one", ruby.AuthUser(Network.TestNet) && oracle.LastResult == "get_pin", oracle.LastResult);

		// Three wrong PINs: Ruby erases its wallet and the oracle its record
		ruby.Logout();
		ruby.DebugSetPin(999999);
		for (var i = 1; i <= 3; i++)
			check($"wrong PIN {i}/3", !ruby.AuthUser(Network.TestNet), $"{oracle.LastResult} state {State()}");
		check("three wrong PINs: oracle record erased", oracle.RecordCount == 0 && oracle.LastResult == "erased", oracle.LastResult);
		check("three wrong PINs: Ruby wallet erased", State() == "UNINIT", State());

		ruby.PinOracle = null;
		ruby.DebugCleanReset();
	}
}
