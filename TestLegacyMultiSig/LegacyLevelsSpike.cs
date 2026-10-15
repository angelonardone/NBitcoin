using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using NBitcoin;
using NBitcoin.RPC;
using NBitcoin.Tests;
using DistricutedCryptographyLib;

// "Legacy Multisignature" payments with pre-signed fee levels, driven through GroupProcessor exactly the way
// GeneXus uses it (FromSDT -> *LegacySpend methods, JSON results). The crypto itself is NBitcoin.SegWitMultiSigSpend,
// tested in NBitcoin.Tests (SegWitMultiSigSpendTests); this checks the library wrapper over a GroupSDT.
//
//   dotnet run -- legacy-levels          offline checks
//   dotnet run -- legacy-levels-node     broadcast + confirm on an isolated regtest node (NodeBuilder)
static class LegacyLevelsSpike
{
	static readonly Network Net = Network.RegTest;
	static int _failures;

	// A participant: the m/48' account of its wallet and the two chains it gives to the group
	// (KeyPaths.Receiving = 0, KeyPaths.Change = 1 under m/48'/coin'/0'/1').
	sealed class Participant
	{
		public string Name = "";
		public ExtKey Account = new ExtKey().Derive(new KeyPath("48'/1'/0'/1'"));
		public string ReceivingXprv => Account.Derive(0).ToString(Net);
		public string ChangeXprv => Account.Derive(1).ToString(Net);
		public string ReceivingXpub => Account.Neuter().Derive(0).ToString(Net);
		public string ChangeXpub => Account.Neuter().Derive(1).ToString(Net);
	}

	// the owner is a participant (group-level keys), the others are contacts
	static (GroupProcessor gp, List<Participant> all) MakeGroup(int k, int n)
	{
		var all = Enumerable.Range(0, n).Select(i => new Participant { Name = i == 0 ? "owner" : "member" + i }).ToList();
		var g = new GroupSDT { GroupId = Guid.NewGuid(), GroupType = 20, GroupName = $"Legacy {k}of{n}", MinimumShares = (short)k,
			AmIGroupOwner = true, IsActive = true, ExtPubKeyMultiSigReceiving = all[0].ReceivingXpub, ExtPubKeyMultiSigChange = all[0].ChangeXpub };
		foreach (var m in all.Skip(1))
			g.Contact.Add(new ContactItem { ContactUserName = m.Name, ExtPubKeyMultiSigReceiving = m.ReceivingXpub, ExtPubKeyMultiSigChange = m.ChangeXpub });
		var gp = new GroupProcessor();
		if (!gp.FromSDT(g)) throw new Exception("FromSDT failed");
		return (gp, all);
	}

	static void Check(string name, bool ok, string detail = "")
	{
		Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}{(detail.Length > 0 ? "  -- " + detail : "")}");
		if (!ok) _failures++;
	}
	static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;
	static bool Ok(string json) => J(json).GetProperty("success").GetBoolean();
	static string ErrOf(string json) => J(json).GetProperty("error").GetString() ?? "";
	static string Str(string json, string p) => J(json).GetProperty(p).GetString() ?? "";
	static void Refused(string name, string json, string contains) =>
		Check(name, !Ok(json) && ErrOf(json).Contains(contains, StringComparison.OrdinalIgnoreCase), Ok(json) ? "UNEXPECTED success" : ErrOf(json));

	static string Address(GroupProcessor gp, int seq, bool isChange) => Str(gp.CreateLegacyAddress(seq, isChange, "RegTest"), "address");

	static string UtxosJson(GroupProcessor gp, IEnumerable<(uint256 txid, int vout, decimal btc, int seq, bool isChange)> coins) =>
		JsonSerializer.Serialize(coins.Select(c => new { TxId = c.txid.ToString(), Vout = c.vout, AmountBtc = c.btc.ToString(System.Globalization.CultureInfo.InvariantCulture),
			Sequence = c.seq, IsChange = c.isChange, Address = Address(gp, c.seq, c.isChange) }));

	static List<(uint256, int, decimal, int, bool)> FakeCoins() => new List<(uint256, int, decimal, int, bool)>
	{
		(new uint256(RandomUtils.GetBytes(32)), 0, 0.5m, 0, false),
		(new uint256(RandomUtils.GetBytes(32)), 1, 0.3m, 3, false),
		(new uint256(RandomUtils.GetBytes(32)), 0, 0.2m, 1, true),
	};

	// k participants sign one after the other; the last one chooses `chosen`. Returns the last result.
	static string SignInTurn(GroupProcessor gp, List<Participant> signers, string bundle, int chosen, bool checkDescribe)
	{
		string result = "";
		for (int s = 0; s < signers.Count; s++)
		{
			var last = s == signers.Count - 1;
			if (checkDescribe)
			{
				var d = gp.DescribeLegacySpend(bundle, signers[s].ReceivingXpub, signers[s].ChangeXpub, "RegTest");
				Check($"  describe before signature {s + 1}: {s} signed, next is last = {last}",
					Ok(d) && J(d).GetProperty("signatures").GetInt32() == s && J(d).GetProperty("nextIsLast").GetBoolean() == last
					&& !J(d).GetProperty("iSigned").GetBoolean(), Ok(d) ? "" : ErrOf(d));
			}
			result = gp.SignLegacySpend(bundle, signers[s].ReceivingXprv, signers[s].ChangeXprv, last ? chosen : -1, "RegTest");
			if (!Ok(result)) return result;
			bundle = Str(result, "bundle");
		}
		return result;
	}

	public static int Run(string[] args)
	{
		if (args[0] == "legacy-levels-node")
			return Node();

		// 1. the addresses of the fee-level code are the addresses the app already has (CreateLegacyAddress)
		{
			var (gp, _) = MakeGroup(2, 3);
			var utxos = UtxosJson(gp, Enumerable.Range(0, 6).Select(i => (new uint256(RandomUtils.GetBytes(32)), 0, 0.1m, i, i % 2 == 1)));
			var r = gp.BuildLegacySpend(utxos, Address(gp, 9, false), "0.2", Address(gp, 7, true), "0.0001", "", false, "RegTest");
			Check("the fee-level code derives the same addresses as CreateLegacyAddress (6 addresses, both chains)", Ok(r), Ok(r) ? "" : ErrOf(r));
		}

		// 2. many combinations, coins of three addresses, signers in turn, the last one chooses
		foreach (var (k, n, chosen) in new[] { (1, 2, 0), (2, 3, 50), (3, 4, 10), (5, 10, 100), (16, 16, 50) })
		{
			var (gp, all) = MakeGroup(k, n);
			var build = gp.BuildLegacySpend(UtxosJson(gp, FakeCoins()), Address(gp, 9, false), "0.7", Address(gp, 2, true), "0.0002", "10,50,100", false, "RegTest");
			Check($"{k}-of-{n}: build 4 levels", Ok(build) && J(build).GetProperty("levels").GetArrayLength() == 4, Ok(build) ? "" : ErrOf(build));
			if (!Ok(build)) continue;
			var signers = all.OrderBy(_ => RandomUtils.GetInt32()).Take(k).ToList();
			var r = SignInTurn(gp, signers, Str(build, "bundle"), chosen, k <= 5);
			var fee = Ok(r) ? J(r).GetProperty("feeBtc").GetDecimal() : -1m;
			Check($"{k}-of-{n}: signed in turn, +{chosen} % chosen, transaction finalized", Ok(r) && J(r).GetProperty("complete").GetBoolean()
				&& Str(r, "txHex").Length > 0 && fee == 0.0002m * (100 + chosen) / 100, Ok(r) ? $"fee {fee}" : ErrOf(r));
		}

		// 3. refusals
		{
			var (gp, all) = MakeGroup(2, 3);
			var bundle = Str(gp.BuildLegacySpend(UtxosJson(gp, FakeCoins()), Address(gp, 9, false), "0.7", Address(gp, 2, true), "0.0002", "10", false, "RegTest"), "bundle");
			var stranger = new Participant();
			Refused("a stranger can not sign", gp.SignLegacySpend(bundle, stranger.ReceivingXprv, stranger.ChangeXprv, -1, "RegTest"), "does not belong");
			Refused("the first signer of a 2-of-3 can not choose the fee", gp.SignLegacySpend(bundle, all[0].ReceivingXprv, all[0].ChangeXprv, 10, "RegTest"), "last signer");
			var once = gp.SignLegacySpend(bundle, all[0].ReceivingXprv, all[0].ChangeXprv, -1, "RegTest");
			Refused("the same member can not sign twice", gp.SignLegacySpend(Str(once, "bundle"), all[0].ReceivingXprv, all[0].ChangeXprv, -1, "RegTest"), "already signed");
			Refused("an option the payment does not have", gp.SignLegacySpend(Str(once, "bundle"), all[1].ReceivingXprv, all[1].ChangeXprv, 50, "RegTest"), "no +50");
			var d = gp.DescribeLegacySpend(Str(once, "bundle"), all[0].ReceivingXpub, all[0].ChangeXpub, "RegTest");
			Check("describe: who signed (owner) and that I signed", Ok(d) && J(d).GetProperty("iSigned").GetBoolean()
				&& J(d).GetProperty("signedBy").EnumerateArray().Select(x => x.GetString()).SequenceEqual(new[] { "" }), d);
			var (other, _) = MakeGroup(2, 3);
			Refused("a payment of another group", other.DescribeLegacySpend(bundle, "", "", "RegTest"), "not a coin of this group");
			var wrongAddress = JsonSerializer.Serialize(new[] { new { TxId = uint256.One.ToString(), Vout = 0, AmountBtc = "1", Sequence = 0, IsChange = false, Address = Address(gp, 1, false) } });
			Refused("a UTXO whose address is not the derived one", gp.BuildLegacySpend(wrongAddress, Address(gp, 9, false), "0.5", Address(gp, 2, true), "0.0001", "", false, "RegTest"), "don't match");
		}

		Console.WriteLine(_failures == 0 ? "\nALL PASS" : $"\n{_failures} FAILURE(S)");
		return _failures == 0 ? 0 : 1;
	}

	// broadcast + confirm through the wrapper on a regtest node started from scratch
	static int Node()
	{
		using var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest);
		var rpc = nodeBuilder.CreateNode().CreateRPCClient();
		nodeBuilder.StartAll();
		rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);
		foreach (var (k, n, chosen) in new[] { (2, 3, 50), (3, 5, 0), (7, 10, 100) })
		{
			var (gp, all) = MakeGroup(k, n);
			var coins = new List<(uint256, int, decimal, int, bool)>();
			foreach (var (seq, isChange, btc) in new[] { (0, false, 0.5m), (3, false, 0.3m), (1, true, 0.2m) })
			{
				var address = BitcoinAddress.Create(Address(gp, seq, isChange), Net);
				var txid = rpc.SendToAddress(address, Money.Coins(btc));
				var vout = rpc.GetRawTransaction(txid).Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				coins.Add((txid, (int)vout.N, btc, seq, isChange));
			}
			rpc.Generate(1);
			var dest = rpc.GetNewAddress();
			var build = gp.BuildLegacySpend(UtxosJson(gp, coins), dest.ToString(), "0.7", Address(gp, 2, true), "0.0002", "10,50,100", false, "RegTest");
			var r = SignInTurn(gp, all.OrderBy(_ => RandomUtils.GetInt32()).Take(k).ToList(), Str(build, "bundle"), chosen, false);
			if (!Ok(r)) { Check($"{k}-of-{n} on the node", false, ErrOf(r)); continue; }
			var tx = Transaction.Parse(Str(r, "txHex"), Net);
			rpc.SendRawTransaction(tx);
			var fee = rpc.GetMempoolEntry(tx.GetHash()).BaseFee;
			rpc.Generate(1);
			Check($"{k}-of-{n} on the node: +{chosen} % chosen, fee {fee.Satoshi} sats, confirmed",
				fee == Money.Coins(0.0002m * (100 + chosen) / 100) && rpc.GetReceivedByAddress(dest, 1) == Money.Coins(0.7m));
		}
		Console.WriteLine(_failures == 0 ? "\nALL PASS" : $"\n{_failures} FAILURE(S)");
		return _failures == 0 ? 0 : 1;
	}
}
