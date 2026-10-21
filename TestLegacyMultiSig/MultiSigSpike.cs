using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.Tests;
using DistricutedCryptographyLib;

// Checks of the "Multi Signature" groups (GroupType 60, NBitcoin.TaprootMultiSig): Taproot, NO owner. The owner of
// the group is one more signer, the internal key is the BIP327 aggregate of all the signers. Driven through
// DelegatedProcessor exactly the way GeneXus uses it (FromSDT -> methods, JSON results).
//
//   dotnet run -- multisig          the offline checks
//   dotnet run -- multisig-node     broadcast + confirm on an isolated regtest node
static class MultiSigSpike
{
	static readonly Network Net = Network.RegTest;
	static int _failures;

	sealed class Participant
	{
		public string Name = "";
		public ExtKey Account = null!;
		public string ReceivingXprv => Account.Derive(2).ToString(Net);
		public string ChangeXprv => Account.Derive(3).ToString(Net);
		public string ReceivingXpub => Account.Neuter().Derive(2).ToString(Net);
		public string ChangeXpub => Account.Neuter().Derive(3).ToString(Net);
	}

	static Participant Make(string name) => new Participant
	{
		Name = name,
		Account = ExtKey.CreateFromSeed(Hashes.SHA256(Encoding.UTF8.GetBytes("multisig-spike-" + name))).Derive(new KeyPath("86'/1'/0'"))
	};

	// k-of-n where n = the owner + the members (the contacts)
	static (DelegatedProcessor gp, GroupSDT group, Participant owner, List<Participant> members) MakeGroup(int k, int members, short groupType = 60)
	{
		var owner = Make("owner");
		var list = Enumerable.Range(1, members).Select(i => Make("member" + i)).ToList();
		var g = new GroupSDT
		{
			GroupType = groupType,
			AmIGroupOwner = true,
			MinimumShares = (short)k,
			ExtPubKeyMultiSigReceiving = owner.ReceivingXpub,
			ExtPubKeyMultiSigChange = owner.ChangeXpub
		};
		foreach (var m in list)
			g.Contact.Add(new ContactItem { ContactUserName = m.Name, ExtPubKeyMultiSigReceiving = m.ReceivingXpub, ExtPubKeyMultiSigChange = m.ChangeXpub });
		var gp = new DelegatedProcessor();
		gp.FromSDT(g);
		return (gp, g, owner, list);
	}

	static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;
	static bool Ok(JsonElement e) => e.GetProperty("success").GetBoolean();
	static string ErrOf(JsonElement e) => e.GetProperty("error").GetString() ?? "";
	static string S(JsonElement e, string name) => e.GetProperty(name).GetString() ?? "";

	static void Check(string name, bool ok, string detail = "")
	{
		if (!ok) _failures++;
		Console.WriteLine($"  [{(ok ? "ok" : "FAIL")}] {name}{(detail.Length > 0 ? "  -> " + detail : "")}");
	}

	static void ExpectError(string name, string json, string contains)
	{
		var e = J(json);
		Check(name, !Ok(e) && ErrOf(e).Contains(contains, StringComparison.OrdinalIgnoreCase), Ok(e) ? "UNEXPECTED success" : ErrOf(e));
	}

	static string Utxos(DelegatedProcessor gp, params (int seq, bool chg, string amount, int n)[] coins)
	{
		var list = new List<object>();
		foreach (var c in coins)
		{
			var address = S(J(gp.CreateAddress(c.seq, c.chg, "regtest")), "address");
			list.Add(new { TxId = new uint256(Hashes.SHA256(Encoding.UTF8.GetBytes($"coin{c.n}"))).ToString(), Vout = c.n, AmountBtc = c.amount, Sequence = c.seq, IsChange = c.chg, Address = address });
		}
		return JsonSerializer.Serialize(list);
	}

	static long FeeSats(JsonElement levels, int percent)
	{
		foreach (var l in levels.EnumerateArray())
			if (l.GetProperty("percent").GetInt32() == percent)
				return (long)(l.GetProperty("feeBtc").GetDecimal() * 100_000_000m);
		return -1;
	}

	static List<ExtPubKey> Xpubs(Participant owner, List<Participant> members, bool change) =>
		members.Select(m => change ? m.ChangeXpub : m.ReceivingXpub).Prepend(change ? owner.ChangeXpub : owner.ReceivingXpub)
			.Select(x => ExtPubKey.Parse(x, Net)).ToList();

	public static int Run(string[] args)
	{
		if (args[0] == "multisig-node")
			return NodeRun();

		Addresses();
		OwnerSignsLikeAMember();
		MemberFirstOwnerLast();
		Thresholds();
		Console.WriteLine(_failures == 0 ? "\nALL CHECKS PASSED" : $"\n{_failures} CHECK(S) FAILED");
		return _failures == 0 ? 0 : 1;
	}

	static void Addresses()
	{
		Console.WriteLine("\n== A) addresses and descriptors of a 2-of-3 Multi Signature group (owner + 2 members) ==");
		var (gp, _, owner, m) = MakeGroup(2, 2);
		var (delegated, _, _, _) = MakeGroup(2, 2, groupType: 30);
		var a0 = J(gp.CreateAddress(0, false, "regtest"));
		Check("n = 3 signers (the owner counts), k = 2", Ok(a0) && a0.GetProperty("n").GetInt32() == 3 && a0.GetProperty("k").GetInt32() == 2 && a0.GetProperty("scripts").GetInt32() == 3, a0.ToString());
		for (int seq = 0; seq < 3; seq++)
		{
			foreach (var change in new[] { false, true })
			{
				var ours = S(J(gp.CreateAddress(seq, change, "regtest")), "address");
				var lib = TaprootMultiSig.FromExtPubKeys(Xpubs(owner, m, change), 2, (uint)seq, Net).Address.ToString();
				Check($"{(change ? "change" : "receiving")} {seq}: the address of TaprootMultiSig of the 3 keys", ours == lib);
			}
		}
		Check("not the Delegated address of the same keys", S(a0, "address") != S(J(delegated.CreateAddress(0, false, "regtest")), "address"));
		var descriptor = S(J(gp.GetDescriptor(false, "regtest")), "descriptor");
		Check("descriptor: tr(musig(3 xpubs), 3 sortedmulti_a leaves)", descriptor.StartsWith("tr(musig(") && descriptor.Split("sortedmulti_a(2,").Length - 1 == 3, descriptor.Length + " chars");
		var est = J(gp.EstimateVsize(Utxos(gp, (0, false, "1.0", 0)), new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString(), "", false, false, "regtest")).GetProperty("vsize").GetInt32();
		var estAsOwner = J(gp.EstimateVsize(Utxos(gp, (0, false, "1.0", 0)), new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString(), "", false, true, "regtest")).GetProperty("vsize").GetInt32();
		Check($"no key path: the estimate is the script path also \"as owner\" ({est} = {estAsOwner})", est == estAsOwner && est > 150);
	}

	// the owner signs FIRST (he may offer the fee options), a member is the last signer and chooses +50 %
	static void OwnerSignsLikeAMember()
	{
		Console.WriteLine("\n== B) 2-of-3: the owner signs first like any member, a member is the last signer ==");
		var (gp, _, owner, m) = MakeGroup(2, 2);
		var utxos = Utxos(gp, (0, false, "1.0", 0), (1, true, "0.5", 1));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		var changeTo = S(J(gp.CreateAddress(2, true, "regtest")), "address");

		ExpectError("the owner cannot spend alone", gp.OwnerSpend(utxos, sendTo, "0.5", changeTo, "0.00002", false, owner.ReceivingXprv, owner.ChangeXprv, "regtest"), "no owner");

		var build = J(gp.BuildSpend(utxos, sendTo, "1.2", changeTo, "0.00002", "10,50,100", false, "regtest"));
		if (!Ok(build)) { Check("build", false, ErrOf(build)); return; }
		var levels = build.GetProperty("levels");
		Check("4 levels, fees 2000 / 2200 / 3000 / 4000 sats", FeeSats(levels, 0) == 2000 && FeeSats(levels, 10) == 2200 && FeeSats(levels, 50) == 3000 && FeeSats(levels, 100) == 4000);

		var s1 = J(gp.SignSpend(S(build, "bundle"), owner.ReceivingXprv, owner.ChangeXprv, -1, "regtest"));
		if (!Ok(s1)) { Check("the owner signs every level", false, ErrOf(s1)); return; }
		Check("the owner signs every level: 1 of 2", s1.GetProperty("signatures").GetInt32() == 1 && !s1.GetProperty("complete").GetBoolean());
		var d1 = J(gp.DescribeSpend(S(s1, "bundle"), owner.ReceivingXpub, owner.ChangeXpub, "regtest"));
		Check("signed by \"owner\", iSigned for the owner, next is the last", d1.GetProperty("signedBy").EnumerateArray().Select(x => x.GetString()).SequenceEqual(new[] { "owner" }) && d1.GetProperty("iSigned").GetBoolean() && d1.GetProperty("nextIsLast").GetBoolean());
		ExpectError("the owner cannot sign twice", gp.SignSpend(S(s1, "bundle"), owner.ReceivingXprv, owner.ChangeXprv, -1, "regtest"), "already signed");
		var outsider = Make("outsider");
		ExpectError("an outsider is refused", gp.SignSpend(S(s1, "bundle"), outsider.ReceivingXprv, outsider.ChangeXprv, -1, "regtest"), "does not belong");

		var s2 = J(gp.SignSpend(S(s1, "bundle"), m[1].ReceivingXprv, m[1].ChangeXprv, 50, "regtest"));
		if (!Ok(s2)) { Check("member2 (last) signs +50 %", false, ErrOf(s2)); return; }
		var tx = Transaction.Parse(S(s2, "txHex"), Net);
		var paid = tx.Outputs.Single(o => o.ScriptPubKey == BitcoinAddress.Create(sendTo, Net).ScriptPubKey).Value;
		var back = tx.Outputs.Single(o => o.ScriptPubKey == BitcoinAddress.Create(changeTo, Net).ScriptPubKey).Value;
		Check("member2 (last) signs +50 % and finalizes: pays 1.2, fee 3000 sats", paid == Money.Coins(1.2m) && Money.Coins(1.5m) - paid - back == Money.Satoshis(3000));
	}

	static void MemberFirstOwnerLast()
	{
		Console.WriteLine("\n== C) 3-of-5 (owner + 4 members): member1, member3, then the owner is the last signer ==");
		var (gp, _, owner, m) = MakeGroup(3, 4);
		var utxos = Utxos(gp, (0, false, "0.7", 0));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Net).ToString();
		var changeTo = S(J(gp.CreateAddress(1, true, "regtest")), "address");
		var build = J(gp.BuildSpend(utxos, sendTo, "0.3", changeTo, "0.00003", "20", false, "regtest"));
		if (!Ok(build)) { Check("build", false, ErrOf(build)); return; }
		var s1 = J(gp.SignSpend(S(build, "bundle"), m[0].ReceivingXprv, m[0].ChangeXprv, -1, "regtest"));
		var s2 = J(gp.SignSpend(S(s1, "bundle"), m[2].ReceivingXprv, m[2].ChangeXprv, -1, "regtest"));
		var d2 = J(gp.DescribeSpend(S(s2, "bundle"), owner.ReceivingXpub, owner.ChangeXpub, "regtest"));
		Check("2 of 3 signed by member1 and member3; the owner has not signed", d2.GetProperty("signatures").GetInt32() == 2 && !d2.GetProperty("iSigned").GetBoolean() && d2.GetProperty("nextIsLast").GetBoolean());
		var s3 = J(gp.SignSpend(S(s2, "bundle"), owner.ReceivingXprv, owner.ChangeXprv, 20, "regtest"));
		Check("the owner (last) chooses +20 %: valid transaction, fee 3600 sats", Ok(s3) && (long)(s3.GetProperty("feeBtc").GetDecimal() * 100_000_000m) == 3600, Ok(s3) ? "" : ErrOf(s3));
	}

	static void Thresholds()
	{
		Console.WriteLine("\n== D) thresholds: n counts the owner ==");
		foreach (var (k, members, ok) in new[] { (1, 1, true), (2, 1, true), (3, 2, true), (4, 2, false), (2, 59, true), (6, 13, false) })
		{
			var (gp, _, _, _) = MakeGroup(k, members);
			var a = J(gp.CreateAddress(0, false, "regtest"));
			Check($"{k}-of-{members + 1}: {(ok ? "accepted" : "refused")}", Ok(a) == ok, Ok(a) ? $"{a.GetProperty("scripts").GetInt32()} scripts" : ErrOf(a));
		}
	}

	static int NodeRun()
	{
		Console.WriteLine("== Multi Signature (TaprootMultiSig) on a regtest node ==");
		using var nb = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Net, "taprootMultiSigTest");
		var rpc = nb.CreateNode().CreateRPCClient();
		nb.StartAll();
		rpc.Generate(Net.Consensus.CoinbaseMaturity + 10);

		var (gp, _, owner, m) = MakeGroup(3, 4);
		string Address(int seq, bool chg) => S(J(gp.CreateAddress(seq, chg, "regtest")), "address");
		object Fund(int seq, bool chg, decimal amount)
		{
			var address = Address(seq, chg);
			var txid = rpc.SendToAddress(BitcoinAddress.Create(address, Net), Money.Coins(amount));
			var tx = rpc.GetRawTransaction(txid);
			var vout = tx.Outputs.FindIndex(o => o.ScriptPubKey == BitcoinAddress.Create(address, Net).ScriptPubKey);
			return new { TxId = txid.ToString(), Vout = vout, AmountBtc = amount.ToString("0.00000000", System.Globalization.CultureInfo.InvariantCulture), Sequence = seq, IsChange = chg, Address = address };
		}
		bool InBlock(string txid)
		{
			var hash = rpc.Generate(1)[0];
			return rpc.GetBlock(hash).Transactions.Any(t => t.GetHash() == uint256.Parse(txid));
		}

		// 0) Bitcoin Core derives our addresses from the per-address descriptor (Core 25 has no musig(): the
		//    aggregate goes as a plain x-only key)
		foreach (var change in new[] { false, true })
		{
			var same = Enumerable.Range(0, 5).All(i =>
			{
				var ms = TaprootMultiSig.FromExtPubKeys(Xpubs(owner, m, change), 3, (uint)i, Net);
				var core = rpc.SendCommand("deriveaddresses", ms.GetDescriptor()).Result.Select(x => x.ToString()).ToList();
				return core.Count == 1 && core[0] == Address(i, change) && core[0] == ms.Address.ToString();
			});
			Check($"3-of-5 {(change ? "change" : "receiving")} 0-4: Bitcoin Core derives the group addresses", same);
		}

		var coins = JsonSerializer.Serialize(new[] { Fund(0, false, 1.0m), Fund(1, true, 0.5m) });
		var coinsBump = JsonSerializer.Serialize(new[] { Fund(2, false, 0.4m) });
		rpc.Generate(1);
		var sendTo = rpc.GetNewAddress().ToString();
		var changeTo = Address(3, true);

		// 1) the owner first, two members after him, two coins, +50 %
		var est = J(gp.EstimateVsize(coins, sendTo, changeTo, false, false, "regtest")).GetProperty("vsize").GetInt32();
		var fee = (est * 20m / 100_000_000m).ToString("0.00000000", System.Globalization.CultureInfo.InvariantCulture);
		var build = J(gp.BuildSpend(coins, sendTo, "1.2", changeTo, fee, "10,50", false, "regtest"));
		var s1 = J(gp.SignSpend(S(build, "bundle"), owner.ReceivingXprv, owner.ChangeXprv, -1, "regtest"));
		var s2 = J(gp.SignSpend(S(s1, "bundle"), m[3].ReceivingXprv, m[3].ChangeXprv, -1, "regtest"));
		var s3 = J(gp.SignSpend(S(s2, "bundle"), m[1].ReceivingXprv, m[1].ChangeXprv, 50, "regtest"));
		if (!Ok(s3)) { Check("3 of 5 sign", false, ErrOf(s3)); return 1; }
		rpc.SendRawTransaction(Transaction.Parse(S(s3, "txHex"), Net));
		Check($"owner + member4 + member2 (last, +50 %), 2 coins: confirmed, vsize {s3.GetProperty("vsize").GetInt32()} (estimate {est})", InBlock(S(s3, "txId")));

		// 2) every level signed by 3 members; +0 % is broadcast and then replaced by +100 %
		var b = J(gp.BuildSpend(coinsBump, sendTo, "0.1", changeTo, "0.00005", "100", false, "regtest"));
		var b1 = J(gp.SignSpend(S(b, "bundle"), m[0].ReceivingXprv, m[0].ChangeXprv, -1, "regtest"));
		var b2 = J(gp.SignSpend(S(b1, "bundle"), m[1].ReceivingXprv, m[1].ChangeXprv, -1, "regtest"));
		var b3 = J(gp.SignSpend(S(b2, "bundle"), m[2].ReceivingXprv, m[2].ChangeXprv, -1, "regtest"));
		var low = J(gp.FinalizeSpend(S(b3, "bundle"), 0, "regtest"));
		var high = J(gp.FinalizeSpend(S(b3, "bundle"), 100, "regtest"));
		rpc.SendRawTransaction(Transaction.Parse(S(low, "txHex"), Net));
		rpc.SendRawTransaction(Transaction.Parse(S(high, "txHex"), Net));
		var mempool = rpc.GetRawMempool().Select(x => x.ToString()).ToList();
		Check("replace-by-fee: +100 % replaced +0 % in the mempool", mempool.Contains(S(high, "txId")) && !mempool.Contains(S(low, "txId")));
		Check("the +100 % transaction confirmed (3 members, the owner did not sign)", InBlock(S(high, "txId")));

		Console.WriteLine(_failures == 0 ? "\nPASS" : $"\n{_failures} CHECK(S) FAILED");
		return _failures == 0 ? 0 : 1;
	}
}
