using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.RPC;
using NBitcoin.Tests;
using DistricutedCryptographyLib;

// Offline checks of "Delegated Multisignature" with pre-signed fee levels, driven through
// DelegatedProcessor exactly the way GeneXus uses it (FromSDT -> methods, JSON results).
//
//   dotnet run -- delegated                       all the offline checks
//   dotnet run -- delegated-address               the first receiving address of the 2-of-3 test group
//   dotnet run -- delegated-node                  broadcast + confirm on an isolated regtest node
static class DelegatedSpike
{
	static readonly Network Net = Network.RegTest;
	static int _failures;

	// One participant: a wallet account (m/86'/1'/0') and the two chains it gives to the group,
	// the same way the app derives them (KeyPaths.MiuSigReceiving = 2, KeyPaths.MuSigChange = 3).
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
		Account = ExtKey.CreateFromSeed(Hashes.SHA256(Encoding.UTF8.GetBytes("delegated-spike-" + name))).Derive(new KeyPath("86'/1'/0'"))
	};

	static (DelegatedProcessor gp, Participant owner, List<Participant> members) MakeGroup(int k, int n)
	{
		var owner = Make("owner");
		var members = Enumerable.Range(1, n).Select(i => Make("member" + i)).ToList();
		var g = new GroupSDT
		{
			MinimumShares = (short)k,
			ExtPubKeyMultiSigReceiving = owner.ReceivingXpub,
			ExtPubKeyMultiSigChange = owner.ChangeXpub
		};
		foreach (var m in members)
			g.Contact.Add(new ContactItem { ContactUserName = m.Name, ExtPubKeyMultiSigReceiving = m.ReceivingXpub, ExtPubKeyMultiSigChange = m.ChangeXpub });
		var gp = new DelegatedProcessor();
		gp.FromSDT(g);
		return (gp, owner, members);
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

	public static int Run(string[] args)
	{
		if (args[0] == "delegated-address")
		{
			var (gp0, _, _) = MakeGroup(2, 3);
			Console.WriteLine(S(J(gp0.CreateAddress(0, false, "regtest")), "address"));
			return 0;
		}
		if (args[0] == "delegated-node")
			return NodeRun();
		if (args[0] == "delegated-design")
			return Design();
		if (args[0] == "delegated-report")
			return Report();

		Vectors();
		TwoOfThree();
		Tampering();
		SendAll();
		OwnerSpend();
		ThreeOfFive();
		DustChange();
		Thresholds();
		LegacyThresholds();
		Sizes(5, 10);
		Sizes(4, 16);

		Console.WriteLine(_failures == 0 ? "\nALL CHECKS PASSED" : $"\n{_failures} CHECK(S) FAILED");
		return _failures == 0 ? 0 : 1;
	}

	// The fixed extended public keys of the GeneXus unit test deriveAddresssForDelegationMuSig1Test.
	static GroupSDT VectorGroup(int k, int members)
	{
		var receiving = new[]
		{
			"tpubDEZUvCj2FMcaNc2VEmHhn9CEC7wjtoRz7uYX4jnn6hFbyVedNH4kwyY3rBdrtQmbFR7Qp4Q2VhCGsCs8PBqPReg8qH9ZTnLd4PDXL7kuoXK",
			"tpubDEbZ8cJoHhNMXYXCoCCqag11kckQxoY81sbC88Samp5ov8eRGTSZgrCfHysRo8zVf1PgyyHf3UFLAmf7kXm2FSswcs2jcXuZa8PRzjq1k4X",
			"tpubDFTd5FohLoP3ZAWyixHgvgbdCGxaPdsXRUjUeQpiE2C7o4bxBvqXz5pfq2MstMrxHVc7AeauFH3DatEjtdL7VnDXBcnm3YcrHQuQe4j1BUF",
			"tpubDE5Bm64sjJXBXf4fTQT3JRnP3MPyaLN2X1vA5gmy4QdNoNSTxswqecEzUzBo2wKiHe49XsQZKdHFABkoWW4ZgQtgGPw7uGvhXK5WVbh3h9y",
			"tpubDEQgusD2c6KT17prVB1L9DxtGp26XfJuz3RYXvChN9TmZUm6zbdNaFbUXGuFwCWv3inFNnh45YVqM9WoVbGRU2QWdeaqF4TGt4tyxZwgdZ4"
		};
		var g = new GroupSDT
		{
			MinimumShares = (short)k,
			ExtPubKeyMultiSigReceiving = "tpubDEQnfwaHwgTLET6nSgfwECcHuiwcm6SrYbAWReBZYNoZrk31oKHmExv8jgjnfeuH9DzJ148we7FTvgGUDGp5v9F1w1BtxhHxf88E61gx5pU",
			ExtPubKeyMultiSigChange = "tpubDEQnfwaHwgTLGHcKCwqZtRApj8kmuKsDE3hTKgsNkqRCyJDxhswBAzba4jrGaHskt79PVuo4gZhC4njzfAkac4dbM52x7wdmPWgrqbbD6yo"
		};
		for (int i = 0; i < members; i++)
			g.Contact.Add(new ContactItem { ContactUserName = "user" + (i + 1), ExtPubKeyMultiSigReceiving = receiving[i] });
		return g;
	}

	// The address is a standard, defined construction: it must not depend on the order of the members,
	// it must not change by accident (pinned vectors), and the size limit is the number of combinations.
	static void Vectors()
	{
		Console.WriteLine("\n== A) The address: defined, pinned, limited by combinations ==");
		var pinned = new (int k, int n, string[] addresses)[]
		{
			(2, 3, new[] { "bcrt1p7llkeeh2rt9qzl6heraaffy92yndmmstfzslsweuw78g0xu59djq55w3rs", "bcrt1phd4ekcz6ljvnljrwcnwa70uxargdd2kg8hvlsd0maegqs9x0klqs7u4sg0", "bcrt1p7m6j60vr6x8x6kjcdca9h46qufafn8yda03a5xl2ce4t8sgu0uhs04p28e" }),
			(3, 5, new[] { "bcrt1pr899e8c8x6cs02l9w8msc4cf9sejjugpa5ruu80qz6az04u2wwlqcsr8ps", "bcrt1pdu0cylcfg85ld52kwzt272kgf4vqhc3zjtm2vstrg83xlzllgy3scnzj5x", "bcrt1pxx9g9faj8ehv5d8a3s3cs3masw7r9z3pyhkrphxe4e9q5p4hka7smmt8p2" })
		};
		foreach (var (k, n, addresses) in pinned)
		{
			var gp = new DelegatedProcessor();
			gp.FromSDT(VectorGroup(k, n));
			for (int seq = 0; seq < addresses.Length; seq++)
			{
				var address = S(J(gp.CreateAddress(seq, false, "regtest")), "address");
				Check($"{k}-of-{n} receiving/{seq} = the pinned address", address == addresses[seq], address);
			}

			// the same members in another order: the same addresses
			var shuffled = VectorGroup(k, n);
			shuffled.Contact.Reverse();
			var gp2 = new DelegatedProcessor();
			gp2.FromSDT(shuffled);
			Check($"{k}-of-{n}: the order of the members does not change the address",
				Enumerable.Range(0, 3).All(seq => S(J(gp.CreateAddress(seq, false, "regtest")), "address") == S(J(gp2.CreateAddress(seq, false, "regtest")), "address")));
		}

		// inside every script the keys are in x-only order (BIP387 sortedmulti_a), and the tree is balanced
		var keys = Enumerable.Range(0, 7).Select(_ => new Key().PubKey).ToList();
		var ms = new DelegatedMultiSig(new Key().PubKey, keys, 4, Net);
		var descriptor = ms.GetDescriptor();
		var sortedInside = System.Text.RegularExpressions.Regex.Matches(descriptor, @"multi_a\(4,([0-9a-f,]+)\)")
			.Select(m => m.Groups[1].Value.Split(','))
			.All(leaf => leaf.SequenceEqual(leaf.OrderBy(x => x, StringComparer.Ordinal)));
		Check("4-of-7: 35 scripts, keys of every script in x-only order", ms.Scripts.Count == 35 && sortedInside);
		var depths = ms.Scripts.Select(script => (ms.TaprootSpendInfo.GetControlBlock(script).ToBytes().Length - 33) / 32).ToList();
		Check("4-of-7: every script at depth 5 or 6 (balanced tree)", depths.Min() == 5 && depths.Max() == 6, $"{depths.Min()}-{depths.Max()}");

		// the limit is the number of combinations, not the number of members
		var (big, _, _) = MakeGroup(8, 16);
		ExpectError("8-of-16 (12,870 combinations) refused", big.CreateAddress(0, false, "regtest"), "combinations");
		var (wide, _, _) = MakeGroup(2, 60);
		var wideAddress = J(wide.CreateAddress(0, false, "regtest"));
		Check("2-of-60 (1,770 combinations) accepted", Ok(wideAddress) && wideAddress.GetProperty("scripts").GetInt32() == 1770, Ok(wideAddress) ? "" : ErrOf(wideAddress));
		var (many, _, _) = MakeGroup(19, 20);
		Check("19-of-20 (20 combinations, more than 16 members) accepted", Ok(J(many.CreateAddress(0, false, "regtest"))));
	}

	// The address as the current GeneXus code builds it (deriveAddresssForDelegationMuSig1 +
	// derOneAddressForDelegationMuSig1): combinations in lexicographic order, weight 100 / scripts.
	static string OldGeneXusAddress(PubKey owner, List<PubKey> sortedKeys, int k)
	{
		var combinations = new List<int[]>();
		void Generate(int start, List<int> current)
		{
			if (current.Count == k) { combinations.Add(current.ToArray()); return; }
			for (int i = start; i < sortedKeys.Count; i++)
			{
				current.Add(i);
				Generate(i + 1, current);
				current.RemoveAt(current.Count - 1);
			}
		}
		Generate(0, new List<int>());
		var weight = (uint)(100 / combinations.Count);
		var scripts = new List<(uint, TapScript)>();
		foreach (var combination in combinations)
		{
			var ops = new List<Op>();
			for (int p = 0; p < combination.Length; p++)
			{
				ops.Add(Op.GetPushOp(sortedKeys[combination[p]].TaprootInternalKey.ToBytes()));
				ops.Add(p == 0 ? OpcodeType.OP_CHECKSIG : OpcodeType.OP_CHECKSIGADD);
			}
			ops.Add((OpcodeType)((int)OpcodeType.OP_1 + k - 1));
			ops.Add(OpcodeType.OP_NUMEQUAL);
			scripts.Add((weight, new Script(ops).ToTapScript(TapLeafVersion.C0)));
		}
		return TaprootSpendInfo.WithHuffmanTree(owner.TaprootInternalKey, scripts.ToArray()).OutputPubKey.OutputKey.GetAddress(Net).ToString();
	}

	static void TwoOfThree()
	{
		Console.WriteLine("\n== B) 2-of-3, two coins on different addresses, fee levels +10 / +50 / +100 % ==");
		var (gp, owner, m) = MakeGroup(2, 3);
		var utxos = Utxos(gp, (0, false, "1.0", 0), (1, true, "0.5", 1));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		var changeTo = S(J(gp.CreateAddress(2, true, "regtest")), "address");

		var estMembers = J(gp.EstimateVsize(utxos, sendTo, "", false, false, "regtest")).GetProperty("vsize").GetInt32();
		var estOwner = J(gp.EstimateVsize(utxos, sendTo, "", false, true, "regtest")).GetProperty("vsize").GetInt32();
		Console.WriteLine($"  estimated vsize: members {estMembers}, owner {estOwner}");

		ExpectError("percentage 15 refused", gp.BuildSpend(utxos, sendTo, "1.2", changeTo, "0.00002", "15", false, "regtest"), "Invalid fee percentage");
		ExpectError("4 percentages refused", gp.BuildSpend(utxos, sendTo, "1.2", changeTo, "0.00002", "10,20,30,40", false, "regtest"), "At most 3");
		ExpectError("repeated percentage refused", gp.BuildSpend(utxos, sendTo, "1.2", changeTo, "0.00002", "10,10", false, "regtest"), "repeated");
		ExpectError("not enough balance refused", gp.BuildSpend(utxos, sendTo, "1.6", changeTo, "0.00002", "", false, "regtest"), "Not enough balance");

		var build = J(gp.BuildSpend(utxos, sendTo, "1.2", changeTo, "0.00002", "100,10,50", false, "regtest"));
		if (!Ok(build)) { Check("build", false, ErrOf(build)); return; }
		var levels = build.GetProperty("levels");
		Check("4 levels, fees 2000 / 2200 / 3000 / 4000 sats", levels.GetArrayLength() == 4 && FeeSats(levels, 0) == 2000 && FeeSats(levels, 10) == 2200 && FeeSats(levels, 50) == 3000 && FeeSats(levels, 100) == 4000,
			string.Join(" / ", levels.EnumerateArray().Select(l => $"+{l.GetProperty("percent")}%={l.GetProperty("feeBtc")}")));
		var bundle0 = S(build, "bundle");

		var d0 = J(gp.DescribeSpend(bundle0, m[0].ReceivingXpub, m[0].ChangeXpub, "regtest"));
		Check("unsigned: 0 of 2, next is not the last", Ok(d0) && d0.GetProperty("signatures").GetInt32() == 0 && d0.GetProperty("required").GetInt32() == 2 && !d0.GetProperty("nextIsLast").GetBoolean());
		Check("describe reads destination, amount and change from the PSBTs", S(d0, "sendTo") == sendTo && S(d0, "changeTo") == changeTo && d0.GetProperty("amountBtc").GetDecimal() == 1.2m && d0.GetProperty("totalInBtc").GetDecimal() == 1.5m);

		ExpectError("first signer cannot choose the fee", gp.SignSpend(bundle0, m[0].ReceivingXprv, m[0].ChangeXprv, 50, "regtest"), "last signer");
		ExpectError("owner key refused among the members", gp.SignSpend(bundle0, owner.ReceivingXprv, owner.ChangeXprv, -1, "regtest"), "owner");
		var outsider = Make("outsider");
		ExpectError("outsider key refused", gp.SignSpend(bundle0, outsider.ReceivingXprv, outsider.ChangeXprv, -1, "regtest"), "does not belong");
		ExpectError("account-level key (one level too high) refused", gp.SignSpend(bundle0, m[0].Account.ToString(Net), m[0].Account.ToString(Net), -1, "regtest"), "does not belong");
		ExpectError("missing change key refused", gp.SignSpend(bundle0, m[0].ReceivingXprv, "", -1, "regtest"), "missing");

		var s1 = J(gp.SignSpend(bundle0, m[0].ReceivingXprv, m[0].ChangeXprv, -1, "regtest"));
		if (!Ok(s1)) { Check("member1 signs every level", false, ErrOf(s1)); return; }
		Check("member1 signs every level: 1 of 2", s1.GetProperty("signatures").GetInt32() == 1 && !s1.GetProperty("complete").GetBoolean());
		var bundle1 = S(s1, "bundle");

		var d1 = J(gp.DescribeSpend(bundle1, m[0].ReceivingXpub, m[0].ChangeXpub, "regtest"));
		var d1b = J(gp.DescribeSpend(bundle1, m[2].ReceivingXpub, m[2].ChangeXpub, "regtest"));
		Check("after 1 signature: next is the last, signed by member1", d1.GetProperty("nextIsLast").GetBoolean() && d1.GetProperty("signedBy").EnumerateArray().Select(x => x.GetString()).SequenceEqual(new[] { "member1" }));
		Check("iSigned: member1 yes, member3 no", d1.GetProperty("iSigned").GetBoolean() && !d1b.GetProperty("iSigned").GetBoolean());

		ExpectError("signing twice refused", gp.SignSpend(bundle1, m[0].ReceivingXprv, m[0].ChangeXprv, -1, "regtest"), "already signed");
		ExpectError("finalize with 1 of 2 refused", gp.FinalizeSpend(bundle1, 0, "regtest"), "More signatures");
		ExpectError("last signer: unknown level refused", gp.SignSpend(bundle1, m[2].ReceivingXprv, m[2].ChangeXprv, 30, "regtest"), "no +30");

		// LAST signer chooses +50 %: signs only that transaction
		var s2 = J(gp.SignSpend(bundle1, m[2].ReceivingXprv, m[2].ChangeXprv, 50, "regtest"));
		if (!Ok(s2)) { Check("member3 (last) signs +50 % and finalizes", false, ErrOf(s2)); return; }
		var tx = Transaction.Parse(S(s2, "txHex"), Net);
		var paid = tx.Outputs.Single(o => o.ScriptPubKey == BitcoinAddress.Create(sendTo, Net).ScriptPubKey).Value;
		var back = tx.Outputs.Single(o => o.ScriptPubKey == BitcoinAddress.Create(changeTo, Net).ScriptPubKey).Value;
		Check("member3 (last) signs +50 % and finalizes: pays 1.2, fee 3000 sats", paid == Money.Coins(1.2m) && Money.Coins(1.5m) - paid - back == Money.Satoshis(3000) && s2.GetProperty("feeBtc").GetDecimal() == 0.00003m);
		Check("final bundle keeps only the chosen level", JsonDocument.Parse(S(s2, "bundle")).RootElement.GetProperty("Levels").GetArrayLength() == 1);
		Check($"real vsize {tx.GetVirtualSize()} <= estimate {estMembers}", tx.GetVirtualSize() <= estMembers);

		// the other way: the 2nd signer signs every level, then any level can be finalized
		var s2all = J(gp.SignSpend(bundle1, m[1].ReceivingXprv, m[1].ChangeXprv, -1, "regtest"));
		Check("member2 signs every level: complete", Ok(s2all) && s2all.GetProperty("complete").GetBoolean());
		foreach (var (percent, sats) in new[] { (0, 2000L), (10, 2200L), (50, 3000L), (100, 4000L) })
		{
			var f = J(gp.FinalizeSpend(S(s2all, "bundle"), percent, "regtest"));
			Check($"finalize +{percent} % -> valid transaction, fee {sats} sats", Ok(f) && (long)(f.GetProperty("feeBtc").GetDecimal() * 100_000_000m) == sats, Ok(f) ? "" : ErrOf(f));
		}
		ExpectError("a 3rd signature refused", gp.SignSpend(S(s2all, "bundle"), m[2].ReceivingXprv, m[2].ChangeXprv, -1, "regtest"), "already has all");
	}

	// A signer must refuse a bundle whose levels are not the same payment.
	static void Tampering()
	{
		Console.WriteLine("\n== C) Tampered bundles are refused ==");
		var (gp, _, m) = MakeGroup(2, 3);
		var utxos = Utxos(gp, (0, false, "1.0", 0));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		var thief = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		var changeTo = S(J(gp.CreateAddress(0, true, "regtest")), "address");

		string Build(string utx, string to, string amount, string change, string fee) =>
			S(J(gp.BuildSpend(utx, to, amount, change, fee, "10,20", false, "regtest")), "bundle");
		string Splice(string good, string evil, int level)
		{
			var a = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(good)!;
			var goodLevels = a["Levels"].EnumerateArray().Select(x => x.Clone()).ToList();
			var evilLevels = JsonDocument.Parse(evil).RootElement.GetProperty("Levels").EnumerateArray().Select(x => x.Clone()).ToList();
			goodLevels[level] = evilLevels[level];
			return JsonSerializer.Serialize(new { Version = 1, Inputs = a["Inputs"], Levels = goodLevels });
		}
		string Sign(string bundle) => gp.SignSpend(bundle, m[0].ReceivingXprv, m[0].ChangeXprv, -1, "regtest");

		var good = Build(utxos, sendTo, "0.4", changeTo, "0.00002");
		Check("untouched bundle signs", Ok(J(Sign(good))));
		ExpectError("a level paying another address", Sign(Splice(good, Build(utxos, thief, "0.4", changeTo, "0.00002"), 2)), "same address");
		ExpectError("a level paying another amount", Sign(Splice(good, Build(utxos, sendTo, "0.9", changeTo, "0.00002"), 1)), "same amount");
		ExpectError("a level sending the change elsewhere", Sign(Splice(good, Build(utxos, sendTo, "0.4", thief, "0.00002"), 2)), "change to the same address");
		ExpectError("a level burning a huge fee", Sign(Splice(good, Build(utxos, sendTo, "0.4", changeTo, "0.01"), 1)), "does not pay the fee it says");
		ExpectError("a level spending another coin", Sign(Splice(good, Build(Utxos(gp, (0, false, "1.0", 7)), sendTo, "0.4", changeTo, "0.00002"), 1)), "same coins");

		// a coin that is not at an address of the group
		var foreign = JsonSerializer.Serialize(new[] { new { TxId = new uint256(Hashes.SHA256(new byte[] { 9 })).ToString(), Vout = 0, AmountBtc = "1.0", Sequence = 0, IsChange = false, Address = thief } });
		ExpectError("a coin at another address", gp.BuildSpend(foreign, sendTo, "0.4", changeTo, "0.00002", "", false, "regtest"), "don't match");

		// a bundle of ANOTHER group (same members, other threshold) is not a coin of this group
		var (gpOther, _, _) = MakeGroup(3, 3);
		var otherBundle = S(J(gpOther.BuildSpend(Utxos(gpOther, (0, false, "1.0", 0)), sendTo, "0.4", changeTo, "0.00002", "", false, "regtest")), "bundle");
		ExpectError("a bundle of another group", Sign(otherBundle), "not a coin of this group");
	}

	static void SendAll()
	{
		Console.WriteLine("\n== D) Send all: the fee comes out of the amount ==");
		var (gp, _, m) = MakeGroup(2, 3);
		var utxos = Utxos(gp, (3, false, "0.7", 0), (4, false, "0.3", 1));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Net).ToString();
		var build = J(gp.BuildSpend(utxos, sendTo, "0", "", "0.00001", "20,40", true, "regtest"));
		if (!Ok(build)) { Check("build", false, ErrOf(build)); return; }
		var s1 = J(gp.SignSpend(S(build, "bundle"), m[1].ReceivingXprv, m[1].ChangeXprv, -1, "regtest"));
		var s2 = J(gp.SignSpend(S(s1, "bundle"), m[0].ReceivingXprv, m[0].ChangeXprv, 40, "regtest"));
		if (!Ok(s2)) { Check("send all +40 %", false, ErrOf(s2)); return; }
		var tx = Transaction.Parse(S(s2, "txHex"), Net);
		Check("send all +40 %: one output of 1.0 - 1400 sats", tx.Outputs.Count == 1 && tx.Outputs[0].Value == Money.Coins(1.0m) - Money.Satoshis(1400));
	}

	static void OwnerSpend()
	{
		Console.WriteLine("\n== E) The owner spends alone (key path) ==");
		var (gp, owner, m) = MakeGroup(2, 3);
		var utxos = Utxos(gp, (0, false, "1.0", 0), (1, true, "0.5", 1));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		var changeTo = S(J(gp.CreateAddress(2, true, "regtest")), "address");
		var est = J(gp.EstimateVsize(utxos, sendTo, changeTo, false, true, "regtest")).GetProperty("vsize").GetInt32();
		var r = J(gp.OwnerSpend(utxos, sendTo, "1.2", changeTo, "0.00002", false, owner.ReceivingXprv, owner.ChangeXprv, "regtest"));
		Check("owner spend: valid transaction", Ok(r), Ok(r) ? "" : ErrOf(r));
		if (Ok(r))
			Check($"real vsize {r.GetProperty("vsize").GetInt32()} <= estimate {est}", r.GetProperty("vsize").GetInt32() <= est);
		ExpectError("a member cannot use the owner path", gp.OwnerSpend(utxos, sendTo, "1.2", changeTo, "0.00002", false, m[0].ReceivingXprv, m[0].ChangeXprv, "regtest"), "not the key of the owner");
	}

	static void ThreeOfFive()
	{
		Console.WriteLine("\n== F) 3-of-5: first, intermediate and last signer (members 5, 2, 4) ==");
		var (gp, _, m) = MakeGroup(3, 5);
		var utxos = Utxos(gp, (0, false, "0.2", 0), (0, true, "0.2", 1), (7, false, "0.2", 2));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		var changeTo = S(J(gp.CreateAddress(1, true, "regtest")), "address");
		var build = J(gp.BuildSpend(utxos, sendTo, "0.45", changeTo, "0.00005", "30", false, "regtest"));
		if (!Ok(build)) { Check("build", false, ErrOf(build)); return; }
		var b0 = S(build, "bundle");
		var s1 = J(gp.SignSpend(b0, m[4].ReceivingXprv, m[4].ChangeXprv, -1, "regtest"));
		var s2 = J(gp.SignSpend(S(s1, "bundle"), m[1].ReceivingXprv, m[1].ChangeXprv, -1, "regtest"));
		Check("after 2 of 3: not complete", Ok(s2) && !s2.GetProperty("complete").GetBoolean() && s2.GetProperty("signatures").GetInt32() == 2, Ok(s2) ? "" : ErrOf(s2));
		var d = J(gp.DescribeSpend(S(s2, "bundle"), "", "", "regtest"));
		Check("signed by member5 and member2, next is the last", d.GetProperty("nextIsLast").GetBoolean() && d.GetProperty("signedBy").EnumerateArray().Select(x => x.GetString()).OrderBy(x => x).SequenceEqual(new[] { "member2", "member5" }));
		Console.WriteLine($"  bundle size: unsigned {b0.Length}, after signer 1 {S(s1, "bundle").Length}, after signer 2 {S(s2, "bundle").Length} chars (signatures of impossible combinations are dropped)");
		var s3 = J(gp.SignSpend(S(s2, "bundle"), m[3].ReceivingXprv, m[3].ChangeXprv, 30, "regtest"));
		Check("member4 (last) chooses +30 %: valid transaction, fee 6500 sats", Ok(s3) && s3.GetProperty("feeBtc").GetDecimal() == 0.000065m, Ok(s3) ? "" : ErrOf(s3));
	}

	static void DustChange()
	{
		Console.WriteLine("\n== G) A change below the dust limit goes to the fee ==");
		var (gp, _, m) = MakeGroup(2, 3);
		var utxos = Utxos(gp, (0, false, "0.00100000", 0));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		var changeTo = S(J(gp.CreateAddress(0, true, "regtest")), "address");
		// 100000 in, pay 97500: change 500 at the base fee (kept), 300 at +10 % (dust, dropped), < 0 at +100 %
		var build = J(gp.BuildSpend(utxos, sendTo, "0.00097500", changeTo, "0.00002", "10", false, "regtest"));
		if (!Ok(build)) { Check("build", false, ErrOf(build)); return; }
		var levels = build.GetProperty("levels");
		Check("base keeps a 500 sats change; +10 % pays 2500 sats and has no change", FeeSats(levels, 0) == 2000 && FeeSats(levels, 10) == 2500,
			string.Join(" / ", levels.EnumerateArray().Select(l => $"+{l.GetProperty("percent")}%: fee {l.GetProperty("feeBtc")} change {l.GetProperty("changeBtc")}")));
		ExpectError("+100 % does not fit in the balance", gp.BuildSpend(utxos, sendTo, "0.00097500", changeTo, "0.00002", "100", false, "regtest"), "+100 % fee option");
		var s1 = J(gp.SignSpend(S(build, "bundle"), m[0].ReceivingXprv, m[0].ChangeXprv, -1, "regtest"));
		var s2 = J(gp.SignSpend(S(s1, "bundle"), m[1].ReceivingXprv, m[1].ChangeXprv, 10, "regtest"));
		Check("+10 % (no change) finalizes", Ok(s2), Ok(s2) ? "" : ErrOf(s2));
	}

	// How heavy the worst case is: the first signer signs every combination he is part of, on every level.
	static void Sizes(int k, int n)
	{
		Console.WriteLine($"\n== H) {k}-of-{n}, 1 coin, 4 levels: time and size ==");
		var sw = Stopwatch.StartNew();
		var (gp, _, m) = MakeGroup(k, n);
		var address = J(gp.CreateAddress(0, false, "regtest"));
		Console.WriteLine($"  scripts in the tree: {address.GetProperty("scripts").GetInt32()}   (address in {sw.ElapsedMilliseconds} ms)");
		var utxos = Utxos(gp, (0, false, "1.0", 0));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		var changeTo = S(J(gp.CreateAddress(0, true, "regtest")), "address");
		sw.Restart();
		var build = J(gp.BuildSpend(utxos, sendTo, "0.5", changeTo, "0.0001", "10,50,100", false, "regtest"));
		if (!Ok(build)) { Check("build", false, ErrOf(build)); return; }
		var bundle = S(build, "bundle");
		Console.WriteLine($"  build: {sw.ElapsedMilliseconds} ms");
		for (int i = 0; i < k; i++)
		{
			sw.Restart();
			var last = i == k - 1;
			var s = J(gp.SignSpend(bundle, m[i].ReceivingXprv, m[i].ChangeXprv, last ? 100 : -1, "regtest"));
			if (!Ok(s)) { Check($"signer {i + 1}", false, ErrOf(s)); return; }
			bundle = S(s, "bundle");
			Console.WriteLine($"  signer {i + 1}{(last ? " (last, +100 %)" : "")}: {sw.ElapsedMilliseconds} ms, bundle {bundle.Length / 1024} KB" + (last ? $", vsize {s.GetProperty("vsize").GetInt32()}" : ""));
			if (last)
				Check($"{k}-of-{n} finalizes", S(s, "txHex").Length > 0);
		}
	}

	// End to end on an isolated regtest node (Bitcoin Core test node, its own temporary data folder):
	// fund addresses of the 2-of-3 test group, then
	//   1) members 1 and 3 spend two coins of different addresses, the last signer chooses +50 %;
	//   2) the owner spends alone;
	//   3) replace-by-fee: the +0 % transaction is broadcast, then replaced by the +100 % one.
	static int NodeRun()
	{
		Console.WriteLine("== Delegated multisig on a regtest node ==");
		using var nb = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Net, "delegatedMultiSigTest");
		var rpc = nb.CreateNode().CreateRPCClient();
		nb.StartAll();
		rpc.Generate(Net.Consensus.CoinbaseMaturity + 10);

		var (gp, owner, m) = MakeGroup(2, 3);
		string Address(int seq, bool chg) => S(J(gp.CreateAddress(seq, chg, "regtest")), "address");
		object Fund(int seq, bool chg, decimal amount)
		{
			var address = Address(seq, chg);
			var txid = rpc.SendToAddress(BitcoinAddress.Create(address, Net), Money.Coins(amount));
			var tx = rpc.GetRawTransaction(txid);
			var vout = tx.Outputs.FindIndex(o => o.ScriptPubKey == BitcoinAddress.Create(address, Net).ScriptPubKey);
			return new { TxId = txid.ToString(), Vout = vout, AmountBtc = amount.ToString("0.00000000", System.Globalization.CultureInfo.InvariantCulture), Sequence = seq, IsChange = chg, Address = address };
		}
		bool Confirmed(string txid) => rpc.GetRawTransactionInfo(uint256.Parse(txid)).Confirmations > 0;

		var coinsMembers = JsonSerializer.Serialize(new[] { Fund(0, false, 1.0m), Fund(1, true, 0.5m) });
		var coinsOwner = JsonSerializer.Serialize(new[] { Fund(2, false, 0.3m), Fund(3, false, 0.2m) });
		var coinsBump = JsonSerializer.Serialize(new[] { Fund(4, false, 0.4m) });
		rpc.Generate(1);
		var sendTo = rpc.GetNewAddress().ToString();
		var changeTo = Address(5, true);

		// 0) Bitcoin Core rebuilds the same addresses from our descriptors (BIP386 tr + BIP387 sortedmulti_a)
		foreach (var (k, n) in new[] { (2, 3), (3, 5), (4, 7), (2, 9), (7, 9) })
		{
			var (dp, _, _) = MakeGroup(k, n);
			foreach (var isChange in new[] { false, true })
			{
				var descriptor = S(J(dp.GetDescriptor(isChange, "regtest")), "descriptor");
				var info = rpc.SendCommand("getdescriptorinfo", descriptor.Split('#')[0]);
				var coreChecksum = info.Result["checksum"]!.ToString();
				var core = rpc.SendCommand("deriveaddresses", descriptor, new[] { 0, 4 }).Result.Select(x => x.ToString()).ToList();
				var ours = Enumerable.Range(0, 5).Select(i => S(J(dp.CreateAddress(i, isChange, "regtest")), "address")).ToList();
				Check($"{k}-of-{n} {(isChange ? "change" : "receiving")}: Bitcoin Core derives our 5 addresses from the descriptor ({descriptor.Length} chars), same checksum",
					core.SequenceEqual(ours) && descriptor.EndsWith("#" + coreChecksum), core.SequenceEqual(ours) ? "" : $"core {core[0]} ours {ours[0]}");
			}
		}
		// ... and from the descriptor of one address built from plain keys
		{
			var plain = new DelegatedMultiSig(new Key().PubKey, Enumerable.Range(0, 6).Select(_ => new Key().PubKey).ToList(), 3, Net);
			var core = rpc.SendCommand("deriveaddresses", plain.GetDescriptor()).Result.Select(x => x.ToString()).ToList();
			Check("3-of-6 from plain keys: Bitcoin Core derives the same address", core.Count == 1 && core[0] == plain.Address.ToString());
		}

		// ... and the Legacy descriptor: sh(wsh(sortedmulti(k, xpub/*, ...)))
		foreach (var (k, n) in new[] { (2, 3), (1, 3), (3, 3), (7, 10) })
		{
			var (lp, _) = MakeLegacyGroup(k, n);
			foreach (var isChange in new[] { false, true })
			{
				var descriptor = S(J(lp.GetLegacyDescriptor(isChange, "regtest")), "descriptor");
				var core = rpc.SendCommand("deriveaddresses", descriptor, new[] { 0, 4 }).Result.Select(x => x.ToString()).ToList();
				var ours = Enumerable.Range(0, 5).Select(i => S(J(lp.CreateLegacyAddress(i, isChange, "regtest")), "address")).ToList();
				Check($"Legacy {k}-of-{n} {(isChange ? "change" : "receiving")}: Bitcoin Core derives our 5 addresses from the descriptor", core.SequenceEqual(ours), core.SequenceEqual(ours) ? "" : $"core {core[0]} ours {ours[0]}");
			}
		}

		// 1) members, two coins, +50 %
		var est = J(gp.EstimateVsize(coinsMembers, sendTo, changeTo, false, false, "regtest")).GetProperty("vsize").GetInt32();
		var feeRate = 20m; // sat/vB
		var fee = (est * feeRate / 100_000_000m).ToString("0.00000000", System.Globalization.CultureInfo.InvariantCulture);
		var build = J(gp.BuildSpend(coinsMembers, sendTo, "1.2", changeTo, fee, "10,50,100", false, "regtest"));
		var s1 = J(gp.SignSpend(S(build, "bundle"), m[0].ReceivingXprv, m[0].ChangeXprv, -1, "regtest"));
		var s2 = J(gp.SignSpend(S(s1, "bundle"), m[2].ReceivingXprv, m[2].ChangeXprv, 50, "regtest"));
		if (!Ok(s2)) { Check("members spend", false, ErrOf(s2)); return 1; }
		rpc.SendRawTransaction(Transaction.Parse(S(s2, "txHex"), Net));
		rpc.Generate(1);
		Check($"members (script path), 2 coins, +50 %: confirmed, vsize {s2.GetProperty("vsize").GetInt32()} (estimate {est}), fee {s2.GetProperty("feeBtc").GetDecimal()} = {feeRate * 1.5m} sat/vB", Confirmed(S(s2, "txId")));

		// 2) owner alone
		var o = J(gp.OwnerSpend(coinsOwner, sendTo, "0.45", changeTo, "0.00005", false, owner.ReceivingXprv, owner.ChangeXprv, "regtest"));
		if (!Ok(o)) { Check("owner spend", false, ErrOf(o)); return 1; }
		rpc.SendRawTransaction(Transaction.Parse(S(o, "txHex"), Net));
		rpc.Generate(1);
		Check($"owner (key path), 2 coins: confirmed, vsize {o.GetProperty("vsize").GetInt32()}", Confirmed(S(o, "txId")));

		// 3) every level signed by both members; +0 % is broadcast and then replaced by +100 %
		var b = J(gp.BuildSpend(coinsBump, sendTo, "0.1", changeTo, "0.00005", "100", false, "regtest"));
		var b1 = J(gp.SignSpend(S(b, "bundle"), m[1].ReceivingXprv, m[1].ChangeXprv, -1, "regtest"));
		var b2 = J(gp.SignSpend(S(b1, "bundle"), m[0].ReceivingXprv, m[0].ChangeXprv, -1, "regtest"));
		var low = J(gp.FinalizeSpend(S(b2, "bundle"), 0, "regtest"));
		var high = J(gp.FinalizeSpend(S(b2, "bundle"), 100, "regtest"));
		rpc.SendRawTransaction(Transaction.Parse(S(low, "txHex"), Net));
		rpc.SendRawTransaction(Transaction.Parse(S(high, "txHex"), Net));
		var mempool = rpc.GetRawMempool().Select(x => x.ToString()).ToList();
		Check("replace-by-fee: +100 % replaced +0 % in the mempool", mempool.Contains(S(high, "txId")) && !mempool.Contains(S(low, "txId")));
		rpc.Generate(1);
		Check("the +100 % transaction confirmed", Confirmed(S(high, "txId")));

		Console.WriteLine(_failures == 0 ? "\nPASS" : $"\n{_failures} CHECK(S) FAILED");
		return _failures == 0 ? 0 : 1;
	}

	// Numbers for the design discussion (no checks): the depth of the tree built the old GeneXus way and
	// the library way, the key order of BIP387, and the size of a spend with one k-of-k script per
	// combination (today) against ONE script with the n keys (BIP387 multi_a).
	static int Design()
	{
		Console.WriteLine("k-of-n | scripts | control block depth: library min-max / old GeneXus min-max | vsize 1 coin 2 outputs: combinations / single multi_a leaf");
		foreach (var (k, n) in new[] { (2, 3), (3, 5), (2, 5), (4, 7), (5, 10), (2, 10), (7, 10), (8, 16), (11, 16) })
		{
			var (gp, owner, m) = MakeGroup(k, n);
			var ownerKey = ExtPubKey.Parse(owner.ReceivingXpub, Net).Derive(0).PubKey;
			var keys = m.Select(x => ExtPubKey.Parse(x.ReceivingXpub, Net).Derive(0).PubKey).OrderBy(x => x.ToHex(), StringComparer.Ordinal).ToList();
			var ms = new DelegatedMultiSig(ownerKey, keys, k, Net);
			var libDepths = ms.Scripts.Select(s => (ms.TaprootSpendInfo.GetControlBlock(s).ToBytes().Length - 33) / 32).ToList();

			var (oldInfo, oldScripts) = OldGeneXusTree(ownerKey, keys, k);
			var oldDepths = oldScripts.Select(s => (oldInfo.GetControlBlock(s).ToBytes().Length - 33) / 32).ToList();

			var utxos = Utxos(gp, (0, false, "1.0", 0));
			var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
			var combinations = J(gp.EstimateVsize(utxos, sendTo, "", false, false, "regtest")).GetProperty("vsize").GetInt32();

			// one leaf: <key1> CHECKSIG <key2> CHECKSIGADD ... <keyn> CHECKSIGADD <k> NUMEQUAL
			var ops = new List<Op>();
			for (int i = 0; i < n; i++)
			{
				ops.Add(Op.GetPushOp(keys[i].TaprootInternalKey.ToBytes()));
				ops.Add(i == 0 ? OpcodeType.OP_CHECKSIG : OpcodeType.OP_CHECKSIGADD);
			}
			ops.Add((OpcodeType)((int)OpcodeType.OP_1 + k - 1));
			ops.Add(OpcodeType.OP_NUMEQUAL);
			var leaf = new Script(ops).ToTapScript(TapLeafVersion.C0);
			var single = TaprootSpendInfo.WithHuffmanTree(ownerKey.TaprootInternalKey, new[] { (1u, leaf) });
			var tx = Net.CreateTransaction();
			tx.Version = 2;
			var txin = new TxIn(new OutPoint(uint256.One, 0));
			var witness = new List<byte[]>();
			for (int i = 0; i < n; i++)
				witness.Add(i < k ? new byte[64] : Array.Empty<byte>());
			witness.Add(leaf.Script.ToBytes());
			witness.Add(single.GetControlBlock(leaf).ToBytes());
			txin.WitScript = new WitScript(witness.ToArray());
			tx.Inputs.Add(txin);
			tx.Outputs.Add(Money.Zero, BitcoinAddress.Create(sendTo, Net));
			tx.Outputs.Add(Money.Zero, single.OutputPubKey.OutputKey.GetAddress(Net));

			Console.WriteLine($"{k}-of-{n} | {ms.Scripts.Count} | {libDepths.Min()}-{libDepths.Max()} / {oldDepths.Min()}-{oldDepths.Max()} | {combinations} / {tx.GetVirtualSize()}");
		}

		// BIP387 sortedmulti_a sorts the x-only keys; today the keys are sorted with their 02/03 prefix
		var (_, _, members) = MakeGroup(3, 5);
		var pubs = members.Select(x => ExtPubKey.Parse(x.ReceivingXpub, Net).Derive(0).PubKey).ToList();
		var withPrefix = pubs.OrderBy(x => x.ToHex(), StringComparer.Ordinal).Select(x => x.ToHex().Substring(2, 8)).ToList();
		var xOnly = pubs.OrderBy(x => x.ToHex().Substring(2), StringComparer.Ordinal).Select(x => x.ToHex().Substring(2, 8)).ToList();
		Console.WriteLine("key order today (with prefix): " + string.Join(" ", withPrefix));
		Console.WriteLine("key order BIP387 (x-only):     " + string.Join(" ", xOnly) + (withPrefix.SequenceEqual(xOnly) ? "  (same for these keys)" : "  (DIFFERENT)"));
		return 0;
	}

	static (TaprootSpendInfo info, List<TapScript> scripts) OldGeneXusTree(PubKey owner, List<PubKey> sortedKeys, int k)
	{
		var combinations = new List<int[]>();
		void Generate(int start, List<int> current)
		{
			if (current.Count == k) { combinations.Add(current.ToArray()); return; }
			for (int i = start; i < sortedKeys.Count; i++)
			{
				current.Add(i);
				Generate(i + 1, current);
				current.RemoveAt(current.Count - 1);
			}
		}
		Generate(0, new List<int>());
		var weight = (uint)(100 / combinations.Count);
		var scripts = new List<(uint, TapScript)>();
		foreach (var combination in combinations)
		{
			var ops = new List<Op>();
			for (int p = 0; p < combination.Length; p++)
			{
				ops.Add(Op.GetPushOp(sortedKeys[combination[p]].TaprootInternalKey.ToBytes()));
				ops.Add(p == 0 ? OpcodeType.OP_CHECKSIG : OpcodeType.OP_CHECKSIGADD);
			}
			ops.Add((OpcodeType)((int)OpcodeType.OP_1 + k - 1));
			ops.Add(OpcodeType.OP_NUMEQUAL);
			scripts.Add((weight, new Script(ops).ToTapScript(TapLeafVersion.C0)));
		}
		return (TaprootSpendInfo.WithHuffmanTree(owner.TaprootInternalKey, scripts.ToArray()), scripts.Select(x => x.Item2).ToList());
	}

	// Re-measures the scenarios of MuSig_Comparison_Analysis.md the way ComprehensiveMultisigExecutor does
	// (1 coin, 2 P2WPKH outputs, the first k signers, SIGHASH_ALL), offline: every transaction is checked
	// with the script interpreter instead of being broadcast. "report" = the three numbers of the document.
	static int Report()
	{
		var scenarios = new (int k, int n, string report)[]
		{
			(1, 2, "185/156/156"), (2, 2, "203/173/156"), (2, 3, "212/172/164"), (3, 3, "230/188/148"), (3, 5, "247/188/180"),
			(5, 5, "284/220/148"), (7, 7, "336/252/148"), (5, 10, "281/204/196"), (10, 10, "443/316/148"),
			(15, 16, "557/436/180"), (16, 16, "620/460/148"), (17, 17, "FAIL/476/148"), (49, 50, "FAIL/812/180"), (2, 50, "-"), (99, 100, "-"), (2, 100, "-")
		};
		Console.WriteLine("k-of-n | report SegWit/MuSig1/MuSig2 | measured SegWit P2SH-P2WSH | measured DelegatedMultiSig (leaf depth) | measured DelegatedMultiSig2 | ms to build + sign");
		foreach (var (k, n, report) in scenarios)
		{
			var owner = new Key();
			var signers = Enumerable.Range(0, n).Select(_ => new Key()).ToList();
			var pubs = signers.Select(x => x.PubKey).ToList();
			var pay = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net);
			var change = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net);
			Transaction NewTx(Coin coin)
			{
				var tx = Net.CreateTransaction();
				tx.Inputs.Add(coin.Outpoint);
				tx.Outputs.Add(Money.Coins(0.5m), pay);
				tx.Outputs.Add(Money.Coins(0.4999m), change);
				return tx;
			}
			string Valid(Transaction tx, Coin coin) => tx.CreateValidator(new[] { coin.TxOut }).ValidateInput(0).Error == null ? "" : " INVALID";

			string segwit;
			try
			{
				var sw = new SegWitMultiSig(pubs, k, Net);
				var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1m), sw.Address));
				var builder = Net.CreateTransactionBuilder();
				builder.AddCoins(sw.CreateCoin(coin));
				foreach (var key in signers.Take(k)) builder.AddKeys(key);
				var tx = builder.SignTransaction(NewTx(coin));
				segwit = tx.GetVirtualSize() + Valid(tx, coin);
			}
			catch (Exception e) { segwit = "FAIL (" + e.Message.Split('.')[0] + ")"; }

			var clock = Stopwatch.StartNew();
			string delegated;
			try
			{
				var ms = new DelegatedMultiSig(owner.PubKey, pubs, k, Net);
				var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1m), ms.Address));
				var builder = ms.CreateSignatureBuilder(NewTx(coin), new ICoin[] { coin });
				foreach (var key in signers.Take(k))
					if (builder.SignWithSigner(key, 0, TaprootSigHash.All).IsComplete) break;
				var tx = builder.FinalizeTransaction(0);
				var witness = tx.Inputs[0].WitScript;
				var depth = (witness.GetUnsafePush(witness.PushCount - 1).Length - 33) / 32;
				delegated = $"{tx.GetVirtualSize()}{Valid(tx, coin)} (depth {depth}, {ms.Scripts.Count} scripts)";
			}
			catch (Exception e) { delegated = "FAIL (" + e.Message.Split('.')[0] + ")"; }
			var delegatedMs = clock.ElapsedMilliseconds;

			clock.Restart();
			string delegated2;
			try
			{
				var ms2 = new DelegatedMultiSig2(owner.PubKey, pubs, k, Net);
				var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1m), ms2.Address));
				var builder = ms2.CreateSignatureBuilder(NewTx(coin), new ICoin[] { coin });
				var nonces = signers.Take(k).Select(key => builder.GenerateNonce(key, 0, TaprootSigHash.All)).ToList();
				foreach (var nonce in nonces) builder.AddNonces(nonce, 0);
				foreach (var key in signers.Take(k))
					if (builder.SignWithSigner(key, 0, TaprootSigHash.All).IsComplete) break;
				var tx = builder.FinalizeTransaction(0);
				var witness = tx.Inputs[0].WitScript;
				var depth = (witness.GetUnsafePush(witness.PushCount - 1).Length - 33) / 32;
				delegated2 = $"{tx.GetVirtualSize()}{Valid(tx, coin)} (depth {depth})";
			}
			catch (Exception e) { delegated2 = "FAIL (" + e.Message.Split('.')[0] + ")"; }

			Console.WriteLine($"{k}-of-{n} | {report} | {segwit} | {delegated} | {delegated2} | {delegatedMs} + {clock.ElapsedMilliseconds}");
		}
		return 0;
	}

	// 1-of-n (one member is enough: the first signer is also the last and chooses the fee) and n-of-n.
	static void Thresholds()
	{
		Console.WriteLine("\n== I) Delegated 1-of-n and n-of-n ==");
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		{
			var (gp, _, m) = MakeGroup(1, 3);
			var utxos = Utxos(gp, (0, false, "1.0", 0));
			var changeTo = S(J(gp.CreateAddress(0, true, "regtest")), "address");
			var build = J(gp.BuildSpend(utxos, sendTo, "0.3", changeTo, "0.00002", "20", false, "regtest"));
			var d = J(gp.DescribeSpend(S(build, "bundle"), "", "", "regtest"));
			Check("1-of-3: the first signature is the last one", Ok(d) && d.GetProperty("nextIsLast").GetBoolean() && d.GetProperty("required").GetInt32() == 1);
			var s1 = J(gp.SignSpend(S(build, "bundle"), m[1].ReceivingXprv, m[1].ChangeXprv, 20, "regtest"));
			Check("1-of-3: one member signs +20 % and gets a valid transaction, fee 2400 sats", Ok(s1) && s1.GetProperty("feeBtc").GetDecimal() == 0.000024m, Ok(s1) ? "" : ErrOf(s1));
		}
		{
			var (gp, _, m) = MakeGroup(3, 3);
			var utxos = Utxos(gp, (0, false, "1.0", 0));
			var changeTo = S(J(gp.CreateAddress(0, true, "regtest")), "address");
			var bundle = S(J(gp.BuildSpend(utxos, sendTo, "0.3", changeTo, "0.00002", "50", false, "regtest")), "bundle");
			bundle = S(J(gp.SignSpend(bundle, m[2].ReceivingXprv, m[2].ChangeXprv, -1, "regtest")), "bundle");
			ExpectError("3-of-3: the 2nd signer cannot finalize", gp.SignSpend(bundle, m[0].ReceivingXprv, m[0].ChangeXprv, 50, "regtest"), "last signer");
			bundle = S(J(gp.SignSpend(bundle, m[0].ReceivingXprv, m[0].ChangeXprv, -1, "regtest")), "bundle");
			var s3 = J(gp.SignSpend(bundle, m[1].ReceivingXprv, m[1].ChangeXprv, 50, "regtest"));
			Check("3-of-3: the three members sign, the last one chooses +50 %: valid transaction, fee 3000 sats", Ok(s3) && s3.GetProperty("feeBtc").GetDecimal() == 0.00003m, Ok(s3) ? "" : ErrOf(s3));
		}
	}

	// A Legacy group (the owner is a signer too): owner + (n - 1) contacts, chains 0 and 1 of each account.
	static (GroupProcessor gp, List<Participant> signers) MakeLegacyGroup(int k, int n, bool reverseContacts = false)
	{
		var signers = Enumerable.Range(0, n).Select(i => Make(i == 0 ? "legacy-owner" : "legacy-member" + i)).ToList();
		var g = new GroupSDT
		{
			MinimumShares = (short)k,
			ExtPubKeyMultiSigReceiving = signers[0].Account.Neuter().Derive(0).ToString(Net),
			ExtPubKeyMultiSigChange = signers[0].Account.Neuter().Derive(1).ToString(Net)
		};
		var contacts = signers.Skip(1).Select(x => new ContactItem { ContactUserName = x.Name, ExtPubKeyMultiSigReceiving = x.Account.Neuter().Derive(0).ToString(Net), ExtPubKeyMultiSigChange = x.Account.Neuter().Derive(1).ToString(Net) }).ToList();
		if (reverseContacts) contacts.Reverse();
		g.Contact.AddRange(contacts);
		var gp = new GroupProcessor();
		gp.FromSDT(g);
		return (gp, signers);
	}

	// Legacy: 1-of-n, n-of-n, and the address does not depend on the order of the members (BIP67).
	static void LegacyThresholds()
	{
		Console.WriteLine("\n== J) Legacy 1-of-n, n-of-n, key order ==");
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net).ToString();
		foreach (var (k, n) in new[] { (1, 3), (3, 3), (2, 3), (16, 16) })
		{
			var (gp, signers) = MakeLegacyGroup(k, n);
			var address = S(J(gp.CreateLegacyAddress(0, false, "regtest")), "address");
			var (gp2, _) = MakeLegacyGroup(k, n, reverseContacts: true);
			Check($"Legacy {k}-of-{n}: the order of the members does not change the address", address == S(J(gp2.CreateLegacyAddress(0, false, "regtest")), "address"), address);

			var txid = new uint256(Hashes.SHA256(Encoding.UTF8.GetBytes($"legacy{k}{n}"))).ToString();
			var utxos = JsonSerializer.Serialize(new[] { new { TxId = txid, Vout = 0, AmountBtc = "1.0" } });
			var change = S(J(gp.CreateLegacyAddress(0, true, "regtest")), "address");
			var psbt = S(J(gp.BuildLegacyPsbt(utxos, sendTo, "0.4", change, "0.0001", false, 0, false, "regtest")), "psbt");
			JsonElement final = default;
			for (int i = 0; i < k; i++)
			{
				// any k of the signers: start from the last one so the owner is not always included
				var signer = signers[n - 1 - i];
				psbt = S(J(gp.SignLegacyPsbt(psbt, 0, signer.Account.Derive(0).ToString(Net), "regtest")), "psbt");
				final = J(gp.FinalizeLegacyPsbt(psbt, "regtest"));
				if (i < k - 1 && Ok(final)) { Check($"Legacy {k}-of-{n}: not final with {i + 1} signature(s)", false); break; }
			}
			var valid = false;
			if (Ok(final))
			{
				var tx = Transaction.Parse(S(final, "txHex"), Net);
				var spent = new TxOut(Money.Coins(1.0m), BitcoinAddress.Create(address, Net));
				valid = tx.CreateValidator(new[] { spent }).ValidateInput(0).Error == null;
			}
			Check($"Legacy {k}-of-{n}: {k} signature(s) give a valid transaction", valid, Ok(final) ? "" : ErrOf(final));
		}
		var (tooBig, _) = MakeLegacyGroup(2, 17);
		ExpectError("Legacy with 17 signers refused", tooBig.CreateLegacyAddress(0, false, "regtest"), "at most 16");
	}
}
