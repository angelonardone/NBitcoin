using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.Tests;
using DistricutedCryptographyLib;

// Checks of the MuSig2 group wallets (roadmap §8.3 / §8.4), driven through MuSig2Processor exactly the way GeneXus
// uses it (FromSDT -> methods, JSON results). Every member has his own processor, like his own app.
//   GroupType 80 "Delegated MultiSig 2": the owner spends alone, any k members in a signing room.
//   GroupType 90 "Multi Signature 2":   no owner (he is one more signer); all of them together by the key path.
//
//   dotnet run -- musig2          the offline checks
//   dotnet run -- musig2-node     descriptors (Bitcoin Core 30.2 reads musig()) + payments confirmed on regtest
static class MuSig2Spike
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
		public MuSig2Processor App = new MuSig2Processor();
	}

	static Participant Make(string name) => new Participant
	{
		Name = name,
		Account = ExtKey.CreateFromSeed(Hashes.SHA256(Encoding.UTF8.GetBytes("musig2-spike-" + name))).Derive(new KeyPath("86'/1'/0'"))
	};

	// owner + members; every participant loads the group in his own processor
	static (GroupSDT group, Participant owner, List<Participant> members) MakeGroup(short groupType, int k, int members, string salt = "")
	{
		var owner = Make("owner" + salt);
		var list = Enumerable.Range(1, members).Select(i => Make("member" + i + salt)).ToList();
		var g = new GroupSDT
		{
			GroupType = groupType,
			MinimumShares = (short)k,
			ExtPubKeyMultiSigReceiving = owner.ReceivingXpub,
			ExtPubKeyMultiSigChange = owner.ChangeXpub,
			OtherGroup = new OtherGroup { ReferenceUserName = owner.Name }
		};
		foreach (var m in list)
			g.Contact.Add(new ContactItem { ContactUserName = m.Name, ExtPubKeyMultiSigReceiving = m.ReceivingXpub, ExtPubKeyMultiSigChange = m.ChangeXpub });
		foreach (var p in list.Prepend(owner))
			p.App.FromSDT(g);
		return (g, owner, list);
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

	static string Utxos(MuSig2Processor app, params (int seq, bool chg, string amount, int n)[] coins)
	{
		var list = new List<object>();
		foreach (var c in coins)
		{
			var address = S(J(app.CreateAddress(c.seq, c.chg, "regtest")), "address");
			list.Add(new { TxId = new uint256(Hashes.SHA256(Encoding.UTF8.GetBytes($"coin{c.n}"))).ToString(), Vout = c.n, AmountBtc = c.amount, Sequence = c.seq, IsChange = c.chg, Address = address });
		}
		return JsonSerializer.Serialize(list);
	}

	// The room: every signer present makes round 1, then round 2, then one of them finalizes.
	// Returns the Finalize result (JSON) and the maps that travelled between the members.
	static (JsonElement result, string nonces, string partials) Room(string session, IEnumerable<Participant> present, Participant finalizer)
	{
		var nonces = new Dictionary<string, string[]>();
		foreach (var p in present)
		{
			var r = J(p.App.CreateNonces(session, p.ReceivingXpub, p.ChangeXpub, "regtest"));
			if (!Ok(r)) return (r, "", "");
			nonces[S(r, "signer")] = JsonSerializer.Deserialize<string[]>(S(r, "publicNonces"))!;
		}
		var noncesJson = JsonSerializer.Serialize(nonces);
		var partials = new Dictionary<string, string[]>();
		foreach (var p in present)
		{
			var r = J(p.App.Sign(session, noncesJson, p.ReceivingXprv, p.ChangeXprv, "regtest"));
			if (!Ok(r)) return (r, noncesJson, "");
			partials[S(r, "signer")] = JsonSerializer.Deserialize<string[]>(S(r, "partialSignatures"))!;
		}
		var partialsJson = JsonSerializer.Serialize(partials);
		return (J(finalizer.App.Finalize(session, noncesJson, partialsJson, "regtest")), noncesJson, partialsJson);
	}

	static string Names(params Participant[] p) => JsonSerializer.Serialize(p.Select(x => x.Name));

	static List<ExtPubKey> Xpubs(IEnumerable<Participant> p, bool change) =>
		p.Select(x => ExtPubKey.Parse(change ? x.ChangeXpub : x.ReceivingXpub, Net)).ToList();

	public static int Run(string[] args)
	{
		if (args[0] == "musig2-node")
			return NodeRun();
		Addresses();
		DelegatedRoom();
		MultiSigRoom();
		Attacks();
		Console.WriteLine(_failures == 0 ? "\nALL CHECKS PASSED" : $"\n{_failures} CHECK(S) FAILED");
		return _failures == 0 ? 0 : 1;
	}

	static void Addresses()
	{
		Console.WriteLine("\n== A) addresses, descriptors and limits ==");
		var (_, owner, m) = MakeGroup(80, 2, 3);
		for (int seq = 0; seq < 3; seq++)
			foreach (var change in new[] { false, true })
			{
				var ours = S(J(owner.App.CreateAddress(seq, change, "regtest")), "address");
				var lib = DelegatedMultiSig2.FromExtPubKeys(Xpubs(new[] { owner }, change)[0], Xpubs(m, change), 2, (uint)seq, Net).Address.ToString();
				Check($"Delegated MultiSig 2 {(change ? "change" : "receiving")} {seq} = DelegatedMultiSig2 of the keys", ours == lib && ours == S(J(m[2].App.CreateAddress(seq, change, "regtest")), "address"));
			}
		var (_, owner2, m2) = MakeGroup(90, 3, 3);
		var a = J(owner2.App.CreateAddress(0, false, "regtest"));
		var lib2 = TaprootMultiSig2.FromExtPubKeys(Xpubs(m2.Prepend(owner2), false), 3, 0, Net).Address.ToString();
		Check("Multi Signature 2: n = 4 (the owner signs), k = 3, 4 leaves, = TaprootMultiSig2 of the 4 keys",
			Ok(a) && a.GetProperty("n").GetInt32() == 4 && a.GetProperty("scripts").GetInt32() == 4 && S(a, "address") == lib2, a.ToString());
		var d1 = S(J(owner.App.GetDescriptor(false, "regtest")), "descriptor");
		var d2 = S(J(owner2.App.GetDescriptor(true, "regtest")), "descriptor");
		Check("descriptors: tr(OWNER/*,{pk(musig(..))x3}) and tr(musig(4)/*,{pk(musig(..))x4})",
			d1.StartsWith("tr(tpub") && d1.Split("pk(musig(").Length - 1 == 3 && d2.StartsWith("tr(musig(") && d2.Split("pk(musig(").Length - 1 == 4);

		var (_, o1, _) = MakeGroup(80, 1, 3, "-k1");
		ExpectError("k = 1 refused (that is a Delegated MultiSig)", o1.App.CreateAddress(0, false, "regtest"), "MuSig2 group needs 2");
		var (_, big, _) = MakeGroup(80, 6, 12, "-big");
		ExpectError("6-of-12 (924 leaves) refused: at most 500", big.App.CreateAddress(0, false, "regtest"), "the maximum is 500");
		var (_, legacy, _) = MakeGroup(60, 2, 2, "-60");
		ExpectError("a Multi Signature (60) group is not a MuSig2 group", legacy.App.CreateAddress(0, false, "regtest"), "not a Delegated MultiSig 2");
	}

	static void DelegatedRoom()
	{
		Console.WriteLine("\n== B) Delegated MultiSig 2, 2-of-3: member1 starts, member1 + member3 sign, member2 finalizes ==");
		var (_, owner, m) = MakeGroup(80, 2, 3);
		var coins = Utxos(m[0].App, (0, false, "1.0", 10), (1, true, "0.5", 11));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Net).ToString();
		var changeTo = S(J(m[0].App.CreateAddress(2, true, "regtest")), "address");
		var vsize = J(m[0].App.EstimateVsize(coins, sendTo, changeTo, false, "leaf", "regtest")).GetProperty("vsize").GetInt32();
		var fee = (vsize * 10m / 100_000_000m).ToString("0.00000000", CultureInfo.InvariantCulture);
		var built = J(m[0].App.BuildSession(coins, sendTo, "1.2", changeTo, 2, fee, false, Names(m[0], m[2]), "regtest"));
		Check("BuildSession", Ok(built), built.ToString().Substring(0, Math.Min(200, built.ToString().Length)));
		var session = S(built, "session");

		// everybody reads the same payment from the transaction
		var ids = new HashSet<string>();
		var exact = 0;
		foreach (var p in m.Append(owner))
		{
			var d = J(p.App.DescribeSession(session, p.ReceivingXpub, p.ChangeXpub, "regtest"));
			ids.Add(S(d, "sessionId"));
			var shouldSign = p == m[0] || p == m[2];
			Check($"{p.Name} reads 1.2 BTC to the destination, change to the group, fee {fee}, signer = {shouldSign}",
				Ok(d) && S(d, "sendTo") == sendTo && d.GetProperty("amountBtc").GetDecimal() == 1.2m && S(d, "changeTo") == changeTo
				&& d.GetProperty("feeBtc").GetDecimal() == decimal.Parse(fee, CultureInfo.InvariantCulture) && d.GetProperty("iAmSigner").GetBoolean() == shouldSign
				&& d.GetProperty("vsize").GetInt32() <= vsize, Ok(d) ? "" : ErrOf(d));
			if (Ok(d)) exact = d.GetProperty("vsize").GetInt32();
		}
		Check($"the estimate before the signers are known is the deepest leaf ({vsize}); with them it is exact ({exact})", exact > 0 && exact <= vsize);
		Check("one session id for everybody", ids.Count == 1);
		ExpectError("member2 (not present) cannot make nonces", m[1].App.CreateNonces(session, m[1].ReceivingXpub, m[1].ChangeXpub, "regtest"), "not one of the signers");
		ExpectError("the owner is not a signer of a leaf", owner.App.CreateNonces(session, owner.ReceivingXpub, owner.ChangeXpub, "regtest"), "not one of the signers");

		var (result, nonces, partials) = Room(session, new[] { m[0], m[2] }, m[1]);
		Check($"room: nonces -> partial signatures -> member2 finalizes, vsize {(Ok(result) ? result.GetProperty("vsize").GetInt32() : 0)} = the session's {exact}",
			Ok(result) && result.GetProperty("vsize").GetInt32() == exact, Ok(result) ? S(result, "txId") : ErrOf(result));
		ExpectError("round 2 again with the same nonces: refused", m[0].App.Sign(session, nonces, m[0].ReceivingXprv, m[0].ChangeXprv, "regtest"), "nonces of this payment are gone");

		// the owner pays alone, key path
		var ownerPay = J(owner.App.OwnerSpend(coins, sendTo, "1.2", changeTo, fee, false, owner.ReceivingXprv, owner.ChangeXprv, "regtest"));
		Check($"the owner pays alone (key path), vsize {(Ok(ownerPay) ? ownerPay.GetProperty("vsize").GetInt32() : 0)}", Ok(ownerPay), Ok(ownerPay) ? "" : ErrOf(ownerPay));
		ExpectError("a member's key cannot pay as the owner", m[0].App.OwnerSpend(coins, sendTo, "1.2", changeTo, fee, false, m[0].ReceivingXprv, m[0].ChangeXprv, "regtest"), "not the key of the owner");
	}

	static void MultiSigRoom()
	{
		Console.WriteLine("\n== C) Multi Signature 2, 3-of-4 (owner + 3 members) ==");
		var (_, owner, m) = MakeGroup(90, 3, 3);
		var coins = Utxos(owner.App, (0, false, "1.0", 20));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Net).ToString();
		var changeTo = S(J(owner.App.CreateAddress(0, true, "regtest")), "address");
		var leaf = J(owner.App.BuildSession(coins, sendTo, "0.3", changeTo, 0, "0.0001", false, Names(m[1], owner, m[2]), "regtest"));
		var (r1, _, _) = Room(S(leaf, "session"), new[] { owner, m[1], m[2] }, m[0]);
		Check($"the owner signs a leaf like any member (owner + member2 + member3), vsize {(Ok(r1) ? r1.GetProperty("vsize").GetInt32() : 0)}", Ok(r1), Ok(r1) ? "" : ErrOf(r1));

		var all = J(owner.App.BuildSession(coins, sendTo, "0.3", changeTo, 0, "0.0001", false, "all", "regtest"));
		var d = J(m[0].App.DescribeSession(S(all, "session"), m[0].ReceivingXpub, m[0].ChangeXpub, "regtest"));
		Check("\"all\": 4 signers, key path", Ok(d) && S(d, "path") == "all" && S(d, "signers").Split(',').Length == 4, d.ToString().Substring(0, Math.Min(160, d.ToString().Length)));
		var (r2, _, _) = Room(S(all, "session"), m.Prepend(owner), m[2]);
		Check($"all 4 present: key path, vsize {(Ok(r2) ? r2.GetProperty("vsize").GetInt32() : 0)} < leaf {(Ok(r1) ? r1.GetProperty("vsize").GetInt32() : 0)}",
			Ok(r2) && Ok(r1) && r2.GetProperty("vsize").GetInt32() < r1.GetProperty("vsize").GetInt32(), Ok(r2) ? "" : ErrOf(r2));
		ExpectError("nobody pays alone in a Multi Signature 2", owner.App.OwnerSpend(coins, sendTo, "0.3", changeTo, "0.0001", false, owner.ReceivingXprv, owner.ChangeXprv, "regtest"), "has no owner");
		ExpectError("\"leaf\" needs exactly k = 3 signers", owner.App.BuildSession(coins, sendTo, "0.3", changeTo, 0, "0.0001", false, Names(owner, m[0]), "regtest"), "exactly 3 signers");
	}

	static void Attacks()
	{
		Console.WriteLine("\n== D) a session that lies, nonces misused, a bad signature ==");
		var (_, owner, m) = MakeGroup(80, 2, 3);
		var coins = Utxos(m[0].App, (0, false, "1.0", 30));
		var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Net).ToString();
		var changeTo = S(J(m[0].App.CreateAddress(1, true, "regtest")), "address");
		var good = S(J(m[0].App.BuildSession(coins, sendTo, "0.4", changeTo, 1, "0.0001", false, Names(m[0], m[1]), "regtest")), "session");

		// edit the session the way a dishonest initiator could
		string Edit(Action<JsonElement, Dictionary<string, object?>> change)
		{
			var e = J(good);
			var d = JsonSerializer.Deserialize<Dictionary<string, object?>>(good)!;
			change(e, d);
			return JsonSerializer.Serialize(d);
		}
		var stranger = new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Net);
		var tx = Transaction.Parse(S(J(good), "Tx"), Net);
		var stolenChange = tx.Clone();
		stolenChange.Outputs[1].ScriptPubKey = stranger.ScriptPubKey;
		ExpectError("the change sent to an address that is not the group's", m[1].App.DescribeSession(Edit((_, d) => d["Tx"] = stolenChange.ToHex()), m[1].ReceivingXpub, m[1].ChangeXpub, "regtest"), "change does not go back");
		var extra = tx.Clone();
		extra.Outputs.Add(Money.Coins(0.1m), stranger);
		ExpectError("a third output", m[1].App.DescribeSession(Edit((_, d) => d["Tx"] = extra.ToHex()), m[1].ReceivingXpub, m[1].ChangeXpub, "regtest"), "Unexpected outputs");
		ExpectError("a change sequence that is not the change address", m[1].App.DescribeSession(Edit((_, d) => d["ChangeSequence"] = 5), m[1].ReceivingXpub, m[1].ChangeXpub, "regtest"), "change does not go back");
		ExpectError("a signer who is not a member", m[1].App.DescribeSession(Edit((_, d) => d["Signers"] = new[] { m[0].Name, "mallory" }), m[1].ReceivingXpub, m[1].ChangeXpub, "regtest"), "not a signer of this group");
		ExpectError("the same member twice", m[1].App.DescribeSession(Edit((_, d) => d["Signers"] = new[] { m[0].Name, m[0].Name }), m[1].ReceivingXpub, m[1].ChangeXpub, "regtest"), "twice");
		ExpectError("an amount that does not match the coin (more fee than it says)", m[1].App.DescribeSession(Edit((e, d) => d["Inputs"] = e.GetProperty("Inputs").EnumerateArray().Select(i => new { TxId = i.GetProperty("TxId").GetString(), Vout = i.GetProperty("Vout").GetInt32(), AmountBtc = "0.0001", Sequence = i.GetProperty("Sequence").GetInt32(), IsChange = false }).ToArray()), m[1].ReceivingXpub, m[1].ChangeXpub, "regtest"), "no fee");

		// the coins checked against the previous transactions (what each signer reads from Electrum)
		var coin = J(coins)[0];
		var prev = Net.CreateTransaction();
		prev.Inputs.Add(new TxIn(new OutPoint(uint256.One, 0)));
		prev.Outputs.Add(Money.Coins(1.0m), BitcoinAddress.Create(S(J(m[0].App.CreateAddress(0, false, "regtest")), "address"), Net));
		var honest = Edit((e, d) => d["Inputs"] = new[] { new { TxId = prev.GetHash().ToString(), Vout = 0, AmountBtc = "1.0", Sequence = 0, IsChange = false } });
		var honestTx = Transaction.Parse(S(J(honest), "Tx"), Net);
		honestTx.Inputs[0].PrevOut = new OutPoint(prev.GetHash(), 0);
		honest = JsonSerializer.Serialize(JsonSerializer.Deserialize<Dictionary<string, object?>>(honest)!.Select(kv => kv.Key == "Tx" ? new KeyValuePair<string, object?>(kv.Key, honestTx.ToHex()) : kv).ToDictionary(kv => kv.Key, kv => kv.Value));
		var prevs = JsonSerializer.Serialize(new Dictionary<string, string> { [prev.GetHash().ToString()] = prev.ToHex() });
		var ok = J(m[1].App.VerifyCoins(honest, prevs, "regtest"));
		Check("VerifyCoins: the coin of the session is the network's", Ok(ok), Ok(ok) ? "" : ErrOf(ok));
		var lying = honest.Replace("\"AmountBtc\":\"1.0\"", "\"AmountBtc\":\"1.1\"");
		ExpectError("VerifyCoins: a session that lies on the amount of a coin", m[1].App.VerifyCoins(lying, prevs, "regtest"), "not the 1.1");
		ExpectError("VerifyCoins: a coin the network does not have", m[1].App.VerifyCoins(honest, "{}", "regtest"), "could not be read");

		// nonces: Abort wipes them; a Retry replaces them
		var n0 = J(m[0].App.CreateNonces(good, m[0].ReceivingXpub, m[0].ChangeXpub, "regtest"));
		var n1 = J(m[1].App.CreateNonces(good, m[1].ReceivingXpub, m[1].ChangeXpub, "regtest"));
		var map = JsonSerializer.Serialize(new Dictionary<string, string[]>
		{
			[m[0].Name] = JsonSerializer.Deserialize<string[]>(S(n0, "publicNonces"))!,
			[m[1].Name] = JsonSerializer.Deserialize<string[]>(S(n1, "publicNonces"))!
		});
		var aborted = J(MuSig2GroupSpend.Abort(S(n0, "sessionId")));
		Check("Abort wipes the secret nonces of both members of this app", Ok(aborted) && aborted.GetProperty("removed").GetInt32() == 2);
		ExpectError("round 2 after Abort: refused", m[0].App.Sign(good, map, m[0].ReceivingXprv, m[0].ChangeXprv, "regtest"), "gone");
		ExpectError("round 2 with the keys of somebody who is not present", m[2].App.Sign(good, map, m[2].ReceivingXprv, m[2].ChangeXprv, "regtest"), "not one of the signers");
		ExpectError("round 2 with the public nonces of one signer only", m[0].App.Sign(good, JsonSerializer.Serialize(new Dictionary<string, string[]> { [m[0].Name] = new[] { "00" } }), m[0].ReceivingXprv, m[0].ChangeXprv, "regtest"), "gone");

		// a bad partial signature: Finalize names the member
		var (result, nonces, partials) = Room(good, new[] { m[0], m[1] }, owner);
		Check("the honest room completes", Ok(result), Ok(result) ? "" : ErrOf(result));
		var bad = JsonSerializer.Deserialize<Dictionary<string, string[]>>(partials)!;
		var sig = bad[m[1].Name][0].ToCharArray();
		sig[63] = sig[63] == '0' ? '1' : '0';
		bad[m[1].Name][0] = new string(sig);
		ExpectError("a wrong partial signature names its member", owner.App.Finalize(good, nonces, JsonSerializer.Serialize(bad), "regtest"), $"signature of {m[1].Name} is not valid");
		ExpectError("a missing partial signature", owner.App.Finalize(good, nonces, JsonSerializer.Serialize(new Dictionary<string, string[]> { [m[0].Name] = bad[m[0].Name] }), "regtest"), "missing");
	}

	static int NodeRun()
	{
		Console.WriteLine("== MuSig2 group wallets on an isolated regtest node (Bitcoin Core 30.2) ==");
		using var nb = NodeBuilder.Create(NodeDownloadData.Bitcoin.v30_2, Net, "musig2Test");
		var rpc = nb.CreateNode().CreateRPCClient();
		nb.StartAll();
		rpc.Generate(Net.Consensus.CoinbaseMaturity + 10);

		foreach (var (type, label) in new[] { ((short)80, "Delegated MultiSig 2"), ((short)90, "Multi Signature 2") })
		{
			Console.WriteLine($"\n-- {label}, 3 signatures --");
			var (_, owner, m) = MakeGroup(type, 3, type == 80 ? 4 : 3, type.ToString(CultureInfo.InvariantCulture));
			var app = m[0].App;
			string Address(int seq, bool chg) => S(J(app.CreateAddress(seq, chg, "regtest")), "address");

			// Bitcoin Core derives the group's addresses from the BIP390 descriptors of the app
			foreach (var change in new[] { false, true })
			{
				var desc = S(J(app.GetDescriptor(change, "regtest")), "descriptor");
				var core = rpc.SendCommand("deriveaddresses", desc, new Newtonsoft.Json.Linq.JArray(0, 4)).Result.Select(x => x.ToString()).ToList();
				Check($"{(change ? "change" : "receiving")} 0-4: Bitcoin Core derives them from the musig() descriptor", core.SequenceEqual(Enumerable.Range(0, 5).Select(i => Address(i, change))));
			}

			object Fund(int seq, bool chg, decimal amount)
			{
				var address = Address(seq, chg);
				var txid = rpc.SendToAddress(BitcoinAddress.Create(address, Net), Money.Coins(amount));
				var tx = rpc.GetRawTransaction(txid);
				var vout = tx.Outputs.FindIndex(o => o.ScriptPubKey == BitcoinAddress.Create(address, Net).ScriptPubKey);
				return new { TxId = txid.ToString(), Vout = vout, AmountBtc = amount.ToString("0.00000000", CultureInfo.InvariantCulture), Sequence = seq, IsChange = chg, Address = address };
			}
			bool InBlock(string txid) => rpc.GetBlock(rpc.Generate(1)[0]).Transactions.Any(t => t.GetHash() == uint256.Parse(txid));

			var payments = new List<(string what, string path, Participant[] present)>
			{
				("3 members by their leaf, 2 coins", "leaf", new[] { m[0], m[1], m[2] }),
			};
			if (type == 80)
				payments.Add(("the owner alone, 2 coins", "owner", Array.Empty<Participant>()));
			else
			{
				payments.Add(("the owner + 2 members by their leaf, 2 coins", "leaf", new[] { owner, m[0], m[2] }));
				payments.Add(("all 4 by the key path, 2 coins", "all", m.Prepend(owner).ToArray()));
			}
			int seqBase = 0;
			foreach (var (what, path, present) in payments)
			{
				var coins = JsonSerializer.Serialize(new[] { Fund(seqBase, false, 0.6m), Fund(seqBase + 1, true, 0.4m) });
				rpc.Generate(1);
				var sendTo = rpc.GetNewAddress().ToString();
				var changeTo = Address(seqBase + 2, true);
				var vsize = J(app.EstimateVsize(coins, sendTo, changeTo, false, path, "regtest")).GetProperty("vsize").GetInt32();
				var fee = (vsize * 10m / 100_000_000m).ToString("0.00000000", CultureInfo.InvariantCulture);
				JsonElement result;
				if (path == "owner")
					result = J(owner.App.OwnerSpend(coins, sendTo, "0.5", changeTo, fee, false, owner.ReceivingXprv, owner.ChangeXprv, "regtest"));
				else
				{
					var built = J(present[0].App.BuildSession(coins, sendTo, "0.5", changeTo, seqBase + 2, fee, false, path == "all" ? "all" : Names(present), "regtest"));
					result = Ok(built) ? Room(S(built, "session"), present, present[present.Length - 1]).result : built;
				}
				if (!Ok(result)) { Check(what, false, ErrOf(result)); seqBase += 3; continue; }
				rpc.SendRawTransaction(Transaction.Parse(S(result, "txHex"), Net));
				Check($"{what}: confirmed, vsize {result.GetProperty("vsize").GetInt32()} (estimate {vsize}), fee {fee}", InBlock(S(result, "txId")) && result.GetProperty("vsize").GetInt32() <= vsize && result.GetProperty("vsize").GetInt32() > vsize - 20);
				seqBase += 3;
			}
		}
		Console.WriteLine(_failures == 0 ? "\nALL CHECKS PASSED" : $"\n{_failures} CHECK(S) FAILED");
		return _failures == 0 ? 0 : 1;
	}
}
