using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using NBitcoin;
using NBitcoin.RPC;
using NBitcoin.Tests;          // NodeBuilder, NodeDownloadData
using DistricutedCryptographyLib;

// End-to-end regtest test for "Legacy Multisignature" (SegWit P2SH-P2WSH N-of-M),
// driven entirely through GroupProcessor (FromSDT -> Legacy* methods), exactly the way
// GeneXus will use it. Proves: build address -> fund -> each member signs their own PSBT
// copy -> combine -> finalize -> broadcast -> confirm, on a real regtest node.

// Offline mode: print the CreateLegacyAddress JSON for a fixed set of xpubs (used to produce
// the deterministic expected address for the GeneXus unit test). No regtest node needed.
if (args.Length > 0 && args[0] == "vector")
{
	var vg = new GroupSDT
	{
		MinimumShares = 2,
		AmIGroupOwner = true,
		ExtPubKeyMultiSigReceiving = "tpubDEQnfwaHwgTLET6nSgfwECcHuiwcm6SrYbAWReBZYNoZrk31oKHmExv8jgjnfeuH9DzJ148we7FTvgGUDGp5v9F1w1BtxhHxf88E61gx5pU"
	};
	vg.Contact.Add(new ContactItem { ExtPubKeyMultiSigReceiving = "tpubDEZUvCj2FMcaNc2VEmHhn9CEC7wjtoRz7uYX4jnn6hFbyVedNH4kwyY3rBdrtQmbFR7Qp4Q2VhCGsCs8PBqPReg8qH9ZTnLd4PDXL7kuoXK" });
	vg.Contact.Add(new ContactItem { ExtPubKeyMultiSigReceiving = "tpubDEbZ8cJoHhNMXYXCoCCqag11kckQxoY81sbC88Samp5ov8eRGTSZgrCfHysRo8zVf1PgyyHf3UFLAmf7kXm2FSswcs2jcXuZa8PRzjq1k4X" });
	var vgp = new GroupProcessor();
	vgp.FromSDT(vg);
	Console.WriteLine(vgp.CreateLegacyAddress(0, false, "regtest"));
	return 0;
}

// Offline mode: deterministic vectors (xprv/xpub pairs + fixed utxo) for the GeneXus
// end-to-end flow unit test. Runs build -> sign x2 -> combine -> finalize and prints everything.
if (args.Length > 0 && args[0] == "vector2")
{
	var net = Network.RegTest;
	string Psbt(string json) => JsonDocument.Parse(json).RootElement.GetProperty("psbt").GetString()!;

	var master = new Mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow").DeriveExtKey();
	var ownerExt = master.Derive(0);
	var c1Ext = master.Derive(1);
	var c2Ext = master.Derive(2);
	var sendTo = master.Derive(10).PrivateKey.PubKey.GetAddress(ScriptPubKeyType.Segwit, net).ToString();
	var change = master.Derive(11).PrivateKey.PubKey.GetAddress(ScriptPubKeyType.Segwit, net).ToString();

	Console.WriteLine("owner.xpub=" + ownerExt.Neuter().ToString(net));
	Console.WriteLine("owner.xprv=" + ownerExt.ToString(net));
	Console.WriteLine("c1.xpub=" + c1Ext.Neuter().ToString(net));
	Console.WriteLine("c1.xprv=" + c1Ext.ToString(net));
	Console.WriteLine("c2.xpub=" + c2Ext.Neuter().ToString(net));
	Console.WriteLine("sendTo=" + sendTo);
	Console.WriteLine("change=" + change);

	var g = new GroupSDT { MinimumShares = 2, AmIGroupOwner = true, ExtPubKeyMultiSigReceiving = ownerExt.Neuter().ToString(net) };
	g.Contact.Add(new ContactItem { ExtPubKeyMultiSigReceiving = c1Ext.Neuter().ToString(net) });
	g.Contact.Add(new ContactItem { ExtPubKeyMultiSigReceiving = c2Ext.Neuter().ToString(net) });
	var gp = new GroupProcessor();
	gp.FromSDT(g);

	var utxos = "[{\"TxId\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"Vout\":0,\"AmountBtc\":\"1.0\"}]";
	var build = gp.BuildLegacyPsbt(utxos, sendTo, "0.5", change, "0.0001", false, 0, false, "regtest");
	Console.WriteLine("build=" + build);
	var p0 = Psbt(build);
	var s1 = Psbt(gp.SignLegacyPsbt(p0, 0, ownerExt.ToString(net), "regtest"));
	var s2 = Psbt(gp.SignLegacyPsbt(p0, 0, c1Ext.ToString(net), "regtest"));
	var comb = Psbt(gp.CombineLegacyPsbts("[\"" + s1 + "\",\"" + s2 + "\"]", "regtest"));
	var fin = gp.FinalizeLegacyPsbt(comb, "regtest");
	Console.WriteLine("final=" + fin);
	return 0;
}

int Fail(string m) { Console.WriteLine("FAIL: " + m); return 1; }

JsonElement Call(string json) => JsonDocument.Parse(json).RootElement;
bool Okk(JsonElement e) => e.GetProperty("success").GetBoolean();
string ErrOf(JsonElement e) => e.GetProperty("error").GetString() ?? "";

// Offline checks (no node): receiving vs change chains derive distinct addresses, and a group with
// more than 16 participants is rejected up-front with a clear message.
if (args.Length > 0 && args[0] == "checks")
{
	var net0 = Network.RegTest;

	// 1) receiving chain != change chain (distinct chain-level xpubs => distinct multisig addresses).
	var cg = new GroupSDT
	{
		MinimumShares = 2,
		AmIGroupOwner = true,
		ExtPubKeyMultiSigReceiving = new ExtKey().Neuter().ToString(net0),
		ExtPubKeyMultiSigChange = new ExtKey().Neuter().ToString(net0)
	};
	cg.Contact.Add(new ContactItem { ExtPubKeyMultiSigReceiving = new ExtKey().Neuter().ToString(net0), ExtPubKeyMultiSigChange = new ExtKey().Neuter().ToString(net0) });
	cg.Contact.Add(new ContactItem { ExtPubKeyMultiSigReceiving = new ExtKey().Neuter().ToString(net0), ExtPubKeyMultiSigChange = new ExtKey().Neuter().ToString(net0) });
	var cgp = new GroupProcessor(); cgp.FromSDT(cg);
	var rcv = Call(cgp.CreateLegacyAddress(0, false, "regtest"));
	var chg = Call(cgp.CreateLegacyAddress(0, true, "regtest"));
	if (!Okk(rcv)) return Fail("receiving address: " + ErrOf(rcv));
	if (!Okk(chg)) return Fail("change address: " + ErrOf(chg));
	if (rcv.GetProperty("address").GetString() == chg.GetProperty("address").GetString())
		return Fail("change address must differ from receiving address");
	Console.WriteLine("receiving=" + rcv.GetProperty("address").GetString());
	Console.WriteLine("change   =" + chg.GetProperty("address").GetString() + "  (differs ✓)");

	// 2) >16 participants (owner + 16 contacts = 17) must be rejected.
	var big = new GroupSDT { MinimumShares = 2, AmIGroupOwner = true, ExtPubKeyMultiSigReceiving = new ExtKey().Neuter().ToString(net0) };
	for (int i = 0; i < 16; i++)
		big.Contact.Add(new ContactItem { ExtPubKeyMultiSigReceiving = new ExtKey().Neuter().ToString(net0) });
	var bgp = new GroupProcessor(); bgp.FromSDT(big);
	var bigRes = Call(bgp.CreateLegacyAddress(0, false, "regtest"));
	if (Okk(bigRes)) return Fail(">16 participants should have been rejected");
	if (!ErrOf(bigRes).Contains("at most 16")) return Fail("unexpected >16 error: " + ErrOf(bigRes));
	Console.WriteLine("17-participant group rejected: " + ErrOf(bigRes) + "  ✓");

	Console.WriteLine("PASS: offline checks (receiving/change + >16 guard)");
	return 0;
}

// Simulate EXACTLY the GeneXus flow, offline (no node), to validate the derivation-level fix.
// Each participant holds an m/48' ACCOUNT ext key (what Wallet.getExtKeyBIP48 returns). SmartGroups stores
// the CHAIN-level xpub neuter(account).Derive(0|1). The fix signs with account.Derive(0|1) (the chain xprv).
if (args.Length > 0 && args[0] == "gxsim")
{
	var net = Network.RegTest;
	string P(string j) => JsonDocument.Parse(j).RootElement.GetProperty("psbt").GetString()!;

	var acct = new KeyPath("48'/1'/0'/1'"); // BIP48 P2SH-P2WSH account (regtest coin = 1')
	// three "wallets": master -> account (this is what getExtKeyBIP48 holds in session)
	var ownerAcct = new Mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow").DeriveExtKey().Derive(acct);
	var c1Acct    = new Mnemonic("letter advice cage absurd amount doctor acoustic avoid letter advice cage above").DeriveExtKey().Derive(acct);
	var c2Acct    = new Mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").DeriveExtKey().Derive(acct);

	// group xpubs exactly like SmartGroups: neuter(account).Derive(0) receiving, .Derive(1) change
	var g = new GroupSDT {
		MinimumShares = 2, AmIGroupOwner = true,
		ExtPubKeyMultiSigReceiving = ownerAcct.Neuter().Derive(0).ToString(net),
		ExtPubKeyMultiSigChange    = ownerAcct.Neuter().Derive(1).ToString(net)
	};
	g.Contact.Add(new ContactItem { ExtPubKeyMultiSigReceiving = c1Acct.Neuter().Derive(0).ToString(net), ExtPubKeyMultiSigChange = c1Acct.Neuter().Derive(1).ToString(net) });
	g.Contact.Add(new ContactItem { ExtPubKeyMultiSigReceiving = c2Acct.Neuter().Derive(0).ToString(net), ExtPubKeyMultiSigChange = c2Acct.Neuter().Derive(1).ToString(net) });
	var gp = new GroupProcessor(); gp.FromSDT(g);

	int seq = 0; bool isChange = false;
	var addr = Call(gp.CreateLegacyAddress(seq, isChange, "regtest"));
	Console.WriteLine("address ok=" + Okk(addr) + "  " + (Okk(addr) ? addr.GetProperty("address").GetString() : ErrOf(addr)));

	var utxos  = "[{\"TxId\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"Vout\":0,\"AmountBtc\":\"1.0\"}]";
	var sendTo = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, net).ToString();
	var change = new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, net).ToString();
	var build  = Call(gp.BuildLegacyPsbt(utxos, sendTo, "0.5", change, "0.0001", false, seq, isChange, "regtest"));
	if (!Okk(build)) { Console.WriteLine("BUILD FAIL: " + ErrOf(build)); return 1; }
	var p0 = build.GetProperty("psbt").GetString()!;

	// chain-level signing keys (THE FIX): account.Derive(0) for the receiving chain
	string ownerChain = ownerAcct.Derive(0).ToString(net);
	string c1Chain    = c1Acct.Derive(0).ToString(net);

	Console.WriteLine("\n--- A) OLD (buggy) way: sign with the ACCOUNT xprv (parallel) ---");
	var oa  = P(gp.SignLegacyPsbt(p0, seq, ownerAcct.ToString(net), "regtest"));
	var ob  = P(gp.SignLegacyPsbt(p0, seq, c1Acct.ToString(net), "regtest"));
	var oc  = Call(gp.CombineLegacyPsbts("[\"" + oa + "\",\"" + ob + "\"]", "regtest"));
	var ofn = Call(gp.FinalizeLegacyPsbt(oc.GetProperty("psbt").GetString()!, "regtest"));
	Console.WriteLine("   finalize success=" + Okk(ofn) + "  " + (Okk(ofn) ? "(UNEXPECTED - should fail)" : "err=" + ErrOf(ofn)));

	Console.WriteLine("\n--- B) FIX, PARALLEL signing: sign with the CHAIN xprv ---");
	var s1 = P(gp.SignLegacyPsbt(p0, seq, ownerChain, "regtest"));
	var s2 = P(gp.SignLegacyPsbt(p0, seq, c1Chain, "regtest"));
	var cb = Call(gp.CombineLegacyPsbts("[\"" + s1 + "\",\"" + s2 + "\"]", "regtest"));
	var f1 = Call(gp.FinalizeLegacyPsbt(cb.GetProperty("psbt").GetString()!, "regtest"));
	Console.WriteLine("   finalize success=" + Okk(f1) + "  " + (Okk(f1) ? "txid=" + f1.GetProperty("txId").GetString() : "err=" + ErrOf(f1)));

	Console.WriteLine("\n--- C) FIX, SEQUENTIAL signing (like GeneXus: signer2 signs the received PSBT) ---");
	var q1 = P(gp.SignLegacyPsbt(p0, seq, ownerChain, "regtest"));           // initiator signs p0
	var fInit = Call(gp.FinalizeLegacyPsbt(q1, "regtest"));                  // expect fail (1 sig)
	Console.WriteLine("   after 1 sig finalize success=" + Okk(fInit) + " (expected false) err=" + ErrOf(fInit));
	var q2 = P(gp.SignLegacyPsbt(q1, seq, c1Chain, "regtest"));              // signer2 signs the already-1-signed psbt
	var cq = Call(gp.CombineLegacyPsbts("[\"" + q1 + "\",\"" + q2 + "\"]", "regtest"));
	var f2 = Call(gp.FinalizeLegacyPsbt(cq.GetProperty("psbt").GetString()!, "regtest"));
	Console.WriteLine("   finalize success=" + Okk(f2) + "  " + (Okk(f2) ? "txid=" + f2.GetProperty("txId").GetString() : "err=" + ErrOf(f2)));

	return 0;
}

try
{
	var net = Network.RegTest;
	Console.WriteLine("== Legacy (SegWit P2SH-P2WSH) 2-of-3 multisig — regtest end-to-end ==");

	using var nb = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, net, "legacyMultiSigTest");
	var rpc = nb.CreateNode().CreateRPCClient();
	nb.StartAll();
	rpc.Generate(net.Consensus.CoinbaseMaturity + 10);

	// Participants: owner + 2 contacts (owner is a member too), threshold 2.
	var ownerExt = new ExtKey();
	var c1Ext = new ExtKey();
	var c2Ext = new ExtKey();

	// Separate chain-level keys per participant for the receiving and change chains
	// (BIP48: neuter(m/48'/coin'/account'/1'/0) vs .../1).
	var ownerChg = new ExtKey();
	var c1Chg = new ExtKey();
	var c2Chg = new ExtKey();

	var group = new GroupSDT
	{
		GroupId = Guid.NewGuid(),
		GroupName = "Legacy MultiSig Test",
		MinimumShares = 2,
		AmIGroupOwner = true,
		IsActive = true,
		ExtPubKeyMultiSigReceiving = ownerExt.Neuter().ToString(net),
		ExtPubKeyMultiSigChange = ownerChg.Neuter().ToString(net)
	};
	group.Contact.Add(new ContactItem { ContactId = Guid.NewGuid(), ContactUserName = "bob", ExtPubKeyMultiSigReceiving = c1Ext.Neuter().ToString(net), ExtPubKeyMultiSigChange = c1Chg.Neuter().ToString(net) });
	group.Contact.Add(new ContactItem { ContactId = Guid.NewGuid(), ContactUserName = "carol", ExtPubKeyMultiSigReceiving = c2Ext.Neuter().ToString(net), ExtPubKeyMultiSigChange = c2Chg.Neuter().ToString(net) });

	var gp = new GroupProcessor();
	if (!gp.FromSDT(group)) return Fail("FromSDT returned false");

	const int seq = 0;

	// 1) Build the 2-of-3 SegWit address on the receiving chain.
	var addrRes = Call(gp.CreateLegacyAddress(seq, false, "regtest"));
	if (!Okk(addrRes)) return Fail("CreateLegacyAddress: " + ErrOf(addrRes));
	var addrStr = addrRes.GetProperty("address").GetString()!;
	var address = BitcoinAddress.Create(addrStr, net);
	Console.WriteLine($"address (k={addrRes.GetProperty("k").GetInt32()} of n={addrRes.GetProperty("n").GetInt32()}) = {addrStr}");

	// 1b) The change chain must derive a distinct address from a distinct set of chain-level xpubs.
	var chgRes = Call(gp.CreateLegacyAddress(seq, true, "regtest"));
	if (!Okk(chgRes)) return Fail("CreateLegacyAddress(change): " + ErrOf(chgRes));
	if (chgRes.GetProperty("address").GetString() == addrStr) return Fail("change address must differ from receiving address");
	Console.WriteLine($"change address = {chgRes.GetProperty("address").GetString()} (differs from receiving)");

	// 2) Fund it.
	var fundAmount = Money.Coins(1.0m);
	var fundTxId = rpc.SendToAddress(address, fundAmount);
	rpc.Generate(1);
	var fundTx = rpc.GetRawTransaction(fundTxId);
	var fundOut = fundTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
	Console.WriteLine($"funded: txid={fundTxId} vout={fundOut.N}");

	// 3) Build the unsigned spending PSBT.
	var utxosJson = JsonSerializer.Serialize(new[]
	{
		new { TxId = fundTxId.ToString(), Vout = (int)fundOut.N, AmountBtc = "1.0" }
	});
	var dest = rpc.GetNewAddress();
	var change = rpc.GetNewAddress();
	var buildRes = Call(gp.BuildLegacyPsbt(utxosJson, dest.ToString(), "0.5", change.ToString(), "0.0001", false, seq, false, "regtest"));
	if (!Okk(buildRes)) return Fail("BuildLegacyPsbt: " + ErrOf(buildRes));
	var unsignedPsbt = buildRes.GetProperty("psbt").GetString()!;

	// 4) Two members each sign their own copy (distributed signing).
	string Sign(ExtKey k)
	{
		var r = Call(gp.SignLegacyPsbt(unsignedPsbt, seq, k.ToString(net), "regtest"));
		if (!Okk(r)) throw new Exception("SignLegacyPsbt: " + ErrOf(r));
		return r.GetProperty("psbt").GetString()!;
	}
	var signedOwner = Sign(ownerExt);
	var signedC1 = Sign(c1Ext);

	// 5) Combine the partial signatures.
	var combRes = Call(gp.CombineLegacyPsbts(JsonSerializer.Serialize(new[] { signedOwner, signedC1 }), "regtest"));
	if (!Okk(combRes)) return Fail("CombineLegacyPsbts: " + ErrOf(combRes));
	var combinedPsbt = combRes.GetProperty("psbt").GetString()!;

	// 6) Finalize -> raw tx.
	var finRes = Call(gp.FinalizeLegacyPsbt(combinedPsbt, "regtest"));
	if (!Okk(finRes)) return Fail("FinalizeLegacyPsbt: " + ErrOf(finRes));
	var txHex = finRes.GetProperty("txHex").GetString()!;
	var txId = finRes.GetProperty("txId").GetString()!;

	// 7) Broadcast + confirm on regtest.
	var finalTx = Transaction.Parse(txHex, net);
	var bcId = rpc.SendRawTransaction(finalTx);
	rpc.Generate(1);
	var confirmed = rpc.GetRawTransaction(uint256.Parse(bcId.ToString()));
	if (confirmed == null) return Fail("broadcast tx not found on node");

	Console.WriteLine($"PASS: 2-of-3 SegWit multisig spent & confirmed. txid={bcId} vsize={confirmed.GetVirtualSize()} vbytes");
	return 0;
}
catch (Exception e)
{
	return Fail(e.ToString());
}
