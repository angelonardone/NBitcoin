using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using NBitcoin;
using DistricutedCryptographyLib;

// Checks of "Legacy Multisignature" (SegWit P2SH-P2WSH N-of-M) and Delegated through GroupProcessor / DelegatedProcessor,
// the way GeneXus uses them. The end-to-end payment on a regtest node is `legacy-levels-node`.
// The old single-PSBT flow (vector2, gxsim and the end-to-end run without arguments) was removed on 2026-10-17
// together with BuildLegacyPsbt / SignLegacyPsbt / CombineLegacyPsbts / FinalizeLegacyPsbt.

// Legacy multisig payments with pre-signed fee levels through GroupProcessor: see LegacyLevelsSpike.cs.
if (args.Length > 0 && args[0].StartsWith("legacy-levels"))
	return LegacyLevelsSpike.Run(args);

// The "Multi Signature" groups (TaprootMultiSig, no owner): see MultiSigSpike.cs.
if (args.Length > 0 && args[0].StartsWith("multisig"))
	return MultiSigSpike.Run(args);

// Offline checks of the Delegated multisig with pre-signed fee levels: see DelegatedSpike.cs.
if (args.Length > 0 && args[0].StartsWith("delegated"))
	return DelegatedSpike.Run(args);

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

Console.WriteLine("usage: TestLegacyMultiSig legacy-levels | legacy-levels-node | delegated... | multisig | multisig-node | vector | checks");
return 1;
