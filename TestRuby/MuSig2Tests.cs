using System.Text.Json;
using DistricutedCryptographyLib;
using NBitcoin;
using NBitcoin.RPC;

// 2026-11-17: the MuSig2 groups (Advanced Delegated Multi Signature = GroupType 80, Advanced Multi Signature = 90) with
// a Ruby wallet. Needs the CI emulator and the local RegTest node:
//   TESTRUBY_GROUPS=musig2 dotnet run -c Release -- groups tcp:127.0.0.1:<port>
internal static class MuSig2Tests
{
	private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;

	public static void Run(string device, string mnemonic, Network net, RPCClient rpc, RubyClient ruby, string dest,
		Action<string, bool, string> check)
	{
		var uart = new GroupTests.FirmwareLog(ruby);
		RunRegistration(device, mnemonic, net, rpc, ruby, uart, check);
		RunOwner(device, mnemonic, net, rpc, ruby, dest, uart, check);
		RunRooms(device, mnemonic, net, rpc, ruby, dest, uart, check);
		// the firmware's measurements (log build): time of a group address, stack left in the temporary tasks
		var measured = uart.Lines("stack left").ToList();
		int Number(string line, string pattern)
		{
			var m = System.Text.RegularExpressions.Regex.Match(line, pattern);
			return m.Success ? int.Parse(m.Groups[1].Value) : -1;
		}
		Console.WriteLine($"-- firmware measurements ({measured.Count} lines): least stack left of each task, slowest group address");
		foreach (var kind in new[] { "Group ", "MuSig2 nonce", "MuSig2 partial" })
		{
			var lines = measured.Where(l => l.Contains(kind)).ToList();
			if (lines.Count > 0)
				Console.WriteLine($"   {kind.Trim()}: {lines.Min(l => Number(l, @"(\d+) bytes of stack"))} bytes of stack left (of 12288), {lines.Count} runs");
		}
		var slowest = measured.Where(l => l.Contains("Group ")).OrderByDescending(l => Number(l, @": (\d+) ms")).FirstOrDefault();
		if (slowest != null)
			Console.WriteLine("   slowest: " + slowest);
	}

	// Phase C: MuSig2 groups registered on Ruby (types musig2-delegated / musig2-multisig): Ruby calculates exactly the
	// library's addresses (MuSig2 leaves: one KeyAgg per leaf), for several sizes, Ruby as owner, creator or member.
	private static void RunRegistration(string device, string mnemonic, Network net, RPCClient rpc, RubyClient ruby,
		GroupTests.FirmwareLog uart, Action<string, bool, string> check)
	{
		Console.WriteLine("== MuSig2 groups registered on Ruby");
		ruby.DebugCleanReset();
		ruby.DebugSetMnemonic(mnemonic);
		var taproot = KeyPath.Parse("m/86'/1'/0'");
		var rubyT = ExtPubKey.Parse(ruby.GetXpub(net, taproot), net);
		ContactItem Member(string name, ExtPubKey account) => new ContactItem
		{ ContactUserName = name, ExtPubKeyMultiSigReceiving = X(account.Derive(2), net), ExtPubKeyMultiSigChange = X(account.Derive(3), net) };
		// n participants with keys in the leaves (80: the members; 90: every signer, the creator included); k sign
		GroupSDT Shape(bool advMulti, int n, int k, string rubyRole, string label)
		{
			var others = Enumerable.Range(0, n + 1).Select(_ => new ExtKey().Derive(taproot).Neuter()).ToList();
			var ownerKey = rubyRole == "owner" || rubyRole == "creator" ? rubyT : others[n];
			var contacts = new List<ContactItem>();
			for (int i = 0; i < (advMulti ? n - 1 : n); i++)
			{
				var isRuby = rubyRole == "member" && i == 0;
				contacts.Add(Member(isRuby ? "Ruby" : $"P{i}", isRuby ? rubyT : others[i]));
			}
			return new GroupSDT
			{
				GroupId = Guid.NewGuid(), GroupType = (short)(advMulti ? 90 : 80), GroupName = label,
				AmIGroupOwner = rubyRole == "owner" || rubyRole == "creator", IsActive = true, MinimumShares = (short)k,
				ExtPubKeyMultiSigReceiving = X(ownerKey.Derive(2), net), ExtPubKeyMultiSigChange = X(ownerKey.Derive(3), net),
				Contact = contacts
			};
		}
		var shapes = new (bool advMulti, int n, int k, string role)[]
		{
			(false, 3, 2, "owner"), (false, 3, 2, "member"), (false, 6, 3, "member"), (false, 15, 2, "member"),
			(true, 2, 2, "creator"), (true, 3, 2, "creator"), (true, 4, 3, "member"), (true, 11, 5, "member"),
		};
		foreach (var (advMulti, n, k, role) in shapes)
		{
			var label = $"{(advMulti ? "AM" : "AD")} {k}of{n} {role}";
			var group = Shape(advMulti, n, k, role, label);
			var mp = new MuSig2Processor();
			mp.FromSDT(group);
			var record = MuSig2GroupSpend.RubyGroupRecord(group, net);
			var watch = System.Diagnostics.Stopwatch.StartNew();
			string error = "";
			try
			{
				ruby.RegisterGroup(net, record.name, record.label, record.type, record.k, record.owner, record.signers, taproot.Derive(2), taproot.Derive(3));
			}
			catch (RubyException e) { error = e.Message; }
			var regMs = watch.ElapsedMilliseconds;
			check($"register {label} ({record.type})", error.Length == 0, error + $" ({regMs} ms)");
			if (error.Length > 0)
				continue;
			var same = true;
			var detail = "";
			long addrMs = 0;
			foreach (var isChange in new[] { false, true })
			{
				foreach (var index in new uint[] { 0, 1, 7 })
				{
					watch.Restart();
					var fromRuby = ruby.GetGroupAddress(net, record.name, isChange, index);
					addrMs = Math.Max(addrMs, watch.ElapsedMilliseconds);
					var fromLib = J(mp.CreateAddress((int)index, isChange, "RegTest")).GetProperty("address").GetString()!;
					if (fromRuby != fromLib)
					{
						same = false;
						detail = $"{(isChange ? "change" : "receiving")} {index}: Ruby {fromRuby} library {fromLib}";
					}
				}
			}
			check($"Ruby's addresses = the library's: {label}", same, detail.Length > 0 ? detail : $"register {regMs} ms, an address at most {addrMs} ms");
		}
		var groups = ruby.GetRegisteredGroups();
		check("get_registered_groups names the MuSig2 types",
			groups.Values.OfType<IDictionary<string, object?>>().Any(g => g["type"] as string == "musig2-delegated")
			&& groups.Values.OfType<IDictionary<string, object?>>().Any(g => g["type"] as string == "musig2-multisig"), "");
		// every registration is removed again: the payments below register their own groups
		ruby.DebugCleanReset();
		ruby.DebugSetMnemonic(mnemonic);
	}

	// Phase B: Ruby signs in a signing room (round 1 musig2_nonces, round 2 sign_psbt with every public nonce), with
	// software signers: Advanced Delegated (80) by a leaf, Advanced Multi Signature (90) by the key path (everybody)
	// and by a leaf; then the refusals.
	private static void RunRooms(string device, string mnemonic, Network net, RPCClient rpc, RubyClient ruby, string dest,
		GroupTests.FirmwareLog uart, Action<string, bool, string> check)
	{
		Console.WriteLine("== MuSig2 signing rooms with a Ruby signer");
		var taproot = KeyPath.Parse("m/86'/1'/0'");
		var rubyT = ExtPubKey.Parse(ruby.GetXpub(net, taproot), net);
		var rr = X(rubyT.Derive(2), net);
		var rc = X(rubyT.Derive(3), net);
		var o = new ExtKey().Derive(taproot);
		var s1 = new ExtKey().Derive(taproot);
		var s2 = new ExtKey().Derive(taproot);
		// software signers by name (Ruby is "Ruby" in the 80 group, "owner" = the creator in the 90 group)
		var software = new Dictionary<string, ExtKey> { ["S1"] = s1, ["S2"] = s2, ["O"] = o };
		ContactItem Contact(string name, ExtPubKey account) => new ContactItem
		{ ContactUserName = name, ExtPubKeyMultiSigReceiving = X(account.Derive(2), net), ExtPubKeyMultiSigChange = X(account.Derive(3), net) };

		// 80: the owner O is software; the members are Ruby, S1 and S2; 2 of 3 (another owner = another group for Ruby)
		GroupSDT G80(ExtKey? owner = null) => new GroupSDT
		{
			GroupId = Guid.NewGuid(), GroupType = 80, GroupName = "Advanced Delegated room", AmIGroupOwner = false, IsActive = true,
			MinimumShares = 2,
			ExtPubKeyMultiSigReceiving = X((owner ?? o).Derive(2).Neuter(), net), ExtPubKeyMultiSigChange = X((owner ?? o).Derive(3).Neuter(), net),
			Contact = new List<ContactItem> { Contact("Ruby", rubyT), Contact("S1", s1.Neuter()), Contact("S2", s2.Neuter()) }
		};
		// 90: Ruby created it (the "owner", one more signer); S1 and S2; 2 of 3
		GroupSDT G90() => new GroupSDT
		{
			GroupId = Guid.NewGuid(), GroupType = 90, GroupName = "Advanced Multi room", AmIGroupOwner = true, IsActive = true,
			MinimumShares = 2,
			ExtPubKeyMultiSigReceiving = rr, ExtPubKeyMultiSigChange = rc,
			Contact = new List<ContactItem> { Contact("S1", s1.Neuter()), Contact("S2", s2.Neuter()) }
		};

		// builds a funded session (2 coins: receiving 0 and change 1)
		(MuSig2Processor mp, string session) Session(GroupSDT g, string signersJson, string amount = "0.7")
		{
			var mp = new MuSig2Processor();
			mp.FromSDT(g);
			string Addr(int seq, bool isChange) => J(mp.CreateAddress(seq, isChange, "RegTest")).GetProperty("address").GetString()!;
			var utxos = new List<object> { Fund(rpc, net, Addr(0, false), 0, false, 0.6m), Fund(rpc, net, Addr(1, true), 1, true, 0.4m) };
			rpc.Generate(1);
			var built = J(mp.BuildSession(JsonSerializer.Serialize(utxos), dest, amount, Addr(2, true), 2, "0.0002", false, signersJson, "RegTest"));
			if (!built.GetProperty("success").GetBoolean())
				throw new Exception("BuildSession: " + built.GetProperty("error").GetString());
			return (mp, built.GetProperty("session").GetString()!);
		}

		bool IsRuby(string name) => name == "Ruby" || name == "owner";
		JsonElement Nonces(MuSig2Processor mp, string session, string name) => IsRuby(name)
			? J(mp.CreateNoncesWithRuby(session, device, rr, rc, "RegTest"))
			: J(mp.CreateNonces(session, X(software[name].Derive(2).Neuter(), net), X(software[name].Derive(3).Neuter(), net), "RegTest"));
		JsonElement Partials(MuSig2Processor mp, string session, string noncesJson, string name) => IsRuby(name)
			? J(mp.SignWithRuby(session, noncesJson, device, rr, rc, "RegTest"))
			: J(mp.Sign(session, noncesJson, software[name].Derive(2).ToString(net), software[name].Derive(3).ToString(net), "RegTest"));
		string Map(Dictionary<string, string> arrays) =>
			"{" + string.Join(",", arrays.Select(p => JsonSerializer.Serialize(p.Key) + ":" + p.Value)) + "}";

		// a whole payment: Ruby joins (the group registered then, as the app does at Open room / I'm here), round 1,
		// round 2 (never a registration: 2026-11-17), finalize, mined. register = false: the registration declined.
		void Pay(GroupSDT g, string signersJson, string[] names, string what, bool register = true)
		{
			var (mp, session) = Session(g, signersJson);
			if (register && names.Any(IsRuby))
			{
				var reg = J(mp.RegisterGroupWithRuby(device, rr, rc, "RegTest"));
				var status = reg.TryGetProperty("status", out var st) ? st.GetString() ?? "" : "";
				check($"{what}: the group registered on Ruby when it joins ({status})",
					reg.GetProperty("success").GetBoolean() && (status == "registered" || status == "already registered"),
					reg.GetProperty("error").GetString() + " " + status);
			}
			var nonces = new Dictionary<string, string>();
			foreach (var name in names)
			{
				var r = Nonces(mp, session, name);
				check($"{what}: {name} round 1", r.GetProperty("success").GetBoolean(), r.GetProperty("error").GetString()!);
				if (!r.GetProperty("success").GetBoolean()) return;
				nonces[r.GetProperty("signer").GetString()!] = r.GetProperty("publicNonces").GetString()!;
			}
			var partials = new Dictionary<string, string>();
			foreach (var name in names)
			{
				if (IsRuby(name))
					uart.Mark();
				var r = Partials(mp, session, Map(nonces), name);
				check($"{what}: {name} round 2", r.GetProperty("success").GetBoolean(), r.GetProperty("error").GetString()!);
				if (IsRuby(name))
				{
					uart.Check(check, register ? $"{what}: Ruby recognises the group's change" : $"{what}: not registered, Ruby shows the change",
						"group change address validated", register);
					uart.Check(check, $"{what}: round 2 asks no registration", "first address", false);
				}
				if (!r.GetProperty("success").GetBoolean()) return;
				partials[r.GetProperty("signer").GetString()!] = r.GetProperty("partialSignatures").GetString()!;
			}
			var fin = J(mp.Finalize(session, Map(nonces), Map(partials), "RegTest"));
			check($"{what}: finalized", fin.GetProperty("success").GetBoolean(), fin.GetProperty("error").GetString()!);
			if (fin.GetProperty("success").GetBoolean())
				Mined(rpc, net, fin, $"{what}: accepted by the node and mined", check);
		}

		Pay(G80(), "[\"Ruby\",\"S1\"]", new[] { "Ruby", "S1" }, "80 leaf (Ruby + S1)");
		Pay(G80(), "[\"S2\",\"Ruby\"]", new[] { "S2", "Ruby" }, "80 leaf (S2 first, Ruby last)");
		Pay(G90(), "all", new[] { "owner", "S1", "S2" }, "90 key path (Ruby + S1 + S2)");
		Pay(G90(), "[\"owner\",\"S2\"]", new[] { "owner", "S2" }, "90 leaf (Ruby + S2)");
		Pay(G80(new ExtKey().Derive(taproot)), "[\"Ruby\",\"S1\"]", new[] { "Ruby", "S1" }, "80 leaf, group not registered", register: false);
		{
			// a Ruby that does not hold the member's keys can not join (round 1 would abort the room)
			var mp = new MuSig2Processor();
			mp.FromSDT(G80());
			var other = new ExtKey().Derive(taproot).Neuter();
			var reg = J(mp.RegisterGroupWithRuby(device, X(other.Derive(2), net), X(other.Derive(3), net), "RegTest"));
			check("refusal: a Ruby without the member's keys can not join", !reg.GetProperty("success").GetBoolean(), reg.GetProperty("error").GetString()!);
		}

		// --- refusals ---
		{
			var g = G80();
			var (mp, a) = Session(g, "[\"Ruby\",\"S1\"]", "0.7");
			var (_, b) = Session(g, "[\"Ruby\",\"S1\"]", "0.5");
			var ra = Nonces(mp, a, "Ruby");
			var sa = Nonces(mp, a, "S1");
			var mapA = Map(new Dictionary<string, string> { ["Ruby"] = ra.GetProperty("publicNonces").GetString()!, ["S1"] = sa.GetProperty("publicNonces").GetString()! });
			// another payment's round 1 replaces Ruby's nonces of the first one
			var rb = Nonces(mp, b, "Ruby");
			check("refusal: nonces of another payment made", rb.GetProperty("success").GetBoolean(), rb.GetProperty("error").GetString()!);
			var r = Partials(mp, a, mapA, "Ruby");
			check("refusal: the nonces of a payment are gone after another payment's round 1", !r.GetProperty("success").GetBoolean() && r.GetProperty("error").GetString()!.Contains("nonces"), r.GetProperty("error").GetString()!);

			// signed once: no second signature with the same nonces
			ra = Nonces(mp, a, "Ruby");
			mapA = Map(new Dictionary<string, string> { ["Ruby"] = ra.GetProperty("publicNonces").GetString()!, ["S1"] = sa.GetProperty("publicNonces").GetString()! });
			r = Partials(mp, a, mapA, "Ruby");
			check("refusal: Ruby signs with fresh nonces", r.GetProperty("success").GetBoolean(), r.GetProperty("error").GetString()!);
			r = Partials(mp, a, mapA, "Ruby");
			check("refusal: Ruby does not sign twice with the same nonces", !r.GetProperty("success").GetBoolean() && r.GetProperty("error").GetString()!.Contains("nonces"), r.GetProperty("error").GetString()!);

			// a round 2 that does not carry Ruby's own nonce: refused, and the nonce is gone (no retry with it)
			ra = Nonces(mp, a, "Ruby");
			var swapped = Map(new Dictionary<string, string> { ["Ruby"] = sa.GetProperty("publicNonces").GetString()!, ["S1"] = ra.GetProperty("publicNonces").GetString()! });
			r = Partials(mp, a, swapped, "Ruby");
			check("refusal: a round 2 without Ruby's own nonce", !r.GetProperty("success").GetBoolean() && r.GetProperty("error").GetString()!.Contains("nonce this Ruby made"), r.GetProperty("error").GetString()!);
			mapA = Map(new Dictionary<string, string> { ["Ruby"] = ra.GetProperty("publicNonces").GetString()!, ["S1"] = sa.GetProperty("publicNonces").GetString()! });
			r = Partials(mp, a, mapA, "Ruby");
			check("refusal: after a refused round 2 the nonce can not be used", !r.GetProperty("success").GetBoolean() && r.GetProperty("error").GetString()!.Contains("nonces"), r.GetProperty("error").GetString()!);

			// Ruby is not among the signers of the payment
			var (mp2, c) = Session(g, "[\"S1\",\"S2\"]");
			r = Nonces(mp2, c, "Ruby");
			check("refusal: Ruby is not a signer of the payment", !r.GetProperty("success").GetBoolean(), r.GetProperty("error").GetString()!);

			// the firmware's own checks, with PSBTs altered after the library built them
			var fingerprint = ruby.GetMasterFingerprint(net);
			PSBT Psbt() => MuSig2GroupSpend.RubyMuSig2PsbtForTests(g, a, "", rubyT.Derive(2), rubyT.Derive(3), fingerprint, net);
			string Refused(Action<PSBT> alter)
			{
				var psbt = Psbt();
				alter(psbt);
				try { ruby.Musig2Nonces(psbt); return ""; }
				catch (RubyException e) { return e.Message; }
			}
			var participants = Psbt().Inputs[0].Unknown.Keys.First(k => k[0] == 0x1a);
			var e1 = Refused(p =>
			{
				foreach (var input in p.Inputs)
				{
					var key = input.Unknown.Keys.First(k => k[0] == 0x1a);
					var value = input.Unknown[key];
					// another key instead of the second participant
					var other = new Key().PubKey.Compress().ToBytes();
					Array.Copy(other, 0, value, 33, 33);
				}
			});
			check("firmware: participants that do not aggregate to the key named are refused", e1.Length > 0, e1);
			var e2 = Refused(p =>
			{
				foreach (var input in p.Inputs)
				{
					var key = input.Unknown.Keys.First(k => k[0] == 0x1a);
					var value = input.Unknown[key];
					input.Unknown.Remove(key);
					var other = (byte[])key.Clone();
					other[1] ^= 1; // the other parity
					input.Unknown[other] = value;
				}
			});
			check("firmware: a wrong aggregate key is refused", e2.Length > 0, e2);
			var e3 = Refused(p =>
			{
				foreach (var input in p.Inputs)
					input.WitnessUtxo = new TxOut(input.WitnessUtxo!.Value, new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, net));
			});
			check("firmware: a leaf that is not in the coin spent is refused", e3.Length > 0, e3);
			var ok = Refused(_ => { });
			check("firmware: the unaltered PSBT gets nonces", ok.Length == 0 && participants.Length == 34, ok);
		}
	}

	private static string X(ExtPubKey k, Network net) => k.ToString(net);

	// pays btc to address sequence/chain of the group, returns the utxo as the KB gives it
	private static object Fund(RPCClient rpc, Network net, string addr, int seq, bool isChange, decimal btc)
	{
		var txid = rpc.SendToAddress(BitcoinAddress.Create(addr, net), Money.Coins(btc));
		var vout = rpc.GetRawTransaction(txid).Outputs.FindIndex(o => o.ScriptPubKey == BitcoinAddress.Create(addr, net).ScriptPubKey);
		return new { TxId = txid.ToString(), Vout = vout, AmountBtc = btc.ToString(System.Globalization.CultureInfo.InvariantCulture), Sequence = seq, IsChange = isChange, Address = addr };
	}

	private static void Mined(RPCClient rpc, Network net, JsonElement r, string what, Action<string, bool, string> check)
	{
		var txid = rpc.SendRawTransaction(Transaction.Parse(r.GetProperty("txHex").GetString()!, net));
		rpc.Generate(1);
		check(what, rpc.GetRawTransactionInfo(txid).Confirmations >= 1,
			$"{txid} vsize {r.GetProperty("vsize").GetInt32()} fee {r.GetProperty("feeBtc").GetDecimal()}");
	}

	// Phase A: a Delegated MultiSig 2 (80) whose OWNER is a Ruby wallet spends alone by the key path (the merkle root of
	// the MuSig2 leaves). Two software members, 2 of 2.
	private static void RunOwner(string device, string mnemonic, Network net, RPCClient rpc, RubyClient ruby, string dest,
		GroupTests.FirmwareLog uart, Action<string, bool, string> check)
	{
		Console.WriteLine("== Advanced Delegated (MuSig2): a Ruby owner spends alone");
		var taproot = KeyPath.Parse("m/86'/1'/0'");
		var rubyTaproot = ExtPubKey.Parse(ruby.GetXpub(net, taproot), net);
		var m1 = new ExtKey().Derive(taproot);
		var m2 = new ExtKey().Derive(taproot);
		GroupSDT Group() => new GroupSDT
		{
			GroupId = Guid.NewGuid(), GroupType = 80, GroupName = "Advanced Delegated Ruby", AmIGroupOwner = true, IsActive = true,
			MinimumShares = 2,
			ExtPubKeyMultiSigReceiving = X(rubyTaproot.Derive(2), net), ExtPubKeyMultiSigChange = X(rubyTaproot.Derive(3), net),
			Contact = new List<ContactItem>
			{
				new ContactItem { ContactUserName = "M1", ExtPubKeyMultiSigReceiving = X(m1.Derive(2).Neuter(), net), ExtPubKeyMultiSigChange = X(m1.Derive(3).Neuter(), net) },
				new ContactItem { ContactUserName = "M2", ExtPubKeyMultiSigReceiving = X(m2.Derive(2).Neuter(), net), ExtPubKeyMultiSigChange = X(m2.Derive(3).Neuter(), net) },
			}
		};
		var mp = new MuSig2Processor();
		check("MuSig2 FromSDT (Ruby owner)", mp.FromSDT(Group()), "");
		string Addr(int seq, bool isChange) => J(mp.CreateAddress(seq, isChange, "RegTest")).GetProperty("address").GetString()!;
		var utxos = new List<object> { Fund(rpc, net, Addr(0, false), 0, false, 0.6m), Fund(rpc, net, Addr(1, true), 1, true, 0.4m) };
		rpc.Generate(1);
		var change = Addr(2, true);
		uart.Mark();
		var r = J(mp.OwnerSpendWithRuby(JsonSerializer.Serialize(utxos), dest, "0.7", change, "0.0001", false, device,
			X(rubyTaproot.Derive(2), net), X(rubyTaproot.Derive(3), net), "RegTest"));
		check("MuSig2: Ruby owner signs alone (key path, 2 inputs of 2 chains)", r.GetProperty("success").GetBoolean(), r.GetProperty("error").GetString()!);
		uart.Check(check, "MuSig2 owner: the group registered on the first payment, its change recognised", "group change address validated", true);
		if (r.GetProperty("success").GetBoolean())
			Mined(rpc, net, r, "Advanced Delegated (Ruby owner) accepted by the node and mined", check);

		var other = new ExtKey().Derive(taproot);
		var bad = J(mp.OwnerSpendWithRuby(JsonSerializer.Serialize(utxos), dest, "0.1", change, "0.0001", false, device,
			X(other.Derive(2).Neuter(), net), X(other.Derive(3).Neuter(), net), "RegTest"));
		check("MuSig2: keys that are not the owner's are refused", !bad.GetProperty("success").GetBoolean(), bad.GetProperty("error").GetString()!);

		ruby.DebugSetMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
		var wrong = J(mp.OwnerSpendWithRuby(JsonSerializer.Serialize(utxos), dest, "0.1", change, "0.0001", false, device,
			X(rubyTaproot.Derive(2), net), X(rubyTaproot.Derive(3), net), "RegTest"));
		check("MuSig2: a Ruby with other words is refused (owner)", !wrong.GetProperty("success").GetBoolean() && wrong.GetProperty("error").GetString()!.Contains("does not hold"), wrong.GetProperty("error").GetString()!);
		ruby.DebugSetMnemonic(mnemonic);
	}
}
