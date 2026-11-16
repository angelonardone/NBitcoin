using System.Text.Json;
using DistricutedCryptographyLib;
using NBitcoin;
using NBitcoin.RPC;

// Group payments where one member is a Ruby (2026-11-13). Legacy MultiSig (P2SH-P2WSH, BIP48): the library has
// only the Ruby member's chain-level xpubs and Ruby signs each fee level (LegacyMultiSig.SignSpendWithRuby).
// Needs the CI emulator (auto-confirms) and the local RegTest node (D:\KBBridge-externalizations\regtest):
//   dotnet run -c Release -- groups tcp:127.0.0.1:30131 [http://dc:dcregtest@127.0.0.1:18443]
internal static class GroupTests
{
	private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;

	private static RubyClient ProcessorClient(string device)
	{
		var field = typeof(RubyProcessor).GetField("Clients",
			System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
		return ((Dictionary<string, RubyClient>)field.GetValue(null)!)[device];
	}

	public static void Run(string device, string mnemonic, string rpcUrl, Action<string, bool, string> check)
	{
		Console.WriteLine("== Legacy MultiSig with a Ruby member");
		var net = Network.RegTest;
		var uri = new Uri(rpcUrl);
		var rpc = new RPCClient(uri.UserInfo, new Uri($"{uri.Scheme}://{uri.Host}:{uri.Port}/wallet/miner"), net);

		// the Ruby holds the test words; prepare it through the processor's own connection
		var processor = new RubyProcessor();
		J(processor.Status(device));
		var ruby = ProcessorClient(device);
		ruby.DebugSetMnemonic(mnemonic);

		var accountPath = KeyPath.Parse("m/48'/1'/0'/1'");
		var masterA = new ExtKey();
		var masterB = new ExtKey();
		var a = masterA.Derive(accountPath); // owner, software
		var b = masterB.Derive(accountPath); // contact, software
		var rubyAccount = ExtPubKey.Parse(ruby.GetXpub(net, accountPath), net);
		var rubyFingerprint = ruby.GetMasterFingerprint(net);
		var mnemonicAccount = new Mnemonic(mnemonic).DeriveExtKey().Derive(accountPath).Neuter();
		check("Ruby m/48'/1'/0'/1' = the words", rubyAccount.GetPublicKey() == mnemonicAccount.GetPublicKey(), "");

		string X(ExtPubKey k) => k.ToString(net);
		// the account key with its origin, as the wallet sends it since 2026-11-13: [fingerprint/48'/1'/0'/1']xpub
		string Origin(HDFingerprint fp, ExtPubKey account) => $"[{fp}/48'/1'/0'/1']{X(account)}";
		// withAccounts: a group made after 2026-11-13 (every member gave his account key: registered on Ruby)
		GroupSDT Group(int k, bool withAccounts = false) => new GroupSDT
		{
			GroupId = Guid.NewGuid(), GroupType = 50, GroupName = withAccounts ? "RubyReg" : "Legacy with Ruby", AmIGroupOwner = true, IsActive = true,
			MinimumShares = (short)k,
			ExtPubKeyMultiSigReceiving = X(a.Derive(0).Neuter()), ExtPubKeyMultiSigChange = X(a.Derive(1).Neuter()),
			ExtPubKeyMultiSigAccount = withAccounts ? Origin(masterA.GetPublicKey().GetHDFingerPrint(), a.Neuter()) : null,
			Contact = new List<ContactItem>
			{
				new ContactItem { ContactUserName = "B", ExtPubKeyMultiSigReceiving = X(b.Derive(0).Neuter()), ExtPubKeyMultiSigChange = X(b.Derive(1).Neuter()),
					ExtPubKeyMultiSigAccount = withAccounts ? Origin(masterB.GetPublicKey().GetHDFingerPrint(), b.Neuter()) : null },
				new ContactItem { ContactUserName = "Ruby", ExtPubKeyMultiSigReceiving = X(rubyAccount.Derive(0)), ExtPubKeyMultiSigChange = X(rubyAccount.Derive(1)),
					ExtPubKeyMultiSigAccount = withAccounts ? Origin(rubyFingerprint, rubyAccount) : null },
			}
		};

		// funds two addresses of the group (receiving 0 and change 1), so a payment spends coins of 2 chains
		List<object> Fund(GroupProcessor gp)
		{
			var utxos = new List<object>();
			foreach (var (seq, isChange, btc) in new[] { (0, false, 0.6m), (1, true, 0.4m) })
			{
				var addr = J(gp.CreateLegacyAddress(seq, isChange, "RegTest")).GetProperty("address").GetString()!;
				var txid = rpc.SendToAddress(BitcoinAddress.Create(addr, net), Money.Coins(btc));
				var tx = rpc.GetRawTransaction(txid);
				var vout = tx.Outputs.FindIndex(o => o.ScriptPubKey == BitcoinAddress.Create(addr, net).ScriptPubKey);
				utxos.Add(new { TxId = txid.ToString(), Vout = vout, AmountBtc = btc.ToString(System.Globalization.CultureInfo.InvariantCulture), Sequence = seq, IsChange = isChange, Address = addr });
			}
			rpc.Generate(1);
			return utxos;
		}

		string Broadcast(JsonElement r, string what)
		{
			var hex = r.GetProperty("txHex").GetString()!;
			var txid = rpc.SendRawTransaction(Transaction.Parse(hex, net));
			rpc.Generate(1);
			var confirmations = rpc.GetRawTransactionInfo(txid).Confirmations;
			check(what, confirmations >= 1, $"{txid} vsize {r.GetProperty("vsize").GetInt32()} fee {r.GetProperty("feeBtc").GetDecimal()}");
			return txid.ToString();
		}

		var dest = rpc.GetNewAddress().ToString();
		var gp = new GroupProcessor();

		// TESTRUBY_GROUPS=registration: only the group registration tests (RunGroupRegistration)
		if (Environment.GetEnvironmentVariable("TESTRUBY_GROUPS") == "registration")
		{
			RunGroupRegistration(device, mnemonic, net, rpc, ruby, dest, check);
			return;
		}

		// 1. software A starts with +10 % / +50 %, Ruby is the last signer and chooses +50 %
		{
			var g = Group(2);
			check("FromSDT 2of3", gp.FromSDT(g), "");
			var utxos = Fund(gp);
			var change = J(gp.CreateLegacyAddress(2, true, "RegTest")).GetProperty("address").GetString()!;
			var built = J(gp.BuildLegacySpend(JsonSerializer.Serialize(utxos), dest, "0.7", change, "0.0001", "10,50", false, "RegTest"));
			check("build 2of3", built.GetProperty("success").GetBoolean(), built.GetProperty("error").GetString()!);
			var s1 = J(gp.SignLegacySpend(built.GetProperty("bundle").GetString()!, a.Derive(0).ToString(net), a.Derive(1).ToString(net), -1, "RegTest"));
			check("software A signs the 3 levels", s1.GetProperty("success").GetBoolean() && s1.GetProperty("signatures").GetInt32() == 1, s1.GetProperty("error").GetString()!);
			var s2 = J(gp.SignLegacySpendWithRuby(s1.GetProperty("bundle").GetString()!, device, X(rubyAccount.Derive(0)), X(rubyAccount.Derive(1)), 50, "RegTest"));
			check("Ruby signs last, +50 %", s2.GetProperty("success").GetBoolean() && s2.GetProperty("complete").GetBoolean(), s2.GetProperty("error").GetString()!);
			if (s2.GetProperty("success").GetBoolean())
				Broadcast(s2, "2of3 (A + Ruby) accepted by the node and mined");
		}

		// 2. Ruby starts (signs the 3 levels on Ruby), software B is the last signer and chooses +10 %
		{
			var g = Group(2);
			gp.FromSDT(g);
			var utxos = Fund(gp);
			var change = J(gp.CreateLegacyAddress(2, true, "RegTest")).GetProperty("address").GetString()!;
			var built = J(gp.BuildLegacySpend(JsonSerializer.Serialize(utxos), dest, "0.7", change, "0.0001", "10,50", false, "RegTest"));
			var s1 = J(gp.SignLegacySpendWithRuby(built.GetProperty("bundle").GetString()!, device, X(rubyAccount.Derive(0)), X(rubyAccount.Derive(1)), -1, "RegTest"));
			check("Ruby starts: signs the 3 levels", s1.GetProperty("success").GetBoolean() && s1.GetProperty("signatures").GetInt32() == 1, s1.GetProperty("error").GetString()!);
			var again = J(gp.SignLegacySpendWithRuby(s1.GetProperty("bundle").GetString()!, device, X(rubyAccount.Derive(0)), X(rubyAccount.Derive(1)), -1, "RegTest"));
			check("Ruby can not sign twice", !again.GetProperty("success").GetBoolean(), again.GetProperty("error").GetString()!);
			var s2 = J(gp.SignLegacySpend(s1.GetProperty("bundle").GetString()!, b.Derive(0).ToString(net), b.Derive(1).ToString(net), 10, "RegTest"));
			check("software B signs last, +10 %", s2.GetProperty("success").GetBoolean() && s2.GetProperty("complete").GetBoolean(), s2.GetProperty("error").GetString()!);
			if (s2.GetProperty("success").GetBoolean())
				Broadcast(s2, "2of3 (Ruby + B) accepted by the node and mined");
		}

		// 3. 1 of 3: Ruby alone, the whole balance, calculated fee
		{
			var g = Group(1);
			gp.FromSDT(g);
			var utxos = Fund(gp);
			var built = J(gp.BuildLegacySpend(JsonSerializer.Serialize(utxos), dest, "0", "", "0.0001", "", true, "RegTest"));
			var s1 = J(gp.SignLegacySpendWithRuby(built.GetProperty("bundle").GetString()!, device, X(rubyAccount.Derive(0)), X(rubyAccount.Derive(1)), 0, "RegTest"));
			check("1of3: Ruby alone sends the whole balance", s1.GetProperty("success").GetBoolean() && s1.GetProperty("complete").GetBoolean(), s1.GetProperty("error").GetString()!);
			if (s1.GetProperty("success").GetBoolean())
				Broadcast(s1, "1of3 (Ruby) accepted by the node and mined");
		}

		// 4. a Ruby with other words is refused before anything is signed
		{
			var g = Group(2);
			gp.FromSDT(g);
			var utxos = new[] { new { TxId = new uint256(RandomUtils.GetBytes(32)).ToString(), Vout = 0, AmountBtc = "0.5", Sequence = 0, IsChange = false, Address = "" } };
			var built = J(gp.BuildLegacySpend(JsonSerializer.Serialize(utxos), dest, "0.1", J(gp.CreateLegacyAddress(1, true, "RegTest")).GetProperty("address").GetString()!, "0.0001", "", false, "RegTest"));
			ruby.DebugSetMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
			var s = J(gp.SignLegacySpendWithRuby(built.GetProperty("bundle").GetString()!, device, X(rubyAccount.Derive(0)), X(rubyAccount.Derive(1)), -1, "RegTest"));
			check("a Ruby with other words is refused", !s.GetProperty("success").GetBoolean() && s.GetProperty("error").GetString()!.Contains("does not hold"), s.GetProperty("error").GetString()!);
			ruby.DebugSetMnemonic(mnemonic);
		}

		// 5. a group whose members gave their account keys (2026-11-13): registered on Ruby, Ruby starts a payment with
		//    +10 % / +50 % (the 3 levels on ONE confirmation: the CI firmware confirms by itself, so the check is that
		//    Ruby signed every level and that the change carried the keys of the group), B is the last signer (+50 %)
		{
			var g = Group(2, withAccounts: true);
			gp.FromSDT(g);
			var sg = J(gp.GetLegacyDescriptor(true, "RegTest"));
			var utxos = Fund(gp);
			var change = J(gp.CreateLegacyAddress(2, true, "RegTest")).GetProperty("address").GetString()!;
			var built = J(gp.BuildLegacySpend(JsonSerializer.Serialize(utxos), dest, "0.7", change, "0.0001", "10,50", false, "RegTest"));
			var before = ruby.GetRegisteredMultisigs().Count;
			var s1 = J(gp.SignLegacySpendWithRuby(built.GetProperty("bundle").GetString()!, device, X(rubyAccount.Derive(0)), X(rubyAccount.Derive(1)), -1, "RegTest"));
			check("registered group: Ruby starts and signs the 3 levels", s1.GetProperty("success").GetBoolean() && s1.GetProperty("signatures").GetInt32() == 1, s1.GetProperty("error").GetString()!);
			var regs = ruby.GetRegisteredMultisigs();
			check("the group is registered on Ruby", regs.Keys.Any(k => k.StartsWith("RubyReg-")), string.Join(", ", regs.Keys) + $" (before: {before})");
			// the same payment again: the registration is identical, nothing new
			var again = J(gp.SignLegacySpendWithRuby(built.GetProperty("bundle").GetString()!, device, X(rubyAccount.Derive(0)), X(rubyAccount.Derive(1)), -1, "RegTest"));
			check("an identical registration adds nothing", again.GetProperty("success").GetBoolean() && ruby.GetRegisteredMultisigs().Count == regs.Count, again.GetProperty("error").GetString()!);
			var s2 = J(gp.SignLegacySpend(s1.GetProperty("bundle").GetString()!, b.Derive(0).ToString(net), b.Derive(1).ToString(net), 50, "RegTest"));
			check("software B signs last, +50 %", s2.GetProperty("success").GetBoolean() && s2.GetProperty("complete").GetBoolean(), s2.GetProperty("error").GetString()!);
			if (s2.GetProperty("success").GetBoolean())
				Broadcast(s2, "registered group (Ruby + B) accepted by the node and mined");
		}

		// 6. fee options checked by Ruby: a fee option that spends other coins is refused; an approved option is signed
		//    without asking once only (a second sign_psbt of it goes through the normal screens again)
		{
			var g = Group(2, withAccounts: true);
			gp.FromSDT(g);
			var utxos = Fund(gp);
			var change = J(gp.CreateLegacyAddress(2, true, "RegTest")).GetProperty("address").GetString()!;
			var bundle = J(J(gp.BuildLegacySpend(JsonSerializer.Serialize(utxos), dest, "0.7", change, "0.0001", "10", false, "RegTest")).GetProperty("bundle").GetString()!);
			var level0 = PSBT.Parse(bundle.GetProperty("Levels")[0].GetProperty("Psbt").GetString()!, net);
			// another payment (other coins) presented as a fee option of level0
			var other = J(gp.BuildLegacySpend(JsonSerializer.Serialize(Fund(gp)), dest, "0.7", change, "0.0002", "", false, "RegTest"));
			var otherPsbt = PSBT.Parse(J(other.GetProperty("bundle").GetString()!).GetProperty("Levels")[0].GetProperty("Psbt").GetString()!, net);
			try
			{
				ruby.SignPsbt(net, level0.ToBytes(), new List<byte[]> { otherPsbt.ToBytes() });
				check("a fee option with other coins is refused", false, "signed");
			}
			catch (RubyException e)
			{
				check("a fee option with other coins is refused", e.Message.Contains("same coins"), e.Message);
			}
		}

		RunDelegatedOwner(device, mnemonic, net, rpc, ruby, dest, check);
	}

	// 2026-11-14: a Delegated group (Taproot) whose OWNER is a Ruby wallet spends alone by the key path. The owner's
	// chain keys are Ruby's m/86'/1'/0'/2 and /3; the members are two software wallets.
	private static void RunDelegatedOwner(string device, string mnemonic, Network net, RPCClient rpc, RubyClient ruby,
		string dest, Action<string, bool, string> check)
	{
		Console.WriteLine("== Delegated: a Ruby owner spends alone");
		string X(ExtPubKey k) => k.ToString(net);
		var taproot = KeyPath.Parse("m/86'/1'/0'");
		var rubyTaproot = ExtPubKey.Parse(ruby.GetXpub(net, taproot), net);
		var m1 = new ExtKey().Derive(taproot);
		var m2 = new ExtKey().Derive(taproot);
		GroupSDT Group(int k) => new GroupSDT
		{
			GroupId = Guid.NewGuid(), GroupType = 30, GroupName = "Delegated Ruby", AmIGroupOwner = true, IsActive = true,
			MinimumShares = (short)k,
			ExtPubKeyMultiSigReceiving = X(rubyTaproot.Derive(2)), ExtPubKeyMultiSigChange = X(rubyTaproot.Derive(3)),
			Contact = new List<ContactItem>
			{
				new ContactItem { ContactUserName = "M1", ExtPubKeyMultiSigReceiving = X(m1.Derive(2).Neuter()), ExtPubKeyMultiSigChange = X(m1.Derive(3).Neuter()) },
				new ContactItem { ContactUserName = "M2", ExtPubKeyMultiSigReceiving = X(m2.Derive(2).Neuter()), ExtPubKeyMultiSigChange = X(m2.Derive(3).Neuter()) },
			}
		};
		var dp = new DelegatedProcessor();
		check("Delegated FromSDT (Ruby owner)", dp.FromSDT(Group(2)), "");
		var utxos = new List<object>();
		foreach (var (seq, isChange, btc) in new[] { (0, false, 0.6m), (1, true, 0.4m) })
		{
			var addr = J(dp.CreateAddress(seq, isChange, "RegTest")).GetProperty("address").GetString()!;
			var txid = rpc.SendToAddress(BitcoinAddress.Create(addr, net), Money.Coins(btc));
			var vout = rpc.GetRawTransaction(txid).Outputs.FindIndex(o => o.ScriptPubKey == BitcoinAddress.Create(addr, net).ScriptPubKey);
			utxos.Add(new { TxId = txid.ToString(), Vout = vout, AmountBtc = btc.ToString(System.Globalization.CultureInfo.InvariantCulture), Sequence = seq, IsChange = isChange, Address = addr });
		}
		rpc.Generate(1);
		var change = J(dp.CreateAddress(2, true, "RegTest")).GetProperty("address").GetString()!;
		var r = J(dp.OwnerSpendWithRuby(JsonSerializer.Serialize(utxos), dest, "0.7", change, "0.0001", false, device,
			X(rubyTaproot.Derive(2)), X(rubyTaproot.Derive(3)), "RegTest"));
		check("Ruby owner signs alone (key path, 2 inputs of 2 chains)", r.GetProperty("success").GetBoolean(), r.GetProperty("error").GetString()!);
		if (r.GetProperty("success").GetBoolean())
		{
			var txid = rpc.SendRawTransaction(Transaction.Parse(r.GetProperty("txHex").GetString()!, net));
			rpc.Generate(1);
			check("Delegated (Ruby owner) accepted by the node and mined", rpc.GetRawTransactionInfo(txid).Confirmations >= 1,
				$"{txid} vsize {r.GetProperty("vsize").GetInt32()} fee {r.GetProperty("feeBtc").GetDecimal()}");
		}
		// the firmware itself (main/utils/psbt.c): a key path with a merkle root is signed only if the coin pays to the
		// key tweaked with THAT root. A PSBT with another root gets no signature.
		{
			var u0 = JsonDocument.Parse(JsonSerializer.Serialize(utxos[0])).RootElement;
			var tx = net.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.Parse(u0.GetProperty("TxId").GetString()!), u0.GetProperty("Vout").GetInt32()));
			tx.Outputs.Add(Money.Coins(0.5m), BitcoinAddress.Create(dest, net));
			var psbt = PSBT.FromTransaction(tx, net);
			var ownerKey = rubyTaproot.Derive(2).Derive(0).PubKey;
			psbt.Inputs[0].WitnessUtxo = new TxOut(Money.Coins(0.6m), BitcoinAddress.Create(u0.GetProperty("Address").GetString()!, net).ScriptPubKey);
			psbt.Inputs[0].TaprootInternalKey = ownerKey.TaprootInternalKey;
			psbt.Inputs[0].TaprootMerkleRoot = new uint256(RandomUtils.GetBytes(32));
			psbt.Inputs[0].HDTaprootKeyPaths[new TaprootPubKey(ownerKey.TaprootInternalKey.ToBytes())] =
				new TaprootKeyPath(new RootedKeyPath(ruby.GetMasterFingerprint(net), taproot.Derive(2).Derive(0)));
			var back = ruby.SignPsbt(psbt);
			check("a key path with a wrong merkle root is not signed", back.Inputs[0].TaprootKeySignature == null, "");
		}
		// the keys of another wallet as the owner's: refused before anything is shown on Ruby
		var other = new ExtKey().Derive(taproot);
		var bad = J(dp.OwnerSpendWithRuby(JsonSerializer.Serialize(utxos), dest, "0.1", change, "0.0001", false, device,
			X(other.Derive(2).Neuter()), X(other.Derive(3).Neuter()), "RegTest"));
		check("keys that are not the owner's are refused", !bad.GetProperty("success").GetBoolean(), bad.GetProperty("error").GetString()!);
		// a Ruby with other words is refused
		var dp2 = new DelegatedProcessor();
		dp2.FromSDT(Group(2));
		ruby.DebugSetMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
		var wrong = J(dp2.OwnerSpendWithRuby(JsonSerializer.Serialize(utxos), dest, "0.1", change, "0.0001", false, device,
			X(rubyTaproot.Derive(2)), X(rubyTaproot.Derive(3)), "RegTest"));
		check("a Ruby with other words is refused (Delegated owner)", !wrong.GetProperty("success").GetBoolean() && wrong.GetProperty("error").GetString()!.Contains("does not hold"), wrong.GetProperty("error").GetString()!);
		ruby.DebugSetMnemonic(mnemonic);

		RunScriptPathMember(device, mnemonic, net, rpc, ruby, dest, check);
	}

	// 2026-11-15: a Ruby wallet signs as a MEMBER (script path, BIP342 multi_a leaves): in a Delegated group (owner
	// software) and in a Multi Signature group (no owner; the Ruby wallet is the creator, one more signer). The Ruby
	// member's chain keys are Ruby's m/86'/1'/0'/2 and /3; the other members are software wallets.
	private static void RunScriptPathMember(string device, string mnemonic, Network net, RPCClient rpc, RubyClient ruby,
		string dest, Action<string, bool, string> check)
	{
		Console.WriteLine("== Delegated / Multi Signature: a Ruby member signs the scripts");
		string X(ExtPubKey k) => k.ToString(net);
		var taproot = KeyPath.Parse("m/86'/1'/0'");
		var rubyTaproot = ExtPubKey.Parse(ruby.GetXpub(net, taproot), net);
		var owner = new ExtKey().Derive(taproot);
		var m1 = new ExtKey().Derive(taproot);
		var m2 = new ExtKey().Derive(taproot);
		ContactItem Member(string name, ExtPubKey account) => new ContactItem
		{
			ContactUserName = name, ExtPubKeyMultiSigReceiving = X(account.Derive(2)), ExtPubKeyMultiSigChange = X(account.Derive(3))
		};
		// Delegated: software owner; members Ruby, M1, M2; 2 of the 3 members sign (3 scripts, Ruby is in 2)
		var delegated = new GroupSDT
		{
			GroupId = Guid.NewGuid(), GroupType = 30, GroupName = "Delegated Ruby member", AmIGroupOwner = false, IsActive = true,
			MinimumShares = 2,
			ExtPubKeyMultiSigReceiving = X(owner.Derive(2).Neuter()), ExtPubKeyMultiSigChange = X(owner.Derive(3).Neuter()),
			Contact = new List<ContactItem> { Member("Ruby", rubyTaproot), Member("M1", m1.Neuter()), Member("M2", m2.Neuter()) }
		};
		// Multi Signature: the Ruby wallet created it (its keys are the group's own), M1 and M2; 2 of the 3 sign
		var multisig = new GroupSDT
		{
			GroupId = Guid.NewGuid(), GroupType = DelegatedMultiSigSpend.MultiSignatureGroupType, GroupName = "MultiSig Ruby",
			AmIGroupOwner = true, IsActive = true, MinimumShares = 2,
			ExtPubKeyMultiSigReceiving = X(rubyTaproot.Derive(2)), ExtPubKeyMultiSigChange = X(rubyTaproot.Derive(3)),
			Contact = new List<ContactItem> { Member("M1", m1.Neuter()), Member("M2", m2.Neuter()) }
		};

		string RubyR() => X(rubyTaproot.Derive(2));
		string RubyC() => X(rubyTaproot.Derive(3));
		string M1R() => m1.Derive(2).ToString(net);
		string M1C() => m1.Derive(3).ToString(net);

		List<object> Fund(DelegatedProcessor p)
		{
			var utxos = new List<object>();
			foreach (var (seq, isChange, btc) in new[] { (0, false, 0.6m), (1, true, 0.4m) })
			{
				var addr = J(p.CreateAddress(seq, isChange, "RegTest")).GetProperty("address").GetString()!;
				var txid = rpc.SendToAddress(BitcoinAddress.Create(addr, net), Money.Coins(btc));
				var vout = rpc.GetRawTransaction(txid).Outputs.FindIndex(o => o.ScriptPubKey == BitcoinAddress.Create(addr, net).ScriptPubKey);
				utxos.Add(new { TxId = txid.ToString(), Vout = vout, AmountBtc = btc.ToString(System.Globalization.CultureInfo.InvariantCulture), Sequence = seq, IsChange = isChange, Address = addr });
			}
			rpc.Generate(1);
			return utxos;
		}
		void Broadcast(string what, JsonElement r)
		{
			if (!r.GetProperty("success").GetBoolean() || r.GetProperty("txHex").GetString() is not { Length: > 0 } hex)
			{
				check(what, false, r.GetProperty("error").GetString()!);
				return;
			}
			var txid = rpc.SendRawTransaction(Transaction.Parse(hex, net));
			rpc.Generate(1);
			check(what, rpc.GetRawTransactionInfo(txid).Confirmations >= 1, $"{txid} vsize {r.GetProperty("vsize").GetInt32()} fee {r.GetProperty("feeBtc").GetDecimal()}");
		}

		foreach (var (name, group) in new[] { ("Delegated", delegated), ("Multi Signature", multisig) })
		{
			var dp = new DelegatedProcessor();
			check($"{name} FromSDT (Ruby member)", dp.FromSDT(group), "");

			// Ruby signs first (every fee level), M1 signs last and picks +10 %
			var utxos = Fund(dp);
			var change = J(dp.CreateAddress(5, true, "RegTest")).GetProperty("address").GetString()!;
			var built = J(dp.BuildSpend(JsonSerializer.Serialize(utxos), dest, "0.7", change, "0.0001", "10", false, "RegTest"));
			check($"{name}: payment built", built.GetProperty("success").GetBoolean(), built.TryGetProperty("error", out var e0) ? e0.GetString()! : "");
			var first = J(dp.SignSpendWithRuby(built.GetProperty("bundle").GetString()!, device, RubyR(), RubyC(), -1, "RegTest"));
			check($"{name}: Ruby signs first (2 fee levels, script path)", first.GetProperty("success").GetBoolean() && first.GetProperty("signatures").GetInt32() == 1,
				first.GetProperty("error").GetString()!);
			if (first.GetProperty("success").GetBoolean())
			{
				var again = J(dp.SignSpendWithRuby(first.GetProperty("bundle").GetString()!, device, RubyR(), RubyC(), -1, "RegTest"));
				check($"{name}: Ruby can not sign twice", !again.GetProperty("success").GetBoolean(), again.GetProperty("error").GetString()!);
				Broadcast($"{name}: M1 signs last (+10 %): accepted by the node and mined",
					J(dp.SignSpend(first.GetProperty("bundle").GetString()!, M1R(), M1C(), 10, "RegTest")));
			}

			// M1 signs first, Ruby signs last and picks the calculated fee
			utxos = Fund(dp);
			built = J(dp.BuildSpend(JsonSerializer.Serialize(utxos), dest, "0.7", change, "0.0001", "20", false, "RegTest"));
			var m1First = J(dp.SignSpend(built.GetProperty("bundle").GetString()!, M1R(), M1C(), -1, "RegTest"));
			check($"{name}: M1 signs first", m1First.GetProperty("success").GetBoolean(), m1First.GetProperty("error").GetString()!);
			Broadcast($"{name}: Ruby signs last (script path): accepted by the node and mined",
				J(dp.SignSpendWithRuby(m1First.GetProperty("bundle").GetString()!, device, RubyR(), RubyC(), 0, "RegTest")));
		}

		// the firmware itself (main/utils/psbt.c): a leaf is signed only if it holds Ruby's key AND the coin commits to it
		{
			var dp = new DelegatedProcessor();
			dp.FromSDT(delegated);
			var utxos = Fund(dp);
			var u0 = JsonDocument.Parse(JsonSerializer.Serialize(utxos[0])).RootElement;
			var ms = DelegatedMultiSig.FromExtPubKeys(owner.Derive(2).Neuter(),
				new[] { rubyTaproot.Derive(2), m1.Derive(2).Neuter(), m2.Derive(2).Neuter() }, 2, 0, net);
			var rubyKey = rubyTaproot.Derive(2).Derive(0).PubKey;
			var rubyIndex = ms.SignerPubKeys.ToList().FindIndex(k => k == rubyKey);
			var fp = ruby.GetMasterFingerprint(net);
			PSBT Request(TapScript script, ControlBlock control)
			{
				var tx = net.CreateTransaction();
				tx.Inputs.Add(new OutPoint(uint256.Parse(u0.GetProperty("TxId").GetString()!), u0.GetProperty("Vout").GetInt32()));
				tx.Outputs.Add(Money.Coins(0.5m), BitcoinAddress.Create(dest, net));
				var psbt = PSBT.FromTransaction(tx, net);
				psbt.Inputs[0].WitnessUtxo = new TxOut(Money.Coins(0.6m), ms.Address.ScriptPubKey);
				psbt.Inputs[0].Unknown[new byte[] { 0x15 }.Concat(control.ToBytes()).ToArray()] = script.Script.ToBytes().Concat(new byte[] { 0xc0 }).ToArray();
				psbt.Inputs[0].HDTaprootKeyPaths[new TaprootPubKey(rubyKey.TaprootInternalKey.ToBytes())] =
					new TaprootKeyPath(new RootedKeyPath(fp, taproot.Derive(2).Derive(0)), new[] { script.LeafHash });
				return psbt;
			}
			bool Signed(PSBT p) => p.Inputs[0].Unknown.Keys.Any(k => k.Length == 65 && k[0] == 0x14);
			check("Delegated: the address of the test = the group's", ms.Address.ToString() == u0.GetProperty("Address").GetString(), "");
			var rubyScripts = Enumerable.Range(0, ms.Scripts.Count).Where(s => ms.GetScriptSignerIndices(s).Contains(rubyIndex)).ToList();
			var mine = rubyScripts[0];
			var notMine = Enumerable.Range(0, ms.Scripts.Count).First(s => !rubyScripts.Contains(s));
			check("firmware: a leaf with Ruby's key, committed in the coin, is signed",
				Signed(ruby.SignPsbt(Request(ms.Scripts[mine], ms.TaprootSpendInfo.GetControlBlock(ms.Scripts[mine])))), "");
			check("firmware: a leaf without Ruby's key is not signed",
				!Signed(ruby.SignPsbt(Request(ms.Scripts[notMine], ms.TaprootSpendInfo.GetControlBlock(ms.Scripts[notMine])))), "");
			// the control block of another leaf: its merkle path does not lead from this leaf to the coin's key
			check("firmware: a leaf the coin does not commit to is not signed",
				!Signed(ruby.SignPsbt(Request(ms.Scripts[mine], ms.TaprootSpendInfo.GetControlBlock(ms.Scripts[notMine])))), "");
			// a leaf of another group with Ruby's key (Ruby + an attacker's key, 1 of 2): not in this coin
			var attacker = new ExtKey().Derive(taproot);
			var foreign = DelegatedMultiSig.FromExtPubKeys(attacker.Derive(2).Neuter(), new[] { rubyTaproot.Derive(2), attacker.Derive(3).Neuter() }, 1, 0, net);
			var foreignLeaf = foreign.Scripts.First(s => s.Script.ToBytes().AsSpan().IndexOf(rubyKey.TaprootInternalKey.ToBytes()) >= 0);
			check("firmware: a leaf of another address is not signed",
				!Signed(ruby.SignPsbt(Request(foreignLeaf, foreign.TaprootSpendInfo.GetControlBlock(foreignLeaf)))), "");
		}

		// keys of another wallet as the Ruby member's, and a Ruby with other words: refused before anything is shown
		{
			var dp = new DelegatedProcessor();
			dp.FromSDT(delegated);
			var utxos = Fund(dp);
			var change = J(dp.CreateAddress(6, true, "RegTest")).GetProperty("address").GetString()!;
			var bundle = J(dp.BuildSpend(JsonSerializer.Serialize(utxos), dest, "0.1", change, "0.0001", "", false, "RegTest")).GetProperty("bundle").GetString()!;
			var other = new ExtKey().Derive(taproot);
			var bad = J(dp.SignSpendWithRuby(bundle, device, X(other.Derive(2).Neuter()), X(other.Derive(3).Neuter()), -1, "RegTest"));
			check("member keys of another wallet are refused", !bad.GetProperty("success").GetBoolean(), bad.GetProperty("error").GetString()!);
			ruby.DebugSetMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
			var wrong = J(dp.SignSpendWithRuby(bundle, device, RubyR(), RubyC(), -1, "RegTest"));
			check("a Ruby with other words is refused (member)", !wrong.GetProperty("success").GetBoolean() && wrong.GetProperty("error").GetString()!.Contains("does not hold"), wrong.GetProperty("error").GetString()!);
			ruby.DebugSetMnemonic(mnemonic);
		}

		RunGroupRegistration(device, mnemonic, net, rpc, ruby, dest, check);
	}

	// 2026-11-16: a Taproot group registered on Ruby (register_group). Ruby calculates the group's addresses itself
	// (firmware main/group.c) and recognises the group's change in a payment of that group.
	// The firmware log is read when the firmware is built with --log-cbor (see FirmwareLog).
	private static void RunGroupRegistration(string device, string mnemonic, Network net, RPCClient rpc, RubyClient ruby,
		string dest, Action<string, bool, string> check)
	{
		Console.WriteLine("== Groups registered on Ruby");
		string X(ExtPubKey k) => k.ToString(net);
		var taproot = KeyPath.Parse("m/86'/1'/0'");
		var rubyTaproot = ExtPubKey.Parse(ruby.GetXpub(net, taproot), net);
		string RubyR() => X(rubyTaproot.Derive(2));
		string RubyC() => X(rubyTaproot.Derive(3));

		var uart = new FirmwareLog(ruby);

		void Clean()
		{
			ruby.DebugCleanReset();
			ruby.DebugSetMnemonic(mnemonic);
		}

		ContactItem Member(string name, ExtPubKey account) => new ContactItem
		{
			ContactUserName = name, ExtPubKeyMultiSigReceiving = X(account.Derive(2)), ExtPubKeyMultiSigChange = X(account.Derive(3))
		};
		// a group of n participants with keys in the scripts (Delegated: the members; Multi Signature: every signer,
		// the creator included), k of them sign. rubyRole: "owner" (Delegated), "creator" (Multi Signature), "member",
		// or "none" (Ruby is not in the group).
		GroupSDT Shape(bool multisig, int n, int k, string rubyRole, string label)
		{
			var others = Enumerable.Range(0, n + 1).Select(_ => new ExtKey().Derive(taproot).Neuter()).ToList();
			var rubyInScripts = rubyRole == "member" || rubyRole == "creator";
			var ownerKey = rubyRole == "owner" || rubyRole == "creator" ? rubyTaproot : others[n];
			var contacts = new List<ContactItem>();
			var scriptParticipants = multisig ? n - 1 : n; // the creator of a Multi Signature is the owner fields
			for (int i = 0; i < scriptParticipants; i++)
			{
				var isRuby = rubyRole == "member" && i == 0;
				contacts.Add(Member(isRuby ? "Ruby" : $"P{i}", isRuby ? rubyTaproot : others[i]));
			}
			_ = rubyInScripts;
			return new GroupSDT
			{
				GroupId = Guid.NewGuid(), GroupType = multisig ? DelegatedMultiSigSpend.MultiSignatureGroupType : (short)30,
				GroupName = label, AmIGroupOwner = rubyRole == "owner" || rubyRole == "creator", IsActive = true,
				MinimumShares = (short)k,
				ExtPubKeyMultiSigReceiving = X(ownerKey.Derive(2)), ExtPubKeyMultiSigChange = X(ownerKey.Derive(3)),
				Contact = contacts
			};
		}
		string NameOf(string label) =>
			ruby.GetRegisteredGroups().FirstOrDefault(g => g.Value is IDictionary<string, object?> d && d["label"] as string == label).Key ?? "";

		// 1. Ruby calculates exactly the library's addresses (receiving and change chains, several indices), for
		//    Delegated and Multi Signature groups of every size Ruby takes, with Ruby as owner, creator or member
		Clean();
		var shapes = new (bool multisig, int n, int k, string role)[]
		{
			(false, 2, 1, "owner"), (false, 3, 2, "owner"), (false, 3, 2, "member"), (false, 4, 4, "member"),
			(false, 5, 3, "member"), (false, 8, 4, "member"), (false, 15, 2, "member"), (false, 13, 5, "member"),
			(true, 2, 2, "creator"), (true, 3, 2, "creator"), (true, 4, 3, "member"), (true, 6, 3, "member"), (true, 15, 14, "creator"),
		};
		foreach (var (multisig, n, k, role) in shapes)
		{
			var label = $"{(multisig ? "MS" : "DG")} {k}of{n} {role}";
			var group = Shape(multisig, n, k, role, label);
			var dp = new DelegatedProcessor();
			dp.FromSDT(group);
			var watch = System.Diagnostics.Stopwatch.StartNew();
			var reg = J(dp.RegisterGroupWithRuby(device, RubyR(), RubyC(), "RegTest"));
			var regMs = watch.ElapsedMilliseconds;
			check($"register {label}", reg.GetProperty("success").GetBoolean() && reg.GetProperty("status").GetString() == "registered",
				reg.GetProperty("error").GetString()! + $" ({regMs} ms)");
			var name = NameOf(label);
			var same = true;
			var detail = $"name {name}, register {regMs} ms";
			foreach (var (isChange, index) in new[] { (false, 0u), (true, 0u), (false, 7u), (true, 1234u) })
			{
				var expected = J(dp.CreateAddress((int)index, isChange, "RegTest")).GetProperty("address").GetString();
				watch.Restart();
				var actual = name.Length > 0 ? ruby.GetGroupAddress(net, name, isChange, index) : "";
				detail += $", {(isChange ? "change" : "receiving")} {index} {watch.ElapsedMilliseconds} ms";
				if (actual != expected)
				{
					same = false;
					detail += $" MISMATCH ruby {actual} lib {expected}";
				}
			}
			check($"{label}: Ruby's addresses = the library's", same, detail);
			var again = J(dp.RegisterGroupWithRuby(device, RubyR(), RubyC(), "RegTest"));
			check($"{label}: registering it again asks nothing", again.GetProperty("success").GetBoolean() && again.GetProperty("status").GetString() == "already registered", "");
			Clean(); // one at a time: the storage of the emulator holds about 10 KB of registrations
		}

		// 2. refused by the firmware: a group without Ruby, keys of another network, too many combinations
		{
			var none = Shape(false, 3, 2, "none", "no Ruby");
			var keys = DelegatedMultiSigSpend.RubyGroupRecord(none, net);
			try
			{
				ruby.RegisterGroup(net, "dcnoruby", "no Ruby", keys.type, keys.k, keys.owner, keys.signers, taproot.Derive(2), taproot.Derive(3));
				check("a group without Ruby is refused", false, "registered");
			}
			catch (RubyException e) { check("a group without Ruby is refused", e.Message.Contains("not a participant"), e.Message); }

			// the raw request, so the keys can be of another network than the request, and the group bigger than the
			// library allows: owner = the Delegated owner's chain keys; signers = the members' chain keys
			IDictionary<string, object?> Raw(GroupSDT g, Network keysNet, string name)
			{
				object Chains(string? r, string? c) => new Dictionary<string, object?>
				{
					["receiving"] = ExtPubKey.Parse(r!, net).ToString(keysNet),
					["change"] = ExtPubKey.Parse(c!, net).ToString(keysNet)
				};
				return new Dictionary<string, object?>
				{
					["network"] = RubyClient.ToRubyNetwork(net), ["group_name"] = name, ["label"] = name, ["type"] = "delegated",
					["threshold"] = (long)g.MinimumShares,
					["owner"] = Chains(g.ExtPubKeyMultiSigReceiving, g.ExtPubKeyMultiSigChange),
					["signers"] = g.Contact.Select(c => Chains(c.ExtPubKeyMultiSigReceiving, c.ExtPubKeyMultiSigChange)).ToList<object?>(),
					["receiving_path"] = taproot.Derive(2).Indexes.Select(i => (object?)(long)i).ToList(),
					["change_path"] = taproot.Derive(3).Indexes.Select(i => (object?)(long)i).ToList(),
				};
			}
			try
			{
				ruby.Call("register_group", Raw(Shape(false, 3, 2, "member", "mainnet keys"), Network.Main, "dcmain"), waitsForUser: true);
				check("keys of another network are refused", false, "registered");
			}
			catch (RubyException e) { check("keys of another network are refused", e.Message.Contains("keys"), e.Message); }

			try
			{
				ruby.Call("register_group", Raw(Shape(false, 15, 6, "member", "too big"), net, "dcbig"), waitsForUser: true); // 5005
				check("a group with more than 2000 combinations is refused", false, "registered");
			}
			catch (RubyException e) { check("a group with more than 2000 combinations is refused", e.Message.Contains("combinations"), e.Message); }
		}

		// 3. payments: the change of the group is recognised (and not shown) only for a payment of that same group
		List<object> Fund(DelegatedProcessor p)
		{
			var utxos = new List<object>();
			foreach (var (seq, isChange, btc) in new[] { (0, false, 0.6m), (1, true, 0.4m) })
			{
				var addr = J(p.CreateAddress(seq, isChange, "RegTest")).GetProperty("address").GetString()!;
				var txid = rpc.SendToAddress(BitcoinAddress.Create(addr, net), Money.Coins(btc));
				var vout = rpc.GetRawTransaction(txid).Outputs.FindIndex(o => o.ScriptPubKey == BitcoinAddress.Create(addr, net).ScriptPubKey);
				utxos.Add(new { TxId = txid.ToString(), Vout = vout, AmountBtc = btc.ToString(System.Globalization.CultureInfo.InvariantCulture), Sequence = seq, IsChange = isChange, Address = addr });
			}
			rpc.Generate(1);
			return utxos;
		}
		{
			Clean();
			// Delegated, Ruby owner: OwnerSpendWithRuby registers the group (first payment) and the change is recognised
			var owned = Shape(false, 3, 2, "owner", "Owner change");
			var dp = new DelegatedProcessor();
			dp.FromSDT(owned);
			var utxos = Fund(dp);
			var change = J(dp.CreateAddress(9, true, "RegTest")).GetProperty("address").GetString()!;
			uart.Mark();
			var r = J(dp.OwnerSpendWithRuby(JsonSerializer.Serialize(utxos), dest, "0.7", change, "0.0001", false, device, RubyR(), RubyC(), "RegTest"));
			check("owner payment: the group is registered by the first payment", r.GetProperty("success").GetBoolean() && NameOf("Owner change").Length > 0, r.GetProperty("error").GetString()!);
			uart.Check(check, "owner payment: Ruby recognises the group's change (change 9)", "Output 1 group change address validated", true);
			if (r.GetProperty("success").GetBoolean())
			{
				rpc.SendRawTransaction(Transaction.Parse(r.GetProperty("txHex").GetString()!, net));
				rpc.Generate(1);
			}

			// the change sent to ANOTHER group of Ruby: not this group's change, so it is shown
			var otherGroup = Shape(false, 3, 2, "owner", "Other group");
			var dpOther = new DelegatedProcessor();
			dpOther.FromSDT(otherGroup);
			J(dpOther.RegisterGroupWithRuby(device, RubyR(), RubyC(), "RegTest"));
			var foreignChange = J(dpOther.CreateAddress(0, true, "RegTest")).GetProperty("address").GetString()!;
			utxos = Fund(dp);
			uart.Mark();
			r = J(dp.OwnerSpendWithRuby(JsonSerializer.Serialize(utxos), dest, "0.7", foreignChange, "0.0001", false, device, RubyR(), RubyC(), "RegTest"));
			check("owner payment with the change to another group: signed", r.GetProperty("success").GetBoolean(), r.GetProperty("error").GetString()!);
			uart.Check(check, "the change to another group is not taken as this group's change", "group change address validated", false);

			// member payments (script path): Delegated and Multi Signature, Ruby signs first with 2 fee levels
			foreach (var (multisig, label) in new[] { (false, "Member change"), (true, "MultiSig change") })
			{
				var group = Shape(multisig, 3, 2, multisig ? "creator" : "member", label);
				var p = new DelegatedProcessor();
				p.FromSDT(group);
				var u = Fund(p);
				var ch = J(p.CreateAddress(3, true, "RegTest")).GetProperty("address").GetString()!;
				var built = J(p.BuildSpend(JsonSerializer.Serialize(u), dest, "0.7", ch, "0.0001", "10", false, "RegTest"));
				uart.Mark();
				var s = J(p.SignSpendWithRuby(built.GetProperty("bundle").GetString()!, device, RubyR(), RubyC(), -1, "RegTest"));
				check($"{label}: Ruby signs (and registers the group)", s.GetProperty("success").GetBoolean() && NameOf(label).Length > 0, s.GetProperty("error").GetString()!);
				uart.Check(check, $"{label}: Ruby recognises the group's change", "Output 1 group change address validated", true);
			}
		}

		// 4. the storage is never filled: registrations stop with a reserve left for the PIN counter
		{
			Clean();
			var count = 0;
			string? refusal = null;
			while (count < 30 && refusal == null)
			{
				var keys = DelegatedMultiSigSpend.RubyGroupRecord(Shape(false, 15, 2, "member", $"Fill {count}"), net);
				try
				{
					ruby.RegisterGroup(net, $"dcfill{count:D2}", $"Fill {count}", keys.type, keys.k, keys.owner, keys.signers, taproot.Derive(2), taproot.Derive(3));
					count++;
				}
				catch (RubyException e) { refusal = e.Message; }
			}
			var info = ruby.GetVersionInfo();
			var free = info.TryGetValue("JADE_NVS_ENTRIES_FREE", out var f) && f is long l ? l : -1;
			check("registrations stop before the storage is full", refusal != null && refusal.Contains("storage") && free >= 32,
				$"{count} groups of 16 participants registered, then: {refusal}; NVS entries free {free}");
			// another wallet does not see (or use) these registrations: they carry the HMAC of this wallet
			ruby.DebugSetMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
			check("another wallet does not see the groups", ruby.GetRegisteredGroups().Count == 0, "");
			ruby.DebugSetMnemonic(mnemonic);
			check("this wallet sees them again", ruby.GetRegisteredGroups().Count == count, "");
			Clean();
		}
	}

	// The firmware log: a firmware built with --log-cbor sends its log lines over the RPC connection, and RubyClient
	// passes them to its Log callback. Mark() remembers where the log is, Check() looks only at what came after.
	// With a firmware without logs the checks are skipped.
	private sealed class FirmwareLog
	{
		private readonly System.Text.StringBuilder _log = new System.Text.StringBuilder();
		private int _mark;

		public FirmwareLog(RubyClient ruby)
		{
			var previous = ruby.Log;
			ruby.Log = line =>
			{
				lock (_log)
					_log.AppendLine(line);
				previous?.Invoke(line);
			};
		}

		private string Log()
		{
			lock (_log)
				return _log.ToString();
		}

		public void Mark() => _mark = Log().Length;

		public void Check(Action<string, bool, string> check, string what, string text, bool expected)
		{
			var log = Log();
			if (log.Length == 0)
			{
				Console.WriteLine($"  (skipped, the firmware sends no log: build it with --log-cbor) {what}");
				return;
			}
			var recent = log.Length > _mark ? log.Substring(_mark) : "";
			var found = recent.Contains(text);
			var lines = recent.Split('\n');
			var line = lines.FirstOrDefault(s => s.Contains(text)) ?? lines.FirstOrDefault(s => s.Contains("group") && (s.Contains("Found") || s.Contains("No registered") || s.Contains("abandoned"))) ?? "";
			check(what, found == expected, line.Trim());
		}
	}
}
