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
	}
}
