using System.Text.Json;
using DistricutedCryptographyLib;
using NBitcoin;

// The wallet flows as GeneXus will run them, through the RubyProcessor External Object (JSON in / out).
internal static class KbFlowTests
{
	// The client RubyProcessor keeps open for the device (to run the DEBUG calls on the same connection)
	private static RubyClient ProcessorClient(string device)
	{
		var field = typeof(RubyProcessor).GetField("Clients",
			System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
		var clients = (Dictionary<string, RubyClient>)field.GetValue(null)!;
		return clients[device];
	}

	private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;

	public static void Run(string device, string mnemonic, Action<string, bool, string> check)
	{
		Console.WriteLine("== wallet flows through RubyProcessor");
		const string NetworkType = "RegTest";
		var net = Network.RegTest;
		var p = new RubyProcessor();

		var status = J(p.Status(device));
		check("Status", status.GetProperty("success").GetBoolean(), status.GetProperty("state").GetString() ?? "");
		var c = ProcessorClient(device);
		c.DebugCleanReset();
		c.DebugSetPin(234567);

		// New wallet: a new oracle, paired with Ruby; the user sets the wallet up on Ruby (here: the debug mnemonic)
		var created = J(p.CreateOracle());
		var oracleState = created.GetProperty("oracleState").GetString()!;
		check("CreateOracle", created.GetProperty("success").GetBoolean() && created.GetProperty("publicKey").GetString()!.Length == 66, "");
		var paired = J(p.Pair(device, oracleState));
		check("Pair", paired.GetProperty("success").GetBoolean(), paired.ToString());
		c.DebugSetMnemonic(mnemonic);

		var unlock = J(p.Unlock(device, NetworkType, oracleState));
		check("first Unlock sets the PIN", unlock.GetProperty("success").GetBoolean() && unlock.GetProperty("unlocked").GetBoolean()
			&& unlock.GetProperty("oracleResult").GetString() == "set_pin", unlock.GetProperty("oracleResult").GetString() ?? "");
		oracleState = unlock.GetProperty("oracleState").GetString()!; // the wallet saves it

		// The wallet is opened again later
		J(p.Logout(device));
		unlock = J(p.Unlock(device, NetworkType, oracleState));
		check("Unlock with the PIN", unlock.GetProperty("unlocked").GetBoolean() && unlock.GetProperty("oracleResult").GetString() == "get_pin"
			&& unlock.GetProperty("state").GetString() == "READY", unlock.GetProperty("oracleResult").GetString() ?? "");
		oracleState = unlock.GetProperty("oracleState").GetString()!;

		// Public info = what NBitcoin.CreateExtKey gives for the software wallet
		var master = new Mnemonic(mnemonic).DeriveExtKey();
		var info = J(p.GetPublicInfo(device, NetworkType));
		var account = info.GetProperty("account");
		var ext = account.GetProperty("Extended");
		var softAccount = master.Derive(new KeyPath("86'/1'/0'"));
		check("GetPublicInfo account", info.GetProperty("success").GetBoolean()
			&& ext.GetProperty("NuterPublicKeyTaproot").GetString() == softAccount.Neuter().ToString(net)
			&& account.GetProperty("PublicKey").GetString() == softAccount.PrivateKey.PubKey.ToString()
			&& ext.GetProperty("Fingerprint").GetString() == softAccount.PrivateKey.PubKey.GetHDFingerPrint().ToString()
			&& ext.GetProperty("ParentFingerprint").GetString() == softAccount.ParentFingerprint.ToString()
			&& ext.GetProperty("Depth").GetInt32() == 3 && ext.GetProperty("Child").GetInt64() == softAccount.Child
			&& ext.GetProperty("keyPath").GetString() == "m/86'/1'/0'"
			&& account.GetProperty("PrivateKey").GetString() == "" && ext.GetProperty("PrivateKeyTaproot").GetString() == "",
			ext.GetProperty("NuterPublicKeyTaproot").GetString()![..16] + "...");
		check("GetPublicInfo bip48", info.GetProperty("bip48").GetProperty("Extended").GetProperty("NuterPublicKey").GetString()
			== master.Derive(new KeyPath("48'/1'/0'/1'")).Neuter().ToString(net), "");
		check("GetPublicInfo fingerprint", info.GetProperty("fingerprint").GetString() == master.GetPublicKey().GetHDFingerPrint().ToString(), "");

		var keys = J(p.GetUtilityKeys(device, NetworkType));
		var soft = RubyUtilityKeys.FromMnemonic(mnemonic, net);
		check("GetUtilityKeys = software keys", keys.GetProperty("success").GetBoolean()
			&& keys.GetProperty("login").GetString() == soft.Login && keys.GetProperty("chat").GetString() == soft.Chat
			&& keys.GetProperty("groups").GetString() == soft.Groups && keys.GetProperty("jsonFiles").GetString() == soft.JsonFiles
			&& keys.GetProperty("fileEncryption").GetString() == soft.FileEncryption && keys.GetProperty("hsm").GetString() == soft.Hsm, "");

		// Payments: coins at receiving 0 and 3, change at change 2
		BitcoinAddress Addr(uint chain, uint index) =>
			softAccount.Derive(chain).Derive(index).GetPublicKey().GetAddress(ScriptPubKeyType.TaprootBIP86, net);
		var funding = net.CreateTransaction();
		funding.Inputs.Add(new OutPoint(RandomUtils.GetUInt256(), 0));
		funding.Outputs.Add(Money.Coins(0.5m), Addr(0, 0));
		funding.Outputs.Add(Money.Coins(0.3m), Addr(0, 3));
		var inputs = JsonSerializer.Serialize(new[]
		{
			new { TxHex = funding.ToHex(), Vout = 0, Chain = 0, Index = 0 },
			new { TxHex = funding.ToHex(), Vout = 1, Chain = 0, Index = 3 }
		});
		var destination = new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, net).ToString();

		var paid = J(p.SignTransaction(device, NetworkType, inputs, destination, "0.6", Addr(1, 2).ToString(), 1, 2, "0.00003", false));
		check("SignTransaction with change", paid.GetProperty("success").GetBoolean(), paid.ToString().Length > 200 ? "" : paid.ToString());
		if (paid.GetProperty("success").GetBoolean())
		{
			var tx = Transaction.Parse(paid.GetProperty("hexTransaction").GetString()!, net);
			check("  pays 0.6 and the change", tx.Outputs.Any(o => o.Value == Money.Coins(0.6m) && o.ScriptPubKey == BitcoinAddress.Create(destination, net).ScriptPubKey)
				&& tx.Outputs.Any(o => o.ScriptPubKey == Addr(1, 2).ScriptPubKey) && tx.Inputs.Count == 2, $"vsize {paid.GetProperty("virtualSize").GetInt32()}");
		}

		var all = J(p.SignTransaction(device, NetworkType, inputs, destination, "0.8", "", 0, -1, "0.00002", true));
		check("SignTransaction send all", all.GetProperty("success").GetBoolean()
			&& Transaction.Parse(all.GetProperty("hexTransaction").GetString()!, net).Outputs.Single().Value == Money.Coins(0.8m) - Money.Coins(0.00002m),
			all.ToString().Length > 200 ? "" : all.ToString());

		var foreign = JsonSerializer.Serialize(new[] { new { TxHex = funding.ToHex(), Vout = 0, Chain = 0, Index = 1 } });
		var bad = J(p.SignTransaction(device, NetworkType, foreign, destination, "0.1", Addr(1, 2).ToString(), 1, 2, "0.00002", false));
		check("SignTransaction refuses a coin of another path", !bad.GetProperty("success").GetBoolean(), bad.GetProperty("error").GetString() ?? "");

		// Wrong PIN: not unlocked, the oracle state changed (attempt counted) and must be saved
		c.DebugSetPin(999999);
		J(p.Logout(device));
		var wrong = J(p.Unlock(device, NetworkType, oracleState));
		check("Unlock wrong PIN", wrong.GetProperty("success").GetBoolean() && !wrong.GetProperty("unlocked").GetBoolean()
			&& wrong.GetProperty("oracleResult").GetString() == "bad_pin 1/3"
			&& wrong.GetProperty("oracleState").GetString() != oracleState, wrong.GetProperty("oracleResult").GetString() ?? "");
		oracleState = wrong.GetProperty("oracleState").GetString()!;
		c.DebugSetPin(234567);
		check("Unlock right PIN after", J(p.Unlock(device, NetworkType, oracleState)).GetProperty("unlocked").GetBoolean(), "");

		// A broken oracle state is reported, not thrown
		check("Unlock with a bad oracle state", !J(p.Unlock(device, NetworkType, "{}")).GetProperty("success").GetBoolean(), "");

		c.DebugCleanReset();
		RubyProcessor.Disconnect(device);
	}
}
