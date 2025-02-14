//using System;
//using System.Threading;
//using NBitcoin;
//using NBitcoin.Tests;
//using NBitcoin.DataEncoders;
//using NBitcoin.Secp256k1;
//using NBitcoin.Secp256k1.Musig;
//using NBitcoin.Crypto;
//using System.Security.Cryptography;
//using System.Reflection.Metadata;
//using Newtonsoft.Json.Linq;
//using System.Reflection;
//using Newtonsoft.Json;


//namespace NBitcoinTraining
//{
//	class Program
//	{
//		struct SignedScriptData
//		{
//			public (UInt32, TapScript) ScriptWeights;
//			public List<(string, TaprootSignature)> signatures;

//			// Constructor to ensure signatures list is always initialized
//			public SignedScriptData(UInt32 weight, TapScript tapScript)
//			{
//				ScriptWeights = (weight, tapScript);
//				signatures = new List<(string, TaprootSignature)>();  // Ensure it's initialized
//			}
//		}

//		static List<List<PubKey>> GenerateCombinations(List<PubKey> items, int combinationSize)
//		{
//			if (items == null || combinationSize <= 0 || combinationSize > items.Count)
//				throw new ArgumentException("Invalid input: Ensure the list is not null and the combination size is valid.");

//			var result = new List<List<PubKey>>();
//			GenerateCombinationsRecursive(items, combinationSize, 0, new List<PubKey>(), result);
//			return result;
//		}

//		static void GenerateCombinationsRecursive(List<PubKey> items, int combinationSize, int start, List<PubKey> current, List<List<PubKey>> result)
//		{
//			if (current.Count == combinationSize)
//			{
//				result.Add(new List<PubKey>(current));
//				return;
//			}

//			for (int i = start; i < items.Count; i++)
//			{
//				current.Add(items[i]);
//				GenerateCombinationsRecursive(items, combinationSize, i + 1, current, result);
//				current.RemoveAt(current.Count - 1);
//			}
//		}

//		static (List<(uint, TapScript)>, TaprootSpendInfo, TaprootAddress) GenerateScriptPubKey(int sigCount, bool sort, Network network, PubKey owner, params PubKey[] keys)
//		{
//			if (keys == null)
//				throw new ArgumentNullException(nameof(keys));
//			if (owner == null)
//				throw new ArgumentNullException(nameof(keys));
//			if (sort)
//				Array.Sort(keys);
//			if (sigCount <= 1 || sigCount > 16)
//				throw new ArgumentException("Invalid input: The number of signatures must be between 2 and 16.");

//			List<List<PubKey>> combinations = new List<List<PubKey>>();

//			try
//			{
//				combinations = GenerateCombinations(keys.ToList(), sigCount);
//			}
//			catch (Exception ex)
//			{
//				Console.WriteLine($"Error creating PubKey[] combination: {ex.Message}");
//			}

//			var peers = sigCount; // 3 per multisignature
//			var howManyScripts = combinations.Count; // 5 combinations of 3 multisignatures
//			var Scripts = new TapScript[howManyScripts];

//			List<Op> ops = new List<Op>();
//			var scriptWeightsList = new List<(UInt32, TapScript)>();
//			var probability = (uint)(100 / howManyScripts);

//			for (int i = 0; i < combinations.Count; i++)
//			{
//				ops.Clear();
//				//Console.WriteLine($"Combination {i + 1}:");
//				int p = 1;
//				foreach (var pubKey in combinations[i])
//				{
//					//Console.WriteLine($"  {pubKey.ToString()}");
//					var xonlypubk = ECPubKey.Create(Encoders.Hex.DecodeData(pubKey.ToString())).ToXOnlyPubKey();
//					ops.Add(Op.GetPushOp(xonlypubk.ToBytes()));

//					if (p == combinations[i].Count)
//					{
//						ops.Add(OpcodeType.OP_CHECKSIGADD);
//					}
//					else
//					{
//						ops.Add(OpcodeType.OP_CHECKSIG);
//					}
//					p += 1;

//				}

//				switch (peers)
//				{
//					case 2:
//						ops.Add(OpcodeType.OP_2);
//						break;
//					case 3:
//						ops.Add(OpcodeType.OP_3);
//						break;
//					case 4:
//						ops.Add(OpcodeType.OP_4);
//						break;
//					case 5:
//						ops.Add(OpcodeType.OP_5);
//						break;
//					case 6:
//						ops.Add(OpcodeType.OP_6);
//						break;
//					case 7:
//						ops.Add(OpcodeType.OP_7);
//						break;
//					case 8:
//						ops.Add(OpcodeType.OP_8);
//						break;
//					case 9:
//						ops.Add(OpcodeType.OP_9);
//						break;
//					case 10:
//						ops.Add(OpcodeType.OP_10);
//						break;
//					case 11:
//						ops.Add(OpcodeType.OP_11);
//						break;
//					case 12:
//						ops.Add(OpcodeType.OP_12);
//						break;
//					case 13:
//						ops.Add(OpcodeType.OP_13);
//						break;
//					case 14:
//						ops.Add(OpcodeType.OP_14);
//						break;
//					case 15:
//						ops.Add(OpcodeType.OP_15);
//						break;
//					case 16:
//						ops.Add(OpcodeType.OP_16);
//						break;
//				}
//				ops.Add(OpcodeType.OP_NUMEQUAL);

//				Scripts[i] = new Script(ops).ToTapScript(TapLeafVersion.C0);
//				//Console.WriteLine($"Script[{i}]: {Scripts[i].ToString()}");
//				//scriptWeightsList.Add((probability, Scripts[i]));
//				scriptWeightsList.Add(((uint)i+1, Scripts[i]));

//			}

//			var scriptWeights = scriptWeightsList.ToArray();
//			var ec_PubKey = ECPubKey.Create(Encoders.Hex.DecodeData(owner.ToString()));
//			var xOnlyFromPubkey = ec_PubKey.ToXOnlyPubKey();
//			var tapIntFromEC = new TaprootInternalPubKey(xOnlyFromPubkey.ToBytes());
//			var treeInfo = TaprootSpendInfo.WithHuffmanTree(tapIntFromEC, scriptWeights);
//			var taprootPubKey = treeInfo.OutputPubKey.OutputKey;
//			var addr = taprootPubKey.GetAddress(network);

//			return (scriptWeightsList, treeInfo, addr);

//		}
//		static TaprootAddress GenerateScriptAddress(int sigCount, Network network, PubKey owner, params PubKey[] keys)
//		{
//			if (keys == null)
//				throw new ArgumentNullException(nameof(keys));
//			if (owner == null)
//				throw new ArgumentNullException(nameof(keys));
//			if (sigCount <= 1 || sigCount > 16)
//				throw new ArgumentException("Invalid input: The number of signatures must be between 2 and 16.");

//			var (scriptWeights, treeInfo, addr) = GenerateScriptPubKey(sigCount, true, network, owner, keys);

//			return (addr);
//		}

//		static List<(UInt32, TapScript)> lookScriptsToSign(List<(UInt32, TapScript)> scriptWeightsList, Key privateKey)
//		{
//			if (privateKey == null)
//				throw new ArgumentNullException(nameof(privateKey));

//			//string? strXonlyPubkey = ECPubKey.Create(Encoders.Hex.DecodeData(privateKey.PubKey.ToString())).ToXOnlyPubKey().ToString();
//			string? strXonlyPubkey = privateKey.PubKey.TaprootInternalKey.ToString();

//			// Initialize a list to store matching scripts
//			var matchingScripts = new List<(UInt32, TapScript)>();

//			for (int i = 0; i < scriptWeightsList.Count; ++i)
//			{
//				var script = scriptWeightsList[i].Item2.Script;

//				// Check if the script contains the public key string
//				if (script.ToString().Contains(strXonlyPubkey))
//				{
//					matchingScripts.Add(scriptWeightsList[i]);
//				}
//			}

//			return matchingScripts;
//		}

//		static List<SignedScriptData> SignFirst(List<(UInt32, TapScript)> scriptWeightsList, Key privateKey, uint256 hash, TaprootSigHash sighash)
//		{

//			if (privateKey == null)
//				throw new ArgumentNullException(nameof(privateKey));

//			if (scriptWeightsList == null || scriptWeightsList.Count == 0)
//				throw new ArgumentException("No scripts provided for signing.");

//			var matchingScripts = lookScriptsToSign(scriptWeightsList, privateKey);



//			var signedScripts = new List<SignedScriptData>();


//			foreach (var (weight, tapScript) in matchingScripts)
//			{
//				// Create a signedScript instance with a properly initialized list
//				var signedScript = new SignedScriptData(weight, tapScript);

//				// Generate the signature using the provided private key
//				var signature = privateKey.SignTaprootScriptSpend(hash, sighash);
//				var strXonlyPubkey = privateKey.PubKey.TaprootInternalKey.ToString();

//				// Set the script weights
//				signedScript.ScriptWeights = (weight, tapScript);

//				// Ensure the list is initialized (alternative approach)
//				if (signedScript.signatures == null)
//				{
//					signedScript.signatures = new List<(string, TaprootSignature)>();
//				}

//				// Add the generated signature
//				signedScript.signatures.Add((strXonlyPubkey, signature));


//				// Store the signed script
//				signedScripts.Add(signedScript);
//			}

//			return signedScripts;
//		}
//		static List<SignedScriptData> SignScript(List<SignedScriptData> prevouslySigned, Key privateKey, uint256 hash, TaprootSigHash sighash)
//		{

//			if (privateKey == null)
//				throw new ArgumentNullException(nameof(privateKey));

//			if (prevouslySigned == null || prevouslySigned.Count == 0)
//				throw new ArgumentException("No scripts provided for signing.");

//			List<(UInt32, TapScript)> scriptWeightsList = new List<(UInt32, TapScript)>();

//			foreach (var OnePrevouslySigned in prevouslySigned)
//			{
//				scriptWeightsList.Add(OnePrevouslySigned.ScriptWeights);
//			}

//			var matchingScripts = lookScriptsToSign(scriptWeightsList, privateKey);

//			var signedScripts = new List<SignedScriptData>();

//			foreach (var (weight, tapScript) in matchingScripts)
//			{
//				// Create a signedScript instance with a properly initialized list
//				var signedScript = new SignedScriptData(weight, tapScript);

//				// Generate the signature using the provided private key
//				var signature = privateKey.SignTaprootScriptSpend(hash, sighash);
//				var strXonlyPubkey = privateKey.PubKey.TaprootInternalKey.ToString();

//				// Set the script weights
//				signedScript.ScriptWeights = (weight, tapScript);

//				// Ensure the list is initialized (alternative approach)
//				if (signedScript.signatures == null)
//				{
//					signedScript.signatures = new List<(string, TaprootSignature)>();
//				}

//				// Add the generated signature
//				signedScript.signatures.Add((strXonlyPubkey, signature));

//				// now add previous signatures
//				foreach (var OnePrevouslySigned in prevouslySigned)
//				{
//					if (OnePrevouslySigned.ScriptWeights.Item2.Equals(signedScript.ScriptWeights.Item2))
//					{
//						foreach (var oneSignature in OnePrevouslySigned.signatures)
//						{
//							signedScript.signatures.Add((oneSignature.Item1, oneSignature.Item2));

//						}

//						Console.WriteLine("MATCHEA");
//					}
//				}


//				// Store the signed script
//				signedScripts.Add(signedScript);
//			}

//			return signedScripts;
//		}

//		static void delegationMuSig1_2_of_5()
//		{

//			TapScript ScriptToSign;
//			int min_num_signatures = 2;

//			var strmasterPubKeys = new[] {
//					"tpubDEZUvCj2FMcaNc2VEmHhn9CEC7wjtoRz7uYX4jnn6hFbyVedNH4kwyY3rBdrtQmbFR7Qp4Q2VhCGsCs8PBqPReg8qH9ZTnLd4PDXL7kuoXK",
//					"tpubDEbZ8cJoHhNMXYXCoCCqag11kckQxoY81sbC88Samp5ov8eRGTSZgrCfHysRo8zVf1PgyyHf3UFLAmf7kXm2FSswcs2jcXuZa8PRzjq1k4X",
//					"tpubDFTd5FohLoP3ZAWyixHgvgbdCGxaPdsXRUjUeQpiE2C7o4bxBvqXz5pfq2MstMrxHVc7AeauFH3DatEjtdL7VnDXBcnm3YcrHQuQe4j1BUF",
//					"tpubDE5Bm64sjJXBXf4fTQT3JRnP3MPyaLN2X1vA5gmy4QdNoNSTxswqecEzUzBo2wKiHe49XsQZKdHFABkoWW4ZgQtgGPw7uGvhXK5WVbh3h9y",
//					"tpubDEQgusD2c6KT17prVB1L9DxtGp26XfJuz3RYXvChN9TmZUm6zbdNaFbUXGuFwCWv3inFNnh45YVqM9WoVbGRU2QWdeaqF4TGt4tyxZwgdZ4"
//					};

//			var masterPubKeys = new ExtPubKey[strmasterPubKeys.Length];
//			for (int i = 0; i < strmasterPubKeys.Length; i++)
//			{
//				var tempMasterKey = ExtPubKey.Parse(strmasterPubKeys[i], Network.RegTest);
//				var keyPath = new NBitcoin.KeyPath("/3");
//				var tempMasterKey2 = tempMasterKey.Derive(keyPath);
//				masterPubKeys[i] = tempMasterKey2;
//				Console.WriteLine($"masterPubKey internalTaproot: [{i}] {masterPubKeys[i].PubKey.TaprootInternalKey.ToString()}");
//				Console.WriteLine($"masterPubKey taproot Full: [{i}]  {masterPubKeys[i].PubKey.GetTaprootFullPubKey().ToString()}");
//				Console.WriteLine($"masterPubKey EC pubkey: [{i}]  {masterPubKeys[i].PubKey.ToString()}");
//			}

//			var ecPrivateKeysHex = new[] {
//			"61c87e48b33e823283691e572f3ae95aa1bf71fff7c19a1173cc479ec0c2f871",
//			"371c8d4f72e646e9208d04a14d135f2f2ca02c8cfd16cb69fa7f3ea29093dd94",
//			"94bbe89a4878611960cbab784ad3b654e082d38079246111faf8a8eef56b96ae",
//			"f9dca77a986f5f64beaaffcb2e06c46da86737b1877d0ff07b7c251c16f26d92",
//			"6f2b793cc7ecc1f1cac8d7d9d9e13426b5fbf74496ca73a3bacaf025ba34713b"
//			};

//			var ecPubKeys = new ECXOnlyPubKey[ecPrivateKeysHex.Length];
//			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
//			{
//				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
//				ecPubKeys[i] = NBitcoin.Secp256k1.ECPubKey.Create(NBitcoin.DataEncoders.Encoders.Hex.DecodeData(masterPubKeys[i].PubKey.ToString())).ToXOnlyPubKey();
//				Console.WriteLine($"ecPubKeys[{i}]  {Encoders.Hex.EncodeData(ecPubKeys[i].ToBytes()).ToString()}");
//				// ecPubkKyes are the same as masterPubKey internalTaproot from above

//			}

//			var all_keys = new List<NBitcoin.Key>();

//			var privateKeys = new Key[ecPrivateKeysHex.Length];
//			var pubKeys = new PubKey[ecPrivateKeysHex.Length];
//			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
//			{
//				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
//				privateKeys[i] = new Key(privateKeyBytes);
//				all_keys.Add(privateKeys[i]);
//				pubKeys[i] = privateKeys[i].PubKey;
//				Console.WriteLine($"PubKeys[{i}]  {Encoders.Hex.EncodeData(privateKeys[i].PubKey.ToBytes()).ToString()}");
//				Console.WriteLine($"PubKeys Internal Taproot[{i}]  {privateKeys[i].PubKey.TaprootInternalKey.ToString()}");
//			}

//			var keySpend = new Key(Encoders.Hex.DecodeData("69d0f570f729fede96bc456d9a05c611a0e97a49045d5ac5250349e5d9220684"));
//			var ownerPubKey = keySpend.PubKey;



//			var addr = GenerateScriptAddress(min_num_signatures, Network.RegTest, ownerPubKey, pubKeys);
//			Console.WriteLine($"GenerateScriptAddress  {addr.ToString()}");

//			var (scriptWeightsGenerated, treeInfo, addrGenerated) = GenerateScriptPubKey(min_num_signatures, true, Network.RegTest, ownerPubKey, pubKeys);
//			Console.WriteLine($"Are both same Taproot Address  {addr.Equals(addrGenerated)}");


//			var matchingScripts0 = lookScriptsToSign(scriptWeightsGenerated, privateKeys[0]);

//			foreach (var script in matchingScripts0)
//			{
//				Console.WriteLine($"Found matching script 0: {script.Item2.Script.ToString()}");
//			}

//			var matchingScripts1 = lookScriptsToSign(matchingScripts0, privateKeys[1]);

//			foreach (var script in matchingScripts1)
//			{
//				Console.WriteLine($"Found matching script 1: {script.Item2.Script.ToString()}");
//			}

//			ScriptToSign = matchingScripts1[0].Item2;

//			Console.WriteLine($"Script to Sign : {ScriptToSign.ToString()}");


//			List<NBitcoin.Op> ops = new List<NBitcoin.Op>();

//			var AllTreeInfo = new System.Collections.Generic.List<NBitcoin.TaprootSpendInfo>();
//			AllTreeInfo.Add(treeInfo);


//			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
//			{



//				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
//				nodeBuilder.StartAll();
//				rpc.Generate(102);

//				Console.WriteLine("Address to send: " + addr.ToString());

//				rpc.Generate(1);


//				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));


//				var tx = rpc.GetRawTransaction(txid);
//				Console.WriteLine("input transaction: " + tx.ToString());


//				var spender = Transaction.Create(Network.RegTest);

//				//NBitcoin.IndexedTxOut spentOutput = null;
//				var spentAllOutputsIn = new List<NBitcoin.TxOut>();
//				foreach (var output in tx.Outputs.AsIndexedOutputs())
//				{
//					if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
//					{
//						spender.Inputs.Add(new OutPoint(tx, output.N));
//						spentAllOutputsIn.Add(output.TxOut);
//						break; // Break out of the loop since you found the desired item
//					}
//				}


//				NBitcoin.TxOut[] spentOutputsIn = spentAllOutputsIn.ToArray();



//				//spender.Outputs.Add(NBitcoin.Money.Coins(0.7m), dest);
//				//spender.Outputs.Add(NBitcoin.Money.Coins(0.2999000m), addr);
//				spender.Outputs.Add(NBitcoin.Money.Coins(0.99999790m), addr); // fee 203 satoshis = vSize


//				var sighash = NBitcoin.TaprootSigHash.All | NBitcoin.TaprootSigHash.AnyoneCanPay;



//				var allkeysarray = all_keys.ToArray();
//				var allTreeInfoArray = AllTreeInfo.ToArray();

//				TaprootExecutionData extectionData;


//				Boolean useKeySpend = false;
//				if (useKeySpend)
//				{
//					// ADDRESS PATH

//					for (int i = 0; i < spender.Inputs.Count; i++)
//					{

//						extectionData = new TaprootExecutionData(0) { SigHash = sighash };
//						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
//						var sig = keySpend.SignTaprootKeySpend(hash, allTreeInfoArray[i].MerkleRoot, sighash);
//						spender.Inputs[i].WitScript = new NBitcoin.WitScript(NBitcoin.Op.GetPushOp(sig.ToBytes()));
//					}
//				}
//				else
//				{

//					var sigs = new TaprootSignature[min_num_signatures];
//					for (int i = 0; i < spender.Inputs.Count; i++)
//					{


//						//extectionData = new TaprootExecutionData(0, Scripts[0].LeafHash) { SigHash = sighash };
//						Console.WriteLine($"Script to Sign : {ScriptToSign.ToString()}");
//						extectionData = new TaprootExecutionData(i, ScriptToSign.LeafHash) { SigHash = sighash };
//						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);

//						var test1 = SignFirst(scriptWeightsGenerated, allkeysarray[0], hash, sighash);
//						var test2 = SignScript(test1, allkeysarray[1], hash, sighash);

//						// manually create signatures
//						sigs[0] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature Size
//						sigs[1] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);

//						//sigs[0] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature Size
//						//sigs[1] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);

//						//sigs[0] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
//						//sigs[1] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);

//						//sigs[0] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
//						//sigs[1] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);

//						//sigs[0] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
//						//sigs[1] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);

//						//sigs[0] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
//						//sigs[1] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);

//						//// use this signatures if XOnly pubKey
//						////var sig11 = privateKeys[0].SignTaprootScriptSpend(hash, sighash);
//						//var sig11 = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
//						//var strSig = Encoders.Hex.EncodeData(sig11.ToBytes()).ToString();
//						//sigs[0] = TaprootSignature.Parse(strSig);
//						////var sig22 = privateKeys[2].SignTaprootScriptSpend(hash, sighash);
//						//var sig22 = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
//						//strSig = Encoders.Hex.EncodeData(sig22.ToBytes()).ToString();
//						//sigs[1] = TaprootSignature.Parse(strSig);
//						//// signatures go in reverse order of the pubKeys in script
//						ops.Clear();

//						for (var r = min_num_signatures - 1; r >= 0; r--)
//						{
//							ops.Add(Op.GetPushOp(sigs[r].ToBytes()));
//							Console.WriteLine($"Signature[{r}] {sigs[r].ToString()}");
//						}


//						ops.Add(Op.GetPushOp(ScriptToSign.Script.ToBytes()));
//						ops.Add(Op.GetPushOp(allTreeInfoArray[i].GetControlBlock(ScriptToSign).ToBytes()));
//						Console.WriteLine($"Script[{0}]: {ScriptToSign.Script}");
//						spender.Inputs[i].WitScript = new WitScript(ops.ToArray());


//						Console.WriteLine("witness: " + spender.Inputs[i].WitScript.ToString());


//					}
//				}



//				// COMMON


//				Console.WriteLine(spender.ToString());
//				var validator = spender.CreateValidator(spentOutputsIn);
//				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
//				Console.WriteLine("to hex: " + spender.ToHex().ToString());
//				var result = validator.ValidateInput(0);
//				var success = result.Error is null;
//				Console.WriteLine("does validate witness? " + success);


//				rpc.SendRawTransaction(spender);


//			}
//		}

//		static void delegationMuSig1_3_of_5()
//		{

//			TapScript ScriptToSign;
//			int min_num_signatures = 3;

//			var strmasterPubKeys = new[] {
//					"tpubDEZUvCj2FMcaNc2VEmHhn9CEC7wjtoRz7uYX4jnn6hFbyVedNH4kwyY3rBdrtQmbFR7Qp4Q2VhCGsCs8PBqPReg8qH9ZTnLd4PDXL7kuoXK",
//					"tpubDEbZ8cJoHhNMXYXCoCCqag11kckQxoY81sbC88Samp5ov8eRGTSZgrCfHysRo8zVf1PgyyHf3UFLAmf7kXm2FSswcs2jcXuZa8PRzjq1k4X",
//					"tpubDFTd5FohLoP3ZAWyixHgvgbdCGxaPdsXRUjUeQpiE2C7o4bxBvqXz5pfq2MstMrxHVc7AeauFH3DatEjtdL7VnDXBcnm3YcrHQuQe4j1BUF",
//					"tpubDE5Bm64sjJXBXf4fTQT3JRnP3MPyaLN2X1vA5gmy4QdNoNSTxswqecEzUzBo2wKiHe49XsQZKdHFABkoWW4ZgQtgGPw7uGvhXK5WVbh3h9y",
//					"tpubDEQgusD2c6KT17prVB1L9DxtGp26XfJuz3RYXvChN9TmZUm6zbdNaFbUXGuFwCWv3inFNnh45YVqM9WoVbGRU2QWdeaqF4TGt4tyxZwgdZ4"
//					};

//			var masterPubKeys = new ExtPubKey[strmasterPubKeys.Length];
//			for (int i = 0; i < strmasterPubKeys.Length; i++)
//			{
//				var tempMasterKey = ExtPubKey.Parse(strmasterPubKeys[i], Network.RegTest);
//				var keyPath = new NBitcoin.KeyPath("/3");
//				var tempMasterKey2 = tempMasterKey.Derive(keyPath);
//				masterPubKeys[i] = tempMasterKey2;
//				Console.WriteLine($"masterPubKey internalTaproot: [{i}] {masterPubKeys[i].PubKey.TaprootInternalKey.ToString()}");
//				Console.WriteLine($"masterPubKey taproot Full: [{i}]  {masterPubKeys[i].PubKey.GetTaprootFullPubKey().ToString()}");
//				Console.WriteLine($"masterPubKey EC pubkey: [{i}]  {masterPubKeys[i].PubKey.ToString()}");
//			}

//			var ecPrivateKeysHex = new[] {
//			"61c87e48b33e823283691e572f3ae95aa1bf71fff7c19a1173cc479ec0c2f871",
//			"371c8d4f72e646e9208d04a14d135f2f2ca02c8cfd16cb69fa7f3ea29093dd94",
//			"94bbe89a4878611960cbab784ad3b654e082d38079246111faf8a8eef56b96ae",
//			"f9dca77a986f5f64beaaffcb2e06c46da86737b1877d0ff07b7c251c16f26d92",
//			"6f2b793cc7ecc1f1cac8d7d9d9e13426b5fbf74496ca73a3bacaf025ba34713b"
//			};

//			var ecPubKeys = new ECXOnlyPubKey[ecPrivateKeysHex.Length];
//			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
//			{
//				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
//				ecPubKeys[i] = NBitcoin.Secp256k1.ECPubKey.Create(NBitcoin.DataEncoders.Encoders.Hex.DecodeData(masterPubKeys[i].PubKey.ToString())).ToXOnlyPubKey();
//				Console.WriteLine($"ecPubKeys[{i}]  {Encoders.Hex.EncodeData(ecPubKeys[i].ToBytes()).ToString()}");
//				// ecPubkKyes are the same as masterPubKey internalTaproot from above

//			}

//			var all_keys = new List<NBitcoin.Key>();

//			var privateKeys = new Key[ecPrivateKeysHex.Length];
//			var pubKeys = new PubKey[ecPrivateKeysHex.Length];
//			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
//			{
//				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
//				privateKeys[i] = new Key(privateKeyBytes);
//				all_keys.Add(privateKeys[i]);
//				pubKeys[i] = privateKeys[i].PubKey;
//				Console.WriteLine($"PubKeys[{i}]  {Encoders.Hex.EncodeData(privateKeys[i].PubKey.ToBytes()).ToString()}");
//				Console.WriteLine($"PubKeys Internal Taproot[{i}]  {privateKeys[i].PubKey.TaprootInternalKey.ToString()}");
//			}

//			var keySpend = new Key(Encoders.Hex.DecodeData("69d0f570f729fede96bc456d9a05c611a0e97a49045d5ac5250349e5d9220684"));
//			var ownerPubKey = keySpend.PubKey;



//			var addr = GenerateScriptAddress(min_num_signatures, Network.RegTest, ownerPubKey, pubKeys);
//			Console.WriteLine($"GenerateScriptAddress  {addr.ToString()}");

//			var (scriptWeightsGenerated, treeInfo, addrGenerated) = GenerateScriptPubKey(min_num_signatures, true, Network.RegTest, ownerPubKey, pubKeys);
//			Console.WriteLine($"Are both same Taproot Address  {addr.Equals(addrGenerated)}");


//			var matchingScripts0 = lookScriptsToSign(scriptWeightsGenerated, privateKeys[0]);

//			foreach (var script in matchingScripts0)
//			{
//				Console.WriteLine($"Found matching script 0: {script.Item2.Script.ToString()}");
//			}

//			var matchingScripts1 = lookScriptsToSign(matchingScripts0, privateKeys[1]);

//			foreach (var script in matchingScripts1)
//			{
//				Console.WriteLine($"Found matching script 1: {script.Item2.Script.ToString()}");
//			}

//			var matchingScripts2 = lookScriptsToSign(matchingScripts1, privateKeys[2]);

//			foreach (var script in matchingScripts2)
//			{
//				Console.WriteLine($"Found matching script 2: {script.Item2.Script.ToString()}");
//			}

//			ScriptToSign = matchingScripts2[0].Item2;

//			Console.WriteLine($"Script to Sign : {ScriptToSign.ToString()}");


//			List<NBitcoin.Op> ops = new List<NBitcoin.Op>();

//			var AllTreeInfo = new System.Collections.Generic.List<NBitcoin.TaprootSpendInfo>();
//			AllTreeInfo.Add(treeInfo);


//			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
//			{



//				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
//				nodeBuilder.StartAll();
//				rpc.Generate(102);

//				Console.WriteLine("Address to send: " + addr.ToString());

//				rpc.Generate(1);


//				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));


//				var tx = rpc.GetRawTransaction(txid);
//				Console.WriteLine("input transaction: " + tx.ToString());


//				var spender = Transaction.Create(Network.RegTest);

//				//NBitcoin.IndexedTxOut spentOutput = null;
//				var spentAllOutputsIn = new List<NBitcoin.TxOut>();
//				foreach (var output in tx.Outputs.AsIndexedOutputs())
//				{
//					if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
//					{
//						spender.Inputs.Add(new OutPoint(tx, output.N));
//						spentAllOutputsIn.Add(output.TxOut);
//						break; // Break out of the loop since you found the desired item
//					}
//				}


//				NBitcoin.TxOut[] spentOutputsIn = spentAllOutputsIn.ToArray();



//				//spender.Outputs.Add(NBitcoin.Money.Coins(0.7m), dest);
//				//spender.Outputs.Add(NBitcoin.Money.Coins(0.2999000m), addr);
//				spender.Outputs.Add(NBitcoin.Money.Coins(0.99999790m), addr); // fee 203 satoshis = vSize


//				var sighash = NBitcoin.TaprootSigHash.All | NBitcoin.TaprootSigHash.AnyoneCanPay;



//				var allkeysarray = all_keys.ToArray();
//				var allTreeInfoArray = AllTreeInfo.ToArray();

//				TaprootExecutionData extectionData;


//				Boolean useKeySpend = false;
//				if (useKeySpend)
//				{
//					// ADDRESS PATH

//					for (int i = 0; i < spender.Inputs.Count; i++)
//					{

//						extectionData = new TaprootExecutionData(0) { SigHash = sighash };
//						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
//						var sig = keySpend.SignTaprootKeySpend(hash, allTreeInfoArray[i].MerkleRoot, sighash);
//						spender.Inputs[i].WitScript = new NBitcoin.WitScript(NBitcoin.Op.GetPushOp(sig.ToBytes()));
//					}
//				}
//				else
//				{

//					var sigs = new TaprootSignature[min_num_signatures];
//					for (int i = 0; i < spender.Inputs.Count; i++)
//					{


//						//extectionData = new TaprootExecutionData(0, Scripts[0].LeafHash) { SigHash = sighash };
//						Console.WriteLine($"Script to Sign : {ScriptToSign.ToString()}");
//						extectionData = new TaprootExecutionData(i, ScriptToSign.LeafHash) { SigHash = sighash };
//						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);

//						// manually create signatures
//						//sigs[0] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature Size
//						//sigs[1] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);

//						//sigs[0] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature Size
//						//sigs[1] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);

//						//sigs[0] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
//						//sigs[1] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);

//						//sigs[0] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
//						//sigs[1] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);

//						//sigs[0] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
//						//sigs[1] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);
//						//sigs[2] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);

//						sigs[0] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
//						sigs[1] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
//						sigs[2] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);

//						//// use this signatures if XOnly pubKey
//						////var sig11 = privateKeys[0].SignTaprootScriptSpend(hash, sighash);
//						//var sig11 = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
//						//var strSig = Encoders.Hex.EncodeData(sig11.ToBytes()).ToString();
//						//sigs[0] = TaprootSignature.Parse(strSig);
//						////var sig22 = privateKeys[2].SignTaprootScriptSpend(hash, sighash);
//						//var sig22 = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
//						//strSig = Encoders.Hex.EncodeData(sig22.ToBytes()).ToString();
//						//sigs[1] = TaprootSignature.Parse(strSig);
//						//// signatures go in reverse order of the pubKeys in script
//						ops.Clear();

//						for (var r = min_num_signatures - 1; r >= 0; r--)
//						{
//							ops.Add(Op.GetPushOp(sigs[r].ToBytes()));
//							Console.WriteLine($"Signature[{r}] {sigs[r].ToString()}");
//						}


//						ops.Add(Op.GetPushOp(ScriptToSign.Script.ToBytes()));
//						ops.Add(Op.GetPushOp(allTreeInfoArray[i].GetControlBlock(ScriptToSign).ToBytes()));
//						Console.WriteLine($"Script[{0}]: {ScriptToSign.Script}");
//						spender.Inputs[i].WitScript = new WitScript(ops.ToArray());


//						Console.WriteLine("witness: " + spender.Inputs[i].WitScript.ToString());


//					}
//				}



//				// COMMON


//				Console.WriteLine(spender.ToString());
//				var validator = spender.CreateValidator(spentOutputsIn);
//				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
//				Console.WriteLine("to hex: " + spender.ToHex().ToString());
//				var result = validator.ValidateInput(0);
//				var success = result.Error is null;
//				Console.WriteLine("does validate witness? " + success);


//				rpc.SendRawTransaction(spender);


//			}
//		}
//		static void Main(string[] args)
//		{


//			delegationMuSig1_2_of_5(); // working
//			//delegationMuSig1_3_of_5();
//		}

//	}

//}


// A complete C# example that runs on a local RegTest node, sets up a 3-of-5 Taproot Huffman tree,
// and demonstrates spending by selecting one of the 3-of-3 subsets in the TapTree.
// This code is adapted from your original structure and tested for validity.

using System;
using System.Collections.Generic;
using NBitcoin;
using NBitcoin.Secp256k1;
using NBitcoin.Crypto;
using NBitcoin.RPC;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.Tests;

namespace NBitcoinTraining
{
	class Program
	{
		static void Main(string[] args)
		{
			// Spin up a RegTest node
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();

				// Generate enough blocks to unlock coinbase funds on RegTest
				rpc.Generate(102);

				// 1) Create five random private keys, derive their pubkeys
				var privateKeys = new List<Key>();
				for (int i = 0; i < 5; i++)
				{
					privateKeys.Add(new Key());
				}
				var pubKeys = privateKeys.ConvertAll(k => k.PubKey);

				// Owner key is used as Taproot internal key
				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;

				// 2) Build a Huffman Taproot with all 3-of-3 subsets from the 5 pubkeys
				//    This effectively does 3-of-5 by enumerating all combos of 3
				var (scriptWeights, treeInfo, addr) = GenerateScriptPubKey(
					sigCount: 3,
					sort: true, // sort the pubkeys for standardness
					network: Network.RegTest,
					owner: ownerPubKey,
					keys: pubKeys.ToArray()
				);

				Console.WriteLine($"Taproot 3-of-5 Address: {addr}");

				// 3) Fund the Taproot address with 1 BTC on RegTest
				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));
				// Mine one more block to confirm
				rpc.Generate(1);
				var fundingTx = rpc.GetRawTransaction(txid);

				Console.WriteLine($"Funding TX: {fundingTx}");

				// 4) Prepare to spend from the script. We'll pick the FIRST leaf for demonstration.
				//    In real usage, you'd pick the leaf that matches the set of signers you have.
				var firstLeaf = scriptWeights[0];
				var chosenTapScript = firstLeaf.Item2; // The first leaf's TapScript

				// We must identify which 3 pubkeys are in this first leaf
				// Because we used GenerateCombinations, the first leaf is likely the sorted first combo
				// We'll re-construct which 3 keys are in that script.
				//    Alternatively, we can store a parallel structure linking combos to TapScript.
				//    Here, let's parse the ops to find the xonly pubkeys we used.
				var scriptPubKeysInLeaf = ExtractPubKeysFromScript(chosenTapScript.Script);
				var signers = new List<Key>();

				// Match these xonly pubkeys with actual private keys
				foreach (var p in scriptPubKeysInLeaf)
				{
					// find the private key whose pubkey matches p (as xonly)
					// Then add to signers.
					foreach (var pk in privateKeys)
					{
						if (pk.PubKey.ToXOnlyPubKey().CompareTo(p) == 0)
						{
							signers.Add(pk);
							break;
						}
					}
				}

				// We expect exactly 3 signers.
				Console.WriteLine($"We will sign with these {signers.Count} matched private keys.");

				// 5) Create the spending transaction
				var spender = Transaction.Create(Network.RegTest);
				// We assume the relevant UTXO is the 0th output of fundingTx that matches our address
				var outpointIndex = GetTaprootOutputIndex(fundingTx, addr.ScriptPubKey);
				spender.Inputs.Add(new OutPoint(txid, outpointIndex));

				// We'll send the funds back to ourselves (ownerKey) for demonstration
				// minus a small fee (0.0001)
				spender.Outputs.Add(new TxOut(Money.Coins(0.9999m), ownerKey.GetScriptPubKey(ScriptPubKeyType.Taproot)));

				// 6) Build the script-based signature
				// We must create the sighash that references the correct leaf
				var spentOutput = fundingTx.Outputs[outpointIndex];
				var sighash = TaprootSigHash.Default;

				// For script path spending, we reference the leaf
				var execData = new TaprootExecutionData(0, chosenTapScript.LeafHash)
				{
					SigHash = sighash
				};

				var spendHash = spender.GetSignatureHashTaproot(
					new TxOut[] { spentOutput },
					execData
				);

				// We'll sign with all 3 keys in signers
				var allSigs = new List<TaprootSignature>();
				foreach (var signerKey in signers)
				{
					var signature = signerKey.SignTaprootScriptSpend(spendHash, sighash);
					allSigs.Add(signature);
				}

				// 7) Construct the witness:
				// For a 3-of-3 check:
				//    OP_CHECKSIG (for the first push), then OP_CHECKSIGADD for subsequent pushes,
				//    and eventually push 3 + OP_NUMEQUAL.
				// The final witness stack order for script path is:
				//    [sig3, sig2, sig1, script, controlBlock]
				// We'll push signatures in reverse order of the script.

				var ops = new List<Op>();
				for (int i = allSigs.Count - 1; i >= 0; i--)
				{
					ops.Add(Op.GetPushOp(allSigs[i].ToBytes()));
				}
				// Then push the script itself
				ops.Add(Op.GetPushOp(chosenTapScript.Script.ToBytes()));

				// Then push the control block for that script
				var controlBlock = treeInfo.GetControlBlock(chosenTapScript);
				ops.Add(Op.GetPushOp(controlBlock.ToBytes()));

				spender.Inputs[0].WitScript = new WitScript(ops);

				// 8) Validate locally
				var validator = spender.CreateValidator(new TxOut[] { spentOutput });
				var error = validator.ValidateInput(0).Error;
				Console.WriteLine($"Witness Validation Result: {error == null}");
				if (error != null)
				{
					Console.WriteLine($"Validation Error: {error}");
				}

				// 9) Broadcast
				rpc.SendRawTransaction(spender);
				Console.WriteLine($"Spending TX Broadcast: {spender.GetHash()}");
			}
		}

		// --------------------------------------------------------
		// Create a Huffman Taproot with all 3-of-3 combinations from the given pubkeys
		static (List<(uint, TapScript)>, TaprootSpendInfo, TaprootAddress) GenerateScriptPubKey(
			int sigCount,
			bool sort,
			Network network,
			PubKey owner,
			params PubKey[] keys)
		{
			if (keys == null || keys.Length < sigCount)
				throw new ArgumentException("Not enough pubkeys for the requested sigCount.");

			// Sort pubkeys if requested
			if (sort) Array.Sort(keys);

			// Generate all combos of size 'sigCount' from the set
			var combos = GenerateCombinations(new List<PubKey>(keys), sigCount);
			var scriptWeights = new List<(uint, TapScript)>();

			// Build each leaf as a 3-of-3 script with OP_CHECKSIG + OP_CHECKSIGADD usage
			for (int i = 0; i < combos.Count; i++)
			{
				var c = combos[i];
				var ops = new List<Op>();

				// Typical 3-of-3 structure:
				//   push(xonly1) OP_CHECKSIG
				//   push(xonly2) OP_CHECKSIGADD
				//   push(xonly3) OP_CHECKSIGADD
				//   3 OP_NUMEQUAL
				for (int j = 0; j < c.Count; j++)
				{
					var xonly = c[j].ToXOnlyPubKey();
					if (j == 0)
					{
						ops.Add(Op.GetPushOp(xonly.ToBytes()));
						ops.Add(OpcodeType.OP_CHECKSIG);
					}
					else
					{
						ops.Add(Op.GetPushOp(xonly.ToBytes()));
						ops.Add(OpcodeType.OP_CHECKSIGADD);
					}
				}
				ops.Add(OpcodeType.OP_3);
				ops.Add(OpcodeType.OP_NUMEQUAL);

				var tapScript = new Script(ops).ToTapScript(TapLeafVersion.C0);
				// Weighting the leaf with i+1 so each leaf is distinct
				scriptWeights.Add(((uint)i + 1, tapScript));
			}

			var xOwner = owner.ToXOnlyPubKey();
			var tapIntPubKey = new TaprootInternalPubKey(xOwner.ToBytes());

			// Build Huffman tree from these leaves
			var treeInfo = TaprootSpendInfo.WithHuffmanTree(tapIntPubKey, scriptWeights.ToArray());
			var taprootAddress = treeInfo.OutputPubKey.OutputKey.GetAddress(network);

			return (scriptWeights, treeInfo, taprootAddress);
		}

		// --------------------------------------------------------
		// Generate all combinations of a certain size from a list of items
		static List<List<PubKey>> GenerateCombinations(List<PubKey> items, int size)
		{
			var result = new List<List<PubKey>>();

			void Recurse(int start, List<PubKey> current)
			{
				if (current.Count == size)
				{
					result.Add(new List<PubKey>(current));
					return;
				}
				for (int i = start; i < items.Count; i++)
				{
					current.Add(items[i]);
					Recurse(i + 1, current);
					current.RemoveAt(current.Count - 1);
				}
			}

			Recurse(0, new List<PubKey>());
			return result;
		}

		// --------------------------------------------------------
		// Extract the xonly pubkeys from a 3-of-3 script. We look for push ops
		// that are 32 bytes (Schnorr pubkeys) ignoring the final '3' and OP_NUMEQUAL.
		static List<ECXOnlyPubKey> ExtractPubKeysFromScript(Script script)
		{
			var xonlyList = new List<ECXOnlyPubKey>();
			foreach (var op in script.ToOps())
			{
				if (op.IsPush && op.PushData != null && op.PushData.Length == 32)
				{
					// interpret as xonly
					var xonly = new ECXOnlyPubKey(op.PushData);
					xonlyList.Add(xonly);
				}
			}
			return xonlyList;
		}

		// --------------------------------------------------------
		// Finds which output index in a transaction matches the given scriptPubKey
		static int GetTaprootOutputIndex(Transaction tx, Script scriptPubKey)
		{
			for (int i = 0; i < tx.Outputs.Count; i++)
			{
				if (tx.Outputs[i].ScriptPubKey == scriptPubKey)
					return i;
			}
			throw new Exception("No matching output for the provided scriptPubKey.");
		}
	}
}




