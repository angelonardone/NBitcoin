using System;
using System.Threading;
using NBitcoin;
using NBitcoin.Tests;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using NBitcoin.Crypto;
using System.Security.Cryptography;
using System.Reflection.Metadata;
using Newtonsoft.Json.Linq;
using System.Reflection;
using Newtonsoft.Json;
using static NBitcoin.WalletPolicies.Miniscript;
using NBitcoin.WalletPolicies;
using static NBitcoin.WalletPolicies.MiniscriptNode;


namespace NBitcoinTraining
{
	class Program
	{
		struct SignedScriptData
		{
			public (UInt32, TapScript) ScriptWeights;
			public List<(string, TaprootSignature)> signatures;

			// Constructor to ensure signatures list is always initialized
			public SignedScriptData(UInt32 weight, TapScript tapScript)
			{
				ScriptWeights = (weight, tapScript);
				signatures = new List<(string, TaprootSignature)>();  // Ensure it's initialized
			}
		}

		static List<List<PubKey>> GenerateCombinations(List<PubKey> items, int combinationSize)
		{
			if (items == null || combinationSize <= 0 || combinationSize > items.Count)
				throw new ArgumentException("Invalid input: Ensure the list is not null and the combination size is valid.");

			var result = new List<List<PubKey>>();
			GenerateCombinationsRecursive(items, combinationSize, 0, new List<PubKey>(), result);
			return result;
		}

		static void GenerateCombinationsRecursive(List<PubKey> items, int combinationSize, int start, List<PubKey> current, List<List<PubKey>> result)
		{
			if (current.Count == combinationSize)
			{
				result.Add(new List<PubKey>(current));
				return;
			}

			for (int i = start; i < items.Count; i++)
			{
				current.Add(items[i]);
				GenerateCombinationsRecursive(items, combinationSize, i + 1, current, result);
				current.RemoveAt(current.Count - 1);
			}
		}

		static (List<(uint, TapScript)>, TaprootSpendInfo, TaprootAddress) GenerateScriptPubKey(int sigCount, bool sort, Network network, PubKey owner, params PubKey[] keys)
		{
			if (keys == null)
				throw new ArgumentNullException(nameof(keys));
			if (owner == null)
				throw new ArgumentNullException(nameof(keys));
			if (sort)
				Array.Sort(keys);
			if (sigCount <= 1 || sigCount > 16)
				throw new ArgumentException("Invalid input: The number of signatures must be between 2 and 16.");

			List<List<PubKey>> combinations = new List<List<PubKey>>();

			try
			{
				combinations = GenerateCombinations(keys.ToList(), sigCount);
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error creating PubKey[] combination: {ex.Message}");
			}

			var peers = sigCount; // 3 per multisignature
			var howManyScripts = combinations.Count; // 5 combinations of 3 multisignatures
			var Scripts = new TapScript[howManyScripts];

			List<Op> ops = new List<Op>();
			var scriptWeightsList = new List<(UInt32, TapScript)>();
			var probability = (uint)(100 / howManyScripts);

			for (int i = 0; i < combinations.Count; i++)
			{


				//ops.Clear();
				////Console.WriteLine($"Combination {i + 1}:");
				//var pubkeys = combinations[i].Select(k => MiniscriptNode.Value.Create(k.GetTaprootFullPubKey())).ToArray();
				//var taproot = FragmentUnboundedParameters.multi_a([new Value.CountValue(peers), .. pubkeys]);
				//Scripts[i] = taproot.GetScript().ToTapScript(TapLeafVersion.C0);
				////Console.WriteLine($"Script[{i}]: {Scripts[i].ToString()}");
				////scriptWeightsList.Add((probability, Scripts[i]));
				//scriptWeightsList.Add((probability, Scripts[i]));


				ops.Clear();
				//Console.WriteLine($"Combination {i + 1}:");
				int p = 1;
				foreach (var pubKey in combinations[i])
				{
					//Console.WriteLine($"  {pubKey.ToString()}");
					var xonlypubk = ECPubKey.Create(Encoders.Hex.DecodeData(pubKey.ToString())).ToXOnlyPubKey();
					ops.Add(Op.GetPushOp(xonlypubk.ToBytes()));

					if (p == 1)
					{
						ops.Add(OpcodeType.OP_CHECKSIG);
					}
					else
					{
						ops.Add(OpcodeType.OP_CHECKSIGADD);
					}
					p += 1;

				}

				switch (peers)
				{
					case 2: ops.Add(OpcodeType.OP_2); break;
					case 3: ops.Add(OpcodeType.OP_3); break;
					case 4: ops.Add(OpcodeType.OP_4); break;
					case 5: ops.Add(OpcodeType.OP_5); break;
					case 6: ops.Add(OpcodeType.OP_6); break;
					case 7: ops.Add(OpcodeType.OP_7); break;
					case 8: ops.Add(OpcodeType.OP_8); break;
					case 9: ops.Add(OpcodeType.OP_9); break;
					case 10: ops.Add(OpcodeType.OP_10); break;
					case 11: ops.Add(OpcodeType.OP_11); break;
					case 12: ops.Add(OpcodeType.OP_12); break;
					case 13: ops.Add(OpcodeType.OP_13); break;
					case 14: ops.Add(OpcodeType.OP_14); break;
					case 15: ops.Add(OpcodeType.OP_15); break;
					case 16: ops.Add(OpcodeType.OP_16); break;
				}
				ops.Add(OpcodeType.OP_NUMEQUAL);

				Scripts[i] = new Script(ops).ToTapScript(TapLeafVersion.C0);
				//Console.WriteLine($"Script[{i}]: {Scripts[i].ToString()}");
				scriptWeightsList.Add((probability, Scripts[i]));
				//scriptWeightsList.Add(((uint)i + 1, Scripts[i]));

			}

			var scriptWeights = scriptWeightsList.ToArray();
			var ec_PubKey = ECPubKey.Create(Encoders.Hex.DecodeData(owner.ToString()));
			var xOnlyFromPubkey = ec_PubKey.ToXOnlyPubKey();
			var tapIntFromEC = new TaprootInternalPubKey(xOnlyFromPubkey.ToBytes());
			var treeInfo = TaprootSpendInfo.WithHuffmanTree(tapIntFromEC, scriptWeights);
			var taprootPubKey = treeInfo.OutputPubKey.OutputKey;
			var addr = taprootPubKey.GetAddress(network);

			return (scriptWeightsList, treeInfo, addr);

		}
		static TaprootAddress GenerateScriptAddress(int sigCount, Network network, PubKey owner, params PubKey[] keys)
		{
			if (keys == null)
				throw new ArgumentNullException(nameof(keys));
			if (owner == null)
				throw new ArgumentNullException(nameof(keys));
			if (sigCount <= 1 || sigCount > 16)
				throw new ArgumentException("Invalid input: The number of signatures must be between 2 and 16.");

			var (scriptWeights, treeInfo, addr) = GenerateScriptPubKey(sigCount, true, network, owner, keys);

			return (addr);
		}

		static List<(UInt32, TapScript)> lookScriptsToSign(List<(UInt32, TapScript)> scriptWeightsList, Key privateKey)
		{
			if (privateKey == null)
				throw new ArgumentNullException(nameof(privateKey));

			//string? strXonlyPubkey = ECPubKey.Create(Encoders.Hex.DecodeData(privateKey.PubKey.ToString())).ToXOnlyPubKey().ToString();
			string? strXonlyPubkey = privateKey.PubKey.TaprootInternalKey.ToString();

			// Initialize a list to store matching scripts
			var matchingScripts = new List<(UInt32, TapScript)>();

			for (int i = 0; i < scriptWeightsList.Count; ++i)
			{
				var script = scriptWeightsList[i].Item2.Script;

				// Check if the script contains the public key string
				if (script.ToString().Contains(strXonlyPubkey))
				{
					matchingScripts.Add(scriptWeightsList[i]);
				}
			}

			return matchingScripts;
		}

		static List<SignedScriptData> SignFirst(List<(UInt32, TapScript)> scriptWeightsList, Key privateKey, uint256 hash, TaprootSigHash sighash)
		{

			if (privateKey == null)
				throw new ArgumentNullException(nameof(privateKey));

			if (scriptWeightsList == null || scriptWeightsList.Count == 0)
				throw new ArgumentException("No scripts provided for signing.");

			var matchingScripts = lookScriptsToSign(scriptWeightsList, privateKey);



			var signedScripts = new List<SignedScriptData>();


			foreach (var (weight, tapScript) in matchingScripts)
			{
				// Create a signedScript instance with a properly initialized list
				var signedScript = new SignedScriptData(weight, tapScript);

				// Generate the signature using the provided private key
				var signature = privateKey.SignTaprootScriptSpend(hash, sighash);
				var strXonlyPubkey = privateKey.PubKey.TaprootInternalKey.ToString();

				// Set the script weights
				signedScript.ScriptWeights = (weight, tapScript);

				// Ensure the list is initialized (alternative approach)
				if (signedScript.signatures == null)
				{
					signedScript.signatures = new List<(string, TaprootSignature)>();
				}

				// Add the generated signature
				signedScript.signatures.Add((strXonlyPubkey, signature));


				// Store the signed script
				signedScripts.Add(signedScript);
			}

			return signedScripts;
		}
		static List<SignedScriptData> SignScript(List<SignedScriptData> prevouslySigned, Key privateKey, uint256 hash, TaprootSigHash sighash)
		{

			if (privateKey == null)
				throw new ArgumentNullException(nameof(privateKey));

			if (prevouslySigned == null || prevouslySigned.Count == 0)
				throw new ArgumentException("No scripts provided for signing.");

			List<(UInt32, TapScript)> scriptWeightsList = new List<(UInt32, TapScript)>();

			foreach (var OnePrevouslySigned in prevouslySigned)
			{
				scriptWeightsList.Add(OnePrevouslySigned.ScriptWeights);
			}

			var matchingScripts = lookScriptsToSign(scriptWeightsList, privateKey);

			var signedScripts = new List<SignedScriptData>();

			foreach (var (weight, tapScript) in matchingScripts)
			{
				// Create a signedScript instance with a properly initialized list
				var signedScript = new SignedScriptData(weight, tapScript);

				// Generate the signature using the provided private key
				var signature = privateKey.SignTaprootScriptSpend(hash, sighash);
				var strXonlyPubkey = privateKey.PubKey.TaprootInternalKey.ToString();

				// Set the script weights
				signedScript.ScriptWeights = (weight, tapScript);

				// Ensure the list is initialized (alternative approach)
				if (signedScript.signatures == null)
				{
					signedScript.signatures = new List<(string, TaprootSignature)>();
				}

				// Add the generated signature
				signedScript.signatures.Add((strXonlyPubkey, signature));

				// now add previous signatures
				foreach (var OnePrevouslySigned in prevouslySigned)
				{
					if (OnePrevouslySigned.ScriptWeights.Item2.Equals(signedScript.ScriptWeights.Item2))
					{
						foreach (var oneSignature in OnePrevouslySigned.signatures)
						{
							signedScript.signatures.Add((oneSignature.Item1, oneSignature.Item2));

						}

						Console.WriteLine("MATCHEA");
					}
				}


				// Store the signed script
				signedScripts.Add(signedScript);
			}

			return signedScripts;
		}

		static void delegationMuSig1_2_of_5()
		{

			TapScript ScriptToSign;
			int min_num_signatures = 2;


			var ecPrivateKeysHex = new[] {
			"61c87e48b33e823283691e572f3ae95aa1bf71fff7c19a1173cc479ec0c2f871",
			"371c8d4f72e646e9208d04a14d135f2f2ca02c8cfd16cb69fa7f3ea29093dd94",
			"94bbe89a4878611960cbab784ad3b654e082d38079246111faf8a8eef56b96ae",
			"f9dca77a986f5f64beaaffcb2e06c46da86737b1877d0ff07b7c251c16f26d92",
			"6f2b793cc7ecc1f1cac8d7d9d9e13426b5fbf74496ca73a3bacaf025ba34713b"
			};



			var all_keys = new List<NBitcoin.Key>();

			var privateKeys = new Key[ecPrivateKeysHex.Length];
			var pubKeys = new PubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				privateKeys[i] = new Key(privateKeyBytes);
				all_keys.Add(privateKeys[i]);
				pubKeys[i] = privateKeys[i].PubKey;
				Console.WriteLine($"PubKeys[{i}]  {Encoders.Hex.EncodeData(privateKeys[i].PubKey.ToBytes()).ToString()}");
				Console.WriteLine($"PubKeys Internal Taproot[{i}]  {privateKeys[i].PubKey.TaprootInternalKey.ToString()}");
			}

			var keySpend = new Key(Encoders.Hex.DecodeData("69d0f570f729fede96bc456d9a05c611a0e97a49045d5ac5250349e5d9220684"));
			var ownerPubKey = keySpend.PubKey;



			var addr = GenerateScriptAddress(min_num_signatures, Network.RegTest, ownerPubKey, pubKeys);
			Console.WriteLine($"GenerateScriptAddress  {addr.ToString()}");

			//////////////// NEW DelegatedMultSig
			var multiSig = new DelegatedMultiSig(ownerPubKey, pubKeys.ToList(), min_num_signatures, Network.RegTest);
			var addr2 = multiSig.Address;
			Console.WriteLine($"DelegatedMultiSig  {addr2.ToString()}");
			Console.WriteLine($"Are both same Taproot Address  {addr.Equals(addr2)}");
			//////////////// NEW DelegatedMultSig

			var (scriptWeightsGenerated, treeInfo, addrGenerated) = GenerateScriptPubKey(min_num_signatures, true, Network.RegTest, ownerPubKey, pubKeys);
			Console.WriteLine($"Are both same Taproot Address  {addr.Equals(addrGenerated)}");

			//////////////////////////////////////////////////////////
			// here I'm looking for the ONE script in all the combination of 2-of-2 that froms the 2-of-5 multisignature using Tapscripts

			var matchingScripts0 = lookScriptsToSign(scriptWeightsGenerated, privateKeys[0]);

			foreach (var script in matchingScripts0)
			{
				Console.WriteLine($"Found matching script 0: {script.Item2.Script.ToString()}");
			}

			var matchingScripts1 = lookScriptsToSign(matchingScripts0, privateKeys[1]);

			foreach (var script in matchingScripts1)
			{
				Console.WriteLine($"Found matching script 1: {script.Item2.Script.ToString()}");
			}

			ScriptToSign = matchingScripts1[0].Item2;
			// here the ScriptToSign is the ONE script where the thre public keys are located
			// for privateKeys[0] and privateKeys[1]
			//////////////////////////////////////////////////////////

			Console.WriteLine($"Script to Sign : {ScriptToSign.ToString()}");


			List<NBitcoin.Op> ops = new List<NBitcoin.Op>();

			var AllTreeInfo = new System.Collections.Generic.List<NBitcoin.TaprootSpendInfo>();
			AllTreeInfo.Add(treeInfo);


			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{



				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				Console.WriteLine("Address to send: " + addr.ToString());

				rpc.Generate(1);


				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));


				var tx = rpc.GetRawTransaction(txid);
				Console.WriteLine("input transaction: " + tx.ToString());

				//////////////// NEW DelegatedMultSig
				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == multiSig.Address.ScriptPubKey);
				var coin = new Coin(spentOutput);
				var all_coins = new System.Collections.Generic.List<NBitcoin.Coin>();
				all_coins.Add(coin);
				//////////////// NEW DelegatedMultSig

				var spender = Transaction.Create(Network.RegTest);

				//NBitcoin.IndexedTxOut spentOutput = null;
				var spentAllOutputsIn = new List<NBitcoin.TxOut>();
				foreach (var output in tx.Outputs.AsIndexedOutputs())
				{
					if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
					{
						spender.Inputs.Add(new OutPoint(tx, output.N));
						spentAllOutputsIn.Add(output.TxOut);
						break; // Break out of the loop since you found the desired item
					}
				}


				NBitcoin.TxOut[] spentOutputsIn = spentAllOutputsIn.ToArray();



				//spender.Outputs.Add(NBitcoin.Money.Coins(0.7m), dest);
				//spender.Outputs.Add(NBitcoin.Money.Coins(0.2999000m), addr);
				spender.Outputs.Add(NBitcoin.Money.Coins(0.99999790m), addr); // fee 203 satoshis = vSize


				var sighash = NBitcoin.TaprootSigHash.All | NBitcoin.TaprootSigHash.AnyoneCanPay;



				var allkeysarray = all_keys.ToArray();
				var allTreeInfoArray = AllTreeInfo.ToArray();

				TaprootExecutionData extectionData;


				Boolean useKeySpend = false;
				if (useKeySpend)
				{
					// ADDRESS PATH

					for (int i = 0; i < spender.Inputs.Count; i++)
					{

						extectionData = new TaprootExecutionData(0) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
						var sig = keySpend.SignTaprootKeySpend(hash, allTreeInfoArray[i].MerkleRoot, sighash);
						Console.WriteLine($"Signature {sig.ToString()}");
						Console.WriteLine($"Signature Size: {sig.ToBytes().Length}");
						spender.Inputs[i].WitScript = new NBitcoin.WitScript(NBitcoin.Op.GetPushOp(sig.ToBytes()));
					}
				}
				else
				{

					var sigs = new TaprootSignature[min_num_signatures];
					for (int i = 0; i < spender.Inputs.Count; i++)
					{


						//extectionData = new TaprootExecutionData(0, Scripts[0].LeafHash) { SigHash = sighash };
						Console.WriteLine($"Script to Sign : {ScriptToSign.ToString()}");
						extectionData = new TaprootExecutionData(i, ScriptToSign.LeafHash) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);

						var test1 = SignFirst(scriptWeightsGenerated, allkeysarray[1], hash, sighash);
						var test2 = SignScript(test1, allkeysarray[0], hash, sighash);


						// manually create signatures
						sigs[0] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash); // signature OK
						sigs[1] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);

						//sigs[0] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
						//sigs[1] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
	
						//// signatures go in reverse order of the pubKeys in script
						ops.Clear();

						for (var r = min_num_signatures - 1; r >= 0; r--)
						{
							ops.Add(Op.GetPushOp(sigs[r].ToBytes()));
							//ops.Add(Op.GetPushOp(test2[0].signatures[r].Item2.ToBytes()));
					Console.WriteLine($"Signature[{r}] {sigs[r].ToString()}");
							Console.WriteLine($"Signature[{r}] Size: {sigs[r].ToBytes().Length}");
						}


						ops.Add(Op.GetPushOp(ScriptToSign.Script.ToBytes()));
						ops.Add(Op.GetPushOp(allTreeInfoArray[i].GetControlBlock(ScriptToSign).ToBytes()));
						Console.WriteLine($"Script[{0}]: {ScriptToSign.Script}");
						spender.Inputs[i].WitScript = new WitScript(ops.ToArray());


						Console.WriteLine("witness: " + spender.Inputs[i].WitScript.ToString());


					}
				}



				// COMMON


				Console.WriteLine(spender.ToString());
				var validator = spender.CreateValidator(spentOutputsIn);
				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
				Console.WriteLine("to hex: " + spender.ToHex().ToString());
				var result = validator.ValidateInput(0);
				var success = result.Error is null;
				Console.WriteLine("does validate witness? " + success);


				rpc.SendRawTransaction(spender);


			}
		}

		static void delegationMuSig1_3_of_5()
		{

			TapScript ScriptToSign;
			int min_num_signatures = 3;


			var strmasterPubKeys = new[] {
			"tpubDEZUvCj2FMcaNc2VEmHhn9CEC7wjtoRz7uYX4jnn6hFbyVedNH4kwyY3rBdrtQmbFR7Qp4Q2VhCGsCs8PBqPReg8qH9ZTnLd4PDXL7kuoXK",
			"tpubDEbZ8cJoHhNMXYXCoCCqag11kckQxoY81sbC88Samp5ov8eRGTSZgrCfHysRo8zVf1PgyyHf3UFLAmf7kXm2FSswcs2jcXuZa8PRzjq1k4X",
			"tpubDFTd5FohLoP3ZAWyixHgvgbdCGxaPdsXRUjUeQpiE2C7o4bxBvqXz5pfq2MstMrxHVc7AeauFH3DatEjtdL7VnDXBcnm3YcrHQuQe4j1BUF",
			"tpubDE5Bm64sjJXBXf4fTQT3JRnP3MPyaLN2X1vA5gmy4QdNoNSTxswqecEzUzBo2wKiHe49XsQZKdHFABkoWW4ZgQtgGPw7uGvhXK5WVbh3h9y",
			"tpubDEQgusD2c6KT17prVB1L9DxtGp26XfJuz3RYXvChN9TmZUm6zbdNaFbUXGuFwCWv3inFNnh45YVqM9WoVbGRU2QWdeaqF4TGt4tyxZwgdZ4"
			};

			var masterPubKeys = new ExtPubKey[strmasterPubKeys.Length];
			for (int i = 0; i < strmasterPubKeys.Length; i++)
			{
				var tempMasterKey = ExtPubKey.Parse(strmasterPubKeys[i], Network.RegTest);
				var keyPath = new NBitcoin.KeyPath("/3");
				var tempMasterKey2 = tempMasterKey.Derive(keyPath);
				masterPubKeys[i] = tempMasterKey2;
				Console.WriteLine($"masterPubKey internalTaproot: [{i}] {masterPubKeys[i].PubKey.TaprootInternalKey.ToString()}");
				Console.WriteLine($"masterPubKey taproot Full: [{i}]  {masterPubKeys[i].PubKey.GetTaprootFullPubKey().ToString()}");
				Console.WriteLine($"masterPubKey EC pubkey: [{i}]  {masterPubKeys[i].PubKey.ToString()}");
			}



				var ecPrivateKeysHex = new[] {
			"61c87e48b33e823283691e572f3ae95aa1bf71fff7c19a1173cc479ec0c2f871",
			"371c8d4f72e646e9208d04a14d135f2f2ca02c8cfd16cb69fa7f3ea29093dd94",
			"94bbe89a4878611960cbab784ad3b654e082d38079246111faf8a8eef56b96ae",
			"f9dca77a986f5f64beaaffcb2e06c46da86737b1877d0ff07b7c251c16f26d92",
			"6f2b793cc7ecc1f1cac8d7d9d9e13426b5fbf74496ca73a3bacaf025ba34713b"
			};

			var ecPubKeys = new ECXOnlyPubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				ecPubKeys[i] = NBitcoin.Secp256k1.ECPubKey.Create(NBitcoin.DataEncoders.Encoders.Hex.DecodeData(masterPubKeys[i].PubKey.ToString())).ToXOnlyPubKey();
				Console.WriteLine($"ecPubKeys[{i}]  {Encoders.Hex.EncodeData(ecPubKeys[i].ToBytes()).ToString()}");
				// ecPubkKyes are the same as masterPubKey internalTaproot from above
			}
			;


			var all_keys = new List<NBitcoin.Key>();

			var privateKeys = new Key[ecPrivateKeysHex.Length];
			var pubKeys = new PubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				privateKeys[i] = new Key(privateKeyBytes);
				all_keys.Add(privateKeys[i]);
				pubKeys[i] = privateKeys[i].PubKey;
				Console.WriteLine($"PubKeys[{i}]  {Encoders.Hex.EncodeData(privateKeys[i].PubKey.ToBytes()).ToString()}");
				Console.WriteLine($"PubKeys Internal Taproot[{i}]  {privateKeys[i].PubKey.TaprootInternalKey.ToString()}");
			}

			var keySpend = new Key(Encoders.Hex.DecodeData("69d0f570f729fede96bc456d9a05c611a0e97a49045d5ac5250349e5d9220684"));
			var ownerPubKey = keySpend.PubKey;



			var addr = GenerateScriptAddress(min_num_signatures, Network.RegTest, ownerPubKey, pubKeys);
			Console.WriteLine($"GenerateScriptAddress  {addr.ToString()}");

			var (scriptWeightsGenerated, treeInfo, addrGenerated) = GenerateScriptPubKey(min_num_signatures, true, Network.RegTest, ownerPubKey, pubKeys);
			Console.WriteLine($"Are both same Taproot Address  {addr.Equals(addrGenerated)}");


			//////////////////////////////////////////////////////////
			// here I'm looking for the ONE script in all the combination of 3-of-3 that froms the 3-of-5 multisignature using Tapscripts

			var matchingScripts0 = lookScriptsToSign(scriptWeightsGenerated, privateKeys[0]);

			foreach (var script in matchingScripts0)
			{
				Console.WriteLine($"Found matching script 0: {script.Item2.Script.ToString()}");
			}

			var matchingScripts1 = lookScriptsToSign(matchingScripts0, privateKeys[1]);

			foreach (var script in matchingScripts1)
			{
				Console.WriteLine($"Found matching script 1: {script.Item2.Script.ToString()}");
			}

			var matchingScripts2 = lookScriptsToSign(matchingScripts1, privateKeys[2]);

			foreach (var script in matchingScripts2)
			{
				Console.WriteLine($"Found matching script 2: {script.Item2.Script.ToString()}");
			}

			ScriptToSign = matchingScripts2[0].Item2;
			// here the ScriptToSign is the ONE script where the thre public keys are located
			// for privateKeys[0], privateKeys[1] and privateKeys[2]
			//////////////////////////////////////////////////////////

			Console.WriteLine($"Script to Sign : {ScriptToSign.ToString()}");


			List<NBitcoin.Op> ops = new List<NBitcoin.Op>();

			var AllTreeInfo = new System.Collections.Generic.List<NBitcoin.TaprootSpendInfo>();
			AllTreeInfo.Add(treeInfo);


			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{



				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				Console.WriteLine("Address to send: " + addr.ToString());

				rpc.Generate(1);


				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));


				var tx = rpc.GetRawTransaction(txid);
				Console.WriteLine("input transaction: " + tx.ToString());


				var spender = Transaction.Create(Network.RegTest);

				//NBitcoin.IndexedTxOut spentOutput = null;
				var spentAllOutputsIn = new List<NBitcoin.TxOut>();
				foreach (var output in tx.Outputs.AsIndexedOutputs())
				{
					if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
					{
						spender.Inputs.Add(new OutPoint(tx, output.N));
						spentAllOutputsIn.Add(output.TxOut);
						break; // Break out of the loop since you found the desired item
					}
				}


				NBitcoin.TxOut[] spentOutputsIn = spentAllOutputsIn.ToArray();



				//spender.Outputs.Add(NBitcoin.Money.Coins(0.7m), dest);
				//spender.Outputs.Add(NBitcoin.Money.Coins(0.2999000m), addr);
				spender.Outputs.Add(NBitcoin.Money.Coins(0.99999790m), addr); // fee 203 satoshis = vSize


				var sighash = NBitcoin.TaprootSigHash.All | NBitcoin.TaprootSigHash.AnyoneCanPay;



				var allkeysarray = all_keys.ToArray();
				var allTreeInfoArray = AllTreeInfo.ToArray();

				TaprootExecutionData extectionData;


				Boolean useKeySpend = false;
				if (useKeySpend)
				{
					// ADDRESS PATH

					for (int i = 0; i < spender.Inputs.Count; i++)
					{

						extectionData = new TaprootExecutionData(0) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
						var sig = keySpend.SignTaprootKeySpend(hash, allTreeInfoArray[i].MerkleRoot, sighash);
						spender.Inputs[i].WitScript = new NBitcoin.WitScript(NBitcoin.Op.GetPushOp(sig.ToBytes()));
					}
				}
				else
				{

					var sigs = new TaprootSignature[min_num_signatures];
					for (int i = 0; i < spender.Inputs.Count; i++)
					{


						//extectionData = new TaprootExecutionData(0, Scripts[0].LeafHash) { SigHash = sighash };
						Console.WriteLine($"Script to Sign : {ScriptToSign.ToString()}");
						extectionData = new TaprootExecutionData(i, ScriptToSign.LeafHash) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);

						// manually create signatures
						sigs[0] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature Size
						sigs[1] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);
						sigs[2] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);

						//sigs[0] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature Size
						//sigs[1] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
						//sigs[2] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);

						//sigs[0] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
						//sigs[1] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
						//sigs[2] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);

						//sigs[0] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
						//sigs[1] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
						//sigs[2] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);

						//sigs[0] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
						//sigs[1] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);
						//sigs[2] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);

						//sigs[0] = allkeysarray[2].SignTaprootScriptSpend(hash, sighash); // invalid Schnorr Signature
						//sigs[1] = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
						//sigs[2] = allkeysarray[1].SignTaprootScriptSpend(hash, sighash);


						ops.Clear();

						for (var r = min_num_signatures - 1; r >= 0; r--)
						{
							ops.Add(Op.GetPushOp(sigs[r].ToBytes()));
							Console.WriteLine($"Signature[{r}] {sigs[r].ToString()}");
							Console.WriteLine($"Signature[{r}] Size: {sigs[r].ToBytes().Length}");
						}


						ops.Add(Op.GetPushOp(ScriptToSign.Script.ToBytes()));
						ops.Add(Op.GetPushOp(allTreeInfoArray[i].GetControlBlock(ScriptToSign).ToBytes()));
						Console.WriteLine($"Script[{0}]: {ScriptToSign.Script}");
						spender.Inputs[i].WitScript = new WitScript(ops.ToArray());


						Console.WriteLine("witness: " + spender.Inputs[i].WitScript.ToString());


					}
				}



				// COMMON


				Console.WriteLine(spender.ToString());
				var validator = spender.CreateValidator(spentOutputsIn);
				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
				Console.WriteLine("to hex: " + spender.ToHex().ToString());
				var result = validator.ValidateInput(0);
				var success = result.Error is null;
				Console.WriteLine("does validate witness? " + success);


				rpc.SendRawTransaction(spender);


			}
		}
		static void Main(string[] args)
		{


			delegationMuSig1_2_of_5(); // working
			//delegationMuSig1_3_of_5(); // not working
		}

	}

}

