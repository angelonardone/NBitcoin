using System;
using System.Threading;
using NBitcoin;
using NBitcoin.Tests;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using NBitcoin.Crypto;


namespace NBitcoinTraining
{
	class Program
	{
		//static Context ctx = Context.Instance;

		static void Main(string[] args)
		{

			//testing_creating_pubkyes_multisig();
			//musig_address_and_path_spend_with_huffman();
			musig_address_and_path_spend_with_huffman_path();

		}


		static void testing_creating_pubkyes_multisig()
		{
			var peers = 2; // 2 per multisignature
			var howManyScripts = 3; // 3 combinations of 2 multisignatures
			var combinationOfPubKeys = new NBitcoin.Secp256k1.ECPubKey[peers];
			var combPubKeysForScripts = new NBitcoin.Secp256k1.ECPubKey[howManyScripts];
			var Scripts = new NBitcoin.TapScript[howManyScripts];
			string pubKeyString;

			var ctx = NBitcoin.Secp256k1.Context.Instance;

			for (int i = 0; i < howManyScripts; i++)
			{

				for (int p = 0; p < peers; p++)
				{
					pubKeyString = "022ad6db003ad8bd340aca9d083be80bc3b641aab3afa9a42ab24d591f53f0b279";
					combinationOfPubKeys[p] = NBitcoin.Secp256k1.ECPubKey.Create(NBitcoin.DataEncoders.Encoders.Hex.DecodeData(pubKeyString));
				}
				combPubKeysForScripts[i] = NBitcoin.Secp256k1.ECPubKey.MusigAggregate(combinationOfPubKeys);
			}


			var scriptWeightsList = new System.Collections.Generic.List<(UInt32, TapScript)>();
			var probability = (uint)(100 / howManyScripts);

			Console.WriteLine(probability.ToString());

			for (int j = 0; j < howManyScripts; j++)
			{

				Scripts[j] = new NBitcoin.Script(NBitcoin.Op.GetPushOp(combPubKeysForScripts[j].ToXOnlyPubKey().ToBytes()), NBitcoin.OpcodeType.OP_CHECKSIG).ToTapScript(NBitcoin.TapLeafVersion.C0);
				scriptWeightsList.Add((probability, Scripts[j]));
			}

			var scriptWeights = System.Linq.Enumerable.ToArray(scriptWeightsList.Select(t => (t.Item1, t.Item2)));


			/*
			NBitcoin.TaprootAddress tapPubAddress = NBitcoin.TaprootAddress.Create("hola", Network.RegTest);
			NBitcoin.TaprootPubKey publicKey = new NBitcoin.TaprootPubKey(tapPubAddress.PubKey.ToBytes());

			var aaaa = new TaprootInternalPubKey(tapPubAddress.PubKey.ToBytes());
			*/


			/* 	
			 {
			"PrivateKey": "043e1d9df83ddfdc4ab9bd0edb54277b94fa215b4d690080e2e9715bcefeef12",
			"PublicKey": "03e7ca096a85e45c9f96a80615eb59b04e34266c7b00981054cea1afe679798d53",
			"TaprootPubKey": "490acbd90e8649e108b20205c1a36a09b092875d3fb771c98ac83fe55bd66591",
			"PublicKeyHash": "4406d48f5aba1587bcee4e161754c0ada187995d",
			"ScriptPublicKey": "1 490acbd90e8649e108b20205c1a36a09b092875d3fb771c98ac83fe55bd66591",
			"Address": "bcrt1pfy9vhkgwsey7zz9jqgzurgm2pxcf9p6a87mhrjv2eql72k7kvkgsf9xewm",
			"WIF": "cMiwywSgPaJWCkYhjQrzar4usVngTvhSXj7KieMUQGqu1VW5NAwY",
			"encryptedWIF": ""
			}
			*/


			var keySpend = new Key(Encoders.Hex.DecodeData("043e1d9df83ddfdc4ab9bd0edb54277b94fa215b4d690080e2e9715bcefeef12"));
			var KeySpendinternalPubKey = keySpend.PubKey.TaprootInternalKey;
			Console.WriteLine("KeySpendinternalPubKey: " + KeySpendinternalPubKey.ToString()); // e7ca096a85e45c9f96a80615eb59b04e34266c7b00981054cea1afe679798d53

			string pubKeyString2 = "03e7ca096a85e45c9f96a80615eb59b04e34266c7b00981054cea1afe679798d53"; // this is the pubKey from the KeySpend above
			var ec_PubKey = NBitcoin.Secp256k1.ECPubKey.Create(NBitcoin.DataEncoders.Encoders.Hex.DecodeData(pubKeyString2));
			var xOnlyFromPubkey = ec_PubKey.ToXOnlyPubKey();
			var tapIntFromEC = new NBitcoin.TaprootInternalPubKey(xOnlyFromPubkey.ToBytes());
			Console.WriteLine("tapIntFromEC: " + tapIntFromEC.ToString()); // e7ca096a85e45c9f96a80615eb59b04e34266c7b00981054cea1afe679798d53
			var tapPubFromEC = new TaprootPubKey(xOnlyFromPubkey.ToBytes());
			Console.WriteLine("tapPubFromEC: " + tapPubFromEC.ToString()); // e7ca096a85e45c9f96a80615eb59b04e34266c7b00981054cea1afe679798d53

			var treeInfo = NBitcoin.TaprootSpendInfo.WithHuffmanTree(tapIntFromEC, scriptWeights);
			var taprootPubKey = treeInfo.OutputPubKey.OutputKey;
			var addr = taprootPubKey.GetAddress(Network.RegTest);
			Console.WriteLine("final address: " + addr.ToString());


		}

		static void musig_address_and_path_spend_with_huffman()
		{
			var ctx = Context.Instance;
			var msg32 = Encoders.Hex.DecodeData("502c616d9910774e00edb71f01b951962cc44ec67072757767f3906ff82ebfe8");

			var ecPrivateKeys =
			new[]{
"c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948",
"c8222b32a0189e5fa1f46700a9d0438c00feb279f0f2087cafe6f5b5ce9d224a",
"b6f2920002873556366ad9f9a44711e4f34b596a892bd175427071e4064a89cc" }
			.Select(Encoders.Hex.DecodeData)
			.Select(c => ctx.CreateECPrivKey(c)).ToArray();

			var peers = ecPrivateKeys.Length;


			var ecPubKeys = ecPrivateKeys.Select(c => c.CreatePubKey()).ToArray();
			var musig = new MusigContext(ecPubKeys, msg32);
			var nonces = ecPubKeys.Select(c => musig.GenerateNonce(c)).ToArray();

			var aggregatedKey = ECPubKey.MusigAggregate(ecPubKeys);

			// This is an example of aggregated signature where the output key is directly signing with schnorr
			musig = new MusigContext(ecPubKeys, msg32);
			musig.ProcessNonces(nonces.Select(n => n.CreatePubNonce()).ToArray());
			var sigs = ecPrivateKeys.Select((c, i) => musig.Sign(c, nonces[i])).ToArray();
			var signature = musig.AggregateSignatures(sigs);
			var schnorrSig = new SchnorrSignature(signature.ToBytes());
			var taprootPubKey = new TaprootPubKey(aggregatedKey.ToXOnlyPubKey().ToBytes());
			Console.WriteLine("Verifica el taprootPubKey: " + taprootPubKey.VerifySignature(msg32, schnorrSig));

			// However, in Bitcoin, the musig pubkey is the internal key... not the output key directly
			// Note that while using the aggregated key as an output key as above isn't impossible, it is not the standard way to use musig.
			var peers_2 = 2;
			var privNonces_1_to_2 = new MusigPrivNonce[peers_2];
			var pubNonces_1_to_2 = new MusigPubNonce[peers_2];
			var musig_1_to_2 = new MusigContext[peers_2];
			var sigs_1_to_2 = new MusigPartialSignature[peers_2];


			var pairPubKeys_0_to_1 = new ECPubKey[peers_2];
			var pairPubKeys_0_to_2 = new ECPubKey[peers_2];
			var pairPubKeys_1_to_1 = new ECPubKey[peers_2];



			pairPubKeys_0_to_1[0] = ecPrivateKeys[0].CreatePubKey();
			pairPubKeys_0_to_1[1] = ecPrivateKeys[1].CreatePubKey();
			var pubKey_0_to_1 = ECPubKey.MusigAggregate(pairPubKeys_0_to_1);
			var TRpubKey_0_to_1 = new TaprootPubKey(pubKey_0_to_1.ToXOnlyPubKey().ToBytes());

			pairPubKeys_0_to_2[0] = ecPrivateKeys[0].CreatePubKey();
			pairPubKeys_0_to_2[1] = ecPrivateKeys[2].CreatePubKey();
			var pubKey_0_to_2 = ECPubKey.MusigAggregate(pairPubKeys_0_to_2);
			var TRpubKey_0_to_2 = new TaprootPubKey(pubKey_0_to_2.ToXOnlyPubKey().ToBytes());

			pairPubKeys_1_to_1[0] = ecPrivateKeys[1].CreatePubKey();
			pairPubKeys_1_to_1[1] = ecPrivateKeys[2].CreatePubKey();
			var pubKey_1_to_2 = ECPubKey.MusigAggregate(pairPubKeys_1_to_1);
			var TRpubKey_1_to_2 = new TaprootPubKey(pubKey_1_to_2.ToXOnlyPubKey().ToBytes());


			//var pubKeyFromHex = ECPubKey.Create(Encoders.Hex.DecodeData(""));


			var howManyScripts = 3;
			var Scripts = new TapScript[howManyScripts];
			Scripts[0] = new Script(Op.GetPushOp(pubKey_1_to_2.ToXOnlyPubKey().ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);
			Scripts[1] = new Script(Op.GetPushOp(pubKey_0_to_1.ToXOnlyPubKey().ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);
			Scripts[2] = new Script(Op.GetPushOp(pubKey_0_to_2.ToXOnlyPubKey().ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);


			var scriptWeightsList = new List<(UInt32, TapScript)>();
			scriptWeightsList.Add((30u, Scripts[0]));
			scriptWeightsList.Add((30u, Scripts[1]));
			scriptWeightsList.Add((30u, Scripts[2]));

			var scriptWeights = scriptWeightsList.ToArray();

			//var scriptWeights = scriptWeightsList.Select(t => (t.Item1, t.Item2)).ToArray();




			// Create a tree as shown below
			// For example, imagine this tree:
			// pubKey_1_to_2 is at depth 1 meanting pubKey0_to_1 and pubKey0_to_2 are at depth 2
			//                                       .....
			//                                     /       \
			//                                    /\       pubKey_1_to_2
			//                                   /  \       
			//                                  /    \
			//                                 /      \
			//                        pubKey0_to_1   pubKey0_to_2         

			var all_keys = new System.Collections.Generic.List<NBitcoin.Key>();
			var keySpend = new Key(Encoders.Hex.DecodeData("c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948"));
			all_keys.Add(keySpend);
			all_keys.Add(keySpend);
			var KeySpendinternalPubKey = keySpend.PubKey.TaprootInternalKey;

			var AllTreeInfo = new System.Collections.Generic.List<NBitcoin.TaprootSpendInfo>();

			//KeySpendinternalPubKey.ComputeTapTweak(aggregatedKey.ToXOnlyPubKey().ToBytes());
			NBitcoin.TaprootSpendInfo treeInfo;
			treeInfo = TaprootSpendInfo.WithHuffmanTree(KeySpendinternalPubKey, scriptWeights);
			AllTreeInfo.Add(treeInfo);
			AllTreeInfo.Add(treeInfo);
			//var treeInfo = builder.Finalize(KeySpendinternalPubKey);

			//var treeInfo = builder.Finalize(new TaprootInternalPubKey(aggregatedKey.ToXOnlyPubKey().ToBytes()));


			taprootPubKey = treeInfo.OutputPubKey.OutputKey;



			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{



				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				var addr = taprootPubKey.GetAddress(Network.RegTest);
				var addr2 = taprootPubKey.GetAddress(Network.RegTest);

				rpc.Generate(1);


				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));
				var txid2 = rpc.SendToAddress(addr, Money.Coins(2.0m));

				var tx = rpc.GetRawTransaction(txid);
				var tx2 = rpc.GetRawTransaction(txid2);
				//var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == addr.ScriptPubKey);

				var spender = nodeBuilder.Network.CreateTransaction();

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
				
				foreach (var output in tx2.Outputs.AsIndexedOutputs())
				{
					if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
					{
						spender.Inputs.Add(new NBitcoin.OutPoint(tx2, output.N));
						spentAllOutputsIn.Add(output.TxOut);
						break; // Break out of the loop since you found the desired item
					}
				}
				

				NBitcoin.TxOut[] spentOutputsIn = spentAllOutputsIn.ToArray();



				var dest = rpc.GetNewAddress();
				spender.Outputs.Add(NBitcoin.Money.Coins(0.7m), dest);
				spender.Outputs.Add(NBitcoin.Money.Coins(2.2999000m), addr);
				// fee is the difference between the total amount from TXOs minus the destination minus the change


				var sighash = NBitcoin.TaprootSigHash.All | NBitcoin.TaprootSigHash.AnyoneCanPay;

				//var spentOutputsIn = new[] { spentOutput.TxOut };



				/*
				// SCRIPT PATH
				var extectionDataScriptSpend = new TaprootExecutionData(0, Scripts[0].LeafHash) { SigHash = sighash };

				var hashScriptSpend = spender.GetSignatureHashTaproot(spentOutputsIn, extectionDataScriptSpend);

				musig = new MusigContext(pairPubKeys_1_to_1, hashScriptSpend.ToBytes());
				nonces = pairPubKeys_1_to_1.Select(c => musig.GenerateNonce(c)).ToArray();
				musig.ProcessNonces(nonces.Select(n => n.CreatePubNonce()).ToArray());
				sigs = new[] { ecPrivateKeys[1], ecPrivateKeys[2] }.Select((c, i) => musig.Sign(c, nonces[i])).ToArray();
				signature = musig.AggregateSignatures(sigs);
				schnorrSig = new SchnorrSignature(signature.ToBytes());
				Console.WriteLine(TRpubKey_1_to_2.VerifySignature(hashScriptSpend, schnorrSig).ToString());

				var trSign = new TaprootSignature(schnorrSig, sighash);
				*/

				// ADDRESS PATH
				/*
				var extectionDataKeySpend = new TaprootExecutionData(0) { SigHash = sighash };

				var hashKeySpend = spender.GetSignatureHashTaproot(spentOutputsIn, extectionDataKeySpend);
				var sig = keySpend.SignTaprootKeySpend(hashKeySpend, treeInfo.MerkleRoot, sighash);

				Console.WriteLine("Veriry signature: " + addr.PubKey.VerifySignature(hashKeySpend, sig.SchnorrSignature));

				var extectionDataKeySpend2 = new TaprootExecutionData(1) { SigHash = sighash };

				var hashKeySpend2 = spender.GetSignatureHashTaproot(spentOutputsIn, extectionDataKeySpend);
				var sig2 = keySpend.SignTaprootKeySpend(hashKeySpend, treeInfo.MerkleRoot, sighash);

				Console.WriteLine("Veriry signature: 2 " + addr.PubKey.VerifySignature(hashKeySpend2, sig2.SchnorrSignature));
				*/
				//Boolean useKeySpend = false;
				//if (useKeySpend)
				//{

				var allkeysarray = all_keys.ToArray();
				var allTreeInfoArray = AllTreeInfo.ToArray();
				for (int i = 0; i < spender.Inputs.Count; i++)
					{
					var extectionDataKeySpend = new NBitcoin.TaprootExecutionData(i) { SigHash = sighash };

					var hashKeySpend = spender.GetSignatureHashTaproot(spentOutputsIn, extectionDataKeySpend);
					var sig = allkeysarray[i].SignTaprootKeySpend(hashKeySpend, allTreeInfoArray[i].MerkleRoot, sighash);

					Console.WriteLine("Veriry signature: " + addr.PubKey.VerifySignature(hashKeySpend, sig.SchnorrSignature));
					spender.Inputs[i].WitScript = new NBitcoin.WitScript(NBitcoin.Op.GetPushOp(sig.ToBytes()));
				}
				/*}
				else
				{
					spender.Inputs[0].WitScript = new WitScript(Op.GetPushOp(trSign.ToBytes()), Op.GetPushOp(Scripts[0].Script.ToBytes()), Op.GetPushOp(treeInfo.GetControlBlock(Scripts[0]).ToBytes()));

				}*/


				// COMMON

				
				

				Console.WriteLine(spender.ToString());
				//var validator = spender.CreateValidator(new[] { spentOutput.TxOut });
				var validator = spender.CreateValidator(spentOutputsIn);
				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
				Console.WriteLine("to hex: " + spender.ToHex().ToString());
				var result = validator.ValidateInput(0);
				var success = result.Error is null;
				Console.WriteLine("does validate witness? " + success);
				rpc.SendRawTransaction(spender);



			}
		}

		static void musig_address_and_path_spend_with_huffman_path()
		{
			var ctx = Context.Instance;
			var msg32 = Encoders.Hex.DecodeData("502c616d9910774e00edb71f01b951962cc44ec67072757767f3906ff82ebfe8");

			var ecPrivateKeys =
			new[]{
"c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948",
"c8222b32a0189e5fa1f46700a9d0438c00feb279f0f2087cafe6f5b5ce9d224a",
"b6f2920002873556366ad9f9a44711e4f34b596a892bd175427071e4064a89cc" }
			.Select(Encoders.Hex.DecodeData)
			.Select(c => ctx.CreateECPrivKey(c)).ToArray();

			var peers = ecPrivateKeys.Length;
			TaprootPubKey taprootPubKey = null;


			var ecPubKeys = ecPrivateKeys.Select(c => c.CreatePubKey()).ToArray();
			var musig = new MusigContext(ecPubKeys, msg32);
			var nonces = ecPubKeys.Select(c => musig.GenerateNonce(c)).ToArray();

			var aggregatedKey = ECPubKey.MusigAggregate(ecPubKeys);

			// This is an example of aggregated signature where the output key is directly signing with schnorr
			musig = new MusigContext(ecPubKeys, msg32);
			musig.ProcessNonces(nonces.Select(n => n.CreatePubNonce()).ToArray());
			var sigs = ecPrivateKeys.Select((c, i) => musig.Sign(c, nonces[i])).ToArray();
			var signature = musig.AggregateSignatures(sigs);
			var schnorrSig = new SchnorrSignature(signature.ToBytes());
			taprootPubKey = new TaprootPubKey(aggregatedKey.ToXOnlyPubKey().ToBytes());
			Console.WriteLine("Verifica el taprootPubKey: " + taprootPubKey.VerifySignature(msg32, schnorrSig));
			
			// However, in Bitcoin, the musig pubkey is the internal key... not the output key directly
			// Note that while using the aggregated key as an output key as above isn't impossible, it is not the standard way to use musig.
			var peers_2 = 2;
			var privNonces_1_to_2 = new MusigPrivNonce[peers_2];
			var pubNonces_1_to_2 = new MusigPubNonce[peers_2];
			var musig_1_to_2 = new MusigContext[peers_2];
			var sigs_1_to_2 = new MusigPartialSignature[peers_2];


			var pairPubKeys_0_to_1 = new ECPubKey[peers_2];
			var pairPubKeys_0_to_2 = new ECPubKey[peers_2];
			var pairPubKeys_1_to_1 = new ECPubKey[peers_2];



			pairPubKeys_0_to_1[0] = ecPrivateKeys[0].CreatePubKey();
			pairPubKeys_0_to_1[1] = ecPrivateKeys[1].CreatePubKey();
			var pubKey_0_to_1 = ECPubKey.MusigAggregate(pairPubKeys_0_to_1);
			var TRpubKey_0_to_1 = new TaprootPubKey(pubKey_0_to_1.ToXOnlyPubKey().ToBytes());

			pairPubKeys_0_to_2[0] = ecPrivateKeys[0].CreatePubKey();
			pairPubKeys_0_to_2[1] = ecPrivateKeys[2].CreatePubKey();
			var pubKey_0_to_2 = ECPubKey.MusigAggregate(pairPubKeys_0_to_2);
			var TRpubKey_0_to_2 = new TaprootPubKey(pubKey_0_to_2.ToXOnlyPubKey().ToBytes());

			pairPubKeys_1_to_1[0] = ecPrivateKeys[1].CreatePubKey();
			pairPubKeys_1_to_1[1] = ecPrivateKeys[2].CreatePubKey();
			var pubKey_1_to_2 = ECPubKey.MusigAggregate(pairPubKeys_1_to_1);
			var TRpubKey_1_to_2 = new TaprootPubKey(pubKey_1_to_2.ToXOnlyPubKey().ToBytes());


			//var pubKeyFromHex = ECPubKey.Create(Encoders.Hex.DecodeData(""));


			var howManyScripts = 3;
			var Scripts = new TapScript[howManyScripts];
			Scripts[0] = new Script(Op.GetPushOp(pubKey_1_to_2.ToXOnlyPubKey().ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);
			Scripts[1] = new Script(Op.GetPushOp(pubKey_0_to_1.ToXOnlyPubKey().ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);
			Scripts[2] = new Script(Op.GetPushOp(pubKey_0_to_2.ToXOnlyPubKey().ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);


			var scriptWeightsList = new List<(UInt32, TapScript)>();
			scriptWeightsList.Add((30u, Scripts[0]));
			scriptWeightsList.Add((30u, Scripts[1]));
			scriptWeightsList.Add((30u, Scripts[2]));

			var scriptWeights = scriptWeightsList.ToArray();

			//var scriptWeights = scriptWeightsList.Select(t => (t.Item1, t.Item2)).ToArray();




			// Create a tree as shown below
			// For example, imagine this tree:
			// pubKey_1_to_2 is at depth 1 meanting pubKey0_to_1 and pubKey0_to_2 are at depth 2
			//                                       .....
			//                                     /       \
			//                                    /\       pubKey_1_to_2
			//                                   /  \       
			//                                  /    \
			//                                 /      \
			//                        pubKey0_to_1   pubKey0_to_2         

			var all_keys = new System.Collections.Generic.List<NBitcoin.Key>();
			var keySpend = new Key(Encoders.Hex.DecodeData("c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948"));
			all_keys.Add(keySpend);
			all_keys.Add(keySpend);
			var KeySpendinternalPubKey = keySpend.PubKey.TaprootInternalKey;

			var AllTreeInfo = new System.Collections.Generic.List<NBitcoin.TaprootSpendInfo>();

			//KeySpendinternalPubKey.ComputeTapTweak(aggregatedKey.ToXOnlyPubKey().ToBytes());
			NBitcoin.TaprootSpendInfo treeInfo;
			treeInfo = TaprootSpendInfo.WithHuffmanTree(KeySpendinternalPubKey, scriptWeights);
			AllTreeInfo.Add(treeInfo);
			AllTreeInfo.Add(treeInfo);
			//var treeInfo = builder.Finalize(KeySpendinternalPubKey);

			//var treeInfo = builder.Finalize(new TaprootInternalPubKey(aggregatedKey.ToXOnlyPubKey().ToBytes()));


			taprootPubKey = treeInfo.OutputPubKey.OutputKey;



			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{



				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				var addr = taprootPubKey.GetAddress(Network.RegTest);
				var addr2 = taprootPubKey.GetAddress(Network.RegTest);

				rpc.Generate(1);


				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));
				var txid2 = rpc.SendToAddress(addr, Money.Coins(2.0m));

				var tx = rpc.GetRawTransaction(txid);
				var tx2 = rpc.GetRawTransaction(txid2);
				//var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == addr.ScriptPubKey);

				var spender = nodeBuilder.Network.CreateTransaction();

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

				foreach (var output in tx2.Outputs.AsIndexedOutputs())
				{
					if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
					{
						spender.Inputs.Add(new NBitcoin.OutPoint(tx2, output.N));
						spentAllOutputsIn.Add(output.TxOut);
						break; // Break out of the loop since you found the desired item
					}
				}


				NBitcoin.TxOut[] spentOutputsIn = spentAllOutputsIn.ToArray();



				var dest = rpc.GetNewAddress();
				spender.Outputs.Add(NBitcoin.Money.Coins(0.7m), dest);
				spender.Outputs.Add(NBitcoin.Money.Coins(2.2999000m), addr);
				// fee is the difference between the total amount from TXOs minus the destination minus the change


				var sighash = NBitcoin.TaprootSigHash.All | NBitcoin.TaprootSigHash.AnyoneCanPay;







				var allkeysarray = all_keys.ToArray();
				var allTreeInfoArray = AllTreeInfo.ToArray();

				Boolean useKeySpend = false;
				if (useKeySpend)
				{
					// ADDRESS PATH
					
					for (int i = 0; i < spender.Inputs.Count; i++)
					{
						var extectionDataKeySpend = new NBitcoin.TaprootExecutionData(i) { SigHash = sighash };

						var hashKeySpend = spender.GetSignatureHashTaproot(spentOutputsIn, extectionDataKeySpend);
						var sig = allkeysarray[i].SignTaprootKeySpend(hashKeySpend, allTreeInfoArray[i].MerkleRoot, sighash);

						Console.WriteLine("Veriry signature: " + addr.PubKey.VerifySignature(hashKeySpend, sig.SchnorrSignature));
						spender.Inputs[i].WitScript = new NBitcoin.WitScript(NBitcoin.Op.GetPushOp(sig.ToBytes()));
					}
				}
				else
				{
					for (int i = 0; i < spender.Inputs.Count; i++)
					{
						// SCRIPT PATH
						var extectionDataScriptSpend = new TaprootExecutionData(i, Scripts[0].LeafHash) { SigHash = sighash };

						var hashScriptSpend = spender.GetSignatureHashTaproot(spentOutputsIn, extectionDataScriptSpend);

						musig = new MusigContext(pairPubKeys_1_to_1, hashScriptSpend.ToBytes());

						//nonces = pairPubKeys_1_to_1.Select(c => musig.GenerateNonce(c)).ToArray();
						nonces = new MusigPrivNonce[pairPubKeys_1_to_1.Length];
						for (int n = 0; n < pairPubKeys_1_to_1.Length; n++)
						{
							nonces[n] = musig.GenerateNonce(pairPubKeys_1_to_1[n]);
						}



						//musig.ProcessNonces(nonces.Select(n => n.CreatePubNonce()).ToArray());
						var pubNonces = new MusigPubNonce[nonces.Length];
						for (int p = 0; p < nonces.Length; p++)
						{
							pubNonces[p] = nonces[p].CreatePubNonce();
						}
						musig.ProcessNonces(pubNonces);


						//sigs = new[] { ecPrivateKeys[1], ecPrivateKeys[2] }.Select((c, i) => musig.Sign(c, nonces[i])).ToArray();
						sigs = new MusigPartialSignature[2]; // Assuming you have 2 private keys
						for (int s = 1; s <= 2; s++)
						{
							sigs[s - 1] = musig.Sign(ecPrivateKeys[s], nonces[s - 1]);
						}
						signature = musig.AggregateSignatures(sigs);
						schnorrSig = new SchnorrSignature(signature.ToBytes());
						Console.WriteLine(TRpubKey_1_to_2.VerifySignature(hashScriptSpend, schnorrSig).ToString());

						var trSign = new TaprootSignature(schnorrSig, sighash);

						spender.Inputs[i].WitScript = new WitScript(Op.GetPushOp(trSign.ToBytes()), Op.GetPushOp(Scripts[0].Script.ToBytes()), Op.GetPushOp(treeInfo.GetControlBlock(Scripts[0]).ToBytes()));
					}
				}



				// COMMON




				Console.WriteLine(spender.ToString());
				//var validator = spender.CreateValidator(new[] { spentOutput.TxOut });
				var validator = spender.CreateValidator(spentOutputsIn);
				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
				Console.WriteLine("to hex: " + spender.ToHex().ToString());
				var result = validator.ValidateInput(0);
				var success = result.Error is null;
				Console.WriteLine("does validate witness? " + success);
				rpc.SendRawTransaction(spender);



			}
		}
	}
}


