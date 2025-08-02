using System;
using System.Threading;
using NBitcoin;
using NBitcoin.Tests;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using NBitcoin.Crypto;
using System.Security.Cryptography;


namespace NBitcoinTraining
{
	class Program
	{
		//static Context ctx = Context.Instance;

		static void Main(string[] args)
		{


			var ctx = Context.Instance;
			var msg32 = Encoders.Hex.DecodeData("502c616d9910774e00edb71f01b951962cc44ec67072757767f3906ff82ebfe8");



/*
			var ecPrivateKeysHex = new[] {
	"c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948",
	"c8222b32a0189e5fa1f46700a9d0438c00feb279f0f2087cafe6f5b5ce9d224a",
	"b6f2920002873556366ad9f9a44711e4f34b596a892bd175427071e4064a89cc"
};*/
			var ecPrivateKeysHex = new[] {
			"527b33ce0c67ec2cc12ba7bb2e48dda66884a5c4b6d110be894a10802b21b3d6",
			"54082c2ee51166cfa4fd8c3076ee30043808b3cca351e3288360af81d3ef9f8c",
			"cba536615bbe1ae2fdf8100104829db61c8cf2a7f0bd9a225cbf09e79d83096c"
			};

			var ecPrivateKeys = new ECPrivKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				ecPrivateKeys[i] = ctx.CreateECPrivKey(privateKeyBytes);
			}


			var peers = ecPrivateKeys.Length;
			TaprootPubKey taprootPubKey = null;


			var ecPubKeys = ecPrivateKeys.Select(c => c.CreatePubKey()).ToArray();
			var musig = new MusigContext(ecPubKeys, msg32);
			var nonces = ecPrivateKeys.Select(c => musig.GenerateNonce(c)).ToArray();

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
			for (int n = 0; n < pairPubKeys_0_to_1.Length; n++)
			{
				Console.WriteLine("pairPubKeys_0_to_1: " + NBitcoin.DataEncoders.Encoders.Hex.EncodeData(pairPubKeys_0_to_1[n].ToBytes()));
			}
			Console.WriteLine(TRpubKey_0_to_1.ScriptPubKey.ToString());

			pairPubKeys_0_to_2[0] = ecPrivateKeys[0].CreatePubKey();
			pairPubKeys_0_to_2[1] = ecPrivateKeys[2].CreatePubKey();
			var pubKey_0_to_2 = ECPubKey.MusigAggregate(pairPubKeys_0_to_2);
			var TRpubKey_0_to_2 = new TaprootPubKey(pubKey_0_to_2.ToXOnlyPubKey().ToBytes());
			for (int n = 0; n < pairPubKeys_0_to_2.Length; n++)
			{
				Console.WriteLine("pairPubKeys_0_to_2: " + NBitcoin.DataEncoders.Encoders.Hex.EncodeData(pairPubKeys_0_to_2[n].ToBytes()));
			}
			Console.WriteLine(TRpubKey_0_to_2.ScriptPubKey.ToString());



			pairPubKeys_1_to_1[0] = ecPrivateKeys[1].CreatePubKey();
			pairPubKeys_1_to_1[1] = ecPrivateKeys[2].CreatePubKey();
			var pubKey_1_to_2 = ECPubKey.MusigAggregate(pairPubKeys_1_to_1);
			var TRpubKey_1_to_2 = new NBitcoin.TaprootPubKey(pubKey_1_to_2.ToXOnlyPubKey().ToBytes());
			for (int n = 0; n < pairPubKeys_1_to_1.Length; n++)
			{
				Console.WriteLine("pairPubKeys_1_to_1: " + NBitcoin.DataEncoders.Encoders.Hex.EncodeData(pairPubKeys_1_to_1[n].ToBytes()));
			}
			Console.WriteLine(TRpubKey_1_to_2.ScriptPubKey.ToString());


			//var pubKeyFromHex = ECPubKey.Create(Encoders.Hex.DecodeData(""));


			var howManyScripts = 3;
			var probability = (uint)(100 / howManyScripts);
			var scriptWeightsList = new List<(UInt32, TapScript)>();
			var Scripts = new TapScript[howManyScripts];
			Scripts[0] = new Script(Op.GetPushOp(pubKey_1_to_2.ToXOnlyPubKey().ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);
			scriptWeightsList.Add((probability, Scripts[0]));
			Scripts[1] = new Script(Op.GetPushOp(pubKey_0_to_1.ToXOnlyPubKey().ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);
			scriptWeightsList.Add((probability, Scripts[1]));
			Scripts[2] = new Script(Op.GetPushOp(pubKey_0_to_2.ToXOnlyPubKey().ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);
			scriptWeightsList.Add((probability, Scripts[2]));






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
			//var keySpend = new Key(Encoders.Hex.DecodeData("c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948"));
			var keySpend = new Key(Encoders.Hex.DecodeData("6db9c7c645504f132d560fe55217108d55b53687b37bff34f7fbb70d9db040b9"));
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

						musig = new NBitcoin.Secp256k1.Musig.MusigContext(pairPubKeys_1_to_1, hashScriptSpend.ToBytes());
						

						//nonces = pairPubKeys_1_to_1.Select(c => musig.GenerateNonce(c)).ToArray();
						// genero 2 nonces usando el public address de cada uno
						nonces = new NBitcoin.Secp256k1.Musig.MusigPrivNonce[pairPubKeys_1_to_1.Length];
						nonces[0] = musig.GenerateNonce(ecPrivateKeys[1]);
						nonces[1] = musig.GenerateNonce(ecPrivateKeys[2]);



						// creo 2 PubNonces usando los nonces creados antes
						var pubNonces = new MusigPubNonce[nonces.Length];
						for (int p = 0; p < nonces.Length; p++)
						{

							var noceBytes = nonces[p].CreatePubNonce().ToBytes();
							var noceString = NBitcoin.DataEncoders.Encoders.Hex.EncodeData(noceBytes);
							var backToByptes = Encoders.Hex.DecodeData(noceString);
							pubNonces[p] = new MusigPubNonce(backToByptes);

							Console.WriteLine("one Public nonce: " + Encoders.Hex.EncodeData(pubNonces[p].ToBytes()));
						}


						// I need to store th pubNonces so I can Process all latter
						musig.ProcessNonces(pubNonces);
						

						sigs = new[] { ecPrivateKeys[1], ecPrivateKeys[2] }.Select((c, i) => musig.Sign(c, nonces[i])).ToArray();
						signature = musig.AggregateSignatures(sigs);

						schnorrSig = new NBitcoin.Crypto.SchnorrSignature(signature.ToBytes());
						Console.WriteLine(TRpubKey_1_to_2.VerifySignature(hashScriptSpend, schnorrSig).ToString());
						Console.WriteLine(TRpubKey_1_to_2.ScriptPubKey.ToString());

						var trSign = new NBitcoin.TaprootSignature(schnorrSig, sighash);

						spender.Inputs[i].WitScript = new WitScript(Op.GetPushOp(trSign.ToBytes()), Op.GetPushOp(Scripts[0].Script.ToBytes()), Op.GetPushOp(allTreeInfoArray[i].GetControlBlock(Scripts[0]).ToBytes()));
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


