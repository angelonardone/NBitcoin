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
		static Context ctx = Context.Instance;

		static void Main(string[] args)
		{
			musig_MusigTest();
			//TestVectorsCore();
			//CanParseAndGeneratePayToTaprootScripts();
			//CanSignUsingTaproot();
		}

		static void musig_MusigTest()
		{

			var msg32 = Encoders.Hex.DecodeData("502c616d9910774e00edb71f01b951962cc44ec67072757767f3906ff82ebfe8");
			var tweak = Encoders.Hex.DecodeData("f24d386cccd01e815007b3a6278151d51a4bbf8835813120cfa0f937cb82f021");
			// adaptor is a separate Private Key revealed after "second signature"
			byte[] bytes_adaptor = Encoders.Hex.DecodeData("c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948");
			var adaptor = ctx.CreateECPrivKey(bytes_adaptor);
			var peers = 3;
			var privKeys = new ECPrivKey[peers];
			var privNonces = new MusigPrivNonce[peers];
			var pubNonces = new MusigPubNonce[peers];
			var musig = new MusigContext[peers];
			var sigs = new MusigPartialSignature[peers];
			var pubKeys = new ECPubKey[peers];

			// Private KEYs
			byte[] bytes1 = Encoders.Hex.DecodeData("c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948");
			privKeys[0] = ctx.CreateECPrivKey(bytes1);
			byte[] bytes2 = Encoders.Hex.DecodeData("c8222b32a0189e5fa1f46700a9d0438c00feb279f0f2087cafe6f5b5ce9d224a");
			privKeys[1] = ctx.CreateECPrivKey(bytes2);
			byte[] bytes3 = Encoders.Hex.DecodeData("b6f2920002873556366ad9f9a44711e4f34b596a892bd175427071e4064a89cc");
			privKeys[2] = ctx.CreateECPrivKey(bytes3);

			for (int i = 0; i < peers; i++)
			{
				pubKeys[i] = privKeys[i].CreatePubKey();
			}

			for (int i = 0; i < peers; i++)
			{
				musig[i] = new MusigContext(pubKeys, msg32); // converti en "pbulic" este construcotr que estaba privet en MusigContext.cs
				privNonces[i] = musig[i].GenerateNonce((uint)i, privKeys[i]);
				pubNonces[i] = privNonces[i].CreatePubNonce();
			}



			var useTweak = false;
			var useAdaptor = false;
			for (int i = 0; i < peers; i++)
			{
				if (useTweak)
				{
					musig[i].Tweak(tweak);
				}
				if (useAdaptor)
				{
					musig[i].UseAdaptor(adaptor.CreatePubKey());
				}

				musig[i].ProcessNonces(pubNonces);
				sigs[i] = musig[i].Sign(privKeys[i], privNonces[i]);
			}
			// Verify all the partial sigs
			for (int i = 0; i < peers; i++)
			{
				Console.WriteLine(musig[i].Verify(pubKeys[i], pubNonces[i], sigs[i]));
				Console.WriteLine(pubKeys[i].ToString());
				Console.WriteLine(pubNonces[i].ToString());
				Console.WriteLine(sigs[i].ToString());
			}

			// Combine
			var schnorrSig = musig[0].AggregateSignatures(sigs);


			if (useAdaptor)
				schnorrSig = musig[0].Adapt(schnorrSig, adaptor);
			// Verify resulting signature
			// SigningPubKey is the tweaked key if tweaked, or the combined key if not
			Console.WriteLine("verify with ctx :" + musig[0].AggregatePubKey.ToXOnlyPubKey().SigVerifyBIP340(schnorrSig, msg32));

			Console.WriteLine("Are all gggregated pub keys the same ?: " + musig[0].AggregatePubKey.Equals(musig[1].AggregatePubKey));
			var aggretaedECpubkey = musig[0].AggregatePubKey;
			Console.WriteLine("Sign verify schnorr ?: " + aggretaedECpubkey.SigVerifySchnorr(schnorrSig, msg32));
			var Aggretaedpubkey = new TaprootPubKey(aggretaedECpubkey.ToXOnlyPubKey().ToBytes());
			Console.WriteLine("Aggregated pub key ?: " + Aggretaedpubkey.ToString());
			Console.WriteLine("Aggregated pub address ?: " + Aggretaedpubkey.GetAddress(Network.RegTest).ToString());

			var uint256msg32 = uint256.Parse("502c616d9910774e00edb71f01b951962cc44ec67072757767f3906ff82ebfe8");
			var schnorrSig2 = new SchnorrSignature(schnorrSig.ToBytes());
			Console.WriteLine("Verify signtature of Aggregated pub key : " + Aggretaedpubkey.VerifySignature(uint256msg32, schnorrSig2));


		}

		static void TestVectorsCore()
		{
			var internalKey = TaprootInternalPubKey.Parse("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51");

			var scriptWeights = new[]
			{
				(10u, Script.FromHex("51")),
				(20u, Script.FromHex("52")),
				(20u, Script.FromHex("53")),
				(30u, Script.FromHex("54")),
				(19u, Script.FromHex("55")),
			};

			var treeInfo = TaprootSpendInfo.WithHuffmanTree(internalKey, scriptWeights);
			/* The resulting tree should put the scripts into a tree similar
			 * to the following:
			 *
			 *   1      __/\__
			 *         /      \
			 *        /\     / \
			 *   2   54 52  53 /\
			 *   3            55 51
			 */
			Console.WriteLine("IsKeyPathOnlySpend: " + treeInfo.IsKeyPathOnlySpend.ToString());
			Console.WriteLine(treeInfo.InternalPubKey.ToString());
			Console.WriteLine(treeInfo.InternalPubKey.GetTaprootFullPubKey().ToString());
			Console.WriteLine(treeInfo.OutputPubKey.ToString());
			Console.WriteLine(treeInfo.OutputPubKey.ScriptPubKey.ToString());
			var expected = new[] { ("51", 3), ("52", 2), ("53", 2), ("54", 2), ("55", 3) };
			/*
			foreach (var t in expected)
			{
				var (script, expectedLength) = t;
				Console.WriteLine(
					treeInfo
						.ScriptToMerkleProofMap!
						.TryGetValue((Script.FromHex(script), (byte)TaprootConstants.TAPROOT_LEAF_TAPSCRIPT), out var scriptSet)
				);
				var actualLength = scriptSet[0];
				Console.WriteLine(expectedLength, actualLength.Count);
			}
			*/
			var outputKey = treeInfo.OutputPubKey;

			foreach (var (_, script) in scriptWeights)
			{
				var ctrlBlock = treeInfo.GetControlBlock(script, (byte)TaprootConstants.TAPROOT_LEAF_TAPSCRIPT);
				Console.WriteLine(ctrlBlock.VerifyTaprootCommitment(outputKey, script));
				Console.WriteLine(outputKey.ToString());
				Console.WriteLine(script.ToString());
				Console.WriteLine(script.ToHex().ToString());
			}
		}
		static void CanParseAndGeneratePayToTaprootScripts()
		{
			var pubkey = new TaprootPubKey(Encoders.Hex.DecodeData("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"));
			var scriptPubKey = new Script("1 53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
#pragma warning disable CS0618 // Type or member is obsolete
			Console.WriteLine(scriptPubKey.Equals(PayToTaprootTemplate.Instance.GenerateScriptPubKey(pubkey)));
#pragma warning restore CS0618 // Type or member is obsolete
			Console.WriteLine(pubkey.Equals(PayToTaprootTemplate.Instance.ExtractScriptPubKeyParameters(scriptPubKey)));

			// signature has wrong length
			scriptPubKey = new Script("1 53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda34300");
			Console.WriteLine(PayToTaprootTemplate.Instance.ExtractScriptPubKeyParameters(scriptPubKey));

			// segwit version is missing
			scriptPubKey = new Script("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
			Console.WriteLine(PayToTaprootTemplate.Instance.ExtractScriptPubKeyParameters(scriptPubKey));

			// too many witnesses
			scriptPubKey = new Script("1 53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343 00");
			Console.WriteLine(PayToTaprootTemplate.Instance.ExtractScriptPubKeyParameters(scriptPubKey));

			var sig = TaprootSignature.Parse(Encoders.Hex.DecodeData("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"));
			var witScript = new WitScript("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0");
			Console.WriteLine(witScript.Equals(PayToTaprootTemplate.Instance.GenerateWitScript(sig)));

			var annex = new byte[] { 0x50 };
			witScript = new WitScript("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0 50");
			Console.WriteLine(witScript.Equals(PayToTaprootTemplate.Instance.GenerateWitScript(sig, annex)));

		}
		static void CanSignUsingTaproot()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				var key = new Key();
				var addr = key.PubKey.GetTaprootFullPubKey().GetAddress(nodeBuilder.Network);

				foreach (var anyoneCanPay in new[] { false, true })
				{
					rpc.Generate(1);
					foreach (var hashType in new[] { TaprootSigHash.All, TaprootSigHash.Default, TaprootSigHash.None, TaprootSigHash.Single })
					{
						if (hashType == TaprootSigHash.Default && anyoneCanPay)
							continue; // Not supported by btc
						var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));

						var tx = rpc.GetRawTransaction(txid);
						var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == addr.ScriptPubKey);

						var spender = nodeBuilder.Network.CreateTransaction();
						spender.Inputs.Add(new OutPoint(tx, spentOutput.N));

						var dest = rpc.GetNewAddress();
						spender.Outputs.Add(Money.Coins(0.7m), dest);
						spender.Outputs.Add(Money.Coins(0.2999000m), addr);

						var sighash = hashType | (anyoneCanPay ? TaprootSigHash.AnyoneCanPay : 0);
						var hash = spender.GetSignatureHashTaproot(new[] { spentOutput.TxOut },
																 new TaprootExecutionData(0) { SigHash = sighash });
						var sig = key.SignTaprootKeySpend(hash, sighash);

						Console.WriteLine("Veriry signature: " + addr.PubKey.VerifySignature(hash, sig.SchnorrSignature));
						spender.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig.ToBytes()));
						Console.WriteLine(spender.ToString());
						rpc.SendRawTransaction(spender);
					}
				}
			}
		}
	}
}
