using System;
using System.Reflection.Emit;
using System.Text;
using System.Threading;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using NBitcoin.Tests;
using Xunit;


namespace NBitcoinTraining
{
	class Program
	{

		static NBitcoin.Secp256k1.Scalar random_scalar_order()
		{
			Scalar num;
			Span<byte> b32 = stackalloc byte[32];
			do
			{
				b32.Clear();
				secp256k1_rand256(b32);
				num = new Scalar(b32, out var overflow);
				if (overflow != 0 || num.IsZero)
				{
					continue;
				}
				return num;
			} while (true);
		}

		static void secp256k1_rand256(Span<byte> output)
		{
			// Should reproduce the secp256k1_test_rng
			RandomUtils.GetBytes(output);
		}

		static Context ctx = Context.Instance;

		static void Main(string[] args)
		{


			//atomic_swap();

			//ecdsaadaptor();

			lockTime();

		}


		static void atomic_swap()
		{

			/********************
			 * Atomic swap
			 * ******************/



			var partial_sig_a = new MusigPartialSignature[2];
			var partial_sig_b = new MusigPartialSignature[2];
			var sk_a = new ECPrivKey[]
				{
						ctx.CreateECPrivKey(random_scalar_order()),
						ctx.CreateECPrivKey(random_scalar_order())
				};
			var sk_b = new ECPrivKey[]
				{
						ctx.CreateECPrivKey(random_scalar_order()),
						ctx.CreateECPrivKey(random_scalar_order())
				};
			var secnonce_a = new MusigPrivNonce[2];
			var secnonce_b = new MusigPrivNonce[2];

			var pk_a = sk_a.Select(p => p.CreatePubKey()).ToArray();
			var pk_b = sk_b.Select(p => p.CreatePubKey()).ToArray();

			var sec_adaptor = ctx.CreateECPrivKey(random_scalar_order());
			var pub_adaptor = sec_adaptor.CreatePubKey();
			byte[] msg32_a = Encoding.ASCII.GetBytes("this is the message blockchain a");
			byte[] msg32_b = Encoding.ASCII.GetBytes("this is the message blockchain b");
			var pre_session_a = new MusigContext(pk_a, msg32_a);
			var combined_pk_a = pre_session_a.AggregatePubKey.ToXOnlyPubKey();
			var pre_session_b = new MusigContext(pk_b, msg32_b);
			var combined_pk_b = pre_session_b.AggregatePubKey.ToXOnlyPubKey();

			for (int i = 0; i < 2; i++)
			{
				secnonce_a[i] = pre_session_a.GenerateNonce((uint)i, sk_a[i]);
				secnonce_b[i] = pre_session_b.GenerateNonce((uint)i, sk_b[i]);
			}

			var pubnonce_a = secnonce_a.Select(p => p.CreatePubNonce()).ToArray();
			var pubnonce_b = secnonce_b.Select(p => p.CreatePubNonce()).ToArray();

			/* Step 2: Exchange nonces */
			pre_session_a.UseAdaptor(pub_adaptor);
			pre_session_a.ProcessNonces(pubnonce_a);

			pre_session_b.UseAdaptor(pub_adaptor);
			pre_session_b.ProcessNonces(pubnonce_b);

			/* Step 3: Signer 0 produces partial signatures for both chains. */
			partial_sig_a[0] = pre_session_a.Sign(sk_a[0], secnonce_a[0]);
			partial_sig_b[0] = pre_session_b.Sign(sk_b[0], secnonce_b[0]);

			/* Step 4: Signer 1 receives partial signatures, verifies them and creates a
			* partial signature to send B-coins to signer 0. */
			Console.WriteLine("should be TRUE " + pre_session_a.Verify(pk_a[0], pubnonce_a[0], partial_sig_a[0]));
			Console.WriteLine("should be TRUE " + pre_session_b.Verify(pk_b[0], pubnonce_b[0], partial_sig_b[0]));
			partial_sig_b[1] = pre_session_b.Sign(sk_b[1], secnonce_b[1]);

			/* Step 5: Signer 0 adapts its own partial signature and combines it with the
			 * partial signature from signer 1. This results in a complete signature which
			* is broadcasted by signer 0 to take B-coins. */
			var final_sig_b = pre_session_b.AggregateSignatures(partial_sig_b);
			final_sig_b = pre_session_b.Adapt(final_sig_b, sec_adaptor);
			Console.WriteLine("should be TRUE " + combined_pk_b.SigVerifyBIP340(final_sig_b, msg32_b));

			/* Step 6: Signer 1 extracts adaptor from the published signature, applies it to
			* other partial signature, and takes A-coins. */
			var sec_adaptor_extracted = pre_session_b.Extract(final_sig_b, partial_sig_b);
			Console.WriteLine("should be EQUAL " + sec_adaptor.Equals(sec_adaptor_extracted));
			partial_sig_a[1] = pre_session_a.Sign(sk_a[1], secnonce_a[1]);
			var final_sig_a = pre_session_a.AggregateSignatures(partial_sig_a);
			final_sig_a = pre_session_a.Adapt(final_sig_a, sec_adaptor);
			Console.WriteLine("should be TRUE " + combined_pk_a.SigVerifyBIP340(final_sig_a, msg32_a));


			/********************
			 * END Atomic swap
			 * ******************/
		}
		static void ecdsaadaptor()
		{

			/********************
				 * ecdsaadaptor
				 * ******************/


			var secKey = Context.Instance.CreateECPrivKey(random_scalar_order());
			Span<byte> msg = stackalloc byte[32];
			msg = random_scalar_order().ToBytes();
			var adaptor_secret = Context.Instance.CreateECPrivKey(random_scalar_order());
			var pubkey = secKey.CreatePubKey();
			var adaptor = adaptor_secret.CreatePubKey();
			Console.WriteLine("should be TRUE " + secKey.TrySignEncryptedECDSA(msg, adaptor, out var adaptor_sig));
			{
				/* Test adaptor_sig_serialize roundtrip */
				Span<byte> adaptor_sig_tmp = stackalloc byte[162];
				Span<byte> adaptor_sig_tmp2 = stackalloc byte[162];
				adaptor_sig.WriteToSpan(adaptor_sig_tmp);
				Console.WriteLine("should be TRUE " + ECDSAEncryptedSignature.TryCreate(adaptor_sig_tmp, out var adaptor_sig2));
				adaptor_sig2.WriteToSpan(adaptor_sig_tmp2);
				Console.WriteLine("should be TRUE " + adaptor_sig_tmp.SequenceEqual(adaptor_sig_tmp2));
			}

			Console.WriteLine("should be TRUE " + pubkey.SigVerifyEncryptedECDSA(adaptor_sig, msg, adaptor));
			{
				Span<byte> adaptor_sig_tmp = stackalloc byte[162];
				adaptor_sig.WriteToSpan(adaptor_sig_tmp);
				if (ECDSAEncryptedSignature.TryCreate(adaptor_sig_tmp, out var sigg))
				{
					Console.WriteLine("should be TRUE " + pubkey.SigVerifyEncryptedECDSA(sigg, msg, adaptor));
				}
			}
			Console.WriteLine("should be FALSE " + adaptor.SigVerifyEncryptedECDSA(adaptor_sig, msg, adaptor));
			{
				Span<byte> msg_tmp = stackalloc byte[32];
				msg.CopyTo(msg_tmp);
				//rand_flip_bit(msg_tmp);
				Console.WriteLine("should be TRUE " + pubkey.SigVerifyEncryptedECDSA(adaptor_sig, msg_tmp, adaptor));
			}
			Console.WriteLine("should be FALSE " + pubkey.SigVerifyEncryptedECDSA(adaptor_sig, msg, pubkey));


			var sig = adaptor_sig.DecryptECDSASignature(adaptor_secret);
			///* Test adaptor_adapt */
			Console.WriteLine("should be TRUE " + pubkey.SigVerify(sig, msg));
			{
				/* Test adaptor_extract_secret */
				Console.WriteLine("should be TRUE " + adaptor_sig.TryRecoverDecryptionKey(sig, adaptor, out var adaptor_secret2));
				Console.WriteLine("should be EQUAL " + adaptor_secret.Equals(adaptor_secret2));
			}





		}



		static void lockTime()
		{
			var ctx = Context.Instance;
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

			var privateKeys = new Key[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				privateKeys[i] = new Key(privateKeyBytes);
			}

			var peers = ecPrivateKeys.Length;
			TaprootPubKey taprootPubKey = null;



			// XOnly pubKey
			var ecPubKeys = ecPrivateKeys.Select(c => c.CreateXOnlyPubKey()).ToArray();
			// pubKeys (compressd)
			//var ecPubKeys = ecPrivateKeys.Select(c => c.CreatePubKey()).ToArray();


			var howManyScripts = 2;
			var Scripts = new TapScript[howManyScripts];
			LockTime target = 110;
			Scripts[0] = new Script(Op.GetPushOp(ecPubKeys[0].ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0); // just signature
			Scripts[1] = new Script(Op.GetPushOp(target.Value), OpcodeType.OP_CHECKLOCKTIMEVERIFY, OpcodeType.OP_DROP, Op.GetPushOp(ecPubKeys[0].ToBytes()), OpcodeType.OP_CHECKSIG).ToTapScript(TapLeafVersion.C0);


			var scriptWeightsList = new List<(UInt32, TapScript)>
			{
				(50u, Scripts[0]),
				(50u, Scripts[1]),
			};

			var scriptWeights = scriptWeightsList.ToArray();

			var keySpend = new Key(Encoders.Hex.DecodeData("c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948"));
			var KeySpendinternalPubKey = keySpend.PubKey.TaprootInternalKey;
			var treeInfo = TaprootSpendInfo.WithHuffmanTree(KeySpendinternalPubKey, scriptWeights);
			taprootPubKey = treeInfo.OutputPubKey.OutputKey;
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var addr = taprootPubKey.GetAddress(Network.RegTest);
				var script_to_run = 1;

				foreach (var useKeySpend in new[] { false, true })
				{
					var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));
					// if the node last block is less thant the LockTime, it will reject the transaccion as none-final
					// this is why I'm generated 200 more blocks
					rpc.Generate(200);

					var tx = rpc.GetRawTransaction(txid);
					var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == addr.ScriptPubKey);

					var spender = nodeBuilder.Network.CreateTransaction();
					
					spender.Inputs.Add(new OutPoint(tx, spentOutput.N));
					// this is mandatory for CLTV
					spender.Inputs[0].Sequence = 1;
					spender.LockTime = 120;

					var dest = rpc.GetNewAddress();
					spender.Outputs.Add(Money.Coins(0.7m), dest);
					spender.Outputs.Add(Money.Coins(0.2999000m), addr);


					var sighash = TaprootSigHash.All | TaprootSigHash.AnyoneCanPay;

					var spentOutputsIn = new[] { spentOutput.TxOut };


					TaprootExecutionData extectionData;

					// ADDRESS PATH
					if (useKeySpend)
						extectionData = new TaprootExecutionData(0) { SigHash = sighash };
					else
						extectionData = new TaprootExecutionData(0, Scripts[script_to_run].LeafHash) { SigHash = sighash };

					var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);

					if (useKeySpend)
					{
						var sig = keySpend.SignTaprootKeySpend(hash, treeInfo.MerkleRoot, sighash);
						spender.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig.ToBytes()));
					}
					else
					{
						// use this signatures if XOnly pubKey
						var sig = privateKeys[0].SignTaprootScriptSpend(hash, sighash);
						spender.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig.ToBytes()), Op.GetPushOp(Scripts[script_to_run].Script.ToBytes()), Op.GetPushOp(treeInfo.GetControlBlock(Scripts[script_to_run]).ToBytes()));

					}
					Console.WriteLine(spender.ToString());
					var validator = spender.CreateValidator(new[] { spentOutput.TxOut });
					var result = validator.ValidateInput(0);
					var success = result.Error is null;
					Console.WriteLine("does validate witness? " + success);
					if (success) {
						rpc.SendRawTransaction(spender);
					}
					else { Console.WriteLine("Error " + result.Error.ToString()); }
				}
			}
		}



	}

}


