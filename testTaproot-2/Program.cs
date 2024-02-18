using System;
using System.Threading;
using NBitcoin;
using NBitcoin.Tests;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


namespace NBitcoinTraining
{
	class Program
	{
		static void Main(string[] args)
		{
			//test_transaction_signatures_node();
			//CanBuildTaprootSingleSigTransactionsAsync();
			musig_MusigTest();
		}

		static void secp256k1_rand256(Span<byte> output)
		{
			// Should reproduce the secp256k1_test_rng
			RandomUtils.GetBytes(output);
		}

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
		static Context ctx = Context.Instance;

		static void musig_MusigTest()
		{


			foreach (var useTweak in new[] { false, true })
				foreach (var useAdaptor in new[] { false, true })
				{
					var msg32 = random_scalar_order().ToBytes();
					var tweak = random_scalar_order().ToBytes();
					var adaptor = ctx.CreateECPrivKey(random_scalar_order());
					var peers = 3;
					var privKeys = new ECPrivKey[peers];
					var privNonces = new MusigPrivNonce[peers];
					var pubNonces = new MusigPubNonce[peers];
					var musig = new MusigContext[peers];
					var sigs = new MusigPartialSignature[peers];
					var pubKeys = new ECPubKey[peers];



					for (int i = 0; i < peers; i++)
					{
						privKeys[i] = ctx.CreateECPrivKey(random_scalar_order());
						pubKeys[i] = privKeys[i].CreatePubKey();
					}

					for (int i = 0; i < peers; i++)
					{
						musig[i] = new MusigContext(pubKeys, msg32); // converti en "pbulic" este construcotr que estaba privet en MusigContext.cs
						privNonces[i] = musig[i].GenerateNonce((uint)i, privKeys[i]);
						pubNonces[i] = privNonces[i].CreatePubNonce();
					}

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
					}

					// Combine
					var schnorrSig = musig[0].AggregateSignatures(sigs);

					if (useAdaptor)
						schnorrSig = musig[0].Adapt(schnorrSig, adaptor);
					// Verify resulting signature
					// SigningPubKey is the tweaked key if tweaked, or the combined key if not
					Console.WriteLine(musig[0].AggregatePubKey.ToXOnlyPubKey().SigVerifyBIP340(schnorrSig, msg32));
				}

		}



		static void CanBuildTaprootSingleSigTransactionsAsync()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var network = Network.RegTest;
				// Removing node logs from output
				nodeBuilder.ConfigParameters.Add("printtoconsole", "0");

				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				var change = new Key();
				var rootKey = new ExtKey();
				var accountKeyPath = new KeyPath("86'/0'/0'");
				var accountRootKeyPath = new RootedKeyPath(rootKey.GetPublicKey().GetHDFingerPrint(), accountKeyPath);
				var accountKey = rootKey.Derive(accountKeyPath);
				var key = accountKey.Derive(new KeyPath("0/0")).PrivateKey;
				var address = key.PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, network);
				var destination = new Key();
				var amount = new Money(1, MoneyUnit.BTC);
				uint256 id = null;
				Transaction tx = null;
				ICoin coin = null;
				TransactionBuilder builder = null;
				var rate = new FeeRate(Money.Satoshis(1), 1);


				void RefreshCoin()
				{
					id = rpc.SendToAddress(address, Money.Coins(1));
					tx = rpc.GetRawTransaction(id);
					coin = tx.Outputs.AsCoins().Where(o => o.ScriptPubKey == address.ScriptPubKey).Single();
					builder = network.CreateTransactionBuilder(0);
				}
				RefreshCoin();

				var signedTx = builder
					.AddCoins(coin)
					.AddKeys(key)
					.Send(destination, amount)
					.SubtractFees()
					.SetChange(change)
					.SendEstimatedFees(rate)
					.BuildTransaction(true);
				rpc.SendRawTransaction(signedTx);

				RefreshCoin();
				// Let's try again, but this time with PSBT
				var psbt = builder
					.AddCoins(coin)
					.Send(destination, amount)
					.SubtractFees()
					.SetChange(change)
					.SendEstimatedFees(rate)
					.BuildPSBT(false);

				var tk = key.PubKey.GetTaprootFullPubKey();
				psbt.Inputs[0].HDTaprootKeyPaths.Add(tk.OutputKey, new TaprootKeyPath(accountRootKeyPath.Derive(KeyPath.Parse("0/0"))));
				psbt.SignAll(ScriptPubKeyType.TaprootBIP86, accountKey, accountRootKeyPath);

				// Check if we can roundtrip
				psbt = CanRoundtripPSBT(psbt);

				psbt.Finalize();
				rpc.SendRawTransaction(psbt.ExtractTransaction());

				// Let's try again, but this time with BuildPSBT(true)
				RefreshCoin();
				psbt = builder
					.AddCoins(coin)
					.AddKeys(key)
					.Send(destination, amount)
					.SubtractFees()
					.SetChange(change)
					.SendEstimatedFees(rate)
					.BuildPSBT(true);
				psbt.Finalize();
				rpc.SendRawTransaction(psbt.ExtractTransaction());

				// Let's try again, this time with a merkle root
				var merkleRoot = RandomUtils.GetUInt256();
				address = key.PubKey.GetTaprootFullPubKey(merkleRoot).GetAddress(network);

				RefreshCoin();
				psbt = builder
					.AddCoins(coin)
					.AddKeys(key.CreateTaprootKeyPair(merkleRoot))
					.Send(destination, amount)
					.SubtractFees()
					.SetChange(change)
					.SendEstimatedFees(rate)
					.BuildPSBT(true);
				//Assert.NotNull(psbt.Inputs[0].TaprootMerkleRoot);
				//Assert.NotNull(psbt.Inputs[0].TaprootInternalKey);
				//Assert.NotNull(psbt.Inputs[0].TaprootKeySignature);
				Console.WriteLine(psbt.Inputs[0].TaprootMerkleRoot);
				Console.WriteLine(psbt.Inputs[0].TaprootInternalKey);
				Console.WriteLine(psbt.Inputs[0].TaprootKeySignature);

				psbt = CanRoundtripPSBT(psbt);
				psbt.Finalize();
				rpc.SendRawTransaction(psbt.ExtractTransaction());

				// Can we sign the PSBT separately?
				RefreshCoin();
				psbt = builder
					.AddCoins(coin)
					.Send(destination, amount)
					.SubtractFees()
					.SetChange(change)
					.SendEstimatedFees(rate)
					.BuildPSBT(false);

				var taprootKeyPair = key.CreateTaprootKeyPair(merkleRoot);
				psbt.Inputs[0].Sign(taprootKeyPair);
				//Assert.NotNull(psbt.Inputs[0].TaprootMerkleRoot);
				//Assert.NotNull(psbt.Inputs[0].TaprootInternalKey);
				//Assert.NotNull(psbt.Inputs[0].TaprootKeySignature);
				Console.WriteLine(psbt.Inputs[0].TaprootMerkleRoot);
				Console.WriteLine(psbt.Inputs[0].TaprootInternalKey);
				Console.WriteLine(psbt.Inputs[0].TaprootKeySignature);

				// This line is useless, we just use it to test the PSBT roundtrip
				psbt.Inputs[0].HDTaprootKeyPaths.Add(taprootKeyPair.PubKey,
													 new TaprootKeyPath(RootedKeyPath.Parse("12345678/86'/0'/0'/0/0"),
													 new uint256[] { RandomUtils.GetUInt256() }));
				psbt = CanRoundtripPSBT(psbt);
				psbt.Finalize();
				rpc.SendRawTransaction(psbt.ExtractTransaction());

				// Can we sign the transaction separately?
				RefreshCoin();
				var coin1 = coin;
				RefreshCoin();
				var coin2 = coin;
				builder = Network.Main.CreateTransactionBuilder(0);
				signedTx = builder
					.AddCoins(coin1, coin2)
					.Send(destination, amount)
					.SubtractFees()
					.SetChange(change)
					.SendEstimatedFees(rate)
					.BuildTransaction(false);
				var unsignedTx = signedTx.Clone();
				builder = Network.Main.CreateTransactionBuilder(0);
				builder.AddKeys(key.CreateTaprootKeyPair(merkleRoot));
				builder.AddCoins(coin1);
				//var ex = Assert.Throws<InvalidOperationException>(() => builder.SignTransactionInPlace(signedTx));
				//Assert.Contains("taproot", ex.Message);
				builder.AddCoin(coin2);
				builder.SignTransactionInPlace(signedTx);
				//Assert.True(!WitScript.IsNullOrEmpty(signedTx.Inputs.FindIndexedInput(coin2.Outpoint).WitScript));
				// Another solution is to set the precomputed transaction data.
				signedTx = unsignedTx;
				builder = Network.Main.CreateTransactionBuilder(0);
				builder.AddKeys(key.CreateTaprootKeyPair(merkleRoot));
				builder.AddCoins(coin2);
				builder.SetSigningOptions(new SigningOptions() { PrecomputedTransactionData = signedTx.PrecomputeTransactionData(new ICoin[] { coin1, coin2 }) });
				builder.SignTransactionInPlace(signedTx);
				//Assert.True(!WitScript.IsNullOrEmpty(signedTx.Inputs.FindIndexedInput(coin2.Outpoint).WitScript));


				// Let's check if we estimate precisely the size of a taproot transaction.
				RefreshCoin();
				signedTx = builder
					.AddCoins(coin)
					.AddKeys(key.CreateTaprootKeyPair(merkleRoot))
					.Send(destination, amount)
					.SubtractFees()
					.SetChange(change)
					.SendEstimatedFees(rate)
					.BuildTransaction(false);
				var actualvsize = builder.EstimateSize(signedTx, true);
				builder.SignTransactionInPlace(signedTx);
				var expectedvsize = signedTx.GetVirtualSize();
				// The estimator can't assume the sighash to be default
				// for all inputs, so we likely overestimate 1 bytes per input
				//Assert.Equal(expectedvsize, actualvsize - 1);
				Console.WriteLine(expectedvsize.ToString() + " | " + (actualvsize - 1).ToString());


			}



		}

		private static PSBT CanRoundtripPSBT(PSBT psbt)
		{
			var psbtBefore = psbt.ToString();
			psbt = psbt.Clone();
			var psbtAfter = psbt.ToString();
			//Assert.Equal(psbtBefore, psbtAfter);
			return psbt;
		}




		static void test_transaction_signatures_node()
		{

			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				// Removing node logs from output
				nodeBuilder.ConfigParameters.Add("printtoconsole", "0");

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

						Console.WriteLine(addr.PubKey.VerifySignature(hash, sig.SchnorrSignature));
						spender.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig.ToBytes()));
						rpc.SendRawTransaction(spender);
					}
				}
			}
		}

	}

}

