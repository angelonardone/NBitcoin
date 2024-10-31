using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.RPC;
using NBitcoin.Protocol;
using System.Net;
using NBitcoin.Scripting;
using System.Transactions;
using Transaction = NBitcoin.Transaction;
using static NBitcoin.RPC.SignRawTransactionRequest;
using static NBitcoin.Scripting.PubKeyProvider;
using System.Drawing;
using System.Reflection.Metadata;
using System.Threading;
using System.Text;

namespace angeloNBitcoin
{
	class Program
	{
		public static object NodeBuilderEx { get; private set; }

		static void Main(string[] args)
		{

			//Schnorr_signature();
			//Schnorr_signature1();
			//Vector_1();
			//Schnorr_sign_and_verify();
			Schnorr_sign_and_verify_address();
			//_ = CanBuildTaprootSingleSigTransactionsAsync();
			//modified_Vector_1();
		}

		public static async Task CanBuildTaprootSingleSigTransactionsAsync()
		{


			var network = Network.RegTest;
			var rpc = new RPCClient("bitcoin:angelo", "http://127.0.0.1:18443", network);

			//nodeBuilder.StartAll();
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

			async Task RefreshCoin()
			{
				id = await rpc.SendToAddressAsync(address, Money.Coins(1));
				tx = await rpc.GetRawTransactionAsync(id);
				coin = tx.Outputs.AsCoins().Where(o => o.ScriptPubKey == address.ScriptPubKey).Single();
				builder = Network.Main.CreateTransactionBuilder(0);
			}
			await RefreshCoin();
			var signedTx = builder
				.AddCoins(coin)
				.AddKeys(key)
				.Send(destination, amount)
				.SubtractFees()
				.SetChange(change)
				.SendEstimatedFees(rate)
				.BuildTransaction(true);
			rpc.SendRawTransaction(signedTx);

			await RefreshCoin();
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
			await RefreshCoin();
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

			await RefreshCoin();
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
			psbt = CanRoundtripPSBT(psbt);
			psbt.Finalize();
			rpc.SendRawTransaction(psbt.ExtractTransaction());

			// Can we sign the PSBT separately?
			await RefreshCoin();
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

			// This line is useless, we just use it to test the PSBT roundtrip
			psbt.Inputs[0].HDTaprootKeyPaths.Add(taprootKeyPair.PubKey,
												 new TaprootKeyPath(RootedKeyPath.Parse("12345678/86'/0'/0'/0/0"),
												 new uint256[] { RandomUtils.GetUInt256() }));
			psbt = CanRoundtripPSBT(psbt);
			psbt.Finalize();
			rpc.SendRawTransaction(psbt.ExtractTransaction());

			// Can we sign the transaction separately?
			await RefreshCoin();
			var coin1 = coin;
			await RefreshCoin();
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
			await RefreshCoin();
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

		}


		private static PSBT CanRoundtripPSBT(PSBT psbt)
		{
			var psbtBefore = psbt.ToString();
			psbt = psbt.Clone();
			var psbtAfter = psbt.ToString();
			//Assert.Equal(psbtBefore, psbtAfter);
			return psbt;
		}


		static void Schnorr_sign_and_verify()
		{
			// Sign
			var privKey = new Key(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000003"));
			var pubKey = privKey.PubKey.GetTaprootFullPubKey();
			var msg256 = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));
			var sig64 = privKey.SignTaprootKeySpend(msg256);
			Console.WriteLine("pubKe: " + pubKey); // "418c46636d9e1a683f58e35b42336e776fdcc3b2d4e39e7a0bf1ab0716e3c5fa"
			Console.WriteLine("sig64: " + sig64.ToString()); // "3eda64917a14d3d823345791e6648c592d2e86ae4e64b5f71fc7857138cbcec7b6c97385ffabab9b55d9027d4abe02b383d29211adb4702ffda7492bf63eeeaf"
															 // Verify
			NBitcoin.TaprootPubKey expectedpubkey = new TaprootPubKey(Encoders.Hex.DecodeData("418c46636d9e1a683f58e35b42336e776fdcc3b2d4e39e7a0bf1ab0716e3c5fa"));
			var expectedSig = new NBitcoin.Crypto.SchnorrSignature(Encoders.Hex.DecodeData("3eda64917a14d3d823345791e6648c592d2e86ae4e64b5f71fc7857138cbcec7b6c97385ffabab9b55d9027d4abe02b383d29211adb4702ffda7492bf63eeeaf"));
			Console.WriteLine(expectedpubkey.VerifySignature(msg256, expectedSig));


		}
		static void Schnorr_sign_and_verify_address()
		{
			// sign
			var network = Network.Main;
			var privKey = new Key(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000003"));
			var publicKey = privKey.PubKey;
			var netAddress = publicKey.GetAddress(ScriptPubKeyType.TaprootBIP86, network);
			Console.WriteLine(netAddress); // "bc1pgxxyvcmdncdxs06cudd5yvmwwahaesaj6n3eu7st7x4sw9hrchaqjy33gs"
			var msg256 = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));
			var sig64 = privKey.SignTaprootKeySpend(msg256);

			// Verify with adddress
			var expectedSig = new NBitcoin.Crypto.SchnorrSignature(Encoders.Hex.DecodeData("3eda64917a14d3d823345791e6648c592d2e86ae4e64b5f71fc7857138cbcec7b6c97385ffabab9b55d9027d4abe02b383d29211adb4702ffda7492bf63eeeaf"));
			NBitcoin.TaprootAddress tapPubAddress = NBitcoin.TaprootAddress.Create("bc1pgxxyvcmdncdxs06cudd5yvmwwahaesaj6n3eu7st7x4sw9hrchaqjy33gs", network);
			Console.WriteLine(tapPubAddress.ScriptPubKey);
			Console.WriteLine("pub_key: " + privKey.PubKey.ToString());
			Console.WriteLine("output_key: " + privKey.PubKey.GetTaprootFullPubKey());
			Console.WriteLine("internal_key: " + privKey.PubKey.TaprootInternalKey);
			Console.WriteLine($"AllPubKeys: {tapPubAddress.ScriptPubKey.GetAllPubKeys()}");
			Console.WriteLine(tapPubAddress.PubKey); // "418c46636d9e1a683f58e35b42336e776fdcc3b2d4e39e7a0bf1ab0716e3c5fa"

			// TaprootPubKey expectedpubkey = new TaprootPubKey(Encoders.Hex.DecodeData("418c46636d9e1a683f58e35b42336e776fdcc3b2d4e39e7a0bf1ab0716e3c5fa"));
			// TaprootPubKey expectedpubkey = new TaprootPubKey(Encoders.Hex.DecodeData(tapPubAddress.PubKey.ToString()));
			TaprootPubKey expectedpubkey = new TaprootPubKey(tapPubAddress.PubKey.ToBytes());
			Console.WriteLine(expectedpubkey.VerifySignature(msg256, expectedSig));

		}

		static void Schnorr_signature1()
		{


			var key = new Key(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000003"));
			var pairKey = key.CreateKeyPair();
			var tapRootKey = key.CreateTaprootKeyPair();



			var expectedpubkey = new TaprootInternalPubKey(Encoders.Hex.DecodeData("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"));
			// 02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
			var pubkey = key.PubKey.TaprootInternalKey;
			var aux = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));

			Console.WriteLine(pubkey.GetTaprootFullPubKey().ToString());
			Console.WriteLine(pubkey.GetTaprootFullPubKey().GetAddress(Network.Main).ToString());

			var msg256 = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));
			var expectedSig = new SchnorrSignature(Encoders.Hex.DecodeData("e05f8b968c6737d6dfad8fe6d8a37cc4dd88eec7936574ef9a33b97d91c567dff8b52c7730dbbc218aeb14ae8f37f7f1f4bb82617622d4416267fa6e17c30dfd"));

			Console.WriteLine(expectedpubkey.ToString());
			Console.WriteLine(pubkey.ToString());

			var sig64 = key.SignTaprootKeySpend(msg256, null, aux, TaprootSigHash.Default).SchnorrSignature;

			Console.WriteLine(expectedSig.Equals(sig64).ToString());
			Console.WriteLine(sig64.Equals(expectedSig).ToString());
			Console.WriteLine(Encoders.Hex.EncodeData(expectedSig.ToBytes()));  // e05f8b968c6737d6dfad8fe6d8a37cc4dd88eec7936574ef9a33b97d91c567dff8b52c7730dbbc218aeb14ae8f37f7f1f4bb82617622d4416267fa6e17c30dfd
			Console.WriteLine(Encoders.Hex.EncodeData(sig64.ToBytes()));        // e05f8b968c6737d6dfad8fe6d8a37cc4dd88eec7936574ef9a33b97d91c567dff8b52c7730dbbc218aeb14ae8f37f7f1f4bb82617622d4416267fa6e17c30dfd
																				// Verify those signatures for good measure.
			Console.WriteLine(pubkey.VerifyTaproot(msg256, null, sig64).ToString());

			var add = BitcoinAddress.Create("bc1pgxxyvcmdncdxs06cudd5yvmwwahaesaj6n3eu7st7x4sw9hrchaqjy33gs", Network.Main);
			Console.WriteLine(add.ScriptPubKey.IsValid.ToString());

		}
		static void Schnorr_signature()
		{
			var pubkey1 = Encoders.Hex.DecodeData("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
			var msg = Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000");
			var sig = Encoders.Hex.DecodeData("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");

			var taproot = new TaprootPubKey(pubkey1).VerifySignature(new uint256(msg), new SchnorrSignature(sig));

			Console.WriteLine(taproot.ToString());


			var key = new Key(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000003"));

			var expectedpubkey = new TaprootInternalPubKey(Encoders.Hex.DecodeData("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"));
			// 02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
			var pubkey = key.PubKey.TaprootInternalKey;
			var aux = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));

			Console.WriteLine(pubkey.GetTaprootFullPubKey().ToString());
			Console.WriteLine(pubkey.GetTaprootFullPubKey().GetAddress(Network.Main).ToString());

			var msg256 = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));
			var expectedSig = new SchnorrSignature(Encoders.Hex.DecodeData("e05f8b968c6737d6dfad8fe6d8a37cc4dd88eec7936574ef9a33b97d91c567dff8b52c7730dbbc218aeb14ae8f37f7f1f4bb82617622d4416267fa6e17c30dfd"));

			Console.WriteLine(expectedpubkey.ToString());
			Console.WriteLine(pubkey.ToString());

			var sig64 = key.SignTaprootKeySpend(msg256, null, aux, TaprootSigHash.Default).SchnorrSignature;

			Console.WriteLine(expectedSig.Equals(sig64).ToString());
			Console.WriteLine(sig64.Equals(expectedSig).ToString());
			Console.WriteLine(Encoders.Hex.EncodeData(expectedSig.ToBytes()));  // e05f8b968c6737d6dfad8fe6d8a37cc4dd88eec7936574ef9a33b97d91c567dff8b52c7730dbbc218aeb14ae8f37f7f1f4bb82617622d4416267fa6e17c30dfd
			Console.WriteLine(Encoders.Hex.EncodeData(sig64.ToBytes()));        // e05f8b968c6737d6dfad8fe6d8a37cc4dd88eec7936574ef9a33b97d91c567dff8b52c7730dbbc218aeb14ae8f37f7f1f4bb82617622d4416267fa6e17c30dfd
																				// Verify those signatures for good measure.
			Console.WriteLine(pubkey.VerifyTaproot(msg256, null, sig64).ToString());

			var add = BitcoinAddress.Create("bc1pgxxyvcmdncdxs06cudd5yvmwwahaesaj6n3eu7st7x4sw9hrchaqjy33gs", Network.Main);
			Console.WriteLine(add.ScriptPubKey.IsValid.ToString());

		}

		static void Vector_1()
		{

			// secret Key
			var key = new Key(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000003"));
			var expectedpubkey = new TaprootInternalPubKey(Encoders.Hex.DecodeData("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"));
			var aux = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));
			var msg256 = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));
			var expectedSig = new SchnorrSignature(Encoders.Hex.DecodeData("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"));

			var pubkey = key.PubKey.TaprootInternalKey;
			Console.WriteLine("Expected verification: " + expectedpubkey.VerifyTaproot(msg256, null, expectedSig).ToString());

			var sig64 = key.SignTaprootKeySpend(msg256, null, aux, TaprootSigHash.Default).SchnorrSignature;
			Console.WriteLine("Actual verification: " + pubkey.VerifyTaproot(msg256, null, sig64).ToString());

			Console.WriteLine(expectedSig.Equals(sig64).ToString()); // should be true but it's false
			Console.WriteLine(sig64.Equals(expectedSig).ToString()); // sould be true but it's falxe
			Console.WriteLine(Encoders.Hex.EncodeData(expectedSig.ToBytes()));  
			Console.WriteLine(Encoders.Hex.EncodeData(sig64.ToBytes()));        
																				


			var add = BitcoinAddress.Create("bc1pgxxyvcmdncdxs06cudd5yvmwwahaesaj6n3eu7st7x4sw9hrchaqjy33gs", Network.Main);
			Console.WriteLine(add.ScriptPubKey.IsValid.ToString());

		}

		static void modified_Vector_1()
		{

			// secret Key
			var key = new Key(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000003"));
			var expectedpubkey = new TaprootInternalPubKey(Encoders.Hex.DecodeData("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"));
			var aux = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));
			var msg256 = new uint256(Encoders.Hex.DecodeData("0000000000000000000000000000000000000000000000000000000000000000"));
			var expectedSig = new SchnorrSignature(Encoders.Hex.DecodeData("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"));

			var pubkey = key.PubKey.TaprootInternalKey;
			Console.WriteLine("Expected verification: " + expectedpubkey.VerifyTaproot(msg256, null, expectedSig).ToString());

			var sig64 = key.SignTaprootKeySpend(msg256, null, aux, TaprootSigHash.Default).SchnorrSignature;
			Console.WriteLine("Actual verification: " + pubkey.VerifyTaproot(msg256, null, sig64).ToString());

			Console.WriteLine(expectedSig.Equals(sig64).ToString()); // should be true but it's false
			Console.WriteLine(sig64.Equals(expectedSig).ToString()); // sould be true but it's falxe
			Console.WriteLine(Encoders.Hex.EncodeData(expectedSig.ToBytes()));
			Console.WriteLine(Encoders.Hex.EncodeData(sig64.ToBytes()));



			var add = BitcoinAddress.Create("bc1pgxxyvcmdncdxs06cudd5yvmwwahaesaj6n3eu7st7x4sw9hrchaqjy33gs", Network.Main);
			Console.WriteLine(add.ScriptPubKey.IsValid.ToString());

		}
	}
}

