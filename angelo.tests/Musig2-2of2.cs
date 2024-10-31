using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using NBitcoin.Crypto;
using Xunit;

namespace angelo.tests
{

	public class all_tests
	{
		[Fact]
		public void one_run()
		{
			var ctx = Context.Instance;
			var msg32 = Encoders.Hex.DecodeData("80cf46a9c169eec65d2f6e8b9fcd62e4b9503d51c8340a576a0c34f73adb6281");



			var ecPrivateKeysHex = new[] {
						"94a368cdd1c3132acf63cd999279408d9d9d6b134bcb626031e7d462923ab8b0",
						"83f3b73d0744a759e4b5c324f4bbfb4b758f7a125e6a85850f611ebfd4f0a88e"
						};
			var peers = ecPrivateKeysHex.Length;
			TaprootPubKey taprootPubKey = null;

			var ecPrivateKeys = new ECPrivKey[peers];
			var ecPubKeys = new ECPubKey[peers];
			var nonces = new MusigPrivNonce[peers];
			var pubNonces = new MusigPubNonce[peers];
			var sigs = new MusigPartialSignature[peers];

			var strPubNonces = new string[peers];
			var strSigs = new string[peers];
			var strEcPubKeys = new string[peers];

			for (int i = 0; i < peers; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				ecPrivateKeys[i] = ctx.CreateECPrivKey(privateKeyBytes);
				ecPubKeys[i] = ecPrivateKeys[i].CreatePubKey();
				strEcPubKeys[i] = Encoders.Hex.EncodeData(ecPubKeys[i].ToBytes());
				//Console.WriteLine($"Public Key {i}: {strEcPubKeys[i]}");
			}


			var aggregatedKey = ECPubKey.MusigAggregate(ecPubKeys);


			var musig = new MusigContext(ecPubKeys, msg32);

			for (int i = 0; i < peers; i++)
			{
				nonces[i] = musig.GenerateNonce(ecPubKeys[i]);
				pubNonces[i] = nonces[i].CreatePubNonce();
				strPubNonces[i] = Encoders.Hex.EncodeData(pubNonces[i].ToBytes());
				//Console.WriteLine($"pubNonce {i}: {strPubNonces[i]}");
			}

			musig.ProcessNonces(pubNonces);

			for (int i = 0; i < peers; i++)
			{
				sigs[i] = musig.Sign(ecPrivateKeys[i], nonces[i]);
				strSigs[i] = Encoders.Hex.EncodeData(sigs[i].ToBytes());
				//Console.WriteLine($"Signature {i}: {strSigs[i]}");
				Assert.True(musig.Verify(ecPubKeys[i], pubNonces[i], sigs[i]));
			}

			var signature = musig.AggregateSignatures(sigs);


			var schnorrSig = new SchnorrSignature(signature.ToBytes());
			taprootPubKey = new TaprootPubKey(aggregatedKey.ToXOnlyPubKey().ToBytes());
			Assert.True(taprootPubKey.VerifySignature(msg32, schnorrSig));


		}





	}

}
