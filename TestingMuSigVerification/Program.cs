using System;
using System.Threading;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using NBitcoin.Crypto;
using System.Security.Cryptography;


namespace NBitcoinTraining
{
	class Program
	{

		static void Main(string[] args)
		{


			var msg6 = Encoders.Hex.DecodeData("80cf46a9c169eec65d2f6e8b9fcd62e4b9503d51c8340a576a0c34f73adb6281");
			var peers2 = 2;


			var strPubNonces6 = new string[peers2];
			var strSigs6 = new string[peers2];
			var strEcPubKeys6 = new string[peers2];


			strEcPubKeys6[0] = "0210ad441bd61957edd3acb6bfebec76ab16903aad6a9096b247509d541dc6a512";
			strEcPubKeys6[1] = "02da631408c787cd180f066bb32bd071c16a42d95adf4e5400e4e3febe63f2b1e2";
			strPubNonces6[0] = "0392af9740f6079a88991b54779de7969d6a41d50f76e18e916f0c2f4a8500065e03030f6a8df876738ed164895b3bfe3c2b7525bfa81e683f558f771a17e839f09f";
			strPubNonces6[1] = "03c584ea9979d1e175d41233814d19be208a1cc5d136f25b7a685105d144877b2202af2f4d5dfe4f4725e7e3a2139862a5218f40ef34b4befdb5b07c32397a4744ff";
			strSigs6[0] = "9223af97e19bded8f04b7c60c05ef712ac2597ae638d53ce40f4b63c444927be";
			strSigs6[1] = "1905a64eb0dadc72465aef4faee4b55692bb15d4d533b8dace3bd695c82d22a3";

			var pubNonces6 = new MusigPubNonce[peers2];
			var sigs6 = new MusigPartialSignature[peers2];
			var ecPubKeys6 = new ECPubKey[peers2];

			for (int i = 0; i < peers2; i++)
			{
				ecPubKeys6[i] = ECPubKey.Create(Encoders.Hex.DecodeData(strEcPubKeys6[i]));
			}
			var aggregatedKey6 = ECPubKey.MusigAggregate(ecPubKeys6);

			var musig6 = new MusigContext(ecPubKeys6, msg6);


			for (int i = 0; i < peers2; i++)
			{
				pubNonces6[i] = new MusigPubNonce(Encoders.Hex.DecodeData(strPubNonces6[i]));
			}

			musig6.ProcessNonces(pubNonces6);

			for (int i = 0; i < peers2; i++)
			{
				sigs6[i] = new MusigPartialSignature(Encoders.Hex.DecodeData(strSigs6[i]));

			}


			Console.WriteLine("Verify signature 1 " + musig6.Verify(ecPubKeys6[0], pubNonces6[0], sigs6[0]));
			Console.WriteLine("Verify signature 2 " + musig6.Verify(ecPubKeys6[1], pubNonces6[1], sigs6[1]));


			var signature6 = musig6.AggregateSignatures(sigs6);


			var schnorrSig6 = new SchnorrSignature(signature6.ToBytes());
			var taprootPubKey6 = new TaprootPubKey(aggregatedKey6.ToXOnlyPubKey().ToBytes());
			Console.WriteLine("Verify taprootPubKey: " + taprootPubKey6.VerifySignature(msg6, schnorrSig6));



		}
	}
}
