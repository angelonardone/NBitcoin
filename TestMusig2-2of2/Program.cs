using System;
using System.Threading;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using NBitcoin.Crypto;
using System.Security.Cryptography;
using System.IO;
using System.Text.Json;


namespace NBitcoinTraining
{
	class Program
	{

		public static string strMsg32 = "80cf46a9c169eec65d2f6e8b9fcd62e4b9503d51c8340a576a0c34f73adb6281";
		public static string priv_key_0 = "94a368cdd1c3132acf63cd999279408d9d9d6b134bcb626031e7d462923ab8b0";
		public static string priv_key_1 = "83f3b73d0744a759e4b5c324f4bbfb4b758f7a125e6a85850f611ebfd4f0a88e";
		public static string pub_key_0 = "0210ad441bd61957edd3acb6bfebec76ab16903aad6a9096b247509d541dc6a512";
		public static string pub_key_1 = "02da631408c787cd180f066bb32bd071c16a42d95adf4e5400e4e3febe63f2b1e2";

		public struct dataToShare
		{
			public string strPuNonce_User0 { get; set; }
			public string strPuNonce_User1 { get; set; }

			public string strSig_User0 { get; set; }
			public string strSig_User1 { get; set; }
		}
		public static dataToShare ReadFromFileAsJson()
		{



			// Check if the file exists
			if (!File.Exists("Musig2-angelo-data.json"))
			{
				// Create an empty file and return an empty MyData structure
				File.WriteAllText("Musig2-angelo-data.json", JsonSerializer.Serialize(new dataToShare()));
				return new dataToShare(); // Return empty structure
			}


			string jsonData = File.ReadAllText("Musig2-angelo-data.json");
			return JsonSerializer.Deserialize<dataToShare>(jsonData);
		}

		public static void SaveToFileAsJson(dataToShare data)
		{
			string jsonData = JsonSerializer.Serialize(data);
			File.WriteAllText("Musig2-angelo-data.json", jsonData);
		}

		public static void create_pubNonce(int user)
		{
			var shareData = ReadFromFileAsJson();


			var ctx = Context.Instance;
			var msg32 = Encoders.Hex.DecodeData(strMsg32);
			ECPrivKey ecPrivKey;
			ECPubKey ecPubKey;
			if (user == 0)
			{
				ecPrivKey = ctx.CreateECPrivKey(Encoders.Hex.DecodeData(priv_key_0));
				ecPubKey = ecPrivKey.CreatePubKey();
				Console.WriteLine("create pubNonce PubkKey0 is equual: " + Encoders.Hex.EncodeData(ecPubKey.ToBytes()).Equals(pub_key_0));
			}
			else
			{
				ecPrivKey = ctx.CreateECPrivKey(Encoders.Hex.DecodeData(priv_key_1));
				ecPubKey = ecPrivKey.CreatePubKey();
				Console.WriteLine("create pubNonce PubkKey1 is equual: " + Encoders.Hex.EncodeData(ecPubKey.ToBytes()).Equals(pub_key_1));
			}


			var ecPubKeys = new ECPubKey[2];
			ecPubKeys[0] = ECPubKey.Create(Encoders.Hex.DecodeData(pub_key_0));
			ecPubKeys[1] = ECPubKey.Create(Encoders.Hex.DecodeData(pub_key_1));

			var musig = new MusigContext(ecPubKeys, msg32);

			var nonce = musig.GenerateNonce(ecPubKey);
			var pubNonces = nonce.CreatePubNonce();

			

			var strPubNonce = Encoders.Hex.EncodeData(pubNonces.ToBytes());

			if (user == 0)
			{
				shareData.strPuNonce_User0 = strPubNonce;
				Console.WriteLine($"strPuNonce_User0: {shareData.strPuNonce_User0}");

			}
			else
			{
				shareData.strPuNonce_User1 = strPubNonce;
				Console.WriteLine($"strPuNonce_User1: {shareData.strPuNonce_User1}");
			}

			SaveToFileAsJson(shareData);

		}

		public static void create_Sig(int user)
		{
			var shareData = ReadFromFileAsJson();
			var ctx = Context.Instance;
			var msg32 = Encoders.Hex.DecodeData(strMsg32);
			ECPrivKey ecPrivKey;
			ECPubKey ecPubKey;
			if (user == 0)
			{
				ecPrivKey = ctx.CreateECPrivKey(Encoders.Hex.DecodeData(priv_key_0));
				ecPubKey = ecPrivKey.CreatePubKey();
				Console.WriteLine("create_sig PubkKey0 is equual: " + Encoders.Hex.EncodeData(ecPubKey.ToBytes()).Equals(pub_key_0));
			}
			else
			{
				ecPrivKey = ctx.CreateECPrivKey(Encoders.Hex.DecodeData(priv_key_1));
				ecPubKey = ecPrivKey.CreatePubKey();
				Console.WriteLine("create_sig PubkKey1 is equual: " + Encoders.Hex.EncodeData(ecPubKey.ToBytes()).Equals(pub_key_1));
			}


			var ecPubKeys = new ECPubKey[2];
			ecPubKeys[0] = ECPubKey.Create(Encoders.Hex.DecodeData(pub_key_0));
			ecPubKeys[1] = ECPubKey.Create(Encoders.Hex.DecodeData(pub_key_1));

			var pubNonces = new MusigPubNonce[2];
			pubNonces[0] = new MusigPubNonce(Encoders.Hex.DecodeData(shareData.strPuNonce_User0));
			pubNonces[1] = new MusigPubNonce(Encoders.Hex.DecodeData(shareData.strPuNonce_User1));

			var musig = new MusigContext(ecPubKeys, msg32);

			musig.ProcessNonces(pubNonces);

			var nonce = musig.GenerateNonce(ecPubKey);

			MusigPartialSignature sig;

			sig = musig.Sign(ecPrivKey, nonce);

			var strSig = Encoders.Hex.EncodeData(sig.ToBytes());

			if (user == 0)
			{
				Console.WriteLine(musig.Verify(ecPubKey, pubNonces[0], sig));
				shareData.strSig_User0 = strSig;
				Console.WriteLine($"strSig_User0: {shareData.strSig_User0}");

			}
			else
			{
				Console.WriteLine(musig.Verify(ecPubKey, pubNonces[1], sig));
				shareData.strSig_User1 = strSig;
				Console.WriteLine($"strSig_User1: {shareData.strSig_User1}");

			}

			SaveToFileAsJson(shareData);
		}


		public static void agregate_Sig()
		{
			var shareData = ReadFromFileAsJson();
			var ctx = Context.Instance;
			var msg32 = Encoders.Hex.DecodeData(strMsg32);


			var ecPubKeys = new ECPubKey[2];
			ecPubKeys[0] = ECPubKey.Create(Encoders.Hex.DecodeData(pub_key_0));
			ecPubKeys[1] = ECPubKey.Create(Encoders.Hex.DecodeData(pub_key_1));

			var pubNonces = new MusigPubNonce[2];
			pubNonces[0] = new MusigPubNonce(Encoders.Hex.DecodeData(shareData.strPuNonce_User0));
			pubNonces[1] = new MusigPubNonce(Encoders.Hex.DecodeData(shareData.strPuNonce_User1));

			var musig = new MusigContext(ecPubKeys, msg32);

			musig.ProcessNonces(pubNonces);
			var sigs = new MusigPartialSignature[2];
			sigs[0] = new MusigPartialSignature(Encoders.Hex.DecodeData(shareData.strSig_User0));
			sigs[1] = new MusigPartialSignature(Encoders.Hex.DecodeData(shareData.strSig_User1));

			var signature = musig.AggregateSignatures(sigs);

			var aggregatedKey = ECPubKey.MusigAggregate(ecPubKeys);

			var schnorrSig = new SchnorrSignature(signature.ToBytes());
			var taprootPubKey = new TaprootPubKey(aggregatedKey.ToXOnlyPubKey().ToBytes());
			var isVerified = taprootPubKey.VerifySignature(msg32, schnorrSig);
			Console.WriteLine(isVerified);


		}


		static void Main(string[] args)
		{

			var shareData = new dataToShare();
			SaveToFileAsJson(shareData);

			// First round
			create_pubNonce(0);
			create_pubNonce(1);

			// Second Round
			create_Sig(0);
			create_Sig(1);

			// Third round
			agregate_Sig();

		}
	}
}
