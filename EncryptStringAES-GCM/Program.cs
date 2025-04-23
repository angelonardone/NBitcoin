using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
	static void Main()
	{
		var mainKey = new NBitcoin.Key(NBitcoin.DataEncoders.Encoders.Hex.DecodeData("611bf4560ecd9d966880bc1221c39aa089b9def014466f7e16ec4e0e8a99492b"));

		string originalText = "This is a secret message.";
		System.Console.WriteLine($"Original Text: {originalText}\n");

		string embeddedCipher = EncryptStringWithEmbeddedMetadata(originalText, mainKey.PubKey);
		System.Console.WriteLine("Encryption complete.");
		System.Console.WriteLine($"Embedded Ciphertext: {embeddedCipher}\n");

		string decryptedText = DecryptStringWithEmbeddedMetadata(embeddedCipher, mainKey);
		System.Console.WriteLine("Decryption complete.");
		System.Console.WriteLine($"Decrypted Text: {decryptedText}");
	}

	static string EncryptStringWithEmbeddedMetadata(string plaintext, NBitcoin.PubKey publicKey)
	{
		byte[] key = new byte[32];
		using (System.Security.Cryptography.RandomNumberGenerator rng = System.Security.Cryptography.RandomNumberGenerator.Create())
		{
			rng.GetBytes(key);
		}

		byte[] nonce = new byte[12];
		byte[] tag = new byte[16];
		using (System.Security.Cryptography.RandomNumberGenerator rng = System.Security.Cryptography.RandomNumberGenerator.Create())
		{
			rng.GetBytes(nonce);
		}

		byte[] encryptedKey = publicKey.Encrypt(key);
		byte[] plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
		byte[] ciphertext = new byte[plaintextBytes.Length];

		using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key))
		{
			aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);
		}

		using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
		using (System.IO.BinaryWriter writer = new System.IO.BinaryWriter(ms))
		{
			writer.Write(nonce);
			writer.Write(tag);
			writer.Write(encryptedKey.Length);
			writer.Write(encryptedKey);
			writer.Write(ciphertext);
			return System.Convert.ToBase64String(ms.ToArray());
		}
	}

	static string DecryptStringWithEmbeddedMetadata(string embeddedCiphertextBase64, NBitcoin.Key privateKey)
	{
		byte[] embeddedBytes = System.Convert.FromBase64String(embeddedCiphertextBase64);

		using (System.IO.MemoryStream ms = new System.IO.MemoryStream(embeddedBytes))
		using (System.IO.BinaryReader reader = new System.IO.BinaryReader(ms))
		{
			byte[] nonce = reader.ReadBytes(12);
			byte[] tag = reader.ReadBytes(16);
			int encryptedKeyLength = reader.ReadInt32();
			byte[] encryptedKey = reader.ReadBytes(encryptedKeyLength);
			byte[] ciphertext = reader.ReadBytes((int)(ms.Length - ms.Position));

			byte[] key = privateKey.Decrypt(encryptedKey);
			byte[] plaintext = new byte[ciphertext.Length];

			using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key))
			{
				aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
			}

			return System.Text.Encoding.UTF8.GetString(plaintext);
		}
	}
}




//using System;
//using System.IO;
//using System.Security.Cryptography;
//using System.Text;
//using NBitcoin;
//using NBitcoin.DataEncoders;

//class Program
//{
//	static void Main()
//	{
//		var mainKey = new Key(Encoders.Hex.DecodeData("611bf4560ecd9d966880bc1221c39aa089b9def014466f7e16ec4e0e8a99492b"));

//		string originalText = "This is a secret message. Este es mas largo";
//		Console.WriteLine($"Original Text: {originalText}\n");

//		var (ciphertext, nonce, tag, encryptedKey) = EncryptString(originalText, mainKey.PubKey);
//		Console.WriteLine("Encryption complete.");
//		Console.WriteLine($"Ciphertext: {ciphertext}\nNonce: {nonce}\nTag: {tag}\nEncrypted Key: {encryptedKey}\n");

//		string decryptedText = DecryptString(ciphertext, nonce, tag, encryptedKey, mainKey);
//		Console.WriteLine("Decryption complete.");
//		Console.WriteLine($"Decrypted Text: {decryptedText}");
//	}

//	static (string ciphertextBase64, string nonceBase64, string tagBase64, string encryptedKeyBase64) EncryptString(string plaintext, PubKey publicKey)
//	{
//		byte[] key = new byte[32];
//		using (var rng = RandomNumberGenerator.Create())
//		{
//			rng.GetBytes(key);
//		}

//		var encryptedKey = publicKey.Encrypt(key);

//		byte[] nonce = new byte[12];
//		byte[] tag = new byte[16];
//		using (var rng = RandomNumberGenerator.Create())
//		{
//			rng.GetBytes(nonce);
//		}

//		byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
//		byte[] ciphertext = new byte[plaintextBytes.Length];

//		using (var aesGcm = new AesGcm(key))
//		{
//			aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);
//		}

//		return (
//			ciphertextBase64: Convert.ToBase64String(ciphertext),
//			nonceBase64: Convert.ToBase64String(nonce),
//			tagBase64: Convert.ToBase64String(tag),
//			encryptedKeyBase64: Convert.ToBase64String(encryptedKey)
//		);
//	}

//	static string DecryptString(string ciphertextBase64, string nonceBase64, string tagBase64, string encryptedKeyBase64, Key privateKey)
//	{
//		byte[] nonce = Convert.FromBase64String(nonceBase64);
//		byte[] tag = Convert.FromBase64String(tagBase64);
//		byte[] encryptedKey = Convert.FromBase64String(encryptedKeyBase64);
//		byte[] ciphertext = Convert.FromBase64String(ciphertextBase64);

//		byte[] key = privateKey.Decrypt(encryptedKey);
//		byte[] plaintext = new byte[ciphertext.Length];

//		using (var aesGcm = new AesGcm(key))
//		{
//			aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
//		}

//		return Encoding.UTF8.GetString(plaintext);
//	}
//}
