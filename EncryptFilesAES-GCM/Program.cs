using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
	static void Main()
	{
		try
		{
			string originalFile = "plaintext.txt";
			string encryptedFile = "encrypted.dat";
			string decryptedFile = "decrypted.txt";

			var mainKey = new NBitcoin.Key(NBitcoin.DataEncoders.Encoders.Hex.DecodeData("611bf4560ecd9d966880bc1221c39aa089b9def014466f7e16ec4e0e8a99492b"));

			var (nonceHex, tagHex, encryptedKeyHex) = EncryptFile(originalFile, encryptedFile, mainKey.PubKey);
			System.Console.WriteLine("Encryption complete.");
			System.Console.WriteLine($"Nonce: {nonceHex}\nTag: {tagHex}\nEncrypted Key: {encryptedKeyHex}");

			DecryptFile(encryptedFile, decryptedFile, mainKey, nonceHex, tagHex, encryptedKeyHex);
			System.Console.WriteLine("Decryption complete.");

			DecryptFile(encryptedFile, decryptedFile, mainKey, "", "", "");
			System.Console.WriteLine("Second Decryption complete.");
		}
		catch (System.Exception ex)
		{
			System.Console.WriteLine($"Error: {ex.Message}");
		}
	}

	static (string nonceHex, string tagHex, string encryptedKeyHex) EncryptFile(string inputFilePath, string outputFilePath, NBitcoin.PubKey publicKey)
	{
		byte[] key = new byte[32];
		using (System.Security.Cryptography.RandomNumberGenerator rng = System.Security.Cryptography.RandomNumberGenerator.Create())
		{
			rng.GetBytes(key);
		}

		byte[] encryptedKey = publicKey.Encrypt(key);
		int encryptedKeySize = encryptedKey.Length;

		byte[] nonce = new byte[12];
		byte[] tag = new byte[16];
		using (System.Security.Cryptography.RandomNumberGenerator rng = System.Security.Cryptography.RandomNumberGenerator.Create())
		{
			rng.GetBytes(nonce);
		}

		byte[] plaintext = System.IO.File.ReadAllBytes(inputFilePath);
		byte[] ciphertext = new byte[plaintext.Length];

		using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key))
		{
			aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
		}

		using (System.IO.FileStream outputStream = new System.IO.FileStream(outputFilePath, System.IO.FileMode.Create))
		using (System.IO.BinaryWriter writer = new System.IO.BinaryWriter(outputStream))
		{
			writer.Write(nonce);
			writer.Write(tag);
			writer.Write(encryptedKeySize);
			writer.Write(encryptedKey);
			writer.Write(ciphertext);
		}

		return (
			nonceHex: System.Convert.ToBase64String(nonce),
			tagHex: System.Convert.ToBase64String(tag),
			encryptedKeyHex: System.Convert.ToBase64String(encryptedKey)
		);
	}

	static void DecryptFile(string inputFilePath, string outputFilePath, NBitcoin.Key privateKey, string expectedNonceHex, string expectedTagHex, string expectedEncryptedKeyHex)
	{
		byte[] nonce = new byte[12];
		byte[] tag = new byte[16];

		using (System.IO.FileStream inputStream = new System.IO.FileStream(inputFilePath, System.IO.FileMode.Open))
		using (System.IO.BinaryReader reader = new System.IO.BinaryReader(inputStream))
		{
			reader.Read(nonce, 0, nonce.Length);
			reader.Read(tag, 0, tag.Length);

			int encryptedKeyLength = reader.ReadInt32();
			byte[] encryptedKey = reader.ReadBytes(encryptedKeyLength);

			if (!string.IsNullOrWhiteSpace(expectedNonceHex) && System.Convert.ToBase64String(nonce) != expectedNonceHex)
				throw new System.InvalidOperationException("Nonce mismatch.");

			if (!string.IsNullOrWhiteSpace(expectedTagHex) && System.Convert.ToBase64String(tag) != expectedTagHex)
				throw new System.InvalidOperationException("Tag mismatch.");

			if (!string.IsNullOrWhiteSpace(expectedEncryptedKeyHex) && System.Convert.ToBase64String(encryptedKey) != expectedEncryptedKeyHex)
				throw new System.InvalidOperationException("Encrypted AES key mismatch.");

			byte[] key = privateKey.Decrypt(encryptedKey);
			byte[] ciphertext = reader.ReadBytes((int)(inputStream.Length - inputStream.Position));
			byte[] plaintext = new byte[ciphertext.Length];

			using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key))
			{
				aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
			}

			System.IO.File.WriteAllBytes(outputFilePath, plaintext);
		}
	}
}






//using System;
//using System.IO;
//using System.Security.Cryptography;
//using NBitcoin;
//using NBitcoin.DataEncoders;

//public class AesGcmEncryption
//{
//	public static void EncryptFile(string inputFilePath, string outputFilePath, PubKey publicKey)
//	{
//		byte[] key = new byte[32];
//		using (var rng = RandomNumberGenerator.Create())
//		{
//			rng.GetBytes(key);
//		}

//		// Encrypt the AES key with the public key
//		var encryptedKey = publicKey.Encrypt(key);
//		int encryptedKeySize = encryptedKey.Length;

//		byte[] nonce = new byte[12]; // GCM standard nonce size
//		byte[] tag = new byte[16];
//		using (var rng = RandomNumberGenerator.Create())
//		{
//			rng.GetBytes(nonce);
//		}

//		byte[] plaintext = File.ReadAllBytes(inputFilePath);
//		byte[] ciphertext = new byte[plaintext.Length];

//		using (var aesGcm = new AesGcm(key)) // Use default constructor
//		{
//			aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
//		}

//		using (var outputStream = new FileStream(outputFilePath, FileMode.Create))
//		using (var writer = new BinaryWriter(outputStream))
//		{
//			writer.Write(nonce);
//			writer.Write(tag);
//			writer.Write(encryptedKeySize);
//			writer.Write(encryptedKey);
//			writer.Write(ciphertext);
//		}
//	}

//	public static void DecryptFile(string inputFilePath, string outputFilePath, Key privateKey)
//	{
//		byte[] nonce = new byte[12];
//		byte[] tag = new byte[16];

//		using (var inputStream = new FileStream(inputFilePath, FileMode.Open))
//		using (var reader = new BinaryReader(inputStream))
//		{
//			reader.Read(nonce, 0, nonce.Length);
//			reader.Read(tag, 0, tag.Length);

//			int encryptedKeyLength = reader.ReadInt32();
//			byte[] encryptedKey = reader.ReadBytes(encryptedKeyLength);

//			byte[] key = privateKey.Decrypt(encryptedKey);
//			byte[] ciphertext = reader.ReadBytes((int)(inputStream.Length - inputStream.Position));
//			byte[] plaintext = new byte[ciphertext.Length];

//			using (var aesGcm = new AesGcm(key)) // Use default constructor
//			{
//				aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
//			}

//			File.WriteAllBytes(outputFilePath, plaintext);
//		}
//	}
//}

//class Program
//{
//	static void Main()
//	{
//		string originalFile = "plaintext.txt";
//		string encryptedFile = "encrypted.dat";
//		string decryptedFile = "decrypted.txt";

//		var mainKey = new Key(Encoders.Hex.DecodeData("611bf4560ecd9d966880bc1221c39aa089b9def014466f7e16ec4e0e8a99492b"));

//		AesGcmEncryption.EncryptFile(originalFile, encryptedFile, mainKey.PubKey);
//		Console.WriteLine("Encryption complete.");

//		AesGcmEncryption.DecryptFile(encryptedFile, decryptedFile, mainKey);
//		Console.WriteLine("Decryption complete.");
//	}
//}
