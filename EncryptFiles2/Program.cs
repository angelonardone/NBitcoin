using System;
using System.IO;
using System.Security.Cryptography.Algorithms;
using System.Security.Cryptography;
using System.Text;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;


public class AesEncryption
{

	// Encrypts the file at inputFilePath and saves encrypted data to outputFilePath
	public static void EncryptFile(string inputFilePath, string outputFilePath, NBitcoin.PubKey publicKey)
	{


		using (var aes = new System.Security.Cryptography.Aes.Create())
		{
			aes.KeySize = 256;
			aes.BlockSize = 128;
			aes.Mode = System.Security.Cryptography.CipherMode.CBC;
			aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;


			// Encrypt the AES key using the public key
			var encrypted_key = publicKey.Encrypt(aes.Key);
			int encrypted_key_size = encrypted_key.Length;

			Console.WriteLine("aes.key " + NBitcoin.DataEncoders.Encoders.Hex.EncodeData(aes.Key));

			using (var encryptor = aes.CreateEncryptor())
			using (var inputStream = new System.IO.FileStream(inputFilePath, System.IO.FileMode.Open))
			using (var outputStream = new System.IO.FileStream(outputFilePath, System.IO.FileMode.Create))
			using (var writer = new System.IO.BinaryWriter(outputStream))
			{
				// IV
				writer.Write(aes.IV);

				// Write the encrypted key length as a 4-byte int
				writer.Write(encrypted_key_size);

				// Write the encrypted key itself
				writer.Write(encrypted_key);

				// Write the encrypted data
				using (var cryptoStream = new System.Security.Cryptography.CryptoStream(outputStream, encryptor, System.Security.Cryptography.CryptoStreamMode.Write))
				{
					inputStream.CopyTo(cryptoStream);
				}
			}
		}
	}


	// Decrypts the file at inputFilePath and saves decrypted data to outputFilePath
	public static void DecryptFile(string inputFilePath, string outputFilePath, NBitcoin.Key private_key)
	{
		byte[] iv = new byte[16];

		using (var inputStream = new System.IO.FileStream(inputFilePath, FileMode.Open))
		using (var reader = new System.IO.BinaryReader(inputStream))
		{
			//IV
			reader.Read(iv, 0, iv.Length);

			// Read encrypted key size and encrypted key
			int encryptedKeyLength = reader.ReadInt32();
			byte[] encrypted_key = reader.ReadBytes(encryptedKeyLength);

			var key = private_key.Decrypt(encrypted_key);


			using (var aes = new System.Security.Cryptography.AesCryptoServiceProvider())
			{
				aes.KeySize = 256;
				aes.BlockSize = 128;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;
				aes.Key = key;
				aes.IV = iv;

				using (var decryptor = aes.CreateDecryptor())
				using (var cryptoStream = new System.Security.Cryptography.CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
				using (var outputStream = new System.IO.FileStream(outputFilePath, FileMode.Create))
				{
					cryptoStream.CopyTo(outputStream);
				}
			}
		}
	}

}
class Program
{
	static void Main()
	{
		string originalFile = "plaintext.txt";
		string encryptedFile = "encrypted.dat";
		string decryptedFile = "decrypted.txt";

		var main_key = new Key(NBitcoin.DataEncoders.Encoders.Hex.DecodeData("611bf4560ecd9d966880bc1221c39aa089b9def014466f7e16ec4e0e8a99492b"));


		Console.WriteLine("taproot pubkey: " + main_key.PubKey.GetTaprootFullPubKey().ToString());
		var pub_tap_key = main_key.PubKey.GetTaprootFullPubKey();

		Console.WriteLine("taproot internal key" + pub_tap_key.InternalKey.ToString());

		var taprootaddress = TaprootAddress.Create("bcrt1pmmezxxh9n9vrp5wtkqxfy93wnp733aefkt9r2cxlqfhet603fmnscr8kg8", Network.RegTest);
		Console.WriteLine("pubKey " + taprootaddress.PubKey.ToString());

		// Encrypt the file
		AesEncryption.EncryptFile(originalFile, encryptedFile, main_key.PubKey);
		Console.WriteLine("Encryption complete.");

		// Decrypt the file
		AesEncryption.DecryptFile(encryptedFile, decryptedFile, main_key);
		Console.WriteLine("Decryption complete.");
	}
}
