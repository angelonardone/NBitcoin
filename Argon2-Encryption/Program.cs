using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;

class Program
{
	static void Main(string[] args)
	{
		try
		{
			string originalText = "This is a secret message!";
			string password = "MySecurePassword123";

			Stopwatch stopwatch = new Stopwatch();

			stopwatch.Start();
			(string encryptedBase64, byte[] salt, byte[] nonce) = EncryptText(originalText, password);
			stopwatch.Stop();
			double encryptTime = stopwatch.Elapsed.TotalSeconds;
			Console.WriteLine($"Encryption Time: {encryptTime:F3} seconds");
			Console.WriteLine($"Encrypted (Base64): {encryptedBase64}");
			Console.WriteLine($"Salt (Base64): {Convert.ToBase64String(salt)}");
			Console.WriteLine($"Nonce (Base64): {Convert.ToBase64String(nonce)}");

			// Null checks for the returned values
			if (encryptedBase64 == null || salt == null || nonce == null)
			{
				throw new InvalidOperationException("Encryption failed: Returned values cannot be null.");
			}

			stopwatch.Reset();
			stopwatch.Start();
			string decryptedText = DecryptText(encryptedBase64, password, salt, nonce);
			stopwatch.Stop();
			double decryptTime = stopwatch.Elapsed.TotalSeconds;
			Console.WriteLine($"Decryption Time: {decryptTime:F3} seconds");
			Console.WriteLine($"Decrypted: {decryptedText}");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error: {ex.Message}");
		}
	}

	static (string encryptedBase64, byte[] salt, byte[] nonce) EncryptText(string text, string password)
	{
		if (text == null || password == null)
		{
			throw new ArgumentNullException(text == null ? nameof(text) : nameof(password));
		}

		byte[] salt = GenerateRandomBytes(16); // 128-bit salt
		byte[] nonce = GenerateRandomBytes(12); // 96-bit nonce for AES-GCM

		byte[] key = DeriveKey(password, salt);

		byte[] plaintext = Encoding.UTF8.GetBytes(text);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[16];

		// Specify the tag size explicitly (16 bytes = 128 bits)
		using (AesGcm aesGcm = new AesGcm(key, tag.Length))
		{
			aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
		}

		byte[] encrypted = new byte[ciphertext.Length + tag.Length];
		Buffer.BlockCopy(ciphertext, 0, encrypted, 0, ciphertext.Length);
		Buffer.BlockCopy(tag, 0, encrypted, ciphertext.Length, tag.Length);

		return (Convert.ToBase64String(encrypted), salt, nonce);
	}

	static string DecryptText(string encryptedBase64, string password, byte[] salt, byte[] nonce)
	{
		if (encryptedBase64 == null || password == null || salt == null || nonce == null)
		{
			throw new ArgumentNullException(
				encryptedBase64 == null ? nameof(encryptedBase64) :
				password == null ? nameof(password) :
				salt == null ? nameof(salt) : nameof(nonce));
		}

		byte[] key = DeriveKey(password, salt);

		byte[] encrypted = Convert.FromBase64String(encryptedBase64);
		byte[] ciphertext = new byte[encrypted.Length - 16];
		byte[] tag = new byte[16];
		Buffer.BlockCopy(encrypted, 0, ciphertext, 0, ciphertext.Length);
		Buffer.BlockCopy(encrypted, ciphertext.Length, tag, 0, tag.Length);

		byte[] plaintext = new byte[ciphertext.Length];
		// Specify the tag size explicitly (16 bytes = 128 bits)
		using (AesGcm aesGcm = new AesGcm(key, tag.Length))
		{
			aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
		}

		return Encoding.UTF8.GetString(plaintext);
	}

	static byte[] DeriveKey(string password, byte[] salt)
	{
		var config = new Argon2Config
		{
			Type = Argon2Type.DataDependentAddressing, // Use Argon2id for balanced security
			Version = Argon2Version.Nineteen,
			TimeCost = 10, // 10 iterations
			MemoryCost = 65536 * 8, // Memory usage in kibibytes (64 MB) * 12 = 7 seconds encrypt and 6 seconds decrypt
			//MemoryCost = 65536 * 12, // Memory usage in kibibytes (64 MB) * 12 = 10 seconds encrypt and 9 seconds decrypt
			Threads = 8, // 8 threads (match CPU cores)
			Password = Encoding.UTF8.GetBytes(password),
			Salt = salt, // Explicitly set the salt
			HashLength = 32 // 256-bit key for AES
		};

		using (var argon2 = new Argon2(config))
		using (SecureArray<byte> hash = argon2.Hash())
		{
			return hash.Buffer;
		}
	}

	static byte[] GenerateRandomBytes(int length)
	{
		byte[] bytes = new byte[length];
		using (var rng = RandomNumberGenerator.Create())
		{
			rng.GetBytes(bytes);
		}
		return bytes;
	}
}
