

// I'm embeding the Salt, nonce and tag into the encrypted result
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

class Program
{
	static void Main(string[] args)
	{
		try
		{
			string originalText = "This is a secret message 123456 7890 1234567890!";
			string password = "MySecurePassword123";

			System.Diagnostics.Stopwatch stopwatch = System.Diagnostics.Stopwatch.StartNew();

			stopwatch.Start();
			string encryptedBase64 = EncryptText(originalText, password);
			stopwatch.Stop();
			double encryptTime = stopwatch.Elapsed.TotalSeconds;
			Console.WriteLine($"Encryption Time: {encryptTime:F3} seconds");
			Console.WriteLine($"Encrypted (Base64): {encryptedBase64}");

			if (encryptedBase64 == null)
			{
				throw new InvalidOperationException("Encryption failed: Returned value cannot be null.");
			}

			stopwatch.Reset();
			stopwatch.Start();
			string decryptedText = DecryptText(encryptedBase64, password);
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

	static string EncryptText(string text, string password)
	{
		if (text == null || password == null)
		{
			throw new ArgumentNullException(text == null ? nameof(text) : nameof(password));
		}

		// Generate salt and nonce
		byte[] salt = GenerateRandomBytes(16); // 128-bit salt
		byte[] nonce = GenerateRandomBytes(12); // 96-bit nonce for AES-GCM

		// Derive key using Argon2id
		byte[] key = DeriveKey(password, salt);

		// Encrypt the text
		byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(text);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[16]; // 128-bit tag

		using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, tag.Length))
		{
			aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
		}

		// Combine salt, nonce, ciphertext, and tag into a single array
		// Format: [salt (16 bytes)][nonce (12 bytes)][ciphertext (variable)][tag (16 bytes)]
		byte[] combined = new byte[16 + 12 + ciphertext.Length + 16];
		System.Buffer.BlockCopy(salt, 0, combined, 0, 16); // Salt: first 16 bytes
		System.Buffer.BlockCopy(nonce, 0, combined, 16, 12); // Nonce: next 12 bytes
		System.Buffer.BlockCopy(ciphertext, 0, combined, 16 + 12, ciphertext.Length); // Ciphertext
		System.Buffer.BlockCopy(tag, 0, combined, 16 + 12 + ciphertext.Length, 16); // Tag: last 16 bytes

		// Convert to Base64
		return System.Convert.ToBase64String(combined);
	}

	static string DecryptText(string encryptedBase64, string password)
	{
		if (encryptedBase64 == null || password == null)
		{
			throw new ArgumentNullException(encryptedBase64 == null ? nameof(encryptedBase64) : nameof(password));
		}

		// Decode the Base64 string
		byte[] combined = System.Convert.FromBase64String(encryptedBase64);

		// Ensure the combined array is long enough to contain salt, nonce, and at least a tag
		if (combined.Length < 16 + 12 + 16)
		{
			throw new ArgumentException("Encrypted data is too short to contain salt, nonce, and tag.");
		}

		// Extract salt, nonce, ciphertext, and tag
		byte[] salt = new byte[16];
		byte[] nonce = new byte[12];
		byte[] ciphertext = new byte[combined.Length - 16 - 12 - 16]; // Remaining length minus salt, nonce, and tag
		byte[] tag = new byte[16];

		System.Buffer.BlockCopy(combined, 0, salt, 0, 16); // First 16 bytes: salt
		System.Buffer.BlockCopy(combined, 16, nonce, 0, 12); // Next 12 bytes: nonce
		System.Buffer.BlockCopy(combined, 16 + 12, ciphertext, 0, ciphertext.Length); // Middle: ciphertext
		System.Buffer.BlockCopy(combined, 16 + 12 + ciphertext.Length, tag, 0, 16); // Last 16 bytes: tag

		// Derive key using the extracted salt
		byte[] key = DeriveKey(password, salt);

		// Decrypt
		byte[] plaintext = new byte[ciphertext.Length];
		using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, tag.Length))
		{
			aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
		}

		return Encoding.UTF8.GetString(plaintext);
	}

	static byte[] DeriveKey(string password, byte[] salt)
	{
		using (Konscious.Security.Cryptography.Argon2id argon2 = new Konscious.Security.Cryptography.Argon2id(Encoding.UTF8.GetBytes(password)))
		{
			argon2.Salt = salt;
			argon2.DegreeOfParallelism = 8; // 8 threads (match CPU cores)
			argon2.Iterations = 10; // 10 iterations
			argon2.MemorySize = 1048576; // 1 GB of memory (in kibibytes)
			return argon2.GetBytes(32); // 256-bit key for AES
		}
	}

	static byte[] GenerateRandomBytes(int length)
	{
		byte[] bytes = new byte[length];
		using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
		{
			rng.GetBytes(bytes);
		}
		return bytes;
	}
}











//using System;
//using System.Diagnostics;
//using System.Security.Cryptography;
//using System.Text;
//using Konscious.Security.Cryptography;

//class Program
//{
//	static void Main(string[] args)
//	{
//		try
//		{
//			string originalText = "This is a secret message!";
//			string password = "MySecurePassword123";

//			Stopwatch stopwatch = new Stopwatch();

//			stopwatch.Start();
//			(string encryptedBase64, byte[] salt, byte[] nonce) = EncryptText(originalText, password);
//			stopwatch.Stop();
//			double encryptTime = stopwatch.Elapsed.TotalSeconds;
//			Console.WriteLine($"Encryption Time: {encryptTime:F3} seconds");
//			Console.WriteLine($"Encrypted (Base64): {encryptedBase64}");
//			Console.WriteLine($"Salt (Base64): {Convert.ToBase64String(salt)}");
//			Console.WriteLine($"Nonce (Base64): {Convert.ToBase64String(nonce)}");

//			if (encryptedBase64 == null || salt == null || nonce == null)
//			{
//				throw new InvalidOperationException("Encryption failed: Returned values cannot be null.");
//			}

//			stopwatch.Reset();
//			stopwatch.Start();
//			string decryptedText = DecryptText(encryptedBase64, password, salt, nonce);
//			stopwatch.Stop();
//			double decryptTime = stopwatch.Elapsed.TotalSeconds;
//			Console.WriteLine($"Decryption Time: {decryptTime:F3} seconds");
//			Console.WriteLine($"Decrypted: {decryptedText}");
//		}
//		catch (Exception ex)
//		{
//			Console.WriteLine($"Error: {ex.Message}");
//		}
//	}

//	static (string encryptedBase64, byte[] salt, byte[] nonce) EncryptText(string text, string password)
//	{
//		if (text == null || password == null)
//		{
//			throw new ArgumentNullException(text == null ? nameof(text) : nameof(password));
//		}

//		byte[] salt = GenerateRandomBytes(16); // 128-bit salt
//		byte[] nonce = GenerateRandomBytes(12); // 96-bit nonce for AES-GCM

//		byte[] key = DeriveKey(password, salt);

//		byte[] plaintext = Encoding.UTF8.GetBytes(text);
//		byte[] ciphertext = new byte[plaintext.Length];
//		byte[] tag = new byte[16];

//		using (AesGcm aesGcm = new AesGcm(key, tag.Length))
//		{
//			aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
//		}

//		byte[] encrypted = new byte[ciphertext.Length + tag.Length];
//		Buffer.BlockCopy(ciphertext, 0, encrypted, 0, ciphertext.Length);
//		Buffer.BlockCopy(tag, 0, encrypted, ciphertext.Length, tag.Length);

//		return (Convert.ToBase64String(encrypted), salt, nonce);
//	}

//	static string DecryptText(string encryptedBase64, string password, byte[] salt, byte[] nonce)
//	{
//		if (encryptedBase64 == null || password == null || salt == null || nonce == null)
//		{
//			throw new ArgumentNullException(
//				encryptedBase64 == null ? nameof(encryptedBase64) :
//				password == null ? nameof(password) :
//				salt == null ? nameof(salt) : nameof(nonce));
//		}

//		byte[] key = DeriveKey(password, salt);

//		byte[] encrypted = Convert.FromBase64String(encryptedBase64);
//		byte[] ciphertext = new byte[encrypted.Length - 16];
//		byte[] tag = new byte[16];
//		Buffer.BlockCopy(encrypted, 0, ciphertext, 0, ciphertext.Length);
//		Buffer.BlockCopy(encrypted, ciphertext.Length, tag, 0, tag.Length);

//		byte[] plaintext = new byte[ciphertext.Length];
//		using (AesGcm aesGcm = new AesGcm(key, tag.Length))
//		{
//			aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
//		}

//		return Encoding.UTF8.GetString(plaintext);
//	}

//	static byte[] DeriveKey(string password, byte[] salt)
//	{
//		// Use Argon2id for balanced security
//		using (var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password)))
//		{
//			// 8 seconds to encrypt and 7 seconds to decrypt
//			argon2.Salt = salt; // Explicitly set the salt
//			argon2.DegreeOfParallelism = 8; // 8 threads (match CPU cores)
//			argon2.Iterations = 10; // 10 iterations
//			argon2.MemorySize = 1048576; // 1 GB of memory (in kibibytes)
//			return argon2.GetBytes(32); // 256-bit key for AES
//		}
//	}

//	static byte[] GenerateRandomBytes(int length)
//	{
//		byte[] bytes = new byte[length];
//		using (var rng = RandomNumberGenerator.Create())
//		{
//			rng.GetBytes(bytes);
//		}
//		return bytes;
//	}
//}
