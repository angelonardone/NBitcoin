// Although using directives are present, the code below uses fully qualified names as requested.
// In standard practice, these using directives would allow for shorter type names.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NBitcoin;
using NBitcoin.DataEncoders;

class Program
{
	static void Main()
	{
		try
		{
			// Use System.String for explicit qualification
			System.String originalFile = "largefile.dat";
			System.String encryptedFile = "encrypted.dat";
			System.String decryptedFile = "decrypted.dat";

			// Use System.Int64 for explicit qualification of long
			// Add 'L' to ensure the multiplication uses 64-bit arithmetic from the start
			System.Int64 desiredSize = 5000L * 1024 * 1024; // Example: 5 GB
															// System.Int64 desiredSize = 50 * 1024 * 1024; // Example: 50 MB.
			CreateDummyFile(originalFile, desiredSize);
			System.Console.WriteLine($"Created dummy file '{originalFile}' of size {desiredSize / (1024 * 1024)} MB.");

			// NBitcoin types are already somewhat qualified by their namespace.
			// Assuming NBitcoin is the root namespace for Key and DataEncoders.
			var mainKey = new NBitcoin.Key(NBitcoin.DataEncoders.Encoders.Hex.DecodeData("611bf4560ecd9d966880bc1221c39aa089b9def014466f7e16ec4e0e8a99492b"));

			// Call local static method (no namespace needed for these)
			var (ivBase64, hmacBase64, encryptedKeyBase64) = EncryptFileStreaming(originalFile, originalFile, encryptedFile, mainKey.PubKey); // PubKey is a property of mainKey
			System.Console.WriteLine("Encryption complete.");
			System.Console.WriteLine($"IV (Base64): {ivBase64}\nHMAC (Base64): {hmacBase64}\nEncrypted Key (Base64): {encryptedKeyBase64}");

			// Call local static method
			System.String originalName = DecryptFileStreaming(encryptedFile, decryptedFile, mainKey, ivBase64, hmacBase64, encryptedKeyBase64);
			System.Console.WriteLine("Decryption complete.");
			System.Console.WriteLine($"Original file name: {originalName}");

			// Optional: Verify file contents match
			System.Console.WriteLine("Verifying file contents...");
			// Call local static method
			if (DoFilesMatch(originalFile, decryptedFile))
			{
				System.Console.WriteLine("Verification successful: Original and decrypted files match.");
			}
			else
			{
				System.Console.WriteLine("Verification FAILED: Original and decrypted files differ.");
			}
		}
		catch (System.Exception ex) // Qualify Exception
		{
			// Use System.Console and ex.ToString() for full details
			System.Console.WriteLine($"Error: {ex.ToString()}");
		}
		finally
		{
			// Clean up test files using System.IO.File
			System.IO.File.Delete("largefile.dat");
			System.IO.File.Delete("encrypted.dat");
			System.IO.File.Delete("decrypted.dat");
			System.Console.WriteLine("Cleaned up dummy files.");
		}
	}

	// Helper method to create a dummy file
	static void CreateDummyFile(System.String filePath, System.Int64 size) // Qualify parameters
	{
		// Qualify FileStream constructor and enum values
		using (var fs = new System.IO.FileStream(filePath, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None))
		{
			fs.SetLength(size); // Instance method call
		}
	}

	// Helper method to compare files
	static System.Boolean DoFilesMatch(System.String file1, System.String file2) // Qualify parameters and return type
	{
		// Qualify constant type
		const System.Int32 bufferSize = 4096;
		// Qualify FileStream constructor and enum values
		using (var fs1 = new System.IO.FileStream(file1, System.IO.FileMode.Open, System.IO.FileAccess.Read))
		using (var fs2 = new System.IO.FileStream(file2, System.IO.FileMode.Open, System.IO.FileAccess.Read))
		{
			// Instance property access
			if (fs1.Length != fs2.Length)
				return false; // bool literal doesn't need qualification

			// Qualify byte array type
			var buffer1 = new System.Byte[bufferSize];
			var buffer2 = new System.Byte[bufferSize];
			// Qualify int type
			System.Int32 bytesRead1, bytesRead2;

			do
			{
				// Instance method calls
				bytesRead1 = fs1.Read(buffer1, 0, bufferSize);
				bytesRead2 = fs2.Read(buffer2, 0, bufferSize);

				// AsSpan and SequenceEqual are often extension methods, called like instance methods.
				// Their full qualification happens via the 'using' directive for the namespace
				// containing the extension methods (like System or System.Linq), not usually at the call site.
				if (bytesRead1 != bytesRead2 || !buffer1.AsSpan(0, bytesRead1).SequenceEqual(buffer2.AsSpan(0, bytesRead2)))
					return false;

			} while (bytesRead1 > 0);
		}
		return true;
	}


	// --- EncryptFileStreaming with Fully Qualified Names ---
	static (System.String ivBase64, System.String hmacBase64, System.String encryptedKeyBase64) EncryptFileStreaming(
		System.String originalName, System.String inputFilePath, System.String outputFilePath, NBitcoin.PubKey publicKey) // Qualify parameters and tuple return types
	{
		// Qualify byte array type
		System.Byte[] aesKey = new System.Byte[32];
		System.Byte[] hmacKey = new System.Byte[32];
		// Qualify static method call
		using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
		{
			rng.GetBytes(aesKey); // Instance method
			rng.GetBytes(hmacKey); // Instance method
		}

		System.Byte[] combinedKey = new System.Byte[64];
		// Qualify static method call
		System.Buffer.BlockCopy(aesKey, 0, combinedKey, 0, 32);
		System.Buffer.BlockCopy(hmacKey, 0, combinedKey, 32, 32);

		// Instance method call on NBitcoin.PubKey object
		System.Byte[] encryptedKey = publicKey.Encrypt(combinedKey);

		System.Byte[] iv = new System.Byte[16];
		using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) // Qualify static method
		{
			rng.GetBytes(iv); // Instance method
		}

		// Qualify static property and instance method
		System.Byte[] nameBytes = System.Text.Encoding.UTF8.GetBytes(originalName);

		System.String tempFilePath = outputFilePath + ".tmp"; // String concatenation

		try
		{
			// --- Step 1: Encrypt data to temporary file ---
			// Qualify constructor and enum values
			using (var tempStream = new System.IO.FileStream(tempFilePath, System.IO.FileMode.Create, System.IO.FileAccess.Write))
			// Qualify static method call
			using (var aes = System.Security.Cryptography.Aes.Create())
			{
				// Instance property assignments with qualified enum values
				aes.Key = aesKey;
				aes.IV = iv;
				aes.Mode = System.Security.Cryptography.CipherMode.CBC;
				aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

				// Instance method call
				using (var encryptor = aes.CreateEncryptor())
				// Qualify constructor and enum value
				using (var cryptoStream = new System.Security.Cryptography.CryptoStream(tempStream, encryptor, System.Security.Cryptography.CryptoStreamMode.Write))
				// Qualify constructor
				using (var writer = new System.IO.BinaryWriter(cryptoStream))
				// Qualify constructor and enum values
				using (var inputStream = new System.IO.FileStream(inputFilePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
				{
					// Instance method calls
					writer.Write(nameBytes.Length);
					writer.Write(nameBytes);
					inputStream.CopyTo(cryptoStream);
				}
			}

			// --- Step 2: Calculate HMAC ---
			System.Byte[] hmac;
			// Qualify constructor and enum values
			using (var tempStreamForHmac = new System.IO.FileStream(tempFilePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
			// Qualify constructor
			using (var hmacSha256 = new System.Security.Cryptography.HMACSHA256(hmacKey))
			{
				// Instance method call
				hmac = hmacSha256.ComputeHash(tempStreamForHmac);
			}

			// --- Step 3: Construct final file ---
			// Qualify constructor and enum values
			using (var outputStream = new System.IO.FileStream(outputFilePath, System.IO.FileMode.Create, System.IO.FileAccess.Write))
			using (var tempStreamForCopy = new System.IO.FileStream(tempFilePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
			{
				// Instance method call
				outputStream.Write(iv, 0, iv.Length);
				// Qualify static method call
				outputStream.Write(System.BitConverter.GetBytes(32), 0, 4);
				outputStream.Write(hmac, 0, hmac.Length);
				outputStream.Write(System.BitConverter.GetBytes(encryptedKey.Length), 0, 4);
				outputStream.Write(encryptedKey, 0, encryptedKey.Length);
				// Instance method call
				tempStreamForCopy.CopyTo(outputStream);
			}

			// --- Step 4: Return metadata ---
			// Qualify static method calls
			return (
				System.Convert.ToBase64String(iv),
				System.Convert.ToBase64String(hmac),
				System.Convert.ToBase64String(encryptedKey)
			);
		}
		finally
		{
			// --- Step 5: Clean up ---
			// Qualify static method call
			System.IO.File.Delete(tempFilePath);
		}
	}


	// --- DecryptFileStreaming with Fully Qualified Names ---
	static System.String DecryptFileStreaming( // Qualify return type and parameters
		System.String inputFilePath,
		System.String outputFilePath,
		NBitcoin.Key privateKey, // NBitcoin type
		System.String expectedIvBase64,
		System.String expectedHmacBase64,
		System.String expectedEncryptedKeyBase64)
	{
		// Qualify constructor and enum values
		using (var inputStream = new System.IO.FileStream(inputFilePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
		// Qualify constructor, static property, bool literal
		using (var reader = new System.IO.BinaryReader(inputStream, System.Text.Encoding.UTF8, leaveOpen: true))
		{
			// --- Read Header ---
			// Instance method calls
			System.Byte[] iv = reader.ReadBytes(16); // Qualify type
			System.Int32 hmacLength = reader.ReadInt32(); // Qualify type
			if (hmacLength != 32)
				// Qualify exception type
				throw new System.Security.Cryptography.CryptographicException($"Unexpected HMAC length: {hmacLength}. Expected 32.");
			System.Byte[] hmac = reader.ReadBytes(hmacLength); // Qualify type
			System.Int32 encryptedKeyLength = reader.ReadInt32(); // Qualify type
			System.Byte[] encryptedKey = reader.ReadBytes(encryptedKeyLength); // Qualify type

			// --- Optional: Verify metadata ---
			// Qualify static method calls
			if (!System.String.IsNullOrWhiteSpace(expectedIvBase64) && System.Convert.ToBase64String(iv) != expectedIvBase64)
				// Qualify exception type
				throw new System.InvalidOperationException("IV mismatch between header and expected value.");
			if (!System.String.IsNullOrWhiteSpace(expectedHmacBase64) && System.Convert.ToBase64String(hmac) != expectedHmacBase64)
				throw new System.InvalidOperationException("HMAC mismatch between header and expected value.");
			if (!System.String.IsNullOrWhiteSpace(expectedEncryptedKeyBase64) && System.Convert.ToBase64String(encryptedKey) != expectedEncryptedKeyBase64)
				throw new System.InvalidOperationException("Encrypted AES key mismatch between header and expected value.");

			// --- Decrypt Keys ---
			System.Byte[] combinedKey; // Qualify type
			try
			{
				// Instance method call on NBitcoin.Key object
				combinedKey = privateKey.Decrypt(encryptedKey);
				if (combinedKey == null || combinedKey.Length != 64)
					throw new System.Security.Cryptography.CryptographicException("Failed to decrypt or invalid decrypted key length.");
			}
			catch (System.Exception ex) // Qualify exception type
			{
				// Qualify exception type
				throw new System.Security.Cryptography.CryptographicException("Failed to decrypt the symmetric keys. Check if the correct private key was used.", ex);
			}

			// Qualify type
			System.Byte[] aesKey = new System.Byte[32];
			System.Byte[] hmacKey = new System.Byte[32];
			// Qualify static method call
			System.Buffer.BlockCopy(combinedKey, 0, aesKey, 0, 32);
			System.Buffer.BlockCopy(combinedKey, 32, hmacKey, 0, 32);

			// --- Verify HMAC ---
			// Qualify type, access instance property
			System.Int64 ciphertextStart = inputStream.Position;
			System.Byte[] computedHmac; // Qualify type
										// Qualify constructor
			using (var hmacSha256 = new System.Security.Cryptography.HMACSHA256(hmacKey))
			{
				// Access instance property
				inputStream.Position = ciphertextStart;
				// Instance method call
				computedHmac = hmacSha256.ComputeHash(inputStream);
				// Access instance property
				inputStream.Position = ciphertextStart; // Reset position AGAIN for decryption
			}

			// Qualify static method call
			if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(hmac, computedHmac))
				// Qualify exception type
				throw new System.Security.Cryptography.CryptographicException("HMAC validation failed. The file may be corrupted or tampered with.");

			// --- Decrypt Data ---
			// Qualify static method call
			using (var aes = System.Security.Cryptography.Aes.Create())
			{
				// Assign instance properties, qualify enum values
				aes.Key = aesKey;
				aes.IV = iv;
				aes.Mode = System.Security.Cryptography.CipherMode.CBC;
				aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

				// Instance method call
				using (var decryptor = aes.CreateDecryptor())
				// Qualify constructor and enum value
				using (var cryptoStream = new System.Security.Cryptography.CryptoStream(inputStream, decryptor, System.Security.Cryptography.CryptoStreamMode.Read))
				{
					System.String originalName; // Qualify type
					System.Byte[] nameLengthBytes = new System.Byte[4]; // Qualify type
																		// Instance method call
					System.Int32 bytesRead = cryptoStream.Read(nameLengthBytes, 0, 4); // Qualify type
					if (bytesRead < 4)
						throw new System.Security.Cryptography.CryptographicException("Failed to read filename length from encrypted stream. File may be truncated or corrupted.");

					// Qualify static method call and type
					System.Int32 nameLength = System.BitConverter.ToInt32(nameLengthBytes, 0);
					// Qualify type
					const System.Int32 maxReasonableNameLength = 1024 * 4;
					if (nameLength < 0 || nameLength > maxReasonableNameLength)
					{
						throw new System.Security.Cryptography.CryptographicException($"Invalid original filename length decoded: {nameLength}");
					}

					if (nameLength == 0)
					{
						// Qualify static property
						originalName = System.String.Empty;
					}
					else
					{
						// Qualify type
						System.Byte[] nameBytes = new System.Byte[nameLength];
						System.Int32 totalNameBytesRead = 0; // Qualify type
						while (totalNameBytesRead < nameLength)
						{
							// Instance method call, Qualify type
							bytesRead = cryptoStream.Read(nameBytes, totalNameBytesRead, nameLength - totalNameBytesRead);
							if (bytesRead == 0)
								throw new System.Security.Cryptography.CryptographicException("Failed to read full filename from encrypted stream. File may be truncated or corrupted.");
							totalNameBytesRead += bytesRead;
						}
						// Qualify static property and instance method
						originalName = System.Text.Encoding.UTF8.GetString(nameBytes);
					}

					// Qualify constructor and enum values
					using (var outStream = new System.IO.FileStream(outputFilePath, System.IO.FileMode.Create, System.IO.FileAccess.Write))
					{
						// Instance method calls
						cryptoStream.CopyTo(outStream);
						outStream.Flush();
					}

					return originalName;
				}
			}
		}
	}
}



//using System;
//using System.IO;
//using System.Security.Cryptography;
//using System.Text;
//using NBitcoin; // Assuming NBitcoin namespace is used for Key/PubKey
//using NBitcoin.DataEncoders; // Assuming Encoders is here

//class Program
//{
//	// --- Main method remains the same ---
//	static void Main()
//	{
//		try
//		{
//			// Create a dummy large file for testing (e.g., > 2GB if possible, or smaller to test logic)
//			// Be cautious with disk space when creating very large files.
//			string originalFile = "largefile.dat";
//			long desiredSize = 5000L * 1024 * 1024; // Example: 5 GB. Increase for real large file test.
//												 // long desiredSize = 2_200_000_000; // Example: ~2.2 GB to trigger the original error
//			CreateDummyFile(originalFile, desiredSize);
//			Console.WriteLine($"Created dummy file '{originalFile}' of size {desiredSize / (1024 * 1024)} MB.");


//			string encryptedFile = "encrypted.dat";
//			string decryptedFile = "decrypted.dat";

//			// Use a real private key hex string (ensure it's 32 bytes / 64 hex chars)
//			var mainKey = new NBitcoin.Key(NBitcoin.DataEncoders.Encoders.Hex.DecodeData("611bf4560ecd9d966880bc1221c39aa089b9def014466f7e16ec4e0e8a99492b"));

//			var (ivBase64, hmacBase64, encryptedKeyBase64) = EncryptFileStreaming("originalName.dat", originalFile, encryptedFile, mainKey.PubKey);
//			Console.WriteLine("Encryption complete.");
//			Console.WriteLine($"IV (Base64): {ivBase64}\nHMAC (Base64): {hmacBase64}\nEncrypted Key (Base64): {encryptedKeyBase64}");

//			string originalName = DecryptFileStreaming(encryptedFile, decryptedFile, mainKey, ivBase64, hmacBase64, encryptedKeyBase64);
//			Console.WriteLine("Decryption complete.");
//			Console.WriteLine($"Original file name: {originalName}");

//			// Optional: Verify file contents match
//			Console.WriteLine("Verifying file contents...");
//			if (DoFilesMatch(originalFile, decryptedFile))
//			{
//				Console.WriteLine("Verification successful: Original and decrypted files match.");
//			}
//			else
//			{
//				Console.WriteLine("Verification FAILED: Original and decrypted files differ.");
//			}
//		}
//		catch (Exception ex)
//		{
//			Console.WriteLine($"Error: {ex.ToString()}"); // Use ToString() for more details including stack trace
//		}
//		finally
//		{
//			// Clean up test files
//			File.Delete("largefile.dat");
//			File.Delete("encrypted.dat");
//			File.Delete("decrypted.dat");
//			Console.WriteLine("Cleaned up dummy files.");
//		}
//	}

//	// Helper method to create a dummy file
//	static void CreateDummyFile(string filePath, long size)
//	{
//		using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
//		{
//			fs.SetLength(size); // Efficiently creates a file of the specified size (sparse if supported)
//								// Optionally write some data if needed for non-sparse files or specific tests
//								// fs.Write(new byte[1], 0, 1); // Write at least one byte
//		}
//	}

//	// Helper method to compare files
//	static bool DoFilesMatch(string file1, string file2)
//	{
//		const int bufferSize = 4096;
//		using (var fs1 = new FileStream(file1, FileMode.Open, FileAccess.Read))
//		using (var fs2 = new FileStream(file2, FileMode.Open, FileAccess.Read))
//		{
//			if (fs1.Length != fs2.Length)
//				return false;

//			var buffer1 = new byte[bufferSize];
//			var buffer2 = new byte[bufferSize];
//			int bytesRead1, bytesRead2;

//			do
//			{
//				bytesRead1 = fs1.Read(buffer1, 0, bufferSize);
//				bytesRead2 = fs2.Read(buffer2, 0, bufferSize);

//				if (bytesRead1 != bytesRead2 || !buffer1.AsSpan(0, bytesRead1).SequenceEqual(buffer2.AsSpan(0, bytesRead2)))
//					return false;

//			} while (bytesRead1 > 0);
//		}
//		return true;
//	}


//	// --- MODIFIED EncryptFileStreaming ---
//	static (string ivBase64, string hmacBase64, string encryptedKeyBase64) EncryptFileStreaming(
//		string originalName, string inputFilePath, string outputFilePath, NBitcoin.PubKey publicKey)
//	{
//		byte[] aesKey = new byte[32]; // AES-256
//		byte[] hmacKey = new byte[32]; // HMAC-SHA256 key
//		using (var rng = RandomNumberGenerator.Create())
//		{
//			rng.GetBytes(aesKey);
//			rng.GetBytes(hmacKey);
//		}

//		// Combine keys for ECIES encryption
//		byte[] combinedKey = new byte[64];
//		Buffer.BlockCopy(aesKey, 0, combinedKey, 0, 32);
//		Buffer.BlockCopy(hmacKey, 0, combinedKey, 32, 32);

//		// Encrypt the combined AES and HMAC keys using the recipient's public key
//		byte[] encryptedKey = publicKey.Encrypt(combinedKey);

//		// Generate a random IV (Initialization Vector) for AES-CBC
//		byte[] iv = new byte[16]; // AES block size is 128 bits (16 bytes)
//		using (var rng = RandomNumberGenerator.Create())
//		{
//			rng.GetBytes(iv);
//		}

//		byte[] nameBytes = Encoding.UTF8.GetBytes(originalName);
//		// No practical limit here with streaming, but good practice to check reasonable length if needed
//		// if (nameBytes.Length > short.MaxValue) // Example limit
//		//     throw new ArgumentOutOfRangeException(nameof(originalName), "Original file name is too long.");

//		string tempFilePath = outputFilePath + ".tmp";

//		try
//		{
//			// --- Step 1: Encrypt data (including original filename) to a temporary file ---
//			using (var tempStream = new FileStream(tempFilePath, FileMode.Create, FileAccess.Write))
//			using (var aes = Aes.Create())
//			{
//				aes.Key = aesKey;
//				aes.IV = iv;
//				aes.Mode = CipherMode.CBC;
//				aes.Padding = PaddingMode.PKCS7;

//				using (var encryptor = aes.CreateEncryptor())
//				using (var cryptoStream = new CryptoStream(tempStream, encryptor, CryptoStreamMode.Write))
//				using (var writer = new BinaryWriter(cryptoStream)) // Use BinaryWriter for length prefix
//				using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
//				{
//					// Write filename length and filename itself *inside* the encrypted stream
//					writer.Write(nameBytes.Length);
//					writer.Write(nameBytes);

//					// Stream the original file content into the crypto stream
//					inputStream.CopyTo(cryptoStream);
//					// CryptoStream needs FlushFinalBlock to write padding etc. when disposed
//				}
//			} // using cryptoStream, encryptor, writer, inputStream, aes - ensures everything is flushed and closed


//			// --- Step 2: Calculate HMAC over the *entire* content of the temporary (ciphertext) file ---
//			byte[] hmac;
//			using (var tempStreamForHmac = new FileStream(tempFilePath, FileMode.Open, FileAccess.Read))
//			using (var hmacSha256 = new HMACSHA256(hmacKey))
//			{
//				// ComputeHash on a stream reads it chunk by chunk - memory efficient
//				hmac = hmacSha256.ComputeHash(tempStreamForHmac);
//			}

//			// --- Step 3: Construct the final output file ---
//			using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
//			using (var tempStreamForCopy = new FileStream(tempFilePath, FileMode.Open, FileAccess.Read))
//			{
//				// Write header: IV (16 bytes)
//				outputStream.Write(iv, 0, iv.Length);

//				// Write header: HMAC length (4 bytes, fixed at 32 for SHA256)
//				outputStream.Write(BitConverter.GetBytes(32), 0, 4);

//				// Write header: HMAC value (32 bytes)
//				outputStream.Write(hmac, 0, hmac.Length);

//				// Write header: Encrypted Key length (4 bytes)
//				outputStream.Write(BitConverter.GetBytes(encryptedKey.Length), 0, 4);

//				// Write header: Encrypted Key value (variable length)
//				outputStream.Write(encryptedKey, 0, encryptedKey.Length);

//				// Append the actual ciphertext from the temp file
//				tempStreamForCopy.CopyTo(outputStream);
//			}

//			// --- Step 4: Return metadata (as Base64 strings for easy handling/storage) ---
//			return (
//				Convert.ToBase64String(iv),
//				Convert.ToBase64String(hmac),
//				Convert.ToBase64String(encryptedKey)
//			);
//		}
//		finally
//		{
//			// --- Step 5: Clean up the temporary file ---
//			File.Delete(tempFilePath);
//		}
//	}


//	// --- DecryptFileStreaming method remains the same, it should already be streaming friendly ---
//	static string DecryptFileStreaming(string inputFilePath, string outputFilePath, NBitcoin.Key privateKey, string expectedIvBase64, string expectedHmacBase64, string expectedEncryptedKeyBase64)
//	{
//		using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
//		// Use BinaryReader to easily read fixed-size header parts
//		using (var reader = new BinaryReader(inputStream, Encoding.UTF8, leaveOpen: true)) // leaveOpen: true because CryptoStream will own closing inputStream later
//		{
//			// --- Read Header ---
//			byte[] iv = reader.ReadBytes(16); // Read IV
//			int hmacLength = reader.ReadInt32(); // Read HMAC length
//			if (hmacLength != 32) // Basic sanity check for SHA256
//				throw new CryptographicException($"Unexpected HMAC length: {hmacLength}. Expected 32.");
//			byte[] hmac = reader.ReadBytes(hmacLength); // Read HMAC
//			int encryptedKeyLength = reader.ReadInt32(); // Read encrypted key length
//			byte[] encryptedKey = reader.ReadBytes(encryptedKeyLength); // Read encrypted key

//			// --- Optional: Verify metadata if provided externally ---
//			// Note: Comparing Base64 strings is easier than converting back and comparing byte arrays
//			if (!string.IsNullOrWhiteSpace(expectedIvBase64) && Convert.ToBase64String(iv) != expectedIvBase64)
//				throw new InvalidOperationException("IV mismatch between header and expected value.");
//			if (!string.IsNullOrWhiteSpace(expectedHmacBase64) && Convert.ToBase64String(hmac) != expectedHmacBase64)
//				throw new InvalidOperationException("HMAC mismatch between header and expected value.");
//			if (!string.IsNullOrWhiteSpace(expectedEncryptedKeyBase64) && Convert.ToBase64String(encryptedKey) != expectedEncryptedKeyBase64)
//				throw new InvalidOperationException("Encrypted AES key mismatch between header and expected value.");

//			// --- Decrypt Keys ---
//			byte[] combinedKey;
//			try
//			{
//				combinedKey = privateKey.Decrypt(encryptedKey);
//				if (combinedKey == null || combinedKey.Length != 64)
//					throw new CryptographicException("Failed to decrypt or invalid decrypted key length.");
//			}
//			catch (Exception ex) // Catch potential decryption errors from NBitcoin
//			{
//				throw new CryptographicException("Failed to decrypt the symmetric keys. Check if the correct private key was used.", ex);
//			}

//			byte[] aesKey = new byte[32];
//			byte[] hmacKey = new byte[32];
//			Buffer.BlockCopy(combinedKey, 0, aesKey, 0, 32);
//			Buffer.BlockCopy(combinedKey, 32, hmacKey, 0, 32);

//			// --- Verify HMAC ---
//			// Remember the position where the ciphertext starts
//			long ciphertextStart = inputStream.Position;

//			byte[] computedHmac;
//			using (var hmacSha256 = new HMACSHA256(hmacKey))
//			{
//				// Ensure we compute hash only over the ciphertext part of the stream
//				inputStream.Position = ciphertextStart;
//				computedHmac = hmacSha256.ComputeHash(inputStream); // Reads the rest of the stream efficiently
//			}

//			// Constant-time comparison for security
//			if (!CryptographicOperations.FixedTimeEquals(hmac, computedHmac))
//				throw new CryptographicException("HMAC validation failed. The file may be corrupted or tampered with.");

//			// --- Decrypt Data ---
//			// Reset position to the beginning of the ciphertext for decryption
//			inputStream.Position = ciphertextStart;

//			using (var aes = Aes.Create())
//			{
//				aes.Key = aesKey;
//				aes.IV = iv;
//				aes.Mode = CipherMode.CBC;
//				aes.Padding = PaddingMode.PKCS7; // Must match encryption padding

//				using (var decryptor = aes.CreateDecryptor())
//				// CryptoStream will read from inputStream (starting at ciphertextStart)
//				using (var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
//				// Use BinaryReader on the DECRYPTED stream to read the length-prefixed filename
//				using (var readerPlain = new BinaryReader(cryptoStream, Encoding.UTF8, leaveOpen: true)) // leaveOpen important for CopyTo below
//				{
//					string originalName = "";
//					try
//					{
//						int nameLength = readerPlain.ReadInt32();
//						// Basic sanity check on name length to prevent huge allocation
//						if (nameLength < 0 || nameLength > 1024 * 1024) // e.g., 1MB limit for name
//						{
//							throw new CryptographicException("Invalid original filename length decoded.");
//						}
//						byte[] nameBytes = readerPlain.ReadBytes(nameLength);
//						originalName = Encoding.UTF8.GetString(nameBytes);
//					}
//					catch (EndOfStreamException ex)
//					{
//						throw new CryptographicException("Failed to read original filename from encrypted stream. File may be truncated or corrupted.", ex);
//					}
//					catch (IOException ex) // Could happen if underlying stream has issues
//					{
//						throw new CryptographicException("IO error while reading filename from decrypted stream.", ex);
//					}


//					// Stream the rest of the decrypted data to the output file
//					using (var outStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
//					{
//						// cryptoStream now points *after* the filename bytes
//						cryptoStream.CopyTo(outStream);
//					}

//					return originalName; // Return the successfully decrypted original filename
//				}
//			}
//		} // using inputStream - finally closes the input file stream
//	}
//}
