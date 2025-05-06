// DistricutedCryptographyLib/YourFile.cs
using System; // Added for ArgumentNullException etc.
using System.Security.Cryptography;
using System.Text;

namespace DistricutedCryptographyLib
{
	public class EncryptionResult
	{
		public string CipherText { get; set; } = string.Empty;
		public string? GeneratedKey { get; set; }
		public string? ErrorMessage { get; set; } // New property for error messages

		// Helper to check if the operation was successful
		public bool Success => string.IsNullOrEmpty(ErrorMessage);
	}

	// New class for Decryption results
	public class DecryptionResult
	{
		public string DecryptedText { get; set; } = string.Empty;
		public string? ErrorMessage { get; set; }

		// Helper to check if the operation was successful
		public bool Success => string.IsNullOrEmpty(ErrorMessage);
	}

	public class EncryptionService
	{
		private const int KeySizeBits = 256;
		private const int KeySizeBytes = KeySizeBits / 8;
		private const int NonceSizeBytes = 12;
		private const int TagSizeBytes = 16;

		public EncryptionResult Encrypt(string plainText, string? base64Key)
		{
			var result = new EncryptionResult();
			try
			{
				if (string.IsNullOrEmpty(plainText))
				{
					result.ErrorMessage = "Plain text cannot be null or empty.";
					return result;
				}

				byte[] keyBytes;
				string? generatedKeyOutput = null;

				if (string.IsNullOrEmpty(base64Key))
				{
					keyBytes = RandomNumberGenerator.GetBytes(KeySizeBytes);
					generatedKeyOutput = Convert.ToBase64String(keyBytes);
				}
				else
				{
					try
					{
						keyBytes = Convert.FromBase64String(base64Key);
						if (keyBytes.Length != KeySizeBytes)
						{
							// Instead of: throw new ArgumentException(...)
							result.ErrorMessage = $"Encryption key must be {KeySizeBytes} bytes long (was {keyBytes.Length} bytes after Base64 decoding).";
							return result;
						}
					}
					catch (FormatException ex)
					{
						// Instead of: throw new ArgumentException(...)
						result.ErrorMessage = $"Encryption key is not a valid Base64 string: {ex.Message}";
						return result;
					}
				}

				byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
				byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
				byte[] tag = new byte[TagSizeBytes];
				byte[] cipherTextBytes = new byte[plainTextBytes.Length];

				using (var aesGcm = new AesGcm(keyBytes, TagSizeBytes))
				{
					aesGcm.Encrypt(nonce, plainTextBytes, cipherTextBytes, tag);
				}

				byte[] encryptedPayloadBytes = new byte[NonceSizeBytes + cipherTextBytes.Length + TagSizeBytes];
				Buffer.BlockCopy(nonce, 0, encryptedPayloadBytes, 0, NonceSizeBytes);
				Buffer.BlockCopy(cipherTextBytes, 0, encryptedPayloadBytes, NonceSizeBytes, cipherTextBytes.Length);
				Buffer.BlockCopy(tag, 0, encryptedPayloadBytes, NonceSizeBytes + cipherTextBytes.Length, TagSizeBytes);

				result.CipherText = Convert.ToBase64String(encryptedPayloadBytes);
				result.GeneratedKey = generatedKeyOutput;
			}
			catch (Exception ex) // Catch any other unexpected exceptions
			{
				result.ErrorMessage = $"An unexpected error occurred during encryption: {ex.Message}";
			}
			return result;
		}

		public DecryptionResult Decrypt(string base64EncryptedPayload, string base64Key)
		{
			var result = new DecryptionResult();
			try
			{
				if (string.IsNullOrEmpty(base64EncryptedPayload))
				{
					result.ErrorMessage = "Encrypted payload cannot be null or empty.";
					return result;
				}
				if (string.IsNullOrEmpty(base64Key))
				{
					result.ErrorMessage = "Decryption key cannot be null or empty.";
					return result;
				}

				byte[] keyBytes;
				try
				{
					keyBytes = Convert.FromBase64String(base64Key);
					if (keyBytes.Length != KeySizeBytes)
					{
						result.ErrorMessage = $"Decryption key must be {KeySizeBytes} bytes long (was {keyBytes.Length} bytes after Base64 decoding).";
						return result;
					}
				}
				catch (FormatException ex)
				{
					result.ErrorMessage = $"Decryption key is not a valid Base64 string: {ex.Message}";
					return result;
				}

				byte[] encryptedPayloadBytes;
				try
				{
					encryptedPayloadBytes = Convert.FromBase64String(base64EncryptedPayload);
				}
				catch (FormatException ex)
				{
					result.ErrorMessage = $"Encrypted payload is not a valid Base64 string: {ex.Message}";
					return result;
				}

				Console.WriteLine($"[Decrypt] Using key: {base64Key.Substring(0, Math.Min(8, base64Key.Length))}...");
				Console.WriteLine($"[Decrypt] Total encrypted payload length: {encryptedPayloadBytes.Length} bytes");

				if (encryptedPayloadBytes.Length < NonceSizeBytes + TagSizeBytes)
				{
					result.ErrorMessage = "Encrypted payload is too short to contain nonce and tag.";
					return result;
				}

				byte[] nonce = new byte[NonceSizeBytes];
				byte[] tag = new byte[TagSizeBytes];
				byte[] cipherTextBytes = new byte[encryptedPayloadBytes.Length - NonceSizeBytes - TagSizeBytes];

				Buffer.BlockCopy(encryptedPayloadBytes, 0, nonce, 0, NonceSizeBytes);
				Buffer.BlockCopy(encryptedPayloadBytes, NonceSizeBytes, cipherTextBytes, 0, cipherTextBytes.Length);
				Buffer.BlockCopy(encryptedPayloadBytes, NonceSizeBytes + cipherTextBytes.Length, tag, 0, TagSizeBytes);

				Console.WriteLine($"[Decrypt] Extracted Nonce length: {nonce.Length} bytes");
				Console.WriteLine($"[Decrypt] Extracted Ciphertext length: {cipherTextBytes.Length} bytes");
				Console.WriteLine($"[Decrypt] Extracted Tag length: {tag.Length} bytes");

				byte[] decryptedBytes = new byte[cipherTextBytes.Length];

				using (var aesGcm = new AesGcm(keyBytes, TagSizeBytes))
				{
					try
					{
						aesGcm.Decrypt(nonce, cipherTextBytes, tag, decryptedBytes);
						result.DecryptedText = Encoding.UTF8.GetString(decryptedBytes);
					}
					catch (AuthenticationTagMismatchException ex)
					{
						// This is a critical security-related failure.
						result.ErrorMessage = $"Decryption failed: Authentication tag mismatch. Data may be tampered or key is incorrect. ({ex.Message})";
						// Optionally log ex.ToString() for more details internally
					}
				}
			}
			catch (Exception ex) // Catch any other unexpected exceptions
			{
				Console.WriteLine($"[Decrypt] Unexpected error: {ex.ToString()}"); // Log the full error internally if desired
				result.ErrorMessage = $"An unexpected error occurred during decryption: {ex.Message}";
			}
			return result;
		}
	}
}
