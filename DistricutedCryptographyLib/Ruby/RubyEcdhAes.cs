using System.Security.Cryptography;
using NBitcoin;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// libwally's wally_aes_cbc_with_ecdh_key, which Ruby (and Jade) use to hand secrets to the host
	/// (get_utility_keys, get_bip85_bip39_entropy):
	///   secret   = SHA256(compressed ECDH point)            (secp256k1_ecdh default hash)
	///   keys     = HMAC-SHA512(key = secret, data = label)
	///   enc key  = keys[0..32], hmac key = keys[32..64]
	///   payload  = IV(16) || AES-256-CBC-PKCS7(plaintext) || HMAC-SHA256(hmac key, IV || ciphertext)
	/// </summary>
	public static class RubyEcdhAes
	{
		private const int BlockLen = 16;
		private const int HmacLen = 32;

		private static (byte[] encKey, byte[] hmacKey) DeriveKeys(Key privKey, PubKey pubKey, byte[] label)
		{
			if (label == null || label.Length == 0)
				throw new ArgumentException("A label is required", nameof(label));
			var shared = pubKey.GetSharedPubkey(privKey).ToBytes(); // compressed point
			var secret = SHA256.HashData(shared);
			var keys = HMACSHA512.HashData(secret, label);
			var encKey = keys[..32];
			var hmacKey = keys[32..];
			CryptographicOperations.ZeroMemory(shared);
			CryptographicOperations.ZeroMemory(secret);
			CryptographicOperations.ZeroMemory(keys);
			return (encKey, hmacKey);
		}

		public static byte[] Encrypt(Key privKey, PubKey pubKey, byte[] plaintext, byte[] label, byte[]? iv = null)
		{
			if (plaintext == null || plaintext.Length == 0)
				throw new ArgumentException("Nothing to encrypt", nameof(plaintext));
			iv ??= RandomNumberGenerator.GetBytes(BlockLen);
			if (iv.Length != BlockLen)
				throw new ArgumentException("The IV must be 16 bytes", nameof(iv));

			var (encKey, hmacKey) = DeriveKeys(privKey, pubKey, label);
			try
			{
				using var aes = Aes.Create();
				aes.Key = encKey;
				var cipher = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
				var output = new byte[BlockLen + cipher.Length + HmacLen];
				Buffer.BlockCopy(iv, 0, output, 0, BlockLen);
				Buffer.BlockCopy(cipher, 0, output, BlockLen, cipher.Length);
				var mac = HMACSHA256.HashData(hmacKey, output.AsSpan(0, BlockLen + cipher.Length));
				Buffer.BlockCopy(mac, 0, output, BlockLen + cipher.Length, HmacLen);
				return output;
			}
			finally
			{
				CryptographicOperations.ZeroMemory(encKey);
				CryptographicOperations.ZeroMemory(hmacKey);
			}
		}

		public static byte[] Decrypt(Key privKey, PubKey pubKey, byte[] payload, byte[] label)
		{
			if (payload == null || payload.Length < BlockLen + BlockLen + HmacLen
				|| (payload.Length - BlockLen - HmacLen) % BlockLen != 0)
				throw new CryptographicException("Invalid encrypted payload length");

			var (encKey, hmacKey) = DeriveKeys(privKey, pubKey, label);
			try
			{
				var macStart = payload.Length - HmacLen;
				var mac = HMACSHA256.HashData(hmacKey, payload.AsSpan(0, macStart));
				if (!CryptographicOperations.FixedTimeEquals(mac, payload.AsSpan(macStart, HmacLen)))
					throw new CryptographicException("Invalid HMAC: the data was not encrypted to this key or was altered");

				using var aes = Aes.Create();
				aes.Key = encKey;
				return aes.DecryptCbc(payload.AsSpan(BlockLen, macStart - BlockLen), payload.AsSpan(0, BlockLen),
					PaddingMode.PKCS7);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(encKey);
				CryptographicOperations.ZeroMemory(hmacKey);
			}
		}
	}
}
