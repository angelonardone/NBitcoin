using System.Security.Cryptography;
using NBitcoin;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// BIP85 child seeds ("hot wallets" of a Ruby wallet): from the master seed and an index, new independent
	/// BIP39 words. With Ruby the device computes them (get_bip85_bip39_entropy, confirmed on its screen) and hands
	/// only the entropy, encrypted to a one-time key of the host. The child words reveal nothing of the master.
	///
	///   path     m/83696968'/39'/{language}'/{words}'/{index}'     (language 0 = English)
	///   entropy  HMAC-SHA512(key = "bip-entropy-from-k", data = private key of that path), first 16 (12 words) or 32 (24 words) bytes
	/// </summary>
	public static class RubyBip85
	{
		// Label of the ECDH encryption of get_bip85_bip39_entropy (HMAC_BIP39_MESSAGE in the firmware).
		internal static readonly byte[] EcdhLabel = System.Text.Encoding.ASCII.GetBytes("bip85_bip39_entropy");

		private static readonly byte[] HmacKey = System.Text.Encoding.ASCII.GetBytes("bip-entropy-from-k");

		/// <summary>The largest BIP85 index (a hardened child index without its hardened bit).</summary>
		public const uint MaxIndex = 0x7FFFFFFF;

		public static void CheckParameters(int numWords, long index)
		{
			if (numWords != 12 && numWords != 24)
				throw new ArgumentException("A child seed has 12 or 24 words", nameof(numWords));
			if (index < 0 || index > MaxIndex)
				throw new ArgumentException($"The child index goes from 0 to {MaxIndex}", nameof(index));
		}

		public static KeyPath Path(int numWords, uint index) => new KeyPath($"83696968'/39'/0'/{numWords}'/{index}'");

		/// <summary>The software derivation: what Ruby computes, from the master extended private key.</summary>
		public static Mnemonic ChildMnemonic(ExtKey master, int numWords, uint index)
		{
			CheckParameters(numWords, index);
			var k = master.Derive(Path(numWords, index)).PrivateKey.ToBytes();
			var full = HMACSHA512.HashData(HmacKey, k);
			var entropy = full[..(numWords == 12 ? 16 : 32)];
			try
			{
				return new Mnemonic(Wordlist.English, entropy);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(k);
				CryptographicOperations.ZeroMemory(full);
				CryptographicOperations.ZeroMemory(entropy);
			}
		}

		/// <summary>The software derivation from the words of the master (no passphrase, as every Ruby wallet).</summary>
		public static Mnemonic ChildMnemonic(string masterMnemonic, int numWords, uint index) =>
			ChildMnemonic(new Mnemonic(masterMnemonic.Trim()).DeriveExtKey(), numWords, index);

		/// <summary>Decrypts the reply of get_bip85_bip39_entropy (the entropy, ECDH-encrypted to hostKey).</summary>
		internal static Mnemonic FromEncrypted(Key hostKey, PubKey devicePubKey, byte[] encrypted, int numWords)
		{
			var entropy = RubyEcdhAes.Decrypt(hostKey, devicePubKey, encrypted, EcdhLabel);
			try
			{
				var expected = numWords == 12 ? 16 : 32;
				if (entropy.Length != expected)
					throw new RubyException(0, $"Ruby returned {entropy.Length} bytes of child entropy, expected {expected}");
				return new Mnemonic(Wordlist.English, entropy);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(entropy);
			}
		}
	}
}
