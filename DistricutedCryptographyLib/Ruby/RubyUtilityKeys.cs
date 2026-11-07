using System.Security.Cryptography;
using NBitcoin;
using NBitcoin.DataEncoders;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// The wallet "utility keys": hardened children of the BIP86 account m/86'/c'/0' used for everything except
	/// spending (login, chat, groups, local JSON files, file encryption, software HSM).
	///
	/// With Ruby they come from the device (get_utility_keys); without it, from the mnemonic. Both give the same keys,
	/// so a Ruby wallet restored from its words in a software wallet is the same wallet. Ruby wallets use no BIP39
	/// passphrase.
	/// </summary>
	public sealed class RubyUtilityKeys
	{
		// Same order as UTILITY_KEY_PATHS in Ruby main/process/get_utility_keys.c (the order of the decrypted keys).
		public static readonly string[] Paths = { "1000'/0'", "2000'/0'", "3000'/0'", "4000'/0'", "5000'/0'", "6000'" };

		public static readonly string[] Names = { "login", "chat", "groups", "jsonFiles", "fileEncryption", "hsm" };

		// Label of the ECDH encryption of get_utility_keys (HMAC_UTILITY_KEYS_MESSAGE in the firmware).
		internal static readonly byte[] EcdhLabel = System.Text.Encoding.ASCII.GetBytes("ruby_utility_keys");

		private const int SerializedLen = 78; // BIP32 serialized extended key

		/// <summary>The keys as extended private keys (xprv / tprv), in the order of Paths.</summary>
		public IReadOnlyList<string> ExtendedPrivateKeys { get; }

		public Network Network { get; }

		public string Login => ExtendedPrivateKeys[0];
		public string Chat => ExtendedPrivateKeys[1];
		public string Groups => ExtendedPrivateKeys[2];
		public string JsonFiles => ExtendedPrivateKeys[3];
		public string FileEncryption => ExtendedPrivateKeys[4];
		public string Hsm => ExtendedPrivateKeys[5];

		private RubyUtilityKeys(IReadOnlyList<string> keys, Network network)
		{
			ExtendedPrivateKeys = keys;
			Network = network;
		}

		/// <summary>The BIP86 account path of a network: m/86'/0'/0' on mainnet, m/86'/1'/0' otherwise.</summary>
		public static KeyPath AccountPath(Network network) =>
			new KeyPath(network.ChainName == ChainName.Mainnet ? "86'/0'/0'" : "86'/1'/0'");

		/// <summary>The software derivation, from the words (no passphrase): what a wallet without Ruby does.</summary>
		public static RubyUtilityKeys FromMnemonic(string mnemonic, Network network)
		{
			var master = new Mnemonic(mnemonic.Trim()).DeriveExtKey();
			return FromAccountKey(master.Derive(AccountPath(network)), network);
		}

		/// <summary>The software derivation from the BIP86 account extended private key.</summary>
		public static RubyUtilityKeys FromAccountKey(ExtKey account, Network network)
		{
			var keys = Paths.Select(p => account.Derive(new KeyPath(p)).GetWif(network).ToString()).ToList();
			return new RubyUtilityKeys(keys, network);
		}

		/// <summary>
		/// Decrypts the reply of get_utility_keys: 6 serialized keys of 78 bytes each, ECDH-encrypted to hostKey.
		/// Checks that each key is valid, of the network and a hardened child.
		/// </summary>
		internal static RubyUtilityKeys FromEncrypted(Key hostKey, PubKey devicePubKey, byte[] encrypted, Network network)
		{
			var plain = RubyEcdhAes.Decrypt(hostKey, devicePubKey, encrypted, EcdhLabel);
			try
			{
				if (plain.Length != Paths.Length * SerializedLen)
					throw new RubyException(0, $"Ruby returned {plain.Length} bytes of utility keys, expected {Paths.Length * SerializedLen}");

				var keys = new List<string>(Paths.Length);
				for (var i = 0; i < Paths.Length; i++)
				{
					var serialized = plain.AsSpan(i * SerializedLen, SerializedLen).ToArray();
					try
					{
						// bytes 9..12: child number, must be hardened
						if ((serialized[9] & 0x80) == 0)
							throw new RubyException(0, $"Ruby returned a non-hardened utility key ({Names[i]})");
						var text = Encoders.Base58Check.EncodeData(serialized);
						// throws if the version does not belong to the network or the key is invalid
						ExtKey.Parse(text, network);
						keys.Add(text);
					}
					finally
					{
						CryptographicOperations.ZeroMemory(serialized);
					}
				}
				return new RubyUtilityKeys(keys, network);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(plain);
			}
		}

		public bool SameAs(RubyUtilityKeys other) =>
			other != null && ExtendedPrivateKeys.SequenceEqual(other.ExtendedPrivateKeys);
	}
}
