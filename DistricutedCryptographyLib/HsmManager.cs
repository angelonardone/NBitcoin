using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NBitcoin;

namespace DistricutedCryptographyLib
{

	using NBitcoin;

	namespace DistricutedCryptographyLib
	{
		public class HsmManager
		{
			static HsmService _singleton;

			public static bool Initialize(string extPrivKey, string networkType)
			{
				if (_singleton != null)
				{
					return false;
				}

				Network network;
				switch (networkType.ToLower())
				{
					case "mainnet": network = Network.Main; break;
					case "testnet": network = Network.TestNet; break;
					case "regtest": network = Network.RegTest; break;
					default:
						return false;
				}

				_singleton = new HsmService();
				var ok = _singleton.InitializeFromExtendedPrivateKey(extPrivKey, network);
				if (!ok)
				{
					_singleton = null;
				}

				return ok;
			}

			public static string GetPublicKey(int index)
			{
				if (_singleton == null)
				{
					return "";
				}

				var pubKey = _singleton.GetDerivedPublicKey(index);

				return pubKey ?? "";
			}

			public static string Sign(string message, int index)
			{
				if (_singleton == null)
				{
					return "";
				}

				if (string.IsNullOrEmpty(message))
				{
					return "";
				}

				var sig = _singleton.Sign(message, index);

				return sig ?? "";
			}

			public static string SignSchnorr(string message, int index)
			{
				if (_singleton == null)
				{
					return "";
				}

				if (string.IsNullOrEmpty(message))
				{
					return "";
				}

				var sig = _singleton.SignSchnorr(message, index);

				return sig ?? "";
			}

			public static string EncryptToPubKey(string message, string recipientPubKey)
			{
				if (_singleton == null)
				{
					return "";
				}

				if (string.IsNullOrEmpty(message) || string.IsNullOrEmpty(recipientPubKey))
				{
					return "";
				}

				var result = _singleton.EncryptToPubKey(message, recipientPubKey);

				return result ?? "";
			}

			public static string Encrypt(string message, int index)
			{
				if (_singleton == null)
				{
					return "";
				}

				if (string.IsNullOrEmpty(message) )
				{
					return "";
				}

				var result = _singleton.Encrypt(message, index);

				return result ?? "";
			}
			public static string Decrypt(string cipher, int index)
			{
				if (_singleton == null)
				{
					return "";
				}

				if (string.IsNullOrEmpty(cipher))
				{
					return "";
				}

				var result = _singleton.Decrypt(cipher, index);

				return result ?? "";
			}

			public static void Clear()
			{
				_singleton?.Clear();
				_singleton = null;
			}

			public static string GetLastError()
			{

				return _singleton?.LastError ?? "HSM not initialized";

			}
		}
	}


}
