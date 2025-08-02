using NBitcoin;
using NBitcoin.DataEncoders;
using System;
using System.Security.Cryptography;
using System.Text;

namespace DistricutedCryptographyLib
{
	public class HsmService
	{
		private byte[] _encryptedKey;
		private byte[] _aesKey;
		private byte[] _aesIV;
		private bool _initialized = false;
		private string _lastError = "";
		private static readonly object _lock = new object();
		private Network _network;

		public string LastError
		{
			get
			{
				lock (_lock)
				{
					return _lastError;
				}
			}
		}

		public bool InitializeFromExtendedPrivateKey(string extPrivKey, Network network)
		{
			lock (_lock)
			{
				if (_initialized)
				{
					_lastError = "HSM already initialized";
					return false;
				}

				try
				{
					Console.WriteLine("init: " + extPrivKey);
					using (Aes aes = Aes.Create())
					{
						aes.GenerateKey();
						aes.GenerateIV();
						_aesKey = aes.Key;
						_aesIV = aes.IV;

						ICryptoTransform encryptor = aes.CreateEncryptor(_aesKey, _aesIV);
						byte[] keyBytes = Encoders.Base58.DecodeData(extPrivKey);
						_encryptedKey = encryptor.TransformFinalBlock(keyBytes, 0, keyBytes.Length);
					}

					_initialized = true;
					_lastError = "";
					_network = network;
					return true;
				}
				catch (Exception ex)
				{
					_lastError = $"Initialization failed: {ex.Message}";
					return false;
				}
			}
		}

		private ExtKey DecryptKey()
		{
			lock (_lock)
			{
				if (!_initialized)
					throw new InvalidOperationException("HSM not initialized");

				using (Aes aes = Aes.Create())
				{
					ICryptoTransform decryptor = aes.CreateDecryptor(_aesKey, _aesIV);
					byte[] decrypted = decryptor.TransformFinalBlock(_encryptedKey, 0, _encryptedKey.Length);
					string extKeyStr = Encoders.Base58.EncodeData(decrypted);
					return ExtKey.Parse(extKeyStr, _network);
				}
			}
		}


		public string GetDerivedPublicKey(int index)
		{
			try
			{
				ExtKey extKey = DecryptKey();
				_lastError = "";
				 return extKey.Derive((uint)index).PrivateKey.PubKey.ToString();
			}
			catch (Exception ex)
			{
				_lastError = $"GetDerivedPublicKey error: {ex.Message}";
				return "";
			}
		}

		public string Sign(string message, int index)
		{
			try
			{
				ExtKey extKey = DecryptKey();
				_lastError = "";

				var key = extKey.Derive((uint)index).PrivateKey;

				byte[] msgBytes = System.Text.Encoding.UTF8.GetBytes(message);
				uint256 msgHash = NBitcoin.Crypto.Hashes.DoubleSHA256(msgBytes);
				byte[] byteSignature = key.SignCompact(msgHash).Signature;
				return Encoders.Hex.EncodeData(byteSignature);
			}
			catch (Exception ex)
			{
				_lastError = $"Sign error: {ex.Message}";
				return "";
			}
		}

		public string SignSchnorr(string message, int index)
		{
			try
			{
				ExtKey extKey = DecryptKey();
				_lastError = "";

				var key = extKey.Derive((uint)index).PrivateKey;

				byte[] msgBytes = System.Text.Encoding.UTF8.GetBytes(message);
				uint256 msgHash = NBitcoin.Crypto.Hashes.DoubleSHA256(msgBytes);
				return key.SignTaprootKeySpend(msgHash).ToString();
			}
			catch (Exception ex)
			{
				_lastError = $"Sign error: {ex.Message}";
				return "";
			}
		}
		public string EncryptToPubKey(string message, string recipientPubKeyHex)
		{
			try
			{

				_lastError = "";
				byte[] bytes = Encoders.Hex.DecodeData(recipientPubKeyHex);
				PubKey publicKey = new NBitcoin.PubKey(bytes);

				return publicKey.Encrypt(message);
			}
			catch (Exception ex)
			{
				_lastError = $"Encrypt error: {ex.Message}";
				return "";
			}
		}

		public string? Encrypt(string message, int index)
		{
			try
			{
				ExtKey extKey = DecryptKey();
				_lastError = "";

				PubKey publicKey = extKey.Derive((uint)index).PrivateKey.PubKey;

				return publicKey.Encrypt(message);
			}
			catch (Exception ex)
			{
				_lastError = $"Sign error: {ex.Message}";
				return "";
			}

		}


		public string Decrypt(string payload, int index)
		{
			try
			{

				ExtKey extKey = DecryptKey();
				_lastError = "";

				var key = extKey.Derive((uint)index).PrivateKey;
				return key.Decrypt(payload);

			}
			catch (Exception ex)
			{
				_lastError = $"Decrypt error: {ex.Message}";
				return "";
			}
		}

		public void Clear()
		{
			lock (_lock)
			{
				_encryptedKey = null;
				_aesKey = null;
				_aesIV = null;
				_initialized = false;
				_lastError = "";
				GC.Collect();
			}
		}
	}

}
