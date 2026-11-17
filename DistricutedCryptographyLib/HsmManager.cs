﻿using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NBitcoin;

namespace DistricutedCryptographyLib
{

	using NBitcoin;

	namespace DistricutedCryptographyLib
	{
		/// <summary>
		/// The wallet HSM: one key per process (loaded when the wallet is opened, kept after it is closed) behind the REST
		/// service HSM/rest. Every operation needs the HSM API key, in one of two ways:
		///   - Bearer:  header "Authorization: Bearer &lt;api key&gt;"  (refused when RequireHmac is on);
		///   - HMAC:    headers X-HSM-Timestamp, X-HSM-Nonce, X-HSM-Signature, where the signature is
		///              hex(HMAC-SHA256(UTF8(api key), StringToSign)) and
		///              StringToSign = "DC-HSM-HMAC-SHA256\n" + operation + "\n" + timestamp + "\n" + nonce
		///                             + for each parameter, in the order of the operation: "\n" + hex(SHA256(UTF8(value))).
		///              The timestamp (Unix seconds) must be within 5 minutes of the HSM clock and a nonce is accepted once.
		/// The GeneXus procedures pass the request headers as "credentials", a JSON object
		/// {"authorization", "timestamp", "nonce", "signature"} (HSM.getCredentials).
		/// </summary>
		public class HsmManager
		{
			public const string HmacScheme = "DC-HSM-HMAC-SHA256";
			public const int MaxClockSkewSeconds = 300;
			const int MaxNonces = 100000;

			static HsmService? _singleton;
			static readonly object _accessLock = new object();
			static byte[]? _apiKey;              // UTF-8 bytes of the API key
			static byte[]? _apiKeyHash;          // SHA-256 of _apiKey, for the Bearer comparison
			static bool _requireHmac;
			static readonly Dictionary<string, long> _nonces = new Dictionary<string, long>(); // nonce -> expiry (Unix s)

			[ThreadStatic] static string? _lastError;

			/// <summary>A new random API key: 32 bytes as 64 lowercase hex characters.</summary>
			public static string NewApiKey()
			{
				return Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
			}

			public static bool Initialize(string extPrivKey, string networkType, string apiKey, bool requireHmac)
			{
				if (_singleton != null)
				{
					_lastError = "HSM already initialized";
					return false;
				}

				Network network;
				switch ((networkType ?? "").ToLower())
				{
					case "mainnet": network = Network.Main; break;
					case "testnet": network = Network.TestNet; break;
					case "regtest": network = Network.RegTest; break;
					default:
						_lastError = "Unknown network type";
						return false;
				}

				var service = new HsmService();
				if (!service.InitializeFromExtendedPrivateKey(extPrivKey, network))
				{
					_lastError = service.LastError;
					return false;
				}
				_singleton = service;
				SetAccess(apiKey, requireHmac);
				_lastError = "";
				return true;
			}

			/// <summary>Changes the API key or the HMAC option of the running HSM (Regenerate API key, HMAC option).</summary>
			public static bool SetAccess(string apiKey, bool requireHmac)
			{
				lock (_accessLock)
				{
					Wipe(_apiKey);
					Wipe(_apiKeyHash);
					if (string.IsNullOrEmpty(apiKey))
					{
						_apiKey = null;
						_apiKeyHash = null;
					}
					else
					{
						_apiKey = Encoding.UTF8.GetBytes(apiKey);
						_apiKeyHash = SHA256.HashData(_apiKey);
					}
					_requireHmac = requireHmac;
					_nonces.Clear();
				}
				return _singleton != null;
			}

			/// <summary>
			/// True when the running HSM is the one of the wallet whose API key this is. The HSM is one per process and every
			/// wallet has its own random key, so the HSM page of a wallet uses this before it changes or stops the running
			/// HSM (Regenerate API key, the HMAC option, Deactivate): the page of another wallet must not touch it.
			/// </summary>
			public static bool IsRunningWithApiKey(string apiKey)
			{
				if (string.IsNullOrEmpty(apiKey))
					return false;
				var hash = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey));
				lock (_accessLock)
				{
					return _singleton != null && _apiKeyHash != null && CryptographicOperations.FixedTimeEquals(hash, _apiKeyHash);
				}
			}

			public static bool IsActive()
			{
				return _singleton != null;
			}

			public static string GetPublicKey(string credentials, int index)
			{
				if (!Authorize(credentials, "getPubKey", index.ToString()))
					return "";

				return Result(_singleton!.GetDerivedPublicKey(index));
			}

			public static string Sign(string credentials, string message, int index)
			{
				if (!Authorize(credentials, "sign", message, index.ToString()))
					return "";
				if (string.IsNullOrEmpty(message))
				{
					_lastError = "Empty message";
					return "";
				}

				return Result(_singleton!.Sign(message, index));
			}

			public static string SignSchnorr(string credentials, string message, int index)
			{
				if (!Authorize(credentials, "SignSchnorr", message, index.ToString()))
					return "";
				if (string.IsNullOrEmpty(message))
				{
					_lastError = "Empty message";
					return "";
				}

				return Result(_singleton!.SignSchnorr(message, index));
			}

			public static string EncryptToPubKey(string credentials, string message, string recipientPubKey)
			{
				if (!Authorize(credentials, "encryptToPubKey", message, recipientPubKey))
					return "";
				if (string.IsNullOrEmpty(message) || string.IsNullOrEmpty(recipientPubKey))
				{
					_lastError = "Empty message or public key";
					return "";
				}

				return Result(_singleton!.EncryptToPubKey(message, recipientPubKey));
			}

			public static string Encrypt(string credentials, string message, int index)
			{
				if (!Authorize(credentials, "encrypt", message, index.ToString()))
					return "";
				if (string.IsNullOrEmpty(message))
				{
					_lastError = "Empty message";
					return "";
				}

				return Result(_singleton!.Encrypt(message, index));
			}

			public static string Decrypt(string credentials, string cipher, int index)
			{
				if (!Authorize(credentials, "decrypt", cipher, index.ToString()))
					return "";
				if (string.IsNullOrEmpty(cipher))
				{
					_lastError = "Empty message";
					return "";
				}

				return Result(_singleton!.Decrypt(cipher, index));
			}

			public static void Clear()
			{
				_singleton?.Clear();
				_singleton = null;
				SetAccess("", false);
			}

			public static string GetLastError()
			{
				return _lastError ?? "";
			}

			/// <summary>The text an HMAC client signs (exposed for the documentation and the tests).</summary>
			public static string StringToSign(string operation, string timestamp, string nonce, params string[] parameters)
			{
				var sb = new StringBuilder();
				sb.Append(HmacScheme).Append('\n').Append(operation).Append('\n').Append(timestamp).Append('\n').Append(nonce);
				foreach (var p in parameters)
				{
					sb.Append('\n').Append(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(p ?? ""))).ToLowerInvariant());
				}
				return sb.ToString();
			}

			static string Result(string? value)
			{
				value ??= "";
				_lastError = value.Length == 0 ? (_singleton?.LastError ?? "HSM not active") : "";
				return value;
			}

			// A caller without valid credentials always gets the same "Unauthorized": the reason stays out of the answer.
			static bool Authorize(string credentials, string operation, params string[] parameters)
			{
				_lastError = "";
				if (_singleton == null)
				{
					_lastError = "HSM not active";
					return false;
				}

				string authorization = "", timestamp = "", nonce = "", signature = "";
				try
				{
					if (!string.IsNullOrWhiteSpace(credentials))
					{
						using var doc = JsonDocument.Parse(credentials);
						authorization = Prop(doc.RootElement, "authorization");
						timestamp = Prop(doc.RootElement, "timestamp");
						nonce = Prop(doc.RootElement, "nonce");
						signature = Prop(doc.RootElement, "signature");
					}
				}
				catch (JsonException)
				{
					_lastError = "Unauthorized";
					return false;
				}

				lock (_accessLock)
				{
					bool ok = false;
					if (_apiKey != null && _apiKeyHash != null)
					{
						if (signature.Length > 0)
							ok = CheckHmac(operation, timestamp, nonce, signature, parameters);
						else if (!_requireHmac)
							ok = CheckBearer(authorization);
					}
					if (!ok)
						_lastError = "Unauthorized";
					return ok;
				}
			}

			static bool CheckBearer(string authorization)
			{
				const string prefix = "Bearer ";
				if (!authorization.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
					return false;
				byte[] given = SHA256.HashData(Encoding.UTF8.GetBytes(authorization.Substring(prefix.Length).Trim()));
				return CryptographicOperations.FixedTimeEquals(given, _apiKeyHash);
			}

			static bool CheckHmac(string operation, string timestamp, string nonce, string signature, string[] parameters)
			{
				if (!long.TryParse(timestamp, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long ts))
					return false;
				long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
				if (Math.Abs(now - ts) > MaxClockSkewSeconds)
					return false;
				if (nonce.Length < 16 || nonce.Length > 128)
					return false;
				foreach (char c in nonce)
				{
					if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_'))
						return false;
				}

				byte[] expected;
				using (var hmac = new HMACSHA256(_apiKey!))
				{
					expected = hmac.ComputeHash(Encoding.UTF8.GetBytes(StringToSign(operation, timestamp, nonce, parameters)));
				}
				byte[] given;
				try
				{
					given = Convert.FromHexString(signature);
				}
				catch (FormatException)
				{
					return false;
				}
				if (!CryptographicOperations.FixedTimeEquals(given, expected))
					return false;

				// A valid request is accepted once: its nonce is remembered until its timestamp leaves the window.
				foreach (var expired in ExpiredNonces(now))
					_nonces.Remove(expired);
				if (_nonces.ContainsKey(nonce) || _nonces.Count >= MaxNonces)
					return false;
				_nonces[nonce] = ts + MaxClockSkewSeconds;
				return true;
			}

			static List<string> ExpiredNonces(long now)
			{
				var list = new List<string>();
				foreach (var kv in _nonces)
				{
					if (kv.Value < now)
						list.Add(kv.Key);
				}
				return list;
			}

			static string Prop(JsonElement root, string name)
			{
				// Case-insensitive: the GeneXus SDT decides the case of the JSON names.
				if (root.ValueKind != JsonValueKind.Object)
					return "";
				foreach (var p in root.EnumerateObject())
				{
					if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.String)
						return (p.Value.GetString() ?? "").Trim();
				}
				return "";
			}

			static void Wipe(byte[]? data)
			{
				if (data != null)
					CryptographicOperations.ZeroMemory(data);
			}
		}
	}


}
