using System.Text.Json;
using NBitcoin;
using NBitcoin.DataEncoders;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// External Object of the Ruby hardware key for GeneXus (same pattern as MuSig2Processor: texts, numbers and
	/// booleans in, JSON out, {"success": false, "error": "..."} on failure).
	///
	/// The connection to Ruby stays open between requests (one per device, in this process). `device` is a serial
	/// port ("COM5", "/dev/ttyUSB0") or "tcp:host:port" for the emulator. `networkType` is the wallet NetworkType
	/// ("MainNet", "TestNet", "RegTest").
	///
	/// A Ruby wallet keeps in its file the state of its blind oracle (RubyPinOracle), encrypted with an oracle key that
	/// lives inside the password-protected wallet secret. Every call that may ask the PIN returns the new encrypted
	/// state, also on errors: the wallet must save it again.
	/// </summary>
	public class RubyProcessor
	{
		private static readonly Dictionary<string, RubyClient> Clients = new(StringComparer.OrdinalIgnoreCase);
		private static readonly object ClientsLock = new();

		private static string Ok(object value) => JsonSerializer.Serialize(value);

		private static object? V(IDictionary<string, object?> map, string key) => map.TryGetValue(key, out var v) ? v : null;

		private static string Err(string message, string? encryptedOracle = null) => encryptedOracle == null
			? JsonSerializer.Serialize(new { success = false, error = message })
			: JsonSerializer.Serialize(new { success = false, error = message, encryptedOracle });

		// The open client of a device; a broken connection is dropped and opened again on the next call.
		private static T WithClient<T>(string device, Func<RubyClient, T> action)
		{
			device = (device ?? "").Trim();
			RubyClient client;
			lock (ClientsLock)
			{
				if (!Clients.TryGetValue(device, out client!))
				{
					client = RubyClient.Connect(device);
					Clients[device] = client;
				}
			}
			try
			{
				return action(client);
			}
			// a SocketException is not an IOException: without it a dead emulator connection was kept (2026-11-08)
			catch (Exception e) when (e is IOException or TimeoutException or ObjectDisposedException
				or UnauthorizedAccessException or System.Net.Sockets.SocketException)
			{
				Disconnect(device);
				throw;
			}
		}

		public static void Disconnect(string device)
		{
			lock (ClientsLock)
			{
				if (Clients.Remove((device ?? "").Trim(), out var client))
					client.Dispose();
			}
		}

		// ---------------------------------------------------------------- devices

		/// <summary>The serial ports where a Ruby answers: {"success", "devices": [{"device", "version", "state"}]}.</summary>
		public string FindDevices()
		{
			var found = new List<object>();
			foreach (var port in RubySerial.ListPorts())
			{
				try
				{
					using var client = new RubyClient(RubySerial.Open(port)) { TimeoutMs = 2000 };
					var info = client.GetVersionInfo();
					if (info.TryGetValue("JADE_VERSION", out var version))
						found.Add(new { device = port, version = Convert.ToString(version), state = Convert.ToString(V(info, "JADE_STATE")) });
				}
				catch (Exception)
				{
					// not a Ruby, busy or no answer
				}
			}
			return Ok(new { success = true, error = "", devices = found });
		}

		/// <summary>Connects and returns {"success", "version", "state" (UNINIT, LOCKED, READY, TEMP), "networks"}.</summary>
		public string Status(string device)
		{
			try
			{
				return WithClient(device, c =>
				{
					var info = c.GetVersionInfo();
					return Ok(new
					{
						success = true,
						error = "",
						version = Convert.ToString(V(info, "JADE_VERSION")),
						state = Convert.ToString(V(info, "JADE_STATE")),
						networks = Convert.ToString(V(info, "JADE_NETWORKS"))
					});
				});
			}
			catch (Exception e)
			{
				return Err(e.Message);
			}
		}

		public string Logout(string device)
		{
			try
			{
				return WithClient(device, c => Ok(new { success = c.Logout(), error = "" }));
			}
			catch (Exception e)
			{
				return Err(e.Message);
			}
		}

		// ---------------------------------------------------------------- oracle and PIN

		// The oracle state is kept in the wallet file as AES-256-GCM under a random "oracle key"; the oracle key travels
		// inside the wallet secret that the password protects (Argon2, ExtendeSecretAndAuthenticator.OracleKey). So
		// the state, which changes on every unlock, is saved again without a new Argon2 (seconds) each time, and its
		// clear text never reaches GeneXus. Format: base64(nonce(12) || ciphertext || tag(16)).
		private static readonly byte[] OracleAad = System.Text.Encoding.ASCII.GetBytes("distributedcryptography-ruby-oracle-v1");

		internal static string EncryptOracle(string oracleKey, RubyPinOracle oracle)
		{
			var key = Convert.FromBase64String(oracleKey);
			var plain = System.Text.Encoding.UTF8.GetBytes(oracle.ExportState());
			var nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(12);
			var cipher = new byte[plain.Length];
			var tag = new byte[16];
			using (var gcm = new System.Security.Cryptography.AesGcm(key, 16))
				gcm.Encrypt(nonce, plain, cipher, tag, OracleAad);
			System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain);
			System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
			return Convert.ToBase64String(nonce.Concat(cipher).Concat(tag).ToArray());
		}

		internal static RubyPinOracle DecryptOracle(string oracleKey, string encryptedOracle)
		{
			var key = Convert.FromBase64String(oracleKey);
			var data = Convert.FromBase64String(encryptedOracle);
			if (key.Length != 32 || data.Length < 12 + 16 + 1)
				throw new FormatException("Invalid oracle key or data");
			var plain = new byte[data.Length - 28];
			using (var gcm = new System.Security.Cryptography.AesGcm(key, 16))
				gcm.Decrypt(data.AsSpan(0, 12), data.AsSpan(12, plain.Length), data.AsSpan(12 + plain.Length), plain, OracleAad);
			System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
			try
			{
				return RubyPinOracle.FromState(System.Text.Encoding.UTF8.GetString(plain));
			}
			finally
			{
				System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain);
			}
		}

		/// <summary>
		/// A new blind oracle for a new Ruby wallet: {"success", "oracleKey" (to keep inside the password-protected
		/// wallet secret), "encryptedOracle" (to keep in the wallet file), "publicKey"}.
		/// </summary>
		public string CreateOracle()
		{
			var oracle = RubyPinOracle.Create();
			var oracleKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
			return Ok(new
			{
				success = true,
				error = "",
				oracleKey,
				encryptedOracle = EncryptOracle(oracleKey, oracle),
				publicKey = oracle.PublicKeyHex
			});
		}

		/// <summary>
		/// Pairs Ruby with the oracle of the wallet (before Ruby has a PIN). The wallet oracle is the default of Ruby:
		/// nothing is asked on the device.
		/// </summary>
		public string Pair(string device, string oracleKey, string encryptedOracle)
		{
			try
			{
				var oracle = DecryptOracle(oracleKey, encryptedOracle);
				return WithClient(device, c => Ok(new { success = c.PairWalletOracle(oracle.PublicKey), error = "" }));
			}
			catch (Exception e)
			{
				return Err(e.Message);
			}
		}

		/// <summary>
		/// Unlocks Ruby: the user enters the PIN on Ruby and the oracle of the wallet answers. On a Ruby without a
		/// wallet, Ruby first guides the user to create or restore one and to choose the PIN.
		/// Returns {"success", "unlocked" (false = wrong PIN), "oracleResult", "state", "encryptedOracle"}: the new
		/// encrypted oracle state, returned also on errors, that the wallet must save in its file.
		/// </summary>
		public string Unlock(string device, string networkType, string oracleKey, string encryptedOracle)
		{
			RubyPinOracle oracle;
			try
			{
				oracle = DecryptOracle(oracleKey, encryptedOracle);
			}
			catch (Exception e)
			{
				return Err("Invalid oracle state: " + e.Message);
			}
			try
			{
				return WithClient(device, c =>
				{
					c.PinOracle = oracle.HandleRequest;
					try
					{
						var unlocked = c.AuthUser(RubyClient.ToNetwork(networkType));
						var state = Convert.ToString(V(c.GetVersionInfo(), "JADE_STATE"));
						return Ok(new
						{
							success = true,
							error = "",
							unlocked,
							oracleResult = oracle.LastResult,
							state,
							encryptedOracle = EncryptOracle(oracleKey, oracle)
						});
					}
					finally
					{
						c.PinOracle = null;
					}
				});
			}
			catch (Exception e)
			{
				return Err(e.Message, EncryptOracle(oracleKey, oracle));
			}
		}

		// ---------------------------------------------------------------- keys

		/// <summary>
		/// The public side of the wallet: {"success", "fingerprint", "account" (ExtKeyInfo JSON of m/86'/c'/0', public
		/// fields only), "bip48" (ExtKeyInfo JSON of m/48'/c'/0'/1', public fields only)}.
		/// </summary>
		public string GetPublicInfo(string device, string networkType)
		{
			try
			{
				var network = RubyClient.ToNetwork(networkType);
				return WithClient(device, c =>
				{
					var coin = network.ChainName == ChainName.Mainnet ? "0'" : "1'";
					var accountPath = "m/86'/" + coin + "/0'";
					var bip48Path = "m/48'/" + coin + "/0'/1'";
					var account = ExtPubKey.Parse(c.GetXpub(network, KeyPath.Parse(accountPath)), network);
					var bip48 = ExtPubKey.Parse(c.GetXpub(network, KeyPath.Parse(bip48Path)), network);
					return Ok(new
					{
						success = true,
						error = "",
						fingerprint = c.GetMasterFingerprint(network).ToString(),
						account = PublicExtKeyInfo(account, accountPath, network),
						bip48 = PublicExtKeyInfo(bip48, bip48Path, network)
					});
				});
			}
			catch (Exception e)
			{
				return Err(e.Message);
			}
		}

		// The public fields of the GeneXus SDT ExtKeyInfo, as NBitcoin.CreateExtKey fills them (the private ones empty,
		// as after Wallet.cleanPrivateKeys).
		private static object PublicExtKeyInfo(ExtPubKey xpub, string keyPath, Network network)
		{
			string Versioned(byte[] main, byte[] test)
			{
				var data = xpub.ToBytes();
				var version = network.ChainName == ChainName.Mainnet ? main : test;
				return Encoders.Base58Check.EncodeData(version.Concat(data).ToArray());
			}
			var xpubText = xpub.ToString(network);
			return new
			{
				PrivateKey = "",
				PublicKey = xpub.PubKey.ToString(),
				ChainCode = "",
				Mnemonic = "",
				WIF = "",
				encryptedWIF = "",
				Extended = new
				{
					PrivateKey = "",
					PrivateKeySegwitP2SH = "",
					PrivateKeySegwit = "",
					PrivateKeyTaproot = "",
					NuterPublicKey = xpubText,
					NuterPublicKeySegwitP2SH = Versioned(new byte[] { 0x04, 0x9D, 0x7C, 0xB2 }, new byte[] { 0x04, 0x4A, 0x52, 0x62 }),
					NuterPublicKeySegwit = Versioned(new byte[] { 0x04, 0xB2, 0x47, 0x46 }, new byte[] { 0x04, 0x5F, 0x1C, 0xF6 }),
					NuterPublicKeyTaproot = xpubText,
					Fingerprint = xpub.PubKey.GetHDFingerPrint().ToString(),
					ParentFingerprint = xpub.ParentFingerprint.ToString(),
					Depth = (int)xpub.Depth,
					Child = (long)xpub.Child,
					isHardended = xpub.IsHardened,
					keyPath
				}
			};
		}

		/// <summary>
		/// The utility keys of the wallet (handed without asking, after the PIN): {"success", "login", "chat", "groups",
		/// "jsonFiles", "fileEncryption", "hsm"} as extended private keys (xprv / tprv) of 1000'/0', 2000'/0',
		/// 3000'/0', 4000'/0', 5000'/0' and 6000' of the BIP86 account: the same keys a software wallet derives.
		/// </summary>
		public string GetUtilityKeys(string device, string networkType)
		{
			try
			{
				return WithClient(device, c =>
				{
					var keys = c.GetUtilityKeys(RubyClient.ToNetwork(networkType));
					return Ok(new
					{
						success = true,
						error = "",
						login = keys.Login,
						chat = keys.Chat,
						groups = keys.Groups,
						jsonFiles = keys.JsonFiles,
						fileEncryption = keys.FileEncryption,
						hsm = keys.Hsm
					});
				});
			}
			catch (Exception e)
			{
				return Err(e.Message);
			}
		}

		// ---------------------------------------------------------------- signing

		private sealed class InputDto
		{
			public string TxHex { get; set; } = "";
			public int Vout { get; set; }
			public int Chain { get; set; } // 0 receiving, 1 change (AddressGeneratedType)
			public int Index { get; set; } // AddressCreationSequence
		}

		/// <summary>
		/// Builds the payment as Wallet.buildTransaction does, but without keys: a PSBT with the BIP86 key paths of
		/// our inputs (and of the change, when changeIndex >= 0) that Ruby signs after the user checks it on its screen.
		/// inputsJson: [{"TxHex", "Vout", "Chain", "Index"}]. sendAll: the fee is taken from amountBtc and there is no
		/// change. Returns {"success", "hexTransaction", "virtualSize"}.
		/// </summary>
		public string SignTransaction(string device, string networkType, string inputsJson, string sendTo,
			string amountBtc, string changeTo, int changeChain, int changeIndex, string feeBtc, bool sendAll)
		{
			try
			{
				var network = RubyClient.ToNetwork(networkType);
				var inputs = JsonSerializer.Deserialize<List<InputDto>>(inputsJson, DelegatedMultiSigSpend.JsonIn)
					?? throw new FormatException("No inputs");
				if (inputs.Count == 0)
					throw new FormatException("No inputs");
				var fee = Money.Coins(DelegatedMultiSigSpend.ParseDec(feeBtc));
				var amount = Money.Coins(DelegatedMultiSigSpend.ParseDec(amountBtc));
				if (sendAll)
					amount -= fee;

				return WithClient(device, c =>
				{
					var fingerprint = c.GetMasterFingerprint(network);
					var accountPath = RubyUtilityKeys.AccountPath(network);
					var account = c.GetAccountXpub(network);

					var coins = new List<Coin>();
					var paths = new List<(PubKey pub, KeyPath path)>();
					foreach (var input in inputs)
					{
						var tx = Transaction.Parse(input.TxHex, network);
						var coin = new Coin(tx, (uint)input.Vout);
						var path = new KeyPath((uint)input.Chain, (uint)input.Index);
						var pub = account.Derive(path).PubKey;
						if (pub.GetScriptPubKey(ScriptPubKeyType.TaprootBIP86) != coin.ScriptPubKey)
							throw new InvalidOperationException(
								$"The coin {tx.GetHash()}:{input.Vout} is not of this Ruby wallet at {input.Chain}/{input.Index}");
						coins.Add(coin);
						paths.Add((pub, path));
					}

					var builder = network.CreateTransactionBuilder();
					builder.AddCoins(coins)
						.Send(BitcoinAddress.Create(sendTo, network), amount)
						.SendFees(fee);
					if (!sendAll)
					{
						var change = BitcoinAddress.Create(changeTo, network);
						builder.SetChange(change);
						if (changeIndex >= 0)
						{
							var path = new KeyPath((uint)changeChain, (uint)changeIndex);
							var pub = account.Derive(path).PubKey;
							if (pub.GetScriptPubKey(ScriptPubKeyType.TaprootBIP86) != change.ScriptPubKey)
								throw new InvalidOperationException("The change address is not of this Ruby wallet");
							paths.Add((pub, path));
						}
					}
					var psbt = builder.BuildPSBT(false);
					foreach (var (pub, path) in paths)
						RubyPsbt.AddBip86KeyPath(psbt, pub, new RootedKeyPath(fingerprint, accountPath.Derive(path)));

					var signed = c.SignPsbt(psbt);
					if (!signed.TryFinalize(out var errors))
						throw new InvalidOperationException("Ruby did not sign every input: " + string.Join("; ", errors));
					var final = signed.ExtractTransaction();
					if (final.GetHash() != psbt.GetGlobalTransaction().GetHash())
						throw new InvalidOperationException("Ruby returned a different transaction");
					if (!builder.Verify(final, out var policyErrors))
						throw new InvalidOperationException("Transaction is not Verified: " + string.Join("; ", policyErrors.Select(p => p.ToString())));
					return Ok(new { success = true, error = "", hexTransaction = final.ToHex(), virtualSize = final.GetVirtualSize() });
				});
			}
			catch (RubyException e) when (e.Code == RubyException.UserCancelled)
			{
				return Err("The payment was declined on Ruby");
			}
			catch (Exception e)
			{
				return Err(e.Message);
			}
		}
	}
}
