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
	/// A Ruby wallet keeps in its file, encrypted with the wallet password, the state of its blind oracle
	/// (RubyPinOracle). Every call that may ask the PIN returns the new oracle state, also on errors: the wallet must
	/// save it again.
	/// </summary>
	public class RubyProcessor
	{
		// Ruby only passes the oracle URL back in its requests (the oracle runs in this process); it must be http(s).
		public const string OracleUrl = "http://oracle.distributedcryptography.local";

		private static readonly Dictionary<string, RubyClient> Clients = new(StringComparer.OrdinalIgnoreCase);
		private static readonly object ClientsLock = new();

		private static string Ok(object value) => JsonSerializer.Serialize(value);

		private static object? V(IDictionary<string, object?> map, string key) => map.TryGetValue(key, out var v) ? v : null;

		private static string Err(string message, string? oracleState = null) => oracleState == null
			? JsonSerializer.Serialize(new { success = false, error = message })
			: JsonSerializer.Serialize(new { success = false, error = message, oracleState });

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
			catch (Exception e) when (e is IOException or TimeoutException or ObjectDisposedException
				or UnauthorizedAccessException)
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
			foreach (var port in RubySerialTransport.ListPorts())
			{
				try
				{
					using var client = new RubyClient(new RubySerialTransport(port)) { TimeoutMs = 2000 };
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

		/// <summary>A new blind oracle for a new Ruby wallet: {"success", "oracleState", "publicKey"}.</summary>
		public string CreateOracle()
		{
			var oracle = RubyPinOracle.Create();
			return Ok(new { success = true, error = "", oracleState = oracle.ExportState(), publicKey = oracle.PublicKeyHex });
		}

		/// <summary>Pairs Ruby with the oracle of the wallet (before Ruby has a PIN). The user confirms on Ruby.</summary>
		public string Pair(string device, string oracleState)
		{
			try
			{
				var oracle = RubyPinOracle.FromState(oracleState);
				return WithClient(device, c => Ok(new { success = c.UpdatePinServer(OracleUrl, oracle.PublicKey), error = "" }));
			}
			catch (Exception e)
			{
				return Err(e.Message);
			}
		}

		/// <summary>
		/// Unlocks Ruby: the user enters the PIN on Ruby and the oracle of the wallet answers. On a Ruby without a
		/// wallet, Ruby first guides the user to create or restore one and to choose the PIN.
		/// Returns {"success", "unlocked" (false = wrong PIN), "oracleResult", "state", "oracleState"}; the oracle
		/// state is returned also on errors and must be saved.
		/// </summary>
		public string Unlock(string device, string networkType, string oracleState)
		{
			RubyPinOracle oracle;
			try
			{
				oracle = RubyPinOracle.FromState(oracleState);
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
							oracleState = oracle.ExportState()
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
				return Err(e.Message, oracle.ExportState());
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
		/// The utility keys of the wallet (Ruby asks the user to confirm): {"success", "login", "chat", "groups",
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
