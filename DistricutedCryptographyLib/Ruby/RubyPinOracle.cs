using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NBitcoin;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// The blind PIN oracle of a Ruby, running inside the wallet (docs/ideas-roadmap.md §12.2).
	///
	/// A C# port of Blockstream's blind_pin_server (pinserver/server.py PINServerECDHv2 + pindb.py PINDb), protocol
	/// v2. Ruby keeps its seed encrypted with a key that needs the PIN AND a secret held here; this oracle never sees
	/// the PIN nor the seed, and forgets its secret after 3 wrong PINs.
	///
	/// - Pairing: RubyClient.PairWalletOracle(PublicKey) before Ruby has a PIN (Ruby refuses to change the oracle
	///   key of an initialized unit). The wallet oracle is the default of Ruby: nothing is asked on the device.
	/// - Use: client.PinOracle = oracle.HandleRequest; then every auth_user that needs the PIN is answered here.
	/// - State: ExportState() (JSON: the oracle private key + one record per device). It changes on EVERY answer
	///   (attempt counter, anti-replay counter), so the wallet must save it again after each unlock, encrypted with
	///   the wallet password as the rest of the wallet. Records are byte-compatible with pindb.py.
	/// </summary>
	public sealed class RubyPinOracle
	{
		private const int StateVersion = 1;
		private const int Sha256Len = 32;
		private const int RecoverableSigLen = 65;
		private const int ReplayCounterLen = 4;
		private const byte RecordVersion = 1; // pindb VERSION_LATEST (records with replay counter)
		private const int RecordLen = 129;

		private static readonly byte[] LabelRequest = Encoding.ASCII.GetBytes("blind_oracle_request");
		private static readonly byte[] LabelResponse = Encoding.ASCII.GetBytes("blind_oracle_response");

		private static readonly BigInteger CurveOrder = BigInteger.Parse(
			"0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			System.Globalization.NumberStyles.HexNumber);

		private readonly object _sync = new object();
		private readonly Key _serverKey;
		private readonly byte[] _aesPinDataKey;
		private readonly Dictionary<string, byte[]> _records; // hex(sha256(pin pubkey)) -> pindb record

		/// <summary>What the last request did (for logs and screens): set_pin, get_pin, bad_pin 1/3 ... erased.</summary>
		public string LastResult { get; private set; } = "";

		/// <summary>The oracle public key (33 bytes) that Ruby must be paired with.</summary>
		public byte[] PublicKey => _serverKey.PubKey.ToBytes();

		public string PublicKeyHex => Convert.ToHexString(PublicKey).ToLowerInvariant();

		/// <summary>Number of devices with a PIN record (normally 0 before pairing, 1 after).</summary>
		public int RecordCount
		{
			get
			{
				lock (_sync)
					return _records.Count;
			}
		}

		private RubyPinOracle(Key serverKey, Dictionary<string, byte[]> records)
		{
			_serverKey = serverKey;
			_aesPinDataKey = HMACSHA256.HashData(serverKey.ToBytes(), "pin_data"u8);
			_records = records;
		}

		public static RubyPinOracle Create() => new RubyPinOracle(new Key(), new Dictionary<string, byte[]>());

		public static RubyPinOracle FromPrivateKey(byte[] privateKey) =>
			new RubyPinOracle(new Key(privateKey), new Dictionary<string, byte[]>());

		// ---------------------------------------------------------------- state

		private sealed class StateDto
		{
			public int Version { get; set; }
			public string Key { get; set; } = "";
			public Dictionary<string, string> Records { get; set; } = new();
		}

		public string ExportState()
		{
			lock (_sync)
			{
				return JsonSerializer.Serialize(new StateDto
				{
					Version = StateVersion,
					Key = Convert.ToHexString(_serverKey.ToBytes()).ToLowerInvariant(),
					Records = _records.ToDictionary(r => r.Key, r => Convert.ToHexString(r.Value).ToLowerInvariant())
				});
			}
		}

		public static RubyPinOracle FromState(string json)
		{
			var dto = JsonSerializer.Deserialize<StateDto>(json, DelegatedMultiSigSpend.JsonIn)
				?? throw new FormatException("Empty oracle state");
			if (dto.Version != StateVersion)
				throw new FormatException($"Unknown oracle state version {dto.Version}");
			var records = new Dictionary<string, byte[]>();
			foreach (var r in dto.Records ?? new())
			{
				var record = Convert.FromHexString(r.Value);
				if (record.Length != RecordLen || Convert.FromHexString(r.Key).Length != Sha256Len)
					throw new FormatException("Invalid oracle record");
				records[r.Key.ToLowerInvariant()] = record;
			}
			return new RubyPinOracle(new Key(Convert.FromHexString(dto.Key)), records);
		}

		// ---------------------------------------------------------------- request

		/// <summary>
		/// Answers an http_request of Ruby (its "params": urls ending in /set_pin or /get_pin, data = {"data":
		/// base64(cke || replay counter || encrypted payload)}) and returns the body for the "pin" reply:
		/// {"data": base64(encrypted aes key)}. A wrong PIN gets a random key, as in pindb (Ruby then fails to decrypt
		/// its seed and counts the attempt). Throws on a malformed request.
		/// </summary>
		public object? HandleRequest(IDictionary<string, object?> httpParams)
		{
			var url = httpParams.TryGetValue("urls", out var u) && u is List<object?> urls && urls.Count > 0
				? urls[0] as string ?? "" : "";
			var document = url.TrimEnd('/');
			document = document[(document.LastIndexOf('/') + 1)..];
			if (document != "set_pin" && document != "get_pin")
				throw new RubyException(RubyException.ProtocolError, $"Unexpected oracle request '{url}'");

			var base64 = ExtractData(httpParams.TryGetValue("data", out var d) ? d : null);
			var encryptedKey = Handle(document == "set_pin", Convert.FromBase64String(base64));
			return new Dictionary<string, object?> { ["data"] = Convert.ToBase64String(encryptedKey) };
		}

		private static string ExtractData(object? data)
		{
			switch (data)
			{
				case IDictionary<string, object?> map when map.TryGetValue("data", out var inner) && inner is string s:
					return s;
				case string json:
					using (var doc = JsonDocument.Parse(json))
						return doc.RootElement.GetProperty("data").GetString() ?? "";
				default:
					throw new RubyException(RubyException.ProtocolError, "Oracle request without data");
			}
		}

		/// <summary>The v2 call: raw request bytes in, encrypted response (96 bytes) out.</summary>
		public byte[] Handle(bool setPin, byte[] request)
		{
			if (request.Length <= 33 + ReplayCounterLen)
				throw new RubyException(RubyException.ProtocolError, "Oracle request too short");
			var cke = new PubKey(request[..33]);
			var replayCounter = request[33..37];
			var encrypted = request[37..];

			lock (_sync)
			{
				using var sessionKey = SessionKey(cke.ToBytes(), replayCounter);
				var payload = RubyEcdhAes.Decrypt(sessionKey, cke, encrypted, LabelRequest);
				byte[] aesKey;
				try
				{
					aesKey = setPin
						? SetPin(cke.ToBytes(), payload, replayCounter)
						: GetAesKey(cke.ToBytes(), payload, replayCounter);
				}
				finally
				{
					CryptographicOperations.ZeroMemory(payload);
				}
				try
				{
					return RubyEcdhAes.Encrypt(sessionKey, cke, aesKey, LabelResponse);
				}
				finally
				{
					CryptographicOperations.ZeroMemory(aesKey);
				}
			}
		}

		// The per-request server key: the static key BIP341-tweaked with sha256(hmac_sha256(cke, replay counter)) as
		// the "merkle root" (server.py PINServerECDHv2.generate_ec_key_pair, wally ec_private_key_bip341_tweak).
		private Key SessionKey(byte[] cke, byte[] replayCounter)
		{
			var merkle = SHA256.HashData(HMACSHA256.HashData(cke, replayCounter));
			return Bip341TweakPrivate(_serverKey, merkle);
		}

		/// <summary>The session public key Ruby computes for a request (for tests and for a software client).</summary>
		public static PubKey SessionPublicKey(byte[] serverPublicKey, byte[] cke, byte[] replayCounter)
		{
			var merkle = SHA256.HashData(HMACSHA256.HashData(cke, replayCounter));
			var full = new PubKey(serverPublicKey).TaprootInternalKey.GetTaprootFullPubKey(new uint256(merkle));
			var compressed = new byte[33];
			compressed[0] = full.OutputKeyParity ? (byte)0x03 : (byte)0x02;
			full.ToBytes().CopyTo(compressed, 1);
			return new PubKey(compressed);
		}

		internal static Key Bip341TweakPrivate(Key key, byte[] merkleRoot32)
		{
			var xonly = key.PubKey.TaprootInternalKey.ToBytes();
			var tagHash = SHA256.HashData("TapTweak"u8);
			var tweak = SHA256.HashData(tagHash.Concat(tagHash).Concat(xonly).Concat(merkleRoot32).ToArray());

			var d = new BigInteger(key.ToBytes(), isUnsigned: true, isBigEndian: true);
			if (key.PubKey.ToBytes()[0] == 0x03) // odd y: BIP340 uses the negated key
				d = CurveOrder - d;
			var t = new BigInteger(tweak, isUnsigned: true, isBigEndian: true);
			if (t >= CurveOrder)
				throw new CryptographicException("Invalid tweak");
			var tweaked = (d + t) % CurveOrder;
			if (tweaked.IsZero)
				throw new CryptographicException("Invalid tweaked key");

			var bytes = new byte[32];
			var raw = tweaked.ToByteArray(isUnsigned: true, isBigEndian: true);
			raw.CopyTo(bytes, 32 - raw.Length);
			try
			{
				return new Key(bytes);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(bytes);
				CryptographicOperations.ZeroMemory(raw);
			}
		}

		// ---------------------------------------------------------------- pindb

		// pin_secret(32) + [entropy(32)] + recoverable sig(65); the sig is over sha256(cke + replay + secret + entropy)
		// and identifies the device (its "pin pubkey").
		private static (byte[] pinSecret, byte[] entropy, byte[] pinPubKey) ExtractFields(byte[] cke, byte[] data,
			byte[] replayCounter)
		{
			byte[] entropy, sig;
			if (data.Length == Sha256Len + Sha256Len + RecoverableSigLen)
			{
				entropy = data[Sha256Len..(2 * Sha256Len)];
				sig = data[(2 * Sha256Len)..];
			}
			else if (data.Length == Sha256Len + RecoverableSigLen)
			{
				entropy = Array.Empty<byte>();
				sig = data[Sha256Len..];
			}
			else
			{
				throw new RubyException(RubyException.ProtocolError, "Invalid oracle payload length");
			}
			var pinSecret = data[..Sha256Len];

			var signedMsg = SHA256.HashData(cke.Concat(replayCounter).Concat(pinSecret).Concat(entropy).ToArray());
			// wally recoverable signature: header 27 + 4 (compressed) + recid, then r || s
			var recId = sig[0] - 31;
			if (recId < 0 || recId > 3)
				throw new RubyException(RubyException.ProtocolError, "Invalid oracle signature");
			var pub = NBitcoin.PubKey.RecoverCompact(new uint256(signedMsg), new CompactSignature(recId, sig[1..]));
			return (pinSecret, entropy, pub.ToBytes());
		}

		private static uint CounterValue(byte[] counter) => BitConverter.ToUInt32(
			BitConverter.IsLittleEndian ? counter : counter.Reverse().ToArray());

		private void SaveRecord(byte[] pinPubKeyHash, byte[] hashPinSecret, byte[] aesKey, byte[] pinPubKey, byte count,
			byte[] replayCounter)
		{
			var storageAesKey = HMACSHA256.HashData(_aesPinDataKey, pinPubKey);
			var plaintext = hashPinSecret.Concat(aesKey).Append(count).Concat(replayCounter).ToArray(); // 69 bytes
			var iv = RandomNumberGenerator.GetBytes(16);
			byte[] encrypted;
			using (var aes = Aes.Create())
			{
				aes.Key = storageAesKey;
				encrypted = iv.Concat(aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7)).ToArray(); // 96 bytes
			}
			CryptographicOperations.ZeroMemory(plaintext);
			CryptographicOperations.ZeroMemory(storageAesKey);

			var pinAuthKey = HMACSHA256.HashData(_aesPinDataKey, pinPubKeyHash);
			var versioned = new[] { RecordVersion }.Concat(encrypted).ToArray();
			var hmac = HMACSHA256.HashData(pinAuthKey, versioned);
			_records[Convert.ToHexString(pinPubKeyHash).ToLowerInvariant()] =
				new[] { RecordVersion }.Concat(hmac).Concat(encrypted).ToArray();
		}

		private (byte[] hashPinSecret, byte[] aesKey, byte count, byte[] replayCounter)? LoadRecord(byte[] pinPubKeyHash,
			byte[] pinPubKey)
		{
			if (!_records.TryGetValue(Convert.ToHexString(pinPubKeyHash).ToLowerInvariant(), out var data))
				return null;
			if (data.Length != RecordLen || data[0] != RecordVersion)
				throw new CryptographicException("Invalid oracle record");

			var pinAuthKey = HMACSHA256.HashData(_aesPinDataKey, pinPubKeyHash);
			var hmac = HMACSHA256.HashData(pinAuthKey, data.AsSpan(33).ToArray().Prepend(data[0]).ToArray());
			if (!CryptographicOperations.FixedTimeEquals(hmac, data.AsSpan(1, 32)))
				throw new CryptographicException("Oracle record altered");

			var storageAesKey = HMACSHA256.HashData(_aesPinDataKey, pinPubKey);
			byte[] plaintext;
			using (var aes = Aes.Create())
			{
				aes.Key = storageAesKey;
				plaintext = aes.DecryptCbc(data.AsSpan(49), data.AsSpan(33, 16), PaddingMode.PKCS7);
			}
			CryptographicOperations.ZeroMemory(storageAesKey);
			if (plaintext.Length != 69)
				throw new CryptographicException("Invalid oracle record");
			var result = (plaintext[..32], plaintext[32..64], plaintext[64], plaintext[65..69]);
			CryptographicOperations.ZeroMemory(plaintext);
			return result;
		}

		private static void CheckAntiReplay(byte[] stored, byte[] client)
		{
			if (CounterValue(client) <= CounterValue(stored))
				throw new RubyException(RubyException.ProtocolError, "Oracle replay counter not increasing");
		}

		// pindb.get_aes_key: the saved key for a right PIN, a random one otherwise; 3 wrong PINs erase the record
		private byte[] GetAesKey(byte[] cke, byte[] payload, byte[] replayCounter)
		{
			var (pinSecret, _, pinPubKey) = ExtractFields(cke, payload, replayCounter);
			byte[] savedKey;
			try
			{
				savedKey = GetAesKeyImpl(pinPubKey, pinSecret, replayCounter);
			}
			catch (Exception e) when (e is RubyException or CryptographicException)
			{
				// GetAesKeyImpl sets LastResult before throwing for a wrong PIN; anything else is a rejection
				if (LastResult.Length == 0)
					LastResult = "rejected: " + e.Message;
				savedKey = RandomNumberGenerator.GetBytes(32);
			}
			var clientKey = HMACSHA256.HashData(savedKey, pinSecret);
			CryptographicOperations.ZeroMemory(savedKey);
			CryptographicOperations.ZeroMemory(pinSecret);
			return clientKey;
		}

		private byte[] GetAesKeyImpl(byte[] pinPubKey, byte[] pinSecret, byte[] replayCounter)
		{
			LastResult = "";
			var pinPubKeyHash = SHA256.HashData(pinPubKey);
			var record = LoadRecord(pinPubKeyHash, pinPubKey)
				?? throw new RubyException(RubyException.ProtocolError, "No PIN record for this device");
			var (savedHps, savedKey, count, replayLocal) = record;
			CheckAntiReplay(replayLocal, replayCounter);

			if (CryptographicOperations.FixedTimeEquals(savedHps, SHA256.HashData(pinSecret)))
			{
				SaveRecord(pinPubKeyHash, savedHps, savedKey, pinPubKey, 0, replayCounter);
				LastResult = "get_pin";
				return savedKey;
			}

			if (count >= 2)
			{
				_records.Remove(Convert.ToHexString(pinPubKeyHash).ToLowerInvariant());
				CryptographicOperations.ZeroMemory(savedKey);
				LastResult = "erased";
				throw new RubyException(RubyException.ProtocolError, "Too many attempts");
			}
			SaveRecord(pinPubKeyHash, savedHps, savedKey, pinPubKey, (byte)(count + 1), replayCounter);
			CryptographicOperations.ZeroMemory(savedKey);
			LastResult = $"bad_pin {count + 1}/3";
			throw new RubyException(RubyException.ProtocolError, "Invalid PIN");
		}

		// pindb.set_pin: a new saved key from our randomness and the device entropy
		private byte[] SetPin(byte[] cke, byte[] payload, byte[] replayCounter)
		{
			var (pinSecret, entropy, pinPubKey) = ExtractFields(cke, payload, replayCounter);
			if (entropy.Length == 0)
				throw new RubyException(RubyException.ProtocolError, "set_pin without entropy");
			var pinPubKeyHash = SHA256.HashData(pinPubKey);

			var existing = LoadRecord(pinPubKeyHash, pinPubKey);
			if (existing is { } e)
			{
				CryptographicOperations.ZeroMemory(e.aesKey);
				CheckAntiReplay(e.replayCounter, replayCounter);
			}

			var ourRandom = RandomNumberGenerator.GetBytes(32);
			var newKey = HMACSHA256.HashData(ourRandom, entropy);
			SaveRecord(pinPubKeyHash, SHA256.HashData(pinSecret), newKey, pinPubKey, 0, new byte[ReplayCounterLen]);
			LastResult = "set_pin";

			var clientKey = HMACSHA256.HashData(newKey, pinSecret);
			CryptographicOperations.ZeroMemory(ourRandom);
			CryptographicOperations.ZeroMemory(newKey);
			CryptographicOperations.ZeroMemory(pinSecret);
			return clientKey;
		}
	}
}
