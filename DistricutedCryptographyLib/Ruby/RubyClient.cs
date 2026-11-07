using System.Security.Cryptography;
using NBitcoin;

namespace DistricutedCryptographyLib
{
	/// <summary>An error returned by Ruby ({ "error": { "code", "message" } }) or found in its reply.</summary>
	public sealed class RubyException : Exception
	{
		// Error codes of the firmware (utils/cbor_rpc.h)
		public const int InvalidRequest = -32600;
		public const int UnknownMethod = -32601;
		public const int BadParameters = -32602;
		public const int InternalError = -32603;
		public const int UserCancelled = -32000;
		public const int ProtocolError = -32001;
		public const int HwLocked = -32002;
		public const int NetworkMismatch = -32003;

		public int Code { get; }

		public RubyException(int code, string message) : base(message)
		{
			Code = code;
		}
	}

	/// <summary>
	/// Client of the Ruby hardware key (our fork of Blockstream's Jade): CBOR RPC over the USB serial port, or over
	/// TCP for the QEMU emulator.
	///
	/// The seed and the spending keys never leave Ruby. The wallet asks it for:
	///   - the master fingerprint and account xpubs (watch-only side of the wallet);
	///   - the utility keys (GetUtilityKeys), ECDH-encrypted to a one-time key of this client;
	///   - PSBT signatures (SignPsbt): Ruby shows the outputs and the fee and the user confirms on the device.
	///
	/// The PIN: Ruby asks the user on its own screen and then needs its blind oracle. Ruby replies to auth_user with
	/// an "http_request"; the client passes its params to PinOracle and sends the answer back to Ruby (the method in
	/// "on-reply"). In DistributedCryptography the oracle runs inside the wallet (no HTTP), see docs §12.2.
	///
	/// One request at a time (calls are serialized with a lock).
	/// </summary>
	public sealed class RubyClient : IDisposable
	{
		private readonly IRubyTransport _transport;
		private readonly object _sync = new object();
		private byte[] _rx = new byte[16 * 1024];
		private int _rxLen;

		/// <summary>Timeout of the calls that do not wait for the user.</summary>
		public int TimeoutMs { get; set; } = 30_000;

		/// <summary>Timeout of the calls that wait for the user on the device (PIN, confirmations).</summary>
		public int UserTimeoutMs { get; set; } = 5 * 60_000;

		/// <summary>The device log lines ({ "log": ... } messages of the debug firmware).</summary>
		public Action<string>? Log { get; set; }

		/// <summary>
		/// Answers the blind oracle requests of Ruby: receives the "params" of the http_request (urls, method, data)
		/// and returns the "body" to send back to Ruby.
		/// </summary>
		public Func<IDictionary<string, object?>, object?>? PinOracle { get; set; }

		public string Description => _transport.Description;

		public RubyClient(IRubyTransport transport)
		{
			_transport = transport ?? throw new ArgumentNullException(nameof(transport));
		}

		public static RubyClient ConnectTcp(string host = "127.0.0.1", int port = 30121) =>
			new RubyClient(new RubyTcpTransport(host, port));

		public static RubyClient ConnectSerial(string portName) =>
			new RubyClient(new RubySerialTransport(portName));

		/// <summary>"tcp:host:port" (emulator) or a serial port name ("COM5", "/dev/ttyUSB0").</summary>
		public static RubyClient Connect(string device)
		{
			device = (device ?? "").Trim();
			if (device.StartsWith("tcp:", StringComparison.OrdinalIgnoreCase))
			{
				var parts = device.Split(':');
				var host = parts.Length > 1 && parts[1].Length > 0 ? parts[1] : "127.0.0.1";
				var port = parts.Length > 2 ? int.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture) : 30121;
				return ConnectTcp(host, port);
			}
			if (device.Length == 0)
				throw new ArgumentException("No Ruby device given (a serial port, or tcp:host:port for the emulator)");
			return ConnectSerial(device);
		}

		public void Dispose() => _transport.Dispose();

		// ---------------------------------------------------------------- networks

		/// <summary>Ruby network name: mainnet, testnet or localtest (regtest).</summary>
		public static string ToRubyNetwork(Network network)
		{
			if (network.ChainName == ChainName.Mainnet)
				return "mainnet";
			if (network.ChainName == ChainName.Testnet)
				return "testnet";
			if (network.ChainName == ChainName.Regtest)
				return "localtest";
			throw new ArgumentException($"Ruby does not support the network {network}");
		}

		/// <summary>From the wallet NetworkType ("MainNet", "TestNet", "RegTest").</summary>
		public static Network ToNetwork(string networkType) => DelegatedMultiSigSpend.GetNetwork(networkType);

		// ---------------------------------------------------------------- RPC

		private static string NewId() => RandomNumberGenerator.GetInt32(100000, 1000000).ToString(System.Globalization.CultureInfo.InvariantCulture);

		/// <summary>
		/// Sends a request and returns its "result". Follows the http_request replies of the PIN flow through
		/// PinOracle. Throws RubyException when Ruby returns an error.
		/// </summary>
		public object? Call(string method, IDictionary<string, object?>? parameters = null, bool waitsForUser = false)
		{
			lock (_sync)
			{
				object? prms = parameters;
				Exception? oracleError = null;
				while (true)
				{
					var id = NewId();
					var reply = SendAndReceive(id, method, prms, waitsForUser);
					object? result;
					try
					{
						result = ResultOrThrow(reply);
					}
					catch (RubyException e) when (oracleError != null)
					{
						throw new RubyException(e.Code, $"{e.Message} (oracle: {oracleError.Message})");
					}

					if (result is not IDictionary<string, object?> map
						|| !map.TryGetValue("http_request", out var httpObj)
						|| httpObj is not IDictionary<string, object?> http)
						return result;

					// The blind oracle step of the PIN: pass the request to the oracle, its answer back to Ruby.
					// Ruby is now waiting for that answer: on any failure send it an empty reply (Ruby rejects it,
					// or offers the user to retry) instead of leaving it waiting.
					if (!http.TryGetValue("on-reply", out var onReply) || onReply is not string next)
						throw new RubyException(RubyException.ProtocolError, "Invalid http_request from Ruby");
					object? body = null;
					try
					{
						if (PinOracle == null)
							throw new RubyException(RubyException.ProtocolError, "Ruby asks for its PIN oracle and none is set");
						if (!http.TryGetValue("params", out var hp) || hp is not IDictionary<string, object?> httpParams)
							throw new RubyException(RubyException.ProtocolError, "Invalid http_request from Ruby");
						body = PinOracle(httpParams);
						oracleError = null;
					}
					catch (Exception e)
					{
						oracleError = e;
					}
					method = next;
					prms = body;
					waitsForUser = true;
				}
			}
		}

		private IDictionary<string, object?> SendAndReceive(string id, string method, object? prms, bool waitsForUser)
		{
			var request = new Dictionary<string, object?> { ["method"] = method, ["id"] = id };
			if (prms != null)
				request["params"] = prms;
			_transport.Write(RubyCbor.Encode(request));
			return ReadReply(id, waitsForUser ? UserTimeoutMs : TimeoutMs);
		}

		private static object? ResultOrThrow(IDictionary<string, object?> reply)
		{
			if (reply.TryGetValue("error", out var err) && err != null)
			{
				var code = 0;
				var message = "Ruby returned an error";
				if (err is IDictionary<string, object?> e)
				{
					if (e.TryGetValue("code", out var c) && c is long l)
						code = (int)l;
					if (e.TryGetValue("message", out var m) && m is string s)
						message = s;
				}
				throw new RubyException(code, message);
			}
			if (!reply.TryGetValue("result", out var result))
				throw new RubyException(RubyException.ProtocolError, "Ruby reply without result");
			return result;
		}

		// Reads messages until the reply to `id`; logs { "log" } messages; ignores replies to other ids.
		private IDictionary<string, object?> ReadReply(string id, int timeoutMs)
		{
			var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
			while (true)
			{
				if (_rxLen > 0 && RubyCbor.TryDecode(_rx, 0, _rxLen, out var msg, out var used))
				{
					Buffer.BlockCopy(_rx, used, _rx, 0, _rxLen - used);
					_rxLen -= used;

					if (msg is IDictionary<string, object?> map)
					{
						if (map.TryGetValue("id", out var rid))
						{
							var replyId = rid as string;
							if (replyId == id || (replyId == "00" && map.ContainsKey("error")))
								return map;
							continue; // a late reply to an earlier request
						}
						if (map.TryGetValue("log", out var log))
						{
							var line = log is byte[] lb ? System.Text.Encoding.UTF8.GetString(lb) : Convert.ToString(log);
							Log?.Invoke(line?.TrimEnd() ?? "");
						}
					}
					continue;
				}

				if (_rxLen == _rx.Length)
				{
					if (_rx.Length >= RubyCbor.MaxMessageSize)
						throw new RubyException(RubyException.ProtocolError, "Message from Ruby too large");
					Array.Resize(ref _rx, _rx.Length * 2);
				}

				var remaining = (int)Math.Min((deadline - DateTime.UtcNow).TotalMilliseconds, int.MaxValue);
				if (remaining <= 0)
					throw new TimeoutException("Ruby did not answer in time");
				_rxLen += _transport.Read(_rx, _rxLen, _rx.Length - _rxLen, Math.Min(remaining, 1000));
			}
		}

		private static IDictionary<string, object?> P(params (string key, object? value)[] items) =>
			items.ToDictionary(i => i.key, i => i.value);

		// ---------------------------------------------------------------- calls

		public IDictionary<string, object?> GetVersionInfo() =>
			Call("get_version_info") as IDictionary<string, object?>
			?? throw new RubyException(RubyException.ProtocolError, "Invalid get_version_info reply");

		/// <summary>0 idle, 1 handling a message, 2 in the device menus.</summary>
		public long Ping() => Call("ping") is long l ? l : -1;

		public bool AddEntropy(byte[] entropy) => Call("add_entropy", P(("entropy", entropy))) is true;

		public bool SetEpoch(long epoch) => Call("set_epoch", P(("epoch", epoch))) is true;

		/// <summary>
		/// Unlocks Ruby for a network: true at once if it is already unlocked, otherwise the user enters the PIN on
		/// the device and PinOracle is asked. False when the PIN was wrong.
		/// </summary>
		public bool AuthUser(Network network, long? epoch = null) =>
			Call("auth_user", P(("network", ToRubyNetwork(network)), ("epoch", epoch ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds())),
				waitsForUser: true) is true;

		public bool Logout() => Call("logout") is true;

		/// <summary>
		/// Pairs Ruby with its blind oracle (the RubyPinOracle of the wallet): the oracle public key and a URL (Ruby
		/// only passes the URL back in its requests; it must start with http:// or https://). Ruby shows the details
		/// and the user confirms. Ruby refuses to change the key once it has a PIN.
		/// </summary>
		public bool UpdatePinServer(string url, byte[] oraclePublicKey) =>
			Call("update_pinserver", P(("urlA", url), ("pubkey", oraclePublicKey)), waitsForUser: true) is true;

		/// <summary>Back to the default (Blockstream) oracle details.</summary>
		public bool ResetPinServer() =>
			Call("update_pinserver", P(("reset_details", true), ("reset_certificate", true)), waitsForUser: true) is true;

		/// <summary>DEBUG firmware only: wipes the wallet and the PIN state.</summary>
		public bool DebugCleanReset() => Call("debug_clean_reset") is true;

		/// <summary>DEBUG firmware only: the PIN the CI firmware "types" (and a new one for a PIN change).</summary>
		public bool DebugSetPin(int pin, int? newPin = null)
		{
			var prms = P(("pin", pin));
			if (newPin != null)
				prms["new_pin"] = newPin.Value;
			return Call("debug_set_pin", prms) is true;
		}

		/// <summary>DEBUG firmware only: loads a mnemonic in RAM (no PIN). Used by the tests with the emulator.</summary>
		public bool DebugSetMnemonic(string mnemonic, string? passphrase = null, bool temporaryWallet = false) =>
			Call("debug_set_mnemonic", P(("mnemonic", mnemonic), ("passphrase", passphrase), ("temporary_wallet", temporaryWallet))) is true;

		/// <summary>The xpub (tpub off mainnet) of a path; an empty path gives the master xpub.</summary>
		public string GetXpub(Network network, KeyPath path) =>
			Call("get_xpub", P(("network", ToRubyNetwork(network)), ("path", path.Indexes.Select(i => (object?)(ulong)i).ToList())))
				as string ?? throw new RubyException(RubyException.ProtocolError, "Invalid get_xpub reply");

		public HDFingerprint GetMasterFingerprint(Network network) =>
			ExtPubKey.Parse(GetXpub(network, new KeyPath()), network).PubKey.GetHDFingerPrint();

		/// <summary>The BIP86 account xpub m/86'/c'/0'.</summary>
		public ExtPubKey GetAccountXpub(Network network) =>
			ExtPubKey.Parse(GetXpub(network, RubyUtilityKeys.AccountPath(network)), network);

		/// <summary>
		/// The wallet utility keys (login, chat, groups, JSON files, file encryption, HSM). Ruby asks the user to
		/// confirm on its screen and returns them ECDH-encrypted to a one-time key made here.
		/// </summary>
		public RubyUtilityKeys GetUtilityKeys(Network network)
		{
			using var hostKey = new Key();
			var reply = Call("get_utility_keys",
				P(("network", ToRubyNetwork(network)), ("pubkey", hostKey.PubKey.ToBytes())), waitsForUser: true)
				as IDictionary<string, object?>
				?? throw new RubyException(RubyException.ProtocolError, "Invalid get_utility_keys reply");

			if (!reply.TryGetValue("pubkey", out var pk) || pk is not byte[] devicePub
				|| !reply.TryGetValue("encrypted", out var enc) || enc is not byte[] encrypted)
				throw new RubyException(RubyException.ProtocolError, "Invalid get_utility_keys reply");

			return RubyUtilityKeys.FromEncrypted(hostKey, new PubKey(devicePub), encrypted, network);
		}

		/// <summary>
		/// Ruby signs the inputs of the PSBT that belong to its wallet (by master fingerprint and key path) after the
		/// user confirms the outputs and the fee on the device. Returns the PSBT with the signatures added.
		/// </summary>
		public byte[] SignPsbt(Network network, byte[] psbt)
		{
			lock (_sync)
			{
				var id = NewId();
				var reply = SendAndReceive(id, "sign_psbt", P(("network", ToRubyNetwork(network)), ("psbt", psbt)), true);
				using var output = new MemoryStream();
				while (true)
				{
					if (ResultOrThrow(reply) is not byte[] chunk)
						throw new RubyException(RubyException.ProtocolError, "Invalid sign_psbt reply");
					output.Write(chunk);

					// Big results come in chunks: ask for the next one with get_extended_data
					if (!reply.TryGetValue("seqnum", out var sn) || sn is not long seqnum
						|| !reply.TryGetValue("seqlen", out var sl) || sl is not long seqlen || seqnum >= seqlen)
						break;
					reply = SendAndReceive(NewId(), "get_extended_data",
						P(("origid", id), ("orig", "sign_psbt"), ("seqnum", seqnum + 1), ("seqlen", seqlen)), false);
				}
				return output.ToArray();
			}
		}

		public PSBT SignPsbt(PSBT psbt)
		{
			var network = psbt.Network;
			return PSBT.Load(SignPsbt(network, psbt.ToBytes()), network);
		}
	}
}
