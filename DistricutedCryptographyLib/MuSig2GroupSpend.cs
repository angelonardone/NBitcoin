using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using NBitcoin;
using NBitcoin.DataEncoders;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// The MuSig2 group wallets (roadmap §8.3 / §8.4), signed LIVE in a "signing room" by the members present:
	/// - "Delegated MultiSig 2" (GroupType <see cref="DelegatedMultiSig2GroupType"/>): NBitcoin.DelegatedMultiSig2.
	///   The owner spends alone by the key path (<see cref="OwnerSpend"/>); any k members by the leaf of those k.
	/// - "Multi Signature 2" (GroupType <see cref="DelegatedMultiSigSpend.MultiSignature2GroupType"/>):
	///   NBitcoin.TaprootMultiSig2. No owner: the owner of the group is one more signer, and when ALL the signers
	///   are present they spend by the key path (the BIP327 aggregate of all of them).
	///
	/// The group keys are read as for Delegated / Multi Signature (DelegatedMultiSigSpend): chain-level extended
	/// keys derived at the HD sequence of each address.
	///
	/// A payment is a SESSION, a JSON text every member present gets from the one who starts it: the coins, the
	/// unsigned transaction, the change sequence and WHO signs (user names). From it every member rebuilds the same
	/// NBitcoin.MuSig2Spend (same id, same messages). Then:
	///   round 1 <see cref="CreateNonces"/>: no password; the SECRET nonces stay in this process
	///           (<see cref="NonceStore"/>), only the public nonces are returned;
	///   round 2 <see cref="Sign"/>: with the member's keys; takes (and wipes) his secret nonces;
	///   anybody <see cref="Finalize"/>: checks every partial signature, returns the signed transaction.
	/// <see cref="Abort"/> wipes the secret nonces of a session (a member left, timeout, cancel).
	///
	/// The session cannot prove that its coins exist with the amounts it says: each member's wallet checks them
	/// against its own list of the group's coins before round 1. A lie there cannot steal anything (BIP341: every
	/// signature commits to all the spent outputs, so the transaction would be invalid), but the fee shown would be wrong.
	///
	/// Every method returns a JSON string and never throws toward GeneXus (same convention as DelegatedMultiSigSpend).
	/// </summary>
	public static class MuSig2GroupSpend
	{
		/// <summary>GroupType of the "Delegated MultiSig 2" groups.</summary>
		public const short DelegatedMultiSig2GroupType = 80;

		/// <summary>
		/// How many leaves (combinations of k signers) an address may have. Building an address costs one BIP327
		/// KeyAgg per leaf (about 0.7 ms each, measured 2026-10-28), so this keeps an address under half a second.
		/// 500 allows 2-of-32, 3-of-15, 4-of-12, 5-of-11 and 8-of-12.
		/// </summary>
		public const int MaxLeaves = 500;

		/// <summary>How long the secret nonces of a member wait for round 2.</summary>
		public static readonly TimeSpan NonceLifetime = TimeSpan.FromMinutes(10);

		private sealed class SessionInput
		{
			public string TxId { get; set; } = "";
			public int Vout { get; set; }
			public string AmountBtc { get; set; } = "0";
			public int Sequence { get; set; }
			public bool IsChange { get; set; }
		}

		private sealed class Session
		{
			public int Version { get; set; } = 1;
			// "leaf": the k members of Signers by their leaf; "all": every signer by the key path (Multi Signature 2)
			public string Path { get; set; } = "leaf";
			public List<string> Signers { get; set; } = new List<string>();
			public List<SessionInput> Inputs { get; set; } = new List<SessionInput>();
			public string Tx { get; set; } = "";
			// the change output goes to the group's change address at this sequence (-1: no change)
			public int ChangeSequence { get; set; } = -1;
		}

		// a session parsed and checked against the group
		private sealed class Loaded
		{
			public Session Session = new Session();
			public MuSig2Spend Spend = null!;
			public Transaction Tx = null!;
			public DelegatedMultiSig2[] MultiSigs = Array.Empty<DelegatedMultiSig2>();
			public TxOut[] Spent = Array.Empty<TxOut>();
			public Dictionary<string, int> SignerIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
			public Money Fee = Money.Zero;
		}

		// ---------------------------------------------------------------------
		// The secret nonces: in memory only, used once, with an expiry
		// ---------------------------------------------------------------------

		/// <summary>
		/// The secret nonces of the members of this app, between round 1 and round 2 (decided with Angelo on
		/// 2026-10-28: never a file, never the browser). Key = session id + signer. Lost on an app restart: the
		/// session is then started again with new nonces.
		/// </summary>
		internal static class NonceStore
		{
			private static readonly object Lock = new object();
			private static readonly Dictionary<string, (MuSig2SecretNonces nonces, DateTime expires)> Entries = new Dictionary<string, (MuSig2SecretNonces, DateTime)>();

			private static string Key(uint256 sessionId, int signerIndex) => sessionId + ":" + signerIndex.ToString(CultureInfo.InvariantCulture);

			public static void Put(uint256 sessionId, int signerIndex, MuSig2SecretNonces nonces)
			{
				lock (Lock)
				{
					Sweep();
					var key = Key(sessionId, signerIndex);
					if (Entries.TryGetValue(key, out var old))
						old.nonces.Dispose();
					Entries[key] = (nonces, DateTime.UtcNow + NonceLifetime);
				}
			}

			public static MuSig2SecretNonces? Take(uint256 sessionId, int signerIndex)
			{
				lock (Lock)
				{
					Sweep();
					var key = Key(sessionId, signerIndex);
					if (!Entries.TryGetValue(key, out var entry))
						return null;
					Entries.Remove(key);
					return entry.nonces;
				}
			}

			public static int Remove(string sessionIdHex)
			{
				lock (Lock)
				{
					var keys = Entries.Keys.Where(k => k.StartsWith(sessionIdHex + ":", StringComparison.OrdinalIgnoreCase)).ToList();
					foreach (var key in keys)
					{
						Entries[key].nonces.Dispose();
						Entries.Remove(key);
					}
					return keys.Count;
				}
			}

			public static int Count
			{
				get { lock (Lock) { Sweep(); return Entries.Count; } }
			}

			private static void Sweep()
			{
				var now = DateTime.UtcNow;
				foreach (var key in Entries.Where(e => e.Value.expires <= now).Select(e => e.Key).ToList())
				{
					Entries[key].nonces.Dispose();
					Entries.Remove(key);
				}
			}
		}

		// ---------------------------------------------------------------------
		// Addresses
		// ---------------------------------------------------------------------

		public static string CreateAddress(GroupSDT group, int sequence, bool isChange, string networkType)
		{
			try
			{
				var net = DelegatedMultiSigSpend.GetNetwork(networkType);
				var ms = MultiSig(group, sequence, isChange, net);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					address = ms.Address.ToString(),
					k = ms.RequiredSignatures,
					n = ms.SignerPubKeys.Count,
					scripts = ms.Scripts.Count,
					isChange,
					sequence
				});
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		/// <summary>The ranged BIP390 descriptor of one chain (Bitcoin Core 30 or later reads musig()).</summary>
		public static string GetDescriptor(GroupSDT group, bool isChange, string networkType)
		{
			try
			{
				var net = DelegatedMultiSigSpend.GetNetwork(networkType);
				var (owner, signers, k) = Keys(group, isChange, net);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					descriptor = owner == null
						? TaprootMultiSig2.GetRangedDescriptor(signers, k, net)
						: DelegatedMultiSig2.GetRangedDescriptor(owner, signers, k, net),
					k,
					n = signers.Count,
					isChange
				});
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		// ---------------------------------------------------------------------
		// Spending
		// ---------------------------------------------------------------------

		/// <summary>
		/// Exact virtual size of a spend: <paramref name="path"/> = "owner" (the owner alone), "leaf" (k signers) or
		/// "all" (every signer of a Multi Signature 2 by the key path). <paramref name="changeAddr"/> may be empty.
		/// </summary>
		public static string EstimateVsize(GroupSDT group, string utxosJson, string sendTo, string changeAddr,
			bool sendAll, string path, string networkType)
		{
			try
			{
				var net = DelegatedMultiSigSpend.GetNetwork(networkType);
				var utxos = DelegatedMultiSigSpend.ParseUtxos(utxosJson);
				var multiSigs = utxos.Select(u => MultiSig(group, u.Sequence, u.IsChange, net)).ToArray();
				var tx = net.CreateTransaction();
				tx.Version = 2;
				foreach (var u in utxos)
					tx.Inputs.Add(new TxIn(new OutPoint(uint256.Parse(u.TxId), (uint)u.Vout)) { Sequence = DelegatedMultiSigSpend.InputSequence });
				tx.Outputs.Add(Money.Zero, BitcoinAddress.Create(sendTo.Trim(), net));
				if (!sendAll)
				{
					var change = string.IsNullOrWhiteSpace(changeAddr) ? multiSigs[0].Address.ScriptPubKey : BitcoinAddress.Create(changeAddr.Trim(), net).ScriptPubKey;
					tx.Outputs.Add(Money.Zero, change);
				}
				// every leaf is at the same depth or one more: the deepest one is the worst case
				var scriptIndex = PathKind(path) == "leaf" ? DeepestLeaf(multiSigs[0]) : -1;
				return JsonSerializer.Serialize(new { success = true, error = "", vsize = MuSig2Spend.EstimateVirtualSize(tx, multiSigs, scriptIndex) });
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		/// <summary>The owner of a Delegated MultiSig 2 spends alone by the key path: build, sign, finalize.</summary>
		public static string OwnerSpend(GroupSDT group, string utxosJson, string sendTo, string amountBtc,
			string changeAddr, string feeBtc, bool sendAll, string receivingExtPrivKey, string changeExtPrivKey,
			string networkType)
		{
			try
			{
				if (DelegatedMultiSigSpend.IsOwnerless(group))
					return DelegatedMultiSigSpend.Err($"A Multi Signature 2 group has no owner: every payment needs {group.MinimumShares} signatures");
				var net = DelegatedMultiSigSpend.GetNetwork(networkType);
				var utxos = DelegatedMultiSigSpend.ParseUtxos(utxosJson);
				var multiSigs = utxos.Select(u => MultiSig(group, u.Sequence, u.IsChange, net)).ToArray();
				CheckAddresses(utxos, multiSigs);
				var fee = Money.Coins(DelegatedMultiSigSpend.ParseDec(feeBtc));
				if (fee <= Money.Zero)
					return DelegatedMultiSigSpend.Err("The fee must be greater than zero");
				var tx = DelegatedMultiSigSpend.BuildTransaction(utxos, sendTo, amountBtc, changeAddr, fee, sendAll, net, "the fee");
				var spent = utxos.Select((u, i) => new TxOut(Money.Coins(DelegatedMultiSigSpend.ParseDec(u.AmountBtc)), multiSigs[i].Address.ScriptPubKey)).ToArray();
				var keys = new List<Key>();
				foreach (var u in utxos)
				{
					var xprv = u.IsChange ? changeExtPrivKey : receivingExtPrivKey;
					if (string.IsNullOrWhiteSpace(xprv))
						return DelegatedMultiSigSpend.Err($"The {(u.IsChange ? "change" : "receiving")} signing key is missing");
					keys.Add(ExtKey.Parse(xprv.Trim(), net).Derive((uint)u.Sequence).PrivateKey);
				}
				Transaction signed;
				try { signed = DelegatedMultiSig2.SignOwnerKeyPath(tx, spent, multiSigs, keys); }
				catch (ArgumentException) { return DelegatedMultiSigSpend.Err("The signing key is not the key of the owner of this group"); }
				DelegatedMultiSigSpend.Validate(signed, spent);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					txHex = signed.ToHex(),
					txId = signed.GetHash().ToString(),
					feeBtc = (spent.Select(o => o.Value).Sum() - signed.Outputs.Select(o => o.Value).Sum()).ToDecimal(MoneyUnit.BTC),
					vsize = signed.GetVirtualSize()
				});
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		/// <summary>
		/// The member who starts the payment builds the session once the members present are known
		/// (<paramref name="signersJson"/>: their user names, exactly k for a leaf; "all" = every signer of a Multi
		/// Signature 2, by the key path). <paramref name="changeSequence"/>: the sequence of
		/// <paramref name="changeAddr"/> on the group's change chain.
		/// </summary>
		public static string BuildSession(GroupSDT group, string utxosJson, string sendTo, string amountBtc,
			string changeAddr, int changeSequence, string feeBtc, bool sendAll, string signersJson, string networkType)
		{
			try
			{
				var net = DelegatedMultiSigSpend.GetNetwork(networkType);
				var utxos = DelegatedMultiSigSpend.ParseUtxos(utxosJson);
				var multiSigs = utxos.Select(u => MultiSig(group, u.Sequence, u.IsChange, net)).ToArray();
				CheckAddresses(utxos, multiSigs);
				var fee = Money.Coins(DelegatedMultiSigSpend.ParseDec(feeBtc));
				if (fee <= Money.Zero)
					return DelegatedMultiSigSpend.Err("The fee must be greater than zero");
				var tx = DelegatedMultiSigSpend.BuildTransaction(utxos, sendTo, amountBtc, changeAddr, fee, sendAll, net, "the fee");

				var session = new Session
				{
					Inputs = utxos.Select(u => new SessionInput { TxId = u.TxId.Trim(), Vout = u.Vout, AmountBtc = u.AmountBtc.Trim(), Sequence = u.Sequence, IsChange = u.IsChange }).ToList(),
					Tx = tx.ToHex(),
					ChangeSequence = tx.Outputs.Count == 2 ? changeSequence : -1
				};
				var all = (signersJson ?? "").Trim().Equals("all", StringComparison.OrdinalIgnoreCase);
				if (all)
				{
					session.Path = "all";
					session.Signers = SignerNames(group).ToList();
				}
				else
				{
					session.Signers = JsonSerializer.Deserialize<List<string>>(string.IsNullOrWhiteSpace(signersJson) ? "[]" : signersJson.Trim(), DelegatedMultiSigSpend.JsonIn) ?? new List<string>();
					session.Signers = session.Signers.Select(s => (s ?? "").Trim()).ToList();
				}
				var sessionJson = JsonSerializer.Serialize(session);
				var loaded = Load(group, sessionJson, net); // the same checks every member makes
				return Describe(group, loaded, "", "", net, sessionJson);
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		/// <summary>
		/// What a session really pays, read from the transaction (never from the message that carried it), its id,
		/// who signs, and whether the member of <paramref name="myReceivingExtPubKey"/> / <paramref name="myChangeExtPubKey"/>
		/// is one of the signers.
		/// </summary>
		public static string DescribeSession(GroupSDT group, string sessionJson, string myReceivingExtPubKey,
			string myChangeExtPubKey, string networkType)
		{
			try
			{
				var net = DelegatedMultiSigSpend.GetNetwork(networkType);
				return Describe(group, Load(group, sessionJson, net), myReceivingExtPubKey, myChangeExtPubKey, net, null);
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		/// <summary>
		/// Round 1 (no password): the public nonces of the member of these extended PUBLIC keys. His secret nonces
		/// stay in this process for <see cref="NonceLifetime"/>; calling again replaces them (a Retry).
		/// </summary>
		public static string CreateNonces(GroupSDT group, string sessionJson, string myReceivingExtPubKey,
			string myChangeExtPubKey, string networkType)
		{
			try
			{
				var net = DelegatedMultiSigSpend.GetNetwork(networkType);
				var loaded = Load(group, sessionJson, net);
				var signer = MySignerIndex(loaded, myReceivingExtPubKey, myChangeExtPubKey, net);
				if (signer < 0 || !loaded.Spend.Signers.Contains(signer))
					return DelegatedMultiSigSpend.Err("You are not one of the signers of this payment");
				var nonces = loaded.Spend.CreateNonces(signer);
				NonceStore.Put(loaded.Spend.Id, signer, nonces);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					sessionId = loaded.Spend.Id.ToString(),
					signer = NameOf(loaded, signer),
					publicNonces = nonces.PublicNonces.Select(n => Encoders.Hex.EncodeData(n)).ToArray()
				});
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		/// <summary>
		/// Round 2: the partial signatures of one member, with his chain-level extended PRIVATE keys and the public
		/// nonces of every signer (<paramref name="publicNoncesJson"/> = {"user name": ["hex", ...one per input]}).
		/// Uses and wipes his secret nonces: whatever happens, round 1 must be done again for another try.
		/// </summary>
		public static string Sign(GroupSDT group, string sessionJson, string publicNoncesJson,
			string receivingExtPrivKey, string changeExtPrivKey, string networkType)
		{
			try
			{
				var net = DelegatedMultiSigSpend.GetNetwork(networkType);
				var loaded = Load(group, sessionJson, net);
				var keys = new List<Key>();
				foreach (var input in loaded.Session.Inputs)
				{
					var xprv = input.IsChange ? changeExtPrivKey : receivingExtPrivKey;
					if (string.IsNullOrWhiteSpace(xprv))
						return DelegatedMultiSigSpend.Err($"The {(input.IsChange ? "change" : "receiving")} signing key is missing");
					keys.Add(ExtKey.Parse(xprv.Trim(), net).Derive((uint)input.Sequence).PrivateKey);
				}
				var signer = IndexOf(loaded.MultiSigs[0].SignerPubKeys, keys[0].PubKey);
				if (signer < 0 || !loaded.Spend.Signers.Contains(signer))
					return DelegatedMultiSigSpend.Err("You are not one of the signers of this payment");
				var nonces = NonceStore.Take(loaded.Spend.Id, signer);
				if (nonces == null)
					return DelegatedMultiSigSpend.Err("Your nonces of this payment are gone (expired, already used, or the app was restarted): start the signing again");
				var partials = loaded.Spend.Sign(keys, nonces, ParseByName(loaded, publicNoncesJson, "public nonces"));
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					sessionId = loaded.Spend.Id.ToString(),
					signer = NameOf(loaded, signer),
					partialSignatures = partials.Select(p => Encoders.Hex.EncodeData(p)).ToArray()
				});
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		/// <summary>
		/// Anybody: checks the partial signature of every signer and returns the signed transaction
		/// (<paramref name="partialSignaturesJson"/> = {"user name": ["hex", ...one per input]}).
		/// </summary>
		public static string Finalize(GroupSDT group, string sessionJson, string publicNoncesJson,
			string partialSignaturesJson, string networkType)
		{
			try
			{
				var net = DelegatedMultiSigSpend.GetNetwork(networkType);
				var loaded = Load(group, sessionJson, net);
				Transaction signed;
				try
				{
					signed = loaded.Spend.Finalize(ParseByName(loaded, publicNoncesJson, "public nonces"), ParseByName(loaded, partialSignaturesJson, "partial signatures"));
				}
				catch (InvalidOperationException e) when (e.Message.StartsWith("The partial signature of signer "))
				{
					// name the member instead of the signer index
					var index = int.Parse(e.Message.Substring("The partial signature of signer ".Length).Split(' ')[0], CultureInfo.InvariantCulture);
					return DelegatedMultiSigSpend.Err($"The signature of {NameOf(loaded, index)} is not valid: the payment cannot be completed");
				}
				DelegatedMultiSigSpend.Validate(signed, loaded.Spent);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					txHex = signed.ToHex(),
					txId = signed.GetHash().ToString(),
					feeBtc = loaded.Fee.ToDecimal(MoneyUnit.BTC),
					vsize = signed.GetVirtualSize()
				});
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		/// <summary>Wipes every secret nonce of a session in this app (a member left, timeout, cancel).</summary>
		public static string Abort(string sessionId)
		{
			try
			{
				var removed = NonceStore.Remove((sessionId ?? "").Trim());
				return JsonSerializer.Serialize(new { success = true, error = "", removed });
			}
			catch (Exception e) { return DelegatedMultiSigSpend.Err(e); }
		}

		// ---------------------------------------------------------------------
		// Helpers
		// ---------------------------------------------------------------------

		private static string PathKind(string path)
		{
			var p = (path ?? "").Trim().ToLowerInvariant();
			if (p != "owner" && p != "leaf" && p != "all")
				throw new Exception($"Unknown spend path '{path}' (owner, leaf or all)");
			return p;
		}

		private static int DeepestLeaf(DelegatedMultiSig2 ms)
		{
			int best = 0, size = -1;
			for (int i = 0; i < ms.Scripts.Count; i++)
			{
				var s = ms.TaprootSpendInfo.GetControlBlock(ms.Scripts[i]).ToBytes().Length;
				if (s > size) { size = s; best = i; }
			}
			return best;
		}

		private static void CheckAddresses(List<DelegatedMultiSigSpend.UtxoDto> utxos, DelegatedMultiSig2[] multiSigs)
		{
			for (int i = 0; i < utxos.Count; i++)
			{
				var address = (utxos[i].Address ?? "").Trim();
				if (address.Length > 0 && address != multiSigs[i].Address.ToString())
					throw new Exception("Generated address and UTXO address don't match");
			}
		}

		// Reads the session and checks it against the group: the coins are of this group, the change goes back to
		// the group's change chain, the signers are members, and the transaction is exactly [payment] or
		// [payment, change]. Every member makes these checks before signing anything.
		private static Loaded Load(GroupSDT group, string sessionJson, Network net)
		{
			if (string.IsNullOrWhiteSpace(sessionJson))
				throw new Exception("The payment is empty");
			var session = JsonSerializer.Deserialize<Session>(sessionJson.Trim(), DelegatedMultiSigSpend.JsonIn) ?? new Session();
			if (session.Version != 1)
				throw new Exception("Unknown payment version");
			if (session.Inputs.Count == 0)
				throw new Exception("The payment spends no coins");
			var path = PathKind(session.Path);
			if (path == "owner")
				throw new Exception("The owner's payment is not signed in a room");

			var loaded = new Loaded { Session = session };
			loaded.Tx = Transaction.Parse(session.Tx.Trim(), net);
			if (loaded.Tx.Inputs.Count != session.Inputs.Count)
				throw new Exception("The transaction does not spend the coins of the payment");
			loaded.MultiSigs = session.Inputs.Select(i => MultiSig(group, i.Sequence, i.IsChange, net)).ToArray();
			loaded.Spent = new TxOut[session.Inputs.Count];
			for (int i = 0; i < session.Inputs.Count; i++)
			{
				var input = session.Inputs[i];
				var outpoint = new OutPoint(uint256.Parse(input.TxId.Trim()), (uint)input.Vout);
				if (loaded.Tx.Inputs[i].PrevOut != outpoint)
					throw new Exception($"Input {i} of the transaction is not the coin of the payment");
				if (loaded.Tx.Inputs[i].WitScript != WitScript.Empty || loaded.Tx.Inputs[i].ScriptSig != Script.Empty)
					throw new Exception("The transaction of the payment is already signed");
				loaded.Spent[i] = new TxOut(Money.Coins(DelegatedMultiSigSpend.ParseDec(input.AmountBtc)), loaded.MultiSigs[i].Address.ScriptPubKey);
			}

			if (loaded.Tx.Outputs.Count < 1 || loaded.Tx.Outputs.Count > 2)
				throw new Exception("Unexpected outputs in the payment");
			if (loaded.Tx.Outputs.Count == 2)
			{
				if (session.ChangeSequence < 0)
					throw new Exception("The payment has a change output but no change address of the group");
				var change = MultiSig(group, session.ChangeSequence, true, net);
				if (loaded.Tx.Outputs[1].ScriptPubKey != change.Address.ScriptPubKey)
					throw new Exception("The change does not go back to the group's change address");
			}
			loaded.Fee = loaded.Spent.Select(o => o.Value).Sum() - loaded.Tx.Outputs.Select(o => o.Value).Sum();
			if (loaded.Fee <= Money.Zero)
				throw new Exception("The payment has no fee");

			// user name -> signer index, by the members' keys at the first input (the same member at every input)
			var first = session.Inputs[0];
			foreach (var m in DelegatedMultiSigSpend.MemberXpubs(group, first.IsChange))
			{
				var pubKey = ExtPubKey.Parse(m.xpub, net).Derive((uint)first.Sequence).PubKey;
				var index = IndexOf(loaded.MultiSigs[0].SignerPubKeys, pubKey);
				if (index >= 0 && m.name.Length > 0)
					loaded.SignerIndex[m.name] = index;
			}
			var signers = new List<int>();
			foreach (var name in session.Signers)
			{
				if (!loaded.SignerIndex.TryGetValue(name, out var index))
					throw new Exception($"'{name}' is not a signer of this group");
				if (signers.Contains(index))
					throw new Exception($"'{name}' is twice among the signers");
				signers.Add(index);
			}
			if (path == "all")
			{
				if (signers.Count != loaded.MultiSigs[0].SignerPubKeys.Count)
					throw new Exception("A payment by the key path needs every signer of the group");
				loaded.Spend = MuSig2Spend.KeyPath(loaded.Tx, loaded.Spent, loaded.MultiSigs);
			}
			else
			{
				var k = loaded.MultiSigs[0].RequiredSignatures;
				if (signers.Count != k)
					throw new Exception($"A payment needs exactly {k} signers present; it names {signers.Count}");
				loaded.Spend = MuSig2Spend.ScriptPath(loaded.Tx, loaded.Spent, loaded.MultiSigs, signers);
			}
			return loaded;
		}

		private static string Describe(GroupSDT group, Loaded loaded, string myReceivingExtPubKey, string myChangeExtPubKey, Network net, string? sessionJson)
		{
			var tx = loaded.Tx;
			var mine = string.IsNullOrWhiteSpace(myReceivingExtPubKey) && string.IsNullOrWhiteSpace(myChangeExtPubKey)
				? -1 : MySignerIndex(loaded, myReceivingExtPubKey, myChangeExtPubKey, net);
			return JsonSerializer.Serialize(new
			{
				success = true,
				error = "",
				session = sessionJson ?? "",
				sessionId = loaded.Spend.Id.ToString(),
				path = loaded.Session.Path,
				signers = loaded.Spend.Signers.Select(s => NameOf(loaded, s)).ToArray(),
				required = loaded.MultiSigs[0].RequiredSignatures,
				iAmSigner = mine >= 0 && loaded.Spend.Signers.Contains(mine),
				me = mine >= 0 ? NameOf(loaded, mine) : "",
				sendTo = tx.Outputs[0].ScriptPubKey.GetDestinationAddress(net)?.ToString() ?? "",
				amountBtc = tx.Outputs[0].Value.ToDecimal(MoneyUnit.BTC),
				changeTo = tx.Outputs.Count == 2 ? tx.Outputs[1].ScriptPubKey.GetDestinationAddress(net)?.ToString() ?? "" : "",
				changeBtc = tx.Outputs.Count == 2 ? tx.Outputs[1].Value.ToDecimal(MoneyUnit.BTC) : 0m,
				totalInBtc = loaded.Spent.Select(o => o.Value).Sum().ToDecimal(MoneyUnit.BTC),
				feeBtc = loaded.Fee.ToDecimal(MoneyUnit.BTC),
				vsize = loaded.Spend.EstimateVirtualSize(),
				inputs = loaded.Session.Inputs.Count
			});
		}

		// the signer index of the member of these extended public keys (at the first input), -1 if he is not one
		private static int MySignerIndex(Loaded loaded, string myReceivingExtPubKey, string myChangeExtPubKey, Network net)
		{
			var first = loaded.Session.Inputs[0];
			var xpub = first.IsChange ? myChangeExtPubKey : myReceivingExtPubKey;
			if (string.IsNullOrWhiteSpace(xpub))
				return -1;
			var pubKey = ExtPubKey.Parse(xpub.Trim(), net).Derive((uint)first.Sequence).PubKey;
			return IndexOf(loaded.MultiSigs[0].SignerPubKeys, pubKey);
		}

		private static string NameOf(Loaded loaded, int signerIndex) =>
			loaded.SignerIndex.FirstOrDefault(p => p.Value == signerIndex).Key ?? $"signer {signerIndex}";

		// {"user name": ["hex", ...]} -> {signer index: [bytes, ...]}
		private static Dictionary<int, IReadOnlyList<byte[]>> ParseByName(Loaded loaded, string json, string what)
		{
			var byName = JsonSerializer.Deserialize<Dictionary<string, List<string>>>(string.IsNullOrWhiteSpace(json) ? "{}" : json.Trim(), DelegatedMultiSigSpend.JsonIn)
				?? new Dictionary<string, List<string>>();
			var result = new Dictionary<int, IReadOnlyList<byte[]>>();
			foreach (var pair in byName)
			{
				if (!loaded.SignerIndex.TryGetValue(pair.Key.Trim(), out var index))
					throw new Exception($"The {what} of '{pair.Key}', who is not a signer of this group");
				result[index] = pair.Value.Select(h => Encoders.Hex.DecodeData((h ?? "").Trim())).ToArray();
			}
			var missing = loaded.Spend.Signers.Where(s => !result.ContainsKey(s)).Select(s => NameOf(loaded, s)).ToList();
			if (missing.Count > 0)
				throw new Exception($"The {what} of {string.Join(", ", missing)} are missing");
			return result;
		}

		// every signer's user name (Multi Signature 2: the owner too)
		private static IEnumerable<string> SignerNames(GroupSDT group) =>
			DelegatedMultiSigSpend.MemberXpubs(group, false).Select(m => m.name);

		private static int IndexOf(IReadOnlyList<PubKey> pubKeys, PubKey pubKey)
		{
			var compressed = pubKey.Compress();
			for (int i = 0; i < pubKeys.Count; i++)
				if (pubKeys[i] == compressed)
					return i;
			return -1;
		}

		private static bool IsMuSig2(GroupSDT group) =>
			group != null && (group.GroupType == DelegatedMultiSig2GroupType || group.GroupType == DelegatedMultiSigSpend.MultiSignature2GroupType);

		// The multisig of one address. Built addresses are kept (the same keys always give the same address) so
		// the address lists of a group do not rebuild every leaf on each call.
		private static readonly object CacheLock = new object();
		private static readonly Dictionary<string, DelegatedMultiSig2> Cache = new Dictionary<string, DelegatedMultiSig2>();
		private const int CacheSize = 5000;

		private static DelegatedMultiSig2 MultiSig(GroupSDT group, int sequence, bool isChange, Network net)
		{
			if (sequence < 0)
				throw new Exception("Invalid address sequence");
			var (owner, signers, k) = Keys(group, isChange, net);
			var cacheKey = string.Join("|", new[] { net.Name, group.GroupType.ToString(CultureInfo.InvariantCulture), owner?.ToString(net) ?? "-", k.ToString(CultureInfo.InvariantCulture), sequence.ToString(CultureInfo.InvariantCulture) }
				.Concat(signers.Select(s => s.ToString(net)).OrderBy(s => s, StringComparer.Ordinal)));
			lock (CacheLock)
			{
				if (Cache.TryGetValue(cacheKey, out var cached))
					return cached;
			}
			DelegatedMultiSig2 ms = owner == null
				? TaprootMultiSig2.FromExtPubKeys(signers, k, (uint)sequence, net)
				: DelegatedMultiSig2.FromExtPubKeys(owner, signers, k, (uint)sequence, net);
			lock (CacheLock)
			{
				if (Cache.Count >= CacheSize)
					Cache.Clear();
				Cache[cacheKey] = ms;
			}
			return ms;
		}

		// owner (null for Multi Signature 2), the signers' chain-level keys and k, checked
		private static (ExtPubKey? owner, List<ExtPubKey> signers, int k) Keys(GroupSDT group, bool isChange, Network net)
		{
			if (group == null)
				throw new Exception("Group is null (call FromSDT first)");
			if (!IsMuSig2(group))
				throw new Exception("This group is not a Delegated MultiSig 2 or a Multi Signature 2 group");
			var chain = isChange ? "change" : "receiving";
			var ownerXpub = isChange ? group.ExtPubKeyMultiSigChange : group.ExtPubKeyMultiSigReceiving;
			if (string.IsNullOrWhiteSpace(ownerXpub))
				throw new Exception($"The owner's {chain} extended public key is missing");
			var owner = ExtPubKey.Parse(ownerXpub.Trim(), net);
			var ownerless = DelegatedMultiSigSpend.IsOwnerless(group);
			var signers = DelegatedMultiSigSpend.MemberXpubs(group, isChange).Select(m => ExtPubKey.Parse(m.xpub, net)).ToList();
			if (signers.Count < 2)
				throw new Exception($"At least 2 {(ownerless ? "participants" : "members")} with a {chain} extended public key are required");
			var all = signers.Select(s => s.ToString(net)).ToList();
			if (!ownerless)
				all.Add(owner.ToString(net));
			if (all.Distinct().Count() != all.Count)
				throw new Exception("Two participants of the group have the same key");
			int k = group.MinimumShares;
			if (k < 2 || k > signers.Count)
				throw new Exception($"Invalid MinimumShares ({k}) for {signers.Count} signers: a MuSig2 group needs 2 to {signers.Count} (for 1 use Delegated MultiSig)");
			var leaves = DelegatedMultiSigSpend.Combinations(signers.Count, k);
			if (leaves > MaxLeaves)
				throw new Exception($"A {k}-of-{signers.Count} group has {leaves:N0} combinations of signers; the maximum is {MaxLeaves:N0}. Use fewer members, or a number of signatures closer to 2 or to all the members");
			return (ownerless ? null : owner, signers, k);
		}
	}
}
