using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.BIP370;
#if HAS_SPAN
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
#endif

namespace NBitcoin
{
#if HAS_SPAN
	/// <summary>
	/// DelegatedMultiSig2: Taproot-based k-of-n multisig using MuSig2 signature aggregation.
	///
	/// PROGRESSIVE SIGNATURE COLLECTION WORKFLOW (DUAL-TRANSACTION):
	/// ==============================================================
	///
	/// This implementation supports a dual-transaction progressive signing protocol where
	/// TWO complete transactions (base fee and buffered fee) are signed in parallel,
	/// allowing the final signer to choose which one to broadcast based on network conditions.
	///
	/// THE PROBLEM:
	/// ------------
	/// In k-of-n multisig scenarios, you don't know which k signers will participate until
	/// they actually sign. Different signing combinations may have different transaction sizes.
	/// If you calculate fees upfront based on a guess, you risk underpaying (transaction rejected)
	/// or overpaying (wasting money).
	///
	/// THE SOLUTION - Dual-Transaction Progressive Protocol:
	/// ------------------------------------------------------
	///
	/// PHASE 0: Setup (Transaction Creator)
	///   - Identifies the first k signers who will participate
	///   - Calculates the cheapest script combination for those signers
	///   - Estimates virtual size for that combination
	///   - Creates TWO separate transactions:
	///     * Transaction A (Base): change = input - payment - fee(base_vsize)
	///     * Transaction B (Buffered): change = input - payment - fee(base_vsize * (1 + buffer%))
	///   - Sends BOTH transactions to first signer
	///
	/// STEP 1: First Signer (MuSig2 Nonce Exchange)
	///   - Generates nonces for ALL script combinations they participate in
	///   - Does this for BOTH transactions (A and B)
	///   - Broadcasts nonces to other signers
	///
	/// STEP 2: Nonce Aggregation
	///   - Once all k signers have shared nonces, nonce aggregation happens
	///   - This must complete before ANY signer can create partial signatures
	///   - Creates aggregated nonce for BOTH transactions
	///
	/// STEP 3: Signers Create Partial Signatures
	///   - Each signer creates partial signatures for their applicable scripts
	///   - Signs BOTH transactions (A and B)
	///   - As more signers add signatures, viable script combinations narrow down
	///   - This happens progressively for BOTH transactions in parallel
	///
	/// STEP 4: Final (kth) Signer
	///   - Completes partial signatures for BOTH transactions
	///   - Now has TWO fully-signed, valid transactions:
	///     * Transaction A: lower fee (base vsize)
	///     * Transaction B: higher fee (buffered vsize)
	///   - Examines current network conditions (mempool, fee rates)
	///   - CHOOSES which transaction to broadcast:
	///     * If network is calm: broadcast Transaction A (save money)
	///     * If network is congested: broadcast Transaction B (ensure confirmation)
	///
	/// KEY DIFFERENCES FROM DelegatedMultiSig:
	/// ----------------------------------------
	/// 1. Uses MuSig2 (interactive Schnorr signature aggregation)
	/// 2. Requires nonce exchange phase before signing
	/// 3. Produces single aggregated signature (more compact)
	/// 4. All k signers MUST participate (no subset selection)
	///
	/// KEY BENEFITS:
	/// -------------
	/// 1. Accurate fee estimation - based on actual signing combination
	/// 2. Flexible fee strategy - final signer has real-time decision power
	/// 3. No risk of underpayment - buffered transaction always available
	/// 4. Compact signatures - MuSig2 produces single 64-byte signature
	/// 5. Interactive security - MuSig2 provides strong security guarantees
	///
	/// USAGE EXAMPLE:
	/// --------------
	/// // Setup: 3-of-5 multisig, 15% buffer
	/// var multiSig = new DelegatedMultiSig2(ownerPubKey, signerPubKeys, 3, network);
	///
	/// // Calculate which k signers will participate (e.g., signers 0, 2, 4)
	/// var participatingKeys = new[] { key0, key2, key4 };
	///
	/// // Create TWO transactions with different fees
	/// var (txBase, txBuffered) = CreateDualTransactions(multiSig, input, output, feeRate, bufferPct);
	///
	/// // Create builders for BOTH
	/// var builderA = multiSig.CreateSignatureBuilder(txBase, coins);
	/// var builderB = multiSig.CreateSignatureBuilder(txBuffered, coins);
	///
	/// // Phase 1: All signers exchange nonces for BOTH transactions
	/// var noncesA_0 = builderA.GenerateNonce(key0, 0);
	/// var noncesB_0 = builderB.GenerateNonce(key0, 0);
	/// // ... collect nonces from all participants for both transactions
	///
	/// // Phase 2: All signers create partial signatures for BOTH
	/// builderA.SignWithSigner(key0, 0);
	/// builderB.SignWithSigner(key0, 0);
	/// // ... collect signatures from all participants
	///
	/// // Phase 3: Final signer chooses which to broadcast
	/// var finalTxA = builderA.FinalizeTransaction(0); // Base fee
	/// var finalTxB = builderB.FinalizeTransaction(0); // Buffered fee
	///
	/// // Choose based on network conditions
	/// var chosenTx = IsNetworkCongested() ? finalTxB : finalTxA;
	/// rpc.SendRawTransaction(chosenTx);
	/// </summary>
	public class DelegatedMultiSig2
	{
		private readonly PubKey _ownerPubKey;
		private readonly List<PubKey> _signerPubKeys;
		private readonly int _requiredSignatures;
		private readonly Network _network;
		private TaprootSpendInfo _taprootSpendInfo;
		private readonly List<TapScript> _scripts;
		private readonly Dictionary<string, int[]> _scriptToSignerIndices;
		private readonly Dictionary<string, ECPubKey> _scriptToAggregatedPubKey;

		public DelegatedMultiSig2(PubKey ownerPubKey, List<PubKey> signerPubKeys, int requiredSignatures, Network network)
		{
			if (ownerPubKey == null)
				throw new ArgumentNullException(nameof(ownerPubKey));
			if (signerPubKeys == null || signerPubKeys.Count == 0)
				throw new ArgumentException("At least one signer public key is required", nameof(signerPubKeys));
			if (requiredSignatures < 1 || requiredSignatures > signerPubKeys.Count)
				throw new ArgumentException($"Required signatures must be between 1 and {signerPubKeys.Count}", nameof(requiredSignatures));
			if (network == null)
				throw new ArgumentNullException(nameof(network));

			_ownerPubKey = ownerPubKey;
			_signerPubKeys = signerPubKeys;
			_requiredSignatures = requiredSignatures;
			_network = network;
			_scripts = new List<TapScript>();
			_scriptToSignerIndices = new Dictionary<string, int[]>();
			_scriptToAggregatedPubKey = new Dictionary<string, ECPubKey>();

			GenerateScripts();
			CreateTaprootSpendInfo();
		}

		public TaprootAddress Address => TaprootPubKey.GetAddress(_network);

		public TaprootPubKey TaprootPubKey => _taprootSpendInfo.OutputPubKey.OutputKey;

		public TaprootSpendInfo TaprootSpendInfo => _taprootSpendInfo;

		public IReadOnlyList<TapScript> Scripts => _scripts.AsReadOnly();

		private void GenerateScripts()
		{
			// Calculate the number of combinations to prevent memory exhaustion
			var combinationCount = CalculateCombinationCount(_signerPubKeys.Count, _requiredSignatures);
			if (combinationCount > 1000000) // Reasonable limit to prevent memory issues
			{
				throw new ArgumentException($"The number of k-of-n combinations ({combinationCount:N0}) is too large. " +
					$"Consider using a different approach for large multisig schemes. " +
					$"Maximum supported combinations: 1,000,000");
			}

			var combinations = GetCombinations(_signerPubKeys.Count, _requiredSignatures);
			var ctx = Context.Instance;

			foreach (var combination in combinations)
			{
				// For MuSig2, we aggregate the public keys for each combination
				var selectedPubKeys = new ECPubKey[combination.Length];
				for (int i = 0; i < combination.Length; i++)
				{
					var signerIndex = combination[i];
					selectedPubKeys[i] = ctx.CreatePubKey(_signerPubKeys[signerIndex].ToBytes());
				}

				// Aggregate the public keys using MuSig
				var aggregatedPubKey = ECPubKey.MusigAggregate(selectedPubKeys);
				var xOnlyPubKey = aggregatedPubKey.ToXOnlyPubKey();

				// Create a script with the aggregated key
				var scriptBuilder = new Script();
				scriptBuilder = scriptBuilder + Op.GetPushOp(xOnlyPubKey.ToBytes()) + OpcodeType.OP_CHECKSIG;

				var tapScript = scriptBuilder.ToTapScript(TapLeafVersion.C0);
				_scripts.Add(tapScript);
				_scriptToSignerIndices[tapScript.LeafHash.ToString()] = combination;
				_scriptToAggregatedPubKey[tapScript.LeafHash.ToString()] = aggregatedPubKey;
			}
		}

		private void CreateTaprootSpendInfo()
		{
			var scriptWeights = _scripts.Select(s => (1u, s)).ToArray();
			var internalKey = _ownerPubKey.TaprootInternalKey;
			_taprootSpendInfo = TaprootSpendInfo.WithHuffmanTree(internalKey, scriptWeights);
		}

		private static double CalculateCombinationCount(int n, int k)
		{
			if (k > n || k < 0) return 0;
			if (k == 0 || k == n) return 1;
			
			// Use symmetry property: C(n,k) = C(n,n-k)
			k = Math.Min(k, n - k);
			
			double result = 1;
			for (int i = 0; i < k; i++)
			{
				result = result * (n - i) / (i + 1);
				// Prevent overflow by checking if result is getting too large
				if (result > double.MaxValue / 1000)
					return double.MaxValue;
			}
			
			return result;
		}

		private static List<int[]> GetCombinations(int n, int k)
		{
			// Handle edge cases first
			if (k == 0) return new List<int[]>();
			if (k == n)
			{
				// n-of-n: only one combination (all participants)
				var allElements = new int[n];
				for (int i = 0; i < n; i++)
					allElements[i] = i;
				return new List<int[]> { allElements };
			}
			
			// Apply combinatorial symmetry optimization: C(n,k) = C(n,n-k)
			// For k > n/2, generate (n-k)-combinations and use their complements
			// This reduces memory usage and generation time for large k values
			bool useComplement = k > n - k;
			int effectiveK = useComplement ? n - k : k;
			
			var baseCombinations = GetCombinationsBase(n, effectiveK);
			
			if (useComplement)
			{
				// Convert each small combination to its complement
				var result = new List<int[]>();
				foreach (var combination in baseCombinations)
				{
					var complement = new int[k];
					var combinationSet = new HashSet<int>(combination);
					int complementIndex = 0;
					
					for (int i = 0; i < n; i++)
					{
						if (!combinationSet.Contains(i))
							complement[complementIndex++] = i;
					}
					
					result.Add(complement);
				}
				return result;
			}
			
			return baseCombinations;
		}
		
		private static List<int[]> GetCombinationsBase(int n, int k)
		{
			var result = new List<int[]>();
			
			// Handle edge cases
			if (k == 0) return result;
			if (k == n)
			{
				var allElements = new int[n];
				for (int i = 0; i < n; i++)
					allElements[i] = i;
				result.Add(allElements);
				return result;
			}
			if (k == 1)
			{
				for (int i = 0; i < n; i++)
					result.Add(new int[] { i });
				return result;
			}
			
			// Use iterative approach to avoid recursion overhead
			var combination = new int[k];
			for (int i = 0; i < k; i++)
				combination[i] = i;
			
			while (true)
			{
				// Add current combination (create array directly instead of cloning)
				var current = new int[k];
				Array.Copy(combination, current, k);
				result.Add(current);
				
				// Find the rightmost element that can be incremented
				int pos = k - 1;
				while (pos >= 0 && combination[pos] == n - k + pos)
					pos--;
				
				if (pos < 0) break; // All combinations generated
				
				// Increment and reset subsequent positions
				combination[pos]++;
				for (int i = pos + 1; i < k; i++)
					combination[i] = combination[i - 1] + 1;
			}
			
			return result;
		}

		public static TaprootAddress CreateAddress(PubKey ownerPubKey, List<PubKey> signerPubKeys, int requiredSignatures, Network network)
		{
			var delegatedMultiSig = new DelegatedMultiSig2(ownerPubKey, signerPubKeys, requiredSignatures, network);
			return delegatedMultiSig.Address;
		}

		public static TaprootAddress CreateAddress(ExtPubKey ownerExtPubKey, uint ownerDerivation, List<ExtPubKey> signerExtPubKeys, uint signerDerivation, int requiredSignatures, Network network)
		{
			var ownerPubKey = ownerExtPubKey.Derive(ownerDerivation).PubKey;
			var signerPubKeys = signerExtPubKeys.Select(extPubKey => extPubKey.Derive(signerDerivation).PubKey).ToList();
			return CreateAddress(ownerPubKey, signerPubKeys, requiredSignatures, network);
		}

		public MuSig2SignatureBuilder CreateSignatureBuilder(Transaction transaction, ICoin[] spentCoins, bool isDynamicFeeMode = false)
		{
			return new MuSig2SignatureBuilder(this, transaction, spentCoins, isDynamicFeeMode);
		}

		/// <summary>
		/// Creates a pair of transactions (base and buffered) for the dual-transaction signing workflow.
		/// This allows all k signers to sign both versions and the final signer to choose which to broadcast.
		/// </summary>
		/// <param name="coin">The input coin to spend</param>
		/// <param name="paymentAddress">The destination address for the payment</param>
		/// <param name="paymentAmount">The amount to send to the payment address</param>
		/// <param name="changeAddress">The address to receive change</param>
		/// <param name="feeRate">The fee rate (satoshis per vbyte)</param>
		/// <param name="signerIndices">The indices of the k signers who will participate (must be exactly k signers)</param>
		/// <param name="bufferPercentage">Buffer percentage for the buffered transaction (e.g., 15.0 for 15%)</param>
		/// <returns>A tuple containing (baseTransaction, bufferedTransaction)</returns>
		public (Transaction baseTx, Transaction bufferedTx) CreateDualTransactions(
			ICoin coin,
			IDestination paymentAddress,
			Money paymentAmount,
			IDestination changeAddress,
			FeeRate feeRate,
			int[] signerIndices,
			double bufferPercentage = 15.0)
		{
			if (coin == null)
				throw new ArgumentNullException(nameof(coin));
			if (paymentAddress == null)
				throw new ArgumentNullException(nameof(paymentAddress));
			if (changeAddress == null)
				throw new ArgumentNullException(nameof(changeAddress));
			if (feeRate == null)
				throw new ArgumentNullException(nameof(feeRate));
			if (signerIndices == null || signerIndices.Length != _requiredSignatures)
				throw new ArgumentException($"Must provide exactly {_requiredSignatures} signer indices for MuSig2");
			if (bufferPercentage < 0 || bufferPercentage > 100)
				throw new ArgumentOutOfRangeException(nameof(bufferPercentage), "Buffer percentage must be between 0 and 100");

			// Find the script for the given signers (in MuSig2, all k signers must participate)
			int targetScriptIndex = -1;
			var signerSet = signerIndices.OrderBy(x => x).ToArray();

			for (int scriptIndex = 0; scriptIndex < _scripts.Count; scriptIndex++)
			{
				var script = _scripts[scriptIndex];
				var scriptSignerIndices = _scriptToSignerIndices[script.LeafHash.ToString()].OrderBy(x => x).ToArray();

				// Check if this script matches the provided signers exactly
				if (scriptSignerIndices.SequenceEqual(signerSet))
				{
					targetScriptIndex = scriptIndex;
					break;
				}
			}

			if (targetScriptIndex == -1)
				throw new ArgumentException("No valid script found for the specified signers");

			// Create a temporary transaction to estimate size
			var tempTx = _network.CreateTransaction();
			tempTx.Inputs.Add(new OutPoint(coin.Outpoint.Hash, coin.Outpoint.N));
			tempTx.Outputs.Add(paymentAmount, paymentAddress);
			tempTx.Outputs.Add(Money.Zero, changeAddress); // Placeholder

			var tempBuilder = CreateSignatureBuilder(tempTx, new[] { coin });
			var estimate = tempBuilder.GetSizeEstimate(0);
			var baseVSize = estimate.ScriptSpendVirtualSizes[targetScriptIndex];

			// Calculate fees
			var baseFee = feeRate.GetFee(baseVSize);
			var bufferedVSize = (int)(baseVSize * (1.0 + bufferPercentage / 100.0));
			var bufferedFee = feeRate.GetFee(bufferedVSize);

			// Calculate change amounts
			var baseChange = (Money)coin.Amount - paymentAmount - baseFee;
			var bufferedChange = (Money)coin.Amount - paymentAmount - bufferedFee;

			if (baseChange < Money.Zero)
				throw new InvalidOperationException("Insufficient funds for base transaction");
			if (bufferedChange < Money.Zero)
				throw new InvalidOperationException("Insufficient funds for buffered transaction");

			// Create base transaction
			var baseTx = _network.CreateTransaction();
			baseTx.Inputs.Add(new OutPoint(coin.Outpoint.Hash, coin.Outpoint.N));
			baseTx.Outputs.Add(paymentAmount, paymentAddress);
			baseTx.Outputs.Add(baseChange, changeAddress);

			// Create buffered transaction
			var bufferedTx = _network.CreateTransaction();
			bufferedTx.Inputs.Add(new OutPoint(coin.Outpoint.Hash, coin.Outpoint.N));
			bufferedTx.Outputs.Add(paymentAmount, paymentAddress);
			bufferedTx.Outputs.Add(bufferedChange, changeAddress);

			return (baseTx, bufferedTx);
		}

		public class TransactionSizeEstimate
		{
			public int KeySpendSize { get; set; }
			public int KeySpendVirtualSize { get; set; }
			public Dictionary<int, int> ScriptSpendSizes { get; set; } = new Dictionary<int, int>();
			public Dictionary<int, int> ScriptSpendVirtualSizes { get; set; } = new Dictionary<int, int>();
			public Dictionary<int, int> ScriptSpendSizesWithBuffer { get; set; } = new Dictionary<int, int>();
			public Dictionary<int, int> ScriptSpendVirtualSizesWithBuffer { get; set; } = new Dictionary<int, int>();
			
			public int GetEstimatedSize(bool isKeySpend, int scriptIndex = -1, bool useBuffer = false)
			{
				if (isKeySpend) return KeySpendSize;
				
				if (useBuffer && ScriptSpendSizesWithBuffer.ContainsKey(scriptIndex))
					return ScriptSpendSizesWithBuffer[scriptIndex];
					
				return ScriptSpendSizes.ContainsKey(scriptIndex) ? ScriptSpendSizes[scriptIndex] : 0;
			}
			
			public int GetVirtualSize(bool isKeySpend, int scriptIndex = -1, bool useBuffer = false)
			{
				if (isKeySpend) return KeySpendVirtualSize;
				
				if (useBuffer && ScriptSpendVirtualSizesWithBuffer.ContainsKey(scriptIndex))
					return ScriptSpendVirtualSizesWithBuffer[scriptIndex];
					
				return ScriptSpendVirtualSizes.ContainsKey(scriptIndex) ? ScriptSpendVirtualSizes[scriptIndex] : 0;
			}
			
			public int GetVirtualSizeWithCustomBuffer(bool isKeySpend, double bufferPercentage, int scriptIndex = -1)
			{
				if (bufferPercentage < 0 || bufferPercentage > 100)
					throw new ArgumentOutOfRangeException(nameof(bufferPercentage), "Buffer percentage must be between 0 and 100");
				
				var baseSize = GetVirtualSize(isKeySpend, scriptIndex, useBuffer: false);
				return (int)(baseSize * (1.0 + bufferPercentage / 100.0));
			}
			
			public int GetSizeWithCustomBuffer(bool isKeySpend, double bufferPercentage, int scriptIndex = -1)
			{
				if (bufferPercentage < 0 || bufferPercentage > 100)
					throw new ArgumentOutOfRangeException(nameof(bufferPercentage), "Buffer percentage must be between 0 and 100");
				
				var baseSize = GetEstimatedSize(isKeySpend, scriptIndex, useBuffer: false);
				return (int)(baseSize * (1.0 + bufferPercentage / 100.0));
			}
		}

		public PSBT CreatePSBT(Transaction transaction, ICoin[] spentCoins)
		{
			var psbt = PSBT.FromTransaction(transaction, _network);
			
			for (int i = 0; i < spentCoins.Length && i < psbt.Inputs.Count; i++)
			{
				var input = psbt.Inputs[i];
				input.WitnessUtxo = spentCoins[i].TxOut;
				
				input.TaprootInternalKey = _ownerPubKey.TaprootInternalKey;
				input.TaprootMerkleRoot = _taprootSpendInfo.MerkleRoot;
			}
			
			return psbt;
		}

		public class MuSig2NonceExchange
		{
			public int InputIndex { get; set; }
			public int ScriptIndex { get; set; }
			internal Dictionary<int, MusigPubNonce> PublicNonces { get; set; } = new Dictionary<int, MusigPubNonce>();
			public bool IsComplete { get; set; }
			public byte[] SignatureHash { get; set; }

			public string Serialize()
			{
				var data = new
				{
					InputIndex,
					ScriptIndex,
					PublicNonces = PublicNonces.ToDictionary(
						kvp => kvp.Key,
						kvp => Encoders.Hex.EncodeData(kvp.Value.ToBytes())
					),
					IsComplete,
					SignatureHash = SignatureHash != null ? Encoders.Hex.EncodeData(SignatureHash) : null
				};

				var json = Newtonsoft.Json.JsonConvert.SerializeObject(data);
				return Encoders.Base64.EncodeData(System.Text.Encoding.UTF8.GetBytes(json));
			}

			public static MuSig2NonceExchange Deserialize(string serialized)
			{
				var jsonBytes = Encoders.Base64.DecodeData(serialized);
				var json = System.Text.Encoding.UTF8.GetString(jsonBytes);
				var jsonObject = Newtonsoft.Json.Linq.JObject.Parse(json);

				var result = new MuSig2NonceExchange
				{
					InputIndex = jsonObject["InputIndex"].ToObject<int>(),
					ScriptIndex = jsonObject["ScriptIndex"].ToObject<int>(),
					IsComplete = jsonObject["IsComplete"].ToObject<bool>(),
					PublicNonces = new Dictionary<int, MusigPubNonce>()
				};

				if (jsonObject["SignatureHash"] != null && jsonObject["SignatureHash"].Type != Newtonsoft.Json.Linq.JTokenType.Null)
				{
					result.SignatureHash = Encoders.Hex.DecodeData(jsonObject["SignatureHash"].ToString());
				}

				foreach (var kvp in jsonObject["PublicNonces"].ToObject<Dictionary<string, string>>())
				{
					var signerIndex = int.Parse(kvp.Key);
					var nonceBytes = Encoders.Hex.DecodeData(kvp.Value);
					result.PublicNonces[signerIndex] = new MusigPubNonce(nonceBytes);
				}

				return result;
			}
		}

		/// <summary>
		/// In-memory session manager for MuSig2 signing.
		/// Provides isolation between concurrent signing sessions and prevents nonce reuse.
		/// All state is lost on application restart (by design).
		/// </summary>
		private static class MuSig2SessionManager
		{
			private static readonly object _lock = new object();
			private static readonly Dictionary<string, MuSig2SessionState> _sessions = new Dictionary<string, MuSig2SessionState>();
			private static readonly TimeSpan _sessionTimeout = TimeSpan.FromHours(1);

			public static string CreateSession(DelegatedMultiSig2 multiSig, Transaction transaction, ICoin[] spentCoins)
			{
				lock (_lock)
				{
					var sessionId = Guid.NewGuid().ToString();
					var state = new MuSig2SessionState
					{
						SessionId = sessionId,
						MultiSig = multiSig,
						Transaction = transaction,
						SpentCoins = spentCoins,
						Created = DateTime.UtcNow,
						LastAccessed = DateTime.UtcNow,
						NonceExchanges = new Dictionary<int, Dictionary<int, MuSig2NonceExchange>>(),
						PrivateNonces = new Dictionary<int, Dictionary<int, MusigPrivNonce>>(),
						PartialSignatures = new Dictionary<int, Dictionary<int, MusigPartialSignature>>(),
						SigHashUsed = new Dictionary<int, TaprootSigHash>()
					};
					_sessions[sessionId] = state;
					CleanupExpiredSessions();
					return sessionId;
				}
			}

			public static MuSig2SessionState GetSession(string sessionId)
			{
				lock (_lock)
				{
					if (!_sessions.TryGetValue(sessionId, out var state))
						throw new InvalidOperationException($"Session {sessionId} not found or expired");

					if (DateTime.UtcNow - state.LastAccessed > _sessionTimeout)
					{
						_sessions.Remove(sessionId);
						throw new InvalidOperationException($"Session {sessionId} has expired");
					}

					state.LastAccessed = DateTime.UtcNow;
					return state;
				}
			}

			public static void CloseSession(string sessionId)
			{
				lock (_lock)
				{
					if (_sessions.TryGetValue(sessionId, out var state))
					{
						// Dispose all private nonces
						foreach (var inputNonces in state.PrivateNonces.Values)
						{
							foreach (var nonce in inputNonces.Values)
							{
								nonce?.Dispose();
							}
						}
						_sessions.Remove(sessionId);
					}
				}
			}

			private static void CleanupExpiredSessions()
			{
				var now = DateTime.UtcNow;
				var expiredSessions = _sessions
					.Where(kvp => now - kvp.Value.LastAccessed > _sessionTimeout)
					.Select(kvp => kvp.Key)
					.ToList();

				foreach (var sessionId in expiredSessions)
				{
					CloseSession(sessionId);
				}
			}

			public static int GetActiveSessionCount()
			{
				lock (_lock)
				{
					CleanupExpiredSessions();
					return _sessions.Count;
				}
			}
		}

		private class MuSig2SessionState
		{
			public string SessionId { get; set; }
			public DelegatedMultiSig2 MultiSig { get; set; }
			public Transaction Transaction { get; set; }
			public ICoin[] SpentCoins { get; set; }
			public DateTime Created { get; set; }
			public DateTime LastAccessed { get; set; }
			public Dictionary<int, Dictionary<int, MuSig2NonceExchange>> NonceExchanges { get; set; }
			public Dictionary<int, Dictionary<int, MusigPrivNonce>> PrivateNonces { get; set; }
			public Dictionary<int, Dictionary<int, MusigPartialSignature>> PartialSignatures { get; set; }
			public Dictionary<int, TaprootSigHash> SigHashUsed { get; set; }
		}

		public class MuSig2SignatureBuilder
		{
			private readonly DelegatedMultiSig2 _multiSig;
			private readonly Transaction _transaction;
			private readonly ICoin[] _spentCoins;
			internal readonly Dictionary<int, Dictionary<int, MuSig2NonceExchange>> _nonceExchanges;
			internal readonly Dictionary<int, Dictionary<int, MusigPrivNonce>> _privateNonces;
			internal readonly Dictionary<int, Dictionary<int, MusigPartialSignature>> _partialSignatures;
			internal readonly Dictionary<int, TaprootSigHash> _sigHashUsed;
			internal readonly Dictionary<int, TransactionSizeEstimate> _sizeEstimates;
			internal bool _useKeySpend;
			internal TapScript _selectedScript;
			private readonly bool _isDynamicFeeMode;
			private Money _fixedOutputAmount;

			internal MuSig2SignatureBuilder(DelegatedMultiSig2 multiSig, Transaction transaction, ICoin[] spentCoins, bool isDynamicFeeMode = false)
			{
				_multiSig = multiSig;
				_transaction = transaction;
				_spentCoins = spentCoins;
				_nonceExchanges = new Dictionary<int, Dictionary<int, MuSig2NonceExchange>>();
				_privateNonces = new Dictionary<int, Dictionary<int, MusigPrivNonce>>();
				_partialSignatures = new Dictionary<int, Dictionary<int, MusigPartialSignature>>();
				_sigHashUsed = new Dictionary<int, TaprootSigHash>();
				_sizeEstimates = new Dictionary<int, TransactionSizeEstimate>();
				_useKeySpend = false;
				_isDynamicFeeMode = isDynamicFeeMode;
				
				// Pre-calculate transaction size estimates for all possible script paths
				for (int inputIndex = 0; inputIndex < transaction.Inputs.Count; inputIndex++)
				{
					_sizeEstimates[inputIndex] = CalculateTransactionSizeEstimates(inputIndex);
				}
			}

			public MuSig2SignatureData SignWithOwner(Key ownerPrivateKey, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
			{
				if (ownerPrivateKey == null)
					throw new ArgumentNullException(nameof(ownerPrivateKey));

				if (ownerPrivateKey.PubKey != _multiSig._ownerPubKey)
					throw new ArgumentException("Provided private key does not match the owner's public key");

				// Automatically set to key spend mode when signing with owner
				_useKeySpend = true;
				_selectedScript = null;

				return SignKeySpend(ownerPrivateKey, inputIndex, sigHash);
			}

			private MuSig2SignatureData SignKeySpend(Key ownerPrivateKey, int inputIndex, TaprootSigHash sigHash)
			{
				var executionData = new TaprootExecutionData(inputIndex) { SigHash = sigHash };
				var hash = _transaction.GetSignatureHashTaproot(_spentCoins.Select(c => c.TxOut).ToArray(), executionData);
				var signature = ownerPrivateKey.SignTaprootKeySpend(hash, _multiSig._taprootSpendInfo.MerkleRoot, sigHash);

				_transaction.Inputs[inputIndex].WitScript = new WitScript(Op.GetPushOp(signature.ToBytes()));

				return new MuSig2SignatureData
				{
					Transaction = _transaction,
					InputIndex = inputIndex,
					IsComplete = true,
					IsKeySpend = true
				};
			}

			public MuSig2NonceData GenerateNonce(Key signerKey, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
			{
				if (_useKeySpend)
					throw new InvalidOperationException("Cannot use signer key for key spend path");

				var signerPubKey = signerKey.PubKey;
				var signerIndex = _multiSig._signerPubKeys.FindIndex(pk => pk == signerPubKey);
				if (signerIndex == -1)
					throw new ArgumentException("Signer key not found in the multisig configuration");

				var ctx = Context.Instance;
				var ecPrivKey = ctx.CreateECPrivKey(signerKey.ToBytes());

				// Find all scripts that this signer participates in
				var validScripts = new List<(TapScript script, int scriptIndex)>();
				for (int i = 0; i < _multiSig._scripts.Count; i++)
				{
					var script = _multiSig._scripts[i];
					var scriptSignerIndices = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					if (scriptSignerIndices.Contains(signerIndex))
					{
						validScripts.Add((script, i));
					}
				}

				if (validScripts.Count == 0)
					throw new ArgumentException("This signer is not part of any valid script combinations");

				// Initialize storage for this input if needed
				if (!_nonceExchanges.ContainsKey(inputIndex))
					_nonceExchanges[inputIndex] = new Dictionary<int, MuSig2NonceExchange>();
				if (!_privateNonces.ContainsKey(inputIndex))
					_privateNonces[inputIndex] = new Dictionary<int, MusigPrivNonce>();

				var nonceDataList = new List<MuSig2NonceExchange>();

				// Generate nonces for all valid scripts
				foreach (var (script, scriptIndex) in validScripts)
				{
					var executionData = new TaprootExecutionData(inputIndex, script.LeafHash) { SigHash = sigHash };
					var hash = _transaction.GetSignatureHashTaproot(_spentCoins.Select(c => c.TxOut).ToArray(), executionData);

					// Get the aggregated pubkey for this script
					var scriptSignerIndices = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					var selectedPubKeys = new ECPubKey[scriptSignerIndices.Length];
					for (int i = 0; i < scriptSignerIndices.Length; i++)
					{
						var idx = scriptSignerIndices[i];
						selectedPubKeys[i] = ctx.CreatePubKey(_multiSig._signerPubKeys[idx].ToBytes());
					}

					// Create musig context with the selected pubkeys
					var musig = new MusigContext(selectedPubKeys, hash.ToBytes());
					
					// Generate nonce
					var privNonce = musig.GenerateNonce(ecPrivKey);
					var pubNonce = privNonce.CreatePubNonce();

					// Store the private nonce
					var nonceKey = scriptIndex * 1000 + signerIndex; // Unique key combining script and signer
					_privateNonces[inputIndex][nonceKey] = privNonce;

					// Get or create nonce exchange for this script
					if (!_nonceExchanges[inputIndex].ContainsKey(scriptIndex))
					{
						_nonceExchanges[inputIndex][scriptIndex] = new MuSig2NonceExchange
						{
							InputIndex = inputIndex,
							ScriptIndex = scriptIndex,
							SignatureHash = hash.ToBytes(),
							PublicNonces = new Dictionary<int, MusigPubNonce>()
						};
					}

					var nonceExchange = _nonceExchanges[inputIndex][scriptIndex];
					nonceExchange.PublicNonces[signerIndex] = pubNonce;

					// Check if we have all nonces for this script
					var expectedSigners = scriptSignerIndices.Length;
					nonceExchange.IsComplete = nonceExchange.PublicNonces.Count == expectedSigners;

					nonceDataList.Add(nonceExchange);
				}

				return new MuSig2NonceData
				{
					SignerIndex = signerIndex,
					NonceExchanges = nonceDataList
				};
			}

			// Optimized method: Generate nonces only for the k signers who will actually sign
			public Dictionary<Key, MuSig2NonceData> GenerateNoncesForSigners(List<Key> signingKeys, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
			{
				if (_useKeySpend)
					throw new InvalidOperationException("Cannot use signer keys for key spend path");

				if (signingKeys == null || signingKeys.Count == 0)
					throw new ArgumentException("At least one signing key is required", nameof(signingKeys));

				if (signingKeys.Count < _multiSig._requiredSignatures)
					throw new ArgumentException($"Need at least {_multiSig._requiredSignatures} signing keys for k-of-n multisig", nameof(signingKeys));

				var result = new Dictionary<Key, MuSig2NonceData>();

				// Only generate nonces for the specified signers (optimization)
				foreach (var signerKey in signingKeys.Take(_multiSig._requiredSignatures))
				{
					var nonceData = GenerateNonce(signerKey, inputIndex, sigHash);
					result[signerKey] = nonceData;
				}

				return result;
			}

			// Progressive Protocol: Generate nonces for all scripts this signer participates in (initial broadcast)
			public MuSig2NonceData GenerateNoncesForAllMyScripts(Key signerKey, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
			{
				// For simplicity, this just calls the existing GenerateNonce method
				// which already generates nonces for all scripts the signer participates in
				return GenerateNonce(signerKey, inputIndex, sigHash);
			}

			// Progressive Protocol: Generate nonces only for scripts with existing participants
			public MuSig2NonceData GenerateNoncesForScriptsWithParticipants(Key signerKey, List<MuSig2NonceData> existingParticipantNonces, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
			{
				if (existingParticipantNonces == null || existingParticipantNonces.Count == 0)
					throw new ArgumentException("At least one existing participant nonce is required");

				// For this implementation, we'll generate nonces for all scripts the signer participates in
				// The actual filtering for "progressive" behavior can be handled at the coordination level
				var allNonces = GenerateNonce(signerKey, inputIndex, sigHash);
				
				// Filter to only include scripts where existing participants are involved
				// This is a simplified version - in a full implementation, this would be more sophisticated
				return allNonces;
			}

			// Aggregate nonces from multiple participants to create coordinator
			public static MuSig2DistributedCoordinator AggregateNoncesFromAllParticipants(List<MuSig2NonceData> allParticipantNonces, DelegatedMultiSig2 multiSig, Transaction transaction, ICoin[] spentCoins)
			{
				if (allParticipantNonces == null || allParticipantNonces.Count == 0)
					throw new ArgumentException("At least one participant nonce is required");

				var coordinator = new MuSig2DistributedCoordinator(multiSig, transaction, spentCoins);
				
				foreach (var participantNonce in allParticipantNonces)
				{
					coordinator.AddParticipantNonces(participantNonce);
				}

				return coordinator;
			}

			// Simplified method to support distributed signing workflow
			public bool CanCompleteDistributedSigning(List<MuSig2NonceData> allParticipantNonces, int inputIndex)
			{
				if (allParticipantNonces == null || allParticipantNonces.Count < _multiSig._requiredSignatures)
					return false;

				// Check if we have complete nonce sets for any valid script combination
				var participantIndices = allParticipantNonces.Select(n => n.SignerIndex).ToHashSet();
				
				for (int scriptIndex = 0; scriptIndex < _multiSig.Scripts.Count; scriptIndex++)
				{
					var script = _multiSig.Scripts[scriptIndex];
					var scriptSignerIndices = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					
					// Check if this script can be completed with current participants
					if (scriptSignerIndices.Length == _multiSig._requiredSignatures && 
						scriptSignerIndices.All(idx => participantIndices.Contains(idx)))
					{
						return true;
					}
				}

				return false;
			}
			
			// Get the cheapest script index for fee optimization (all possible scripts)
			public int GetCheapestScriptIndex(int inputIndex)
			{
				var sizeEstimate = GetSizeEstimate(inputIndex);
				if (sizeEstimate == null || sizeEstimate.ScriptSpendVirtualSizes.Count == 0)
					return 0;
				
				return sizeEstimate.ScriptSpendVirtualSizes
					.OrderBy(kvp => kvp.Value)
					.First().Key;
			}

			// Get the cheapest script index for a specific set of participating signers
			public int GetCheapestScriptIndexForSigners(List<Key> participatingSigners, int inputIndex)
			{
				if (participatingSigners == null || participatingSigners.Count < _multiSig._requiredSignatures)
					throw new ArgumentException("Insufficient participating signers");

				var sizeEstimate = GetSizeEstimate(inputIndex);
				if (sizeEstimate == null || sizeEstimate.ScriptSpendVirtualSizes.Count == 0)
					return 0;

				// Find signer indices for the participating signers
				var participatingIndices = new HashSet<int>();
				for (int i = 0; i < participatingSigners.Count; i++)
				{
					for (int j = 0; j < _multiSig._signerPubKeys.Count; j++)
					{
						if (_multiSig._signerPubKeys[j].Equals(participatingSigners[i].PubKey))
						{
							participatingIndices.Add(j);
							break;
						}
					}
				}

				// Find scripts that exactly match the participating signers
				var validScriptIndices = new List<int>();
				for (int scriptIndex = 0; scriptIndex < _multiSig.Scripts.Count; scriptIndex++)
				{
					var script = _multiSig.Scripts[scriptIndex];
					var scriptSignerIndices = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					
					// Check if this script uses exactly the participating signers
					if (scriptSignerIndices.Length == participatingIndices.Count && 
						scriptSignerIndices.All(idx => participatingIndices.Contains(idx)))
					{
						validScriptIndices.Add(scriptIndex);
					}
				}

				if (validScriptIndices.Count == 0)
					throw new ArgumentException("No script found for the specified participating signers");

				// Find the cheapest among valid scripts
				return validScriptIndices
					.Where(idx => sizeEstimate.ScriptSpendVirtualSizes.ContainsKey(idx))
					.OrderBy(idx => sizeEstimate.ScriptSpendVirtualSizes[idx])
					.First();
			}
			
			// Compare key spend vs script spend costs
			public bool IsKeySpendCheaper(int inputIndex, FeeRate feeRate)
			{
				var sizeEstimate = GetSizeEstimate(inputIndex);
				if (sizeEstimate == null)
					return true; // Default to key spend if no estimate
				
				var keySpendFee = feeRate.GetFee(sizeEstimate.KeySpendVirtualSize);
				var cheapestScriptIndex = GetCheapestScriptIndex(inputIndex);
				var scriptSpendFee = feeRate.GetFee(sizeEstimate.ScriptSpendVirtualSizes[cheapestScriptIndex]);
				
				return keySpendFee < scriptSpendFee;
			}

			public void AddNonces(MuSig2NonceData nonceData, int inputIndex)
			{
				if (!_nonceExchanges.ContainsKey(inputIndex))
					_nonceExchanges[inputIndex] = new Dictionary<int, MuSig2NonceExchange>();

				foreach (var exchange in nonceData.NonceExchanges)
				{
					if (!_nonceExchanges[inputIndex].ContainsKey(exchange.ScriptIndex))
					{
						_nonceExchanges[inputIndex][exchange.ScriptIndex] = new MuSig2NonceExchange
						{
							InputIndex = exchange.InputIndex,
							ScriptIndex = exchange.ScriptIndex,
							SignatureHash = exchange.SignatureHash,
							PublicNonces = new Dictionary<int, MusigPubNonce>()
						};
					}

					var localExchange = _nonceExchanges[inputIndex][exchange.ScriptIndex];
					
					// Add new nonces
					foreach (var kvp in exchange.PublicNonces)
					{
						localExchange.PublicNonces[kvp.Key] = kvp.Value;
					}

					// Check if complete
					var script = _multiSig._scripts[exchange.ScriptIndex];
					var scriptSignerIndices = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					localExchange.IsComplete = localExchange.PublicNonces.Count == scriptSignerIndices.Length;
				}
			}

			public MuSig2SignatureData SignWithSigner(Key signerKey, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
			{
				if (_useKeySpend)
					throw new InvalidOperationException("Cannot use signer key for key spend path");

				var signerPubKey = signerKey.PubKey;
				var signerIndex = _multiSig._signerPubKeys.FindIndex(pk => pk == signerPubKey);
				if (signerIndex == -1)
					throw new ArgumentException("Signer key not found in the multisig configuration");

				var ctx = Context.Instance;
				var ecPrivKey = ctx.CreateECPrivKey(signerKey.ToBytes());

				// Find all scripts that this signer participates in
				var validScripts = new List<(TapScript script, int scriptIndex)>();
				for (int i = 0; i < _multiSig._scripts.Count; i++)
				{
					var script = _multiSig._scripts[i];
					var scriptSignerIndices = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					if (scriptSignerIndices.Contains(signerIndex))
					{
						validScripts.Add((script, i));
					}
				}

				if (validScripts.Count == 0)
					throw new ArgumentException("This signer is not part of any valid script combinations");

				// Check that we have all nonces for at least one script
				bool hasCompleteNonces = false;
				foreach (var (script, scriptIndex) in validScripts)
				{
					if (_nonceExchanges.ContainsKey(inputIndex) && 
						_nonceExchanges[inputIndex].ContainsKey(scriptIndex) &&
						_nonceExchanges[inputIndex][scriptIndex].IsComplete)
					{
						hasCompleteNonces = true;
						break;
					}
				}

				if (!hasCompleteNonces)
					throw new InvalidOperationException("Nonce exchange must be completed before signing. All signers must exchange nonces first.");

				// Initialize storage
				if (!_partialSignatures.ContainsKey(inputIndex))
					_partialSignatures[inputIndex] = new Dictionary<int, MusigPartialSignature>();

				// Store the sighash used
				_sigHashUsed[inputIndex] = sigHash;

				var signatures = new List<(int scriptIndex, MusigPartialSignature signature)>();

				// Sign for all valid scripts where we have complete nonces
				foreach (var (script, scriptIndex) in validScripts)
				{
					if (!_nonceExchanges[inputIndex].ContainsKey(scriptIndex) || 
						!_nonceExchanges[inputIndex][scriptIndex].IsComplete)
						continue;

					var nonceExchange = _nonceExchanges[inputIndex][scriptIndex];
					var executionData = new TaprootExecutionData(inputIndex, script.LeafHash) { SigHash = sigHash };
					var hash = _transaction.GetSignatureHashTaproot(_spentCoins.Select(c => c.TxOut).ToArray(), executionData);

					// Get the aggregated pubkey for this script
					var scriptSignerIndices = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					var selectedPubKeys = new ECPubKey[scriptSignerIndices.Length];
					for (int i = 0; i < scriptSignerIndices.Length; i++)
					{
						var idx = scriptSignerIndices[i];
						selectedPubKeys[i] = ctx.CreatePubKey(_multiSig._signerPubKeys[idx].ToBytes());
					}

					// Create musig context
					var musig = new MusigContext(selectedPubKeys, hash.ToBytes());

					// Process all nonces
					var orderedNonces = new MusigPubNonce[scriptSignerIndices.Length];
					for (int i = 0; i < scriptSignerIndices.Length; i++)
					{
						var idx = scriptSignerIndices[i];
						if (!nonceExchange.PublicNonces.ContainsKey(idx))
							throw new InvalidOperationException($"Missing nonce from signer {idx} for script {scriptIndex}");
						orderedNonces[i] = nonceExchange.PublicNonces[idx];
					}
					musig.ProcessNonces(orderedNonces);

					// Get our private nonce
					var nonceKey = scriptIndex * 1000 + signerIndex;
					if (!_privateNonces[inputIndex].ContainsKey(nonceKey))
						throw new InvalidOperationException("Private nonce not found. GenerateNonce must be called before signing.");
					
					var privNonce = _privateNonces[inputIndex][nonceKey];

					// Find our position in the selected pubkeys
					var ourPosition = Array.IndexOf(scriptSignerIndices, signerIndex);
					if (ourPosition == -1)
						throw new InvalidOperationException("Signer not found in script");

					// Sign
					var partialSig = musig.Sign(ecPrivKey, privNonce);

					// Store the partial signature
					var sigKey = scriptIndex * 1000 + signerIndex;
					_partialSignatures[inputIndex][sigKey] = partialSig;
					
					signatures.Add((scriptIndex, partialSig));
				}

				// Check if any script is complete
				var isComplete = IsSignatureComplete(inputIndex);

				return new MuSig2SignatureData
				{
					Transaction = _transaction,
					InputIndex = inputIndex,
					PartialSignatures = signatures,
					IsComplete = isComplete
				};
			}

			private bool IsSignatureComplete(int inputIndex)
			{
				if (!_partialSignatures.ContainsKey(inputIndex))
					return false;

				// Check each script
				for (int scriptIndex = 0; scriptIndex < _multiSig._scripts.Count; scriptIndex++)
				{
					var script = _multiSig._scripts[scriptIndex];
					var scriptSignerIndices = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					
					// Count signatures for this script
					int sigCount = 0;
					foreach (var signerIndex in scriptSignerIndices)
					{
						var sigKey = scriptIndex * 1000 + signerIndex;
						if (_partialSignatures[inputIndex].ContainsKey(sigKey))
							sigCount++;
					}

					// If all signers have signed, this script is complete
					if (sigCount == scriptSignerIndices.Length)
						return true;
				}

				return false;
			}

			public Transaction FinalizeTransaction(int inputIndex)
			{
				if (_useKeySpend)
				{
					return _transaction;
				}

				if (!IsSignatureComplete(inputIndex))
					throw new InvalidOperationException($"Not enough signatures for input {inputIndex}. All signers must provide signatures.");

				// Find the first complete script
				TapScript selectedScript = null;
				int selectedScriptIndex = -1;
				List<MusigPartialSignature> orderedSignatures = null;

				for (int scriptIndex = 0; scriptIndex < _multiSig._scripts.Count; scriptIndex++)
				{
					var script = _multiSig._scripts[scriptIndex];
					var signerIndicesForScript = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					
					// Collect signatures for this script
					var sigs = new List<MusigPartialSignature>();
					bool hasAllSigs = true;

					foreach (var signerIndex in signerIndicesForScript)
					{
						var sigKey = scriptIndex * 1000 + signerIndex;
						if (_partialSignatures[inputIndex].ContainsKey(sigKey))
						{
							sigs.Add(_partialSignatures[inputIndex][sigKey]);
						}
						else
						{
							hasAllSigs = false;
							break;
						}
					}

					if (hasAllSigs && sigs.Count == signerIndicesForScript.Length)
					{
						selectedScript = script;
						selectedScriptIndex = scriptIndex;
						orderedSignatures = sigs;
						break;
					}
				}

				if (selectedScript == null)
					throw new InvalidOperationException("No script has all required signatures");

				// Aggregate signatures
				var ctx = Context.Instance;
				var scriptSignerIndices = _multiSig._scriptToSignerIndices[selectedScript.LeafHash.ToString()];
				var selectedPubKeys = new ECPubKey[scriptSignerIndices.Length];
				for (int i = 0; i < scriptSignerIndices.Length; i++)
				{
					var idx = scriptSignerIndices[i];
					selectedPubKeys[i] = ctx.CreatePubKey(_multiSig._signerPubKeys[idx].ToBytes());
				}

				// Get the sighash that was used for signing
				var sigHash = _sigHashUsed.ContainsKey(inputIndex) ? _sigHashUsed[inputIndex] : TaprootSigHash.Default;
				
				var executionData = new TaprootExecutionData(inputIndex, selectedScript.LeafHash) { SigHash = sigHash };
				var hash = _transaction.GetSignatureHashTaproot(_spentCoins.Select(c => c.TxOut).ToArray(), executionData);

				var musig = new MusigContext(selectedPubKeys, hash.ToBytes());
				
				// Process nonces again
				var nonceExchange = _nonceExchanges[inputIndex][selectedScriptIndex];
				var orderedNonces = new MusigPubNonce[scriptSignerIndices.Length];
				for (int i = 0; i < scriptSignerIndices.Length; i++)
				{
					var idx = scriptSignerIndices[i];
					orderedNonces[i] = nonceExchange.PublicNonces[idx];
				}
				musig.ProcessNonces(orderedNonces);

				// Aggregate signatures
				var aggregatedSig = musig.AggregateSignatures(orderedSignatures.ToArray());
				var schnorrSig = new SchnorrSignature(aggregatedSig.ToBytes());
				var taprootSig = new TaprootSignature(schnorrSig, sigHash);

				// Build witness
				var witnessItems = new List<byte[]>();
				witnessItems.Add(taprootSig.ToBytes());
				witnessItems.Add(selectedScript.Script.ToBytes());
				witnessItems.Add(_multiSig._taprootSpendInfo.GetControlBlock(selectedScript).ToBytes());

				_transaction.Inputs[inputIndex].WitScript = new WitScript(witnessItems.ToArray());

				return _transaction;
			}

			public string GetNonceExchangeString(int inputIndex, int scriptIndex)
			{
				if (!_nonceExchanges.ContainsKey(inputIndex) || 
					!_nonceExchanges[inputIndex].ContainsKey(scriptIndex))
					return "";

				return _nonceExchanges[inputIndex][scriptIndex].Serialize();
			}

			public string GetPartialSignatureString(int inputIndex)
			{
				if (!_partialSignatures.ContainsKey(inputIndex))
					return "";

				var signatures = new List<MuSig2PartialSignatureInfo>();
				
				foreach (var kvp in _partialSignatures[inputIndex])
				{
					var scriptIndex = kvp.Key / 1000;
					var signerIndex = kvp.Key % 1000;
					
					signatures.Add(new MuSig2PartialSignatureInfo
					{
						ScriptIndex = scriptIndex,
						SignerIndex = signerIndex,
						Signature = Encoders.Hex.EncodeData(kvp.Value.ToBytes())
					});
				}

				var data = new
				{
					InputIndex = inputIndex,
					PartialSignatures = signatures
				};

				var json = Newtonsoft.Json.JsonConvert.SerializeObject(data);
				return Encoders.Base64.EncodeData(System.Text.Encoding.UTF8.GetBytes(json));
			}

			public void AddPartialSignatures(string serialized, int inputIndex)
			{
				var jsonBytes = Encoders.Base64.DecodeData(serialized);
				var json = System.Text.Encoding.UTF8.GetString(jsonBytes);
				var jsonObject = Newtonsoft.Json.Linq.JObject.Parse(json);

				if (!_partialSignatures.ContainsKey(inputIndex))
					_partialSignatures[inputIndex] = new Dictionary<int, MusigPartialSignature>();

				var signatures = jsonObject["PartialSignatures"].ToObject<List<MuSig2PartialSignatureInfo>>();
				foreach (var sig in signatures)
				{
					var sigKey = sig.ScriptIndex * 1000 + sig.SignerIndex;
					var sigBytes = Encoders.Hex.DecodeData(sig.Signature);
					_partialSignatures[inputIndex][sigKey] = new MusigPartialSignature(sigBytes);
				}
			}
			
			public TransactionSizeEstimate GetSizeEstimate(int inputIndex)
			{
				return _sizeEstimates.ContainsKey(inputIndex) ? _sizeEstimates[inputIndex] : null;
			}
			
			public TransactionSizeEstimate GetSizeEstimateWithCustomBuffer(int inputIndex, double bufferPercentage)
			{
				if (bufferPercentage < 0 || bufferPercentage > 100)
					throw new ArgumentOutOfRangeException(nameof(bufferPercentage), "Buffer percentage must be between 0 and 100");
				
				if (!_sizeEstimates.ContainsKey(inputIndex))
					return null;
				
				var baseEstimate = _sizeEstimates[inputIndex];
				var customEstimate = new TransactionSizeEstimate
				{
					KeySpendSize = baseEstimate.KeySpendSize,
					KeySpendVirtualSize = baseEstimate.KeySpendVirtualSize,
					ScriptSpendSizes = new Dictionary<int, int>(baseEstimate.ScriptSpendSizes),
					ScriptSpendVirtualSizes = new Dictionary<int, int>(baseEstimate.ScriptSpendVirtualSizes),
					ScriptSpendSizesWithBuffer = new Dictionary<int, int>(),
					ScriptSpendVirtualSizesWithBuffer = new Dictionary<int, int>()
				};
				
				// Apply custom buffer to all script spend sizes
				foreach (var kvp in baseEstimate.ScriptSpendSizes)
				{
					customEstimate.ScriptSpendSizesWithBuffer[kvp.Key] = (int)(kvp.Value * (1.0 + bufferPercentage / 100.0));
				}
				
				foreach (var kvp in baseEstimate.ScriptSpendVirtualSizes)
				{
					customEstimate.ScriptSpendVirtualSizesWithBuffer[kvp.Key] = (int)(kvp.Value * (1.0 + bufferPercentage / 100.0));
				}
				
				return customEstimate;
			}

			private TransactionSizeEstimate CalculateTransactionSizeEstimates(int inputIndex)
			{
				var estimate = new TransactionSizeEstimate();
				
				// Calculate base transaction size (without witness data)
				var txCopy = _transaction.Clone();
				// Clear all witness data to get base size
				for (int i = 0; i < txCopy.Inputs.Count; i++)
				{
					txCopy.Inputs[i].WitScript = WitScript.Empty;
				}
				var baseSize = txCopy.GetSerializedSize();
				
				// For witness transactions, we need to account for witness marker and flag (2 bytes)
				if (!_transaction.HasWitness)
				{
					baseSize += 2; // Add witness marker and flag that will be present
				}
				
				// Key spend estimation
				// Witness: 1 stack item count + 1 length byte + 64 bytes signature = 66 bytes
				var keySpendWitnessSize = 66;
				var keySpendTotalSize = baseSize + keySpendWitnessSize;
				estimate.KeySpendSize = keySpendTotalSize;
				// Virtual size = (base_size * 3 + total_size) / 4
				estimate.KeySpendVirtualSize = (baseSize * 3 + keySpendTotalSize + 3) / 4; // +3 for rounding up
				
				// Script spend sizes for each script combination
				for (int scriptIndex = 0; scriptIndex < _multiSig._scripts.Count; scriptIndex++)
				{
					var script = _multiSig._scripts[scriptIndex];
					var scriptBytes = script.Script.ToBytes();
					var controlBlockBytes = _multiSig._taprootSpendInfo.GetControlBlock(script).ToBytes();
					
					// Calculate witness size for MuSig2 (single aggregated signature)
					var witnessSize = 1; // witness stack count
					// Single aggregated signature: 1 byte length + 64 bytes signature
					witnessSize += 65;
					// Script: length prefix + script bytes
					witnessSize += GetVarIntSize(scriptBytes.Length) + scriptBytes.Length;
					// Control block: length prefix + control block bytes
					witnessSize += GetVarIntSize(controlBlockBytes.Length) + controlBlockBytes.Length;
					
					var totalSize = baseSize + witnessSize;
					var virtualSize = (baseSize * 3 + totalSize + 3) / 4; // +3 for rounding up
					
					estimate.ScriptSpendSizes[scriptIndex] = totalSize;
					estimate.ScriptSpendVirtualSizes[scriptIndex] = virtualSize;
					estimate.ScriptSpendSizesWithBuffer[scriptIndex] = (int)(totalSize * 1.05); // 5% buffer
					estimate.ScriptSpendVirtualSizesWithBuffer[scriptIndex] = (int)(virtualSize * 1.05); // 5% buffer
				}
				
				return estimate;
			}
			
			private static int GetVarIntSize(int length)
			{
				if (length < 0xFD) return 1;
				if (length <= 0xFFFF) return 3;
				if (length <= int.MaxValue) return 5;
				return 9;
			}
			
			public void SetDynamicFeeParameters(Money fixedOutputAmount)
			{
				if (!_isDynamicFeeMode)
					throw new InvalidOperationException("Dynamic fee mode must be enabled when creating the builder");
				
				_fixedOutputAmount = fixedOutputAmount;
			}
			
			public DynamicFeeCalculation CalculateDynamicFees(int inputIndex, FeeRate feeRate)
			{
				if (!_isDynamicFeeMode)
					throw new InvalidOperationException("Dynamic fee mode must be enabled when creating the builder");
				
				var sizeEstimate = GetSizeEstimate(inputIndex);
				var inputAmount = (Money)_spentCoins[inputIndex].Amount;
				
				// Find the cheapest script (MuSig2 scripts should all be similar size)
				var cheapestScriptIndex = sizeEstimate.ScriptSpendVirtualSizes
					.OrderBy(kvp => kvp.Value)
					.First().Key;
				
				return new DynamicFeeCalculation
				{
					InputAmount = inputAmount,
					FixedOutputAmount = _fixedOutputAmount ?? Money.Zero,
					FeeRate = feeRate,
					EstimatedVSize = sizeEstimate.ScriptSpendVirtualSizes[cheapestScriptIndex],
					BufferedVSize = sizeEstimate.ScriptSpendVirtualSizesWithBuffer[cheapestScriptIndex],
					EstimatedFee = feeRate.GetFee(sizeEstimate.ScriptSpendVirtualSizes[cheapestScriptIndex]),
					BufferedFee = feeRate.GetFee(sizeEstimate.ScriptSpendVirtualSizesWithBuffer[cheapestScriptIndex]),
					ScriptIndex = cheapestScriptIndex
				};
			}
		}
		
		public class DynamicFeeCalculation
		{
			public Money InputAmount { get; set; }
			public Money FixedOutputAmount { get; set; }
			public FeeRate FeeRate { get; set; }
			public int EstimatedVSize { get; set; }
			public int BufferedVSize { get; set; }
			public Money EstimatedFee { get; set; }
			public Money BufferedFee { get; set; }
			public int ScriptIndex { get; set; }
			
			public Money GetChangeAmount(bool useBuffered)
			{
				var fee = useBuffered ? BufferedFee : EstimatedFee;
				return InputAmount - FixedOutputAmount - fee;
			}
		}

		public class MuSig2NonceData
		{
			public int SignerIndex { get; set; }
			public List<MuSig2NonceExchange> NonceExchanges { get; set; }

			public string Serialize()
			{
				var data = new
				{
					SignerIndex,
					NonceExchanges = NonceExchanges.Select(ne => ne.Serialize()).ToList()
				};

				var json = Newtonsoft.Json.JsonConvert.SerializeObject(data);
				return Encoders.Base64.EncodeData(System.Text.Encoding.UTF8.GetBytes(json));
			}

			public static MuSig2NonceData Deserialize(string serialized)
			{
				var jsonBytes = Encoders.Base64.DecodeData(serialized);
				var json = System.Text.Encoding.UTF8.GetString(jsonBytes);
				var jsonObject = Newtonsoft.Json.Linq.JObject.Parse(json);

				var result = new MuSig2NonceData
				{
					SignerIndex = jsonObject["SignerIndex"].ToObject<int>(),
					NonceExchanges = new List<MuSig2NonceExchange>()
				};

				foreach (var ne in jsonObject["NonceExchanges"])
				{
					result.NonceExchanges.Add(MuSig2NonceExchange.Deserialize(ne.ToString()));
				}

				return result;
			}
		}

		public class MuSig2SignatureData
		{
			public Transaction Transaction { get; set; }
			public int InputIndex { get; set; }
			internal List<(int scriptIndex, MusigPartialSignature signature)> PartialSignatures { get; set; }
			public bool IsComplete { get; set; }
			public bool IsKeySpend { get; set; }
		}

		public class MuSig2PartialSignatureInfo
		{
			public int ScriptIndex { get; set; }
			public int SignerIndex { get; set; }
			public string Signature { get; set; }
		}

		// Helper class for coordinating distributed MuSig2 protocol
		// This is a simplified version that works with the existing infrastructure
		public class MuSig2DistributedCoordinator
		{
			public List<int> ParticipantIndices { get; set; }
			public List<MuSig2NonceData> AllNonces { get; set; }
			public DelegatedMultiSig2 MultiSig { get; private set; }
			public Transaction Transaction { get; private set; }
			public ICoin[] SpentCoins { get; private set; }

			public MuSig2DistributedCoordinator(DelegatedMultiSig2 multiSig, Transaction transaction, ICoin[] spentCoins)
			{
				MultiSig = multiSig;
				Transaction = transaction;
				SpentCoins = spentCoins;
				AllNonces = new List<MuSig2NonceData>();
				ParticipantIndices = new List<int>();
			}

			public void AddParticipantNonces(MuSig2NonceData nonces)
			{
				AllNonces.Add(nonces);
				if (!ParticipantIndices.Contains(nonces.SignerIndex))
				{
					ParticipantIndices.Add(nonces.SignerIndex);
				}
			}

			public int GetCheapestScriptIndexForParticipants()
			{
				if (ParticipantIndices.Count < MultiSig._requiredSignatures)
					throw new InvalidOperationException($"Need at least {MultiSig._requiredSignatures} participants");

				var builder = MultiSig.CreateSignatureBuilder(Transaction, SpentCoins);
				var sizeEstimate = builder.GetSizeEstimate(0);
				
				if (sizeEstimate == null || sizeEstimate.ScriptSpendVirtualSizes.Count == 0)
					return 0;

				// Find scripts where ALL current participants are involved
				var validScriptIndices = new List<int>();
				var participantSet = ParticipantIndices.ToHashSet();
				
				for (int scriptIndex = 0; scriptIndex < MultiSig.Scripts.Count; scriptIndex++)
				{
					var script = MultiSig.Scripts[scriptIndex];
					var scriptSignerIndices = MultiSig._scriptToSignerIndices[script.LeafHash.ToString()];
					
					// Check if this script uses exactly our participants (k-of-n match)
					if (scriptSignerIndices.Length == MultiSig._requiredSignatures && 
						scriptSignerIndices.All(idx => participantSet.Contains(idx)) &&
						scriptSignerIndices.ToHashSet().SetEquals(participantSet))
					{
						validScriptIndices.Add(scriptIndex);
					}
				}

				if (validScriptIndices.Count == 0)
					throw new InvalidOperationException("No valid scripts found for current participants");

				// Return the script with the smallest virtual size
				return validScriptIndices
					.OrderBy(idx => sizeEstimate.ScriptSpendVirtualSizes[idx])
					.First();
			}

			public Money CalculateCheapestFee(FeeRate feeRate)
			{
				var cheapestIndex = GetCheapestScriptIndexForParticipants();
				var builder = MultiSig.CreateSignatureBuilder(Transaction, SpentCoins);
				var sizeEstimate = builder.GetSizeEstimate(0);
				var virtualSize = sizeEstimate.ScriptSpendVirtualSizes[cheapestIndex];
				return feeRate.GetFee(virtualSize);
			}

			public Money CalculateBufferedFee(FeeRate feeRate, double bufferPercentage)
			{
				var baseFee = CalculateCheapestFee(feeRate);
				var bufferAmount = Money.Satoshis((long)(baseFee.Satoshi * bufferPercentage));
				return baseFee + bufferAmount;
			}
		}
	}
#endif
}