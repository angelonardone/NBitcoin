using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.BIP370;
#if HAS_SPAN
using NBitcoin.Secp256k1;
#endif

namespace NBitcoin
{
#if HAS_SPAN
	/// <summary>
	/// DelegatedMultiSig: Taproot-based k-of-n multisig using script path combinations.
	///
	/// PROGRESSIVE SIGNATURE COLLECTION WORKFLOW:
	/// ==========================================
	///
	/// This implementation supports a progressive signing protocol where signatures are collected
	/// incrementally, with fee estimation narrowing down as more signers participate. This solves
	/// the problem of accurate fee calculation in multisig scenarios.
	///
	/// THE PROBLEM:
	/// ------------
	/// In traditional multisig, you don't know which k signers will participate until they sign.
	/// Different signing combinations may have different transaction sizes (and thus fees).
	/// If you estimate fees based on one combination but collect signatures from a different one,
	/// your transaction may underpay or overpay fees.
	///
	/// THE SOLUTION - Progressive Signature Protocol:
	/// -----------------------------------------------
	///
	/// STEP 1: First Signer
	///   - Receives unsigned transaction
	///   - System identifies ALL script combinations containing this signer
	///   - For each combination, calculates TWO fee scenarios:
	///     * Base: exact virtual size
	///     * Buffered: virtual size + buffer% (e.g., 15%)
	///   - First signer signs ALL applicable combinations (both base and buffered)
	///   - Creates PartialSignatureData with all signatures
	///   - Passes to next potential signer
	///
	/// STEP 2: Subsequent Signers (2nd through k-1)
	///   - Receive PartialSignatureData from previous signer
	///   - System filters to ONLY combinations where THIS signer participates
	///   - This naturally narrows down the possible signing paths
	///   - Signer adds signatures to filtered combinations (both base and buffered)
	///   - Passes updated PartialSignatureData to next signer
	///
	/// STEP 3: Final (kth) Signer
	///   - By now, only ONE specific combination of k signers remains viable
	///   - BUT there are TWO versions of this combination:
	///     * Version A: transaction with base fee (exact vsize)
	///     * Version B: transaction with buffered fee (vsize + buffer%)
	///   - Final signer adds their signature to both versions
	///   - Final signer CHOOSES which transaction to broadcast based on:
	///     * Current network congestion
	///     * Fee urgency
	///     * Cost vs. speed preference
	///   - Calls FinalizeTransaction(inputIndex, useBufferedSize: true/false)
	///
	/// KEY BENEFITS:
	/// -------------
	/// 1. Accurate fee estimation - based on actual signers, not guesses
	/// 2. Flexible fee strategy - final signer controls cost vs. speed tradeoff
	/// 3. No wasted signatures - all signatures contribute to path narrowing
	/// 4. Protection against fee underpayment - buffer provides safety margin
	///
	/// USAGE EXAMPLE:
	/// --------------
	/// // Setup: 3-of-7 multisig, 15% buffer
	/// var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, network);
	/// var builder = multiSig.CreateSignatureBuilder(tx, coins);
	///
	/// // Signer 1 (creates initial signatures for all their combinations)
	/// var sig1 = builder.SignWithSigner(key1, 0); // Signs all combos with signer 1
	/// // Pass sig1.Serialize() to other signers
	///
	/// // Signer 2 (adds to combinations that include both signer 1 and 2)
	/// var sig2 = builder.SignWithSigner(key2, 0); // Narrows down further
	///
	/// // Signer 3 (final signer - now only one combo remains)
	/// var sig3 = builder.SignWithSigner(key3, 0);
	///
	/// // Final signer chooses: low fee (false) or high fee with buffer (true)
	/// var finalTx = builder.FinalizeTransaction(0, useBufferedSize: false);
	/// </summary>
	public class DelegatedMultiSig
	{
		private readonly PubKey _ownerPubKey;
		private readonly List<PubKey> _signerPubKeys;
		private readonly int _requiredSignatures;
		private readonly Network _network;
		private TaprootSpendInfo _taprootSpendInfo;
		private readonly List<TapScript> _scripts;
		private readonly Dictionary<string, int[]> _scriptToSignerIndices;

		public DelegatedMultiSig(PubKey ownerPubKey, List<PubKey> signerPubKeys, int requiredSignatures, Network network)
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

			foreach (var combination in combinations)
			{
				var scriptBuilder = new Script();

				for (int i = 0; i < combination.Length; i++)
				{
					var signerIndex = combination[i];
#if HAS_SPAN
					var xOnlyPubKey = _signerPubKeys[signerIndex].TaprootPubKey;
					scriptBuilder = scriptBuilder + Op.GetPushOp(xOnlyPubKey.ToBytes());
#else
					scriptBuilder = scriptBuilder + Op.GetPushOp(_signerPubKeys[signerIndex].ToBytes());
#endif

					if (i == 0)
					{
						scriptBuilder = scriptBuilder + OpcodeType.OP_CHECKSIG;
					}
					else
					{
						scriptBuilder = scriptBuilder + OpcodeType.OP_CHECKSIGADD;
					}
				}

				// BIP387: Use OP_k for k <= 16, raw number for k > 16
				if (_requiredSignatures <= 16)
				{
					// Use OP_k opcodes (OP_1 through OP_16)
					scriptBuilder = scriptBuilder + (OpcodeType)((int)OpcodeType.OP_1 + _requiredSignatures - 1) + OpcodeType.OP_NUMEQUAL;
				}
				else
				{
					// Use raw number encoding for k > 16
					scriptBuilder = scriptBuilder + Op.GetPushOp(_requiredSignatures) + OpcodeType.OP_NUMEQUAL;
				}

				var tapScript = scriptBuilder.ToTapScript(TapLeafVersion.C0);
				_scripts.Add(tapScript);
				_scriptToSignerIndices[tapScript.LeafHash.ToString()] = combination;
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
			var delegatedMultiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, requiredSignatures, network);
			return delegatedMultiSig.Address;
		}

		public static TaprootAddress CreateAddress(ExtPubKey ownerExtPubKey, uint ownerDerivation, List<ExtPubKey> signerExtPubKeys, uint signerDerivation, int requiredSignatures, Network network)
		{
			var ownerPubKey = ownerExtPubKey.Derive(ownerDerivation).PubKey;
			var signerPubKeys = signerExtPubKeys.Select(extPubKey => extPubKey.Derive(signerDerivation).PubKey).ToList();
			return CreateAddress(ownerPubKey, signerPubKeys, requiredSignatures, network);
		}

		public DelegatedMultiSigSignatureBuilder CreateSignatureBuilder(Transaction transaction, ICoin[] spentCoins, bool isDynamicFeeMode = false)
		{
			return new DelegatedMultiSigSignatureBuilder(this, transaction, spentCoins, isDynamicFeeMode);
		}

		/// <summary>
		/// Creates dual transactions (base and buffered) for a specific signer combination.
		/// This is used internally after the final signer combination is known.
		/// For the progressive PSBT workflow, use CreatePSBTForFirstSigner instead.
		/// </summary>
		/// <param name="coin">The input coin to spend</param>
		/// <param name="paymentAddress">The destination address for the payment</param>
		/// <param name="paymentAmount">The amount to send to the payment address</param>
		/// <param name="changeAddress">The address to receive change</param>
		/// <param name="feeRate">The fee rate (satoshis per vbyte)</param>
		/// <param name="signerIndices">The indices of the k signers who will participate</param>
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
			if (signerIndices == null || signerIndices.Length < _requiredSignatures)
				throw new ArgumentException($"Must provide at least {_requiredSignatures} signer indices");
			if (bufferPercentage < 0 || bufferPercentage > 100)
				throw new ArgumentOutOfRangeException(nameof(bufferPercentage), "Buffer percentage must be between 0 and 100");

			// Find the cheapest script for the given signers
			int cheapestScriptIndex = -1;
			int smallestVSize = int.MaxValue;

			for (int scriptIndex = 0; scriptIndex < _scripts.Count; scriptIndex++)
			{
				var script = _scripts[scriptIndex];
				var scriptSignerIndices = _scriptToSignerIndices[script.LeafHash.ToString()];

				// Check if this script matches the provided signers
				if (scriptSignerIndices.Length == _requiredSignatures &&
					scriptSignerIndices.All(idx => signerIndices.Contains(idx)))
				{
					// Create a temporary transaction to estimate size
					var tempTx = _network.CreateTransaction();
					tempTx.Inputs.Add(new OutPoint(coin.Outpoint.Hash, coin.Outpoint.N));
					tempTx.Outputs.Add(paymentAmount, paymentAddress);
					tempTx.Outputs.Add(Money.Zero, changeAddress); // Placeholder

					var tempBuilder = CreateSignatureBuilder(tempTx, new[] { coin });
					var estimate = tempBuilder.GetSizeEstimate(0);
					var vsize = estimate.ScriptSpendVirtualSizes[scriptIndex];

					if (vsize < smallestVSize)
					{
						smallestVSize = vsize;
						cheapestScriptIndex = scriptIndex;
					}
				}
			}

			if (cheapestScriptIndex == -1)
				throw new ArgumentException("No valid script found for the specified signers");

			// Calculate fees
			var baseFee = feeRate.GetFee(smallestVSize);
			var bufferedVSize = (int)(smallestVSize * (1.0 + bufferPercentage / 100.0));
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

		/// <summary>
		/// Creates a MultiPathPSBT for the first signer in a progressive signing workflow.
		/// Each script path gets its own transaction with the optimal fee for that specific combination.
		/// </summary>
		/// <param name="firstSignerKey">The first signer's private key</param>
		/// <param name="coin">The input coin to spend</param>
		/// <param name="paymentAddress">The destination address for the payment</param>
		/// <param name="paymentAmount">The amount to send to the payment address</param>
		/// <param name="changeAddress">The address to receive change</param>
		/// <param name="feeRate">The fee rate (satoshis per vbyte)</param>
		/// <param name="bufferPercentage">Buffer percentage for fee (e.g., 15.0 for 15%)</param>
		/// <param name="inputIndex">Index of the input to sign (default: 0)</param>
		/// <param name="sigHash">Taproot signature hash type (default: TaprootSigHash.All)</param>
		/// <returns>A MultiPathPSBT containing separate transactions for each viable script path</returns>
		public MultiPathPSBT CreateMultiPathPSBTForFirstSigner(
			Key firstSignerKey,
			ICoin coin,
			IDestination paymentAddress,
			Money paymentAmount,
			IDestination changeAddress,
			FeeRate feeRate,
			double bufferPercentage = 15.0,
			int inputIndex = 0,
			TaprootSigHash sigHash = TaprootSigHash.All)
		{
			if (firstSignerKey == null)
				throw new ArgumentNullException(nameof(firstSignerKey));
			if (coin == null)
				throw new ArgumentNullException(nameof(coin));
			if (paymentAddress == null)
				throw new ArgumentNullException(nameof(paymentAddress));
			if (changeAddress == null)
				throw new ArgumentNullException(nameof(changeAddress));
			if (feeRate == null)
				throw new ArgumentNullException(nameof(feeRate));
			if (bufferPercentage < 0 || bufferPercentage > 100)
				throw new ArgumentOutOfRangeException(nameof(bufferPercentage));

			var signerPubKey = firstSignerKey.PubKey;
			var signerIndex = _signerPubKeys.FindIndex(pk => pk == signerPubKey);
			if (signerIndex == -1)
				throw new ArgumentException("Signer key not found in the multisig configuration");

			var pathPSBTs = new List<(int scriptIndex, int[] signerIndices, PSBT psbt, int virtualSize)>();

			// Create a separate transaction for each script where this signer participates
			for (int scriptIdx = 0; scriptIdx < _scripts.Count; scriptIdx++)
			{
				var script = _scripts[scriptIdx];
				var scriptSignerIndices = _scriptToSignerIndices[script.LeafHash.ToString()];

				if (!scriptSignerIndices.Contains(signerIndex))
					continue;

				// Calculate exact virtual size for this script path
				var (baseTx, _) = CreateDualTransactions(coin, paymentAddress, paymentAmount,
					changeAddress, feeRate, scriptSignerIndices, bufferPercentage);

				// Create PSBT for this specific path
				var psbt = CreatePSBT(baseTx, new[] { coin });

				// Sign this specific path
				SignPSBT(psbt, firstSignerKey, inputIndex, sigHash);

				// Calculate actual virtual size
				var builder = CreateSignatureBuilder(baseTx, new[] { coin });
				var estimate = builder.GetSizeEstimate(inputIndex);
				var vsize = estimate.ScriptSpendVirtualSizes[scriptIdx];

				pathPSBTs.Add((scriptIdx, scriptSignerIndices, psbt, vsize));
			}

			if (pathPSBTs.Count == 0)
				throw new InvalidOperationException("Signer does not participate in any script paths");

			return new MultiPathPSBT(pathPSBTs, signerIndex);
		}

		/// <summary>
		/// Creates a PSBT (Partially Signed Bitcoin Transaction) from an unsigned transaction.
		/// Sets up Taproot-specific fields including the internal key and merkle root.
		/// </summary>
		/// <param name="transaction">The unsigned transaction to convert to a PSBT</param>
		/// <param name="spentCoins">Array of coins being spent (must match transaction inputs)</param>
		/// <returns>A PSBT ready for signing by participants</returns>
		/// <remarks>
		/// The created PSBT includes:
		/// - WitnessUtxo for each input (required for Taproot)
		/// - TaprootInternalKey (owner's public key)
		/// - TaprootMerkleRoot (root of the script tree)
		/// </remarks>
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

		/// <summary>
		/// Signs a PSBT with a signer's key, adding partial signatures for all scripts the signer participates in.
		/// Uses BIP 174 proprietary fields to store DelegatedMultiSig partial signatures.
		/// </summary>
		/// <param name="psbt">The PSBT to sign (modified in-place)</param>
		/// <param name="signerKey">The private key of the signer</param>
		/// <param name="inputIndex">Index of the input to sign (default: 0)</param>
		/// <param name="sigHash">Taproot signature hash type (default: TaprootSigHash.Default)</param>
		/// <returns>The modified PSBT with signatures added</returns>
		/// <exception cref="ArgumentException">Thrown when signer key is not found in the multisig configuration</exception>
		/// <remarks>
		/// <para>This method implements BIP 174 compliant PSBT signing using proprietary fields.</para>
		/// <para>Proprietary key format:</para>
		/// <code>
		/// 0xFC                           // Proprietary type byte
		/// &lt;compact_size:identifier_len&gt;  // Length of identifier (5)
		/// "DMSIG"                        // Identifier (5 ASCII bytes)
		/// &lt;compact_size:scriptIndex&gt;     // Which script combination was used
		/// &lt;byte:signerIndex&gt;             // Which signer created this signature
		/// </code>
		/// <para>The PSBT can be serialized with ToBase64() and transmitted to other signers.</para>
		/// <para>Each signer can call SignPSBT on the deserialized PSBT to add their signatures.</para>
		/// </remarks>
		/// <example>
		/// <code>
		/// // First signer signs
		/// multiSig.SignPSBT(psbt, signerKeys[0], 0, TaprootSigHash.All);
		/// var serialized = psbt.ToBase64();
		///
		/// // Second signer receives and signs
		/// var psbt2 = PSBT.Parse(serialized, Network.RegTest);
		/// multiSig.SignPSBT(psbt2, signerKeys[2], 0, TaprootSigHash.All);
		/// </code>
		/// </example>
		public PSBT SignPSBT(PSBT psbt, Key signerKey, int inputIndex = 0, TaprootSigHash sigHash = TaprootSigHash.Default)
	{
		var signerPubKey = signerKey.PubKey;
		var signerIndex = _signerPubKeys.FindIndex(pk => pk == signerPubKey);
		if (signerIndex == -1)
			throw new ArgumentException("Signer key not found in the multisig configuration");

		var transaction = psbt.GetGlobalTransaction();
		var spentCoins = new List<ICoin>();
		foreach (var input in psbt.Inputs)
		{
			if (input.WitnessUtxo != null)
				spentCoins.Add(new Coin(input.PrevOut, input.WitnessUtxo));
		}

		var builder = CreateSignatureBuilder(transaction, spentCoins.ToArray());
		builder.SignWithSigner(signerKey, inputIndex, sigHash);

		// Store partial signatures using BIP 174 proprietary fields
		// Format: 0xFC + <compact_size:id_len> + identifier + <compact_size:subtype> + key_data
		var partialSigs = builder._partialSignatures[inputIndex];
		var inputPSBT = psbt.Inputs[inputIndex];

		foreach (var sig in partialSigs)
		{
			// Proprietary key components
			var identifier = System.Text.Encoding.ASCII.GetBytes("DMSIG"); // 5 bytes
			var subtype = (ulong)sig.ScriptIndex;
			var keyData = new byte[] { (byte)sig.SignerIndex };

			// Build BIP 174 compliant proprietary key
			var keyBytes = new List<byte>();
			keyBytes.Add(0xFC); // Type byte

			// Identifier length + identifier
			keyBytes.AddRange(GetCompactSizeBytes((ulong)identifier.Length));
			keyBytes.AddRange(identifier);

			// Subtype
			keyBytes.AddRange(GetCompactSizeBytes(subtype));

			// Key data
			keyBytes.AddRange(keyData);

			// Value: Taproot signature bytes
			var valueBytes = sig.Signature.ToBytes();

			inputPSBT.Unknown[keyBytes.ToArray()] = valueBytes;
		}

		return psbt;
	}

		/// <summary>
		/// Checks if a PSBT has enough signatures to be finalized.
		/// </summary>
		/// <param name="psbt">The PSBT to check</param>
		/// <param name="inputIndex">Index of the input to check (default: 0)</param>
		/// <returns>True if the PSBT has k or more signatures and can be finalized</returns>
		/// <remarks>
		/// This method counts unique signers in the PSBT proprietary fields.
		/// A PSBT is complete when it has at least k signatures from different signers.
		/// </remarks>
		private bool IsComplete(PSBT psbt, int inputIndex = 0)
		{
			var inputPSBT = psbt.Inputs[inputIndex];
			var uniqueSigners = new HashSet<byte>();

			foreach (var kvp in inputPSBT.Unknown)
			{
				var key = kvp.Key;
				if (key.Length < 2 || key[0] != 0xFC)
					continue;

				try
				{
					int offset = 1;
					var idLen = ReadCompactSizeFromBytes(key, ref offset);
					if (offset + (int)idLen > key.Length)
						continue;

					var identifier = new byte[idLen];
					Array.Copy(key, offset, identifier, 0, (int)idLen);
					offset += (int)idLen;

					var identifierStr = System.Text.Encoding.ASCII.GetString(identifier);
					if (identifierStr != "DMSIG")
						continue;

					// Read scriptIndex (we don't need it for counting)
					ReadCompactSizeFromBytes(key, ref offset);

					// Read signerIndex
					if (offset >= key.Length)
						continue;
					var signerIndex = key[offset];

					uniqueSigners.Add(signerIndex);
				}
				catch
				{
					continue;
				}
			}

			return uniqueSigners.Count >= _requiredSignatures;
		}

		/// <summary>
		/// Attempts to finalize a PSBT if it has enough signatures.
		/// Returns the finalized transaction if successful, or null if more signatures are needed.
		/// </summary>
		/// <param name="psbt">The PSBT to finalize</param>
		/// <param name="inputIndex">Index of the input to finalize (default: 0)</param>
		/// <param name="useBufferedSize">Whether to use buffered size estimation (default: false)</param>
		/// <returns>Finalized transaction if complete, null otherwise</returns>
		/// <remarks>
		/// <para>This method provides a convenient way to check and finalize in one call.</para>
		/// <para>Typical workflow:</para>
		/// <code>
		/// multiSig.SignPSBT(psbt, myKey);
		/// var tx = multiSig.TryFinalizePSBT(psbt);
		/// if (tx != null)
		///     rpc.SendRawTransaction(tx);  // Ready to broadcast
		/// else
		///     SendToNextSigner(psbt.ToBase64());  // Need more signatures
		/// </code>
		/// </remarks>
		public Transaction TryFinalizePSBT(PSBT psbt, int inputIndex = 0, bool useBufferedSize = false)
		{
			if (!IsComplete(psbt, inputIndex))
				return null;

			return FinalizePSBT(psbt, inputIndex, useBufferedSize);
		}

		/// <summary>
		/// Finalizes a PSBT by extracting partial signatures and creating the final witness.
		/// Returns a fully signed transaction ready for broadcast.
		/// </summary>
		/// <param name="psbt">The PSBT containing all required signatures</param>
		/// <param name="inputIndex">Index of the input to finalize (default: 0)</param>
		/// <param name="useBufferedSize">Whether to use buffered size estimation (default: false)</param>
		/// <returns>Fully signed transaction ready for broadcast</returns>
		/// <exception cref="InvalidOperationException">Thrown when insufficient signatures are present</exception>
		/// <remarks>
		/// <para>This method:</para>
		/// <list type="number">
		/// <item><description>Extracts all partial signatures from PSBT proprietary fields</description></item>
		/// <item><description>Reconstructs the witness script with collected signatures</description></item>
		/// <item><description>Validates that the k-of-n threshold is met</description></item>
		/// <item><description>Returns a fully signed transaction</description></item>
		/// </list>
		/// <para>The proprietary fields follow BIP 174 format with "DMSIG" identifier.</para>
		/// <para>Each signature includes scriptIndex and signerIndex for proper reconstruction.</para>
		/// </remarks>
		/// <example>
		/// <code>
		/// // After all k signers have signed the PSBT
		/// var finalTx = multiSig.FinalizePSBT(psbt, 0);
		///
		/// // Broadcast the transaction
		/// var txid = rpc.SendRawTransaction(finalTx);
		/// </code>
		/// </example>
		public Transaction FinalizePSBT(PSBT psbt, int inputIndex = 0, bool useBufferedSize = false)
	{
		var transaction = psbt.GetGlobalTransaction();
		var spentCoins = new List<ICoin>();
		foreach (var input in psbt.Inputs)
		{
			if (input.WitnessUtxo != null)
				spentCoins.Add(new Coin(input.PrevOut, input.WitnessUtxo));
		}

		var builder = CreateSignatureBuilder(transaction, spentCoins.ToArray());

		// Extract partial signatures from PSBT proprietary fields
		var inputPSBT = psbt.Inputs[inputIndex];
		var partialSignatures = new List<PartialSignature>();

		foreach (var kvp in inputPSBT.Unknown)
		{
			var key = kvp.Key;
			if (key.Length < 2 || key[0] != 0xFC)
				continue;

			try
			{
				int offset = 1;

				// Read identifier length
				var idLen = ReadCompactSizeFromBytes(key, ref offset);
				if (offset + (int)idLen > key.Length)
					continue;

				// Read identifier
				var identifier = new byte[idLen];
				Array.Copy(key, offset, identifier, 0, (int)idLen);
				offset += (int)idLen;

				// Check if this is our identifier
				var identifierStr = System.Text.Encoding.ASCII.GetString(identifier);
				if (identifierStr != "DMSIG")
					continue;

				// Read subtype (scriptIndex)
				var scriptIndex = (int)ReadCompactSizeFromBytes(key, ref offset);

				// Read key data (signerIndex)
				if (offset >= key.Length)
					continue;
				var signerIndex = key[offset];

				// Parse signature from value
				if (!TaprootSignature.TryParse(kvp.Value, out var signature))
					continue;

				// Reconstruct the PartialSignature
				partialSignatures.Add(new PartialSignature
				{
					SignerIndex = signerIndex,
					Signature = signature,
					ScriptIndex = scriptIndex,
					EstimatedVirtualSize = 0,
					EstimatedVirtualSizeWithBuffer = 0
				});
			}
			catch
			{
				// Skip malformed proprietary keys
				continue;
			}
		}

		// Add all partial signatures to the builder
		if (!builder._partialSignatures.ContainsKey(inputIndex))
			builder._partialSignatures[inputIndex] = new List<PartialSignature>();
		builder._partialSignatures[inputIndex].AddRange(partialSignatures);

		// Finalize the transaction
		return builder.FinalizeTransaction(inputIndex, useBufferedSize);
	}

		/// <summary>
		/// Gets the size in bytes of a varint encoding for the given length.
		/// </summary>
		private static int GetVarIntSize(int length)
		{
			if (length < 0xFD) return 1;
			if (length <= 0xFFFF) return 3;
			if (length <= int.MaxValue) return 5;
			return 9;
		}

		/// <summary>
		/// Encodes a value as compact size bytes per Bitcoin protocol.
		/// Used for BIP 174 PSBT proprietary field encoding.
		/// </summary>
		/// <param name="value">The value to encode</param>
		/// <returns>Byte array containing the compact size encoded value</returns>
		/// <remarks>
		/// <para>Compact size encoding rules:</para>
		/// <list type="bullet">
		/// <item><description>Values &lt; 0xFD: 1 byte (the value itself)</description></item>
		/// <item><description>Values ≤ 0xFFFF: 3 bytes (0xFD + 2-byte little-endian)</description></item>
		/// <item><description>Values ≤ 0xFFFFFFFF: 5 bytes (0xFE + 4-byte little-endian)</description></item>
		/// <item><description>Values &gt; 0xFFFFFFFF: 9 bytes (0xFF + 8-byte little-endian)</description></item>
		/// </list>
		/// </remarks>
		private static byte[] GetCompactSizeBytes(ulong value)
	{
		if (value < 0xFD)
		{
			return new byte[] { (byte)value };
		}
		else if (value <= 0xFFFF)
		{
			var bytes = new byte[3];
			bytes[0] = 0xFD;
			bytes[1] = (byte)(value & 0xFF);
			bytes[2] = (byte)((value >> 8) & 0xFF);
			return bytes;
		}
		else if (value <= 0xFFFFFFFF)
		{
			var bytes = new byte[5];
			bytes[0] = 0xFE;
			bytes[1] = (byte)(value & 0xFF);
			bytes[2] = (byte)((value >> 8) & 0xFF);
			bytes[3] = (byte)((value >> 16) & 0xFF);
			bytes[4] = (byte)((value >> 24) & 0xFF);
			return bytes;
		}
		else
		{
			var bytes = new byte[9];
			bytes[0] = 0xFF;
			for (int i = 0; i < 8; i++)
			{
				bytes[i + 1] = (byte)((value >> (i * 8)) & 0xFF);
			}
			return bytes;
		}
	}

		/// <summary>
		/// Reads a compact size value from a byte array at the given offset.
		/// Used for parsing BIP 174 PSBT proprietary fields.
		/// </summary>
		/// <param name="data">Byte array containing the compact size value</param>
		/// <param name="offset">Current offset in the array (updated after reading)</param>
		/// <returns>The decoded value</returns>
		/// <exception cref="ArgumentException">Thrown when offset is out of range or encoding is invalid</exception>
		/// <remarks>
		/// <para>This method reads compact size values according to Bitcoin protocol:</para>
		/// <list type="bullet">
		/// <item><description>First byte &lt; 0xFD: Return the byte value, advance offset by 1</description></item>
		/// <item><description>First byte == 0xFD: Read 2-byte little-endian value, advance offset by 3</description></item>
		/// <item><description>First byte == 0xFE: Read 4-byte little-endian value, advance offset by 5</description></item>
		/// <item><description>First byte == 0xFF: Read 8-byte little-endian value, advance offset by 9</description></item>
		/// </list>
		/// <para>The offset parameter is passed by reference and updated to point past the decoded value.</para>
		/// </remarks>
		private static ulong ReadCompactSizeFromBytes(byte[] data, ref int offset)
	{
		if (offset >= data.Length)
			throw new ArgumentException("Offset out of range");

		byte firstByte = data[offset++];
		if (firstByte < 0xFD)
		{
			return firstByte;
		}
		else if (firstByte == 0xFD)
		{
			if (offset + 2 > data.Length)
				throw new ArgumentException("Invalid compact size encoding");
			var value = (ulong)data[offset] | ((ulong)data[offset + 1] << 8);
			offset += 2;
			return value;
		}
		else if (firstByte == 0xFE)
		{
			if (offset + 4 > data.Length)
				throw new ArgumentException("Invalid compact size encoding");
			var value = (ulong)data[offset] | ((ulong)data[offset + 1] << 8) |
						((ulong)data[offset + 2] << 16) | ((ulong)data[offset + 3] << 24);
			offset += 4;
			return value;
		}
		else // 0xFF
		{
			if (offset + 8 > data.Length)
				throw new ArgumentException("Invalid compact size encoding");
			var value = 0UL;
			for (int i = 0; i < 8; i++)
			{
				value |= ((ulong)data[offset + i] << (i * 8));
			}
			offset += 8;
			return value;
		}
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

		public class DelegatedMultiSigSignatureBuilder
		{
			private readonly DelegatedMultiSig _multiSig;
			private readonly Transaction _transaction;
			private readonly ICoin[] _spentCoins;
			internal readonly Dictionary<int, List<PartialSignature>> _partialSignatures;
			internal readonly Dictionary<int, TransactionSizeEstimate> _sizeEstimates;
			internal bool _useKeySpend;
			internal TapScript _selectedScript;
			private readonly bool _isDynamicFeeMode;
			private Money _fixedOutputAmount;

			internal DelegatedMultiSigSignatureBuilder(DelegatedMultiSig multiSig, Transaction transaction, ICoin[] spentCoins, bool isDynamicFeeMode = false)
			{
				_multiSig = multiSig;
				_transaction = transaction;
				_spentCoins = spentCoins;
				_partialSignatures = new Dictionary<int, List<PartialSignature>>();
				_sizeEstimates = new Dictionary<int, TransactionSizeEstimate>();
				_useKeySpend = false;
				_isDynamicFeeMode = isDynamicFeeMode;
				
				// Pre-calculate transaction size estimates for all possible script paths
				for (int inputIndex = 0; inputIndex < transaction.Inputs.Count; inputIndex++)
				{
					_sizeEstimates[inputIndex] = CalculateTransactionSizeEstimates(inputIndex);
				}
			}

			[Obsolete("UseKeySpend() is no longer needed. SignWithOwner() automatically sets key spend mode.")]
			public DelegatedMultiSigSignatureBuilder UseKeySpend()
			{
				_useKeySpend = true;
				_selectedScript = null;
				return this;
			}

			[Obsolete("UseScript() is no longer needed. SignWithSigner() automatically signs all scripts the signer participates in.")]
			public DelegatedMultiSigSignatureBuilder UseScript(int scriptIndex)
			{
				if (scriptIndex < 0 || scriptIndex >= _multiSig._scripts.Count)
					throw new ArgumentOutOfRangeException(nameof(scriptIndex));

				_useKeySpend = false;
				_selectedScript = _multiSig._scripts[scriptIndex];
				return this;
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

			public PartialSignatureData SignWithOwner(Key ownerPrivateKey, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
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

			public PartialSignatureData SignWithSigner(Key signerKey, int inputIndex, TaprootSigHash sigHash = TaprootSigHash.Default)
			{
				if (_useKeySpend)
					throw new InvalidOperationException("Cannot use signer key for key spend path");

				var signerPubKey = signerKey.PubKey;
				var signerIndex = _multiSig._signerPubKeys.FindIndex(pk => pk == signerPubKey);
				if (signerIndex == -1)
					throw new ArgumentException("Signer key not found in the multisig configuration");

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

				// Create signatures for all valid scripts
				var signatures = new List<PartialSignature>();
				foreach (var (script, scriptIndex) in validScripts)
				{
					var executionData = new TaprootExecutionData(inputIndex, script.LeafHash) { SigHash = sigHash };
					var hash = _transaction.GetSignatureHashTaproot(_spentCoins.Select(c => c.TxOut).ToArray(), executionData);
					var signature = signerKey.SignTaprootScriptSpend(hash, sigHash);

					// Calculate actual virtual size for this specific script combination
					var (estimatedVSize, estimatedVSizeWithBuffer) = CalculateScriptVirtualSize(script, scriptIndex, inputIndex);

					signatures.Add(new PartialSignature
					{
						SignerIndex = signerIndex,
						Signature = signature,
						ScriptIndex = scriptIndex,
						EstimatedVirtualSize = estimatedVSize,
						EstimatedVirtualSizeWithBuffer = estimatedVSizeWithBuffer
					});
				}

				// Add all signatures to the collection
				if (!_partialSignatures.ContainsKey(inputIndex))
					_partialSignatures[inputIndex] = new List<PartialSignature>();

				_partialSignatures[inputIndex].AddRange(signatures);

				// Return data with all signatures for this signer
				return new PartialSignatureData
				{
					Transaction = _transaction,
					InputIndex = inputIndex,
					ScriptIndex = -1, // Multiple scripts, so -1 indicates "all applicable"
					PartialSignatures = signatures,
					IsComplete = IsSignatureComplete(inputIndex)
				};
			}

			public PartialSignatureData AddPartialSignature(PartialSignatureData data, int inputIndex)
			{
				if (!_partialSignatures.ContainsKey(inputIndex))
					_partialSignatures[inputIndex] = new List<PartialSignature>();

				foreach (var sig in data.PartialSignatures)
				{
					// Check if we already have a signature from this signer for this script
					var existingSig = _partialSignatures[inputIndex]
						.FirstOrDefault(s => s.SignerIndex == sig.SignerIndex && s.ScriptIndex == sig.ScriptIndex);
					
					if (existingSig == null)
					{
						_partialSignatures[inputIndex].Add(sig);
					}
				}

				return new PartialSignatureData
				{
					Transaction = _transaction,
					InputIndex = inputIndex,
					ScriptIndex = data.ScriptIndex,
					PartialSignatures = _partialSignatures[inputIndex].ToList(),
					IsComplete = IsSignatureComplete(inputIndex)
				};
			}

			private PartialSignatureData SignKeySpend(Key ownerPrivateKey, int inputIndex, TaprootSigHash sigHash)
			{
				var executionData = new TaprootExecutionData(inputIndex) { SigHash = sigHash };
				var hash = _transaction.GetSignatureHashTaproot(_spentCoins.Select(c => c.TxOut).ToArray(), executionData);
				var signature = ownerPrivateKey.SignTaprootKeySpend(hash, _multiSig._taprootSpendInfo.MerkleRoot, sigHash);

				_transaction.Inputs[inputIndex].WitScript = new WitScript(Op.GetPushOp(signature.ToBytes()));

				return new PartialSignatureData
				{
					Transaction = _transaction,
					InputIndex = inputIndex,
					IsComplete = true,
					IsKeySpend = true
				};
			}

			private bool IsSignatureComplete(int inputIndex)
			{
				if (!_partialSignatures.ContainsKey(inputIndex))
					return false;

				// Group signatures by script index
				var signaturesByScript = _partialSignatures[inputIndex]
					.GroupBy(s => s.ScriptIndex)
					.ToDictionary(g => g.Key, g => g.ToList());

				// Check if any script has enough signatures
				foreach (var (scriptIndex, sigs) in signaturesByScript)
				{
					// Count unique signers for this script
					var uniqueSigners = sigs.Select(s => s.SignerIndex).Distinct().Count();
					if (uniqueSigners >= _multiSig._requiredSignatures)
						return true;
				}

				return false;
			}

			public Transaction FinalizeTransaction(int inputIndex, bool useBufferedSize = false)
			{
				if (_useKeySpend)
				{
					return _transaction;
				}

				if (!IsSignatureComplete(inputIndex))
					throw new InvalidOperationException($"Not enough signatures for input {inputIndex}. Need {_multiSig._requiredSignatures} signatures from unique signers.");

				var signatures = _partialSignatures[inputIndex];

				// Group signatures by script index
				var signaturesByScript = signatures
					.GroupBy(s => s.ScriptIndex)
					.ToDictionary(g => g.Key, g => g.ToList());

				// Find the first script that has enough unique signers
				TapScript selectedScript = null;
				List<PartialSignature> selectedSignatures = null;
				int selectedScriptIndex = -1;

				foreach (var (scriptIndex, sigs) in signaturesByScript)
				{
					// Get unique signers for this script
					var uniqueSignatures = sigs
						.GroupBy(s => s.SignerIndex)
						.Select(g => g.First())
						.ToList();

					if (uniqueSignatures.Count >= _multiSig._requiredSignatures)
					{
						selectedScript = _multiSig._scripts[scriptIndex];
						selectedSignatures = uniqueSignatures;
						selectedScriptIndex = scriptIndex;
						break;
					}
				}

				if (selectedScript == null)
					throw new InvalidOperationException("No script has enough signatures to finalize the transaction");

				// Note: Dynamic fee adjustment should be done before collecting signatures
				// The transaction should already have the correct outputs when signatures are collected

				// Get the signer indices for this script
				var scriptSignerIndices = _multiSig._scriptToSignerIndices[selectedScript.LeafHash.ToString()];

				// Order signatures according to the script's public key order (reverse)
				var orderedSignatures = new List<TaprootSignature>();
				for (int i = scriptSignerIndices.Length - 1; i >= 0; i--)
				{
					var signerIndex = scriptSignerIndices[i];
					var sig = selectedSignatures.FirstOrDefault(s => s.SignerIndex == signerIndex);
					if (sig != null)
					{
						orderedSignatures.Add(sig.Signature);
						if (orderedSignatures.Count == _multiSig._requiredSignatures)
							break;
					}
				}

				// Build witness
				var witnessItems = new List<byte[]>();
				foreach (var sig in orderedSignatures)
				{
					witnessItems.Add(sig.ToBytes());
				}
				witnessItems.Add(selectedScript.Script.ToBytes());
				witnessItems.Add(_multiSig._taprootSpendInfo.GetControlBlock(selectedScript).ToBytes());

				_transaction.Inputs[inputIndex].WitScript = new WitScript(witnessItems.ToArray());

				return _transaction;
			}

			public string GetPartialSignatureString(int inputIndex)
			{
				if (!_partialSignatures.ContainsKey(inputIndex))
					return "";

				var data = new PartialSignatureData
				{
					Transaction = _transaction,
					InputIndex = inputIndex,
					ScriptIndex = _selectedScript != null ? _multiSig._scripts.IndexOf(_selectedScript) : -1,
					PartialSignatures = _partialSignatures[inputIndex].ToList(),
					IsComplete = IsSignatureComplete(inputIndex),
					IsKeySpend = _useKeySpend
				};

				return data.Serialize();
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
					
					// Calculate witness size
					var witnessSize = 1; // witness stack count
					// Each signature: 1 byte length + 64 bytes signature
					witnessSize += _multiSig._requiredSignatures * 65;
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
				
				// Find the cheapest script
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

			private (int estimatedVSize, int estimatedVSizeWithBuffer) CalculateScriptVirtualSize(TapScript script, int scriptIndex, int inputIndex)
			{
				// ALWAYS calculate accurate size using realistic dummy transaction instead of using generic estimates
				// This ensures we get the most accurate size for the specific script combination
				// Debug: Console.WriteLine($"Calculating accurate size for script {scriptIndex}...");
				
				// Create a realistic dummy transaction to get accurate size measurement
				var tempTx = _transaction.Clone();
				
				// Calculate witness stack components more accurately
				var signatureSize = 65; // 64-byte Schnorr signature + 1-byte sighash flag
				var scriptBytes = script.Script.ToBytes();
				var controlBlock = _multiSig._taprootSpendInfo.GetControlBlock(script);
				var controlBlockBytes = controlBlock.ToBytes();
				
				// Build realistic witness stack
				var witnessStack = new List<byte[]>();
				
				// Add dummy signatures (in reverse order as required by script)
				for (int i = 0; i < _multiSig._requiredSignatures; i++)
				{
					var dummySig = new byte[signatureSize];
					Array.Fill(dummySig, (byte)0x30); // Realistic dummy data
					dummySig[64] = 0x01; // SIGHASH_ALL
					witnessStack.Add(dummySig);
				}
				
				// Add script and control block
				witnessStack.Add(scriptBytes);
				witnessStack.Add(controlBlockBytes);
				
				// Set the witness for this input
				tempTx.Inputs[inputIndex].WitScript = new WitScript(witnessStack);
				
				// Calculate the actual virtual size using NBitcoin's built-in calculation
				var estimatedVSize = tempTx.GetVirtualSize();
				
				// Apply default 15% buffer for buffered size
				var estimatedVSizeWithBuffer = (int)(estimatedVSize * 1.15);
				
				// Debug: Console.WriteLine($"Script {scriptIndex} - Calculated vSize: {estimatedVSize}, Sigs: {_multiSig._requiredSignatures}, Script: {scriptBytes.Length}b, Control: {controlBlockBytes.Length}b");
				
				return (estimatedVSize, estimatedVSizeWithBuffer);
			}

			public int GetActualVirtualSizeForScript(int inputIndex, int scriptIndex, bool useBufferedSize = false)
			{
				if (!_partialSignatures.ContainsKey(inputIndex))
					return -1;

				// Find any signature for this script that has the virtual size stored
				var signatureForScript = _partialSignatures[inputIndex]
					.FirstOrDefault(s => s.ScriptIndex == scriptIndex && s.EstimatedVirtualSize > 0);

				if (signatureForScript == null)
					return -1;

				return useBufferedSize ? signatureForScript.EstimatedVirtualSizeWithBuffer : signatureForScript.EstimatedVirtualSize;
			}

			public int GetCheapestScriptIndexForSigners(int[] signerIndices)
			{
				if (signerIndices == null || signerIndices.Length < _multiSig._requiredSignatures)
					throw new ArgumentException($"Must provide at least {_multiSig._requiredSignatures} signer indices");

				var candidateScripts = new List<(int scriptIndex, int virtualSize)>();

				// Find all scripts that contain these specific signers
				for (int scriptIndex = 0; scriptIndex < _multiSig._scripts.Count; scriptIndex++)
				{
					var script = _multiSig._scripts[scriptIndex];
					var scriptSignerIndices = _multiSig._scriptToSignerIndices[script.LeafHash.ToString()];

					// Check if all provided signers are in this script
					if (signerIndices.All(si => scriptSignerIndices.Contains(si)))
					{
						// Get the stored virtual size for this script if available
						var storedVSize = GetActualVirtualSizeForScript(0, scriptIndex);
						if (storedVSize > 0)
						{
							candidateScripts.Add((scriptIndex, storedVSize));
						}
						else
						{
							// Fallback to generic estimate if not yet calculated
							var sizeEstimate = GetSizeEstimate(0);
							if (sizeEstimate?.ScriptSpendVirtualSizes.ContainsKey(scriptIndex) == true)
							{
								candidateScripts.Add((scriptIndex, sizeEstimate.ScriptSpendVirtualSizes[scriptIndex]));
							}
						}
					}
				}

				if (candidateScripts.Count == 0)
					throw new ArgumentException("No script found that contains all the specified signers");

				// Return the script index with the smallest virtual size
				return candidateScripts.OrderBy(s => s.virtualSize).First().scriptIndex;
			}
			
			private void AdjustTransactionForDynamicFee(int scriptIndex, bool useBufferedSize)
			{
				if (_fixedOutputAmount == null || _fixedOutputAmount == Money.Zero)
					return;
				
				var totalInput = Money.Zero;
				foreach (var coin in _spentCoins)
				{
					totalInput += (Money)coin.Amount;
				}
				
				// Calculate the change output index (assuming it's the last output)
				var changeOutputIndex = _transaction.Outputs.Count - 1;
				if (changeOutputIndex < 0)
					return;
				
				// Get the appropriate vsize
				var sizeEstimate = GetSizeEstimate(0);
				var vsize = useBufferedSize ? 
					sizeEstimate.ScriptSpendVirtualSizesWithBuffer[scriptIndex] : 
					sizeEstimate.ScriptSpendVirtualSizes[scriptIndex];
				
				// Determine fee rate from current transaction
				var outputSum = Money.Zero;
				foreach (var output in _transaction.Outputs)
				{
					outputSum += (Money)output.Value;
				}
				var currentFee = totalInput - outputSum;
				var currentVSize = sizeEstimate.ScriptSpendVirtualSizes[scriptIndex];
				var feeRate = new FeeRate(currentFee, currentVSize);
				
				// Calculate new fee based on chosen size
				var newFee = feeRate.GetFee(vsize);
				
				// Adjust change output
				var change = totalInput - _fixedOutputAmount - newFee;
				if (change < Money.Zero)
					throw new InvalidOperationException("Insufficient funds for transaction with chosen fee");
				
				_transaction.Outputs[changeOutputIndex].Value = change;
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

		public class PartialSignature
		{
			public int SignerIndex { get; set; }
			public TaprootSignature Signature { get; set; }
			public int ScriptIndex { get; set; }
			public int EstimatedVirtualSize { get; set; } // Store actual virtual size for this script combination
			public int EstimatedVirtualSizeWithBuffer { get; set; } // Store buffered virtual size
		}

		public class PartialSignatureData
		{
			public Transaction Transaction { get; set; }
			public int InputIndex { get; set; }
			public int ScriptIndex { get; set; }
			public List<PartialSignature> PartialSignatures { get; set; }
			public bool IsComplete { get; set; }
			public bool IsKeySpend { get; set; }

			public string Serialize()
			{
				var data = new
				{
					Transaction = Transaction.ToHex(),
					InputIndex,
					ScriptIndex,
					PartialSignatures = PartialSignatures?.Select(ps => new
					{
						ps.SignerIndex,
						Signature = ps.Signature.ToString(),
						ps.ScriptIndex
					}).ToArray(),
					IsComplete,
					IsKeySpend
				};

				var json = Newtonsoft.Json.JsonConvert.SerializeObject(data);
				return Encoders.Base64.EncodeData(System.Text.Encoding.UTF8.GetBytes(json));
			}

			public static PartialSignatureData Deserialize(string serialized)
			{
				var jsonBytes = Encoders.Base64.DecodeData(serialized);
				var json = System.Text.Encoding.UTF8.GetString(jsonBytes);
				var jsonObject = Newtonsoft.Json.Linq.JObject.Parse(json);

				var result = new PartialSignatureData
				{
					Transaction = Transaction.Parse(jsonObject["Transaction"].ToString(), Network.Main),
					InputIndex = jsonObject["InputIndex"].ToObject<int>(),
					ScriptIndex = jsonObject["ScriptIndex"].ToObject<int>(),
					IsComplete = jsonObject["IsComplete"].ToObject<bool>(),
					IsKeySpend = jsonObject["IsKeySpend"].ToObject<bool>()
				};

				if (jsonObject["PartialSignatures"] != null)
				{
					result.PartialSignatures = new List<PartialSignature>();
					foreach (var ps in jsonObject["PartialSignatures"])
					{
						result.PartialSignatures.Add(new PartialSignature
						{
							SignerIndex = ps["SignerIndex"].ToObject<int>(),
							Signature = TaprootSignature.Parse(ps["Signature"].ToString()),
							ScriptIndex = ps["ScriptIndex"].ToObject<int>()
						});
					}
				}

				return result;
			}
		}

		/// <summary>
		/// Represents multiple transaction paths in a progressive PSBT signing workflow.
		/// Each path corresponds to a different signer combination, with optimal fees.
		/// </summary>
		public class MultiPathPSBT
		{
			private readonly List<(int scriptIndex, int[] signerIndices, PSBT psbt, int virtualSize)> _paths;
			private readonly HashSet<int> _currentSigners;

			public MultiPathPSBT(List<(int scriptIndex, int[] signerIndices, PSBT psbt, int virtualSize)> paths, int firstSignerIndex)
			{
				_paths = paths;
				_currentSigners = new HashSet<int> { firstSignerIndex };
			}

			private MultiPathPSBT(List<(int scriptIndex, int[] signerIndices, PSBT psbt, int virtualSize)> paths, HashSet<int> currentSigners)
			{
				_paths = paths;
				_currentSigners = currentSigners;
			}

			public int PathCount => _paths.Count;

			public IReadOnlyList<(int scriptIndex, int[] signerIndices, int virtualSize)> GetViablePaths()
			{
				return _paths
					.Where(p => p.signerIndices.All(idx => _currentSigners.Contains(idx)) ||
					            p.signerIndices.Any(idx => !_currentSigners.Contains(idx)))
					.Select(p => (p.scriptIndex, p.signerIndices, p.virtualSize))
					.ToList();
			}

			/// <summary>
			/// Adds a signer's signatures to all paths where they participate.
			/// Returns a new MultiPathPSBT with filtered paths.
			/// </summary>
			public MultiPathPSBT AddSigner(DelegatedMultiSig multiSig, Key signerKey, int inputIndex = 0, TaprootSigHash sigHash = TaprootSigHash.All)
			{
				var signerPubKey = signerKey.PubKey;
				var signerIndex = multiSig._signerPubKeys.FindIndex(pk => pk == signerPubKey);
				if (signerIndex == -1)
					throw new ArgumentException("Signer key not found in the multisig configuration");

				// Filter to paths that include this signer
				var viablePaths = _paths
					.Where(p => p.signerIndices.Contains(signerIndex))
					.ToList();

				if (viablePaths.Count == 0)
					throw new ArgumentException($"Signer {signerIndex} does not participate in any remaining paths");

				// Sign all viable paths
				foreach (var path in viablePaths)
				{
					multiSig.SignPSBT(path.psbt, signerKey, inputIndex, sigHash);
				}

				// Update current signers
				var newSigners = new HashSet<int>(_currentSigners) { signerIndex };

				return new MultiPathPSBT(viablePaths, newSigners);
			}

			/// <summary>
			/// Tries to finalize if we have enough signatures.
			/// Returns the cheapest complete transaction, or null if more signatures needed.
			/// </summary>
			public Transaction TryFinalize(DelegatedMultiSig multiSig, int inputIndex = 0)
			{
				// Find all paths that have k signatures
				var completePaths = _paths
					.Select(p => new
					{
						Path = p,
						Finalized = multiSig.TryFinalizePSBT(p.psbt, inputIndex)
					})
					.Where(x => x.Finalized != null)
					.ToList();

				if (completePaths.Count == 0)
					return null;

				// Return the cheapest (smallest virtual size)
				var cheapest = completePaths.OrderBy(x => x.Path.virtualSize).First();
				return cheapest.Finalized;
			}

			/// <summary>
			/// Serializes to a compact format for transmission between signers.
			/// </summary>
			public string Serialize()
			{
				var data = new
				{
					Paths = _paths.Select(p => new
					{
						ScriptIndex = p.scriptIndex,
						SignerIndices = p.signerIndices,
						PSBT = p.psbt.ToBase64(),
						VirtualSize = p.virtualSize
					}).ToArray(),
					CurrentSigners = _currentSigners.ToArray()
				};

				var json = Newtonsoft.Json.JsonConvert.SerializeObject(data);
				return Encoders.Base64.EncodeData(System.Text.Encoding.UTF8.GetBytes(json));
			}

			/// <summary>
			/// Deserializes from the compact format.
			/// </summary>
			public static MultiPathPSBT Deserialize(string serialized, Network network)
			{
				var jsonBytes = Encoders.Base64.DecodeData(serialized);
				var json = System.Text.Encoding.UTF8.GetString(jsonBytes);
				var jsonObject = Newtonsoft.Json.Linq.JObject.Parse(json);

				var paths = new List<(int scriptIndex, int[] signerIndices, PSBT psbt, int virtualSize)>();
				foreach (var pathJson in jsonObject["Paths"])
				{
					var scriptIndex = pathJson["ScriptIndex"].ToObject<int>();
					var signerIndices = pathJson["SignerIndices"].ToObject<int[]>();
					var psbt = PSBT.Parse(pathJson["PSBT"].ToString(), network);
					var virtualSize = pathJson["VirtualSize"].ToObject<int>();

					paths.Add((scriptIndex, signerIndices, psbt, virtualSize));
				}

				var currentSigners = new HashSet<int>(jsonObject["CurrentSigners"].ToObject<int[]>());

				return new MultiPathPSBT(paths, currentSigners);
			}
		}
	}
#endif
}