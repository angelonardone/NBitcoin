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
			var result = new List<int[]>();
			var combination = new int[k];
			GenerateCombinations(0, 0, n, k, combination, result);
			return result;
		}

		private static void GenerateCombinations(int start, int index, int n, int k, int[] combination, List<int[]> result)
		{
			if (index == k)
			{
				result.Add((int[])combination.Clone());
				return;
			}

			for (int i = start; i < n; i++)
			{
				combination[index] = i;
				GenerateCombinations(i + 1, index + 1, n, k, combination, result);
			}
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
	}
#endif
}