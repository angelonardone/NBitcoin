using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
#if HAS_SPAN
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
#endif

namespace NBitcoin
{
#if HAS_SPAN
	/// <summary>
	/// DelegatedMultiSig2: a Taproot k-of-n multisig where every k-of-n script is ONE MuSig2 (BIP327) key.
	///
	/// - The owner spends alone by the key path (<see cref="SignOwnerKeyPath"/>).
	/// - Any k of the n signers spend by the script path: the leaf of THOSE k signers is
	///   &lt;KeyAgg(KeySort(their keys))&gt; OP_CHECKSIG, so on chain there is one key and one 64-byte signature
	///   (cheaper and more private than the k signatures of <see cref="DelegatedMultiSig"/>).
	/// - MuSig2 is interactive: the k signers must be present at the same time, first to exchange nonces and
	///   then to sign (<see cref="MuSig2Spend"/>). Only the leaf of the signers present is signed; there are no
	///   pre-signed fee levels and no nonces for other leaves.
	///
	/// The construction is the one of <see cref="DelegatedMultiSig"/> (standardized 2026-10-08), only the leaves
	/// change:
	/// - signers in a canonical order: plain keys by x-only key; HD wallets (<see cref="FromExtPubKeys"/>) by the
	///   bytes of the extended public key, the same order for every address;
	/// - one leaf per combination of k signers, the combinations in lexicographic order over the signer order;
	/// - the DEFINED tree of <see cref="DelegatedMultiSig"/> (every leaf at depth ceil(log2 C(n,k)) or one less);
	/// - each leaf key = BIP327 KeyAgg over the keys of the combination sorted by KeySort, as BIP390 musig()
	///   requires ("Keys must be sorted with the KeySort algorithm after all derivation and prior to
	///   aggregation"), so the whole wallet is the BIP390 descriptor of <see cref="GetRangedDescriptor"/>:
	///   tr(OWNER/*,{pk(musig(xpubA/*,xpubB/*)),...}).
	///
	/// <see cref="TaprootMultiSig2"/> is the same without owner: its key path is the KeyAgg of ALL the signers.
	/// </summary>
	public class DelegatedMultiSig2
	{
		// null in a multisig without owner (TaprootMultiSig2)
		private readonly PubKey _ownerPubKey;
		private readonly TaprootInternalPubKey _internalKey;
		private readonly List<PubKey> _signerPubKeys;
		private readonly int _requiredSignatures;
		private readonly Network _network;
		private readonly List<TapScript> _scripts = new List<TapScript>();
		// per leaf: the signer indices of its combination (signer order) and its keys in KeySort order
		private readonly List<int[]> _combinations;
		private readonly List<PubKey[]> _leafPubKeys = new List<PubKey[]>();
		private readonly TaprootSpendInfo _taprootSpendInfo;

		/// <summary>
		/// Builds the multisig from plain public keys. The signers are put in x-only order, so the result does not
		/// depend on the order they are given in.
		/// </summary>
		public DelegatedMultiSig2(PubKey ownerPubKey, List<PubKey> signerPubKeys, int requiredSignatures, Network network)
			: this(ownerPubKey ?? throw new ArgumentNullException(nameof(ownerPubKey)), ownerPubKey.TaprootInternalKey, signerPubKeys, requiredSignatures, network, sortSigners: true)
		{
		}

		/// <summary>For a multisig WITHOUT owner (<see cref="TaprootMultiSig2"/>): the key path is <paramref name="internalKey"/>.</summary>
		protected DelegatedMultiSig2(TaprootInternalPubKey internalKey, List<PubKey> signerPubKeys, int requiredSignatures, Network network, bool sortSigners)
			: this(null, internalKey ?? throw new ArgumentNullException(nameof(internalKey)), signerPubKeys, requiredSignatures, network, sortSigners)
		{
		}

		private DelegatedMultiSig2(PubKey ownerPubKey, TaprootInternalPubKey internalKey, List<PubKey> signerPubKeys, int requiredSignatures, Network network, bool sortSigners)
		{
			if (signerPubKeys == null || signerPubKeys.Count < 2)
				throw new ArgumentException("At least two signer public keys are required", nameof(signerPubKeys));
			// 1-of-n has nothing to aggregate: that is a DelegatedMultiSig
			if (requiredSignatures < 2 || requiredSignatures > signerPubKeys.Count)
				throw new ArgumentException($"Required signatures must be between 2 and {signerPubKeys.Count}", nameof(requiredSignatures));
			if (network == null)
				throw new ArgumentNullException(nameof(network));
			var keys = signerPubKeys.Select(pubKey => pubKey.Compress()).ToList();
			if (keys.Select(XOnlyHex).Distinct().Count() != keys.Count)
				throw new ArgumentException("The signer public keys must be different", nameof(signerPubKeys));
			var combinationCount = DelegatedMultiSig.CalculateCombinationCount(keys.Count, requiredSignatures);
			if (combinationCount > 1000000)
				throw new ArgumentException($"The number of k-of-n combinations ({combinationCount:N0}) is too large. Maximum supported combinations: 1,000,000", nameof(requiredSignatures));

			_ownerPubKey = ownerPubKey;
			_internalKey = internalKey;
			_signerPubKeys = sortSigners ? keys.OrderBy(XOnlyHex, StringComparer.Ordinal).ToList() : keys;
			_requiredSignatures = requiredSignatures;
			_network = network;
			_combinations = DelegatedMultiSig.GetCombinations(_signerPubKeys.Count, requiredSignatures);

			foreach (var combination in _combinations)
			{
				var leafKeys = KeySort(combination.Select(index => _signerPubKeys[index]));
				var aggregate = AggregateXOnly(leafKeys);
				var script = new Script(Op.GetPushOp(aggregate), OpcodeType.OP_CHECKSIG);
				_scripts.Add(script.ToTapScript(TapLeafVersion.C0));
				_leafPubKeys.Add(leafKeys.ToArray());
			}
			_taprootSpendInfo = DelegatedMultiSig.BuildDefinedTree(_internalKey, _scripts);
		}

		/// <summary>
		/// Builds the multisig of an HD wallet at one address index: every key is the child <paramref name="index"/>
		/// of its extended public key, the signers in the order of their extended public keys (the same for every
		/// index), so <see cref="GetRangedDescriptor"/> describes every address.
		/// </summary>
		public static DelegatedMultiSig2 FromExtPubKeys(ExtPubKey ownerExtPubKey, IEnumerable<ExtPubKey> signerExtPubKeys, int requiredSignatures, uint index, Network network)
		{
			if (ownerExtPubKey == null)
				throw new ArgumentNullException(nameof(ownerExtPubKey));
			if (signerExtPubKeys == null)
				throw new ArgumentNullException(nameof(signerExtPubKeys));
			var owner = ownerExtPubKey.Derive(index).PubKey;
			var signers = DelegatedMultiSig.SortExtPubKeys(signerExtPubKeys).Select(extPubKey => extPubKey.Derive(index).PubKey).ToList();
			return new DelegatedMultiSig2(owner, owner.TaprootInternalKey, signers, requiredSignatures, network, sortSigners: false);
		}

		public static TaprootAddress CreateAddress(PubKey ownerPubKey, List<PubKey> signerPubKeys, int requiredSignatures, Network network)
		{
			return new DelegatedMultiSig2(ownerPubKey, signerPubKeys, requiredSignatures, network).Address;
		}

		public static TaprootAddress CreateAddress(ExtPubKey ownerExtPubKey, IEnumerable<ExtPubKey> signerExtPubKeys, int requiredSignatures, uint index, Network network)
		{
			return FromExtPubKeys(ownerExtPubKey, signerExtPubKeys, requiredSignatures, index, network).Address;
		}

		/// <summary>BIP327 KeySort: the keys in the order of their 33-byte compressed encoding.</summary>
		public static List<PubKey> KeySort(IEnumerable<PubKey> pubKeys) => TaprootMultiSig.KeySort(pubKeys);

		// BIP327 KeyAgg of the keys in the given order, as an x-only key
		internal static byte[] AggregateXOnly(IEnumerable<PubKey> pubKeys)
		{
			return TaprootMultiSig.AggregateInternalKey(pubKeys).ToBytes();
		}

		private static string XOnlyHex(PubKey pubKey) => Encoders.Hex.EncodeData(pubKey.TaprootInternalKey.ToBytes());

		public Network Network => _network;

		public TaprootAddress Address => TaprootPubKey.GetAddress(_network);

		public TaprootPubKey TaprootPubKey => _taprootSpendInfo.OutputPubKey.OutputKey;

		public TaprootSpendInfo TaprootSpendInfo => _taprootSpendInfo;

		public IReadOnlyList<TapScript> Scripts => _scripts.AsReadOnly();

		/// <summary>The owner's public key (the key path); null when there is no owner.</summary>
		public PubKey OwnerPubKey => _ownerPubKey;

		public bool HasOwner => _ownerPubKey != null;

		/// <summary>The Taproot internal key (the owner's key, or the aggregate of all the signers).</summary>
		public TaprootInternalPubKey InternalKey => _internalKey;

		/// <summary>The signers' public keys in signer order. A signer's index is its position here.</summary>
		public IReadOnlyList<PubKey> SignerPubKeys => _signerPubKeys.AsReadOnly();

		public int RequiredSignatures => _requiredSignatures;

		/// <summary>The signer indices of the combination of a leaf, in signer order.</summary>
		public IReadOnlyList<int> GetScriptSignerIndices(int scriptIndex) => Array.AsReadOnly(_combinations[scriptIndex]);

		/// <summary>The keys aggregated in a leaf, in KeySort order.</summary>
		public IReadOnlyList<PubKey> GetScriptPubKeys(int scriptIndex) => Array.AsReadOnly(_leafPubKeys[scriptIndex]);

		/// <summary>The leaf of exactly these k signers (signer indices, any order).</summary>
		public int GetScriptIndex(IEnumerable<int> signerIndices)
		{
			if (signerIndices == null)
				throw new ArgumentNullException(nameof(signerIndices));
			var wanted = signerIndices.OrderBy(index => index).ToArray();
			if (wanted.Length != _requiredSignatures || wanted.Distinct().Count() != wanted.Length)
				throw new ArgumentException($"Exactly {_requiredSignatures} different signers are required", nameof(signerIndices));
			if (wanted[0] < 0 || wanted[wanted.Length - 1] >= _signerPubKeys.Count)
				throw new ArgumentOutOfRangeException(nameof(signerIndices), "Unknown signer index");
			for (int i = 0; i < _combinations.Count; i++)
				if (_combinations[i].SequenceEqual(wanted))
					return i;
			throw new InvalidOperationException("No leaf for these signers");
		}

		/// <summary>
		/// The descriptor of this address (BIP386 tr(), BIP390 musig() in every leaf), with its checksum. Bitcoin Core
		/// versions without musig() do not read it: <see cref="GetDescriptorWithoutMuSig"/> gives the same address.
		/// </summary>
		public string GetDescriptor()
		{
			var leaves = Enumerable.Range(0, _scripts.Count)
				.Select(i => $"pk(musig({string.Join(",", _leafPubKeys[i].Select(pubKey => pubKey.ToHex()))}))")
				.ToList();
			return NBitcoin.WalletPolicies.Miniscript.AddChecksum($"tr({InternalKeyExpression()},{DelegatedMultiSig.TreeExpression(leaves, 0, leaves.Count)})");
		}

		/// <summary>The same address with every aggregate written as a plain x-only key (any Taproot descriptor wallet).</summary>
		public string GetDescriptorWithoutMuSig()
		{
			var leaves = _scripts.Select(script => $"pk({Encoders.Hex.EncodeData(script.Script.ToOps().First().PushData)})").ToList();
			return NBitcoin.WalletPolicies.Miniscript.AddChecksum($"tr({Encoders.Hex.EncodeData(_internalKey.ToBytes())},{DelegatedMultiSig.TreeExpression(leaves, 0, leaves.Count)})");
		}

		// The key path in GetDescriptor: the owner's key as x-only (TaprootMultiSig2: musig() of all the signers)
		protected virtual string InternalKeyExpression() => Encoders.Hex.EncodeData(_internalKey.ToBytes());

		// The leaves of a ranged descriptor: pk(musig(...)) of every combination of the ranged signer keys.
		protected static string RangedTree(IReadOnlyList<string> signers, int requiredSignatures)
		{
			if (requiredSignatures < 2 || requiredSignatures > signers.Count)
				throw new ArgumentException($"Required signatures must be between 2 and {signers.Count}", nameof(requiredSignatures));
			var leaves = DelegatedMultiSig.GetCombinations(signers.Count, requiredSignatures)
				.Select(combination => $"pk(musig({string.Join(",", combination.Select(index => signers[index]))}))")
				.ToList();
			return DelegatedMultiSig.TreeExpression(leaves, 0, leaves.Count);
		}

		/// <summary>
		/// The ranged descriptor of a whole HD wallet built with <see cref="FromExtPubKeys"/>: its address i is
		/// FromExtPubKeys(..., i, ...).Address (BIP390 sorts the keys of each musig() after the derivation).
		/// </summary>
		public static string GetRangedDescriptor(ExtPubKey ownerExtPubKey, IEnumerable<ExtPubKey> signerExtPubKeys, int requiredSignatures, Network network)
		{
			if (ownerExtPubKey == null)
				throw new ArgumentNullException(nameof(ownerExtPubKey));
			if (signerExtPubKeys == null)
				throw new ArgumentNullException(nameof(signerExtPubKeys));
			if (network == null)
				throw new ArgumentNullException(nameof(network));
			var signers = DelegatedMultiSig.SortExtPubKeys(signerExtPubKeys).Select(extPubKey => extPubKey.ToString(network) + "/*").ToList();
			return NBitcoin.WalletPolicies.Miniscript.AddChecksum($"tr({ownerExtPubKey.ToString(network)}/*,{RangedTree(signers, requiredSignatures)})");
		}

		/// <summary>The virtual size of the witness of one input: the key path, or the leaf <paramref name="scriptIndex"/>.</summary>
		public WitScript DummyWitness(int scriptIndex)
		{
			var signature = new byte[64]; // TaprootSigHash.Default: no sighash byte
			if (scriptIndex < 0)
				return new WitScript(Op.GetPushOp(signature));
			var script = _scripts[scriptIndex];
			return new WitScript(new[] { signature, script.Script.ToBytes(), _taprootSpendInfo.GetControlBlock(script).ToBytes() }, true);
		}

		/// <summary>
		/// The owner spends alone by the key path (no MuSig2): one Schnorr signature per input. Every input must be
		/// an address of a DelegatedMultiSig2 with an owner; <paramref name="ownerKeys"/> = the owner's key of each.
		/// </summary>
		public static Transaction SignOwnerKeyPath(Transaction transaction, IReadOnlyList<TxOut> spentOutputs, IReadOnlyList<DelegatedMultiSig2> inputMultiSigs, IReadOnlyList<Key> ownerKeys)
		{
			MuSig2Spend.CheckInputs(transaction, spentOutputs, inputMultiSigs);
			if (ownerKeys == null || ownerKeys.Count != transaction.Inputs.Count)
				throw new ArgumentException("One owner key per input is required", nameof(ownerKeys));
			var signed = transaction.Clone();
			var spent = spentOutputs.ToArray();
			for (int i = 0; i < signed.Inputs.Count; i++)
			{
				var multiSig = inputMultiSigs[i];
				if (!multiSig.HasOwner)
					throw new InvalidOperationException("This multisig has no owner: nobody spends alone by the key path");
				if (ownerKeys[i].PubKey.Compress() != multiSig.OwnerPubKey.Compress())
					throw new ArgumentException($"The key of input {i} is not the owner's key", nameof(ownerKeys));
				var hash = signed.GetSignatureHashTaproot(spent, new TaprootExecutionData(i) { SigHash = TaprootSigHash.Default });
				var signature = ownerKeys[i].SignTaprootKeySpend(hash, multiSig.TaprootSpendInfo.MerkleRoot, TaprootSigHash.Default);
				signed.Inputs[i].WitScript = new WitScript(Op.GetPushOp(signature.ToBytes()));
			}
			return signed;
		}
	}

	/// <summary>
	/// TaprootMultiSig2: <see cref="DelegatedMultiSig2"/> WITHOUT owner; every participant is an equal signer.
	/// The key path is the BIP327 KeyAgg of ALL the signers (KeySort order, as <see cref="TaprootMultiSig"/>):
	/// nobody spends alone, and when all n are present they spend by the key path (<see cref="MuSig2Spend.KeyPath"/>),
	/// the cheapest and most private spend. Ranged descriptor: tr(musig(A/*,B/*,...),{pk(musig(A/*,B/*)),...}).
	/// </summary>
	public class TaprootMultiSig2 : DelegatedMultiSig2
	{
		private readonly List<PubKey> _aggregateOrder;

		public TaprootMultiSig2(List<PubKey> signerPubKeys, int requiredSignatures, Network network)
			: this(signerPubKeys, requiredSignatures, network, sortSigners: true)
		{
		}

		private TaprootMultiSig2(List<PubKey> signerPubKeys, int requiredSignatures, Network network, bool sortSigners)
			: this(signerPubKeys, requiredSignatures, network, sortSigners, KeySort(signerPubKeys ?? throw new ArgumentNullException(nameof(signerPubKeys))))
		{
		}

		private TaprootMultiSig2(List<PubKey> signerPubKeys, int requiredSignatures, Network network, bool sortSigners, List<PubKey> aggregateOrder)
			: base(TaprootMultiSig.AggregateInternalKey(aggregateOrder), signerPubKeys, requiredSignatures, network, sortSigners)
		{
			_aggregateOrder = aggregateOrder;
		}

		/// <summary>The multisig of an HD wallet at one address index (see <see cref="DelegatedMultiSig2.FromExtPubKeys"/>).</summary>
		public static TaprootMultiSig2 FromExtPubKeys(IEnumerable<ExtPubKey> signerExtPubKeys, int requiredSignatures, uint index, Network network)
		{
			if (signerExtPubKeys == null)
				throw new ArgumentNullException(nameof(signerExtPubKeys));
			var keys = DelegatedMultiSig.SortExtPubKeys(signerExtPubKeys).Select(extPubKey => extPubKey.Derive(index).PubKey).ToList();
			return new TaprootMultiSig2(keys, requiredSignatures, network, sortSigners: false);
		}

		public static TaprootAddress CreateAddress(List<PubKey> signerPubKeys, int requiredSignatures, Network network)
		{
			return new TaprootMultiSig2(signerPubKeys, requiredSignatures, network).Address;
		}

		public static TaprootAddress CreateAddress(IEnumerable<ExtPubKey> signerExtPubKeys, int requiredSignatures, uint index, Network network)
		{
			return FromExtPubKeys(signerExtPubKeys, requiredSignatures, index, network).Address;
		}

		/// <summary>The keys of the key path aggregate, in KeySort order.</summary>
		public IReadOnlyList<PubKey> AggregatedPubKeys => _aggregateOrder.AsReadOnly();

		protected override string InternalKeyExpression() => $"musig({string.Join(",", _aggregateOrder.Select(pubKey => pubKey.ToHex()))})";

		/// <summary>The ranged descriptor of a whole HD wallet built with <see cref="FromExtPubKeys"/>.</summary>
		public static string GetRangedDescriptor(IEnumerable<ExtPubKey> signerExtPubKeys, int requiredSignatures, Network network)
		{
			if (signerExtPubKeys == null)
				throw new ArgumentNullException(nameof(signerExtPubKeys));
			if (network == null)
				throw new ArgumentNullException(nameof(network));
			var signers = DelegatedMultiSig.SortExtPubKeys(signerExtPubKeys).Select(extPubKey => extPubKey.ToString(network) + "/*").ToList();
			return NBitcoin.WalletPolicies.Miniscript.AddChecksum($"tr(musig({string.Join(",", signers)}),{RangedTree(signers, requiredSignatures)})");
		}
	}

	/// <summary>
	/// The secret nonces of ONE signer for ONE <see cref="MuSig2Spend"/> (one per input), between round 1 and round 2.
	/// They cannot be serialized and are used once: <see cref="MuSig2Spend.Sign"/> uses and wipes them, and any
	/// second use is refused. Keep this object in memory only: a secret nonce used twice with different nonces of
	/// the other signers gives away the private key (BIP327).
	/// </summary>
	public sealed class MuSig2SecretNonces : IDisposable
	{
		private MusigPrivNonce[] _nonces;

		internal MuSig2SecretNonces(uint256 spendId, int signerIndex, MusigPrivNonce[] nonces)
		{
			SpendId = spendId;
			SignerIndex = signerIndex;
			_nonces = nonces;
			PublicNonces = nonces.Select(nonce => nonce.CreatePubNonce().ToBytes()).ToArray();
		}

		/// <summary>The <see cref="MuSig2Spend.Id"/> they were created for.</summary>
		public uint256 SpendId { get; }

		public int SignerIndex { get; }

		/// <summary>The public nonces to send to the other signers: 66 bytes per input.</summary>
		public IReadOnlyList<byte[]> PublicNonces { get; }

		public bool IsUsed => _nonces == null;

		// hands the nonces out once; from then on the object is used
		internal MusigPrivNonce[] Take()
		{
			var nonces = _nonces ?? throw new InvalidOperationException("These secret nonces were already used or wiped: start again with new nonces");
			_nonces = null;
			return nonces;
		}

		public void Dispose()
		{
			var nonces = _nonces;
			_nonces = null;
			if (nonces != null)
				foreach (var nonce in nonces)
					nonce.Dispose();
		}
	}

	/// <summary>
	/// One payment signed live with MuSig2 by the signers present, for <see cref="DelegatedMultiSig2"/> and
	/// <see cref="TaprootMultiSig2"/>. Every signer builds the same object from the same public data (the unsigned
	/// transaction, the spent outputs, the multisig of the address of each input and who signs), so they all get
	/// the same <see cref="Id"/> and the same messages to sign.
	///
	///   round 1 (no private key): each signer <see cref="CreateNonces"/> → sends <see cref="MuSig2SecretNonces.PublicNonces"/>
	///   round 2: each signer <see cref="Sign"/> with every public nonce → sends its partial signatures (32 bytes per input)
	///   anybody: <see cref="Finalize"/> checks every partial signature and returns the signed transaction
	///
	/// A signer is a signer index (the position in <see cref="DelegatedMultiSig2.SignerPubKeys"/>, the same member
	/// at every address of an HD wallet). If a signer leaves or anything fails, the spend is abandoned and a new
	/// one starts with new nonces.
	/// </summary>
	public sealed class MuSig2Spend
	{
		private readonly Transaction _transaction;
		private readonly TxOut[] _spentOutputs;
		private readonly DelegatedMultiSig2[] _inputMultiSigs;
		private readonly int[] _signers;
		private readonly uint256[] _sigHashes;

		private MuSig2Spend(Transaction transaction, IReadOnlyList<TxOut> spentOutputs, IReadOnlyList<DelegatedMultiSig2> inputMultiSigs, int[] signers, int scriptIndex)
		{
			_transaction = transaction.Clone();
			_spentOutputs = spentOutputs.ToArray();
			_inputMultiSigs = inputMultiSigs.ToArray();
			_signers = signers;
			ScriptIndex = scriptIndex;
			_sigHashes = new uint256[_transaction.Inputs.Count];
			for (int i = 0; i < _sigHashes.Length; i++)
			{
				var executionData = scriptIndex < 0
					? new TaprootExecutionData(i) { SigHash = TaprootSigHash.Default }
					: new TaprootExecutionData(i, _inputMultiSigs[i].Scripts[scriptIndex].LeafHash) { SigHash = TaprootSigHash.Default };
				_sigHashes[i] = _transaction.GetSignatureHashTaproot(_spentOutputs, executionData);
			}
			Id = ComputeId();
		}

		/// <summary>The k signers present spend by their leaf.</summary>
		public static MuSig2Spend ScriptPath(Transaction transaction, IReadOnlyList<TxOut> spentOutputs, IReadOnlyList<DelegatedMultiSig2> inputMultiSigs, IEnumerable<int> signerIndices)
		{
			CheckInputs(transaction, spentOutputs, inputMultiSigs);
			if (signerIndices == null)
				throw new ArgumentNullException(nameof(signerIndices));
			var signers = signerIndices.OrderBy(index => index).ToArray();
			var scriptIndex = inputMultiSigs[0].GetScriptIndex(signers);
			return new MuSig2Spend(transaction, spentOutputs, inputMultiSigs, signers, scriptIndex);
		}

		/// <summary>All n signers of a <see cref="TaprootMultiSig2"/> spend by the key path.</summary>
		public static MuSig2Spend KeyPath(Transaction transaction, IReadOnlyList<TxOut> spentOutputs, IReadOnlyList<DelegatedMultiSig2> inputMultiSigs)
		{
			CheckInputs(transaction, spentOutputs, inputMultiSigs);
			if (inputMultiSigs.Any(multiSig => !(multiSig is TaprootMultiSig2)))
				throw new InvalidOperationException("Only a multisig without owner (TaprootMultiSig2) is spent by all its signers by the key path");
			var signers = Enumerable.Range(0, inputMultiSigs[0].SignerPubKeys.Count).ToArray();
			return new MuSig2Spend(transaction, spentOutputs, inputMultiSigs, signers, -1);
		}

		internal static void CheckInputs(Transaction transaction, IReadOnlyList<TxOut> spentOutputs, IReadOnlyList<DelegatedMultiSig2> inputMultiSigs)
		{
			if (transaction == null)
				throw new ArgumentNullException(nameof(transaction));
			if (spentOutputs == null || spentOutputs.Count != transaction.Inputs.Count)
				throw new ArgumentException("One spent output per input is required", nameof(spentOutputs));
			if (inputMultiSigs == null || inputMultiSigs.Count != transaction.Inputs.Count || transaction.Inputs.Count == 0)
				throw new ArgumentException("One multisig per input is required", nameof(inputMultiSigs));
			var first = inputMultiSigs[0];
			for (int i = 0; i < inputMultiSigs.Count; i++)
			{
				var multiSig = inputMultiSigs[i] ?? throw new ArgumentException($"No multisig for input {i}", nameof(inputMultiSigs));
				if (spentOutputs[i] == null || spentOutputs[i].ScriptPubKey != multiSig.Address.ScriptPubKey)
					throw new ArgumentException($"Input {i} does not spend an output of its multisig address", nameof(spentOutputs));
				if (multiSig.GetType() != first.GetType() || multiSig.SignerPubKeys.Count != first.SignerPubKeys.Count || multiSig.RequiredSignatures != first.RequiredSignatures)
					throw new ArgumentException("Every input must belong to the same multisig wallet", nameof(inputMultiSigs));
			}
		}

		/// <summary>Identifies this spend: the transaction, the spent outputs, the path and the signers.</summary>
		public uint256 Id { get; }

		/// <summary>The leaf being signed, or -1 for the key path.</summary>
		public int ScriptIndex { get; }

		public bool IsKeyPath => ScriptIndex < 0;

		/// <summary>The signer indices that must sign, in order.</summary>
		public IReadOnlyList<int> Signers => Array.AsReadOnly(_signers);

		public Transaction Transaction => _transaction.Clone();

		/// <summary>The virtual size of the signed transaction (exact: the witness of a MuSig2 spend has a fixed size).</summary>
		public int EstimateVirtualSize() => EstimateVirtualSize(_transaction, _inputMultiSigs, ScriptIndex);

		/// <summary>The virtual size of <paramref name="transaction"/> once signed by the key path (-1) or by a leaf.</summary>
		public static int EstimateVirtualSize(Transaction transaction, IReadOnlyList<DelegatedMultiSig2> inputMultiSigs, int scriptIndex)
		{
			if (transaction == null)
				throw new ArgumentNullException(nameof(transaction));
			if (inputMultiSigs == null || inputMultiSigs.Count != transaction.Inputs.Count)
				throw new ArgumentException("One multisig per input is required", nameof(inputMultiSigs));
			var dummy = transaction.Clone();
			for (int i = 0; i < dummy.Inputs.Count; i++)
				dummy.Inputs[i].WitScript = inputMultiSigs[i].DummyWitness(scriptIndex);
			return dummy.GetVirtualSize();
		}

		private uint256 ComputeId()
		{
			var stream = new System.IO.MemoryStream();
			void Write(byte[] data)
			{
				var length = BitConverter.GetBytes(data.Length);
				stream.Write(length, 0, length.Length);
				stream.Write(data, 0, data.Length);
			}
			Write(System.Text.Encoding.ASCII.GetBytes("DelegatedMultiSig2/MuSig2Spend"));
			Write(_transaction.ToBytes());
			foreach (var output in _spentOutputs)
				Write(output.ToBytes());
			Write(BitConverter.GetBytes(ScriptIndex));
			foreach (var signer in _signers)
				Write(BitConverter.GetBytes(signer));
			return new uint256(Hashes.SHA256(stream.ToArray()));
		}

		// The MuSig2 context of one input: the keys of the leaf (or of every signer for the key path, tweaked as
		// BIP341 requires) and the message of that input.
		private MusigContext Context(int inputIndex, PubKey signingPubKey)
		{
			var multiSig = _inputMultiSigs[inputIndex];
			var keys = IsKeyPath ? ((TaprootMultiSig2)multiSig).AggregatedPubKeys : multiSig.GetScriptPubKeys(ScriptIndex);
			var ecKeys = keys.Select(pubKey => ECPubKey.Create(pubKey.ToBytes())).ToArray();
			var signing = signingPubKey == null ? null : ECPubKey.Create(signingPubKey.Compress().ToBytes());
			var context = new MusigContext(ecKeys, _sigHashes[inputIndex].ToBytes(), signing);
			if (IsKeyPath)
				context.Tweak(multiSig.TaprootSpendInfo.OutputPubKey.Tweak.Span);
			return context;
		}

		private PubKey SignerPubKey(int inputIndex, int signerIndex) => _inputMultiSigs[inputIndex].SignerPubKeys[signerIndex];

		private void CheckSigner(int signerIndex)
		{
			if (Array.IndexOf(_signers, signerIndex) < 0)
				throw new ArgumentException($"Signer {signerIndex} is not one of the signers of this spend", nameof(signerIndex));
		}

		/// <summary>
		/// Round 1: the secret nonces of <paramref name="signerIndex"/>, one per input. No private key is needed
		/// (BIP327 NonceGen with the public key only and fresh randomness).
		/// </summary>
		public MuSig2SecretNonces CreateNonces(int signerIndex)
		{
			CheckSigner(signerIndex);
			var nonces = new MusigPrivNonce[_transaction.Inputs.Count];
			for (int i = 0; i < nonces.Length; i++)
				nonces[i] = Context(i, SignerPubKey(i, signerIndex)).GenerateNonce();
			return new MuSig2SecretNonces(Id, signerIndex, nonces);
		}

		// the public nonces of every signer, in KeySort order of the keys of each input, checked
		private MusigPubNonce[] OrderedNonces(int inputIndex, IReadOnlyDictionary<int, IReadOnlyList<byte[]>> publicNonces)
		{
			if (publicNonces == null)
				throw new ArgumentNullException(nameof(publicNonces));
			if (publicNonces.Count != _signers.Length || _signers.Any(signer => !publicNonces.ContainsKey(signer)))
				throw new ArgumentException("A public nonce of every signer, and only of them, is required", nameof(publicNonces));
			return _signers.Select(signer =>
			{
				var nonces = publicNonces[signer];
				if (nonces == null || nonces.Count != _transaction.Inputs.Count)
					throw new ArgumentException($"Signer {signer} must give one public nonce per input", nameof(publicNonces));
				return new MusigPubNonce(nonces[inputIndex]);
			}).ToArray();
		}

		/// <summary>
		/// Round 2: the partial signatures of one signer (32 bytes per input). <paramref name="inputKeys"/> = his
		/// private key at the address of each input. Uses and wipes <paramref name="secretNonces"/>: whatever
		/// happens, they cannot be used again.
		/// </summary>
		public IReadOnlyList<byte[]> Sign(IReadOnlyList<Key> inputKeys, MuSig2SecretNonces secretNonces, IReadOnlyDictionary<int, IReadOnlyList<byte[]>> publicNonces)
		{
			if (secretNonces == null)
				throw new ArgumentNullException(nameof(secretNonces));
			var nonces = secretNonces.Take();
			try
			{
				if (secretNonces.SpendId != Id)
					throw new ArgumentException("These secret nonces were created for another spend", nameof(secretNonces));
				var signerIndex = secretNonces.SignerIndex;
				CheckSigner(signerIndex);
				if (inputKeys == null || inputKeys.Count != _transaction.Inputs.Count)
					throw new ArgumentException("One private key per input is required", nameof(inputKeys));
				if (publicNonces == null || !publicNonces.TryGetValue(signerIndex, out var mine) || mine == null || mine.Count != nonces.Length
					|| Enumerable.Range(0, nonces.Length).Any(i => !mine[i].SequenceEqual(secretNonces.PublicNonces[i])))
					throw new ArgumentException("The public nonces do not contain this signer's own nonces", nameof(publicNonces));
				var signatures = new byte[nonces.Length][];
				for (int i = 0; i < nonces.Length; i++)
				{
					if (inputKeys[i] == null || inputKeys[i].PubKey.Compress() != SignerPubKey(i, signerIndex).Compress())
						throw new ArgumentException($"The key of input {i} is not the key of signer {signerIndex}", nameof(inputKeys));
					var context = Context(i, null);
					context.ProcessNonces(OrderedNonces(i, publicNonces));
					var secret = inputKeys[i].ToBytes();
					try
					{
						using var privateKey = ECPrivKey.Create(secret);
						signatures[i] = context.Sign(privateKey, nonces[i]).ToBytes();
					}
					finally
					{
						Array.Clear(secret, 0, secret.Length);
					}
				}
				return signatures;
			}
			finally
			{
				foreach (var nonce in nonces)
					nonce.Dispose();
			}
		}

		/// <summary>
		/// Checks the partial signature of every signer against its public nonce and key, aggregates them and
		/// returns the signed transaction. A wrong partial signature names its signer.
		/// </summary>
		public Transaction Finalize(IReadOnlyDictionary<int, IReadOnlyList<byte[]>> publicNonces, IReadOnlyDictionary<int, IReadOnlyList<byte[]>> partialSignatures)
		{
			if (partialSignatures == null)
				throw new ArgumentNullException(nameof(partialSignatures));
			if (partialSignatures.Count != _signers.Length || _signers.Any(signer => !partialSignatures.ContainsKey(signer)))
				throw new ArgumentException("A partial signature of every signer, and only of them, is required", nameof(partialSignatures));
			var signed = _transaction.Clone();
			for (int i = 0; i < signed.Inputs.Count; i++)
			{
				var context = Context(i, null);
				var nonces = OrderedNonces(i, publicNonces);
				context.ProcessNonces(nonces);
				var partials = new MusigPartialSignature[_signers.Length];
				for (int s = 0; s < _signers.Length; s++)
				{
					var signer = _signers[s];
					var signatures = partialSignatures[signer];
					if (signatures == null || signatures.Count != signed.Inputs.Count || signatures[i] == null || signatures[i].Length != 32)
						throw new ArgumentException($"Signer {signer} must give one 32-byte partial signature per input", nameof(partialSignatures));
					partials[s] = new MusigPartialSignature(signatures[i]);
					var pubKey = ECPubKey.Create(SignerPubKey(i, signer).Compress().ToBytes());
					if (!context.Verify(pubKey, nonces[s], partials[s]))
						throw new InvalidOperationException($"The partial signature of signer {signer} for input {i} is not valid");
				}
				var signature = new TaprootSignature(new SchnorrSignature(context.AggregateSignatures(partials).ToBytes()), TaprootSigHash.Default);
				var multiSig = _inputMultiSigs[i];
				if (IsKeyPath)
				{
					signed.Inputs[i].WitScript = new WitScript(Op.GetPushOp(signature.ToBytes()));
				}
				else
				{
					var script = multiSig.Scripts[ScriptIndex];
					signed.Inputs[i].WitScript = new WitScript(new[] { signature.ToBytes(), script.Script.ToBytes(), multiSig.TaprootSpendInfo.GetControlBlock(script).ToBytes() }, true);
				}
			}
			return signed;
		}
	}
#endif
}
