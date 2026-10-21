using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.DataEncoders;
#if HAS_SPAN
using NBitcoin.Secp256k1;
#endif

namespace NBitcoin
{
#if HAS_SPAN
	/// <summary>
	/// TaprootMultiSig: a Taproot k-of-n multisig where EVERY participant is an equal signer. There is no owner.
	///
	/// The address is the one of <see cref="DelegatedMultiSig"/> (one BIP387 multi_a k-of-k script per combination
	/// of k signers, the same defined tree, the same sequential PSBT signing and pre-signed fee levels) with one
	/// difference: the Taproot INTERNAL KEY (the key path) is not the key of an owner but the BIP327 (MuSig2)
	/// aggregate of the keys of ALL the n signers:
	///
	///   internal key = KeyAgg(P1, ..., Pn)        (BIP327, "KeyAgg coefficient")
	///
	/// - It is deterministic: anybody with the n public keys computes it, so the address can be rebuilt and
	///   described by a standard descriptor (BIP390 musig() inside BIP386 tr()).
	/// - Nobody can spend alone by the key path. Only ALL n signers together could, with a live MuSig2 session
	///   (an n-of-n, stricter than the k-of-n of the scripts); this class never does it.
	/// - Why not the plain sum P1 + ... + Pn: a participant could choose his key as X - (sum of the others), so
	///   the sum would be X, a key only he knows, and he could spend ALONE by the key path (rogue-key attack).
	///   KeyAgg multiplies every key by a coefficient that depends on all the keys, which prevents it.
	/// - Why not an unspendable "NUMS" key (BIP341): it also blocks the key path, but forever; the aggregate keeps
	///   the option of a cheaper and more private n-of-n spend when every signer is online.
	///
	/// Key order. Plain keys: the signers in x-only order (BIP387 sortedmulti_a) and the aggregate over the keys
	/// sorted by BIP327 KeySort. HD wallet (<see cref="FromExtPubKeys"/>): ONE order for every address, the order of
	/// the extended public keys (<see cref="DelegatedMultiSig.SortExtPubKeys"/>), for the scripts AND the aggregate,
	/// so the whole wallet is the single ranged descriptor of <see cref="GetRangedDescriptor"/>:
	///   tr(musig(xpubA/*,xpubB/*,...),{sortedmulti_a(k,xpubA/*,...),...})
	/// </summary>
	public class TaprootMultiSig : DelegatedMultiSig
	{
		private readonly List<PubKey> _aggregateOrder;

		/// <summary>
		/// Builds the multisig from plain public keys, in a canonical order (the result does not depend on the order
		/// they are given in): the scripts by x-only key, the internal key = KeyAgg(KeySort(keys)).
		/// </summary>
		public TaprootMultiSig(List<PubKey> signerPubKeys, int requiredSignatures, Network network)
			: this(signerPubKeys, requiredSignatures, network, sortSigners: true, KeySort(signerPubKeys))
		{
		}

		private TaprootMultiSig(List<PubKey> signerPubKeys, int requiredSignatures, Network network, bool sortSigners, List<PubKey> aggregateOrder)
			: base(AggregateInternalKey(aggregateOrder), signerPubKeys, requiredSignatures, network, sortSigners)
		{
			_aggregateOrder = aggregateOrder;
		}

		/// <summary>
		/// Builds the multisig of an HD wallet at one address index: every key is the child <paramref name="index"/>
		/// of its extended public key, in the order of the extended public keys for the scripts and the aggregate.
		/// </summary>
		public static TaprootMultiSig FromExtPubKeys(IEnumerable<ExtPubKey> signerExtPubKeys, int requiredSignatures, uint index, Network network)
		{
			if (signerExtPubKeys == null)
				throw new ArgumentNullException(nameof(signerExtPubKeys));
			var keys = SortExtPubKeys(signerExtPubKeys).Select(extPubKey => extPubKey.Derive(index).PubKey).ToList();
			return new TaprootMultiSig(keys, requiredSignatures, network, sortSigners: false, keys);
		}

		/// <summary>The address of an HD wallet at one index (see <see cref="FromExtPubKeys"/>).</summary>
		public static TaprootAddress CreateAddress(IEnumerable<ExtPubKey> signerExtPubKeys, int requiredSignatures, uint index, Network network)
		{
			return FromExtPubKeys(signerExtPubKeys, requiredSignatures, index, network).Address;
		}

		/// <summary>The address of plain public keys (see the constructor).</summary>
		public static TaprootAddress CreateAddress(List<PubKey> signerPubKeys, int requiredSignatures, Network network)
		{
			return new TaprootMultiSig(signerPubKeys, requiredSignatures, network).Address;
		}

		/// <summary>
		/// The BIP327 KeyAgg of <paramref name="pubKeys"/> IN THE GIVEN ORDER, as a Taproot internal key (its x
		/// coordinate). Check it against the BIP327 vectors (key_agg_vectors.json).
		/// </summary>
		public static TaprootInternalPubKey AggregateInternalKey(IEnumerable<PubKey> pubKeys)
		{
			if (pubKeys == null)
				throw new ArgumentNullException(nameof(pubKeys));
			var ecKeys = pubKeys.Select(pubKey => ECPubKey.Create(pubKey.Compress().ToBytes())).ToArray();
			if (ecKeys.Length == 0)
				throw new ArgumentException("At least one public key is required", nameof(pubKeys));
			var aggregate = ECPubKey.MusigAggregate(ecKeys, sort: false);
			return new TaprootInternalPubKey(aggregate.ToXOnlyPubKey().ToBytes());
		}

		/// <summary>BIP327 KeySort: the keys in the order of their 33-byte compressed encoding.</summary>
		public static List<PubKey> KeySort(IEnumerable<PubKey> pubKeys)
		{
			if (pubKeys == null)
				throw new ArgumentNullException(nameof(pubKeys));
			return pubKeys.Select(pubKey => pubKey.Compress())
				.OrderBy(pubKey => Encoders.Hex.EncodeData(pubKey.ToBytes()), StringComparer.Ordinal).ToList();
		}

		/// <summary>The keys of the aggregate (the internal key), in the order they were aggregated.</summary>
		public IReadOnlyList<PubKey> AggregatedPubKeys => _aggregateOrder.AsReadOnly();

		/// <summary>
		/// The descriptor of this address with the internal key written as BIP390 musig() of the n keys (in the order
		/// of the aggregate). <see cref="DelegatedMultiSig.GetDescriptor"/> gives the same address with the aggregate
		/// as a plain x-only key, which descriptor wallets without musig() support (Bitcoin Core before musig())
		/// also understand.
		/// </summary>
		public string GetMuSigDescriptor()
		{
			var musig = "musig(" + string.Join(",", _aggregateOrder.Select(pubKey => pubKey.ToHex())) + ")";
			var leaves = DescriptorLeaves(pubKey => Encoders.Hex.EncodeData(pubKey.TaprootInternalKey.ToBytes()));
			return NBitcoin.WalletPolicies.Miniscript.AddChecksum($"tr({musig},{DescriptorTree(leaves)})");
		}

		/// <summary>
		/// The ranged descriptor of a whole HD wallet built with <see cref="FromExtPubKeys"/> (BIP390 musig() of the
		/// ranged keys inside BIP386 tr(), BIP387 sortedmulti_a leaves): its address i is FromExtPubKeys(..., i, ...).
		/// </summary>
		public static string GetRangedDescriptor(IEnumerable<ExtPubKey> signerExtPubKeys, int requiredSignatures, Network network)
		{
			if (signerExtPubKeys == null)
				throw new ArgumentNullException(nameof(signerExtPubKeys));
			if (network == null)
				throw new ArgumentNullException(nameof(network));
			var signers = SortExtPubKeys(signerExtPubKeys).Select(extPubKey => extPubKey.ToString(network) + "/*").ToList();
			if (requiredSignatures < 1 || requiredSignatures > signers.Count)
				throw new ArgumentException($"Required signatures must be between 1 and {signers.Count}", nameof(requiredSignatures));
			var leaves = Combinations(signers.Count, requiredSignatures)
				.Select(combination => $"sortedmulti_a({requiredSignatures},{string.Join(",", combination.Select(index => signers[index]))})")
				.ToList();
			return NBitcoin.WalletPolicies.Miniscript.AddChecksum($"tr(musig({string.Join(",", signers)}),{DescriptorTree(leaves)})");
		}
	}
#endif
}
