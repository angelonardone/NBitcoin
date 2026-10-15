using System;
using System.Collections.Generic;
using System.Linq;

namespace NBitcoin
{
	/// <summary>
	/// An HD k-of-n SegWit P2SH-P2WSH multisig (OP_CHECKMULTISIG, at most 16 members), the wallet behind the
	/// "Legacy Multisignature" group of Distributed Cryptography. Every member gives two chain-level extended
	/// public keys (receiving and change, BIP48 <c>m/48'/coin'/account'/1'/0</c> and <c>/1</c>); the address
	/// number <c>sequence</c> of a chain uses the child <c>sequence</c> of every member's key, sorted in
	/// lexicographic order (BIP67), so it is the standard descriptor
	/// <c>sh(wsh(sortedmulti(k, xpub/*, ...)))</c> (BIP383) and does not depend on the order of the members.
	/// </summary>
	public class SegWitMultiSigGroup
	{
		private readonly List<ExtPubKey> _receiving;
		private readonly List<ExtPubKey> _change;
		private readonly Dictionary<string, SegWitMultiSig> _cache = new Dictionary<string, SegWitMultiSig>();

		public int RequiredSignatures { get; }
		public int MemberCount => _receiving.Count;
		public Network Network { get; }

		/// <param name="receivingXpubs">the receiving-chain extended public key of each member</param>
		/// <param name="changeXpubs">the change-chain extended public key of each member, in the same member order</param>
		public SegWitMultiSigGroup(IEnumerable<ExtPubKey> receivingXpubs, IEnumerable<ExtPubKey> changeXpubs, int requiredSignatures, Network network)
		{
			_receiving = receivingXpubs?.ToList() ?? throw new ArgumentNullException(nameof(receivingXpubs));
			_change = changeXpubs?.ToList() ?? throw new ArgumentNullException(nameof(changeXpubs));
			Network = network ?? throw new ArgumentNullException(nameof(network));
			if (_receiving.Count != _change.Count)
				throw new ArgumentException("Every member needs a receiving and a change extended public key");
			if (_receiving.Count < 2 || _receiving.Count > 16)
				throw new ArgumentException("A P2SH-P2WSH multisig has from 2 to 16 members");
			if (requiredSignatures < 1 || requiredSignatures > _receiving.Count)
				throw new ArgumentException("Invalid number of required signatures");
			RequiredSignatures = requiredSignatures;
		}

		/// <summary>The public key of a member at an address (child <paramref name="sequence"/> of its chain key).</summary>
		public PubKey MemberPubKey(int member, int sequence, bool isChange)
		{
			if (sequence < 0)
				throw new ArgumentException("The address sequence can not be negative");
			return (isChange ? _change : _receiving)[member].Derive((uint)sequence).PubKey;
		}

		/// <summary>The multisig of the address number <paramref name="sequence"/> of a chain (keys sorted, BIP67).</summary>
		public SegWitMultiSig GetMultiSig(int sequence, bool isChange)
		{
			var cacheKey = (isChange ? "1/" : "0/") + sequence;
			if (!_cache.TryGetValue(cacheKey, out var ms))
			{
				var keys = Enumerable.Range(0, MemberCount)
					.Select(m => MemberPubKey(m, sequence, isChange))
					.OrderBy(k => k.ToHex(), StringComparer.Ordinal)
					.ToList();
				ms = new SegWitMultiSig(keys, RequiredSignatures, Network);
				_cache[cacheKey] = ms;
			}
			return ms;
		}

		/// <summary>The member that owns <paramref name="pubKey"/> at that address, or -1.</summary>
		public int MemberOf(PubKey pubKey, int sequence, bool isChange)
		{
			for (int m = 0; m < MemberCount; m++)
				if (MemberPubKey(m, sequence, isChange) == pubKey)
					return m;
			return -1;
		}

		/// <summary>The ranged descriptor of one chain, with its checksum (BIP383 sortedmulti inside sh(wsh())).</summary>
		public string GetDescriptor(bool isChange)
		{
			var keys = (isChange ? _change : _receiving).Select(x => x.ToString(Network) + "/*");
			return WalletPolicies.Miniscript.AddChecksum($"sh(wsh(sortedmulti({RequiredSignatures},{string.Join(",", keys)})))");
		}
	}

	/// <summary>A coin of a <see cref="SegWitMultiSigGroup"/>: where it is and which address of the group holds it.</summary>
	public class SegWitMultiSigUtxo
	{
		public OutPoint Outpoint { get; set; }
		public Money Amount { get; set; }
		public int Sequence { get; set; }
		public bool IsChange { get; set; }

		public SegWitMultiSigUtxo(OutPoint outpoint, Money amount, int sequence, bool isChange)
		{
			Outpoint = outpoint;
			Amount = amount;
			Sequence = sequence;
			IsChange = isChange;
		}
	}

	/// <summary>The derivation of one input of a bundle.</summary>
	public class SegWitMultiSigBundleInput
	{
		public int Sequence { get; set; }
		public bool IsChange { get; set; }
	}

	/// <summary>One version of the payment: the calculated fee (percent 0) or the calculated fee + percent.</summary>
	public class SegWitMultiSigFeeLevel
	{
		public int Percent { get; set; }
		public PSBT Psbt { get; set; }
	}

	/// <summary>
	/// A payment with pre-signed fee levels: the same coins and the same payment, one PSBT per fee.
	/// The members sign one after the other (maybe days apart): every signer signs every level, and the last
	/// one chooses the level that is sent, so the fee can follow the network without starting again.
	/// </summary>
	public class SegWitMultiSigBundle
	{
		public List<SegWitMultiSigBundleInput> Inputs { get; set; } = new List<SegWitMultiSigBundleInput>();
		public List<SegWitMultiSigFeeLevel> Levels { get; set; } = new List<SegWitMultiSigFeeLevel>();
	}

	/// <summary>What a bundle really pays and who signed it, read from its PSBTs.</summary>
	public class SegWitMultiSigSpendInfo
	{
		public int Required { get; set; }
		public Money TotalIn { get; set; } = Money.Zero;
		public Script PaymentScript { get; set; } = Script.Empty;
		public Script ChangeScript { get; set; }
		/// <summary>the members (index in the group) that signed</summary>
		public List<int> SignedBy { get; set; } = new List<int>();
		public List<Money> Fees { get; set; } = new List<Money>();
		public int Signatures => SignedBy.Count;
		public bool Complete => SignedBy.Count >= Required;
		public bool NextIsLast => SignedBy.Count == Required - 1;
	}

	/// <summary>
	/// Pre-signed fee levels for <see cref="SegWitMultiSigGroup"/> payments (the same idea as the Delegated
	/// multisig of the library): Build, Check, Sign, Finalize. Every check is made on the PSBTs themselves, never
	/// on the message that carried them: a signer signs only a bundle that passed <see cref="Check"/>.
	/// </summary>
	public static class SegWitMultiSigSpend
	{
		/// <summary>At most this many fee options above the calculated fee (so at most 4 levels).</summary>
		public const int MaxExtraFeeLevels = 3;

		/// <summary>The inputs signal replace-by-fee (BIP125), so a higher level can replace a lower one.</summary>
		public const uint InputSequence = 0xFFFFFFFD;

		/// <summary>Rounding margin when checking the fee of a level.</summary>
		public const long FeeToleranceSats = 1000;

		/// <summary>The calculated fee plus the percentage, rounded up to the satoshi.</summary>
		public static Money LevelFee(Money baseFee, int percent) =>
			Money.Satoshis((baseFee.Satoshi * (100 + percent) + 99) / 100);

		/// <summary>Checks a list of extra fee options (10, 20 ... 100, at most 3, no repeats) and sorts it.</summary>
		public static List<int> CheckPercentages(IEnumerable<int> percents)
		{
			var result = new List<int>();
			foreach (var percent in percents ?? Enumerable.Empty<int>())
			{
				CheckPercent(percent);
				if (result.Contains(percent))
					throw new ArgumentException($"The +{percent} % fee option is repeated");
				result.Add(percent);
			}
			if (result.Count > MaxExtraFeeLevels)
				throw new ArgumentException($"At most {MaxExtraFeeLevels} extra fee options are allowed");
			result.Sort();
			return result;
		}

		private static void CheckPercent(int percent)
		{
			if (percent < 10 || percent > 100 || percent % 10 != 0)
				throw new ArgumentException($"Invalid fee percentage {percent}: it must be 10, 20 ... 100");
		}

		/// <summary>
		/// Build the unsigned bundle. <paramref name="sendAll"/>: the whole balance goes to
		/// <paramref name="destination"/> (no change; the amount of each level is the total minus its fee).
		/// Otherwise the change goes to <paramref name="change"/>; a change below the dust limit is not created.
		/// </summary>
		public static SegWitMultiSigBundle Build(SegWitMultiSigGroup group, IList<SegWitMultiSigUtxo> utxos,
			BitcoinAddress destination, Money amount, bool sendAll, BitcoinAddress change, Money baseFee,
			IEnumerable<int> extraPercents)
		{
			if (group == null) throw new ArgumentNullException(nameof(group));
			if (utxos == null || utxos.Count == 0) throw new ArgumentException("No coins to spend");
			if (destination == null) throw new ArgumentNullException(nameof(destination));
			if (baseFee == null || baseFee <= Money.Zero) throw new ArgumentException("The fee must be greater than zero");
			if (!sendAll && change == null) throw new ArgumentNullException(nameof(change));

			var bundle = new SegWitMultiSigBundle();
			foreach (var u in utxos)
				bundle.Inputs.Add(new SegWitMultiSigBundleInput { Sequence = u.Sequence, IsChange = u.IsChange });

			var levels = new List<int> { 0 };
			levels.AddRange(CheckPercentages(extraPercents));
			foreach (var percent in levels)
			{
				var fee = LevelFee(baseFee, percent);
				var tx = BuildTransaction(group.Network, utxos, destination, amount, sendAll, change, fee,
					percent == 0 ? "the fee" : $"the +{percent} % fee option");
				var psbt = PSBT.FromTransaction(tx, group.Network);
				for (int i = 0; i < utxos.Count; i++)
				{
					var ms = group.GetMultiSig(utxos[i].Sequence, utxos[i].IsChange);
					psbt.Inputs[i].WitnessUtxo = new TxOut(utxos[i].Amount, ms.Address.ScriptPubKey);
					psbt.Inputs[i].WitnessScript = ms.MultisigScript;
					psbt.Inputs[i].RedeemScript = ms.P2WSH;
				}
				bundle.Levels.Add(new SegWitMultiSigFeeLevel { Percent = percent, Psbt = psbt });
			}
			Check(group, bundle);
			return bundle;
		}

		private static Transaction BuildTransaction(Network net, IList<SegWitMultiSigUtxo> utxos, BitcoinAddress destination,
			Money amount, bool sendAll, BitcoinAddress change, Money fee, string feeName)
		{
			var tx = net.CreateTransaction();
			tx.Version = 2;
			var total = Money.Zero;
			foreach (var u in utxos)
			{
				tx.Inputs.Add(new TxIn(u.Outpoint) { Sequence = InputSequence });
				total += u.Amount;
			}
			if (sendAll)
			{
				var payment = new TxOut(total - fee, destination);
				if (payment.Value <= Money.Zero || payment.Value < payment.GetDustThreshold())
					throw new ArgumentException($"Not enough balance to pay {feeName}");
				tx.Outputs.Add(payment);
			}
			else
			{
				if (amount == null || amount <= Money.Zero)
					throw new ArgumentException("The amount must be greater than zero");
				var payment = new TxOut(amount, destination);
				if (amount < payment.GetDustThreshold())
					throw new ArgumentException("The amount is too small (dust)");
				var rest = total - amount - fee;
				if (rest < Money.Zero)
					throw new ArgumentException($"Not enough balance to pay {feeName}");
				tx.Outputs.Add(payment);
				var changeOut = new TxOut(rest, change);
				if (rest >= changeOut.GetDustThreshold())
					tx.Outputs.Add(changeOut);
			}
			return tx;
		}

		/// <summary>
		/// Checks that the bundle is what it claims to be and returns what it pays: every level spends the same
		/// coins, all of them at addresses of <paramref name="group"/> (with the witness script of that address);
		/// every level pays the same destination and returns the change to the same address; the amount changes
		/// only when everything is sent; no level pays less than the calculated fee nor more than its percentage;
		/// every input of every level is signed by the same members, and only by members.
		/// </summary>
		public static SegWitMultiSigSpendInfo Check(SegWitMultiSigGroup group, SegWitMultiSigBundle bundle)
		{
			if (group == null) throw new ArgumentNullException(nameof(group));
			if (bundle == null || bundle.Inputs.Count == 0 || bundle.Levels.Count == 0)
				throw new ArgumentException("The payment has no inputs or no fee levels");
			// After the last signer chose, the bundle keeps only the chosen level (any percent): that is valid
			// only when it is complete (checked at the end). Otherwise the first level is the calculated fee.
			bool chosenLevel = bundle.Levels.Count == 1 && bundle.Levels[0].Percent != 0;
			if (chosenLevel)
				CheckPercent(bundle.Levels[0].Percent);
			else if (bundle.Levels[0].Percent != 0)
				throw new ArgumentException("The first fee level must be the calculated fee");
			if (bundle.Levels.Count > 1 + MaxExtraFeeLevels)
				throw new ArgumentException($"At most {MaxExtraFeeLevels} extra fee options are allowed");
			for (int l = 1; l < bundle.Levels.Count; l++)
			{
				CheckPercent(bundle.Levels[l].Percent);
				if (bundle.Levels[l].Percent <= bundle.Levels[l - 1].Percent)
					throw new ArgumentException("The fee options are not in order");
			}
			var psbts = bundle.Levels.Select(l => l.Psbt ?? throw new ArgumentException("A fee level is empty")).ToList();
			foreach (var psbt in psbts)
				if (psbt.Inputs.Count != bundle.Inputs.Count)
					throw new ArgumentException("A fee level does not spend the coins of the payment");

			var info = new SegWitMultiSigSpendInfo { Required = group.RequiredSignatures };
			var multiSigs = bundle.Inputs.Select(i => group.GetMultiSig(i.Sequence, i.IsChange)).ToList();

			// the coins: the same in every level, every one at an address of this group
			var first = psbts[0];
			for (int i = 0; i < first.Inputs.Count; i++)
			{
				var utxo = first.Inputs[i].WitnessUtxo ?? throw new ArgumentException($"Input {i} has no amount");
				if (utxo.ScriptPubKey != multiSigs[i].Address.ScriptPubKey)
					throw new ArgumentException($"Input {i} is not a coin of this group");
				info.TotalIn += utxo.Value;
				foreach (var psbt in psbts)
				{
					var other = psbt.Inputs[i];
					if (other.PrevOut != first.Inputs[i].PrevOut || other.WitnessUtxo == null ||
						other.WitnessUtxo.Value != utxo.Value || other.WitnessUtxo.ScriptPubKey != utxo.ScriptPubKey)
						throw new ArgumentException("The fee levels do not spend the same coins");
					if (other.WitnessScript != multiSigs[i].MultisigScript)
						throw new ArgumentException($"Input {i} does not carry the script of its address");
				}
			}

			// the outputs: [payment] or [payment, change]
			var baseTx = first.GetGlobalTransaction();
			if (baseTx.Outputs.Count < 1 || baseTx.Outputs.Count > 2)
				throw new ArgumentException("Unexpected outputs in the payment");
			info.PaymentScript = baseTx.Outputs[0].ScriptPubKey;
			bool anyChange = false, sameAmount = true;
			foreach (var psbt in psbts)
			{
				var tx = psbt.GetGlobalTransaction();
				if (tx.Outputs.Count < 1 || tx.Outputs.Count > 2)
					throw new ArgumentException("Unexpected outputs in a fee level");
				if (tx.Outputs[0].ScriptPubKey != info.PaymentScript)
					throw new ArgumentException("The fee levels do not pay the same address");
				if (tx.Outputs[0].Value != baseTx.Outputs[0].Value)
					sameAmount = false;
				if (tx.Outputs.Count == 2)
				{
					anyChange = true;
					info.ChangeScript ??= tx.Outputs[1].ScriptPubKey;
					if (tx.Outputs[1].ScriptPubKey != info.ChangeScript)
						throw new ArgumentException("The fee levels do not return the change to the same address");
				}
				info.Fees.Add(info.TotalIn - tx.Outputs.Select(o => o.Value).Sum());
			}
			if (anyChange && !sameAmount)
				throw new ArgumentException("The fee levels do not pay the same amount");

			// the fees: never below the calculated one, never above the percentage
			if (info.Fees[0] <= Money.Zero)
				throw new ArgumentException("The payment has no fee");
			for (int l = 1; l < psbts.Count; l++)
			{
				var nominal = LevelFee(info.Fees[0], bundle.Levels[l].Percent);
				if (info.Fees[l] < info.Fees[0] || info.Fees[l] > nominal + Money.Satoshis(FeeToleranceSats))
					throw new ArgumentException($"The +{bundle.Levels[l].Percent} % fee option does not pay the fee it says");
			}

			// the signers: members only, the same members on every input of every level
			HashSet<int> signers = null;
			foreach (var psbt in psbts)
			{
				for (int i = 0; i < psbt.Inputs.Count; i++)
				{
					var members = new HashSet<int>();
					foreach (var sig in psbt.Inputs[i].PartialSigs)
					{
						var member = group.MemberOf(sig.Key, bundle.Inputs[i].Sequence, bundle.Inputs[i].IsChange);
						if (member < 0)
							throw new ArgumentException($"Input {i} has a signature of somebody who is not a member");
						members.Add(member);
					}
					if (signers == null)
						signers = members;
					else if (!members.SetEquals(signers))
						throw new ArgumentException("The fee levels are not signed by the same members");
				}
			}
			info.SignedBy = (signers ?? new HashSet<int>()).OrderBy(m => m).ToList();
			if (info.SignedBy.Count > group.RequiredSignatures)
				throw new ArgumentException("The payment has more signatures than it needs");
			if (chosenLevel && !info.Complete)
				throw new ArgumentException("The first fee level must be the calculated fee");
			return info;
		}

		/// <summary>
		/// One member signs. <paramref name="receivingKey"/> / <paramref name="changeKey"/> are the member's
		/// chain-level extended private keys; the key of each input is derived at the input's sequence.
		/// <paramref name="finalPercent"/> &lt; 0: sign every level (first and intermediate signers).
		/// <paramref name="finalPercent"/> &gt;= 0: the LAST signer signs only that level; the bundle keeps only
		/// that level, ready for <see cref="Finalize"/>.
		/// </summary>
		public static SegWitMultiSigSpendInfo Sign(SegWitMultiSigGroup group, SegWitMultiSigBundle bundle,
			ExtKey receivingKey, ExtKey changeKey, int finalPercent)
		{
			var info = Check(group, bundle);
			var keys = new List<Key>();
			int member = -1;
			for (int i = 0; i < bundle.Inputs.Count; i++)
			{
				var input = bundle.Inputs[i];
				var chainKey = input.IsChange ? changeKey : receivingKey;
				if (chainKey == null)
					throw new ArgumentException($"The {(input.IsChange ? "change" : "receiving")} signing key is missing");
				var key = chainKey.Derive((uint)input.Sequence).PrivateKey;
				var m = group.MemberOf(key.PubKey, input.Sequence, input.IsChange);
				if (m < 0)
					throw new ArgumentException("The signing key does not belong to a member of this group");
				if (member >= 0 && m != member)
					throw new ArgumentException("The receiving and change keys are of different members");
				member = m;
				keys.Add(key);
			}
			if (info.SignedBy.Contains(member))
				throw new ArgumentException("You have already signed this payment");
			if (info.Complete)
				throw new ArgumentException("This payment already has all the signatures it needs");

			if (finalPercent >= 0)
			{
				if (!info.NextIsLast)
					throw new ArgumentException($"The fee is chosen by the last signer: this payment has {info.Signatures} of {info.Required} signatures");
				var index = bundle.Levels.FindIndex(l => l.Percent == finalPercent);
				if (index < 0)
					throw new ArgumentException($"This payment has no +{finalPercent} % fee option");
				bundle.Levels = new List<SegWitMultiSigFeeLevel> { bundle.Levels[index] };
			}

			foreach (var level in bundle.Levels)
				for (int i = 0; i < bundle.Inputs.Count; i++)
					level.Psbt.Inputs[i].Sign(keys[i]);
			return Check(group, bundle);
		}

		/// <summary>The raw transaction of one level of a bundle that has its k signatures, checked by the script interpreter.</summary>
		public static Transaction Finalize(SegWitMultiSigGroup group, SegWitMultiSigBundle bundle, int percent)
		{
			var info = Check(group, bundle);
			if (!info.Complete)
				throw new ArgumentException($"More signatures are needed: this payment has {info.Signatures} of {info.Required}");
			var level = bundle.Levels.FirstOrDefault(l => l.Percent == percent)
				?? throw new ArgumentException($"This payment has no +{percent} % fee option");
			var psbt = level.Psbt.Clone();
			psbt.Finalize();
			var tx = psbt.ExtractTransaction();
			var spent = psbt.Inputs.Select(i => i.WitnessUtxo).ToArray();
			var validator = tx.CreateValidator(spent);
			for (int i = 0; i < tx.Inputs.Count; i++)
			{
				var result = validator.ValidateInput(i);
				if (result.Error != null)
					throw new InvalidOperationException($"The signed transaction is not valid (input {i}): {result.Error}");
			}
			return tx;
		}
	}
}
