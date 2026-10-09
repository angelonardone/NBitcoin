using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using NBitcoin;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// "Delegated Multisignature" = a Taproot address where the group OWNER spends alone by the key path
	/// and any k of the n MEMBERS spend by the script path (NBitcoin.DelegatedMultiSig: one k-of-k
	/// tapscript per combination of members).
	///
	/// All crypto is done here, driven by the GroupSDT that GeneXus hands over through
	/// DelegatedProcessor.FromSDT(). The owner is GroupSDT.ExtPubKeyMultiSigReceiving / ExtPubKeyMultiSigChange,
	/// the members are the Contact items (the owner is NOT a contact here) and the threshold is
	/// GroupSDT.MinimumShares. Every key is a chain-level extended key, derived (non-hardened) at the
	/// HD sequence of each address, so a spend can mix inputs of different addresses.
	///
	/// PRE-SIGNED FEE LEVELS. The member who starts a payment chooses the fee ("calculated") and up to
	/// <see cref="MaxExtraFeeLevels"/> extra levels, each a percentage ABOVE it (10, 20 ... 100). One
	/// transaction is built per level: same inputs and payment, a different fee. The first signer and
	/// every following one sign ALL the levels. The LAST signer (the k-th) chooses one level, signs
	/// only that transaction, and it is finalized.
	///
	/// The levels travel together in a "bundle": a JSON string with one PSBT per level. GeneXus treats it
	/// as an opaque text (it is stored where Legacy stores its PSBT).
	///
	/// Every method returns a JSON string and never throws toward GeneXus:
	/// <c>{ "success": true, "error": "", ... }</c> or <c>{ "success": false, "error": "..." }</c>.
	/// </summary>
	public static class DelegatedMultiSigSpend
	{
		/// <summary>How many fee levels the first signer may add to the calculated fee.</summary>
		public const int MaxExtraFeeLevels = 3;

		/// <summary>
		/// How many combinations of members (scripts in the address) a group may have. The limit is not the
		/// number of members: every signer signs each combination he is part of, on every fee level, so the
		/// work and the size of the bundle grow with C(n, k). 2000 allows 2-of-60, 3-of-23, 4-of-16, 5-of-12
		/// and 8-of-13.
		/// </summary>
		public const int MaxCombinations = 2000;

		// 64-byte Schnorr signatures (no sighash byte): the signature commits to the whole transaction.
		private const TaprootSigHash SigHash = TaprootSigHash.Default;

		// Opt-in replace-by-fee, so a higher level can replace a lower one that is still unconfirmed.
		private const uint InputSequence = 0xFFFFFFFD;

		// A level may pay this much more than its nominal fee (a change below the dust limit goes to the fee).
		private const long FeeToleranceSats = 1000;

		private static readonly JsonSerializerOptions JsonIn = new JsonSerializerOptions
		{
			PropertyNameCaseInsensitive = true
		};

		// Input shape for the UTXOs to spend (sent by GeneXus as a JSON array).
		private sealed class UtxoDto
		{
			public string TxId { get; set; } = "";
			public int Vout { get; set; }
			public string AmountBtc { get; set; } = "0";
			public int Sequence { get; set; }
			public bool IsChange { get; set; }
			// Optional: the address the wallet has for this UTXO; checked against the derived one.
			public string Address { get; set; } = "";
		}

		private sealed class BundleInput
		{
			public int Sequence { get; set; }
			public bool IsChange { get; set; }
		}

		private sealed class BundleLevel
		{
			public int Percent { get; set; }
			public string Psbt { get; set; } = "";
		}

		private sealed class Bundle
		{
			public int Version { get; set; } = 1;
			public List<BundleInput> Inputs { get; set; } = new List<BundleInput>();
			public List<BundleLevel> Levels { get; set; } = new List<BundleLevel>();
		}

		// A bundle parsed and checked against the group.
		private sealed class Spend
		{
			public Bundle Bundle = new Bundle();
			public List<PSBT> Psbts = new List<PSBT>();
			public List<DelegatedMultiSig> MultiSigs = new List<DelegatedMultiSig>(); // one per input
			public TxOut[] SpentOutputs = Array.Empty<TxOut>();
			public Money TotalIn = Money.Zero;
			public Script PaymentScript = Script.Empty;
			public Script? ChangeScript;
			public List<int> Signers = new List<int>(); // signer indices of input 0
		}

		// ---------------------------------------------------------------------
		// Public API (operates on a GroupSDT plus primitive parameters)
		// ---------------------------------------------------------------------

		/// <summary>
		/// Build the Taproot address of the group at the given HD sequence on the receiving chain
		/// (<paramref name="isChange"/> = false) or the change chain (true).
		/// </summary>
		public static string CreateAddress(GroupSDT group, int sequence, bool isChange, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var ms = BuildMultiSig(group, sequence, isChange, net);
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
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// The ranged output descriptor (BIP386 tr() with BIP387 sortedmulti_a scripts) of one chain of the
		/// group: its address number i is CreateAddress(i). Importing the receiving and the change descriptor
		/// in a descriptor wallet (Bitcoin Core) shows every address and coin of the group without this library.
		/// </summary>
		public static string GetDescriptor(GroupSDT group, bool isChange, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var (owner, members, k) = GroupKeys(group, isChange, net);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					descriptor = DelegatedMultiSig.GetRangedDescriptor(owner, members, k, net),
					k,
					n = members.Count,
					isChange
				});
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// Virtual size of the spend, to calculate the fee before building it. For the members it is the
		/// worst case over the script paths; for the owner (<paramref name="asOwner"/>) the key path.
		/// <paramref name="changeAddr"/> may be empty: a Taproot output is assumed.
		/// </summary>
		public static string EstimateVsize(GroupSDT group, string utxosJson, string sendTo, string changeAddr,
			bool sendAll, bool asOwner, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var utxos = ParseUtxos(utxosJson);
				var cache = new Dictionary<string, DelegatedMultiSig>();
				var tx = net.CreateTransaction();
				tx.Version = 2;
				Script? firstScript = null;
				foreach (var u in utxos)
				{
					var ms = GetMultiSig(cache, group, u.Sequence, u.IsChange, net);
					firstScript ??= ms.Address.ScriptPubKey;
					var txin = new TxIn(new OutPoint(uint256.Parse(u.TxId), (uint)u.Vout)) { Sequence = InputSequence };
					txin.WitScript = asOwner ? new WitScript(new[] { new byte[64] }) : WorstCaseWitness(ms);
					tx.Inputs.Add(txin);
				}
				tx.Outputs.Add(Money.Zero, BitcoinAddress.Create(sendTo.Trim(), net));
				if (!sendAll)
				{
					var changeScript = string.IsNullOrWhiteSpace(changeAddr) ? firstScript! : BitcoinAddress.Create(changeAddr.Trim(), net).ScriptPubKey;
					tx.Outputs.Add(Money.Zero, changeScript);
				}
				return JsonSerializer.Serialize(new { success = true, error = "", vsize = tx.GetVirtualSize() });
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// Build the (unsigned) bundle: one PSBT for <paramref name="feeBtc"/> (level 0, the calculated fee)
		/// and one per percentage of <paramref name="percentages"/> (comma separated, e.g. "10,30,100";
		/// each a multiple of 10 between 10 and 100, at most <see cref="MaxExtraFeeLevels"/>).
		/// </summary>
		public static string BuildSpend(GroupSDT group, string utxosJson, string sendTo, string amountBtc,
			string changeAddr, string feeBtc, string percentages, bool sendAll, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var utxos = ParseUtxos(utxosJson);
				var cache = new Dictionary<string, DelegatedMultiSig>();
				var multiSigs = utxos.Select(u => GetMultiSig(cache, group, u.Sequence, u.IsChange, net)).ToList();
				CheckUtxoAddresses(utxos, multiSigs);

				var baseFee = Money.Coins(ParseDec(feeBtc));
				if (baseFee <= Money.Zero)
					return Err("The fee must be greater than zero");

				var bundle = new Bundle();
				foreach (var u in utxos)
					bundle.Inputs.Add(new BundleInput { Sequence = u.Sequence, IsChange = u.IsChange });

				var levels = new List<int> { 0 };
				levels.AddRange(ParsePercentages(percentages));
				foreach (var percent in levels)
				{
					var fee = LevelFee(baseFee, percent);
					var tx = BuildTransaction(utxos, sendTo, amountBtc, changeAddr, fee, sendAll, net,
						percent == 0 ? "the fee" : $"the +{percent} % fee option");
					bundle.Levels.Add(new BundleLevel { Percent = percent, Psbt = CreatePsbt(tx, utxos, multiSigs, net).ToBase64() });
				}

				var bundleJson = JsonSerializer.Serialize(bundle);
				var spend = LoadSpend(group, bundleJson, net);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					bundle = bundleJson,
					levels = DescribeLevels(spend, net)
				});
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// Sign the bundle with one member's keys. <paramref name="receivingExtPrivKey"/> and
		/// <paramref name="changeExtPrivKey"/> are the member's chain-level extended private keys, the
		/// private side of the two extended public keys he gave to the group; the key of each input is
		/// derived at the input's sequence.
		/// <paramref name="finalPercent"/> &lt; 0: sign every level (first and intermediate signers).
		/// <paramref name="finalPercent"/> &gt;= 0: LAST signer: sign only that level and finalize it;
		/// the result carries <c>txHex</c> / <c>txId</c> and the bundle keeps only that level.
		/// </summary>
		public static string SignSpend(GroupSDT group, string bundleJson, string receivingExtPrivKey,
			string changeExtPrivKey, int finalPercent, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var spend = LoadSpend(group, bundleJson, net);
				var k = spend.MultiSigs[0].RequiredSignatures;

				// the member's key for each input
				var keys = new List<Key>();
				for (int i = 0; i < spend.MultiSigs.Count; i++)
				{
					var input = spend.Bundle.Inputs[i];
					var xprv = input.IsChange ? changeExtPrivKey : receivingExtPrivKey;
					if (string.IsNullOrWhiteSpace(xprv))
						return Err($"The {(input.IsChange ? "change" : "receiving")} signing key is missing");
					var key = ExtKey.Parse(xprv.Trim(), net).Derive((uint)input.Sequence).PrivateKey;
					var ms = spend.MultiSigs[i];
					if (key.PubKey == ms.OwnerPubKey)
						return Err("The owner of the group does not sign with the members: he spends alone");
					if (!ms.SignerPubKeys.Contains(key.PubKey))
						return Err("The signing key does not belong to a member of this group");
					keys.Add(key);
				}

				var signerIndex = IndexOf(spend.MultiSigs[0].SignerPubKeys, keys[0].PubKey);
				if (spend.Signers.Contains(signerIndex))
					return Err("You have already signed this payment");
				if (spend.Signers.Count >= k)
					return Err("This payment already has all the signatures it needs");

				if (finalPercent >= 0)
				{
					if (spend.Signers.Count + 1 < k)
						return Err($"The fee is chosen by the last signer: this payment has {spend.Signers.Count} of {k} signatures");
					var index = spend.Bundle.Levels.FindIndex(l => l.Percent == finalPercent);
					if (index < 0)
						return Err($"This payment has no +{finalPercent} % fee option");
					// keep only the chosen level
					spend.Bundle.Levels = new List<BundleLevel> { spend.Bundle.Levels[index] };
					spend.Psbts = new List<PSBT> { spend.Psbts[index] };
				}

				for (int l = 0; l < spend.Psbts.Count; l++)
				{
					for (int i = 0; i < spend.MultiSigs.Count; i++)
					{
						spend.MultiSigs[i].SignPSBT(spend.Psbts[l], keys[i], i, SigHash);
						spend.MultiSigs[i].PrunePSBT(spend.Psbts[l], i);
					}
					spend.Bundle.Levels[l].Psbt = spend.Psbts[l].ToBase64();
				}

				var signatures = spend.Signers.Count + 1;
				var signedBundle = JsonSerializer.Serialize(spend.Bundle);
				if (finalPercent < 0)
				{
					return JsonSerializer.Serialize(new
					{
						success = true,
						error = "",
						bundle = signedBundle,
						signatures,
						required = k,
						complete = signatures >= k,
						txHex = "",
						txId = "",
						feeBtc = 0m,
						vsize = 0
					});
				}

				var tx = FinalizeLevel(spend, 0);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					bundle = signedBundle,
					signatures,
					required = k,
					complete = true,
					txHex = tx.ToHex(),
					txId = tx.GetHash().ToString(),
					feeBtc = Fee(spend, 0).ToDecimal(MoneyUnit.BTC),
					vsize = tx.GetVirtualSize()
				});
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// Finalize one level of a bundle that already has the k signatures and extract the raw transaction.
		/// </summary>
		public static string FinalizeSpend(GroupSDT group, string bundleJson, int percent, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var spend = LoadSpend(group, bundleJson, net);
				var k = spend.MultiSigs[0].RequiredSignatures;
				if (spend.Signers.Count < k)
					return Err($"More signatures are needed: this payment has {spend.Signers.Count} of {k}");
				var index = spend.Bundle.Levels.FindIndex(l => l.Percent == percent);
				if (index < 0)
					return Err($"This payment has no +{percent} % fee option");
				var tx = FinalizeLevel(spend, index);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					txHex = tx.ToHex(),
					txId = tx.GetHash().ToString(),
					feeBtc = Fee(spend, index).ToDecimal(MoneyUnit.BTC),
					vsize = tx.GetVirtualSize()
				});
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// What a bundle really pays, read from its PSBTs (never from the message that carried it): the
		/// destination, the amount, the change address and the fee of each level, who signed, and whether
		/// the next signature is the last one. <paramref name="myReceivingExtPubKey"/> /
		/// <paramref name="myChangeExtPubKey"/> (optional) tell whether that member already signed.
		/// </summary>
		public static string DescribeSpend(GroupSDT group, string bundleJson, string myReceivingExtPubKey,
			string myChangeExtPubKey, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var spend = LoadSpend(group, bundleJson, net);
				var ms = spend.MultiSigs[0];
				var k = ms.RequiredSignatures;
				var first = spend.Bundle.Inputs[0];

				var names = SignerNames(group, first.Sequence, first.IsChange, net);
				var signedBy = spend.Signers
					.Select(s => names.TryGetValue(ms.SignerPubKeys[s].ToHex(), out var name) ? name : "")
					.ToList();

				bool iSigned = false;
				var myXpub = first.IsChange ? myChangeExtPubKey : myReceivingExtPubKey;
				if (!string.IsNullOrWhiteSpace(myXpub))
				{
					var myPubKey = ExtPubKey.Parse(myXpub.Trim(), net).Derive((uint)first.Sequence).PubKey;
					var myIndex = IndexOf(ms.SignerPubKeys, myPubKey);
					iSigned = myIndex >= 0 && spend.Signers.Contains(myIndex);
				}

				var baseTx = spend.Psbts[0].GetGlobalTransaction();
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					required = k,
					signatures = spend.Signers.Count,
					complete = spend.Signers.Count >= k,
					nextIsLast = spend.Signers.Count == k - 1,
					iSigned,
					sendTo = spend.PaymentScript.GetDestinationAddress(net)?.ToString() ?? "",
					changeTo = spend.ChangeScript?.GetDestinationAddress(net)?.ToString() ?? "",
					amountBtc = baseTx.Outputs[0].Value.ToDecimal(MoneyUnit.BTC),
					totalInBtc = spend.TotalIn.ToDecimal(MoneyUnit.BTC),
					signedBy,
					levels = DescribeLevels(spend, net)
				});
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// The OWNER spends alone by the key path: build, sign and finalize in one call (one fee, no levels).
		/// <paramref name="receivingExtPrivKey"/> / <paramref name="changeExtPrivKey"/> are the owner's
		/// chain-level extended private keys.
		/// </summary>
		public static string OwnerSpend(GroupSDT group, string utxosJson, string sendTo, string amountBtc,
			string changeAddr, string feeBtc, bool sendAll, string receivingExtPrivKey, string changeExtPrivKey,
			string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var utxos = ParseUtxos(utxosJson);
				var cache = new Dictionary<string, DelegatedMultiSig>();
				var multiSigs = utxos.Select(u => GetMultiSig(cache, group, u.Sequence, u.IsChange, net)).ToList();
				CheckUtxoAddresses(utxos, multiSigs);

				var fee = Money.Coins(ParseDec(feeBtc));
				if (fee <= Money.Zero)
					return Err("The fee must be greater than zero");
				var tx = BuildTransaction(utxos, sendTo, amountBtc, changeAddr, fee, sendAll, net, "the fee");
				var spentOutputs = utxos.Select((u, i) => new TxOut(Money.Coins(ParseDec(u.AmountBtc)), multiSigs[i].Address.ScriptPubKey)).ToArray();

				for (int i = 0; i < utxos.Count; i++)
				{
					var xprv = utxos[i].IsChange ? changeExtPrivKey : receivingExtPrivKey;
					if (string.IsNullOrWhiteSpace(xprv))
						return Err($"The {(utxos[i].IsChange ? "change" : "receiving")} signing key is missing");
					var key = ExtKey.Parse(xprv.Trim(), net).Derive((uint)utxos[i].Sequence).PrivateKey;
					if (key.PubKey != multiSigs[i].OwnerPubKey)
						return Err("The signing key is not the key of the owner of this group");
					var hash = tx.GetSignatureHashTaproot(spentOutputs, new TaprootExecutionData(i) { SigHash = SigHash });
					var signature = key.SignTaprootKeySpend(hash, multiSigs[i].TaprootSpendInfo.MerkleRoot, SigHash);
					tx.Inputs[i].WitScript = new WitScript(new[] { signature.ToBytes() });
				}
				Validate(tx, spentOutputs);

				var totalIn = spentOutputs.Select(o => o.Value).Sum();
				var totalOut = tx.Outputs.Select(o => o.Value).Sum();
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					txHex = tx.ToHex(),
					txId = tx.GetHash().ToString(),
					feeBtc = (totalIn - totalOut).ToDecimal(MoneyUnit.BTC),
					vsize = tx.GetVirtualSize()
				});
			}
			catch (Exception e) { return Err(e); }
		}

		// ---------------------------------------------------------------------
		// Building
		// ---------------------------------------------------------------------

		private static List<UtxoDto> ParseUtxos(string utxosJson)
		{
			var utxos = JsonSerializer.Deserialize<List<UtxoDto>>(utxosJson ?? "[]", JsonIn) ?? new List<UtxoDto>();
			if (utxos.Count == 0)
				throw new Exception("No UTXOs provided");
			return utxos;
		}

		private static void CheckUtxoAddresses(List<UtxoDto> utxos, List<DelegatedMultiSig> multiSigs)
		{
			for (int i = 0; i < utxos.Count; i++)
			{
				var address = (utxos[i].Address ?? "").Trim();
				if (address.Length > 0 && address != multiSigs[i].Address.ToString())
					throw new Exception("Generated address and UTXO address don't match");
			}
		}

		// "10,30,100" -> [10, 30, 100] (sorted, checked)
		private static List<int> ParsePercentages(string percentages)
		{
			var result = new List<int>();
			foreach (var part in (percentages ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
			{
				if (!int.TryParse(part, NumberStyles.Integer, CultureInfo.InvariantCulture, out var percent))
					throw new Exception($"Invalid fee percentage '{part}'");
				CheckPercent(percent);
				if (result.Contains(percent))
					throw new Exception($"The +{percent} % fee option is repeated");
				result.Add(percent);
			}
			if (result.Count > MaxExtraFeeLevels)
				throw new Exception($"At most {MaxExtraFeeLevels} extra fee options are allowed");
			result.Sort();
			return result;
		}

		private static void CheckPercent(int percent)
		{
			if (percent < 10 || percent > 100 || percent % 10 != 0)
				throw new Exception($"Invalid fee percentage {percent}: it must be 10, 20 ... 100");
		}

		// The calculated fee plus the percentage, rounded up to the satoshi.
		private static Money LevelFee(Money baseFee, int percent) =>
			Money.Satoshis((baseFee.Satoshi * (100 + percent) + 99) / 100);

		private static Transaction BuildTransaction(List<UtxoDto> utxos, string sendTo, string amountBtc,
			string changeAddr, Money fee, bool sendAll, Network net, string feeName)
		{
			var tx = net.CreateTransaction();
			tx.Version = 2;
			var total = Money.Zero;
			foreach (var u in utxos)
			{
				tx.Inputs.Add(new TxIn(new OutPoint(uint256.Parse(u.TxId), (uint)u.Vout)) { Sequence = InputSequence });
				total += Money.Coins(ParseDec(u.AmountBtc));
			}

			var destination = BitcoinAddress.Create(sendTo.Trim(), net);
			if (sendAll)
			{
				var payment = new TxOut(total - fee, destination);
				if (payment.Value <= Money.Zero || payment.Value < payment.GetDustThreshold())
					throw new Exception($"Not enough balance to pay {feeName}");
				tx.Outputs.Add(payment);
			}
			else
			{
				var amount = Money.Coins(ParseDec(amountBtc));
				if (amount <= Money.Zero)
					throw new Exception("The amount must be greater than zero");
				var payment = new TxOut(amount, destination);
				if (amount < payment.GetDustThreshold())
					throw new Exception("The amount is too small (dust)");
				var change = total - amount - fee;
				if (change < Money.Zero)
					throw new Exception($"Not enough balance to pay {feeName}");
				tx.Outputs.Add(payment);
				var changeOut = new TxOut(change, BitcoinAddress.Create(changeAddr.Trim(), net));
				// a change below the dust limit is not created: it goes to the fee
				if (change >= changeOut.GetDustThreshold())
					tx.Outputs.Add(changeOut);
			}
			return tx;
		}

		private static PSBT CreatePsbt(Transaction tx, List<UtxoDto> utxos, List<DelegatedMultiSig> multiSigs, Network net)
		{
			var psbt = PSBT.FromTransaction(tx, net);
			for (int i = 0; i < utxos.Count; i++)
			{
				var input = psbt.Inputs[i];
				input.WitnessUtxo = new TxOut(Money.Coins(ParseDec(utxos[i].AmountBtc)), multiSigs[i].Address.ScriptPubKey);
				input.TaprootInternalKey = multiSigs[i].OwnerPubKey.TaprootInternalKey;
				input.TaprootMerkleRoot = multiSigs[i].TaprootSpendInfo.MerkleRoot;
			}
			return psbt;
		}

		// k signatures + the script + the largest control block of the tree
		private static WitScript WorstCaseWitness(DelegatedMultiSig ms)
		{
			TapScript worst = ms.Scripts[0];
			int worstSize = 0;
			foreach (var script in ms.Scripts)
			{
				var size = script.Script.Length + ms.TaprootSpendInfo.GetControlBlock(script).ToBytes().Length;
				if (size > worstSize)
				{
					worstSize = size;
					worst = script;
				}
			}
			var items = new List<byte[]>();
			for (int i = 0; i < ms.RequiredSignatures; i++)
				items.Add(new byte[64]);
			items.Add(worst.Script.ToBytes());
			items.Add(ms.TaprootSpendInfo.GetControlBlock(worst).ToBytes());
			return new WitScript(items.ToArray());
		}

		// ---------------------------------------------------------------------
		// Reading and checking a bundle
		// ---------------------------------------------------------------------

		// Parses the bundle and checks that it is what it claims to be: every level spends the same
		// coins of THIS group, pays the same destination and returns the change to the same address,
		// and no level pays more fee than its percentage says. A signer signs only what passed here.
		private static Spend LoadSpend(GroupSDT group, string bundleJson, Network net)
		{
			if (string.IsNullOrWhiteSpace(bundleJson))
				throw new Exception("The payment is empty");
			var bundle = JsonSerializer.Deserialize<Bundle>(bundleJson.Trim(), JsonIn) ?? new Bundle();
			if (bundle.Inputs.Count == 0 || bundle.Levels.Count == 0)
				throw new Exception("The payment has no inputs or no fee levels");
			if (bundle.Levels[0].Percent != 0)
				throw new Exception("The first fee level must be the calculated fee");
			if (bundle.Levels.Count > 1 + MaxExtraFeeLevels)
				throw new Exception($"At most {MaxExtraFeeLevels} extra fee options are allowed");
			for (int l = 1; l < bundle.Levels.Count; l++)
			{
				CheckPercent(bundle.Levels[l].Percent);
				if (bundle.Levels[l].Percent <= bundle.Levels[l - 1].Percent)
					throw new Exception("The fee options are not in order");
			}

			var spend = new Spend { Bundle = bundle };
			var cache = new Dictionary<string, DelegatedMultiSig>();
			foreach (var input in bundle.Inputs)
				spend.MultiSigs.Add(GetMultiSig(cache, group, input.Sequence, input.IsChange, net));

			foreach (var level in bundle.Levels)
			{
				var psbt = PSBT.Parse(level.Psbt.Trim(), net);
				if (psbt.Inputs.Count != bundle.Inputs.Count)
					throw new Exception("A fee level does not spend the coins of the payment");
				spend.Psbts.Add(psbt);
			}

			// the coins: the same in every level, and every one at an address of this group
			var first = spend.Psbts[0];
			spend.SpentOutputs = new TxOut[first.Inputs.Count];
			for (int i = 0; i < first.Inputs.Count; i++)
			{
				var utxo = first.Inputs[i].WitnessUtxo;
				if (utxo == null)
					throw new Exception($"Input {i} has no amount");
				if (utxo.ScriptPubKey != spend.MultiSigs[i].Address.ScriptPubKey)
					throw new Exception($"Input {i} is not a coin of this group");
				spend.SpentOutputs[i] = utxo;
				spend.TotalIn += utxo.Value;
				foreach (var psbt in spend.Psbts)
				{
					var other = psbt.Inputs[i];
					if (other.PrevOut != first.Inputs[i].PrevOut || other.WitnessUtxo == null ||
						other.WitnessUtxo.Value != utxo.Value || other.WitnessUtxo.ScriptPubKey != utxo.ScriptPubKey)
						throw new Exception("The fee levels do not spend the same coins");
				}
			}

			// the outputs: [payment] or [payment, change]
			var baseTx = first.GetGlobalTransaction();
			if (baseTx.Outputs.Count < 1 || baseTx.Outputs.Count > 2)
				throw new Exception("Unexpected outputs in the payment");
			spend.PaymentScript = baseTx.Outputs[0].ScriptPubKey;
			bool anyChange = false;
			bool sameAmount = true;
			for (int l = 0; l < spend.Psbts.Count; l++)
			{
				var tx = spend.Psbts[l].GetGlobalTransaction();
				if (tx.Outputs.Count < 1 || tx.Outputs.Count > 2)
					throw new Exception("Unexpected outputs in a fee level");
				if (tx.Outputs[0].ScriptPubKey != spend.PaymentScript)
					throw new Exception("The fee levels do not pay the same address");
				if (tx.Outputs[0].Value != baseTx.Outputs[0].Value)
					sameAmount = false;
				if (tx.Outputs.Count == 2)
				{
					anyChange = true;
					spend.ChangeScript ??= tx.Outputs[1].ScriptPubKey;
					if (tx.Outputs[1].ScriptPubKey != spend.ChangeScript)
						throw new Exception("The fee levels do not return the change to the same address");
				}
			}
			// the amount only changes with the level when everything is sent (no change output at all)
			if (anyChange && !sameAmount)
				throw new Exception("The fee levels do not pay the same amount");

			// the fees: never below the calculated one, never above the percentage
			var baseFee = Fee(spend, 0);
			if (baseFee <= Money.Zero)
				throw new Exception("The payment has no fee");
			for (int l = 1; l < spend.Psbts.Count; l++)
			{
				var fee = Fee(spend, l);
				var nominal = LevelFee(baseFee, bundle.Levels[l].Percent);
				if (fee < baseFee || fee > nominal + Money.Satoshis(FeeToleranceSats))
					throw new Exception($"The +{bundle.Levels[l].Percent} % fee option does not pay the fee it says");
			}

			// the signers: the same members on every input of every level. A member has a different key
			// (and signer index) on each address, so the signers are compared by member.
			spend.Signers = spend.MultiSigs[0].GetPSBTSignerIndices(first, 0).ToList();
			var firstMembers = SignerMembers(group, bundle.Inputs[0], spend.MultiSigs[0], spend.Signers, net);
			foreach (var psbt in spend.Psbts)
			{
				for (int i = 0; i < psbt.Inputs.Count; i++)
				{
					var members = SignerMembers(group, bundle.Inputs[i], spend.MultiSigs[i], spend.MultiSigs[i].GetPSBTSignerIndices(psbt, i), net);
					if (!members.SetEquals(firstMembers))
						throw new Exception("The fee levels are not signed by the same members");
				}
			}
			return spend;
		}

		// signer indices of one input -> positions of those members in the group's contact list
		private static HashSet<int> SignerMembers(GroupSDT group, BundleInput input, DelegatedMultiSig ms,
			IEnumerable<int> signerIndices, Network net)
		{
			var byKey = new Dictionary<string, int>();
			foreach (var m in MemberXpubs(group, input.IsChange))
				byKey[ExtPubKey.Parse(m.xpub, net).Derive((uint)input.Sequence).PubKey.ToHex()] = m.position;
			return new HashSet<int>(signerIndices.Select(s => byKey[ms.SignerPubKeys[s].ToHex()]));
		}

		private static Money Fee(Spend spend, int level)
		{
			var tx = spend.Psbts[level].GetGlobalTransaction();
			return spend.TotalIn - tx.Outputs.Select(o => o.Value).Sum();
		}

		private static object[] DescribeLevels(Spend spend, Network net)
		{
			var result = new List<object>();
			for (int l = 0; l < spend.Psbts.Count; l++)
			{
				var tx = spend.Psbts[l].GetGlobalTransaction();
				result.Add(new
				{
					percent = spend.Bundle.Levels[l].Percent,
					feeBtc = Fee(spend, l).ToDecimal(MoneyUnit.BTC),
					amountBtc = tx.Outputs[0].Value.ToDecimal(MoneyUnit.BTC),
					changeBtc = tx.Outputs.Count == 2 ? tx.Outputs[1].Value.ToDecimal(MoneyUnit.BTC) : 0m
				});
			}
			return result.ToArray();
		}

		// Builds the witness of every input from the collected signatures and checks the transaction
		// with the script interpreter before handing it out.
		private static Transaction FinalizeLevel(Spend spend, int level)
		{
			var psbt = spend.Psbts[level];
			var tx = psbt.GetGlobalTransaction();
			for (int i = 0; i < spend.MultiSigs.Count; i++)
			{
				var finalized = spend.MultiSigs[i].FinalizePSBT(psbt, i);
				tx.Inputs[i].WitScript = finalized.Inputs[i].WitScript;
			}
			Validate(tx, spend.SpentOutputs);
			return tx;
		}

		private static void Validate(Transaction tx, TxOut[] spentOutputs)
		{
			var validator = tx.CreateValidator(spentOutputs);
			for (int i = 0; i < tx.Inputs.Count; i++)
			{
				var result = validator.ValidateInput(i);
				if (result.Error != null)
					throw new Exception($"The signed transaction is not valid (input {i}): {result.Error}");
			}
		}

		// ---------------------------------------------------------------------
		// Group helpers
		// ---------------------------------------------------------------------

		private static DelegatedMultiSig GetMultiSig(Dictionary<string, DelegatedMultiSig> cache, GroupSDT group,
			int sequence, bool isChange, Network net)
		{
			var cacheKey = (isChange ? "1/" : "0/") + sequence.ToString(CultureInfo.InvariantCulture);
			if (!cache.TryGetValue(cacheKey, out var ms))
			{
				ms = BuildMultiSig(group, sequence, isChange, net);
				cache[cacheKey] = ms;
			}
			return ms;
		}

		private static DelegatedMultiSig BuildMultiSig(GroupSDT group, int sequence, bool isChange, Network net)
		{
			if (sequence < 0)
				throw new Exception("Invalid address sequence");
			var (ownerXpub, memberXpubs, k) = GroupKeys(group, isChange, net);
			return DelegatedMultiSig.FromExtPubKeys(ownerXpub, memberXpubs, k, (uint)sequence, net);
		}

		// The owner's and the members' chain-level extended public keys and the threshold, checked.
		private static (ExtPubKey owner, List<ExtPubKey> members, int k) GroupKeys(GroupSDT group, bool isChange, Network net)
		{
			if (group == null)
				throw new Exception("Group is null (call FromSDT first)");

			var chain = isChange ? "change" : "receiving";
			var ownerXpub = isChange ? group.ExtPubKeyMultiSigChange : group.ExtPubKeyMultiSigReceiving;
			if (string.IsNullOrWhiteSpace(ownerXpub))
				throw new Exception($"The owner's {chain} extended public key is missing");
			var owner = ExtPubKey.Parse(ownerXpub.Trim(), net);

			var members = MemberXpubs(group, isChange).Select(m => ExtPubKey.Parse(m.xpub, net)).ToList();
			if (members.Count < 2)
				throw new Exception($"At least 2 members with a {chain} extended public key are required");
			var all = members.Select(m => m.ToString(net)).Append(owner.ToString(net)).ToList();
			if (all.Distinct().Count() != all.Count)
				throw new Exception("Two participants of the group have the same key");

			int k = group.MinimumShares;
			if (k <= 0 || k > members.Count)
				throw new Exception($"Invalid MinimumShares ({k}) for {members.Count} members");

			var combinations = Combinations(members.Count, k);
			if (combinations > MaxCombinations)
				throw new Exception($"A {k}-of-{members.Count} group has {combinations:N0} combinations of signers; the maximum is {MaxCombinations:N0}. Use fewer members, or a number of signatures closer to 1 or to all the members");

			return (owner, members, k);
		}

		// C(n, k), capped: it only has to be compared with MaxCombinations
		private static double Combinations(int n, int k)
		{
			k = Math.Min(k, n - k);
			double result = 1;
			for (int i = 0; i < k; i++)
			{
				result = result * (n - i) / (i + 1);
				if (result > 1e15)
					return result;
			}
			return Math.Round(result);
		}

		// The members = every contact that gave its chain-level extended public key.
		// position = the member's place in the contact list (the same on both chains).
		private static List<(int position, string name, string xpub)> MemberXpubs(GroupSDT group, bool isChange)
		{
			var members = new List<(int position, string name, string xpub)>();
			if (group.Contact != null)
			{
				for (int position = 0; position < group.Contact.Count; position++)
				{
					var c = group.Contact[position];
					if (c == null) continue;
					var xpub = isChange ? c.ExtPubKeyMultiSigChange : c.ExtPubKeyMultiSigReceiving;
					if (!string.IsNullOrWhiteSpace(xpub))
						members.Add((position, (c.ContactUserName ?? "").Trim(), xpub!.Trim()));
				}
			}
			return members;
		}

		// public key (hex) at the given address -> member user name
		private static Dictionary<string, string> SignerNames(GroupSDT group, int sequence, bool isChange, Network net)
		{
			var names = new Dictionary<string, string>();
			foreach (var m in MemberXpubs(group, isChange))
				names[ExtPubKey.Parse(m.xpub, net).Derive((uint)sequence).PubKey.ToHex()] = m.name;
			return names;
		}

		private static int IndexOf(IReadOnlyList<PubKey> pubKeys, PubKey pubKey)
		{
			for (int i = 0; i < pubKeys.Count; i++)
			{
				if (pubKeys[i] == pubKey)
					return i;
			}
			return -1;
		}

		private static Network GetNetwork(string networkType)
		{
			switch ((networkType ?? "").Trim().ToLowerInvariant())
			{
				case "mainnet":
				case "main":
					return Network.Main;
				case "testnet":
				case "test":
					return Network.TestNet;
				case "regtest":
				case "":
					return Network.RegTest;
				default:
					return Network.RegTest;
			}
		}

		private static decimal ParseDec(string s) =>
			decimal.Parse((s ?? "0").Trim(), NumberStyles.Any, CultureInfo.InvariantCulture);

		private static string Err(string message) =>
			JsonSerializer.Serialize(new { success = false, error = message });

		private static string Err(Exception e) => Err(e.Message);
	}
}
