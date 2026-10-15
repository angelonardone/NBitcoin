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
	/// "Legacy Multisignature" = traditional SegWit P2SH-P2WSH N-of-M multisig (OP_CHECKMULTISIG).
	///
	/// All crypto is done here, inside the library, driven entirely by the GroupSDT that GeneXus
	/// hands over through GroupProcessor.FromSDT(). The participant set is the group owner plus every
	/// Contact (the owner is a member too); each participant contributes a chain-level extended public
	/// key — ExtPubKeyMultiSigReceiving for the receiving chain or ExtPubKeyMultiSigChange for the
	/// change chain (BIP48: neuter(m/48'/coin'/account'/1'/0) and .../1 respectively) — and the
	/// threshold is GroupSDT.MinimumShares. Per call, every participant key is derived (non-hardened)
	/// at the given HD <c>sequence</c> on the selected chain (<c>isChange</c>), so a fresh multisig
	/// address can be produced for each index, exactly like the Delegated wallet does.
	///
	/// The public keys go into the script in lexicographic order (BIP67), so the address does not depend on
	/// the order of the members and the group is the standard descriptor
	/// <c>sh(wsh(sortedmulti(k, xpub/*, ...)))</c> (BIP383), which other wallets import: see GetDescriptor.
	///
	/// Every method returns a JSON string (never throws toward GeneXus): on success
	/// <c>{ "success": true, "error": "", ... }</c>, on failure <c>{ "success": false, "error": "..." }</c>.
	/// Distributed signing uses PSBT (BIP174) as the interchange artifact: build once, each member
	/// signs their own copy with their key, the copies are combined and finalized when the threshold
	/// is reached.
	/// </summary>
	public static class LegacyMultiSig
	{
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
		}

		// ---------------------------------------------------------------------
		// Public API (operates on a GroupSDT plus primitive parameters)
		// ---------------------------------------------------------------------

		/// <summary>
		/// Build the N-of-M SegWit (P2SH-P2WSH) address for the group at the given HD sequence on the
		/// receiving chain (<paramref name="isChange"/> = false) or the change chain (true).
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
					p2shP2wsh = ToHex(ms.P2SH_P2WSH),
					p2wsh = ToHex(ms.P2WSH),
					witnessScript = ToHex(ms.MultisigScript),
					k = ms.RequiredSignatures,
					n = ms.SignerPubKeys.Count,
					isChange,
					sequence
				});
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// The ranged output descriptor of one chain of the group (receiving or change), with its checksum:
		/// its address number i is CreateAddress(i). A descriptor wallet (Bitcoin Core, Sparrow) derives the
		/// same addresses from it and can watch the group without this library. Only public keys.
		/// </summary>
		public static string GetDescriptor(GroupSDT group, bool isChange, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var xpubs = ParticipantXpubs(group, isChange);
				CheckParticipants(group, xpubs.Count, isChange ? "change" : "receiving");
				var keys = xpubs.Select(xpub => ExtPubKey.Parse(xpub, net).ToString(net) + "/*");
				var descriptor = NBitcoin.WalletPolicies.Miniscript.AddChecksum(
					$"sh(wsh(sortedmulti({group.MinimumShares},{string.Join(",", keys)})))");
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					descriptor,
					k = (int)group.MinimumShares,
					n = xpubs.Count,
					isChange
				});
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// Build the (unsigned) spending PSBT. All UTXOs are assumed to belong to the multisig address
		/// at <paramref name="sequence"/>. Returns the PSBT (base64) ready to be signed by each member.
		/// </summary>
		public static string BuildPsbt(GroupSDT group, string utxosJson, string sendTo, string amountBtc,
			string changeAddr, string feeBtc, bool sendAll, int sequence, bool isChange, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var ms = BuildMultiSig(group, sequence, isChange, net);

				var utxos = JsonSerializer.Deserialize<List<UtxoDto>>(utxosJson ?? "[]", JsonIn) ?? new List<UtxoDto>();
				if (utxos.Count == 0)
					return Err("No UTXOs provided");

				var builder = net.CreateTransactionBuilder();
				var coins = new List<ScriptCoin>();
				foreach (var u in utxos)
				{
					var outpoint = new OutPoint(uint256.Parse(u.TxId), (uint)u.Vout);
					var txout = new TxOut(Money.Coins(ParseDec(u.AmountBtc)), ms.Address.ScriptPubKey);
					var coin = ms.CreateCoin(new Coin(outpoint, txout));
					coins.Add(coin);
					builder.AddCoins(coin);
				}

				var destination = BitcoinAddress.Create(sendTo.Trim(), net);
				if (sendAll)
				{
					builder.SendAll(destination);
				}
				else
				{
					builder.Send(destination, Money.Coins(ParseDec(amountBtc)));
					builder.SetChange(BitcoinAddress.Create(changeAddr.Trim(), net));
				}
				builder.SendFees(Money.Coins(ParseDec(feeBtc)));

				var unsigned = builder.BuildTransaction(false);
				var psbt = PSBT.FromTransaction(unsigned, net);
				psbt.AddCoins(coins.ToArray());
				// Attach the witness (multisig) and the P2WSH redeem scripts so every signer/finalizer
				// has the full nesting info without needing the group again.
				psbt.AddScripts(ms.MultisigScript, ms.P2WSH);

				return JsonSerializer.Serialize(new { success = true, error = "", psbt = psbt.ToBase64() });
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// Sign the PSBT with one member's key: derives the member's child key at <paramref name="sequence"/>
		/// from their chain-level extended private key (the receiving- or change-chain xprv that matches the
		/// chain the input addresses were derived on) and adds the partial signature.
		/// </summary>
		public static string SignPsbt(string psbtBase64, int sequence, string signerExtPrivKey, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var psbt = PSBT.Parse(psbtBase64.Trim(), net);
				var extKey = ExtKey.Parse(signerExtPrivKey.Trim(), net);
				var childKey = extKey.Derive((uint)sequence).PrivateKey;
				psbt.SignWithKeys(childKey);
				return JsonSerializer.Serialize(new { success = true, error = "", psbt = psbt.ToBase64() });
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>Combine several partially-signed PSBTs (JSON array of base64 strings) into one.</summary>
		public static string CombinePsbts(string psbtsJson, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var list = JsonSerializer.Deserialize<List<string>>(psbtsJson ?? "[]", JsonIn) ?? new List<string>();
				if (list.Count == 0)
					return Err("No PSBTs provided");

				var combined = PSBT.Parse(list[0].Trim(), net);
				for (int i = 1; i < list.Count; i++)
					combined = combined.Combine(PSBT.Parse(list[i].Trim(), net));

				return JsonSerializer.Serialize(new { success = true, error = "", psbt = combined.ToBase64() });
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// Finalize a (combined) PSBT and extract the broadcastable raw transaction.
		/// Returns success=false with the missing-signature detail if the threshold is not yet met.
		/// </summary>
		public static string Finalize(string psbtBase64, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var psbt = PSBT.Parse(psbtBase64.Trim(), net);
				if (!psbt.TryFinalize(out var errors))
				{
					var detail = errors == null ? "" : string.Join("; ", errors.Select(e => e.ToString()));
					return Err("PSBT not complete (need more signatures): " + detail);
				}
				var tx = psbt.ExtractTransaction();
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					txHex = tx.ToHex(),
					txId = tx.GetHash().ToString()
				});
			}
			catch (Exception e) { return Err(e); }
		}

		// ---------------------------------------------------------------------
		// Payments with pre-signed fee levels (2026-10-15): same JSON contract as DelegatedMultiSigSpend.
		// The crypto and every check are NBitcoin.SegWitMultiSigSpend (tested in NBitcoin.Tests on a node).
		// Each UTXO carries its own derivation, so a payment may spend coins of several addresses.
		// ---------------------------------------------------------------------

		private sealed class SpendUtxoDto
		{
			public string TxId { get; set; } = "";
			public int Vout { get; set; }
			public string AmountBtc { get; set; } = "0";
			public int Sequence { get; set; }
			public bool IsChange { get; set; }
			// Optional: the address the wallet has for this UTXO; checked against the derived one.
			public string Address { get; set; } = "";
		}

		private sealed class BundleInputDto
		{
			public int Sequence { get; set; }
			public bool IsChange { get; set; }
		}

		private sealed class BundleLevelDto
		{
			public int Percent { get; set; }
			public string Psbt { get; set; } = "";
		}

		private sealed class BundleDto
		{
			public int Version { get; set; } = 1;
			public List<BundleInputDto> Inputs { get; set; } = new List<BundleInputDto>();
			public List<BundleLevelDto> Levels { get; set; } = new List<BundleLevelDto>();
		}

		/// <summary>
		/// Build the unsigned bundle: one PSBT for the calculated fee and one per percentage above it
		/// (<paramref name="percentages"/> = "10,30,100": multiples of 10 up to 100, at most 3).
		/// utxosJson: [{TxId, Vout, AmountBtc, Sequence, IsChange, Address}].
		/// </summary>
		public static string BuildSpend(GroupSDT group, string utxosJson, string sendTo, string amountBtc,
			string changeAddr, string feeBtc, string percentages, bool sendAll, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var sg = ToSegWitGroup(group, net, out _);
				var utxos = JsonSerializer.Deserialize<List<SpendUtxoDto>>(utxosJson ?? "[]", JsonIn) ?? new List<SpendUtxoDto>();
				if (utxos.Count == 0)
					return Err("No UTXOs provided");
				var coins = new List<SegWitMultiSigUtxo>();
				foreach (var u in utxos)
				{
					var address = (u.Address ?? "").Trim();
					if (address.Length > 0 && address != sg.GetMultiSig(u.Sequence, u.IsChange).Address.ToString())
						return Err("Generated address and UTXO address don't match");
					coins.Add(new SegWitMultiSigUtxo(new OutPoint(uint256.Parse(u.TxId.Trim()), (uint)u.Vout),
						Money.Coins(ParseDec(u.AmountBtc)), u.Sequence, u.IsChange));
				}
				var percents = new List<int>();
				foreach (var part in (percentages ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
				{
					if (!int.TryParse(part, NumberStyles.Integer, CultureInfo.InvariantCulture, out var percent))
						return Err($"Invalid fee percentage '{part}'");
					percents.Add(percent);
				}
				var bundle = SegWitMultiSigSpend.Build(sg, coins, BitcoinAddress.Create(sendTo.Trim(), net),
					sendAll ? null : Money.Coins(ParseDec(amountBtc)), sendAll,
					sendAll ? null : BitcoinAddress.Create((changeAddr ?? "").Trim(), net),
					Money.Coins(ParseDec(feeBtc)), percents);
				var info = SegWitMultiSigSpend.Check(sg, bundle);
				return JsonSerializer.Serialize(new { success = true, error = "", bundle = ToJson(bundle), levels = DescribeLevels(bundle, info) });
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// Sign the bundle with one member's chain-level extended private keys (receiving and change).
		/// <paramref name="finalPercent"/> &lt; 0: sign every level (first and intermediate signers).
		/// <paramref name="finalPercent"/> &gt;= 0 (LAST signer): sign only that level and finalize it: the
		/// result carries <c>txHex</c> / <c>txId</c> and the bundle keeps only that level.
		/// </summary>
		public static string SignSpend(GroupSDT group, string bundleJson, string receivingExtPrivKey,
			string changeExtPrivKey, int finalPercent, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var sg = ToSegWitGroup(group, net, out _);
				var bundle = FromJson(bundleJson, net);
				var receiving = string.IsNullOrWhiteSpace(receivingExtPrivKey) ? null : ExtKey.Parse(receivingExtPrivKey.Trim(), net);
				var change = string.IsNullOrWhiteSpace(changeExtPrivKey) ? null : ExtKey.Parse(changeExtPrivKey.Trim(), net);
				var info = SegWitMultiSigSpend.Sign(sg, bundle, receiving, change, finalPercent);
				string txHex = "", txId = "";
				decimal feeBtc = 0m;
				int vsize = 0;
				if (finalPercent >= 0)
				{
					var tx = SegWitMultiSigSpend.Finalize(sg, bundle, finalPercent);
					txHex = tx.ToHex();
					txId = tx.GetHash().ToString();
					feeBtc = info.Fees[0].ToDecimal(MoneyUnit.BTC);
					vsize = tx.GetVirtualSize();
				}
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					bundle = ToJson(bundle),
					signatures = info.Signatures,
					required = info.Required,
					complete = info.Complete,
					txHex,
					txId,
					feeBtc,
					vsize
				});
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>Finalize one level of a bundle that already has the required signatures.</summary>
		public static string FinalizeSpend(GroupSDT group, string bundleJson, int percent, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var sg = ToSegWitGroup(group, net, out _);
				var bundle = FromJson(bundleJson, net);
				var info = SegWitMultiSigSpend.Check(sg, bundle);
				var tx = SegWitMultiSigSpend.Finalize(sg, bundle, percent);
				var index = bundle.Levels.FindIndex(l => l.Percent == percent);
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					txHex = tx.ToHex(),
					txId = tx.GetHash().ToString(),
					feeBtc = info.Fees[index].ToDecimal(MoneyUnit.BTC),
					vsize = tx.GetVirtualSize()
				});
			}
			catch (Exception e) { return Err(e); }
		}

		/// <summary>
		/// What a bundle really pays, read from its PSBTs (never from the message that carried it): destination,
		/// amount, change address, the fee of each level, who signed, and whether the next signature is the last.
		/// <paramref name="myReceivingExtPubKey"/> / <paramref name="myChangeExtPubKey"/> (optional) tell
		/// whether that member already signed.
		/// </summary>
		public static string DescribeSpend(GroupSDT group, string bundleJson, string myReceivingExtPubKey,
			string myChangeExtPubKey, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var sg = ToSegWitGroup(group, net, out var names);
				var bundle = FromJson(bundleJson, net);
				var info = SegWitMultiSigSpend.Check(sg, bundle);
				bool iSigned = false;
				var first = bundle.Inputs[0];
				var myXpub = first.IsChange ? myChangeExtPubKey : myReceivingExtPubKey;
				if (!string.IsNullOrWhiteSpace(myXpub))
				{
					var me = sg.MemberOf(ExtPubKey.Parse(myXpub.Trim(), net).Derive((uint)first.Sequence).PubKey, first.Sequence, first.IsChange);
					iSigned = me >= 0 && info.SignedBy.Contains(me);
				}
				var baseTx = bundle.Levels[0].Psbt.GetGlobalTransaction();
				return JsonSerializer.Serialize(new
				{
					success = true,
					error = "",
					required = info.Required,
					signatures = info.Signatures,
					complete = info.Complete,
					nextIsLast = info.NextIsLast,
					iSigned,
					sendTo = info.PaymentScript.GetDestinationAddress(net)?.ToString() ?? "",
					changeTo = info.ChangeScript?.GetDestinationAddress(net)?.ToString() ?? "",
					amountBtc = baseTx.Outputs[0].Value.ToDecimal(MoneyUnit.BTC),
					totalInBtc = info.TotalIn.ToDecimal(MoneyUnit.BTC),
					signedBy = info.SignedBy.Select(m => names[m]).ToList(),
					levels = DescribeLevels(bundle, info)
				});
			}
			catch (Exception e) { return Err(e); }
		}

		// The participants in a fixed order (owner, then the contacts), each with BOTH chain keys, and their names.
		private static SegWitMultiSigGroup ToSegWitGroup(GroupSDT group, Network net, out List<string> names)
		{
			if (group == null)
				throw new Exception("Group is null (call FromSDT first)");
			var receiving = new List<ExtPubKey>();
			var change = new List<ExtPubKey>();
			var found = new List<string>();
			void Add(string? r, string? c, string name)
			{
				if (string.IsNullOrWhiteSpace(r) && string.IsNullOrWhiteSpace(c))
					return;
				if (string.IsNullOrWhiteSpace(r) || string.IsNullOrWhiteSpace(c))
					throw new Exception($"{(name.Length > 0 ? name : "A participant")} has only one of the two extended public keys of the group");
				receiving.Add(ExtPubKey.Parse(r!.Trim(), net));
				change.Add(ExtPubKey.Parse(c!.Trim(), net));
				found.Add(name);
			}
			Add(group.ExtPubKeyMultiSigReceiving, group.ExtPubKeyMultiSigChange, "");
			if (group.Contact != null)
				foreach (var c in group.Contact)
					if (c != null)
						Add(c.ExtPubKeyMultiSigReceiving, c.ExtPubKeyMultiSigChange, (c.ContactUserName ?? "").Trim());
			CheckParticipants(group, receiving.Count, "receiving");
			names = found;
			return new SegWitMultiSigGroup(receiving, change, group.MinimumShares, net);
		}

		private static object[] DescribeLevels(SegWitMultiSigBundle bundle, SegWitMultiSigSpendInfo info)
		{
			var result = new List<object>();
			for (int l = 0; l < bundle.Levels.Count; l++)
			{
				var tx = bundle.Levels[l].Psbt.GetGlobalTransaction();
				result.Add(new
				{
					percent = bundle.Levels[l].Percent,
					feeBtc = info.Fees[l].ToDecimal(MoneyUnit.BTC),
					amountBtc = tx.Outputs[0].Value.ToDecimal(MoneyUnit.BTC),
					changeBtc = tx.Outputs.Count == 2 ? tx.Outputs[1].Value.ToDecimal(MoneyUnit.BTC) : 0m
				});
			}
			return result.ToArray();
		}

		private static string ToJson(SegWitMultiSigBundle bundle) => JsonSerializer.Serialize(new BundleDto
		{
			Inputs = bundle.Inputs.Select(i => new BundleInputDto { Sequence = i.Sequence, IsChange = i.IsChange }).ToList(),
			Levels = bundle.Levels.Select(l => new BundleLevelDto { Percent = l.Percent, Psbt = l.Psbt.ToBase64() }).ToList()
		});

		private static SegWitMultiSigBundle FromJson(string bundleJson, Network net)
		{
			if (string.IsNullOrWhiteSpace(bundleJson))
				throw new Exception("The payment is empty");
			var dto = JsonSerializer.Deserialize<BundleDto>(bundleJson.Trim(), JsonIn) ?? new BundleDto();
			return new SegWitMultiSigBundle
			{
				Inputs = dto.Inputs.Select(i => new SegWitMultiSigBundleInput { Sequence = i.Sequence, IsChange = i.IsChange }).ToList(),
				Levels = dto.Levels.Select(l => new SegWitMultiSigFeeLevel { Percent = l.Percent, Psbt = PSBT.Parse(l.Psbt.Trim(), net) }).ToList()
			};
		}

		// ---------------------------------------------------------------------
		// Helpers
		// ---------------------------------------------------------------------

		private static SegWitMultiSig BuildMultiSig(GroupSDT group, int sequence, bool isChange, Network net)
		{
			if (group == null)
				throw new Exception("Group is null (call FromSDT first)");

			var pubKeys = ParticipantPubKeys(group, sequence, isChange, net);
			CheckParticipants(group, pubKeys.Count, isChange ? "change" : "receiving");
			return new SegWitMultiSig(pubKeys, group.MinimumShares, net);
		}

		private static void CheckParticipants(GroupSDT group, int count, string chain)
		{
			if (count < 2)
				throw new Exception($"At least 2 participants (owner + contacts) with a {chain} extended public key are required");

			// OP_CHECKMULTISIG / P2SH-P2WSH hard cap: an N-of-M multisig supports at most 16 signers
			// (OP_16). Reject early with a clear message instead of letting NBitcoin throw deep down.
			if (count > 16)
				throw new Exception($"Too many participants ({count}); a Legacy SegWit P2SH-P2WSH multisig supports at most 16 (owner + contacts)");

			int k = group.MinimumShares;
			if (k <= 0 || k > count)
				throw new Exception($"Invalid MinimumShares ({k}) for {count} participants");
		}

		// Participants = owner + every contact, each contributing their chain-level extended public key
		// (ExtPubKeyMultiSigReceiving when isChange=false, ExtPubKeyMultiSigChange when true).
		private static List<string> ParticipantXpubs(GroupSDT group, bool isChange)
		{
			if (group == null)
				throw new Exception("Group is null (call FromSDT first)");

			var xpubs = new List<string>();
			var ownerXpub = isChange ? group.ExtPubKeyMultiSigChange : group.ExtPubKeyMultiSigReceiving;
			if (!string.IsNullOrWhiteSpace(ownerXpub))
				xpubs.Add(ownerXpub!.Trim());

			if (group.Contact != null)
			{
				foreach (var c in group.Contact)
				{
					if (c == null) continue;
					var contactXpub = isChange ? c.ExtPubKeyMultiSigChange : c.ExtPubKeyMultiSigReceiving;
					if (!string.IsNullOrWhiteSpace(contactXpub))
						xpubs.Add(contactXpub!.Trim());
				}
			}
			return xpubs;
		}

		// The participants' public keys at the given sequence (non-hardened child of each chain-level key),
		// in lexicographic order of the compressed key (BIP67 / sortedmulti): the order they have in the script.
		private static List<PubKey> ParticipantPubKeys(GroupSDT group, int sequence, bool isChange, Network net)
		{
			return ParticipantXpubs(group, isChange)
				.Select(xpub => ExtPubKey.Parse(xpub, net).Derive((uint)sequence).PubKey)
				.OrderBy(pubKey => pubKey.ToHex(), StringComparer.Ordinal)
				.ToList();
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

		private static string ToHex(Script script) => Encoders.Hex.EncodeData(script.ToBytes());

		private static string Err(string message) =>
			JsonSerializer.Serialize(new { success = false, error = message });

		private static string Err(Exception e) => Err(e.Message);
	}
}
