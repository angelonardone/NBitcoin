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
		// Helpers
		// ---------------------------------------------------------------------

		private static SegWitMultiSig BuildMultiSig(GroupSDT group, int sequence, bool isChange, Network net)
		{
			if (group == null)
				throw new Exception("Group is null (call FromSDT first)");

			var chain = isChange ? "change" : "receiving";
			var pubKeys = ParticipantPubKeys(group, sequence, isChange, net);
			if (pubKeys.Count < 2)
				throw new Exception($"At least 2 participants (owner + contacts) with a {chain} extended public key are required");

			// OP_CHECKMULTISIG / P2SH-P2WSH hard cap: an N-of-M multisig supports at most 16 signers
			// (OP_16). Reject early with a clear message instead of letting NBitcoin throw deep down.
			if (pubKeys.Count > 16)
				throw new Exception($"Too many participants ({pubKeys.Count}); a Legacy SegWit P2SH-P2WSH multisig supports at most 16 (owner + contacts)");

			int k = group.MinimumShares;
			if (k <= 0 || k > pubKeys.Count)
				throw new Exception($"Invalid MinimumShares ({k}) for {pubKeys.Count} participants");

			return new SegWitMultiSig(pubKeys, k, net);
		}

		// Participants = owner + every contact, each contributing their chain-level extended public key
		// (ExtPubKeyMultiSigReceiving when isChange=false, ExtPubKeyMultiSigChange when true), derived
		// (non-hardened) at the given sequence. Order is deterministic: owner first.
		private static List<PubKey> ParticipantPubKeys(GroupSDT group, int sequence, bool isChange, Network net)
		{
			var xpubs = new List<string>();
			var ownerXpub = isChange ? group.ExtPubKeyMultiSigChange : group.ExtPubKeyMultiSigReceiving;
			if (!string.IsNullOrWhiteSpace(ownerXpub))
				xpubs.Add(ownerXpub!);

			if (group.Contact != null)
			{
				foreach (var c in group.Contact)
				{
					if (c == null) continue;
					var contactXpub = isChange ? c.ExtPubKeyMultiSigChange : c.ExtPubKeyMultiSigReceiving;
					if (!string.IsNullOrWhiteSpace(contactXpub))
						xpubs.Add(contactXpub!);
				}
			}

			var pubKeys = new List<PubKey>();
			foreach (var xpub in xpubs)
			{
				var epk = ExtPubKey.Parse(xpub.Trim(), net);
				pubKeys.Add(epk.Derive((uint)sequence).PubKey);
			}
			return pubKeys;
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
