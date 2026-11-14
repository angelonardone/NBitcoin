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

		/// <summary>
		/// Same as <see cref="SignSpend"/> for a member whose keys live on Ruby (docs/ruby-wallet.md): the library only
		/// has the member's chain-level extended PUBLIC keys (the ones it gave the group) and Ruby signs each fee level
		/// after the user checks it on its screen (one confirmation per level). Ruby's own m/48'/coin'/0'/1' must give
		/// those two keys, so a Ruby holding another wallet is refused before anything is shown.
		/// Declined on Ruby -> {"success": false, "error": "The payment was declined on Ruby"}.
		/// </summary>
		public static string SignSpendWithRuby(GroupSDT group, string bundleJson, string device,
			string receivingExtPubKey, string changeExtPubKey, int finalPercent, string networkType)
		{
			try
			{
				var net = GetNetwork(networkType);
				var sg = ToSegWitGroup(group, net, out _);
				var bundle = FromJson(bundleJson, net);
				var receiving = ExtPubKey.Parse((receivingExtPubKey ?? "").Trim(), net);
				var change = ExtPubKey.Parse((changeExtPubKey ?? "").Trim(), net);
				var coin = net.ChainName == ChainName.Mainnet ? "0'" : "1'";
				var accountPath = KeyPath.Parse("m/48'/" + coin + "/0'/1'");
				var accounts = MemberAccounts(group, sg, net);
				var info = RubyProcessor.WithClient(device, c =>
				{
					var fingerprint = c.GetMasterFingerprint(net);
					var account = ExtPubKey.Parse(c.GetXpub(net, accountPath), net);
					if (account.Derive(0).GetPublicKey() != receiving.GetPublicKey() || account.Derive(1).GetPublicKey() != change.GetPublicKey())
						throw new InvalidOperationException("This Ruby does not hold the keys of this group member");
					// 2026-11-13: with the account key of every member the group is registered on Ruby (asked once on
					// Ruby, then an identical registration answers at once) and every PSBT carries the keys of all the
					// members: Ruby recognises the change as the group's own and does not show it, and the fee levels
					// of a payment are confirmed on one screen.
					var registered = false;
					if (accounts != null)
					{
						var signers = accounts.Select(a => a.Xpub.GetPublicKey() == account.GetPublicKey()
								? (fingerprint, accountPath, a.Xpub.ToString(net))
								: (a.Fingerprint, a.Path, a.Xpub.ToString(net)))
							.OrderBy(s => s.Item3, StringComparer.Ordinal).ToList();
						c.RegisterMultisig(net, RegistrationName(group, sg), "sh(wsh(multi(k)))", true, group.MinimumShares, signers);
						registered = true;
					}
					return SignExternal(sg, bundle, receiving, change, new RootedKeyPath(fingerprint, accountPath), finalPercent,
						requests =>
						{
							if (registered)
								foreach (var request in requests)
									AddGroupKeyPaths(sg, bundle, request, accounts!, fingerprint, accountPath, account);
							// one screen for every fee level: only when Ruby can recognise the change (the other levels
							// differ only in it); otherwise each level is confirmed on its own
							if (registered && requests.Count > 1 && requests[0].Outputs.Count == 2)
								return c.SignPsbtFeeOptions(requests);
							return requests.Select(r => c.SignPsbt(r)).ToList();
						});
				});
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
			catch (RubyException e) when (e.Code == RubyException.UserCancelled)
			{
				return Err("The payment was declined on Ruby");
			}
			catch (Exception e) { return Err(e); }
		}

		internal sealed class MemberAccount
		{
			public HDFingerprint Fingerprint { get; set; }
			public KeyPath Path { get; set; } = new KeyPath();
			public ExtPubKey Xpub { get; set; } = null!;
		}

		/// <summary>
		/// The BIP48 account key of every member ("[fingerprint/48'/coin'/0'/1']xpub", ExtPubKeyMultiSigAccount), in the
		/// order of the group, each checked against the two chain keys the member gave the group (account/0 and /1).
		/// Null when a member has none (groups made before 2026-11-13): then nothing is registered on Ruby.
		/// </summary>
		internal static List<MemberAccount>? MemberAccounts(GroupSDT group, SegWitMultiSigGroup sg, Network net)
		{
			var origins = new List<string?>();
			if (!string.IsNullOrWhiteSpace(group.ExtPubKeyMultiSigReceiving) || !string.IsNullOrWhiteSpace(group.ExtPubKeyMultiSigChange))
				origins.Add(group.ExtPubKeyMultiSigAccount);
			foreach (var c in group.Contact ?? new List<ContactItem>())
				if (c != null && (!string.IsNullOrWhiteSpace(c.ExtPubKeyMultiSigReceiving) || !string.IsNullOrWhiteSpace(c.ExtPubKeyMultiSigChange)))
					origins.Add(c.ExtPubKeyMultiSigAccount);
			if (origins.Count != sg.MemberCount)
				return null;
			var accounts = new List<MemberAccount>();
			for (int m = 0; m < origins.Count; m++)
			{
				var text = (origins[m] ?? "").Trim();
				var close = text.IndexOf(']');
				if (!text.StartsWith("[") || close < 0)
					return null;
				var origin = RootedKeyPath.Parse(text.Substring(1, close - 1));
				var xpub = ExtPubKey.Parse(text.Substring(close + 1), net);
				if (xpub.Derive(0).Derive(0).PubKey != sg.MemberPubKey(m, 0, false) || xpub.Derive(1).Derive(0).PubKey != sg.MemberPubKey(m, 0, true))
					throw new InvalidOperationException("The account key of a member does not match the keys he gave the group");
				accounts.Add(new MemberAccount { Fingerprint = origin.MasterFingerprint, Path = origin.KeyPath, Xpub = xpub });
			}
			return accounts;
		}

		/// <summary>The name of the group on Ruby (at most 15 printable characters): a part of its name + a hash of its keys.</summary>
		internal static string RegistrationName(GroupSDT group, SegWitMultiSigGroup sg)
		{
			var keys = string.Join(",", Enumerable.Range(0, sg.MemberCount).Select(m => sg.MemberPubKey(m, 0, false).ToHex()).OrderBy(k => k, StringComparer.Ordinal))
				+ "/" + sg.RequiredSignatures;
			var hash = Encoders.Hex.EncodeData(NBitcoin.Crypto.Hashes.SHA256(System.Text.Encoding.UTF8.GetBytes(keys))).Substring(0, 6);
			var prefix = new string((group.GroupName ?? "").Where(ch => ch > 32 && ch < 127).Take(8).ToArray());
			return (prefix.Length > 0 ? prefix + "-" : "DC-") + hash;
		}

		/// <summary>
		/// Every member's key, with its origin, on every input and on the change output (when there is one): what Ruby
		/// needs to check the inputs and the change against the registered group.
		/// </summary>
		internal static void AddGroupKeyPaths(SegWitMultiSigGroup sg, SegWitMultiSigBundle bundle, PSBT request,
			IList<MemberAccount> accounts, HDFingerprint rubyFingerprint, KeyPath rubyAccountPath, ExtPubKey rubyAccount)
		{
			RootedKeyPath Origin(MemberAccount a, uint chain, uint seq) => a.Xpub.GetPublicKey() == rubyAccount.GetPublicKey()
				? new RootedKeyPath(rubyFingerprint, rubyAccountPath.Derive(chain).Derive(seq))
				: new RootedKeyPath(a.Fingerprint, a.Path.Derive(chain).Derive(seq));
			for (int i = 0; i < bundle.Inputs.Count; i++)
			{
				uint chain = bundle.Inputs[i].IsChange ? 1u : 0u, seq = (uint)bundle.Inputs[i].Sequence;
				foreach (var a in accounts)
					request.Inputs[i].AddKeyPath(a.Xpub.Derive(chain).Derive(seq).PubKey, Origin(a, chain, seq));
			}
			// the change: an output on the change chain of the group (the library always builds [payment, change])
			var maxSeq = bundle.Inputs.Select(x => x.Sequence).DefaultIfEmpty(0).Max() + 1000;
			foreach (var output in request.Outputs)
			{
				for (int seq = 0; seq <= maxSeq; seq++)
				{
					if (sg.GetMultiSig(seq, true).Address.ScriptPubKey != output.ScriptPubKey)
						continue;
					foreach (var a in accounts)
						output.AddKeyPath(a.Xpub.Derive(1).Derive((uint)seq).PubKey, Origin(a, 1, (uint)seq));
					break;
				}
			}
		}

		/// <summary>
		/// One member signs on an external signer that holds the keys (Ruby): the same checks and the same result as
		/// SegWitMultiSigSpend.Sign, but only the member's chain-level extended PUBLIC keys are here. Each PSBT gets,
		/// on every input, the BIP32 path of the member's key (<paramref name="memberAccount"/> = master fingerprint +
		/// m/48'/coin'/account'/1', then chain/sequence) and goes to <paramref name="signer"/>, which must return it
		/// with the member's signature on every input and the same transaction. Every signature is verified here.
		/// <paramref name="signer"/> gets the PSBT of every fee level that is signed (in the order of the bundle) and
		/// returns them signed, in the same order.
		/// </summary>
		internal static SegWitMultiSigSpendInfo SignExternal(SegWitMultiSigGroup group, SegWitMultiSigBundle bundle,
			ExtPubKey receivingXpub, ExtPubKey changeXpub, RootedKeyPath memberAccount, int finalPercent,
			Func<IList<PSBT>, IList<PSBT>> signer)
		{
			if (memberAccount == null) throw new ArgumentNullException(nameof(memberAccount));
			if (signer == null) throw new ArgumentNullException(nameof(signer));
			var info = SegWitMultiSigSpend.Check(group, bundle);
			var pubKeys = new List<PubKey>();
			int member = -1;
			for (int i = 0; i < bundle.Inputs.Count; i++)
			{
				var input = bundle.Inputs[i];
				var chainXpub = input.IsChange ? changeXpub : receivingXpub;
				if (chainXpub == null)
					throw new ArgumentException($"The {(input.IsChange ? "change" : "receiving")} extended public key is missing");
				var pub = chainXpub.Derive((uint)input.Sequence).PubKey;
				var m = group.MemberOf(pub, input.Sequence, input.IsChange);
				if (m < 0)
					throw new ArgumentException("The signing key does not belong to a member of this group");
				if (member >= 0 && m != member)
					throw new ArgumentException("The receiving and change keys are of different members");
				member = m;
				pubKeys.Add(pub);
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

			var requests = new List<PSBT>();
			foreach (var level in bundle.Levels)
			{
				var request = level.Psbt.Clone();
				for (int i = 0; i < bundle.Inputs.Count; i++)
				{
					var path = memberAccount.Derive(new KeyPath((uint)(bundle.Inputs[i].IsChange ? 1 : 0), (uint)bundle.Inputs[i].Sequence));
					request.Inputs[i].AddKeyPath(pubKeys[i], path);
				}
				requests.Add(request);
			}
			var signedAll = signer(requests) ?? throw new InvalidOperationException("The signer returned nothing");
			if (signedAll.Count != bundle.Levels.Count)
				throw new InvalidOperationException("The signer did not sign every fee level");
			for (int l = 0; l < bundle.Levels.Count; l++)
			{
				var level = bundle.Levels[l];
				var signedPsbt = signedAll[l];
				if (signedPsbt.GetGlobalTransaction().GetHash() != level.Psbt.GetGlobalTransaction().GetHash())
					throw new InvalidOperationException("The signer returned a different transaction");
				for (int i = 0; i < bundle.Inputs.Count; i++)
				{
					if (!signedPsbt.Inputs[i].PartialSigs.TryGetValue(pubKeys[i], out var sig))
						throw new InvalidOperationException($"The signer did not sign input {i}");
					if (sig.SigHash != SigHash.All)
						throw new InvalidOperationException($"The signer used another sighash on input {i}");
					var hash = level.Psbt.Inputs[i].GetSignatureHash(SigHash.All, null);
					if (!pubKeys[i].Verify(hash, sig.Signature))
						throw new InvalidOperationException($"The signature of input {i} is not valid");
					level.Psbt.Inputs[i].PartialSigs[pubKeys[i]] = sig;
				}
			}
			// Check: only members signed, the same members on every level
			return SegWitMultiSigSpend.Check(group, bundle);
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
