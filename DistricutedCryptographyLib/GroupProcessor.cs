using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistricutedCryptographyLib
{
	public class GroupProcessor
	{
		// Holds the last GroupSDT ingested from GeneXus so it can be handed back via ToSDT().
		private GroupSDT _group = new GroupSDT();

		// Receives a GroupSDT from GeneXus and stores an independent deep copy inside the library.
		// Returns false when the incoming group is null.
		public bool FromSDT(GroupSDT group)
		{
			if (group == null)
			{
				return false;
			}

			_group = Clone(group);
			return true;
		}

		// Returns an independent deep copy of the GroupSDT currently held by the library back to GeneXus.
		public GroupSDT ToSDT()
		{
			return Clone(_group);
		}

		// ---------------------------------------------------------------------
		// "Legacy Multisignature" — SegWit P2SH-P2WSH N-of-M, driven by the held group.
		// Thin wrappers over LegacyMultiSig so GeneXus only deals with primitive params/returns
		// (all complex crypto stays in the library). Call FromSDT() first to load the group.
		// ---------------------------------------------------------------------

		// Build the N-of-M SegWit address for the loaded group at the given HD sequence on the
		// receiving chain (isChange=false) or the change chain (isChange=true).
		public string CreateLegacyAddress(int sequence, bool isChange, string networkType)
		{
			return LegacyMultiSig.CreateAddress(_group, sequence, isChange, networkType);
		}

		// Build the unsigned spending PSBT (base64) for the loaded group. isChange selects the chain
		// the spent (input) multisig addresses were derived on.
		public string BuildLegacyPsbt(string utxosJson, string sendTo, string amountBtc,
			string changeAddr, string feeBtc, bool sendAll, int sequence, bool isChange, string networkType)
		{
			return LegacyMultiSig.BuildPsbt(_group, utxosJson, sendTo, amountBtc, changeAddr, feeBtc, sendAll, sequence, isChange, networkType);
		}

		// Sign a PSBT with one member's chain-level extended private key (derived at the given sequence).
		public string SignLegacyPsbt(string psbtBase64, int sequence, string signerExtPrivKey, string networkType)
		{
			return LegacyMultiSig.SignPsbt(psbtBase64, sequence, signerExtPrivKey, networkType);
		}

		// Combine several partially-signed PSBTs (JSON array of base64) into one.
		public string CombineLegacyPsbts(string psbtsJson, string networkType)
		{
			return LegacyMultiSig.CombinePsbts(psbtsJson, networkType);
		}

		// Finalize a (combined) PSBT and extract the broadcastable raw transaction.
		public string FinalizeLegacyPsbt(string psbtBase64, string networkType)
		{
			return LegacyMultiSig.Finalize(psbtBase64, networkType);
		}

		private static GroupSDT Clone(GroupSDT source)
		{
			if (source == null)
			{
				return new GroupSDT();
			}

			var copy = new GroupSDT
			{
				GroupId = source.GroupId,
				GroupType = source.GroupType,
				GroupName = source.GroupName,
				AmIGroupOwner = source.AmIGroupOwner,
				IsActive = source.IsActive,
				MinimumShares = source.MinimumShares,
				EncPassword = source.EncPassword,
				ClearTextShare = source.ClearTextShare,
				EncryptedTextShare = source.EncryptedTextShare,
				NumOfSharesReached = source.NumOfSharesReached,
				ExtPubKeyMultiSigReceiving = source.ExtPubKeyMultiSigReceiving,
				ExtPubKeyMultiSigChange = source.ExtPubKeyMultiSigChange,
				SubGroupType = source.SubGroupType,
				BountyGroupId = source.BountyGroupId,
				DataGroupId = source.DataGroupId,
				ExtPubKeyTimeBountyReceiving = source.ExtPubKeyTimeBountyReceiving,
				OtherGroup = Clone(source.OtherGroup)
			};

			if (source.TimeConstrain != null)
			{
				foreach (var item in source.TimeConstrain)
				{
					copy.TimeConstrain.Add(Clone(item));
				}
			}

			if (source.Contact != null)
			{
				foreach (var item in source.Contact)
				{
					copy.Contact.Add(Clone(item));
				}
			}

			return copy;
		}

		private static OtherGroup Clone(OtherGroup source)
		{
			if (source == null)
			{
				return new OtherGroup();
			}

			return new OtherGroup
			{
				ReferenceGroupId = source.ReferenceGroupId,
				InvitationDeclined = source.InvitationDeclined,
				EncPassword = source.EncPassword,
				ReferenceUserName = source.ReferenceUserName,
				Signature = source.Signature,
				ExtPubKeyMultiSigReceiving = source.ExtPubKeyMultiSigReceiving,
				ExtPubKeyMultiSigChange = source.ExtPubKeyMultiSigChange,
				ExtPubKeyTimeBountyReceiving = source.ExtPubKeyTimeBountyReceiving
			};
		}

		private static TimeConstrainItem Clone(TimeConstrainItem source)
		{
			return new TimeConstrainItem
			{
				Sequence = source.Sequence,
				Address = source.Address,
				Date = source.Date,
				EncryptedSecret = source.EncryptedSecret,
				EncryptedKey = source.EncryptedKey
			};
		}

		private static ContactItem Clone(ContactItem source)
		{
			var copy = new ContactItem
			{
				ContactId = source.ContactId,
				NumShares = source.NumShares,
				ContactPrivateName = source.ContactPrivateName,
				ContactUserName = source.ContactUserName,
				ContactUserPubKey = source.ContactUserPubKey,
				ContactEncryptedKey = source.ContactEncryptedKey,
				ContactEncryptedText = source.ContactEncryptedText,
				ContactInvitationSent = source.ContactInvitationSent,
				ContactInvitationAccepted = source.ContactInvitationAccepted,
				ContactInvitationDeclined = source.ContactInvitationDeclined,
				ContactInviSent = source.ContactInviSent,
				ContactInvRec = source.ContactInvRec,
				ContactGroupId = source.ContactGroupId,
				ContactGroupEncPassword = source.ContactGroupEncPassword,
				ClearTextShare = source.ClearTextShare,
				NumOfSharesReached = source.NumOfSharesReached,
				ExtPubKeyMultiSigReceiving = source.ExtPubKeyMultiSigReceiving,
				ExtPubKeyMultiSigChange = source.ExtPubKeyMultiSigChange,
				ExtPubKeyTimeBountyReceiving = source.ExtPubKeyTimeBountyReceiving
			};

			if (source.MuSigSignatures != null)
			{
				foreach (var item in source.MuSigSignatures)
				{
					copy.MuSigSignatures.Add(new MuSigSignaturesItem { Signature = item.Signature });
				}
			}

			return copy;
		}
	}
}
