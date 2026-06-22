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
