using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistricutedCryptographyLib
{
	public class GroupSDT
	{
		public Guid GroupId { get; set; }
		public short GroupType { get; set; }  // Assuming GroupType, Wallet as numeric
		public string? GroupName { get; set; }
		public bool AmIGroupOwner { get; set; }
		public bool IsActive { get; set; }
		public short MinimumShares { get; set; }  // Numeric(4.0) -> decimal
		public string? EncPassword { get; set; }
		public string? ClearTextShare { get; set; }
		public bool NumOfSharesReached { get; set; }
		public string? ExtPubKeyMultiSigReceiving { get; set; }
		public string? ExtPubKeyMultiSigChange { get; set; }
		public List<ContactItem> Contact { get; set; } = new List<ContactItem>();
		public List<OtherGroup> OtherGroup { get; set; } = new List<OtherGroup>();
	}

	public class ContactItem
	{
		public Guid ContactId { get; set; }
		public short NumShares { get; set; }  // Numeric(4.0)
		public string? ContactPrivateName { get; set; }
		public string? ContactUserName { get; set; }
		public string? ContactUserPubKey { get; set; }
		public string? ContactEncryptedKey { get; set; }
		public string? ContactEncryptedText { get; set; }
		public DateTime? ContactInvitationSent { get; set; }
		public DateTime? ContactInvitationAccepted { get; set; }
		public bool ContactInvitationDeclined { get; set; }
		public bool ContactInviSent { get; set; }
		public bool ContactInvRec { get; set; }
		public Guid ContactGroupId { get; set; }
		public string? ContactGroupEncPassword { get; set; }
		public string? ClearTextShare { get; set; }
		public bool NumOfSharesReached { get; set; }
		public string? ExtPubKeyMultiSigReceiving { get; set; }
		public string? ExtPubKeyMultiSigChange { get; set; }
		public List<MuSigSignaturesItem> MuSigSignatures { get; set; } = new List<MuSigSignaturesItem>();
	}

	public class MuSigSignaturesItem
	{
		public string? Signature { get; set; }
	}

	public class OtherGroup
	{
		public Guid ReferenceGroupId { get; set; }
		public bool InvitationDeclined { get; set; }
		public string? EncPassword { get; set; }
		public string? ReferenceUserName { get; set; }
		public string? Signature { get; set; }
		public string? ExtPubKeyMultiSigReceiving { get; set; }
		public string? ExtPubKeyMultiSigChange { get; set; }
	}
}
