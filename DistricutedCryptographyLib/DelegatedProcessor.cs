namespace DistricutedCryptographyLib
{
	/// <summary>
	/// External Object for the "Delegated Multisignature" groups: Taproot, the owner spends alone (key
	/// path), k of the n members spend together (script path) with pre-signed fee levels.
	///
	/// Same pattern as GroupProcessor for Legacy: GeneXus loads the group with FromSDT() and then calls
	/// methods that take and return only texts, numbers and booleans (the results are JSON). All the
	/// crypto is in DelegatedMultiSigSpend. In the loaded group the owner is
	/// ExtPubKeyMultiSigReceiving / ExtPubKeyMultiSigChange and the members are the contacts (the owner
	/// is not a contact).
	/// </summary>
	public class DelegatedProcessor
	{
		// Keeps an independent copy of the group, exactly as Legacy does.
		private readonly GroupProcessor _groups = new GroupProcessor();
		private GroupSDT _group = new GroupSDT();

		// Receives the group from GeneXus. Returns false when it is null.
		public bool FromSDT(GroupSDT group)
		{
			if (!_groups.FromSDT(group))
			{
				return false;
			}

			_group = _groups.ToSDT();
			return true;
		}

		// Returns an independent copy of the loaded group back to GeneXus.
		public GroupSDT ToSDT()
		{
			return _groups.ToSDT();
		}

		// Build the Taproot address of the loaded group at the given HD sequence and chain.
		public string CreateAddress(int sequence, bool isChange, string networkType)
		{
			return DelegatedMultiSigSpend.CreateAddress(_group, sequence, isChange, networkType);
		}

		// The ranged output descriptor of the receiving or the change chain of the loaded group: with it a
		// descriptor wallet (Bitcoin Core) derives the same addresses and can watch or recover the group.
		public string GetDescriptor(bool isChange, string networkType)
		{
			return DelegatedMultiSigSpend.GetDescriptor(_group, isChange, networkType);
		}

		// Virtual size of a spend (worst script path for the members, key path for the owner), to
		// calculate the fee. utxosJson: [{TxId, Vout, AmountBtc, Sequence, IsChange, Address}].
		public string EstimateVsize(string utxosJson, string sendTo, string changeAddr, bool sendAll,
			bool asOwner, string networkType)
		{
			return DelegatedMultiSigSpend.EstimateVsize(_group, utxosJson, sendTo, changeAddr, sendAll, asOwner, networkType);
		}

		// Build the unsigned bundle: one PSBT for the calculated fee and one per percentage above it
		// (percentages = "10,30,100": multiples of 10 up to 100, at most 3).
		public string BuildSpend(string utxosJson, string sendTo, string amountBtc, string changeAddr,
			string feeBtc, string percentages, bool sendAll, string networkType)
		{
			return DelegatedMultiSigSpend.BuildSpend(_group, utxosJson, sendTo, amountBtc, changeAddr, feeBtc, percentages, sendAll, networkType);
		}

		// Sign the bundle with one member's chain-level extended private keys. finalPercent < 0: sign
		// every level; finalPercent >= 0 (last signer): sign only that level and finalize it.
		public string SignSpend(string bundleJson, string receivingExtPrivKey, string changeExtPrivKey,
			int finalPercent, string networkType)
		{
			return DelegatedMultiSigSpend.SignSpend(_group, bundleJson, receivingExtPrivKey, changeExtPrivKey, finalPercent, networkType);
		}

		// Finalize one level of a bundle that already has the required signatures.
		public string FinalizeSpend(string bundleJson, int percent, string networkType)
		{
			return DelegatedMultiSigSpend.FinalizeSpend(_group, bundleJson, percent, networkType);
		}

		// What the bundle really pays (destination, amount, change, fee of each level), who signed and
		// whether the next signature is the last one.
		public string DescribeSpend(string bundleJson, string myReceivingExtPubKey, string myChangeExtPubKey,
			string networkType)
		{
			return DelegatedMultiSigSpend.DescribeSpend(_group, bundleJson, myReceivingExtPubKey, myChangeExtPubKey, networkType);
		}

		// The owner spends alone by the key path: build, sign and finalize in one call.
		public string OwnerSpend(string utxosJson, string sendTo, string amountBtc, string changeAddr,
			string feeBtc, bool sendAll, string receivingExtPrivKey, string changeExtPrivKey, string networkType)
		{
			return DelegatedMultiSigSpend.OwnerSpend(_group, utxosJson, sendTo, amountBtc, changeAddr, feeBtc, sendAll, receivingExtPrivKey, changeExtPrivKey, networkType);
		}
	}
}
