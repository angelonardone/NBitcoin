namespace DistricutedCryptographyLib
{
	/// <summary>
	/// External Object for the MuSig2 group wallets: "Delegated MultiSig 2" (GroupType 80, the owner spends alone) and
	/// "Multi Signature 2" (GroupType 90, no owner), signed live in a signing room by the members present.
	///
	/// Same pattern as DelegatedProcessor: GeneXus loads the group with FromSDT() and then calls methods that take and
	/// return only texts, numbers and booleans (the results are JSON). All the crypto is in MuSig2GroupSpend; the
	/// secret nonces never leave this process (only the public nonces are returned).
	/// </summary>
	public class MuSig2Processor
	{
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

		// The Taproot address of the loaded group at the given HD sequence and chain.
		public string CreateAddress(int sequence, bool isChange, string networkType)
		{
			return MuSig2GroupSpend.CreateAddress(_group, sequence, isChange, networkType);
		}

		// The ranged BIP390 descriptor (musig()) of the receiving or the change chain.
		public string GetDescriptor(bool isChange, string networkType)
		{
			return MuSig2GroupSpend.GetDescriptor(_group, isChange, networkType);
		}

		// Exact virtual size of a spend; path = "owner", "leaf" (k members) or "all" (every signer, key path).
		// utxosJson: [{TxId, Vout, AmountBtc, Sequence, IsChange, Address}].
		public string EstimateVsize(string utxosJson, string sendTo, string changeAddr, bool sendAll, string path,
			string networkType)
		{
			return MuSig2GroupSpend.EstimateVsize(_group, utxosJson, sendTo, changeAddr, sendAll, path, networkType);
		}

		// The owner of a Delegated MultiSig 2 spends alone by the key path: build, sign and finalize in one call.
		public string OwnerSpend(string utxosJson, string sendTo, string amountBtc, string changeAddr, string feeBtc,
			bool sendAll, string receivingExtPrivKey, string changeExtPrivKey, string networkType)
		{
			return MuSig2GroupSpend.OwnerSpend(_group, utxosJson, sendTo, amountBtc, changeAddr, feeBtc, sendAll, receivingExtPrivKey, changeExtPrivKey, networkType);
		}

		// The session of a payment, built once the members present are known (signersJson = ["user", ...] or "all").
		public string BuildSession(string utxosJson, string sendTo, string amountBtc, string changeAddr,
			int changeSequence, string feeBtc, bool sendAll, string signersJson, string networkType)
		{
			return MuSig2GroupSpend.BuildSession(_group, utxosJson, sendTo, amountBtc, changeAddr, changeSequence, feeBtc, sendAll, signersJson, networkType);
		}

		// What a session pays (read from its transaction), its id, its signers and whether I am one of them.
		public string DescribeSession(string sessionJson, string myReceivingExtPubKey, string myChangeExtPubKey,
			string networkType)
		{
			return MuSig2GroupSpend.DescribeSession(_group, sessionJson, myReceivingExtPubKey, myChangeExtPubKey, networkType);
		}

		// Round 1, no password: my public nonces; the secret ones stay in this process.
		public string CreateNonces(string sessionJson, string myReceivingExtPubKey, string myChangeExtPubKey,
			string networkType)
		{
			return MuSig2GroupSpend.CreateNonces(_group, sessionJson, myReceivingExtPubKey, myChangeExtPubKey, networkType);
		}

		// Round 2: my partial signatures (uses and wipes my secret nonces).
		public string Sign(string sessionJson, string publicNoncesJson, string receivingExtPrivKey,
			string changeExtPrivKey, string networkType)
		{
			return MuSig2GroupSpend.Sign(_group, sessionJson, publicNoncesJson, receivingExtPrivKey, changeExtPrivKey, networkType);
		}

		// Anybody: checks every partial signature and returns the signed transaction.
		public string Finalize(string sessionJson, string publicNoncesJson, string partialSignaturesJson,
			string networkType)
		{
			return MuSig2GroupSpend.Finalize(_group, sessionJson, publicNoncesJson, partialSignaturesJson, networkType);
		}

		// Checks the coins of a session against the previous transactions ({"txid": "raw hex"}) read from the network.
		public string VerifyCoins(string sessionJson, string prevTxsJson, string networkType)
		{
			return MuSig2GroupSpend.VerifyCoins(_group, sessionJson, prevTxsJson, networkType);
		}

		// Wipes the secret nonces of a session in this app.
		public string Abort(string sessionId)
		{
			return MuSig2GroupSpend.Abort(sessionId);
		}
	}
}
