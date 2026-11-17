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

		// The owner of a Delegated MultiSig 2 whose keys are on Ruby spends alone: Ruby signs by the key path.
		// receivingExtPubKey / changeExtPubKey: the chain keys the owner gave the group (Ruby's m/86'/coin'/0'/2 and /3).
		public string OwnerSpendWithRuby(string utxosJson, string sendTo, string amountBtc, string changeAddr,
			string feeBtc, bool sendAll, string device, string receivingExtPubKey, string changeExtPubKey,
			string networkType)
		{
			return MuSig2GroupSpend.OwnerSpendWithRuby(_group, utxosJson, sendTo, amountBtc, changeAddr, feeBtc, sendAll, device, receivingExtPubKey, changeExtPubKey, networkType);
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

		// Round 1 with a Ruby wallet (no screen): Ruby makes my nonces and keeps the secret ones; the public ones are
		// returned as CreateNonces returns them. myReceivingExtPubKey / myChangeExtPubKey: Ruby's chain keys in the group.
		public string CreateNoncesWithRuby(string sessionJson, string device, string myReceivingExtPubKey,
			string myChangeExtPubKey, string networkType)
		{
			return MuSig2GroupSpend.CreateNoncesWithRuby(_group, sessionJson, device, myReceivingExtPubKey, myChangeExtPubKey, networkType);
		}

		// A Ruby wallet opens a room or presses I'm here: the group registered on Ruby before the room's 3 minutes
		// ({"success", "error", "status"}); also checks that Ruby is connected, unlocked and holds my keys.
		public string RegisterGroupWithRuby(string device, string myReceivingExtPubKey, string myChangeExtPubKey,
			string networkType)
		{
			return MuSig2GroupSpend.RegisterGroupWithRuby(_group, device, myReceivingExtPubKey, myChangeExtPubKey, networkType);
		}

		// Round 2 with a Ruby wallet: Ruby shows the payment and makes my partial signatures (as Sign returns them).
		public string SignWithRuby(string sessionJson, string publicNoncesJson, string device, string myReceivingExtPubKey,
			string myChangeExtPubKey, string networkType)
		{
			return MuSig2GroupSpend.SignWithRuby(_group, sessionJson, publicNoncesJson, device, myReceivingExtPubKey, myChangeExtPubKey, networkType);
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
