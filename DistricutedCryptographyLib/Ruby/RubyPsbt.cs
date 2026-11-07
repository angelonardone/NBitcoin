using NBitcoin;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// PSBT helpers for Ruby. Ruby signs an input only when the PSBT says which of its keys it is: the master
	/// fingerprint and the BIP32 path (for taproot, PSBT_IN_TAP_BIP32_DERIVATION + the internal key). The same data
	/// on an output tells Ruby it is our change (verified on the device and not shown as a payment).
	/// </summary>
	public static class RubyPsbt
	{
		/// <summary>
		/// Adds the BIP86 (taproot key path) derivation of one key to every input and output of the PSBT whose
		/// scriptPubKey is that key's address. Returns how many inputs / outputs were marked.
		/// </summary>
		public static int AddBip86KeyPath(PSBT psbt, PubKey pubKey, RootedKeyPath rootedKeyPath)
		{
			var internalKey = pubKey.TaprootInternalKey;
			var script = pubKey.GetScriptPubKey(ScriptPubKeyType.TaprootBIP86);
			var xonly = new TaprootPubKey(internalKey.ToBytes());
			var count = 0;
			foreach (var coin in psbt.Inputs.Cast<PSBTCoin>().Concat(psbt.Outputs))
			{
				if (coin.GetTxOut()?.ScriptPubKey != script)
					continue;
				coin.TaprootInternalKey = internalKey;
				coin.HDTaprootKeyPaths[xonly] = new TaprootKeyPath(rootedKeyPath);
				count++;
			}
			return count;
		}

		/// <summary>
		/// Marks the inputs and outputs that pay to addresses of a BIP86 account: account/chain/index for the chains
		/// 0 (receive) and 1 (change) and the indexes below `scanLimit`.
		/// </summary>
		public static int AddBip86AccountKeyPaths(PSBT psbt, ExtPubKey accountXpub, HDFingerprint masterFingerprint,
			KeyPath accountPath, int scanLimit)
		{
			var wanted = psbt.Inputs.Cast<PSBTCoin>().Concat(psbt.Outputs)
				.Select(c => c.GetTxOut()?.ScriptPubKey).Where(s => s != null).ToHashSet();
			var count = 0;
			for (uint chain = 0; chain <= 1; chain++)
			{
				var chainKey = accountXpub.Derive(chain);
				for (uint i = 0; i < scanLimit; i++)
				{
					var pub = chainKey.Derive(i).PubKey;
					if (!wanted.Contains(pub.GetScriptPubKey(ScriptPubKeyType.TaprootBIP86)))
						continue;
					count += AddBip86KeyPath(psbt, pub,
						new RootedKeyPath(masterFingerprint, accountPath.Derive(chain).Derive(i)));
				}
			}
			return count;
		}
	}
}
