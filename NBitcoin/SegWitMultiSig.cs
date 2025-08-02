using System;
using System.Collections.Generic;
using System.Linq;

namespace NBitcoin
{
    /// <summary>
    /// SegWitMultiSig - Simple wrapper around standard SegWit P2SH-P2WSH multisig
    /// Uses standard OP_CHECKMULTISIG for ≤16 participants
    /// No owner concept - pure k-of-n multisig where any k signers can spend
    /// </summary>
    public class SegWitMultiSig
    {
        private readonly List<PubKey> _signerPubKeys;
        private readonly int _requiredSignatures;
        private readonly Network _network;
        private readonly Script _multisigScript;
        private readonly Script _p2wsh;
        private readonly Script _p2shP2wsh;
        private readonly BitcoinAddress _address;

        public IReadOnlyList<PubKey> SignerPubKeys => _signerPubKeys.AsReadOnly();
        public int RequiredSignatures => _requiredSignatures;
        public Network Network => _network;
        public BitcoinAddress Address => _address;
        public Script MultisigScript => _multisigScript;
        public Script P2WSH => _p2wsh;
        public Script P2SH_P2WSH => _p2shP2wsh;

        public SegWitMultiSig(IEnumerable<PubKey> signerPubKeys, int requiredSignatures, Network network)
        {
            _signerPubKeys = signerPubKeys?.ToList() ?? throw new ArgumentNullException(nameof(signerPubKeys));
            _requiredSignatures = requiredSignatures;
            _network = network ?? throw new ArgumentNullException(nameof(network));

            if (_requiredSignatures <= 0 || _requiredSignatures > _signerPubKeys.Count)
                throw new ArgumentException("Invalid required signatures count");

            if (_signerPubKeys.Count < 2)
                throw new ArgumentException("At least 2 signers required");

            if (_signerPubKeys.Count > 16)
                throw new ArgumentException("Maximum 16 signers supported (OP_CHECKMULTISIG limit)");

            // Generate standard multisig script using OP_CHECKMULTISIG
            _multisigScript = PayToMultiSigTemplate.Instance.GenerateScriptPubKey(_requiredSignatures, _signerPubKeys.ToArray());
            _p2wsh = _multisigScript.WitHash.ScriptPubKey;
            _p2shP2wsh = _p2wsh.Hash.ScriptPubKey;
            _address = _p2shP2wsh.GetDestinationAddress(_network);
        }

        /// <summary>
        /// Create a ScriptCoin for spending from this multisig
        /// </summary>
        /// <param name="outpoint">The outpoint to spend</param>
        /// <param name="txOut">The transaction output</param>
        /// <returns>A ScriptCoin that can be used with TransactionBuilder</returns>
        public ScriptCoin CreateCoin(OutPoint outpoint, TxOut txOut)
        {
            return new ScriptCoin(outpoint, txOut, _multisigScript);
        }

        /// <summary>
        /// Create a ScriptCoin for spending from this multisig
        /// </summary>
        /// <param name="coin">The base coin</param>
        /// <returns>A ScriptCoin that can be used with TransactionBuilder</returns>
        public ScriptCoin CreateCoin(Coin coin)
        {
            return new ScriptCoin(coin.Outpoint, coin.TxOut, _multisigScript);
        }

        /// <summary>
        /// Estimate the virtual size of a transaction spending from this multisig
        /// </summary>
        /// <param name="inputCount">Number of inputs</param>
        /// <param name="outputCount">Number of outputs</param>
        /// <returns>Estimated virtual size in bytes</returns>
        public int EstimateVirtualSize(int inputCount = 1, int outputCount = 2)
        {
            // Base transaction size
            var baseTxSize = 10; // version + input_count + output_count + locktime
            baseTxSize += inputCount * 41; // per input: outpoint(36) + script_sig_len(1) + sequence(4)
            baseTxSize += outputCount * 34; // per output: value(8) + script_pubkey_len(1) + script_pubkey(25)
            
            // Witness size for P2SH-P2WSH multisig
            var witnessSize = inputCount * (
                1 + // witness stack count
                1 + // OP_0 for multisig bug
                _requiredSignatures * (1 + 72) + // k signatures (1 byte len + ~72 bytes sig)
                1 + _multisigScript.Length // script length + script
            );
            
            // Calculate virtual size using witness discount
            var virtualSize = baseTxSize + (witnessSize + 3) / 4;
            
            return virtualSize;
        }
    }
}