#if HAS_SPAN
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NBitcoin;
using NBitcoin.DataEncoders;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace DelegatedMultiSigLib
{
    /// <summary>
    /// GeneXus-friendly static wrapper for NBitcoin.DelegatedMultiSig.
    /// All public methods use simple types (string, int, bool) for External Object compatibility.
    /// Supports multi-input transactions where each input has different derived keys.
    ///
    /// DUAL-TRANSACTION WORKFLOW (v4):
    /// ===============================
    /// When bufferPercentage > 0 and fee > 0, the library builds TWO transactions:
    ///   - Base: exact fee calculated from virtual size
    ///   - Buffered: fee increased by bufferPercentage% for higher priority
    /// Each signer signs BOTH transactions. The last signer chooses which to broadcast.
    ///
    /// First signer: picks bufferPercentage (e.g. 15%). Fee is auto-calculated.
    /// Subsequent signers: sign both tracks automatically.
    /// Last signer: chooses base (cheapest) or buffered (higher priority) to broadcast.
    /// </summary>
    public class MultiSigService
    {
        private static string _lastError = "";

        public static string GetLastError() => _lastError;

        // ─── Address Creation ───────────────────────────────────────────

        /// <summary>
        /// Creates a Taproot multisig address from individual EC public keys.
        /// signerPubKeysJson: JSON array of hex pub keys (non-owner signers only)
        /// </summary>
        public static string CreateAddress(string ownerPubKeyHex, string signerPubKeysJson,
            int requiredSignatures, string networkType)
        {
            try
            {
                _lastError = "";
                var network = ParseNetwork(networkType);
                var ownerPubKey = new PubKey(ownerPubKeyHex);
                var signerPubKeys = ParsePubKeyArray(signerPubKeysJson);
                return DelegatedMultiSig.CreateAddress(ownerPubKey, signerPubKeys,
                    requiredSignatures, network).ToString();
            }
            catch (Exception ex) { _lastError = ex.Message; return ""; }
        }

        /// <summary>
        /// Creates a Taproot multisig address from extended public keys at a derivation index.
        /// signerExtPubKeysJson: JSON array of extended pub key strings (non-owner signers only)
        /// </summary>
        public static string CreateAddressFromExtPubKeys(string ownerExtPubKeyStr,
            string signerExtPubKeysJson, int derivationIndex, int requiredSignatures,
            string networkType)
        {
            try
            {
                _lastError = "";
                var network = ParseNetwork(networkType);
                var ownerExtPubKey = ExtPubKey.Parse(ownerExtPubKeyStr, network);
                var signerExtPubKeys = ParseExtPubKeyArray(signerExtPubKeysJson, network);
                return DelegatedMultiSig.CreateAddress(ownerExtPubKey, (uint)derivationIndex,
                    signerExtPubKeys, (uint)derivationIndex, requiredSignatures, network).ToString();
            }
            catch (Exception ex) { _lastError = ex.Message; return ""; }
        }

        // ─── Build & Sign ───────────────────────────────────────────────

        /// <summary>
        /// Builds a transaction from UTXOs and signs with the provided private keys.
        /// Each input can have different pub keys (different derivation indices).
        ///
        /// DUAL-TRANSACTION MODE (v4):
        /// When bufferPercentage > 0 and feeBtc > 0, builds and signs TWO transactions:
        ///   - Base transaction with feeBtc
        ///   - Buffered transaction with feeBtc * (1 + bufferPercentage/100)
        /// Both are serialized together. The last signer chooses which to broadcast.
        ///
        /// inputsJson: [{"txid":"hex","vout":N,"rawTxHex":"hex",
        ///               "ownerPubKeyHex":"hex","signerPubKeys":["hex",...],
        ///               "signerPrivKeyHex":"hex"}]
        ///
        /// For fee estimation only, omit or leave empty "signerPrivKeyHex" in each input.
        ///
        /// sendAmountBtc/feeBtc: decimal BTC values as strings (e.g. "0.001")
        ///
        /// Returns JSON: {"success":bool,"serializedData":"base64",
        ///   "hexTransaction":"hex","hexTransactionBuffered":"hex",
        ///   "isComplete":bool,"virtualSize":N,"virtualSizeWithBuffer":N,
        ///   "bufferPercentage":N,"baseFee":N,"bufferedFee":N,"error":"msg"}
        /// </summary>
        public static string BuildAndSignTransaction(string inputsJson, string sendToAddress,
            string sendAmountBtc, string changeAddress, string feeBtc, bool sendAll,
            bool isOwner, int requiredSignatures, string networkType,
            double bufferPercentage = 5.0)
        {
            try
            {
                _lastError = "";
                var network = ParseNetwork(networkType);
                var inputs = JArray.Parse(inputsJson);

                // ─── Parse inputs and build coins ───
                var perInputInfo = new JArray();
                long totalInputSatoshis = 0;
                var allCoins = new List<Coin>();
                var outpoints = new List<OutPoint>();

                foreach (var inp in inputs)
                {
                    var txid = uint256.Parse(inp["txid"]!.ToString());
                    var vout = (uint)inp["vout"]!;
                    var rawHex = inp["rawTxHex"]!.ToString();
                    var prevTx = Transaction.Parse(rawHex, network);
                    var txOut = prevTx.Outputs[(int)vout];
                    totalInputSatoshis += txOut.Value.Satoshi;

                    var outpoint = new OutPoint(txid, vout);
                    outpoints.Add(outpoint);
                    allCoins.Add(new Coin(outpoint, txOut));

                    perInputInfo.Add(new JObject
                    {
                        ["ownerPubKey"] = inp["ownerPubKeyHex"]!.ToString(),
                        ["signerPubKeys"] = (JArray)inp["signerPubKeys"]!,
                        ["satoshis"] = txOut.Value.Satoshi,
                        ["scriptPubKey"] = txOut.ScriptPubKey.ToHex()
                    });
                }

                // ─── Calculate fees ───
                var baseFee = Money.Coins(decimal.Parse(feeBtc));
                var sendAmount = string.IsNullOrEmpty(sendAmountBtc) || sendAll
                    ? Money.Zero : Money.Coins(decimal.Parse(sendAmountBtc));
                var dest = BitcoinAddress.Create(sendToAddress, network);
                var coinsArray = allCoins.ToArray();

                // ─── Build BASE transaction ───
                var baseTx = BuildTxWithOutputs(network, outpoints, sendAmount, baseFee,
                    totalInputSatoshis, dest, changeAddress, sendAll);

                // ─── Build BUFFERED transaction (if buffer > 0 and fee > 0) ───
                bool hasDualTx = bufferPercentage > 0 && baseFee > Money.Zero;
                Transaction bufferedTx = null;
                var bufferedFee = baseFee;

                if (hasDualTx)
                {
                    bufferedFee = Money.Satoshis((long)Math.Ceiling(
                        baseFee.Satoshi * (1.0 + bufferPercentage / 100.0)));

                    try
                    {
                        bufferedTx = BuildTxWithOutputs(network, outpoints, sendAmount,
                            bufferedFee, totalInputSatoshis, dest, changeAddress, sendAll);
                    }
                    catch
                    {
                        // Insufficient funds for buffered fee - fall back to single track
                        hasDualTx = false;
                        bufferedFee = baseFee;
                    }
                }

                // ─── Sign BASE transaction ───
                var (baseSigs, baseComplete, baseVSize) = SignTransactionInputs(
                    baseTx, inputs, coinsArray, isOwner, requiredSignatures, network);

                // ─── Sign BUFFERED transaction ───
                var bufferedSigs = new JArray();
                bool bufferedComplete = false;

                if (hasDualTx && bufferedTx != null)
                {
                    (bufferedSigs, bufferedComplete, _) = SignTransactionInputs(
                        bufferedTx, inputs, coinsArray, isOwner, requiredSignatures, network);
                }

                if (isOwner && baseComplete)
                    baseVSize = baseTx.GetVirtualSize();

                int maxVirtualSizeWithBuffer = hasDualTx
                    ? (int)(baseVSize * (1.0 + bufferPercentage / 100.0))
                    : baseVSize;

                // ─── Serialize state (v4 with dual tracks) ───
                var state = new JObject
                {
                    ["v"] = 4,
                    ["net"] = networkType,
                    ["requiredSigs"] = requiredSignatures,
                    ["txHex"] = baseTx.ToHex(),
                    ["inputs"] = perInputInfo,
                    ["sigs"] = baseSigs,
                    ["isKeySpend"] = isOwner,
                    ["isComplete"] = baseComplete,
                    ["bufferPercentage"] = bufferPercentage,
                    ["virtualSize"] = baseVSize,
                    ["virtualSizeWithBuffer"] = maxVirtualSizeWithBuffer,
                    ["baseFeeSat"] = baseFee.Satoshi,
                    ["bufferedFeeSat"] = bufferedFee.Satoshi
                };

                if (hasDualTx && bufferedTx != null)
                {
                    state["txHexBuffered"] = bufferedTx.ToHex();
                    state["sigsBuffered"] = bufferedSigs;
                }

                var serialized = Convert.ToBase64String(
                    Encoding.UTF8.GetBytes(state.ToString(Formatting.None)));

                return new JObject
                {
                    ["success"] = true,
                    ["serializedData"] = serialized,
                    ["hexTransaction"] = baseTx.ToHex(),
                    ["hexTransactionBuffered"] = hasDualTx && bufferedTx != null ? bufferedTx.ToHex() : "",
                    ["isComplete"] = baseComplete,
                    ["virtualSize"] = baseVSize,
                    ["virtualSizeWithBuffer"] = maxVirtualSizeWithBuffer,
                    ["bufferPercentage"] = bufferPercentage,
                    ["baseFeeSat"] = baseFee.Satoshi,
                    ["bufferedFeeSat"] = bufferedFee.Satoshi,
                    ["error"] = ""
                }.ToString(Formatting.None);
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                return new JObject
                {
                    ["success"] = false, ["serializedData"] = "",
                    ["hexTransaction"] = "", ["hexTransactionBuffered"] = "",
                    ["isComplete"] = false,
                    ["virtualSize"] = 0, ["virtualSizeWithBuffer"] = 0,
                    ["bufferPercentage"] = 0,
                    ["baseFeeSat"] = 0, ["bufferedFeeSat"] = 0,
                    ["error"] = ex.Message
                }.ToString(Formatting.None);
            }
        }

        /// <summary>
        /// Adds signatures from an additional signer to the serialized state.
        /// Signs BOTH base and buffered transactions when dual-track state (v4).
        /// signerPrivKeysJson: JSON array of hex private keys, one per input (same order as inputs).
        ///
        /// Returns JSON: {"success":bool,"serializedData":"base64",
        ///   "hexTransaction":"hex","hexTransactionBuffered":"hex",
        ///   "isComplete":bool,"virtualSize":N,"virtualSizeWithBuffer":N,
        ///   "bufferPercentage":N,"baseFeeSat":N,"bufferedFeeSat":N,"error":"msg"}
        /// </summary>
        public static string AddSignature(string serializedMultiSigState, string signerPrivKeysJson)
        {
            try
            {
                _lastError = "";
                var raw = DeserializeState(serializedMultiSigState);
                var network = ParseNetwork(raw.NetworkType);
                var privKeys = JArray.Parse(signerPrivKeysJson)
                    .Select(k => k.ToString()).ToArray();

                if (privKeys.Length != raw.Inputs.Count)
                    throw new ArgumentException(
                        $"Expected {raw.Inputs.Count} private keys, got {privKeys.Length}");

                // ─── Sign BASE track ───
                var (baseSigs, baseComplete, baseVSize, baseTx) = SignOneTrack(
                    raw.TxHex, raw.Signatures, raw.Inputs, privKeys,
                    raw.RequiredSigs, network, baseComplete: false);

                // ─── Sign BUFFERED track (if present) ───
                JArray bufferedSigs = new JArray();
                bool bufferedComplete = false;
                Transaction bufferedTx = null;
                bool hasDualTx = !string.IsNullOrEmpty(raw.TxHexBuffered);

                if (hasDualTx)
                {
                    (bufferedSigs, bufferedComplete, _, bufferedTx) = SignOneTrack(
                        raw.TxHexBuffered, raw.SignaturesBuffered, raw.Inputs, privKeys,
                        raw.RequiredSigs, network, baseComplete: false);
                }

                if (baseComplete)
                    baseVSize = baseTx.GetVirtualSize();

                int maxVSizeWithBuffer = hasDualTx
                    ? (int)(baseVSize * (1.0 + raw.BufferPercentage / 100.0))
                    : baseVSize;

                // ─── Build updated state ───
                var state = new JObject
                {
                    ["v"] = 4,
                    ["net"] = raw.NetworkType,
                    ["requiredSigs"] = raw.RequiredSigs,
                    ["txHex"] = baseTx.ToHex(),
                    ["inputs"] = raw.Inputs,
                    ["sigs"] = baseSigs,
                    ["isKeySpend"] = false,
                    ["isComplete"] = baseComplete,
                    ["bufferPercentage"] = raw.BufferPercentage,
                    ["virtualSize"] = baseVSize,
                    ["virtualSizeWithBuffer"] = maxVSizeWithBuffer,
                    ["baseFeeSat"] = raw.BaseFeeSat,
                    ["bufferedFeeSat"] = raw.BufferedFeeSat
                };

                if (hasDualTx && bufferedTx != null)
                {
                    state["txHexBuffered"] = bufferedTx.ToHex();
                    state["sigsBuffered"] = bufferedSigs;
                }

                var serialized = Convert.ToBase64String(
                    Encoding.UTF8.GetBytes(state.ToString(Formatting.None)));

                return new JObject
                {
                    ["success"] = true,
                    ["serializedData"] = serialized,
                    ["hexTransaction"] = baseTx.ToHex(),
                    ["hexTransactionBuffered"] = hasDualTx && bufferedTx != null ? bufferedTx.ToHex() : "",
                    ["isComplete"] = baseComplete,
                    ["virtualSize"] = baseVSize,
                    ["virtualSizeWithBuffer"] = maxVSizeWithBuffer,
                    ["bufferPercentage"] = raw.BufferPercentage,
                    ["baseFeeSat"] = raw.BaseFeeSat,
                    ["bufferedFeeSat"] = raw.BufferedFeeSat,
                    ["error"] = ""
                }.ToString(Formatting.None);
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                return new JObject
                {
                    ["success"] = false, ["serializedData"] = serializedMultiSigState,
                    ["hexTransaction"] = "", ["hexTransactionBuffered"] = "",
                    ["isComplete"] = false,
                    ["virtualSize"] = 0, ["virtualSizeWithBuffer"] = 0,
                    ["bufferPercentage"] = 0,
                    ["baseFeeSat"] = 0, ["bufferedFeeSat"] = 0,
                    ["error"] = ex.Message
                }.ToString(Formatting.None);
            }
        }

        /// <summary>
        /// Finalizes a transaction when all required signatures have been collected.
        /// Returns JSON: {"success":bool,"hexTransaction":"hex","virtualSize":N,"error":"msg"}
        /// </summary>
        public static string FinalizeTransaction(string serializedMultiSigState)
        {
            try
            {
                _lastError = "";
                var raw = DeserializeState(serializedMultiSigState);
                var network = ParseNetwork(raw.NetworkType);
                var tx = Transaction.Parse(raw.TxHex, network);
                var allCoins = ReconstructCoins(raw.Inputs, network);

                for (int i = 0; i < raw.Inputs.Count; i++)
                {
                    var inputInfo = raw.Inputs[i];
                    var ownerPubKey = new PubKey(inputInfo["ownerPubKey"]!.ToString());
                    var signerPubKeys = ((JArray)inputInfo["signerPubKeys"]!)
                        .Select(k => new PubKey(k.ToString())).ToList();
                    var dms = new DelegatedMultiSig(ownerPubKey, signerPubKeys,
                        raw.RequiredSigs, network);
                    var builder = dms.CreateSignatureBuilder(tx, allCoins);

                    ReplaySignaturesForInput(builder, raw.Signatures, i, tx, network);
                    builder.FinalizeTransaction(i);
                }

                var finalVSize = tx.GetVirtualSize();
                return new JObject
                {
                    ["success"] = true,
                    ["hexTransaction"] = tx.ToHex(),
                    ["virtualSize"] = finalVSize,
                    ["virtualSizeWithBuffer"] = (int)(finalVSize * (1.0 + raw.BufferPercentage / 100.0)),
                    ["bufferPercentage"] = raw.BufferPercentage,
                    ["error"] = ""
                }.ToString(Formatting.None);
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                return new JObject
                {
                    ["success"] = false, ["hexTransaction"] = "",
                    ["virtualSize"] = 0, ["error"] = ex.Message
                }.ToString(Formatting.None);
            }
        }

        // ─── Query ──────────────────────────────────────────────────────

        public static bool IsComplete(string serializedMultiSigState)
        {
            try
            {
                var raw = DeserializeState(serializedMultiSigState);
                return raw.IsComplete;
            }
            catch { return false; }
        }

        public static int GetSignerCount(string serializedMultiSigState)
        {
            try
            {
                var raw = DeserializeState(serializedMultiSigState);
                return raw.Signatures
                    .Select(s => (int)s["signerIndex"]!)
                    .Distinct().Count();
            }
            catch { return 0; }
        }

        // ─── Internal: Build Transaction with Outputs ───────────────────

        private static Transaction BuildTxWithOutputs(Network network, List<OutPoint> outpoints,
            Money sendAmount, Money fee, long totalInputSatoshis,
            IDestination dest, string changeAddress, bool sendAll)
        {
            var tx = network.CreateTransaction();
            foreach (var op in outpoints)
                tx.Inputs.Add(op);

            if (sendAll)
            {
                var amount = Money.Satoshis(totalInputSatoshis) - fee;
                if (amount <= Money.Zero)
                    throw new InvalidOperationException("Insufficient funds: total inputs less than fee");
                tx.Outputs.Add(amount, dest);
            }
            else
            {
                tx.Outputs.Add(sendAmount, dest);
                var change = Money.Satoshis(totalInputSatoshis) - sendAmount - fee;
                if (change < Money.Zero)
                    throw new InvalidOperationException("Insufficient funds for transaction");
                if (change > Money.Zero)
                    tx.Outputs.Add(change, BitcoinAddress.Create(changeAddress, network));
            }
            return tx;
        }

        // ─── Internal: Sign All Inputs of a Transaction ─────────────────

        private static (JArray sigs, bool isComplete, int maxVSize) SignTransactionInputs(
            Transaction tx, JArray inputs, Coin[] coinsArray,
            bool isOwner, int requiredSignatures, Network network)
        {
            var sigs = new JArray();
            bool isComplete = false;
            int maxVirtualSize = 0;

            for (int i = 0; i < inputs.Count; i++)
            {
                var inp = inputs[i];
                var ownerPubKey = new PubKey(inp["ownerPubKeyHex"]!.ToString());
                var signerPubKeys = ((JArray)inp["signerPubKeys"]!)
                    .Select(k => new PubKey(k.ToString())).ToList();
                var dms = new DelegatedMultiSig(ownerPubKey, signerPubKeys,
                    requiredSignatures, network);
                var builder = dms.CreateSignatureBuilder(tx, coinsArray);

                var privKeyHex = inp["signerPrivKeyHex"]?.ToString() ?? "";

                if (isOwner && !string.IsNullOrEmpty(privKeyHex))
                {
                    var ownerKey = new Key(Encoders.Hex.DecodeData(privKeyHex));
                    builder.SignWithOwner(ownerKey, i);
                    isComplete = true;
                }
                else if (!string.IsNullOrEmpty(privKeyHex))
                {
                    var signerKey = new Key(Encoders.Hex.DecodeData(privKeyHex));
                    var partial = builder.SignWithSigner(signerKey, i);
                    if (partial.PartialSignatures != null)
                    {
                        foreach (var ps in partial.PartialSignatures)
                        {
                            sigs.Add(new JObject
                            {
                                ["inputIndex"] = i,
                                ["signerIndex"] = ps.SignerIndex,
                                ["signatureHex"] = Encoders.Hex.EncodeData(ps.Signature.ToBytes()),
                                ["scriptIndex"] = ps.ScriptIndex,
                                ["vSize"] = ps.EstimatedVirtualSize
                            });
                        }
                    }
                    isComplete = partial.IsComplete;
                }

                if (!isOwner)
                {
                    var est = builder.GetSizeEstimate(i);
                    if (est != null)
                    {
                        var maxScript = est.ScriptSpendVirtualSizes.Values.DefaultIfEmpty(0).Max();
                        if (maxScript > maxVirtualSize) maxVirtualSize = maxScript;
                    }
                }
            }

            return (sigs, isComplete, maxVirtualSize);
        }

        // ─── Internal: Sign One Track (for AddSignature) ────────────────

        private static (JArray updatedSigs, bool isComplete, int maxVSize, Transaction tx)
            SignOneTrack(string txHex, JArray existingSigs, JArray inputs,
                string[] privKeys, int requiredSigs, Network network, bool baseComplete)
        {
            var tx = Transaction.Parse(txHex, network);
            var allCoins = ReconstructCoins(inputs, network);
            var newSigs = new JArray(existingSigs.ToArray()); // clone existing
            bool isComplete = false;
            int maxVirtualSize = 0;

            for (int i = 0; i < inputs.Count; i++)
            {
                var inputInfo = inputs[i];
                var ownerPubKey = new PubKey(inputInfo["ownerPubKey"]!.ToString());
                var signerPubKeys = ((JArray)inputInfo["signerPubKeys"]!)
                    .Select(k => new PubKey(k.ToString())).ToList();
                var dms = new DelegatedMultiSig(ownerPubKey, signerPubKeys,
                    requiredSigs, network);
                var builder = dms.CreateSignatureBuilder(tx, allCoins);

                // Replay existing signatures for this input
                ReplaySignaturesForInput(builder, existingSigs, i, tx, network);

                // Add new signer's signature
                var signerKey = new Key(Encoders.Hex.DecodeData(privKeys[i]));
                var partial = builder.SignWithSigner(signerKey, i);
                if (partial.PartialSignatures != null)
                {
                    foreach (var ps in partial.PartialSignatures)
                    {
                        var exists = newSigs.Any(s =>
                            (int)s["inputIndex"]! == i &&
                            (int)s["signerIndex"]! == ps.SignerIndex &&
                            (int)s["scriptIndex"]! == ps.ScriptIndex);
                        if (!exists)
                        {
                            newSigs.Add(new JObject
                            {
                                ["inputIndex"] = i,
                                ["signerIndex"] = ps.SignerIndex,
                                ["signatureHex"] = Encoders.Hex.EncodeData(ps.Signature.ToBytes()),
                                ["scriptIndex"] = ps.ScriptIndex,
                                ["vSize"] = ps.EstimatedVirtualSize
                            });
                        }
                    }
                }
                isComplete = partial.IsComplete;

                // If complete, finalize this input
                if (isComplete)
                {
                    try { builder.FinalizeTransaction(i); }
                    catch { /* non-fatal, signature state still valid */ }
                }

                var est = builder.GetSizeEstimate(i);
                if (est != null)
                {
                    var maxScript = est.ScriptSpendVirtualSizes.Values.DefaultIfEmpty(0).Max();
                    if (maxScript > maxVirtualSize) maxVirtualSize = maxScript;
                }
            }

            if (isComplete)
                maxVirtualSize = tx.GetVirtualSize();

            return (newSigs, isComplete, maxVirtualSize, tx);
        }

        // ─── Internal State ─────────────────────────────────────────────

        private class RawState
        {
            public string NetworkType { get; set; } = "";
            public int RequiredSigs { get; set; }
            public string TxHex { get; set; } = "";
            public string TxHexBuffered { get; set; } = "";
            public JArray Inputs { get; set; } = new();
            public JArray Signatures { get; set; } = new();
            public JArray SignaturesBuffered { get; set; } = new();
            public bool IsKeySpend { get; set; }
            public bool IsComplete { get; set; }
            public double BufferPercentage { get; set; }
            public int VirtualSize { get; set; }
            public int VirtualSizeWithBuffer { get; set; }
            public long BaseFeeSat { get; set; }
            public long BufferedFeeSat { get; set; }
        }

        private static RawState DeserializeState(string serialized)
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(serialized));
            var j = JObject.Parse(json);
            var version = (int)(j["v"] ?? 3);

            var state = new RawState
            {
                NetworkType = j["net"]!.ToString(),
                RequiredSigs = (int)j["requiredSigs"]!,
                TxHex = j["txHex"]!.ToString(),
                Inputs = (JArray)j["inputs"]!,
                Signatures = (JArray)j["sigs"]!,
                IsKeySpend = (bool)(j["isKeySpend"] ?? false),
                IsComplete = (bool)(j["isComplete"] ?? false),
                BufferPercentage = (double)(j["bufferPercentage"] ?? 5.0),
                VirtualSize = (int)(j["virtualSize"] ?? 0),
                VirtualSizeWithBuffer = (int)(j["virtualSizeWithBuffer"] ?? 0)
            };

            // v4 dual-track fields
            if (version >= 4)
            {
                state.TxHexBuffered = j["txHexBuffered"]?.ToString() ?? "";
                state.SignaturesBuffered = (JArray)(j["sigsBuffered"] ?? new JArray());
                state.BaseFeeSat = (long)(j["baseFeeSat"] ?? 0);
                state.BufferedFeeSat = (long)(j["bufferedFeeSat"] ?? 0);
            }
            else
            {
                // v3 backward compatibility
                state.TxHexBuffered = "";
                state.SignaturesBuffered = new JArray();
                state.BaseFeeSat = 0;
                state.BufferedFeeSat = 0;
            }

            return state;
        }

        private static Coin[] ReconstructCoins(JArray inputs, Network network)
        {
            var coins = new List<Coin>();
            foreach (var inp in inputs)
            {
                var amount = Money.Satoshis((long)inp["satoshis"]!);
                var spk = Script.FromHex(inp["scriptPubKey"]!.ToString());
                coins.Add(new Coin(new OutPoint(uint256.Zero, 0), new TxOut(amount, spk)));
            }
            return coins.ToArray();
        }

        private static void ReplaySignaturesForInput(DelegatedMultiSig.DelegatedMultiSigSignatureBuilder builder,
            JArray signatures, int inputIndex, Transaction tx, Network network)
        {
            var inputSigs = signatures.Where(s => (int)s["inputIndex"]! == inputIndex);
            var partialSigs = new List<DelegatedMultiSig.PartialSignature>();
            foreach (var sig in inputSigs)
            {
                var sigBytes = Encoders.Hex.DecodeData(sig["signatureHex"]!.ToString());
                partialSigs.Add(new DelegatedMultiSig.PartialSignature
                {
                    SignerIndex = (int)sig["signerIndex"]!,
                    Signature = new TaprootSignature(new NBitcoin.Crypto.SchnorrSignature(sigBytes)),
                    ScriptIndex = (int)sig["scriptIndex"]!,
                    EstimatedVirtualSize = sig["vSize"] != null ? (int)sig["vSize"] : 0
                });
            }

            if (partialSigs.Count > 0)
            {
                var psd = new DelegatedMultiSig.PartialSignatureData
                {
                    Transaction = tx,
                    InputIndex = inputIndex,
                    ScriptIndex = -1,
                    PartialSignatures = partialSigs,
                    IsComplete = false,
                    IsKeySpend = false
                };
                builder.AddPartialSignature(psd, inputIndex);
            }
        }

        // ─── Result Parsing (for GeneXus) ───────────────────────────────

        public static bool GetResultSuccess(string resultJson)
        {
            try { return (bool)JObject.Parse(resultJson)["success"]!; }
            catch { return false; }
        }

        public static string GetResultSerializedData(string resultJson)
        {
            try { return JObject.Parse(resultJson)["serializedData"]?.ToString() ?? ""; }
            catch { return ""; }
        }

        public static string GetResultHexTransaction(string resultJson)
        {
            try { return JObject.Parse(resultJson)["hexTransaction"]?.ToString() ?? ""; }
            catch { return ""; }
        }

        /// <summary>
        /// Returns the hex of the buffered transaction (higher fee).
        /// Empty string if no buffered transaction exists.
        /// </summary>
        public static string GetResultHexTransactionBuffered(string resultJson)
        {
            try { return JObject.Parse(resultJson)["hexTransactionBuffered"]?.ToString() ?? ""; }
            catch { return ""; }
        }

        public static bool GetResultIsComplete(string resultJson)
        {
            try { return (bool)(JObject.Parse(resultJson)["isComplete"] ?? false); }
            catch { return false; }
        }

        public static int GetResultVirtualSize(string resultJson)
        {
            try { return (int)(JObject.Parse(resultJson)["virtualSize"] ?? 0); }
            catch { return 0; }
        }

        public static int GetResultVirtualSizeWithBuffer(string resultJson)
        {
            try { return (int)(JObject.Parse(resultJson)["virtualSizeWithBuffer"] ?? 0); }
            catch { return 0; }
        }

        public static double GetResultBufferPercentage(string resultJson)
        {
            try { return (double)(JObject.Parse(resultJson)["bufferPercentage"] ?? 0.0); }
            catch { return 0.0; }
        }

        /// <summary>
        /// Returns the base fee in BTC (as a double with 8 decimal precision).
        /// This is the cheapest fee based on exact virtual size.
        /// </summary>
        public static double GetResultBaseFee(string resultJson)
        {
            try
            {
                var sat = (long)(JObject.Parse(resultJson)["baseFeeSat"] ?? 0);
                return (double)sat / 100_000_000.0;
            }
            catch { return 0.0; }
        }

        /// <summary>
        /// Returns the buffered fee in BTC (as a double with 8 decimal precision).
        /// This is the fee with buffer percentage applied for higher priority.
        /// </summary>
        public static double GetResultBufferedFee(string resultJson)
        {
            try
            {
                var sat = (long)(JObject.Parse(resultJson)["bufferedFeeSat"] ?? 0);
                return (double)sat / 100_000_000.0;
            }
            catch { return 0.0; }
        }

        public static string GetResultError(string resultJson)
        {
            try { return JObject.Parse(resultJson)["error"]?.ToString() ?? ""; }
            catch { return ""; }
        }

        // ─── Parsing Helpers ────────────────────────────────────────────

        private static Network ParseNetwork(string networkType)
        {
            return networkType.ToLower() switch
            {
                "mainnet" or "main" => Network.Main,
                "testnet" or "test" => Network.TestNet,
                "regtest" => Network.RegTest,
                _ => throw new ArgumentException($"Unknown network: {networkType}")
            };
        }

        private static List<PubKey> ParsePubKeyArray(string json)
        {
            return JArray.Parse(json).Select(k => new PubKey(k.ToString())).ToList();
        }

        private static List<ExtPubKey> ParseExtPubKeyArray(string json, Network network)
        {
            return JArray.Parse(json).Select(k => ExtPubKey.Parse(k.ToString(), network)).ToList();
        }
    }
}
#endif
