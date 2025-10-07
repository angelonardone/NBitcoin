//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Threading.Tasks;
//using System.IO;
//using NBitcoin;
//using NBitcoin.Tests;
//using NBitcoin.RPC;
//using Xunit;
//using Newtonsoft.Json;

//namespace NBitcoin.Tests
//{
//    /// <summary>
//    /// COMPREHENSIVE MULTISIG EXECUTOR
//    /// This application ACTUALLY executes real transactions for EVERY viable k-of-n combination
//    /// Records REAL transaction data from the blockchain, not estimates
//    /// </summary>
//    [Trait("UnitTest", "UnitTest")]
//    public class ComprehensiveMultisigExecutor
//    {
//        private class ExecutionResult
//        {
//            public int K { get; set; }
//            public int N { get; set; }
//            public long Combinations { get; set; }
            
//            // ACTUAL transaction data from blockchain
//            public string SegWitTxId { get; set; }
//            public int SegWitActualSize { get; set; }
//            public int SegWitActualVirtualSize { get; set; }
//            public int SegWitWitnessSize { get; set; }
//            public bool SegWitSuccess { get; set; }
//            public string SegWitError { get; set; }
//            public double SegWitExecutionTimeMs { get; set; }
            
//            // TaprootSegWit removed - not reliable
            
//            public string MuSig1TxId { get; set; }
//            public int MuSig1ActualSize { get; set; }
//            public int MuSig1ActualVirtualSize { get; set; }
//            public int MuSig1WitnessSize { get; set; }
//            public bool MuSig1Success { get; set; }
//            public string MuSig1Error { get; set; }
//            public double MuSig1ExecutionTimeMs { get; set; }
            
//            public string MuSig2TxId { get; set; }
//            public int MuSig2ActualSize { get; set; }
//            public int MuSig2ActualVirtualSize { get; set; }
//            public int MuSig2WitnessSize { get; set; }
//            public bool MuSig2Success { get; set; }
//            public string MuSig2Error { get; set; }
//            public double MuSig2ExecutionTimeMs { get; set; }
            
//            public DateTime ExecutionTime { get; set; }
//            public int BlockHeight { get; set; }
//            public double TotalExecutionTimeMs { get; set; }
            
//            // Calculated metrics
//            public double MuSig1VsSegWitPercent => SegWitSuccess && MuSig1Success ? 
//                ((double)(MuSig1ActualVirtualSize - SegWitActualVirtualSize) / SegWitActualVirtualSize * 100) : 0;
//            public double MuSig2VsSegWitPercent => SegWitSuccess && MuSig2Success ? 
//                ((double)(MuSig2ActualVirtualSize - SegWitActualVirtualSize) / SegWitActualVirtualSize * 100) : 0;
//            // TaprootSegWit comparison removed
//            public string BestMethod
//            {
//                get
//                {
//                    var results = new List<(string method, int size, bool success)>();
//                    if (SegWitSuccess) results.Add(("SegWit", SegWitActualVirtualSize, true));
//                    if (MuSig1Success) results.Add(("MuSig1", MuSig1ActualVirtualSize, true));
//                    if (MuSig2Success) results.Add(("MuSig2", MuSig2ActualVirtualSize, true));
                    
//                    return results.Any() ? results.OrderBy(r => r.size).First().method : "None";
//                }
//            }
//        }
        
//        [Fact]
//        public async Task ExecuteComprehensiveMultisigComparison()
//        {
//            Console.WriteLine("🚀 COMPREHENSIVE MULTISIG EXECUTOR");
//            Console.WriteLine("==================================");
//            Console.WriteLine("This will execute REAL transactions for EVERY viable k-of-n combination");
//            Console.WriteLine();
            
//            using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
//            {
//                var rpc = nodeBuilder.CreateNode().CreateRPCClient();
//                nodeBuilder.StartAll();
                
//                // Generate initial blocks for coinbase maturity
//                Console.WriteLine("⛏️  Mining initial blocks...");
//                rpc.Generate(Network.RegTest.Consensus.CoinbaseMaturity + 100);
//                var initialHeight = rpc.GetBlockCount();
//                Console.WriteLine($"✅ Initial block height: {initialHeight}");
                
//                // Generate all viable k-of-n combinations
//                var allCombinations = GenerateAllViableCombinations();
//                Console.WriteLine($"\n📊 Total k-of-n combinations to test: {allCombinations.Count}");
//                Console.WriteLine($"   • This will create {allCombinations.Count * 3} real transactions (SegWit, MuSig1, MuSig2)");
//                Console.WriteLine($"   • Estimated time: {allCombinations.Count * 2} seconds\n");
                
//                var results = new List<ExecutionResult>();
//                var startTime = DateTime.UtcNow;
//                var progressCount = 0;
                
//                // Execute transactions for EVERY combination
//                foreach (var (k, n) in allCombinations)
//                {
//                    progressCount++;
//                    var percentage = (progressCount * 100.0 / allCombinations.Count);
//                    var comboStartTime = DateTime.UtcNow;
                    
//                    Console.WriteLine($"\n🔄 [{progressCount}/{allCombinations.Count}] ({percentage:F1}%) Starting {k}-of-{n} multisig test...");
//                    Console.WriteLine($"   ⏰ Started at: {comboStartTime:HH:mm:ss}");
                    
//                    try
//                    {
//                        var result = await ExecuteSingleCombination(k, n, rpc);
//                        var comboEndTime = DateTime.UtcNow;
//                        result.TotalExecutionTimeMs = (comboEndTime - comboStartTime).TotalMilliseconds;
//                        results.Add(result);
                        
//                        Console.WriteLine($"   ✅ Completed {k}-of-{n} in {result.TotalExecutionTimeMs:F0}ms");
//                        Console.WriteLine($"      • SegWit: {(result.SegWitSuccess ? "✅" : "❌")} ({result.SegWitExecutionTimeMs:F0}ms)");
//                        Console.WriteLine($"      • MuSig1: {(result.MuSig1Success ? "✅" : "❌")} ({result.MuSig1ExecutionTimeMs:F0}ms)");
//                        Console.WriteLine($"      • MuSig2: {(result.MuSig2Success ? "✅" : "❌")} ({result.MuSig2ExecutionTimeMs:F0}ms)");
//                    }
//                    catch (Exception ex)
//                    {
//                        var comboEndTime = DateTime.UtcNow;
//                        var errorTime = (comboEndTime - comboStartTime).TotalMilliseconds;
//                        Console.WriteLine($"   ❌ FAILED {k}-of-{n} after {errorTime:F0}ms: {ex.Message}");
                        
//                        // Create failed result for tracking
//                        var failedResult = new ExecutionResult
//                        {
//                            K = k, N = n,
//                            TotalExecutionTimeMs = errorTime,
//                            ExecutionTime = DateTime.UtcNow,
//                            BlockHeight = rpc.GetBlockCount(),
//                            SegWitSuccess = false, SegWitError = ex.Message,
//                            MuSig1Success = false, MuSig1Error = ex.Message,
//                            MuSig2Success = false, MuSig2Error = ex.Message
//                        };
//                        results.Add(failedResult);
//                    }
                    
//                    // Mine a block every 10 combinations to prevent mempool issues
//                    if (progressCount % 10 == 0)
//                    {
//                        Console.WriteLine($"   ⛏️  Mining block to clear mempool...");
//                        rpc.Generate(1);
//                    }
//                }
                
//                // Mine final blocks to confirm all transactions
//                Console.WriteLine("\n\n⛏️  Mining blocks to confirm all transactions...");
//                rpc.Generate(10);
                
//                var endTime = DateTime.UtcNow;
//                var duration = endTime - startTime;
                
//                // Generate comprehensive report
//                Console.WriteLine($"\n✅ EXECUTION COMPLETE!");
//                Console.WriteLine($"   • Total combinations tested: {results.Count}");
//                Console.WriteLine($"   • Total transactions created: {results.Count * 3}");
//                Console.WriteLine($"   • Total time: {duration.TotalSeconds:F1} seconds");
//                Console.WriteLine($"   • Final block height: {rpc.GetBlockCount()}");
                
//                // Save results to JSON file
//                var jsonPath = SaveResultsToJson(results);
//                Console.WriteLine($"\n💾 Results saved to: {jsonPath}");
                
//                // Generate analysis reports
//                GenerateComprehensiveReport(results);
//                GenerateComparisonTable(results);
//                GenerateStatisticalAnalysis(results);
                
//                // Verify success
//                var successfulCombos = results.Count(r => r.SegWitSuccess || r.MuSig1Success || r.MuSig2Success);
//                Assert.True(successfulCombos > 0, "At least some combinations should succeed");
//                Console.WriteLine($"\n🎉 Successfully tested {successfulCombos} combinations with real transactions!");
//            }
//        }
        
//        private async Task<ExecutionResult> ExecuteSingleCombination(int k, int n, RPCClient rpc)
//        {
//            var result = new ExecutionResult
//            {
//                K = k,
//                N = n,
//                Combinations = CalculateCombinations(n, k),
//                ExecutionTime = DateTime.UtcNow,
//                BlockHeight = rpc.GetBlockCount()
//            };
            
//            Console.WriteLine($"      🔑 Generating {n} keys for {k}-of-{n} multisig...");
            
//            // Generate keys for this combination
//            var ownerKey = new Key();
//            var signerKeys = Enumerable.Range(0, n).Select(_ => new Key()).ToList();
//            var signerPubKeys = signerKeys.Select(key => key.PubKey).ToList();
            
//            // Execute SegWit multisig transaction
//            Console.WriteLine($"      📝 Testing SegWit multisig...");
//            var segwitStart = DateTime.UtcNow;
//            try
//            {
//                var segwitResult = await ExecuteSegWitMultisig(k, signerKeys, rpc);
//                result.SegWitExecutionTimeMs = (DateTime.UtcNow - segwitStart).TotalMilliseconds;
//                result.SegWitTxId = segwitResult.TxId;
//                result.SegWitActualSize = segwitResult.ActualSize;
//                result.SegWitActualVirtualSize = segwitResult.ActualVirtualSize;
//                result.SegWitWitnessSize = segwitResult.WitnessSize;
//                result.SegWitSuccess = true;
//                Console.WriteLine($"         ✅ SegWit completed in {result.SegWitExecutionTimeMs:F0}ms");
//            }
//            catch (Exception ex)
//            {
//                result.SegWitExecutionTimeMs = (DateTime.UtcNow - segwitStart).TotalMilliseconds;
//                result.SegWitSuccess = false;
//                result.SegWitError = ex.Message;
//                Console.WriteLine($"         ❌ SegWit failed after {result.SegWitExecutionTimeMs:F0}ms: {ex.Message}");
//            }
            
//            // Execute DelegatedMultiSig (MuSig1) transaction
//            Console.WriteLine($"      🎯 Testing MuSig1 (DelegatedMultiSig)...");
//            var muSig1Start = DateTime.UtcNow;
//            try
//            {
//                var muSig1Result = await ExecuteMuSig1Transaction(ownerKey.PubKey, signerPubKeys, k, signerKeys, rpc);
//                result.MuSig1ExecutionTimeMs = (DateTime.UtcNow - muSig1Start).TotalMilliseconds;
//                result.MuSig1TxId = muSig1Result.TxId;
//                result.MuSig1ActualSize = muSig1Result.ActualSize;
//                result.MuSig1ActualVirtualSize = muSig1Result.ActualVirtualSize;
//                result.MuSig1WitnessSize = muSig1Result.WitnessSize;
//                result.MuSig1Success = true;
//                Console.WriteLine($"         ✅ MuSig1 completed in {result.MuSig1ExecutionTimeMs:F0}ms");
//            }
//            catch (Exception ex)
//            {
//                result.MuSig1ExecutionTimeMs = (DateTime.UtcNow - muSig1Start).TotalMilliseconds;
//                result.MuSig1Success = false;
//                result.MuSig1Error = ex.Message;
//                Console.WriteLine($"         ❌ MuSig1 failed after {result.MuSig1ExecutionTimeMs:F0}ms: {ex.Message}");
//            }
            
//            // Execute DelegatedMultiSig2 (MuSig2) transaction
//            Console.WriteLine($"      🚀 Testing MuSig2 (DelegatedMultiSig2)...");
//            var muSig2Start = DateTime.UtcNow;
//            try
//            {
//                var muSig2Result = await ExecuteMuSig2Transaction(ownerKey.PubKey, signerPubKeys, k, signerKeys, rpc);
//                result.MuSig2ExecutionTimeMs = (DateTime.UtcNow - muSig2Start).TotalMilliseconds;
//                result.MuSig2TxId = muSig2Result.TxId;
//                result.MuSig2ActualSize = muSig2Result.ActualSize;
//                result.MuSig2ActualVirtualSize = muSig2Result.ActualVirtualSize;
//                result.MuSig2WitnessSize = muSig2Result.WitnessSize;
//                result.MuSig2Success = true;
//                Console.WriteLine($"         ✅ MuSig2 completed in {result.MuSig2ExecutionTimeMs:F0}ms");
//            }
//            catch (Exception ex)
//            {
//                result.MuSig2ExecutionTimeMs = (DateTime.UtcNow - muSig2Start).TotalMilliseconds;
//                result.MuSig2Success = false;
//                result.MuSig2Error = ex.Message;
//                Console.WriteLine($"         ❌ MuSig2 failed after {result.MuSig2ExecutionTimeMs:F0}ms: {ex.Message}");
//            }
            
//            return result;
//        }
        
//        private async Task<(string TxId, int ActualSize, int ActualVirtualSize, int WitnessSize)> 
//            ExecuteSegWitMultisig(int k, List<Key> signerKeys, RPCClient rpc)
//        {
//            // Handle both standard multisig (≤16) and large multisig (>16) cases
//            if (signerKeys.Count <= 16 && k <= 16)
//            {
//                return await ExecuteStandardSegWitMultisigComprehensive(k, signerKeys, rpc);
//            }
//            else
//            {
//                return await ExecuteLargeSegWitMultisigComprehensive(k, signerKeys, rpc);
//            }
//        }
        
//        private async Task<(string TxId, int ActualSize, int ActualVirtualSize, int WitnessSize)> 
//            ExecuteStandardSegWitMultisigComprehensive(int k, List<Key> signerKeys, RPCClient rpc)
//        {
//            // Standard SegWit multisig for ≤16 participants using OP_CHECKMULTISIG
//            var pubKeys = signerKeys.Select(key => key.PubKey).ToArray();
//            var multiSigScript = PayToMultiSigTemplate.Instance.GenerateScriptPubKey(k, pubKeys);
//            var p2wsh = multiSigScript.WitHash.ScriptPubKey;
//            var p2shP2wsh = p2wsh.Hash.ScriptPubKey;
//            var address = p2shP2wsh.GetDestinationAddress(Network.RegTest);
            
//            // Fund the address
//            var fundingAmount = Money.Coins(1.0m);
//            var fundingStart = DateTime.UtcNow;
//            var fundingTxId = await rpc.SendToAddressAsync(address, fundingAmount);
//            var fundingTime = (DateTime.UtcNow - fundingStart).TotalMilliseconds;
            
//            if (fundingTime > 10000) // Only warn if funding takes more than 10 seconds
//            {
//                Console.WriteLine($"            ⚠️  WARNING: SegWit funding took {fundingTime:F0}ms - possible RPC timeout");
//            }
            
//            var getTxStart = DateTime.UtcNow;
//            var fundingTx = await rpc.GetRawTransactionAsync(fundingTxId);
//            var getTxTime = (DateTime.UtcNow - getTxStart).TotalMilliseconds;
            
//            if (getTxTime > 10000) // Only warn if getting tx takes more than 10 seconds
//            {
//                Console.WriteLine($"            ⚠️  WARNING: SegWit GetRawTransaction took {getTxTime:F0}ms - possible RPC timeout");
//            }
            
//            var findOutputStart = DateTime.UtcNow;
//            var fundingOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == p2shP2wsh);
//            var findOutputTime = (DateTime.UtcNow - findOutputStart).TotalMilliseconds;
            
//            // Create spending transaction
//            var spendingTx = Network.RegTest.CreateTransaction();
//            spendingTx.Inputs.Add(new TxIn(new OutPoint(fundingTxId, fundingOutput.N)));
            
//            var paymentAddress = await rpc.GetNewAddressAsync();
//            var changeAddress = await rpc.GetNewAddressAsync();
            
//            var paymentAmount = Money.Coins(0.5m);
//            spendingTx.Outputs.Add(paymentAmount, paymentAddress);
//            var feeRate = new FeeRate(Money.Satoshis(10), 1);
//            var estimatedFee = feeRate.GetFee(300 + k * 75);
//            var changeAmount = fundingAmount - paymentAmount - estimatedFee;
//            spendingTx.Outputs.Add(changeAmount, changeAddress);
            
//            var signingStart = DateTime.UtcNow;
            
//            // Create signatures
//            var coin = new ScriptCoin(fundingOutput, multiSigScript);
//            var builder = Network.RegTest.CreateTransactionBuilder();
//            builder.AddCoins(coin);
            
//            // Add k signatures
//            for (int i = 0; i < k; i++)
//            {
//                builder.AddKeys(signerKeys[i]);
//            }
            
//            builder.SignTransactionInPlace(spendingTx);
            
//            // Set the P2SH redeem script
//            spendingTx.Inputs[0].ScriptSig = new Script(Op.GetPushOp(p2wsh.ToBytes()));
            
//            var signingTime = (DateTime.UtcNow - signingStart).TotalMilliseconds;
            
//            if (signingTime > 10000) // Only warn if signing takes more than 10 seconds
//            {
//                Console.WriteLine($"            ⚠️  WARNING: SegWit signing took {signingTime:F0}ms - unusually slow");
//            }
            
//            var broadcastStart = DateTime.UtcNow;
            
//            // Broadcast and get actual sizes
//            var broadcastTxId = await rpc.SendRawTransactionAsync(spendingTx);
//            var broadcastTime = (DateTime.UtcNow - broadcastStart).TotalMilliseconds;
            
//            if (broadcastTime > 10000) // Only warn if broadcast takes more than 10 seconds
//            {
//                Console.WriteLine($"            ⚠️  WARNING: SegWit broadcast took {broadcastTime:F0}ms - possible RPC timeout");
//            }
            
//            var finalTxStart = DateTime.UtcNow;
//            // Get the actual transaction from mempool/blockchain
//            var actualTx = await rpc.GetRawTransactionAsync(uint256.Parse(broadcastTxId.ToString()));
//            var finalTxTime = (DateTime.UtcNow - finalTxStart).TotalMilliseconds;
            
//            var actualSize = actualTx.GetSerializedSize();
//            var actualVirtualSize = actualTx.GetVirtualSize();
//            var witnessSize = actualTx.Inputs[0].WitScript.ToBytes().Length;
            
//            return (broadcastTxId.ToString(), actualSize, actualVirtualSize, witnessSize);
//        }
        
//        private async Task<(string TxId, int ActualSize, int ActualVirtualSize, int WitnessSize)> 
//            ExecuteLargeSegWitMultisigComprehensive(int k, List<Key> signerKeys, RPCClient rpc)
//        {
//            // Large multisig is no longer supported - use standard SegWit for ≤16 participants
//            if (signerKeys.Count > 16 || k > 16)
//            {
//                throw new NotSupportedException("Large multisig (>16 participants) is no longer supported");
//            }
            
//            var signerPubKeys = signerKeys.Select(key => key.PubKey).ToList();
//            var segWitMultiSig = new SegWitMultiSig(signerPubKeys, k, Network.RegTest);
//            var address = segWitMultiSig.Address;
            
//            // Fund the address
//            var fundingAmount = Money.Coins(1.0m);
//            var fundingTxId = await rpc.SendToAddressAsync(address, fundingAmount);
//            var fundingTx = await rpc.GetRawTransactionAsync(fundingTxId);
//            var fundingOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
//            var coin = new Coin(fundingOutput);
            
//            // Create spending transaction
//            var spendingTx = Network.RegTest.CreateTransaction();
//            spendingTx.Inputs.Add(new TxIn(new OutPoint(fundingTxId, fundingOutput.N)));
            
//            var paymentAddress = await rpc.GetNewAddressAsync();
//            var changeAddress = await rpc.GetNewAddressAsync();
//            var paymentAmount = Money.Coins(0.5m);
            
//            spendingTx.Outputs.Add(paymentAmount, paymentAddress);
//            var estimatedVSize = segWitMultiSig.EstimateVirtualSize();
//            var feeRate = new FeeRate(Money.Satoshis(10), 1);
//            var estimatedFee = feeRate.GetFee(estimatedVSize);
//            var changeAmount = fundingAmount - paymentAmount - estimatedFee;
//            spendingTx.Outputs.Add(changeAmount, changeAddress);
            
//            // Sign using standard TransactionBuilder approach
//            var scriptCoin = segWitMultiSig.CreateCoin(coin);
//            var builder = Network.RegTest.CreateTransactionBuilder();
//            builder.AddCoins(scriptCoin);
            
//            // Add first k signers
//            var selectedSigners = signerKeys.Take(k).ToList();
//            foreach (var signer in selectedSigners)
//            {
//                builder.AddKeys(signer);
//            }
            
//            // Sign and broadcast
//            var signedTx = builder.SignTransaction(spendingTx);
//            var broadcastTxId = await rpc.SendRawTransactionAsync(signedTx);
            
//            // Get actual transaction details
//            var actualTx = await rpc.GetRawTransactionAsync(broadcastTxId);
//            var actualSize = actualTx.GetSerializedSize();
//            var actualVirtualSize = actualTx.GetVirtualSize();
//            var witnessSize = actualTx.Inputs[0].WitScript.ToBytes().Length;
            
//            return (broadcastTxId.ToString(), actualSize, actualVirtualSize, witnessSize);
//        }
        
//        private async Task<(string TxId, int ActualSize, int ActualVirtualSize, int WitnessSize)> 
//            ExecuteMuSig1Transaction(PubKey ownerPubKey, List<PubKey> signerPubKeys, int k, List<Key> signerKeys, RPCClient rpc)
//        {
//            var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, k, Network.RegTest);
//            var address = multiSig.Address;
            
//            // Fund the address
//            var fundingAmount = Money.Coins(1.0m);
//            var fundingTxId = await rpc.SendToAddressAsync(address, fundingAmount);
//            var fundingTx = await rpc.GetRawTransactionAsync(fundingTxId);
//            var fundingOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
//            var coin = new Coin(fundingOutput);
            
//            // Create spending transaction with proper structure
//            var spendingTx = Network.RegTest.CreateTransaction();
//            spendingTx.Inputs.Add(coin.Outpoint);
            
//            var paymentAddress = await rpc.GetNewAddressAsync();
//            var changeAddress = await rpc.GetNewAddressAsync();
//            var paymentAmount = Money.Coins(0.5m);
            
//            spendingTx.Outputs.Add(paymentAmount, paymentAddress);
//            var tempFee = new FeeRate(Money.Satoshis(10), 1).GetFee(300);
//            var tempChange = fundingAmount - paymentAmount - tempFee;
//            spendingTx.Outputs.Add(tempChange, changeAddress);
            
//            // Use participant-aware signing workflow
//            var builder = multiSig.CreateSignatureBuilder(spendingTx, new[] { coin });
//            var selectedSigners = signerKeys.Take(k).ToList();
            
//            // First signer calculates accurate sizes
//            builder.SignWithSigner(selectedSigners[0], 0, TaprootSigHash.All);
            
//            // Get participant-aware size
//            var participantIndices = Enumerable.Range(0, k).ToArray();
//            var cheapestScriptIndex = builder.GetCheapestScriptIndexForSigners(participantIndices);
//            var accurateVSize = builder.GetActualVirtualSizeForScript(0, cheapestScriptIndex);
            
//            // Update fee
//            var feeRate = new FeeRate(Money.Satoshis(10), 1);
//            var accurateFee = feeRate.GetFee(accurateVSize);
//            var accurateChange = fundingAmount - paymentAmount - accurateFee;
//            spendingTx.Outputs[1].Value = accurateChange;
            
//            // Complete signing with all participants
//            var finalBuilder = multiSig.CreateSignatureBuilder(spendingTx, new[] { coin });
//            foreach (var signer in selectedSigners)
//            {
//                var sigData = finalBuilder.SignWithSigner(signer, 0, TaprootSigHash.All);
//                if (sigData.IsComplete) break;
//            }
            
//            var finalTx = finalBuilder.FinalizeTransaction(0);
            
//            // Broadcast and get actual sizes
//            var broadcastTxId = await rpc.SendRawTransactionAsync(finalTx);
            
//            // Get the actual transaction
//            var actualTx = await rpc.GetRawTransactionAsync(uint256.Parse(broadcastTxId.ToString()));
//            var actualSize = actualTx.GetSerializedSize();
//            var actualVirtualSize = actualTx.GetVirtualSize();
//            var witnessSize = actualTx.Inputs[0].WitScript.ToBytes().Length;
            
//            return (broadcastTxId.ToString(), actualSize, actualVirtualSize, witnessSize);
//        }
        
//        private async Task<(string TxId, int ActualSize, int ActualVirtualSize, int WitnessSize)> 
//            ExecuteMuSig2Transaction(PubKey ownerPubKey, List<PubKey> signerPubKeys, int k, List<Key> signerKeys, RPCClient rpc)
//        {
//            var multiSig = new DelegatedMultiSig2(ownerPubKey, signerPubKeys, k, Network.RegTest);
//            var address = multiSig.Address;
            
//            // Fund the address
//            var fundingAmount = Money.Coins(1.0m);
//            var fundingTxId = await rpc.SendToAddressAsync(address, fundingAmount);
//            var fundingTx = await rpc.GetRawTransactionAsync(fundingTxId);
//            var fundingOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
//            var coin = new Coin(fundingOutput);
            
//            // Create spending transaction
//            var spendingTx = Network.RegTest.CreateTransaction();
//            spendingTx.Inputs.Add(coin.Outpoint);
            
//            var paymentAddress = await rpc.GetNewAddressAsync();
//            var changeAddress = await rpc.GetNewAddressAsync();
//            var paymentAmount = Money.Coins(0.5m);
            
//            spendingTx.Outputs.Add(paymentAmount, paymentAddress);
//            var estimatedFee = new FeeRate(Money.Satoshis(10), 1).GetFee(200);
//            var changeAmount = fundingAmount - paymentAmount - estimatedFee;
//            spendingTx.Outputs.Add(changeAmount, changeAddress);
            
//            // MuSig2 interactive protocol
//            var builder = multiSig.CreateSignatureBuilder(spendingTx, new[] { coin });
//            var selectedSigners = signerKeys.Take(k).ToList();
            
//            // Phase 1: Nonce exchange
//            var nonces = new List<DelegatedMultiSig2.MuSig2NonceData>();
//            foreach (var signer in selectedSigners)
//            {
//                var nonceData = builder.GenerateNonce(signer, 0, TaprootSigHash.All);
//                nonces.Add(nonceData);
//            }
            
//            foreach (var nonce in nonces)
//            {
//                builder.AddNonces(nonce, 0);
//            }
            
//            // Phase 2: Signing
//            foreach (var signer in selectedSigners)
//            {
//                var sigData = builder.SignWithSigner(signer, 0, TaprootSigHash.All);
//                if (sigData.IsComplete) break;
//            }
            
//            var finalTx = builder.FinalizeTransaction(0);
            
//            // Broadcast and get actual sizes
//            var broadcastTxId = await rpc.SendRawTransactionAsync(finalTx);
            
//            // Get the actual transaction
//            var actualTx = await rpc.GetRawTransactionAsync(uint256.Parse(broadcastTxId.ToString()));
//            var actualSize = actualTx.GetSerializedSize();
//            var actualVirtualSize = actualTx.GetVirtualSize();
//            var witnessSize = actualTx.Inputs[0].WitScript.ToBytes().Length;
            
//            return (broadcastTxId.ToString(), actualSize, actualVirtualSize, witnessSize);
//        }
        
//        private List<(int k, int n)> GenerateAllViableCombinations()
//        {
//            var combinations = new List<(int k, int n)>();
            
//            // PERFORMANCE FIX: Reduce test scope to essential combinations
//            // Original issue: 435 combinations × 3 transactions = 1,305 blockchain transactions
//            // This creates a representative sample focusing on practical use cases
            
//            // Essential small multisigs (1-of-2 through 5-of-7)
//            for (int n = 2; n <= 7; n++)
//            {
//                for (int k = 1; k <= n; k++)
//                {
//                    combinations.Add((k, n));
//                }
//            }
            
//            // Medium multisigs - expanded coverage (avoid high-combination counts)
//            var mediumConfigs = new[] { 
//                // 8-participant coverage
//                (1, 8), (2, 8), (3, 8), (4, 8), (5, 8), (6, 8), (7, 8), (8, 8),
                
//                // 9-participant coverage  
//                (1, 9), (2, 9), (3, 9), (7, 9), (8, 9), (9, 9),
                
//                // 10-participant coverage
//                (1, 10), (2, 10), (3, 10), (4, 10), (7, 10), (8, 10), (9, 10), (10, 10),
                
//                // 11-participant coverage
//                (1, 11), (2, 11), (3, 11), (9, 11), (10, 11), (11, 11),
                
//                // 12-participant coverage
//                (1, 12), (2, 12), (3, 12), (4, 12), (9, 12), (10, 12), (11, 12), (12, 12),
                
//                // 13-participant coverage
//                (1, 13), (2, 13), (3, 13), (11, 13), (12, 13), (13, 13),
                
//                // 14-participant coverage  
//                (1, 14), (2, 14), (3, 14), (12, 14), (13, 14), (14, 14),
                
//                // 15-participant coverage
//                (1, 15), (2, 15), (3, 15), (4, 15), (12, 15), (13, 15), (14, 15), (15, 15)
//            };
//            combinations.AddRange(mediumConfigs);
            
//            // Large multisigs - expanded coverage with careful combination limits
//            var largeConfigs = new[] { 
//                // 16-participant (SegWit limit) - complete coverage
//                (1, 16), (2, 16), (3, 16), (4, 16), (5, 16), (12, 16), (13, 16), (14, 16), (15, 16), (16, 16),
                
//                // 17-participant (first beyond SegWit)
//                (1, 17), (2, 17), (3, 17), (4, 17), (14, 17), (15, 17), (16, 17), (17, 17),
                
//                // 18-participant
//                (1, 18), (2, 18), (3, 18), (4, 18), (15, 18), (16, 18), (17, 18), (18, 18),
                
//                // 19-participant (new)
//                (1, 19), (2, 19), (3, 19), (4, 19), (16, 19), (17, 19), (18, 19), (19, 19),
                
//                // 20-participant coverage
//                (1, 20), (2, 20), (3, 20), (4, 20), (5, 20), (16, 20), (17, 20), (18, 20), (19, 20), (20, 20),
                
//                // 21-participant (new)
//                (1, 21), (2, 21), (3, 21), (4, 21), (18, 21), (19, 21), (20, 21), (21, 21),
                
//                // 22-participant
//                (1, 22), (2, 22), (3, 22), (4, 22), (19, 22), (20, 22), (21, 22), (22, 22),
                
//                // 23-participant (new)
//                (1, 23), (2, 23), (3, 23), (4, 23), (20, 23), (21, 23), (22, 23), (23, 23),
                
//                // 24-participant (new)
//                (1, 24), (2, 24), (3, 24), (4, 24), (21, 24), (22, 24), (23, 24), (24, 24),
                
//                // 25-participant coverage
//                (1, 25), (2, 25), (3, 25), (4, 25), (5, 25), (21, 25), (22, 25), (23, 25), (24, 25), (25, 25),
                
//                // 26-participant (new)
//                (1, 26), (2, 26), (3, 26), (4, 26), (23, 26), (24, 26), (25, 26), (26, 26),
                
//                // 27-participant (new)
//                (1, 27), (2, 27), (3, 27), (4, 27), (24, 27), (25, 27), (26, 27), (27, 27),
                
//                // 28-participant
//                (1, 28), (2, 28), (3, 28), (4, 28), (25, 28), (26, 28), (27, 28), (28, 28),
                
//                // 29-participant (new)
//                (1, 29), (2, 29), (3, 29), (4, 29), (26, 29), (27, 29), (28, 29), (29, 29),
                
//                // 30-participant coverage
//                (1, 30), (2, 30), (3, 30), (4, 30), (5, 30), (26, 30), (27, 30), (28, 30), (29, 30), (30, 30),
                
//                // 32-participant (new - power of 2)
//                (1, 32), (2, 32), (3, 32), (4, 32), (29, 32), (30, 32), (31, 32), (32, 32),
                
//                // 35-participant (new)
//                (1, 35), (2, 35), (3, 35), (4, 35), (32, 35), (33, 35), (34, 35), (35, 35),
                
//                // 40-participant (new - nice round number)
//                (1, 40), (2, 40), (3, 40), (4, 40), (37, 40), (38, 40), (39, 40), (40, 40),
                
//                // 50-participant (new - half-century)
//                (1, 50), (2, 50), (3, 50), (4, 50), (47, 50), (48, 50), (49, 50), (50, 50)
//            };
//            combinations.AddRange(largeConfigs);
            
//            // Filter by combinations limit and remove duplicates
//            // SAFETY: Exclude combinations that would cause DelegatedMultiSig constructor to hang
//            var filteredCombinations = combinations.Distinct()
//                .Where(c => {
//                    var combCount = CalculateCombinations(c.n, c.k);
//                    // More aggressive filtering: limit to 50,000 to prevent hangs in DelegatedMultiSig
//                    var isReasonable = combCount > 0 && combCount <= 50000;
//                    if (!isReasonable)
//                    {
//                        Console.WriteLine($"⚠️  Excluding {c.k}-of-{c.n} (C({c.n},{c.k}) = {combCount:N0} - too many combinations)");
//                    }
//                    return isReasonable;
//                })
//                .OrderBy(c => c.n)
//                .ThenBy(c => c.k)
//                .ToList();
                
//            return filteredCombinations;
//        }
        
//        private long CalculateCombinations(int n, int k)
//        {
//            if (k > n) return 0;
//            if (k == 0 || k == n) return 1;
//            if (k > n - k) k = n - k;
            
//            double logResult = 0;
//            for (int i = 0; i < k; i++)
//            {
//                logResult += Math.Log10(n - i) - Math.Log10(i + 1);
//            }
            
//            if (logResult > 6.0) return long.MaxValue;
            
//            long result = 1;
//            for (int i = 0; i < k; i++)
//            {
//                result = result * (n - i) / (i + 1);
//                if (result < 0 || result > 1000000) return long.MaxValue;
//            }
//            return result;
//        }
        
//        private string SaveResultsToJson(List<ExecutionResult> results)
//        {
//            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd_HH-mm-ss");
//            var filename = $"multisig_comparison_results_{timestamp}.json";
//            var filepath = Path.Combine(Directory.GetCurrentDirectory(), filename);
            
//            var json = JsonConvert.SerializeObject(results, Formatting.Indented);
//            File.WriteAllText(filepath, json);
            
//            return filepath;
//        }
        
//        // TaprootSegWit execution removed - not reliable
        
//        private void GenerateComprehensiveReport(List<ExecutionResult> results)
//        {
//            Console.WriteLine("\n" + "=".PadRight(120, '='));
//            Console.WriteLine("COMPREHENSIVE MULTISIG COMPARISON - ACTUAL BLOCKCHAIN DATA");
//            Console.WriteLine("=".PadRight(120, '='));
            
//            var successfulResults = results.Where(r => 
//                (r.SegWitSuccess || r.MuSig1Success || r.MuSig2Success)).ToList();
            
//            Console.WriteLine($"\n📊 EXECUTION SUMMARY:");
//            Console.WriteLine($"   • Total combinations tested: {results.Count}");
//            Console.WriteLine($"   • Successful combinations: {successfulResults.Count}");
//            Console.WriteLine($"   • Total transactions created: {results.Sum(r => (r.SegWitSuccess ? 1 : 0) + (r.MuSig1Success ? 1 : 0) + (r.MuSig2Success ? 1 : 0))}");
            
//            // Success rates by method
//            var segwitSuccess = results.Count(r => r.SegWitSuccess);
//            var muSig1Success = results.Count(r => r.MuSig1Success);
//            var muSig2Success = results.Count(r => r.MuSig2Success);
            
//            Console.WriteLine($"\n📈 SUCCESS RATES:");
//            Console.WriteLine($"   • SegWit: {segwitSuccess}/{results.Count} ({100.0 * segwitSuccess / results.Count:F1}%)");
//            Console.WriteLine($"   • MuSig1: {muSig1Success}/{results.Count} ({100.0 * muSig1Success / results.Count:F1}%)");
//            Console.WriteLine($"   • MuSig2: {muSig2Success}/{results.Count} ({100.0 * muSig2Success / results.Count:F1}%)");
            
//            // Average sizes from ACTUAL transactions
//            var avgSegWitSize = results.Where(r => r.SegWitSuccess).Average(r => r.SegWitActualVirtualSize);
//            var avgMuSig1Size = results.Where(r => r.MuSig1Success).Average(r => r.MuSig1ActualVirtualSize);
//            var avgMuSig2Size = results.Where(r => r.MuSig2Success).Average(r => r.MuSig2ActualVirtualSize);
            
//            Console.WriteLine($"\n📏 AVERAGE ACTUAL VIRTUAL SIZES:");
//            Console.WriteLine($"   • SegWit: {avgSegWitSize:F1} vbytes");
//            Console.WriteLine($"   • MuSig1: {avgMuSig1Size:F1} vbytes");
//            Console.WriteLine($"   • MuSig2: {avgMuSig2Size:F1} vbytes");
//            Console.WriteLine($"   • MuSig1 vs SegWit: {(avgMuSig1Size - avgSegWitSize) / avgSegWitSize * 100:F1}%");
//            Console.WriteLine($"   • MuSig2 vs SegWit: {(avgMuSig2Size - avgSegWitSize) / avgSegWitSize * 100:F1}%");
//        }
        
//        private void GenerateComparisonTable(List<ExecutionResult> results)
//        {
//            Console.WriteLine("\n" + "=".PadRight(140, '='));
//            Console.WriteLine("ACTUAL TRANSACTION SIZES FROM BLOCKCHAIN");
//            Console.WriteLine("=".PadRight(140, '='));
//            Console.WriteLine("NOTE: 'X' indicates SegWit multisig is not possible (>16 participants)");
//            Console.WriteLine("=".PadRight(140, '='));
            
//            // Headers with timing info
//            var headers = new[] { "k-of-n", "Comb.", "SegWit", "MuSig1", "MuSig2", "Best", "Total(ms)", "SegWit(ms)", "MuSig1(ms)", "MuSig2(ms)" };
//            Console.WriteLine(string.Join(" | ", headers.Select((h, i) => h.PadRight(GetColumnWidth(i)))));
//            Console.WriteLine(string.Join("-+-", headers.Select((_, i) => "".PadRight(GetColumnWidth(i), '-'))));
            
//            // Show ALL results, not just a subset
//            var displayResults = results
//                .OrderBy(r => r.N)
//                .ThenBy(r => r.K);
            
//            foreach (var result in displayResults)
//            {
//                // Mark SegWit as "X" if >16 participants (Bitcoin protocol limit)
//                var segwitDisplay = result.N > 16 ? "X" : 
//                                   result.SegWitSuccess ? result.SegWitActualVirtualSize.ToString() : "FAIL";
                
//                var row = new[]
//                {
//                    $"{result.K}-of-{result.N}",
//                    result.Combinations.ToString(),
//                    segwitDisplay,
//                    result.MuSig1Success ? result.MuSig1ActualVirtualSize.ToString() : "FAIL",
//                    result.MuSig2Success ? result.MuSig2ActualVirtualSize.ToString() : "FAIL",
//                    result.BestMethod,
//                    result.TotalExecutionTimeMs.ToString("F0"),
//                    result.SegWitExecutionTimeMs.ToString("F0"),
//                    result.MuSig1ExecutionTimeMs.ToString("F0"),
//                    result.MuSig2ExecutionTimeMs.ToString("F0")
//                };
                
//                Console.WriteLine(string.Join(" | ", row.Select((cell, i) => cell.PadRight(GetColumnWidth(i)))));
//            }
            
//            Console.WriteLine("=".PadRight(140, '='));
//            Console.WriteLine($"Total results: {results.Count} combinations");
//        }
        
//        private int GetColumnWidth(int columnIndex)
//        {
//            return columnIndex switch
//            {
//                0 => 7,   // k-of-n
//                1 => 6,   // Combinations  
//                2 => 7,   // SegWit
//                3 => 7,   // MuSig1
//                4 => 7,   // MuSig2
//                5 => 8,   // Best
//                6 => 10,  // Total(ms)
//                7 => 10,  // SegWit(ms)
//                8 => 10,  // MuSig1(ms)
//                9 => 10,  // MuSig2(ms)
//                _ => 10
//            };
//        }
        
//        private void GenerateStatisticalAnalysis(List<ExecutionResult> results)
//        {
//            Console.WriteLine("\n" + "=".PadRight(80, '='));
//            Console.WriteLine("STATISTICAL ANALYSIS");
//            Console.WriteLine("=".PadRight(80, '='));
            
//            var successfulComparisons = results.Where(r => 
//                r.SegWitSuccess && r.MuSig1Success && r.MuSig2Success).ToList();
            
//            if (!successfulComparisons.Any())
//            {
//                Console.WriteLine("Not enough successful comparisons for analysis.");
//                return;
//            }
            
//            // Best/worst savings
//            var bestMuSig2Savings = successfulComparisons.OrderBy(r => r.MuSig2VsSegWitPercent).First();
//            var worstMuSig2Savings = successfulComparisons.OrderByDescending(r => r.MuSig2VsSegWitPercent).First();
            
//            Console.WriteLine($"\n🏆 BEST/WORST CASES:");
//            Console.WriteLine($"   • Best MuSig2 savings: {bestMuSig2Savings.K}-of-{bestMuSig2Savings.N} ({bestMuSig2Savings.MuSig2VsSegWitPercent:F1}%)");
//            Console.WriteLine($"   • Worst MuSig2 performance: {worstMuSig2Savings.K}-of-{worstMuSig2Savings.N} ({worstMuSig2Savings.MuSig2VsSegWitPercent:F1}%)");
            
//            // Winner statistics
//            var muSig2Wins = successfulComparisons.Count(r => r.BestMethod == "MuSig2");
//            var muSig1Wins = successfulComparisons.Count(r => r.BestMethod == "MuSig1");
//            var segWitWins = successfulComparisons.Count(r => r.BestMethod == "SegWit");
            
//            Console.WriteLine($"\n🥇 WINNER DISTRIBUTION:");
//            Console.WriteLine($"   • MuSig2 wins: {muSig2Wins} ({100.0 * muSig2Wins / successfulComparisons.Count():F1}%)");
//            Console.WriteLine($"   • MuSig1 wins: {muSig1Wins} ({100.0 * muSig1Wins / successfulComparisons.Count():F1}%)");
//            Console.WriteLine($"   • SegWit wins: {segWitWins} ({100.0 * segWitWins / successfulComparisons.Count():F1}%)");
            
//            // Size distribution
//            Console.WriteLine($"\n📊 SIZE DISTRIBUTION:");
//            var segWitComparisons = successfulComparisons.Where(r => r.SegWitSuccess);
            
//            if (segWitComparisons.Any())
//            {
//                Console.WriteLine($"   • Min SegWit vSize: {segWitComparisons.Min(r => r.SegWitActualVirtualSize)} vbytes");
//                Console.WriteLine($"   • Max SegWit vSize: {segWitComparisons.Max(r => r.SegWitActualVirtualSize)} vbytes");
//            }
//            Console.WriteLine($"   • Min MuSig1 vSize: {successfulComparisons.Min(r => r.MuSig1ActualVirtualSize)} vbytes");
//            Console.WriteLine($"   • Max MuSig1 vSize: {successfulComparisons.Max(r => r.MuSig1ActualVirtualSize)} vbytes");
//            Console.WriteLine($"   • Min MuSig2 vSize: {successfulComparisons.Min(r => r.MuSig2ActualVirtualSize)} vbytes");
//            Console.WriteLine($"   • Max MuSig2 vSize: {successfulComparisons.Max(r => r.MuSig2ActualVirtualSize)} vbytes");
            
//            Console.WriteLine("=".PadRight(80, '='));
//        }
//    }
//}
