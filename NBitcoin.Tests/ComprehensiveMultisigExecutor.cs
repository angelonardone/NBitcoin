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
            
//            // TaprootSegWit removed - not reliable
            
//            public string MuSig1TxId { get; set; }
//            public int MuSig1ActualSize { get; set; }
//            public int MuSig1ActualVirtualSize { get; set; }
//            public int MuSig1WitnessSize { get; set; }
//            public bool MuSig1Success { get; set; }
//            public string MuSig1Error { get; set; }
            
//            public string MuSig2TxId { get; set; }
//            public int MuSig2ActualSize { get; set; }
//            public int MuSig2ActualVirtualSize { get; set; }
//            public int MuSig2WitnessSize { get; set; }
//            public bool MuSig2Success { get; set; }
//            public string MuSig2Error { get; set; }
            
//            public DateTime ExecutionTime { get; set; }
//            public int BlockHeight { get; set; }
            
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
//                    Console.Write($"\r⏳ Progress: {progressCount}/{allCombinations.Count} ({percentage:F1}%) - Testing {k}-of-{n}...");
                    
//                    var result = await ExecuteSingleCombination(k, n, rpc);
//                    results.Add(result);
                    
//                    // Mine a block every 10 combinations to prevent mempool issues
//                    if (progressCount % 10 == 0)
//                    {
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
            
//            // Generate keys for this combination
//            var ownerKey = new Key();
//            var signerKeys = Enumerable.Range(0, n).Select(_ => new Key()).ToList();
//            var signerPubKeys = signerKeys.Select(key => key.PubKey).ToList();
            
//            // Execute SegWit multisig transaction
//            try
//            {
//                var segwitResult = await ExecuteSegWitMultisig(k, signerKeys, rpc);
//                result.SegWitTxId = segwitResult.TxId;
//                result.SegWitActualSize = segwitResult.ActualSize;
//                result.SegWitActualVirtualSize = segwitResult.ActualVirtualSize;
//                result.SegWitWitnessSize = segwitResult.WitnessSize;
//                result.SegWitSuccess = true;
//            }
//            catch (Exception ex)
//            {
//                result.SegWitSuccess = false;
//                result.SegWitError = ex.Message;
//            }
            
//            // Execute DelegatedMultiSig (MuSig1) transaction
//            try
//            {
//                var muSig1Result = await ExecuteMuSig1Transaction(ownerKey.PubKey, signerPubKeys, k, signerKeys, rpc);
//                result.MuSig1TxId = muSig1Result.TxId;
//                result.MuSig1ActualSize = muSig1Result.ActualSize;
//                result.MuSig1ActualVirtualSize = muSig1Result.ActualVirtualSize;
//                result.MuSig1WitnessSize = muSig1Result.WitnessSize;
//                result.MuSig1Success = true;
//            }
//            catch (Exception ex)
//            {
//                result.MuSig1Success = false;
//                result.MuSig1Error = ex.Message;
//            }
            
//            // Execute DelegatedMultiSig2 (MuSig2) transaction
//            try
//            {
//                var muSig2Result = await ExecuteMuSig2Transaction(ownerKey.PubKey, signerPubKeys, k, signerKeys, rpc);
//                result.MuSig2TxId = muSig2Result.TxId;
//                result.MuSig2ActualSize = muSig2Result.ActualSize;
//                result.MuSig2ActualVirtualSize = muSig2Result.ActualVirtualSize;
//                result.MuSig2WitnessSize = muSig2Result.WitnessSize;
//                result.MuSig2Success = true;
//            }
//            catch (Exception ex)
//            {
//                result.MuSig2Success = false;
//                result.MuSig2Error = ex.Message;
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
//            var fundingTxId = await rpc.SendToAddressAsync(address, fundingAmount);
//            var fundingTx = await rpc.GetRawTransactionAsync(fundingTxId);
//            var fundingOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == p2shP2wsh);
            
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
            
//            // Broadcast and get actual sizes
//            var broadcastTxId = await rpc.SendRawTransactionAsync(spendingTx);
            
//            // Get the actual transaction from mempool/blockchain
//            var actualTx = await rpc.GetRawTransactionAsync(uint256.Parse(broadcastTxId.ToString()));
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
            
//            // Generate ALL k-of-n combinations where C(n,k) <= 1,000,000
//            for (int n = 2; n <= 100; n++)
//            {
//                for (int k = 1; k <= n; k++)
//                {
//                    var combCount = CalculateCombinations(n, k);
//                    if (combCount > 0 && combCount <= 1000000)
//                    {
//                        combinations.Add((k, n));
//                    }
//                }
//            }
            
//            return combinations.OrderBy(c => c.n).ThenBy(c => c.k).ToList();
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
            
//            // Headers
//            var headers = new[] { "k-of-n", "Comb.", "SegWit", "MuSig1", "MuSig2", "Best" };
//            Console.WriteLine(string.Join(" | ", headers.Select((h, i) => h.PadRight(GetColumnWidth(i)))));
//            Console.WriteLine(string.Join("-+-", headers.Select((_, i) => "".PadRight(GetColumnWidth(i), '-'))));
            
//            // Show first 20 results and some interesting ones
//            var displayResults = results
//                .Where(r => r.SegWitSuccess || r.MuSig1Success || r.MuSig2Success)
//                .Take(20)
//                .Concat(results.Where(r => r.K == r.N / 2).Take(5)) // Add some k=n/2 cases
//                .Distinct()
//                .OrderBy(r => r.N)
//                .ThenBy(r => r.K);
            
//            foreach (var result in displayResults)
//            {
//                var row = new[]
//                {
//                    $"{result.K}-of-{result.N}",
//                    result.Combinations.ToString(),
//                    result.SegWitSuccess ? result.SegWitActualVirtualSize.ToString() : "FAIL",
//                    result.MuSig1Success ? result.MuSig1ActualVirtualSize.ToString() : "FAIL",
//                    result.MuSig2Success ? result.MuSig2ActualVirtualSize.ToString() : "FAIL",
//                    result.BestMethod
//                };
                
//                Console.WriteLine(string.Join(" | ", row.Select((cell, i) => cell.PadRight(GetColumnWidth(i)))));
//            }
            
//            Console.WriteLine("=".PadRight(140, '='));
//            Console.WriteLine($"(Showing {displayResults.Count()} of {results.Count} total results)");
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
//                5 => 13,  // Best
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
