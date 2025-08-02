using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NBitcoin;
using NBitcoin.Tests;
using NBitcoin.RPC;
using Xunit;

namespace NBitcoin.Tests
{
    /// <summary>
    /// Tests for SegWitMultiSig - Traditional SegWit P2SH-P2WSH multisig (≤16 participants)
    /// No owner concept - pure k-of-n multisig using standard OP_CHECKMULTISIG
    /// </summary>
    [Trait("UnitTest", "UnitTest")]
    public class SegWitMultiSigTests
    {
        [Fact]
        public void CanCreateSegWitMultiSig_2of3()
        {
            // Generate test keys
            var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
            var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

            // Create SegWitMultiSig
            var multiSig = new SegWitMultiSig(signerPubKeys, 2, Network.RegTest);

            // Verify basic properties
            Assert.Equal(3, multiSig.SignerPubKeys.Count);
            Assert.Equal(2, multiSig.RequiredSignatures);
            Assert.Equal(Network.RegTest, multiSig.Network);
            Assert.NotNull(multiSig.Address);
            Assert.NotNull(multiSig.MultisigScript);
        }

        [Fact]
        public void SegWitMultiSig_ValidatesInputs()
        {
            var signerKeys = new List<Key> { new Key(), new Key() };
            var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

            // Should reject invalid configurations
            Assert.Throws<ArgumentException>(() => 
                new SegWitMultiSig(signerPubKeys, 0, Network.RegTest)); // k = 0

            Assert.Throws<ArgumentException>(() => 
                new SegWitMultiSig(signerPubKeys, 3, Network.RegTest)); // k > n

            Assert.Throws<ArgumentException>(() => 
                new SegWitMultiSig(new List<PubKey> { new Key().PubKey }, 1, Network.RegTest)); // n < 2

            // Should reject >16 participants
            var tooManyKeys = Enumerable.Range(0, 17).Select(_ => new Key().PubKey).ToList();
            Assert.Throws<ArgumentException>(() => 
                new SegWitMultiSig(tooManyKeys, 10, Network.RegTest)); // n > 16
        }

        [Theory]
        [InlineData(2, 3)]   // 2-of-3
        [InlineData(3, 5)]   // 3-of-5  
        [InlineData(5, 10)]  // 5-of-10
        [InlineData(7, 15)]  // 7-of-15
        [InlineData(10, 16)] // 10-of-16 (maximum)
        public async Task SegWitMultiSig_WorksWithRealTransactions(int k, int n)
        {
            Console.WriteLine($"\n🧪 TESTING SegWitMultiSig {k}-of-{n} Configuration");
            Console.WriteLine("=" + new string('=', 50));
            Console.WriteLine($"   • Traditional SegWit P2SH-P2WSH");
            Console.WriteLine($"   • Uses standard OP_CHECKMULTISIG");
            Console.WriteLine($"   • ECDSA signatures");
            
            using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
            {
                var rpc = nodeBuilder.CreateNode().CreateRPCClient();
                nodeBuilder.StartAll();
                
                // Generate initial blocks
                rpc.Generate(Network.RegTest.Consensus.CoinbaseMaturity + 10);
                
                // Generate test keys
                var signerKeys = Enumerable.Range(0, n).Select(_ => new Key()).ToList();
                var signerPubKeys = signerKeys.Select(key => key.PubKey).ToList();

                // Create SegWitMultiSig
                var multiSig = new SegWitMultiSig(signerPubKeys, k, Network.RegTest);

                Console.WriteLine($"✅ Created successfully!");
                Console.WriteLine($"   • Address: {multiSig.Address}");
                Console.WriteLine($"   • Script size: {multiSig.MultisigScript.ToBytes().Length} bytes");
                
                // Test with real transaction
                var result = await ExecuteRealTransaction(multiSig, signerKeys, k, rpc);
                
                Console.WriteLine($"✅ REAL TRANSACTION SUCCESSFUL!");
                Console.WriteLine($"   • Virtual Size: {result.VirtualSize} vbytes");
                Console.WriteLine($"   • Cost at 10 sat/vB: ~{result.VirtualSize * 10} sats");
                Console.WriteLine($"   • TxId: {result.TxId.Substring(0, 16)}...");
                
                Assert.True(result.Success);
                Assert.True(result.VirtualSize > 0);
                Assert.NotNull(result.TxId);
            }
        }

        [Fact]
        public async Task SegWitMultiSig_CompareWithStandardMultisig()
        {
            Console.WriteLine($"\n📊 COMPARING SegWitMultiSig vs Standard NBitcoin Multisig");
            Console.WriteLine("=" + new string('=', 60));
            
            using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
            {
                var rpc = nodeBuilder.CreateNode().CreateRPCClient();
                nodeBuilder.StartAll();
                rpc.Generate(Network.RegTest.Consensus.CoinbaseMaturity + 10);
                
                var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
                var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();
                
                // Test our SegWitMultiSig
                var multiSig = new SegWitMultiSig(signerPubKeys, 2, Network.RegTest);
                var ourResult = await ExecuteRealTransaction(multiSig, signerKeys, 2, rpc);
                
                // Test standard NBitcoin approach
                var standardResult = await ExecuteStandardMultisig(signerKeys, 2, rpc);
                
                Console.WriteLine($"Results:");
                Console.WriteLine($"   • SegWitMultiSig:     {ourResult.VirtualSize} vbytes");
                Console.WriteLine($"   • Standard NBitcoin:  {standardResult.VirtualSize} vbytes");
                Console.WriteLine($"   • Difference:         {ourResult.VirtualSize - standardResult.VirtualSize} vbytes");
                
                // They should be very similar since both use standard OP_CHECKMULTISIG
                Assert.True(Math.Abs(ourResult.VirtualSize - standardResult.VirtualSize) < 10);
            }
        }
        
        private async Task<TransactionResult> ExecuteRealTransaction(SegWitMultiSig multiSig, List<Key> signerKeys, int k, RPCClient rpc)
        {
            // Fund the multisig address
            var fundingAmount = Money.Coins(1.0m);
            var fundingTxId = await rpc.SendToAddressAsync(multiSig.Address, fundingAmount);
            
            // Get funding transaction details
            var fundingTx = await rpc.GetRawTransactionAsync(fundingTxId);
            var fundingOutput = fundingTx.Outputs.AsIndexedOutputs()
                .First(o => o.TxOut.ScriptPubKey == multiSig.Address.ScriptPubKey);
            
            // Create spending transaction
            var spendingTx = Network.RegTest.CreateTransaction();
            spendingTx.Inputs.Add(new TxIn(new OutPoint(fundingTxId, fundingOutput.N)));
            
            var paymentAddress = await rpc.GetNewAddressAsync();
            var changeAddress = await rpc.GetNewAddressAsync();
            var paymentAmount = Money.Coins(0.5m);
            
            spendingTx.Outputs.Add(paymentAmount, paymentAddress);
            
            // Use multiSig's size estimation for more accurate fee
            var estimatedVSize = multiSig.EstimateVirtualSize();
            var feeRate = new FeeRate(Money.Satoshis(10), 1);
            var estimatedFee = feeRate.GetFee(estimatedVSize);
            var changeAmount = fundingAmount - paymentAmount - estimatedFee;
            spendingTx.Outputs.Add(changeAmount, changeAddress);
            
            // Sign using standard TransactionBuilder approach
            var coin = multiSig.CreateCoin(new Coin(fundingOutput));
            var builder = Network.RegTest.CreateTransactionBuilder();
            builder.AddCoins(coin);
            
            // Add first k signers
            var selectedSigners = signerKeys.Take(k).ToList();
            foreach (var signer in selectedSigners)
            {
                builder.AddKeys(signer);
            }
            
            // Sign and broadcast
            var signedTx = builder.SignTransaction(spendingTx);
            var broadcastTxId = await rpc.SendRawTransactionAsync(signedTx);
            
            // Get actual transaction details
            var actualTx = await rpc.GetRawTransactionAsync(broadcastTxId);
            
            return new TransactionResult
            {
                Success = true,
                VirtualSize = actualTx.GetVirtualSize(),
                TxId = broadcastTxId.ToString()
            };
        }
        
        private async Task<TransactionResult> ExecuteStandardMultisig(List<Key> signerKeys, int k, RPCClient rpc)
        {
            // Standard NBitcoin multisig approach for comparison
            var pubKeys = signerKeys.Select(key => key.PubKey).ToArray();
            var multiSigScript = PayToMultiSigTemplate.Instance.GenerateScriptPubKey(k, pubKeys);
            var p2wsh = multiSigScript.WitHash.ScriptPubKey;
            var p2shP2wsh = p2wsh.Hash.ScriptPubKey;
            var address = p2shP2wsh.GetDestinationAddress(Network.RegTest);
            
            // Fund the multisig address
            var fundingAmount = Money.Coins(1.0m);
            var fundingTxId = await rpc.SendToAddressAsync(address, fundingAmount);
            var fundingTx = await rpc.GetRawTransactionAsync(fundingTxId);
            var fundingOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == p2shP2wsh);
            
            // Create spending transaction
            var spendingTx = Network.RegTest.CreateTransaction();
            spendingTx.Inputs.Add(new TxIn(new OutPoint(fundingTxId, fundingOutput.N)));
            
            var paymentAddress = await rpc.GetNewAddressAsync();
            var changeAddress = await rpc.GetNewAddressAsync();
            var paymentAmount = Money.Coins(0.5m);
            
            spendingTx.Outputs.Add(paymentAmount, paymentAddress);
            var feeRate = new FeeRate(Money.Satoshis(10), 1);
            var estimatedFee = feeRate.GetFee(300 + k * 75);
            var changeAmount = fundingAmount - paymentAmount - estimatedFee;
            spendingTx.Outputs.Add(changeAmount, changeAddress);
            
            // Sign using standard TransactionBuilder
            var coin = new ScriptCoin(fundingOutput, multiSigScript);
            var builder = Network.RegTest.CreateTransactionBuilder();
            builder.AddCoins(coin);
            
            // Add k signatures (take first k signers)
            for (int i = 0; i < k; i++)
            {
                builder.AddKeys(signerKeys[i]);
            }
            
            var signedTx = builder.SignTransaction(spendingTx);
            var broadcastTxId = await rpc.SendRawTransactionAsync(signedTx);
            var actualTx = await rpc.GetRawTransactionAsync(uint256.Parse(broadcastTxId.ToString()));
            
            return new TransactionResult
            {
                Success = true,
                VirtualSize = actualTx.GetVirtualSize(),
                TxId = broadcastTxId.ToString()
            };
        }
        
        private class TransactionResult
        {
            public bool Success { get; set; }
            public int VirtualSize { get; set; }
            public string TxId { get; set; }
        }
    }
}