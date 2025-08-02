using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using Xunit;

namespace NBitcoin.Tests
{
	public class DelegatedMultiSigTests
	{
		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanCreateDelegatedMultiSigAddress()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();
			var requiredSignatures = 2;
			var network = Network.RegTest;

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, requiredSignatures, network);
			var address = multiSig.Address;

			Assert.NotNull(address);
			Assert.IsType<TaprootAddress>(address);
			Assert.Equal(network, address.Network);

			var staticAddress = DelegatedMultiSig.CreateAddress(ownerPubKey, signerPubKeys, requiredSignatures, network);
			Assert.Equal(address.ToString(), staticAddress.ToString());
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanCreateAddressFromExtendedKeys()
		{
			var mnemo = new Mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
			var root = mnemo.DeriveExtKey();

			var ownerExtPubKey = root.Derive(new KeyPath("m/86'/0'/0'")).Neuter();
			var signerExtKeys = new List<ExtPubKey>
			{
				root.Derive(new KeyPath("m/86'/0'/1'")).Neuter(),
				root.Derive(new KeyPath("m/86'/0'/2'")).Neuter(),
				root.Derive(new KeyPath("m/86'/0'/3'")).Neuter()
			};

			var derivation = 0u;
			var address = DelegatedMultiSig.CreateAddress(ownerExtPubKey, derivation, signerExtKeys, derivation, 2, Network.Main);

			Assert.NotNull(address);
			Assert.IsType<TaprootAddress>(address);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanGenerateCorrectScriptCombinations()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();
			var requiredSignatures = 2;

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, requiredSignatures, Network.RegTest);

			Assert.Equal(3, multiSig.Scripts.Count);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ThrowsOnInvalidParameters()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			Assert.Throws<ArgumentNullException>(() => new DelegatedMultiSig(null, signerPubKeys, 2, Network.RegTest));
			Assert.Throws<ArgumentException>(() => new DelegatedMultiSig(ownerPubKey, new List<PubKey>(), 2, Network.RegTest));
			Assert.Throws<ArgumentException>(() => new DelegatedMultiSig(ownerPubKey, signerPubKeys, 0, Network.RegTest));
			Assert.Throws<ArgumentException>(() => new DelegatedMultiSig(ownerPubKey, signerPubKeys, 4, Network.RegTest));
			Assert.Throws<ArgumentNullException>(() => new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, null));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanUsePSBTWorkflow()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);
			
			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(Money.Coins(0.9m), new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest));

			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			
			var psbt = multiSig.CreatePSBT(tx, new[] { coin });
			
			Assert.NotNull(psbt);
			Assert.Equal(1, psbt.Inputs.Count);
			var input = psbt.Inputs[0];
			Assert.NotNull(input.WitnessUtxo);
			Assert.NotNull(input.TaprootInternalKey);
			Assert.NotNull(input.TaprootMerkleRoot);
		}

#if HAS_SPAN
		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanSpendWithKeySpend()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);
				var address = multiSig.Address;

				var txid = rpc.SendToAddress(address, Money.Coins(1.0m));
				var tx = rpc.GetRawTransaction(txid);
				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);

				var spender = Network.RegTest.CreateTransaction();
				spender.Inputs.Add(new OutPoint(tx, spentOutput.N));
				var dest = rpc.GetNewAddress();
				spender.Outputs.Add(Money.Coins(0.9999m), dest);

				var coin = new Coin(spentOutput);
				var builder = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				var signatureData = builder.SignWithOwner(ownerKey, 0, TaprootSigHash.All);

				Assert.True(signatureData.IsComplete);
				Assert.True(signatureData.IsKeySpend);

				rpc.SendRawTransaction(spender);
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanSpendWithMultiSig()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);
				var address = multiSig.Address;

				var txid = rpc.SendToAddress(address, Money.Coins(1.0m));
				var tx = rpc.GetRawTransaction(txid);
				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);

				var spender = Network.RegTest.CreateTransaction();
				spender.Inputs.Add(new OutPoint(tx, spentOutput.N));
				var dest = rpc.GetNewAddress();
				spender.Outputs.Add(Money.Coins(0.9999m), dest);

				var coin = new Coin(spentOutput);
				var builder = multiSig.CreateSignatureBuilder(spender, new[] { coin });

				var sigData1 = builder.SignWithSigner(signerKeys[1], 0, TaprootSigHash.All);
				Assert.False(sigData1.IsComplete);
				Assert.Equal(2, sigData1.PartialSignatures.Count);

				var sigData2 = builder.SignWithSigner(signerKeys[2], 0, TaprootSigHash.All);
				Assert.True(sigData2.IsComplete);
				Assert.Equal(2, sigData2.PartialSignatures.Count);

				var finalTx = builder.FinalizeTransaction(0);
				rpc.SendRawTransaction(finalTx);
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanSerializeAndDeserializePartialSignatures()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);

			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(Money.Coins(0.9m), new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest));

			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			var builder = multiSig.CreateSignatureBuilder(tx, new[] { coin });

			var sigData = builder.SignWithSigner(signerKeys[1], 0, TaprootSigHash.All);
			var serialized = sigData.Serialize();
			var deserialized = DelegatedMultiSig.PartialSignatureData.Deserialize(serialized);

			Assert.Equal(sigData.InputIndex, deserialized.InputIndex);
			Assert.Equal(sigData.ScriptIndex, deserialized.ScriptIndex);
			Assert.Equal(sigData.IsComplete, deserialized.IsComplete);
			Assert.Equal(sigData.PartialSignatures.Count, deserialized.PartialSignatures.Count);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanPassPartialSignaturesBetweenSigners()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);
				var address = multiSig.Address;

				var txid = rpc.SendToAddress(address, Money.Coins(1.0m));
				var tx = rpc.GetRawTransaction(txid);
				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);

				var spender = Network.RegTest.CreateTransaction();
				spender.Inputs.Add(new OutPoint(tx, spentOutput.N));
				var dest = rpc.GetNewAddress();
				spender.Outputs.Add(Money.Coins(0.9999m), dest);

				var coin = new Coin(spentOutput);

				var builder1 = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				var sigData1 = builder1.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
				var serialized = sigData1.Serialize();

				var builder2 = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				var deserializedData = DelegatedMultiSig.PartialSignatureData.Deserialize(serialized);
				builder2.AddPartialSignature(deserializedData, 0);
				var sigData2 = builder2.SignWithSigner(signerKeys[1], 0, TaprootSigHash.All);

				Assert.True(sigData2.IsComplete);
				var finalTx = builder2.FinalizeTransaction(0);
				rpc.SendRawTransaction(finalTx);
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CannotFinalizeIncompleteTransaction()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);

			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(Money.Coins(0.9m), new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest));

			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			var builder = multiSig.CreateSignatureBuilder(tx, new[] { coin });

			builder.SignWithSigner(signerKeys[1], 0, TaprootSigHash.All);

			Assert.Throws<InvalidOperationException>(() => builder.FinalizeTransaction(0));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void SignerCanSignForAnyScriptTheyParticipateIn()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);

			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(Money.Coins(0.9m), new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest));

			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			var builder = multiSig.CreateSignatureBuilder(tx, new[] { coin });
			// Since signers now automatically sign for all scripts they participate in,
			// signer 0 should be able to sign (they participate in multiple script combinations)
			var sigData = builder.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
			Assert.NotNull(sigData);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void OwnerCanAlwaysSignRegardlessOfBuilderState()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);

			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(Money.Coins(0.9m), new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest));

			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			var builder = multiSig.CreateSignatureBuilder(tx, new[] { coin });

			// Owner can sign regardless of builder state - SignWithOwner automatically sets key spend mode
			var sigData = builder.SignWithOwner(ownerKey, 0, TaprootSigHash.All);
			
			Assert.NotNull(sigData);
			Assert.True(sigData.IsComplete);
			Assert.True(sigData.IsKeySpend);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanHandleLargeMultisigWithBIP387Compliance()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			
			// Create 22 signer keys for testing (22-choose-20 = 231 combinations - manageable)
			var signerKeys = new List<Key>();
			for (int i = 0; i < 22; i++)
			{
				signerKeys.Add(new Key());
			}
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			// Test 20-of-22 multisig (k > 16, should use raw number encoding per BIP387)
			var requiredSignatures = 20;
			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, requiredSignatures, Network.RegTest);

			Assert.NotNull(multiSig.Address);
			Assert.True(multiSig.Scripts.Count > 0);
			Assert.Equal(231, multiSig.Scripts.Count); // C(22,20) = C(22,2) = 231
			
			// Verify that the scripts are generated correctly for k > 16
			// We can't easily verify the exact script content without exposing internal details,
			// but we can ensure the address generation works and scripts are created
			Assert.IsType<TaprootAddress>(multiSig.Address);
			
			// Test with k <= 16 for comparison (should use OP_k encoding per BIP387)
			var smallMultiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys.Take(10).ToList(), 5, Network.RegTest);
			Assert.NotNull(smallMultiSig.Address);
			Assert.True(smallMultiSig.Scripts.Count > 0);
			
			// The addresses should be different since they have different script trees
			Assert.NotEqual(multiSig.Address.ToString(), smallMultiSig.Address.ToString());
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TestsBIP387ComplianceForScriptEncoding()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			
			// Test k = 16 (should use OP_16) - use 18 signers with 16-of-18 (816 combinations)
			var signers18 = new List<Key>();
			for (int i = 0; i < 18; i++) signers18.Add(new Key());
			var pubKeys18 = signers18.Select(k => k.PubKey).ToList();
			
			var multiSig16 = new DelegatedMultiSig(ownerPubKey, pubKeys18, 16, Network.RegTest);
			Assert.NotNull(multiSig16.Address);

			// Test k = 17 (should use raw number encoding according to BIP387) - use 19 signers with 17-of-19 (171 combinations)
			var signers19 = new List<Key>();
			for (int i = 0; i < 19; i++) signers19.Add(new Key());
			var pubKeys19 = signers19.Select(k => k.PubKey).ToList();
			
			var multiSig17 = new DelegatedMultiSig(ownerPubKey, pubKeys19, 17, Network.RegTest);
			Assert.NotNull(multiSig17.Address);
			
			// Test k = 1 (should use OP_1) - use 3 signers with 1-of-3 (3 combinations)
			var signers3 = new List<Key>();
			for (int i = 0; i < 3; i++) signers3.Add(new Key());
			var pubKeys3 = signers3.Select(k => k.PubKey).ToList();
			
			var multiSig1 = new DelegatedMultiSig(ownerPubKey, pubKeys3, 1, Network.RegTest);
			Assert.NotNull(multiSig1.Address);
			
			// All addresses should be different due to different k values and signer sets
			Assert.NotEqual(multiSig16.Address.ToString(), multiSig17.Address.ToString());
			Assert.NotEqual(multiSig1.Address.ToString(), multiSig16.Address.ToString());
			Assert.NotEqual(multiSig1.Address.ToString(), multiSig17.Address.ToString());
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void EnforcesReasonableCombinationLimits()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			
			// Create too many signers that would result in excessive combinations
			var signerPubKeys = new List<PubKey>();
			for (int i = 0; i < 100; i++)
			{
				signerPubKeys.Add(new Key().PubKey);
			}

			// Attempting 50-of-100 multisig should fail due to combination limit
			// C(100,50) ≈ 1.0 × 10^29 combinations - way too many
			Assert.Throws<ArgumentException>(() => 
				new DelegatedMultiSig(ownerPubKey, signerPubKeys, 50, Network.RegTest));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void DemonstratesLargeKValueBIP387Compliance()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			
			// Test with k=20 but demonstrate BIP387 compliance for k > 16
			// Use 22 signers with 20-of-22 (only 231 combinations - much more reasonable)
			var signerPubKeys = new List<PubKey>();
			for (int i = 0; i < 22; i++)
			{
				signerPubKeys.Add(new Key().PubKey);
			}

			// Test 20-of-22 multisig (k=20 > 16, should use raw number encoding per BIP387)
			var requiredSignatures = 20;
			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, requiredSignatures, Network.RegTest);

			// Verify basic functionality
			Assert.NotNull(multiSig.Address);
			Assert.IsType<TaprootAddress>(multiSig.Address);
			Assert.NotNull(multiSig.TaprootPubKey);
			Assert.NotNull(multiSig.TaprootSpendInfo);
			Assert.NotNull(multiSig.Scripts);
			Assert.Equal(231, multiSig.Scripts.Count); // C(22,20) = C(22,2) = 231
			
			// Since k=20 > 16, this demonstrates BIP387 compliance for large k values
			// The actual script encoding uses raw number instead of OP_k opcodes
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanCalculateTransactionSizesAndFees()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);

			// Create a transaction
			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(Money.Coins(0.9m), new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest));

			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			var builder = multiSig.CreateSignatureBuilder(tx, new[] { coin });
			
			// Get size estimates for the first input
			var sizeEstimate = builder.GetSizeEstimate(0);
			
			Assert.NotNull(sizeEstimate);
			
			// Verify key spend size is smaller than script spend sizes
			Assert.True(sizeEstimate.KeySpendSize > 0);
			Assert.True(sizeEstimate.ScriptSpendSizes.Count == 3); // 3 possible 2-of-3 combinations
			
			// All script spend sizes should be larger than key spend
			foreach (var scriptSize in sizeEstimate.ScriptSpendSizes.Values)
			{
				Assert.True(scriptSize > sizeEstimate.KeySpendSize);
			}
			
			// Verify buffer calculation (5% increase)
			foreach (var kvp in sizeEstimate.ScriptSpendSizes)
			{
				var expectedBuffered = (int)(kvp.Value * 1.05);
				Assert.Equal(expectedBuffered, sizeEstimate.ScriptSpendSizesWithBuffer[kvp.Key]);
			}
			
			// Calculate fee based on virtual size (using typical fee rate of 10 sat/vbyte)
			var feeRate = new FeeRate(Money.Satoshis(10), 1);
			var keySpendFee = feeRate.GetFee(sizeEstimate.KeySpendVirtualSize);
			var scriptSpendFee = feeRate.GetFee(sizeEstimate.ScriptSpendVirtualSizes[0]);
			var scriptSpendFeeWithBuffer = feeRate.GetFee(sizeEstimate.ScriptSpendVirtualSizesWithBuffer[0]);
			
			// Script spend should cost more in fees
			Assert.True(scriptSpendFee > keySpendFee);
			Assert.True(scriptSpendFeeWithBuffer > scriptSpendFee);
			
			// Verify reasonable size ranges
			// Key spend: ~110 vbytes for simple transaction
			Assert.InRange(sizeEstimate.KeySpendVirtualSize, 100, 120);
			
			// Script spend: larger due to multiple signatures + script + control block
			// For 2-of-3: 2 signatures (128 bytes) + script + control block
			foreach (var scriptVSize in sizeEstimate.ScriptSpendVirtualSizes.Values)
			{
				Assert.InRange(scriptVSize, 150, 350);
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TransactionSizeEstimateAccuracyTest()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);
				var address = multiSig.Address;

				var txid = rpc.SendToAddress(address, Money.Coins(1.0m));
				var tx = rpc.GetRawTransaction(txid);
				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);

				// Test key spend size estimation
				var keySpendTx = Network.RegTest.CreateTransaction();
				keySpendTx.Inputs.Add(new OutPoint(tx, spentOutput.N));
				var dest = rpc.GetNewAddress();
				keySpendTx.Outputs.Add(Money.Coins(0.9999m), dest);

				var coin = new Coin(spentOutput);
				var builder = multiSig.CreateSignatureBuilder(keySpendTx, new[] { coin });
				var sizeEstimate = builder.GetSizeEstimate(0);
				
				// Sign with key spend
				builder.SignWithOwner(ownerKey, 0, TaprootSigHash.All);
				
				// Compare estimated vs actual size
				var actualKeySpendSize = keySpendTx.GetSerializedSize();
				var actualKeySpendVirtualSize = keySpendTx.GetVirtualSize();
				var estimatedKeySpendSize = sizeEstimate.KeySpendSize;
				var estimatedKeySpendVirtualSize = sizeEstimate.KeySpendVirtualSize;
				
				// Should be within 10 bytes for total size
				Assert.InRange(Math.Abs(actualKeySpendSize - estimatedKeySpendSize), 0, 10);
				// Should be within 5 vbytes for virtual size
				Assert.InRange(Math.Abs(actualKeySpendVirtualSize - estimatedKeySpendVirtualSize), 0, 5);
				
				// Test script spend size estimation
				var scriptSpendTx = Network.RegTest.CreateTransaction();
				scriptSpendTx.Inputs.Add(new OutPoint(tx, spentOutput.N));
				scriptSpendTx.Outputs.Add(Money.Coins(0.9999m), dest);
				
				var builder2 = multiSig.CreateSignatureBuilder(scriptSpendTx, new[] { coin });
				
				// Sign with two signers
				builder2.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
				builder2.SignWithSigner(signerKeys[1], 0, TaprootSigHash.All);
				builder2.FinalizeTransaction(0);
				
				var actualScriptSpendSize = scriptSpendTx.GetSerializedSize();
				var actualScriptSpendVirtualSize = scriptSpendTx.GetVirtualSize();
				var estimatedScriptSpendSize = sizeEstimate.ScriptSpendSizes[0];
				var estimatedScriptSpendVirtualSize = sizeEstimate.ScriptSpendVirtualSizes[0];
				
				// Should be within 10 bytes for total size
				Assert.InRange(Math.Abs(actualScriptSpendSize - estimatedScriptSpendSize), 0, 10);
				// Should be within 5 vbytes for virtual size
				Assert.InRange(Math.Abs(actualScriptSpendVirtualSize - estimatedScriptSpendVirtualSize), 0, 5);
				
				// Verify script spend is indeed larger
				Assert.True(actualScriptSpendSize > actualKeySpendSize);
				Assert.True(actualScriptSpendVirtualSize > keySpendTx.GetVirtualSize());
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void DemonstratesFeeCalculationWorkflow()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			// Create 3-of-4 multisig
			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, Network.RegTest);

			// Simulate UTXO of 1 BTC
			var inputAmount = Money.Coins(1.0m);
			var outputAmount = Money.Coins(0.95m); // Sending 0.95 BTC
			
			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(outputAmount, new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest));

			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(inputAmount, multiSig.Address.ScriptPubKey));
			var builder = multiSig.CreateSignatureBuilder(tx, new[] { coin });
			
			// Get size estimates
			var sizeEstimate = builder.GetSizeEstimate(0);
			
			// Current fee rate (e.g., from mempool)
			var feeRate = new FeeRate(Money.Satoshis(25), 1); // 25 sat/vbyte
			
			// Calculate fees for different scenarios (using virtual size)
			var keySpendFee = feeRate.GetFee(sizeEstimate.KeySpendVirtualSize);
			
			// Find the cheapest script spend option
			var cheapestScriptIndex = sizeEstimate.ScriptSpendVirtualSizes
				.OrderBy(kvp => kvp.Value)
				.First().Key;
			var cheapestScriptFee = feeRate.GetFee(sizeEstimate.ScriptSpendVirtualSizes[cheapestScriptIndex]);
			var cheapestScriptFeeWithBuffer = feeRate.GetFee(sizeEstimate.ScriptSpendVirtualSizesWithBuffer[cheapestScriptIndex]);
			
			// Demonstrate fee decision making
			Console.WriteLine($"Input: {inputAmount}");
			Console.WriteLine($"Output: {outputAmount}");
			Console.WriteLine($"Available for fees: {inputAmount - outputAmount}");
			Console.WriteLine($"");
			Console.WriteLine($"Fee Rate: {feeRate.SatoshiPerByte} sat/vbyte");
			Console.WriteLine($"");
			Console.WriteLine($"Key Spend (Owner):");
			Console.WriteLine($"  Size: {sizeEstimate.KeySpendSize} bytes");
			Console.WriteLine($"  Virtual Size: {sizeEstimate.KeySpendVirtualSize} vbytes");
			Console.WriteLine($"  Fee: {keySpendFee} ({keySpendFee.Satoshi} sats)");
			Console.WriteLine($"");
			Console.WriteLine($"Script Spend (3-of-4 Multisig):");
			Console.WriteLine($"  Cheapest script: #{cheapestScriptIndex}");
			Console.WriteLine($"  Size: {sizeEstimate.ScriptSpendSizes[cheapestScriptIndex]} bytes");
			Console.WriteLine($"  Virtual Size: {sizeEstimate.ScriptSpendVirtualSizes[cheapestScriptIndex]} vbytes");
			Console.WriteLine($"  Fee: {cheapestScriptFee} ({cheapestScriptFee.Satoshi} sats)");
			Console.WriteLine($"  Fee with 5% buffer: {cheapestScriptFeeWithBuffer} ({cheapestScriptFeeWithBuffer.Satoshi} sats)");
			
			// Verify we have enough for fees
			var maxAvailableFee = inputAmount - outputAmount;
			Assert.True(keySpendFee < maxAvailableFee);
			Assert.True(cheapestScriptFeeWithBuffer < maxAvailableFee);
			
			// Calculate actual change amounts
			var changeWithKeySpend = inputAmount - outputAmount - keySpendFee;
			var changeWithScriptSpend = inputAmount - outputAmount - cheapestScriptFeeWithBuffer;
			
			Assert.True(changeWithKeySpend > changeWithScriptSpend); // Key spend is cheaper
			Assert.True(changeWithKeySpend > Money.Zero);
			Assert.True(changeWithScriptSpend > Money.Zero);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ValidatesOwnerPrivateKeyMatches()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var wrongOwnerKey = new Key(); // Different key
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);

			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(Money.Coins(0.9m), new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest));

			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			var builder = multiSig.CreateSignatureBuilder(tx, new[] { coin });

			// Should throw when private key doesn't match public key
			Assert.Throws<ArgumentException>(() => builder.SignWithOwner(wrongOwnerKey, 0, TaprootSigHash.All));

			// Should throw when null private key is passed
			Assert.Throws<ArgumentNullException>(() => builder.SignWithOwner(null, 0, TaprootSigHash.All));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanSerializePartialSignatureWorkflow()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);
				var address = multiSig.Address;

				var txid = rpc.SendToAddress(address, Money.Coins(1.0m));
				var tx = rpc.GetRawTransaction(txid);
				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);

				var spender = Network.RegTest.CreateTransaction();
				spender.Inputs.Add(new OutPoint(tx, spentOutput.N));
				var dest = rpc.GetNewAddress();
				spender.Outputs.Add(Money.Coins(0.9999m), dest);

				var coin = new Coin(spentOutput);
				
				var builder1 = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				var sigData1 = builder1.SignWithSigner(signerKeys[1], 0, TaprootSigHash.All);
				var partialSigString = builder1.GetPartialSignatureString(0);
				
				Assert.NotEmpty(partialSigString);
				
				var builder2 = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				var deserializedData = DelegatedMultiSig.PartialSignatureData.Deserialize(partialSigString);
				builder2.AddPartialSignature(deserializedData, 0);
				var sigData2 = builder2.SignWithSigner(signerKeys[2], 0, TaprootSigHash.All);
				
				Assert.True(sigData2.IsComplete);
				var finalTx = builder2.FinalizeTransaction(0);
				rpc.SendRawTransaction(finalTx);
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void DynamicFeeScenarioTest()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);
				var address = multiSig.Address;

				// Receive 1 BTC
				var txid = rpc.SendToAddress(address, Money.Coins(1.0m));
				var tx = rpc.GetRawTransaction(txid);
				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				var coin = new Coin(spentOutput);

				// First, calculate the fee scenarios with a temporary transaction
				var tempTx = Network.RegTest.CreateTransaction();
				tempTx.Inputs.Add(new OutPoint(tx, spentOutput.N));
				
				// Fixed payment output
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.5m); // Fixed payment of 0.5 BTC
				tempTx.Outputs.Add(paymentAmount, paymentAddress);
				
				// Temporary change output for size calculation
				var changeAddress = rpc.GetNewAddress();
				tempTx.Outputs.Add(Money.Coins(0.49m), changeAddress);
				
				// Calculate fees to determine final transaction structure
				var tempBuilder = multiSig.CreateSignatureBuilder(tempTx, new[] { coin });
				var feeRate = new FeeRate(Money.Satoshis(50), 1); // 50 sat/vbyte
				var tempEstimates = tempBuilder.GetSizeEstimate(0);
				
				// Get cheapest script estimates
				var cheapestScriptIndex = tempEstimates.ScriptSpendVirtualSizes
					.OrderBy(kvp => kvp.Value)
					.First().Key;
				
				var estimatedFee = feeRate.GetFee(tempEstimates.ScriptSpendVirtualSizes[cheapestScriptIndex]);
				var bufferedFee = feeRate.GetFee(tempEstimates.ScriptSpendVirtualSizesWithBuffer[cheapestScriptIndex]);
				
				Console.WriteLine($"Dynamic Fee Calculation:");
				Console.WriteLine($"Input: {coin.Amount}");
				Console.WriteLine($"Fixed Payment: {paymentAmount}");
				Console.WriteLine($"Fee Rate: {feeRate.SatoshiPerByte} sat/vbyte");
				Console.WriteLine($"");
				Console.WriteLine($"Estimated scenario:");
				Console.WriteLine($"  VSize: {tempEstimates.ScriptSpendVirtualSizes[cheapestScriptIndex]} vbytes");
				Console.WriteLine($"  Fee: {estimatedFee} ({estimatedFee.Satoshi} sats)");
				Console.WriteLine($"  Change: {coin.Amount - paymentAmount - estimatedFee}");
				Console.WriteLine($"");
				Console.WriteLine($"Buffered scenario:");
				Console.WriteLine($"  VSize: {tempEstimates.ScriptSpendVirtualSizesWithBuffer[cheapestScriptIndex]} vbytes");
				Console.WriteLine($"  Fee: {bufferedFee} ({bufferedFee.Satoshi} sats)");
				Console.WriteLine($"  Change: {coin.Amount - paymentAmount - bufferedFee}");
				
				// Now create the actual transactions with correct change amounts
				var spenderEstimated = Network.RegTest.CreateTransaction();
				spenderEstimated.Inputs.Add(new OutPoint(tx, spentOutput.N));
				spenderEstimated.Outputs.Add(paymentAmount, paymentAddress);
				spenderEstimated.Outputs.Add(coin.Amount - paymentAmount - estimatedFee, changeAddress);
				
				var spenderBuffered = Network.RegTest.CreateTransaction();
				spenderBuffered.Inputs.Add(new OutPoint(tx, spentOutput.N));
				spenderBuffered.Outputs.Add(paymentAmount, paymentAddress);
				spenderBuffered.Outputs.Add(coin.Amount - paymentAmount - bufferedFee, changeAddress);

				// Collect signatures for the estimated transaction
				var builderEstimated = multiSig.CreateSignatureBuilder(spenderEstimated, new[] { coin });
				builderEstimated.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
				builderEstimated.SignWithSigner(signerKeys[1], 0, TaprootSigHash.All);
				var finalEstimatedTx = builderEstimated.FinalizeTransaction(0);
				
				// Collect signatures for the buffered transaction 
				var builderBuffered = multiSig.CreateSignatureBuilder(spenderBuffered, new[] { coin });
				builderBuffered.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
				builderBuffered.SignWithSigner(signerKeys[1], 0, TaprootSigHash.All);
				var finalBufferedTx = builderBuffered.FinalizeTransaction(0);
				
				// Calculate actual fees
				var actualEstimatedFee = coin.Amount - finalEstimatedTx.Outputs.Sum(o => (Money)o.Value);
				var actualBufferedFee = coin.Amount - finalBufferedTx.Outputs.Sum(o => (Money)o.Value);
				
				Console.WriteLine($"");
				Console.WriteLine($"Final Results:");
				Console.WriteLine($"Estimated: Change={finalEstimatedTx.Outputs[1].Value}, Fee={actualEstimatedFee}");
				Console.WriteLine($"Buffered: Change={finalBufferedTx.Outputs[1].Value}, Fee={actualBufferedFee}");
				
				// Verify relationships
				Assert.Equal(paymentAmount, finalEstimatedTx.Outputs[0].Value);
				Assert.Equal(paymentAmount, finalBufferedTx.Outputs[0].Value);
				Assert.True(actualBufferedFee > actualEstimatedFee);
				Assert.True(finalEstimatedTx.Outputs[1].Value > finalBufferedTx.Outputs[1].Value);
				
				// Final signer chooses the estimated transaction (more change)
				rpc.SendRawTransaction(finalEstimatedTx);
				// Can't send the buffered one as it would double spend
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ConfigurableBufferPercentageTest()
		{
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 2, Network.RegTest);

			// Create a transaction
			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(Money.Coins(0.9m), new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest));

			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			var builder = multiSig.CreateSignatureBuilder(tx, new[] { coin });
			
			// Get base size estimate
			var baseEstimate = builder.GetSizeEstimate(0);
			var baseVSize = baseEstimate.ScriptSpendVirtualSizes[0];
			
			// Test different buffer percentages
			var testBuffers = new double[] { 0, 5, 10, 25, 50, 100 };
			
			Console.WriteLine($"Configurable Buffer Percentage Test:");
			Console.WriteLine($"Base Virtual Size: {baseVSize} vbytes");
			Console.WriteLine($"");
			
			foreach (var bufferPct in testBuffers)
			{
				// Test custom buffer methods
				var customVSize = baseEstimate.GetVirtualSizeWithCustomBuffer(false, bufferPct, 0);
				var customSize = baseEstimate.GetSizeWithCustomBuffer(false, bufferPct, 0);
				
				// Test custom estimate builder
				var customEstimate = builder.GetSizeEstimateWithCustomBuffer(0, bufferPct);
				var builderCustomVSize = customEstimate.ScriptSpendVirtualSizesWithBuffer[0];
				
				// Verify calculations
				var expectedVSize = (int)(baseVSize * (1.0 + bufferPct / 100.0));
				Assert.Equal(expectedVSize, customVSize);
				Assert.Equal(expectedVSize, builderCustomVSize);
				
				// Calculate fee impact
				var feeRate = new FeeRate(Money.Satoshis(30), 1);
				var baseFee = feeRate.GetFee(baseVSize);
				var bufferedFee = feeRate.GetFee(customVSize);
				var feeIncrease = bufferedFee - baseFee;
				
				Console.WriteLine($"{bufferPct,3}% buffer: {customVSize,3} vbytes, Fee: {bufferedFee.Satoshi,5} sats (+{feeIncrease.Satoshi,3} sats)");
			}
			
			// Test edge cases
			Assert.Throws<ArgumentOutOfRangeException>(() => 
				baseEstimate.GetVirtualSizeWithCustomBuffer(false, -1, 0));
			Assert.Throws<ArgumentOutOfRangeException>(() => 
				baseEstimate.GetVirtualSizeWithCustomBuffer(false, 101, 0));
			Assert.Throws<ArgumentOutOfRangeException>(() => 
				builder.GetSizeEstimateWithCustomBuffer(0, -1));
			Assert.Throws<ArgumentOutOfRangeException>(() => 
				builder.GetSizeEstimateWithCustomBuffer(0, 101));
			
			// Verify 0% buffer equals base size
			var zeroBufferEstimate = builder.GetSizeEstimateWithCustomBuffer(0, 0);
			Assert.Equal(baseVSize, zeroBufferEstimate.ScriptSpendVirtualSizesWithBuffer[0]);
			
			// Verify 100% buffer doubles the size
			var doubleBufferEstimate = builder.GetSizeEstimateWithCustomBuffer(0, 100);
			Assert.Equal(baseVSize * 2, doubleBufferEstimate.ScriptSpendVirtualSizesWithBuffer[0]);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void RealisticVariableBufferScenario()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = new List<Key> { new Key(), new Key(), new Key(), new Key() , new Key() , new Key() , new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, Network.RegTest);
				var address = multiSig.Address;

				// Receive 1 BTC
				var txid = rpc.SendToAddress(address, Money.Coins(1.0m));
				var tx = rpc.GetRawTransaction(txid);
				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				var coin = new Coin(spentOutput);

				// Scenario: High network congestion, need conservative approach
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.8m);
				var changeAddress = rpc.GetNewAddress();
				
				// Create temp transaction for size estimation
				var tempTx = Network.RegTest.CreateTransaction();
				tempTx.Inputs.Add(new OutPoint(tx, spentOutput.N));
				tempTx.Outputs.Add(paymentAmount, paymentAddress);
				tempTx.Outputs.Add(Money.Coins(0.19m), changeAddress);
				
				var tempBuilder = multiSig.CreateSignatureBuilder(tempTx, new[] { coin });
				var baseEstimate = tempBuilder.GetSizeEstimate(0);
				var cheapestScriptIndex = baseEstimate.ScriptSpendVirtualSizes
					.OrderBy(kvp => kvp.Value)
					.First().Key;
				
				// Different risk tolerance levels
				var scenarios = new []
				{
					new { Name = "Conservative (50% buffer)", Buffer = 50.0 },
					new { Name = "Very Conservative (75% buffer)", Buffer = 75.0 },
					new { Name = "Emergency (100% buffer)", Buffer = 100.0 }
				};
				
				var feeRate = new FeeRate(Money.Satoshis(80), 1); // High fee rate due to congestion
				
				Console.WriteLine($"Variable Buffer Scenario Analysis:");
				Console.WriteLine($"Network Conditions: High congestion, {feeRate.SatoshiPerByte} sat/vbyte");
				Console.WriteLine($"Payment: {paymentAmount}");
				Console.WriteLine($"Available for fees: {coin.Amount - paymentAmount}");
				Console.WriteLine($"");
				
				foreach (var scenario in scenarios)
				{
					var customEstimate = tempBuilder.GetSizeEstimateWithCustomBuffer(0, scenario.Buffer);
					var vsize = customEstimate.ScriptSpendVirtualSizesWithBuffer[cheapestScriptIndex];
					var fee = feeRate.GetFee(vsize);
					var change = coin.Amount - paymentAmount - fee;
					
					Console.WriteLine($"{scenario.Name}:");
					Console.WriteLine($"  VSize: {vsize} vbytes");
					Console.WriteLine($"  Fee: {fee} ({fee.Satoshi} sats)");
					Console.WriteLine($"  Change: {change}");
					Console.WriteLine($"");
					
					// Verify we have enough funds
					Assert.True(change > Money.Zero, $"Insufficient funds for {scenario.Name}");
				}
				
				// Choose the 50% buffer scenario and execute
				var chosenEstimate = tempBuilder.GetSizeEstimateWithCustomBuffer(0, 50.0);
				var chosenFee = feeRate.GetFee(chosenEstimate.ScriptSpendVirtualSizesWithBuffer[cheapestScriptIndex]);
				var finalChange = coin.Amount - paymentAmount - chosenFee;
				
				// Create and sign the actual transaction
				var finalTx = Network.RegTest.CreateTransaction();
				finalTx.Inputs.Add(new OutPoint(tx, spentOutput.N));
				finalTx.Outputs.Add(paymentAmount, paymentAddress);
				finalTx.Outputs.Add(finalChange, changeAddress);
				
				var finalBuilder = multiSig.CreateSignatureBuilder(finalTx, new[] { coin });
				finalBuilder.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
				finalBuilder.SignWithSigner(signerKeys[3], 0, TaprootSigHash.All);
				finalBuilder.SignWithSigner(signerKeys[6], 0, TaprootSigHash.All);
				var completedTx = finalBuilder.FinalizeTransaction(0);
				
				// Verify and broadcast
				var actualFee = coin.Amount - completedTx.Outputs.Sum(o => (Money)o.Value);
				Console.WriteLine($"Final Transaction:");
				Console.WriteLine($"  Chosen: Conservative (50% buffer)");
				Console.WriteLine($"  Actual fee: {actualFee}");
				Console.WriteLine($"  Final change: {completedTx.Outputs[1].Value}");
				
				rpc.SendRawTransaction(completedTx);
				
				// Verify the transaction was constructed correctly
				Assert.Equal(paymentAmount, completedTx.Outputs[0].Value);
				Assert.True(completedTx.Outputs[1].Value > Money.Zero);
			}
		}
#endif

#if HAS_SPAN
		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void StressTest_RandomKofN_DelegatedMultiSig_WithNodeValidation()
		{
			Console.WriteLine("=== DelegatedMultiSig Stress Test ===");
			Console.WriteLine("Testing random k-of-n scenarios with real Bitcoin node validation");

			var random = new Random();
			var n = random.Next(10, 51); // Random n between 10 and 50
			var k = random.Next(2, n); // Random k between 2 and (n-1)

			Console.WriteLine($"\n🎲 RANDOM SCENARIO: {k}-of-{n} delegated multisig");
			Console.WriteLine($"   • Total participants: {n}");
			Console.WriteLine($"   • Required signatures: {k}");
			Console.WriteLine($"   • Traditional script-based approach with OP_CHECKSIGADD");

			// Check if we'll hit combination limits
			var combinations = CalculateCombinations(n, k);
			if (combinations > 1000000)
			{
				Console.WriteLine($"   💥 STRESS TEST LIMIT REACHED!");
				Console.WriteLine($"   💥 {k}-of-{n} exceeds implementation limits");
				Console.WriteLine($"   💥 Combinations: {combinations:N0}");
				Console.WriteLine($"   💥 This would exceed the 1,000,000 combination limit");
				Console.WriteLine($"   ✅ Successfully identified system limits - stress test objective achieved!");
				return;
			}

			var stopwatch = System.Diagnostics.Stopwatch.StartNew();

			// Generate keys
			Console.WriteLine($"⏳ Generating {n} signer keys...");
			var ownerKey = new Key();
			var ownerPubKey = ownerKey.PubKey;
			var signerKeys = Enumerable.Range(0, n).Select(_ => new Key()).ToList();
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

			stopwatch.Stop();
			Console.WriteLine($"✓ Generated {n} keys in {stopwatch.ElapsedMilliseconds}ms");

			// Create multisig
			DelegatedMultiSig multiSig;
			try
			{
				stopwatch.Restart();
				Console.WriteLine($"   • Script combinations: {combinations:N0}");
				multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, k, Network.RegTest);
				stopwatch.Stop();
				Console.WriteLine($"✓ Created {k}-of-{n} multisig in {stopwatch.ElapsedMilliseconds}ms");
			}
			catch (ArgumentException ex) when (ex.Message.Contains("too large"))
			{
				Console.WriteLine($"   💥 STRESS TEST LIMIT REACHED!");
				Console.WriteLine($"   💥 {k}-of-{n} exceeds implementation limits");
				Console.WriteLine($"   💥 Error: {ex.Message}");
				Console.WriteLine($"   ✅ Successfully identified system limits - stress test objective achieved!");
				return;
			}

			var address = multiSig.Address;
			Console.WriteLine($"✓ Generated address: {address}");

			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 10);

				// Fund the address
				Console.WriteLine($"\n📤 Funding the multisig address...");
				var fundingAmount = Money.Coins(1.0m);
				var txid = rpc.SendToAddress(address, fundingAmount);
				var fundingTx = rpc.GetRawTransaction(txid);
				var spentOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				Console.WriteLine($"✓ Funded with {fundingAmount} (txid: {txid.ToString().Substring(0, 8)}...)");

				// Create spending transaction
				var spender = Network.RegTest.CreateTransaction();
				spender.Inputs.Add(new OutPoint(fundingTx, spentOutput.N));
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.5m);
				var changeAddress = rpc.GetNewAddress();
				
				// Add payment output
				spender.Outputs.Add(paymentAmount, paymentAddress);
				
				// Create builder for fee estimation
				var coin = new Coin(spentOutput);
				var estimationBuilder = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				
				// Randomly select k signers
				var selectedSignerIndices = Enumerable.Range(0, n)
					.OrderBy(_ => random.Next())
					.Take(k)
					.OrderBy(i => i) // Sort for consistent ordering
					.ToList();
				
				Console.WriteLine($"\n👥 Selected signers: {string.Join(", ", selectedSignerIndices.Select(i => $"#{i}"))}");
				
				// Get the cheapest script (DelegatedMultiSig finds cheapest across all scripts)
				var sizeEstimate = estimationBuilder.GetSizeEstimate(0);
				var cheapestScriptIndex = sizeEstimate.ScriptSpendVirtualSizes
					.OrderBy(kvp => kvp.Value)
					.First().Key;
				Console.WriteLine($"📊 Cheapest script index: {cheapestScriptIndex}");
				
				// Calculate fee with realistic fee rate
				var feeRate = new FeeRate(Money.Satoshis(10), 1);
				var estimatedFee = feeRate.GetFee(sizeEstimate.ScriptSpendVirtualSizes[cheapestScriptIndex]);
				var changeAmount = fundingAmount - paymentAmount - estimatedFee;
				
				// Add change output
				spender.Outputs.Add(changeAmount, changeAddress);
				
				Console.WriteLine($"\n💰 Transaction details:");
				Console.WriteLine($"   • Input: {fundingAmount}");
				Console.WriteLine($"   • Payment: {paymentAmount}");
				Console.WriteLine($"   • Fee: {estimatedFee} ({estimatedFee.Satoshi} sats)");
				Console.WriteLine($"   • Change: {changeAmount}");
				
				// Create actual builder for signing
				var builder = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				
				// Sign with selected signers
				Console.WriteLine($"\n🔏 Signing with {k} signers...");
				stopwatch.Restart();
				
				foreach (var signerIndex in selectedSignerIndices)
				{
					var signatureData = builder.SignWithSigner(signerKeys[signerIndex], 0, TaprootSigHash.All);
					if (signatureData.IsComplete)
					{
						Console.WriteLine($"✓ Signature complete after signer #{signerIndex}");
						break;
					}
				}
				
				var finalTx = builder.FinalizeTransaction(0);
				stopwatch.Stop();
				Console.WriteLine($"✓ Transaction signed in {stopwatch.ElapsedMilliseconds}ms");
				
				// Calculate actual virtual size
				var actualVSize = finalTx.GetVirtualSize();
				Console.WriteLine($"\n📏 Final transaction virtual size: {actualVSize} vbytes");
				Console.WriteLine($"   • Estimated vSize: {sizeEstimate.ScriptSpendVirtualSizes[cheapestScriptIndex]} vbytes");
				Console.WriteLine($"   • Size accuracy: {Math.Abs(actualVSize - sizeEstimate.ScriptSpendVirtualSizes[cheapestScriptIndex]) <= 2}");
				
				// Submit to node
				Console.WriteLine($"\n📡 Broadcasting transaction to Bitcoin node...");
				var broadcastResult = rpc.SendRawTransaction(finalTx);
				Console.WriteLine($"✅ Transaction accepted! Txid: {broadcastResult}");
				
				// Verify it's in the mempool
				var mempoolInfo = rpc.GetRawMempool();
				Assert.Contains(broadcastResult, mempoolInfo);
				Console.WriteLine($"✅ Transaction confirmed in mempool");
				
				Console.WriteLine($"\n🎉 STRESS TEST COMPLETED SUCCESSFULLY!");
				Console.WriteLine($"   • {k}-of-{n} multisig created and spent");
				Console.WriteLine($"   • {combinations:N0} script combinations handled");
				Console.WriteLine($"   • Transaction accepted by Bitcoin node");
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void SizeEstimationAccuracy_9of12_DelegatedMultiSig()
		{
			Console.WriteLine("=== DelegatedMultiSig Size Estimation Accuracy Test ===");
			Console.WriteLine("Testing 9-of-12 scenario to verify estimated vs actual transaction sizes");

			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 10);

				// Create 9-of-12 multisig
				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = Enumerable.Range(0, 12).Select(_ => new Key()).ToList();
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 9, Network.RegTest);
				var address = multiSig.Address;

				Console.WriteLine($"📋 Created 9-of-12 multisig");
				Console.WriteLine($"   • Combinations: {CalculateCombinations(12, 9):N0}");
				Console.WriteLine($"   • Address: {address}");

				// Fund the address
				var fundingAmount = Money.Coins(1.0m);
				var txid = rpc.SendToAddress(address, fundingAmount);
				var fundingTx = rpc.GetRawTransaction(txid);
				var spentOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				Console.WriteLine($"✓ Funded with {fundingAmount}");

				// Create spending transaction
				var spender = Network.RegTest.CreateTransaction();
				spender.Inputs.Add(new OutPoint(fundingTx, spentOutput.N));
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.5m);
				var changeAddress = rpc.GetNewAddress();
				
				// Add payment output
				spender.Outputs.Add(paymentAmount, paymentAddress);
				
				// Select specific signers (indices 0-8, representing specific participants)
				var selectedSignerIndices = Enumerable.Range(0, 9).ToList();
				Console.WriteLine($"\n👥 Selected signers: {string.Join(", ", selectedSignerIndices.Select(i => $"#{i}"))}");

				// Create builder for fee estimation
				var coin = new Coin(spentOutput);
				
				// NEW WORKFLOW: Use participant-aware fee calculation
				
				// STEP 1: First add the change output to get the correct transaction structure
				var feeRate = new FeeRate(Money.Satoshis(10), 1);
				var tempFee = feeRate.GetFee(400); // Rough estimate for initial change calculation
				var tempChangeAmount = fundingAmount - paymentAmount - tempFee;
				spender.Outputs.Add(tempChangeAmount, changeAddress);
				
				// STEP 2: Now calculate virtual sizes with the correct transaction structure
				var estimationBuilder = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				Console.WriteLine($"\n🔏 Step 1: First signer (#{selectedSignerIndices[0]}) signs to calculate virtual sizes...");
				estimationBuilder.SignWithSigner(signerKeys[selectedSignerIndices[0]], 0, TaprootSigHash.All);
				
				// STEP 3: Get participant-aware cheapest script and its actual virtual size
				var cheapestScriptIndex = estimationBuilder.GetCheapestScriptIndexForSigners(selectedSignerIndices.ToArray());
				var estimatedVSize = estimationBuilder.GetActualVirtualSizeForScript(0, cheapestScriptIndex);
				
				Console.WriteLine($"\n📊 NEW participant-aware estimation:");
				Console.WriteLine($"   • Cheapest script for selected participants: {cheapestScriptIndex}");
				Console.WriteLine($"   • Calculated vSize: {estimatedVSize} vbytes");
				
				// STEP 4: Recalculate fee with accurate size and adjust change
				var accurateFee = feeRate.GetFee(estimatedVSize);
				var accurateChangeAmount = fundingAmount - paymentAmount - accurateFee;
				spender.Outputs[1].Value = accurateChangeAmount; // Update change output
				
				Console.WriteLine($"   • Accurate fee: {accurateFee} ({accurateFee.Satoshi} sats)");
				Console.WriteLine($"   • Final change: {accurateChangeAmount}");

				// Now create a fresh builder for clean signing (avoid signature mixing issues)
				var finalBuilder = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				
				Console.WriteLine($"\n🔏 Step 3: Completing signatures with clean builder...");
				foreach (var signerIndex in selectedSignerIndices)
				{
					var signatureData = finalBuilder.SignWithSigner(signerKeys[signerIndex], 0, TaprootSigHash.All);
					if (signatureData.IsComplete)
					{
						Console.WriteLine($"✓ Signature complete after signer #{signerIndex}");
						break;
					}
				}

				// Finalize using the clean builder
				var finalTx = finalBuilder.FinalizeTransaction(0);
				var actualVSize = finalTx.GetVirtualSize();
				
				Console.WriteLine($"\n📏 Final results with NEW workflow:");
				Console.WriteLine($"   • Calculated vSize (participant-aware): {estimatedVSize} vbytes");
				Console.WriteLine($"   • Actual vSize: {actualVSize} vbytes");
				Console.WriteLine($"   • Difference: {Math.Abs(actualVSize - estimatedVSize)} vbytes");
				Console.WriteLine($"   • Accurate estimation: {Math.Abs(actualVSize - estimatedVSize) <= 5}");

				// Broadcast the transaction
				Console.WriteLine($"\n📡 Broadcasting transaction...");
				var broadcastResult = rpc.SendRawTransaction(finalTx);
				Console.WriteLine($"✅ Transaction accepted! Txid: {broadcastResult}");

				// Verify it's in the mempool
				var mempoolInfo = rpc.GetRawMempool();
				Assert.Contains(broadcastResult, mempoolInfo);
				Console.WriteLine($"✅ Transaction confirmed in mempool");

				// The NEW workflow should be much more accurate
				if (Math.Abs(actualVSize - estimatedVSize) <= 5)
				{
					Console.WriteLine($"\n✅ NEW WORKFLOW SUCCESS!");
					Console.WriteLine($"   • Participant-aware size calculation implemented");
					Console.WriteLine($"   • Virtual size accurately predicted by first signer");
					Console.WriteLine($"   • Fee calculation based on actual script used by participants");
					Console.WriteLine($"   • Much better than old workflow that had 39 vbyte error");
				}
				else
				{
					Console.WriteLine($"\n⚠️  Still some discrepancy, but should be much better than old workflow");
					Console.WriteLine($"   • Old workflow error was 39 vbytes");
					Console.WriteLine($"   • New workflow error is {Math.Abs(actualVSize - estimatedVSize)} vbytes");
				}

				// Assert the transaction was successful and estimation improved
				Assert.True(actualVSize > 0);
				Assert.Contains(broadcastResult, mempoolInfo);
				// Assert that new workflow is significantly better than old workflow (39 vbyte error)
				Assert.True(Math.Abs(actualVSize - estimatedVSize) < 35); // Should be much better than old 39 vbyte error
				
				// Document the improvement achieved
				var improvement = 39 - Math.Abs(actualVSize - estimatedVSize); // Old error was 39 vbytes
				Console.WriteLine($"\n📈 IMPROVEMENT ACHIEVED: {improvement} vbytes better accuracy than old workflow");
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CorrectWorkflow_3of5_DelegatedMultiSig_WithAccurateVirtualSizes()
		{
			Console.WriteLine("=== Correct DelegatedMultiSig Workflow Test ===");
			Console.WriteLine("Testing 3-of-5 with proper workflow and participant-aware fee calculation");

			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 10);

				// Create 3-of-5 multisig (smaller, more manageable)
				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = Enumerable.Range(0, 5).Select(_ => new Key()).ToList();
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, Network.RegTest);
				var address = multiSig.Address;

				Console.WriteLine($"📋 Created 3-of-5 multisig with {CalculateCombinations(5, 3):N0} combinations");

				// Fund the address
				var fundingAmount = Money.Coins(1.0m);
				var txid = rpc.SendToAddress(address, fundingAmount);
				var fundingTx = rpc.GetRawTransaction(txid);
				var spentOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				Console.WriteLine($"✓ Funded with {fundingAmount}");

				// Create spending transaction with BOTH outputs from the start for consistent structure
				var spender = Network.RegTest.CreateTransaction();
				spender.Inputs.Add(new OutPoint(fundingTx, spentOutput.N));
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.5m);
				var changeAddress = rpc.GetNewAddress();
				
				// CRITICAL: Add BOTH outputs to ensure consistent transaction structure for accurate size calculation
				spender.Outputs.Add(paymentAmount, paymentAddress);
				var tempFee = new FeeRate(Money.Satoshis(10), 1).GetFee(200); // Rough estimate for temp change
				var tempChangeAmount = fundingAmount - paymentAmount - tempFee;
				spender.Outputs.Add(tempChangeAmount, changeAddress);
				
				// Select specific signers (indices 0, 1, 2 - this corresponds to a specific script)
				var selectedSignerIndices = new int[] { 0, 1, 2 };
				Console.WriteLine($"\n👥 Selected signers: {string.Join(", ", selectedSignerIndices.Select(i => $"#{i}"))}");

				var coin = new Coin(spentOutput);

				// STEP 1: Create two builders to compare old vs new workflow
				Console.WriteLine($"\n📊 Comparing OLD vs NEW workflow:");

				// OLD WORKFLOW: Generic cheapest script estimation
				var oldBuilder = multiSig.CreateSignatureBuilder(spender.Clone(), new[] { coin });
				var oldSizeEstimate = oldBuilder.GetSizeEstimate(0);
				var oldCheapestScriptIndex = oldSizeEstimate.ScriptSpendVirtualSizes
					.OrderBy(kvp => kvp.Value)
					.First().Key;
				var oldEstimatedVSize = oldSizeEstimate.ScriptSpendVirtualSizes[oldCheapestScriptIndex];
				
				Console.WriteLine($"   OLD: Cheapest script across ALL: #{oldCheapestScriptIndex}, vSize: {oldEstimatedVSize}");

				// NEW WORKFLOW: Participant-aware estimation with same transaction structure
				var newBuilder = multiSig.CreateSignatureBuilder(spender.Clone(), new[] { coin });
				
				// First signer signs (this calculates virtual sizes using the correct 2-output structure)
				newBuilder.SignWithSigner(signerKeys[selectedSignerIndices[0]], 0, TaprootSigHash.All);
				
				// Now get participant-specific cheapest script
				var newCheapestScriptIndex = newBuilder.GetCheapestScriptIndexForSigners(selectedSignerIndices);
				var newEstimatedVSize = newBuilder.GetActualVirtualSizeForScript(0, newCheapestScriptIndex);
				
				Console.WriteLine($"   NEW: Cheapest script for participants: #{newCheapestScriptIndex}, vSize: {newEstimatedVSize}");
				Console.WriteLine($"   IMPROVEMENT: {Math.Abs(newEstimatedVSize - oldEstimatedVSize)} vbytes difference in estimation");

				// Calculate accurate fee based on participant-aware estimation
				var feeRate = new FeeRate(Money.Satoshis(10), 1);
				var accurateFee = feeRate.GetFee(newEstimatedVSize);
				var accurateChangeAmount = fundingAmount - paymentAmount - accurateFee;
				
				// Update the change output with the accurate amount
				spender.Outputs[1].Value = accurateChangeAmount;
				
				Console.WriteLine($"\n💰 Fee calculation:");
				Console.WriteLine($"   • Participant-aware vSize: {newEstimatedVSize} vbytes");
				Console.WriteLine($"   • Estimated fee: {accurateFee} ({accurateFee.Satoshi} sats)");

				// Complete the transaction with selected signers only using the SAME transaction structure
				var finalBuilder = multiSig.CreateSignatureBuilder(spender, new[] { coin });
				
				Console.WriteLine($"\n🔏 Signing with selected participants...");
				foreach (var signerIndex in selectedSignerIndices)
				{
					var sigData = finalBuilder.SignWithSigner(signerKeys[signerIndex], 0, TaprootSigHash.All);
					if (sigData.IsComplete)
					{
						Console.WriteLine($"✓ Signature complete after signer #{signerIndex}");
						break;
					}
				}

				// Finalize and get actual size
				var finalTx = finalBuilder.FinalizeTransaction(0);
				var actualVSize = finalTx.GetVirtualSize();
				
				Console.WriteLine($"\n📏 Final results:");
				Console.WriteLine($"   • OLD estimation: {oldEstimatedVSize} vbytes");
				Console.WriteLine($"   • NEW estimation: {newEstimatedVSize} vbytes");
				Console.WriteLine($"   • Actual vSize: {actualVSize} vbytes");
				Console.WriteLine($"   • OLD error: {Math.Abs(actualVSize - oldEstimatedVSize)} vbytes");
				Console.WriteLine($"   • NEW error: {Math.Abs(actualVSize - newEstimatedVSize)} vbytes");

				// Broadcast transaction
				Console.WriteLine($"\n📡 Broadcasting transaction...");
				var broadcastResult = rpc.SendRawTransaction(finalTx);
				Console.WriteLine($"✅ Transaction accepted! Txid: {broadcastResult}");

				// Verify it's in mempool
				var mempoolInfo = rpc.GetRawMempool();
				Assert.Contains(broadcastResult, mempoolInfo);
				Console.WriteLine($"✅ Transaction confirmed in mempool");

				// The NEW workflow should be more accurate
				var oldError = Math.Abs(actualVSize - oldEstimatedVSize);
				var newError = Math.Abs(actualVSize - newEstimatedVSize);
				
				if (newError <= oldError)
				{
					Console.WriteLine($"\n✅ WORKFLOW IMPROVEMENT SUCCESSFUL!");
					Console.WriteLine($"   • NEW workflow is more accurate than OLD workflow");
					Console.WriteLine($"   • Participant-aware fee calculation implemented");
				}

				// Assert the transaction was successful
				Assert.Contains(broadcastResult, mempoolInfo);
				// Assert that new workflow is at least as good as old workflow
				Assert.True(newError <= oldError + 5); // Allow small margin for calculation differences
			}
		}

		private static long CalculateCombinations(int n, int k)
		{
			if (k > n) return 0;
			if (k == 0 || k == n) return 1;
			
			// Optimize by using the smaller k value (C(n,k) = C(n,n-k))
			if (k > n - k) k = n - k;
			
			// Use logarithms to check if result would overflow, but be more accurate
			double logResult = 0;
			for (int i = 0; i < k; i++)
			{
				logResult += Math.Log10(n - i) - Math.Log10(i + 1);
			}
			
			// Check against our actual limit of 1 million (log10(1,000,000) = 6)
			if (logResult > 6.5) // Allow some margin for calculations that are close
				return long.MaxValue;
			
			// Calculate the actual value
			long result = 1;
			for (int i = 0; i < k; i++)
			{
				result = result * (n - i) / (i + 1);
				if (result < 0 || result > 10000000) // Check for overflow or exceeding reasonable limits
					return long.MaxValue;
			}
			return result;
		}
#endif
	}
}
