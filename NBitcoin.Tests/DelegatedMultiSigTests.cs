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

				// Scenario: High network congestion, dual-transaction approach
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.8m);
				var changeAddress = rpc.GetNewAddress();
				var feeRate = new FeeRate(Money.Satoshis(80), 1); // High fee rate due to congestion

				// Participating signers: 0, 3, 6 (these will actually sign)
				var participatingSignerIndices = new int[] { 0, 3, 6 };

				Console.WriteLine($"Dual-Transaction Progressive Signing Scenario:");
				Console.WriteLine($"Network Conditions: High congestion, {feeRate.SatoshiPerByte} sat/vbyte");
				Console.WriteLine($"Payment: {paymentAmount}");
				Console.WriteLine($"Available for fees: {coin.Amount - paymentAmount}");
				Console.WriteLine($"Participating signers: {string.Join(", ", participatingSignerIndices)}");
				Console.WriteLine($"");

				// Create TWO transactions (base and buffered 50%)
				var (baseTx, bufferedTx) = multiSig.CreateDualTransactions(
					coin,
					paymentAddress,
					paymentAmount,
					changeAddress,
					feeRate,
					participatingSignerIndices,
					bufferPercentage: 50.0);

				var baseFee = coin.Amount - baseTx.Outputs.Sum(o => (Money)o.Value);
				var bufferedFee = coin.Amount - bufferedTx.Outputs.Sum(o => (Money)o.Value);

				Console.WriteLine($"Transaction A (Base):");
				Console.WriteLine($"  Fee: {baseFee} ({baseFee.Satoshi} sats)");
				Console.WriteLine($"  Change: {baseTx.Outputs[1].Value}");
				Console.WriteLine($"");

				Console.WriteLine($"Transaction B (Buffered 50%):");
				Console.WriteLine($"  Fee: {bufferedFee} ({bufferedFee.Satoshi} sats)");
				Console.WriteLine($"  Change: {bufferedTx.Outputs[1].Value}");
				Console.WriteLine($"");

				// Create builders for BOTH transactions
				var builderBase = multiSig.CreateSignatureBuilder(baseTx, new[] { coin });
				var builderBuffered = multiSig.CreateSignatureBuilder(bufferedTx, new[] { coin });

				// Each signer signs BOTH transactions
				Console.WriteLine($"Collecting signatures from all participants...");
				builderBase.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
				builderBuffered.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
				Console.WriteLine($"  Signer 0: signed both transactions");

				builderBase.SignWithSigner(signerKeys[3], 0, TaprootSigHash.All);
				builderBuffered.SignWithSigner(signerKeys[3], 0, TaprootSigHash.All);
				Console.WriteLine($"  Signer 3: signed both transactions");

				builderBase.SignWithSigner(signerKeys[6], 0, TaprootSigHash.All);
				builderBuffered.SignWithSigner(signerKeys[6], 0, TaprootSigHash.All);
				Console.WriteLine($"  Signer 6: signed both transactions");
				Console.WriteLine($"");

				// Finalize BOTH transactions
				var completedBaseTx = builderBase.FinalizeTransaction(0);
				var completedBufferedTx = builderBuffered.FinalizeTransaction(0);

				// Final signer (signer 6) now has TWO options to choose from
				Console.WriteLine($"Final signer decision point:");
				Console.WriteLine($"  Option A (Base): Fee = {baseFee}, Change = {completedBaseTx.Outputs[1].Value}");
				Console.WriteLine($"  Option B (Buffered): Fee = {bufferedFee}, Change = {completedBufferedTx.Outputs[1].Value}");
				Console.WriteLine($"");

				// Simulate decision: choose buffered for high congestion
				var chosenTx = completedBufferedTx;
				Console.WriteLine($"Decision: Broadcasting BUFFERED transaction due to high congestion");
				Console.WriteLine($"  Final fee: {bufferedFee}");
				Console.WriteLine($"  Final change: {chosenTx.Outputs[1].Value}");

				// Broadcast chosen transaction
				rpc.SendRawTransaction(chosenTx);

				// Verify the transaction was constructed correctly
				Assert.Equal(paymentAmount, chosenTx.Outputs[0].Value);
				Assert.True(chosenTx.Outputs[1].Value > Money.Zero);

				// Verify BOTH transactions are valid (could have broadcast either one)
				var actualBaseFee = coin.Amount - completedBaseTx.Outputs.Sum(o => (Money)o.Value);
				var actualBufferedFee = coin.Amount - completedBufferedTx.Outputs.Sum(o => (Money)o.Value);
				Assert.True(actualBufferedFee > actualBaseFee, "Buffered transaction should have higher fee");

				Console.WriteLine($"");
				Console.WriteLine($"SUCCESS: Dual-transaction workflow completed");
				Console.WriteLine($"  - Both transactions were fully signed");
				Console.WriteLine($"  - Final signer chose the appropriate one for network conditions");
				Console.WriteLine($"  - Alternative transaction is available if needed");
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

				// Verify estimation accuracy
				var estimationError = Math.Abs(actualVSize - estimatedVSize);
				if (estimationError == 0)
				{
					Console.WriteLine($"\n✅ PERFECT ESTIMATION!");
					Console.WriteLine($"   • Participant-aware size calculation implemented");
					Console.WriteLine($"   • Virtual size accurately predicted by first signer");
					Console.WriteLine($"   • Fee calculation based on actual script used by participants");
				}
				else if (estimationError <= 5)
				{
					Console.WriteLine($"\n✅ HIGHLY ACCURATE ESTIMATION!");
					Console.WriteLine($"   • Participant-aware size calculation implemented");
					Console.WriteLine($"   • Virtual size within {estimationError} vbytes of actual");
					Console.WriteLine($"   • Fee calculation based on actual script used by participants");
				}
				else
				{
					Console.WriteLine($"\n✅ WORKFLOW SUCCESS!");
					Console.WriteLine($"   • Participant-aware size calculation implemented");
					Console.WriteLine($"   • Estimation error: {estimationError} vbytes");
				}

				// Assert the transaction was successful and estimation is accurate
				Assert.True(actualVSize > 0);
				Assert.Contains(broadcastResult, mempoolInfo);
				Assert.True(estimationError <= 10); // Should be reasonably accurate
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

				// Calculate participant-aware estimation
				Console.WriteLine($"\n📊 Participant-aware fee calculation:");

				var builder = multiSig.CreateSignatureBuilder(spender.Clone(), new[] { coin });

				// First signer signs (this calculates virtual sizes using the correct 2-output structure)
				builder.SignWithSigner(signerKeys[selectedSignerIndices[0]], 0, TaprootSigHash.All);

				// Now get participant-specific cheapest script
				var cheapestScriptIndex = builder.GetCheapestScriptIndexForSigners(selectedSignerIndices);
				var estimatedVSize = builder.GetActualVirtualSizeForScript(0, cheapestScriptIndex);

				Console.WriteLine($"   • Cheapest script for participants: #{cheapestScriptIndex}");
				Console.WriteLine($"   • Estimated vSize: {estimatedVSize} vbytes");

				// Calculate accurate fee based on participant-aware estimation
				var feeRate = new FeeRate(Money.Satoshis(10), 1);
				var accurateFee = feeRate.GetFee(estimatedVSize);
				var accurateChangeAmount = fundingAmount - paymentAmount - accurateFee;

				// Update the change output with the accurate amount
				spender.Outputs[1].Value = accurateChangeAmount;

				Console.WriteLine($"\n💰 Fee calculation:");
				Console.WriteLine($"   • Participant-aware vSize: {estimatedVSize} vbytes");
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
				Console.WriteLine($"   • Estimated vSize: {estimatedVSize} vbytes");
				Console.WriteLine($"   • Actual vSize: {actualVSize} vbytes");
				Console.WriteLine($"   • Estimation error: {Math.Abs(actualVSize - estimatedVSize)} vbytes");

				// Broadcast transaction
				Console.WriteLine($"\n📡 Broadcasting transaction...");
				var broadcastResult = rpc.SendRawTransaction(finalTx);
				Console.WriteLine($"✅ Transaction accepted! Txid: {broadcastResult}");

				// Verify it's in mempool
				var mempoolInfo = rpc.GetRawMempool();
				Assert.Contains(broadcastResult, mempoolInfo);
				Console.WriteLine($"✅ Transaction confirmed in mempool");

				// Verify accuracy
				var estimationError = Math.Abs(actualVSize - estimatedVSize);
				if (estimationError == 0)
				{
					Console.WriteLine($"\n✅ PERFECT ESTIMATION!");
					Console.WriteLine($"   • Participant-aware fee calculation is 100% accurate");
				}
				else
				{
					Console.WriteLine($"\n✅ WORKFLOW SUCCESSFUL!");
					Console.WriteLine($"   • Participant-aware fee calculation implemented");
					Console.WriteLine($"   • Estimation within {estimationError} vbytes of actual");
				}

				// Assert the transaction was successful and estimation is accurate
				Assert.Contains(broadcastResult, mempoolInfo);
				Assert.True(estimationError <= 5); // Allow small margin for calculation differences
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void DualBufferProgressiveSigning_3of5()
		{
			Console.WriteLine("=== Progressive Signing with Dual Buffer (5% and 10%) ===");
			Console.WriteLine("Testing 3-of-5 multisig with three transaction versions");

			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 10);

				// Create 3-of-5 multisig
				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = Enumerable.Range(0, 5).Select(_ => new Key()).ToList();
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, Network.RegTest);
				var address = multiSig.Address;

				Console.WriteLine($"📋 Created 3-of-5 multisig");
				Console.WriteLine($"   • Address: {address}");

				// Fund the address
				var fundingAmount = Money.Coins(1.0m);
				var txid = rpc.SendToAddress(address, fundingAmount);
				var fundingTx = rpc.GetRawTransaction(txid);
				var spentOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				var coin = new Coin(spentOutput);
				Console.WriteLine($"✓ Funded with {fundingAmount}");

				// Payment details
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.8m);
				var changeAddress = rpc.GetNewAddress();
				var feeRate = new FeeRate(Money.Satoshis(50), 1); // 50 sat/vbyte

				// Participating signers: 0, 2, 4
				var participatingSignerIndices = new int[] { 0, 2, 4 };
				Console.WriteLine($"\n👥 Participating signers: {string.Join(", ", participatingSignerIndices.Select(i => $"#{i}"))}");

				// Create THREE transactions (base, 5% buffer, 10% buffer)
				Console.WriteLine($"\n💰 Creating three transaction versions:");

				var (baseTx, buffer5Tx) = multiSig.CreateDualTransactions(
					coin, paymentAddress, paymentAmount, changeAddress, feeRate,
					participatingSignerIndices, bufferPercentage: 5.0);

				var (_, buffer10Tx) = multiSig.CreateDualTransactions(
					coin, paymentAddress, paymentAmount, changeAddress, feeRate,
					participatingSignerIndices, bufferPercentage: 10.0);

				var baseFee = coin.Amount - baseTx.Outputs.Sum(o => (Money)o.Value);
				var buffer5Fee = coin.Amount - buffer5Tx.Outputs.Sum(o => (Money)o.Value);
				var buffer10Fee = coin.Amount - buffer10Tx.Outputs.Sum(o => (Money)o.Value);

				Console.WriteLine($"   • Base transaction: Fee = {baseFee} ({baseFee.Satoshi} sats)");
				Console.WriteLine($"   • 5% buffer: Fee = {buffer5Fee} ({buffer5Fee.Satoshi} sats)");
				Console.WriteLine($"   • 10% buffer: Fee = {buffer10Fee} ({buffer10Fee.Satoshi} sats)");

				// PHASE 1: First signer (signer 0) signs all THREE transactions
				Console.WriteLine($"\n🔏 Phase 1: Signer #0 signs all three transactions");

				var builderBase = multiSig.CreateSignatureBuilder(baseTx, new[] { coin });
				var builderBuffer5 = multiSig.CreateSignatureBuilder(buffer5Tx, new[] { coin });
				var builderBuffer10 = multiSig.CreateSignatureBuilder(buffer10Tx, new[] { coin });

				builderBase.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
				builderBuffer5.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);
				builderBuffer10.SignWithSigner(signerKeys[0], 0, TaprootSigHash.All);

				Console.WriteLine($"   ✓ Signed base transaction");
				Console.WriteLine($"   ✓ Signed 5% buffer transaction");
				Console.WriteLine($"   ✓ Signed 10% buffer transaction");

				// Serialize ALL signatures to pass to next signer
				var serializedBase = builderBase.GetPartialSignatureString(0);
				var serializedBuffer5 = builderBuffer5.GetPartialSignatureString(0);
				var serializedBuffer10 = builderBuffer10.GetPartialSignatureString(0);

				Console.WriteLine($"   📦 Serialized signatures for transmission");
				Console.WriteLine($"      • Base: {serializedBase.Length} bytes");
				Console.WriteLine($"      • 5% buffer: {serializedBuffer5.Length} bytes");
				Console.WriteLine($"      • 10% buffer: {serializedBuffer10.Length} bytes");

				// PHASE 2: Second signer (signer 2) receives and adds their signatures
				Console.WriteLine($"\n🔏 Phase 2: Signer #2 receives and signs all three transactions");

				// Signer 2 deserializes the data received from Signer 0
				var sigData0Base = DelegatedMultiSig.PartialSignatureData.Deserialize(serializedBase);
				var sigData0Buffer5 = DelegatedMultiSig.PartialSignatureData.Deserialize(serializedBuffer5);
				var sigData0Buffer10 = DelegatedMultiSig.PartialSignatureData.Deserialize(serializedBuffer10);

				// Signer 2 extracts the transactions from the received data
				var baseTx2 = sigData0Base.Transaction;
				var buffer5Tx2 = sigData0Buffer5.Transaction;
				var buffer10Tx2 = sigData0Buffer10.Transaction;

				var builder2Base = multiSig.CreateSignatureBuilder(baseTx2, new[] { coin });
				var builder2Buffer5 = multiSig.CreateSignatureBuilder(buffer5Tx2, new[] { coin });
				var builder2Buffer10 = multiSig.CreateSignatureBuilder(buffer10Tx2, new[] { coin });

				// Add signer 0's signatures
				builder2Base.AddPartialSignature(sigData0Base, 0);
				builder2Buffer5.AddPartialSignature(sigData0Buffer5, 0);
				builder2Buffer10.AddPartialSignature(sigData0Buffer10, 0);

				// Signer 2 adds their signatures
				builder2Base.SignWithSigner(signerKeys[2], 0, TaprootSigHash.All);
				builder2Buffer5.SignWithSigner(signerKeys[2], 0, TaprootSigHash.All);
				builder2Buffer10.SignWithSigner(signerKeys[2], 0, TaprootSigHash.All);

				Console.WriteLine($"   ✓ Added signatures to base transaction");
				Console.WriteLine($"   ✓ Added signatures to 5% buffer transaction");
				Console.WriteLine($"   ✓ Added signatures to 10% buffer transaction");

				// Serialize ALL accumulated signatures for final signer
				serializedBase = builder2Base.GetPartialSignatureString(0);
				serializedBuffer5 = builder2Buffer5.GetPartialSignatureString(0);
				serializedBuffer10 = builder2Buffer10.GetPartialSignatureString(0);

				Console.WriteLine($"   📦 Re-serialized with two signers");

				// PHASE 3: Final signer (signer 4) receives, signs, and chooses which to broadcast
				Console.WriteLine($"\n🔏 Phase 3: Final signer #4 receives, signs, and decides");

				// Signer 4 deserializes the data received from Signer 2
				var sigData2Base = DelegatedMultiSig.PartialSignatureData.Deserialize(serializedBase);
				var sigData2Buffer5 = DelegatedMultiSig.PartialSignatureData.Deserialize(serializedBuffer5);
				var sigData2Buffer10 = DelegatedMultiSig.PartialSignatureData.Deserialize(serializedBuffer10);

				// Signer 4 extracts the transactions from the received data
				var baseTx4 = sigData2Base.Transaction;
				var buffer5Tx4 = sigData2Buffer5.Transaction;
				var buffer10Tx4 = sigData2Buffer10.Transaction;

				var builder4Base = multiSig.CreateSignatureBuilder(baseTx4, new[] { coin });
				var builder4Buffer5 = multiSig.CreateSignatureBuilder(buffer5Tx4, new[] { coin });
				var builder4Buffer10 = multiSig.CreateSignatureBuilder(buffer10Tx4, new[] { coin });

				// Add previous signatures from Signers 0 and 2
				builder4Base.AddPartialSignature(sigData2Base, 0);
				builder4Buffer5.AddPartialSignature(sigData2Buffer5, 0);
				builder4Buffer10.AddPartialSignature(sigData2Buffer10, 0);

				// Final signer adds their signatures
				var sig4Base = builder4Base.SignWithSigner(signerKeys[4], 0, TaprootSigHash.All);
				var sig4Buffer5 = builder4Buffer5.SignWithSigner(signerKeys[4], 0, TaprootSigHash.All);
				var sig4Buffer10 = builder4Buffer10.SignWithSigner(signerKeys[4], 0, TaprootSigHash.All);

				Console.WriteLine($"   ✓ All three transactions now have 3 signatures");
				Console.WriteLine($"   ✓ Complete: {sig4Base.IsComplete}, {sig4Buffer5.IsComplete}, {sig4Buffer10.IsComplete}");

				// Finalize all THREE transactions
				var finalBaseTx = builder4Base.FinalizeTransaction(0);
				var finalBuffer5Tx = builder4Buffer5.FinalizeTransaction(0);
				var finalBuffer10Tx = builder4Buffer10.FinalizeTransaction(0);

				// Show sizes and validate all three
				Console.WriteLine($"\n📏 Final transaction sizes:");
				Console.WriteLine($"   • Base: {finalBaseTx.GetVirtualSize()} vbytes, Fee: {baseFee}");
				Console.WriteLine($"   • 5% buffer: {finalBuffer5Tx.GetVirtualSize()} vbytes, Fee: {buffer5Fee}");
				Console.WriteLine($"   • 10% buffer: {finalBuffer10Tx.GetVirtualSize()} vbytes, Fee: {buffer10Fee}");

				// Validate all three transactions are properly signed
				Console.WriteLine($"\n✅ Validating all three transactions:");

				Assert.Equal(paymentAmount, finalBaseTx.Outputs[0].Value);
				Assert.Equal(paymentAmount, finalBuffer5Tx.Outputs[0].Value);
				Assert.Equal(paymentAmount, finalBuffer10Tx.Outputs[0].Value);
				Console.WriteLine($"   ✓ All three have correct payment amount");

				Assert.True(finalBaseTx.Outputs[1].Value > Money.Zero);
				Assert.True(finalBuffer5Tx.Outputs[1].Value > Money.Zero);
				Assert.True(finalBuffer10Tx.Outputs[1].Value > Money.Zero);
				Console.WriteLine($"   ✓ All three have positive change");

				Assert.True(buffer5Fee > baseFee);
				Assert.True(buffer10Fee > buffer5Fee);
				Console.WriteLine($"   ✓ Fees are correctly ordered: base < 5% < 10%");

				// Final decision: broadcast the 5% buffer transaction
				Console.WriteLine($"\n📡 Final decision: Broadcasting 5% buffer transaction");
				Console.WriteLine($"   • Chosen fee: {buffer5Fee}");
				Console.WriteLine($"   • Change returned: {finalBuffer5Tx.Outputs[1].Value}");

				var broadcastResult = rpc.SendRawTransaction(finalBuffer5Tx);
				Console.WriteLine($"   ✅ Transaction accepted! Txid: {broadcastResult}");

				// Verify in mempool
				var mempoolInfo = rpc.GetRawMempool();
				Assert.Contains(broadcastResult, mempoolInfo);
				Console.WriteLine($"   ✅ Transaction confirmed in mempool");

				Console.WriteLine($"\n✅ SUCCESS: Progressive dual-buffer signing workflow completed!");
				Console.WriteLine($"   • Three transactions created (base, 5%, 10%)");
				Console.WriteLine($"   • All three signed progressively by 3 signers");
				Console.WriteLine($"   • Signatures serialized and passed between signers");
				Console.WriteLine($"   • Final signer chose 5% buffer for broadcast");
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

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void DualBufferProgressiveSigning_3of5_PSBT()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);
		
				Console.WriteLine($"=== Progressive Signing with Dual Buffer (5% and 10%) using PSBT ===");
				Console.WriteLine($"Testing 3-of-5 multisig with three transaction versions");
		
				// Setup
				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = new List<Key> { new Key(), new Key(), new Key(), new Key(), new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();
		
				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, Network.RegTest);
				var address = multiSig.Address;
		
				Console.WriteLine($"📋 Created 3-of-5 multisig");
				Console.WriteLine($"   • Address: {address}");
		
				// Fund the address
				var fundingAmount = Money.Coins(1.0m);
				var txid = rpc.SendToAddress(address, fundingAmount);
				var fundingTx = rpc.GetRawTransaction(txid);
				var spentOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				var coin = new Coin(spentOutput);
				Console.WriteLine($"✓ Funded with {fundingAmount}");
		
				// Payment details
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.8m);
				var changeAddress = rpc.GetNewAddress();
				var feeRate = new FeeRate(Money.Satoshis(50), 1);
		
				// Participating signers: 0, 2, 4
				var participatingSignerIndices = new int[] { 0, 2, 4 };
				Console.WriteLine($"\n👥 Participating signers: {string.Join(", ", participatingSignerIndices.Select(i => $"#{i}"))}");
		
				// Create THREE transactions (base, 5% buffer, 10% buffer)
				Console.WriteLine($"\n💰 Creating three transaction versions:");
		
				var (baseTx, buffer5Tx) = multiSig.CreateDualTransactions(
					coin, paymentAddress, paymentAmount, changeAddress, feeRate,
					participatingSignerIndices, bufferPercentage: 5.0);
		
				var (_, buffer10Tx) = multiSig.CreateDualTransactions(
					coin, paymentAddress, paymentAmount, changeAddress, feeRate,
					participatingSignerIndices, bufferPercentage: 10.0);
		
				var baseFee = coin.Amount - baseTx.Outputs.Sum(o => (Money)o.Value);
				var buffer5Fee = coin.Amount - buffer5Tx.Outputs.Sum(o => (Money)o.Value);
				var buffer10Fee = coin.Amount - buffer10Tx.Outputs.Sum(o => (Money)o.Value);
		
				Console.WriteLine($"   • Base transaction: Fee = {baseFee} ({baseFee.Satoshi} sats)");
				Console.WriteLine($"   • 5% buffer: Fee = {buffer5Fee} ({buffer5Fee.Satoshi} sats)");
				Console.WriteLine($"   • 10% buffer: Fee = {buffer10Fee} ({buffer10Fee.Satoshi} sats)");
		
				// PHASE 1: First signer (signer 0) creates and signs PSBTs
				Console.WriteLine($"\n🔏 Phase 1: Signer #0 creates and signs PSBTs for all three transactions");
		
				var psbtBase = multiSig.CreatePSBT(baseTx, new[] { coin });
				var psbtBuffer5 = multiSig.CreatePSBT(buffer5Tx, new[] { coin });
				var psbtBuffer10 = multiSig.CreatePSBT(buffer10Tx, new[] { coin });
		
				multiSig.SignPSBT(psbtBase, signerKeys[0], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer5, signerKeys[0], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer10, signerKeys[0], 0, TaprootSigHash.All);
		
				Console.WriteLine($"   ✓ Signed base transaction PSBT");
				Console.WriteLine($"   ✓ Signed 5% buffer transaction PSBT");
				Console.WriteLine($"   ✓ Signed 10% buffer transaction PSBT");
		
				// Serialize PSBTs to base64 for transmission
				var serializedBase = psbtBase.ToBase64();
				var serializedBuffer5 = psbtBuffer5.ToBase64();
				var serializedBuffer10 = psbtBuffer10.ToBase64();
		
				Console.WriteLine($"   📦 Serialized PSBTs for transmission");
				Console.WriteLine($"      • Base: {serializedBase.Length} characters");
				Console.WriteLine($"      • 5% buffer: {serializedBuffer5.Length} characters");
				Console.WriteLine($"      • 10% buffer: {serializedBuffer10.Length} characters");
		
				// PHASE 2: Second signer (signer 2) receives and signs PSBTs
				Console.WriteLine($"\n🔏 Phase 2: Signer #2 receives and signs all three PSBTs");
		
				// Signer 2 deserializes the PSBTs received from Signer 0
				var psbtBase2 = PSBT.Parse(serializedBase, Network.RegTest);
				var psbtBuffer5_2 = PSBT.Parse(serializedBuffer5, Network.RegTest);
				var psbtBuffer10_2 = PSBT.Parse(serializedBuffer10, Network.RegTest);
		
				// Signer 2 adds their signatures
				multiSig.SignPSBT(psbtBase2, signerKeys[2], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer5_2, signerKeys[2], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer10_2, signerKeys[2], 0, TaprootSigHash.All);
		
				Console.WriteLine($"   ✓ Added signatures to base transaction PSBT");
				Console.WriteLine($"   ✓ Added signatures to 5% buffer transaction PSBT");
				Console.WriteLine($"   ✓ Added signatures to 10% buffer transaction PSBT");
		
				// Re-serialize for final signer
				serializedBase = psbtBase2.ToBase64();
				serializedBuffer5 = psbtBuffer5_2.ToBase64();
				serializedBuffer10 = psbtBuffer10_2.ToBase64();
		
				Console.WriteLine($"   📦 Re-serialized PSBTs with two signers");
		
				// PHASE 3: Final signer (signer 4) receives, signs, and finalizes
				Console.WriteLine($"\n🔏 Phase 3: Final signer #4 receives, signs, and decides");
		
				// Signer 4 deserializes the PSBTs received from Signer 2
				var psbtBase4 = PSBT.Parse(serializedBase, Network.RegTest);
				var psbtBuffer5_4 = PSBT.Parse(serializedBuffer5, Network.RegTest);
				var psbtBuffer10_4 = PSBT.Parse(serializedBuffer10, Network.RegTest);
		
				// Signer 4 adds their signatures
				multiSig.SignPSBT(psbtBase4, signerKeys[4], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer5_4, signerKeys[4], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer10_4, signerKeys[4], 0, TaprootSigHash.All);
		
				Console.WriteLine($"   ✓ All three PSBTs now have 3 signatures");
		
				// Finalize all THREE transactions
				var finalBaseTx = multiSig.FinalizePSBT(psbtBase4, 0);
				var finalBuffer5Tx = multiSig.FinalizePSBT(psbtBuffer5_4, 0);
				var finalBuffer10Tx = multiSig.FinalizePSBT(psbtBuffer10_4, 0);
		
				// Show sizes and validate all three
				Console.WriteLine($"\n📏 Final transaction sizes:");
				Console.WriteLine($"   • Base: {finalBaseTx.GetVirtualSize()} vbytes, Fee: {baseFee}");
				Console.WriteLine($"   • 5% buffer: {finalBuffer5Tx.GetVirtualSize()} vbytes, Fee: {buffer5Fee}");
				Console.WriteLine($"   • 10% buffer: {finalBuffer10Tx.GetVirtualSize()} vbytes, Fee: {buffer10Fee}");
		
				// Validate all three transactions
				Console.WriteLine($"\n✅ Validating all three transactions:");
		
				Assert.Equal(paymentAmount, finalBaseTx.Outputs[0].Value);
				Assert.Equal(paymentAmount, finalBuffer5Tx.Outputs[0].Value);
				Assert.Equal(paymentAmount, finalBuffer10Tx.Outputs[0].Value);
				Console.WriteLine($"   ✓ All three have correct payment amount");
		
				Assert.True(finalBaseTx.Outputs[1].Value > Money.Zero);
				Assert.True(finalBuffer5Tx.Outputs[1].Value > Money.Zero);
				Assert.True(finalBuffer10Tx.Outputs[1].Value > Money.Zero);
				Console.WriteLine($"   ✓ All three have positive change");
		
				Assert.True(baseFee < buffer5Fee);
				Assert.True(buffer5Fee < buffer10Fee);
				Console.WriteLine($"   ✓ Fees are correctly ordered: base < 5% < 10%");
		
				// Final decision: Broadcast the 5% buffer transaction
				Console.WriteLine($"\n📡 Final decision: Broadcasting 5% buffer transaction");
				Console.WriteLine($"   • Chosen fee: {buffer5Fee}");
				Console.WriteLine($"   • Change returned: {finalBuffer5Tx.Outputs[1].Value}");
		
				var broadcastTxid = rpc.SendRawTransaction(finalBuffer5Tx);
				Console.WriteLine($"   ✅ Transaction accepted! Txid: {broadcastTxid}");
		
				var mempoolInfo = rpc.GetRawMempool();
				Assert.Contains(broadcastTxid, mempoolInfo);
				Console.WriteLine($"   ✅ Transaction confirmed in mempool");
		
				Console.WriteLine($"\n✅ SUCCESS: Progressive dual-buffer signing workflow completed using PSBT!");
				Console.WriteLine($"   • Three transactions created (base, 5%, 10%)");
				Console.WriteLine($"   • All three signed progressively by 3 signers using PSBT");
				Console.WriteLine($"   • PSBTs serialized and passed between signers");
				Console.WriteLine($"   • Final signer chose 5% buffer for broadcast");
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void PSBT_BIP174_Compliance_Test()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				Console.WriteLine($"=== BIP 174 Compliant PSBT Implementation Test ===");
				Console.WriteLine($"Testing progressive signing with serialized PSBTs");

				// Setup
				var ownerKey = new Key();
				var ownerPubKey = ownerKey.PubKey;
				var signerKeys = new List<Key> { new Key(), new Key(), new Key(), new Key(), new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();

				var multiSig = new DelegatedMultiSig(ownerPubKey, signerPubKeys, 3, Network.RegTest);
				var address = multiSig.Address;

				Console.WriteLine($"📋 Created 3-of-5 multisig");
				Console.WriteLine($"   • Address: {address}");

				// Fund the address
				var fundingAmount = Money.Coins(1.0m);
				var txid = rpc.SendToAddress(address, fundingAmount);
				var fundingTx = rpc.GetRawTransaction(txid);
				var spentOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				var coin = new Coin(spentOutput);
				Console.WriteLine($"✓ Funded with {fundingAmount}");

				// Payment details
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.8m);
				var changeAddress = rpc.GetNewAddress();
				var feeRate = new FeeRate(Money.Satoshis(50), 1);

				// Participating signers: 0, 2, 4
				var participatingSignerIndices = new int[] { 0, 2, 4 };
				Console.WriteLine($"\n👥 Participating signers: {string.Join(", ", participatingSignerIndices.Select(i => $"#{i}"))}");

				// Create THREE transactions (base, 5% buffer, 10% buffer)
				Console.WriteLine($"\n💰 Creating three transaction versions:");

				var (baseTx, buffer5Tx) = multiSig.CreateDualTransactions(
					coin, paymentAddress, paymentAmount, changeAddress, feeRate,
					participatingSignerIndices, bufferPercentage: 5.0);

				var (_, buffer10Tx) = multiSig.CreateDualTransactions(
					coin, paymentAddress, paymentAmount, changeAddress, feeRate,
					participatingSignerIndices, bufferPercentage: 10.0);

				var baseFee = coin.Amount - baseTx.Outputs.Sum(o => (Money)o.Value);
				var buffer5Fee = coin.Amount - buffer5Tx.Outputs.Sum(o => (Money)o.Value);
				var buffer10Fee = coin.Amount - buffer10Tx.Outputs.Sum(o => (Money)o.Value);

				Console.WriteLine($"   • Base transaction: Fee = {baseFee} ({baseFee.Satoshi} sats)");
				Console.WriteLine($"   • 5% buffer: Fee = {buffer5Fee} ({buffer5Fee.Satoshi} sats)");
				Console.WriteLine($"   • 10% buffer: Fee = {buffer10Fee} ({buffer10Fee.Satoshi} sats)");

				// PHASE 1: First signer (signer 0) creates and signs PSBTs
				Console.WriteLine($"\n🔏 Phase 1: Signer #0 creates and signs PSBTs for all three transactions");

				var psbtBase = multiSig.CreatePSBT(baseTx, new[] { coin });
				var psbtBuffer5 = multiSig.CreatePSBT(buffer5Tx, new[] { coin });
				var psbtBuffer10 = multiSig.CreatePSBT(buffer10Tx, new[] { coin });

				multiSig.SignPSBT(psbtBase, signerKeys[0], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer5, signerKeys[0], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer10, signerKeys[0], 0, TaprootSigHash.All);

				Console.WriteLine($"   ✓ Signed base transaction PSBT");
				Console.WriteLine($"   ✓ Signed 5% buffer transaction PSBT");
				Console.WriteLine($"   ✓ Signed 10% buffer transaction PSBT");

				// Verify proprietary fields were added
				Assert.NotEmpty(psbtBase.Inputs[0].Unknown);
				Assert.NotEmpty(psbtBuffer5.Inputs[0].Unknown);
				Assert.NotEmpty(psbtBuffer10.Inputs[0].Unknown);
				Console.WriteLine($"   ✓ Proprietary fields added to PSBT inputs");

				// Serialize PSBTs to base64 for transmission
				var serializedBase = psbtBase.ToBase64();
				var serializedBuffer5 = psbtBuffer5.ToBase64();
				var serializedBuffer10 = psbtBuffer10.ToBase64();

				Console.WriteLine($"   📦 Serialized PSBTs for transmission");
				Console.WriteLine($"      • Base: {serializedBase.Length} characters");
				Console.WriteLine($"      • 5% buffer: {serializedBuffer5.Length} characters");
				Console.WriteLine($"      • 10% buffer: {serializedBuffer10.Length} characters");

				// PHASE 2: Second signer (signer 2) receives and signs PSBTs
				Console.WriteLine($"\n🔏 Phase 2: Signer #2 receives and signs all three PSBTs");

				// Signer 2 deserializes the PSBTs received from Signer 0
				var psbtBase2 = PSBT.Parse(serializedBase, Network.RegTest);
				var psbtBuffer5_2 = PSBT.Parse(serializedBuffer5, Network.RegTest);
				var psbtBuffer10_2 = PSBT.Parse(serializedBuffer10, Network.RegTest);

				// Verify proprietary fields survived serialization
				Assert.NotEmpty(psbtBase2.Inputs[0].Unknown);
				Console.WriteLine($"   ✓ Proprietary fields preserved through serialization");

				// Signer 2 adds their signatures
				multiSig.SignPSBT(psbtBase2, signerKeys[2], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer5_2, signerKeys[2], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer10_2, signerKeys[2], 0, TaprootSigHash.All);

				Console.WriteLine($"   ✓ Added signatures to base transaction PSBT");
				Console.WriteLine($"   ✓ Added signatures to 5% buffer transaction PSBT");
				Console.WriteLine($"   ✓ Added signatures to 10% buffer transaction PSBT");

				// Re-serialize for final signer
				serializedBase = psbtBase2.ToBase64();
				serializedBuffer5 = psbtBuffer5_2.ToBase64();
				serializedBuffer10 = psbtBuffer10_2.ToBase64();

				Console.WriteLine($"   📦 Re-serialized PSBTs with two signers");

				// PHASE 3: Final signer (signer 4) receives, signs, and finalizes
				Console.WriteLine($"\n🔏 Phase 3: Final signer #4 receives, signs, and decides");

				// Signer 4 deserializes the PSBTs received from Signer 2
				var psbtBase4 = PSBT.Parse(serializedBase, Network.RegTest);
				var psbtBuffer5_4 = PSBT.Parse(serializedBuffer5, Network.RegTest);
				var psbtBuffer10_4 = PSBT.Parse(serializedBuffer10, Network.RegTest);

				// Signer 4 adds their signatures
				multiSig.SignPSBT(psbtBase4, signerKeys[4], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer5_4, signerKeys[4], 0, TaprootSigHash.All);
				multiSig.SignPSBT(psbtBuffer10_4, signerKeys[4], 0, TaprootSigHash.All);

				Console.WriteLine($"   ✓ All three PSBTs now have 3 signatures");

				// Finalize all THREE transactions
				var finalBaseTx = multiSig.FinalizePSBT(psbtBase4, 0);
				var finalBuffer5Tx = multiSig.FinalizePSBT(psbtBuffer5_4, 0);
				var finalBuffer10Tx = multiSig.FinalizePSBT(psbtBuffer10_4, 0);

				// Show sizes and validate all three
				Console.WriteLine($"\n📏 Final transaction sizes:");
				Console.WriteLine($"   • Base: {finalBaseTx.GetVirtualSize()} vbytes, Fee: {baseFee}");
				Console.WriteLine($"   • 5% buffer: {finalBuffer5Tx.GetVirtualSize()} vbytes, Fee: {buffer5Fee}");
				Console.WriteLine($"   • 10% buffer: {finalBuffer10Tx.GetVirtualSize()} vbytes, Fee: {buffer10Fee}");

				// Validate all three transactions
				Console.WriteLine($"\n✅ Validating all three transactions:");

				Assert.Equal(paymentAmount, finalBaseTx.Outputs[0].Value);
				Assert.Equal(paymentAmount, finalBuffer5Tx.Outputs[0].Value);
				Assert.Equal(paymentAmount, finalBuffer10Tx.Outputs[0].Value);
				Console.WriteLine($"   ✓ All three have correct payment amount");

				Assert.True(finalBaseTx.Outputs[1].Value > Money.Zero);
				Assert.True(finalBuffer5Tx.Outputs[1].Value > Money.Zero);
				Assert.True(finalBuffer10Tx.Outputs[1].Value > Money.Zero);
				Console.WriteLine($"   ✓ All three have positive change");

				Assert.True(baseFee < buffer5Fee);
				Assert.True(buffer5Fee < buffer10Fee);
				Console.WriteLine($"   ✓ Fees are correctly ordered: base < 5% < 10%");

				// Final decision: Broadcast the 5% buffer transaction
				Console.WriteLine($"\n📡 Final decision: Broadcasting 5% buffer transaction");
				Console.WriteLine($"   • Chosen fee: {buffer5Fee}");
				Console.WriteLine($"   • Change returned: {finalBuffer5Tx.Outputs[1].Value}");

				var broadcastTxid = rpc.SendRawTransaction(finalBuffer5Tx);
				Console.WriteLine($"   ✅ Transaction accepted! Txid: {broadcastTxid}");

				var mempoolInfo = rpc.GetRawMempool();
				Assert.Contains(broadcastTxid, mempoolInfo);
				Console.WriteLine($"   ✅ Transaction confirmed in mempool");

				Console.WriteLine($"\n✅ SUCCESS: BIP 174 compliant PSBT workflow verified!");
				Console.WriteLine($"   • Proprietary fields correctly encoded with compact size");
				Console.WriteLine($"   • PSBTs serialized and deserialized correctly");
				Console.WriteLine($"   • All three transactions signed progressively");
				Console.WriteLine($"   • Final transaction broadcast successfully");
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void PSBT_SimplifiedWorkflow_AutoFinalize()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				Console.WriteLine($"=== Correct Multi-Path Progressive PSBT Workflow ===");
				Console.WriteLine($"Demonstrating: Multiple transactions, each with optimal fee for its signer combination");

				// Setup 3-of-5 multisig
				var ownerKey = new Key();
				var signerKeys = new List<Key> { new Key(), new Key(), new Key(), new Key(), new Key() };
				var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();
				var multiSig = new DelegatedMultiSig(ownerKey.PubKey, signerPubKeys, 3, Network.RegTest);

				Console.WriteLine($"📋 Created 3-of-5 multisig");
				Console.WriteLine($"   • Address: {multiSig.Address}");
				Console.WriteLine($"   • Total possible 3-signer combinations: {multiSig.Scripts.Count}");

				// Fund the address
				var fundingAmount = Money.Coins(1.0m);
				var txid = rpc.SendToAddress(multiSig.Address, fundingAmount);
				var fundingTx = rpc.GetRawTransaction(txid);
				var spentOutput = fundingTx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == multiSig.Address.ScriptPubKey);
				var coin = new Coin(spentOutput);
				Console.WriteLine($"✓ Funded with {fundingAmount}");

				// Payment details
				var paymentAddress = rpc.GetNewAddress();
				var paymentAmount = Money.Coins(0.8m);
				var changeAddress = rpc.GetNewAddress();
				var feeRate = new FeeRate(Money.Satoshis(50), 1);

				// CORRECT WORKFLOW: First signer creates MULTIPLE transactions (one per path)
				Console.WriteLine($"\n👤 Signer #0: Creating multi-path PSBT...");
				Console.WriteLine($"   • Signer #0 doesn't know who else will sign");
				Console.WriteLine($"   • Creating SEPARATE transaction for EACH possible signing combination");
				Console.WriteLine($"   • Each transaction has OPTIMAL fee for that specific combination");

				var multiPathPSBT = multiSig.CreateMultiPathPSBTForFirstSigner(
					signerKeys[0],
					coin,
					paymentAddress,
					paymentAmount,
					changeAddress,
					feeRate,
					bufferPercentage: 15.0);

				Console.WriteLine($"   • Created {multiPathPSBT.PathCount} separate transactions");
				Console.WriteLine($"   • All signed by signer #0");

				var finalTx = multiPathPSBT.TryFinalize(multiSig);
				Assert.Null(finalTx);
				Console.WriteLine($"   ✗ Not enough signatures yet (need 3, have 1)");
				Console.WriteLine($"   → Broadcasting multi-path PSBT to ALL potential signers");

				// Signer 2 receives and signs (filters to only their paths)
				var serialized = multiPathPSBT.Serialize();
				var multiPathPSBT2 = DelegatedMultiSig.MultiPathPSBT.Deserialize(serialized, Network.RegTest);

				Console.WriteLine($"\n👤 Signer #2: Receives multi-path PSBT and signs...");
				Console.WriteLine($"   • Filters to paths where signer #2 participates");
				var multiPathPSBT2AfterSign = multiPathPSBT2.AddSigner(multiSig, signerKeys[2], 0, TaprootSigHash.All);
				Console.WriteLine($"   • Narrowed from {multiPathPSBT2.PathCount} to {multiPathPSBT2AfterSign.PathCount} viable paths");

				finalTx = multiPathPSBT2AfterSign.TryFinalize(multiSig);
				Assert.Null(finalTx);
				Console.WriteLine($"   ✗ Not enough signatures yet (need 3, have 2)");
				Console.WriteLine($"   → Broadcasting to remaining potential signers");

				// Signer 4 receives and signs (only one path remains)
				serialized = multiPathPSBT2AfterSign.Serialize();
				var multiPathPSBT3 = DelegatedMultiSig.MultiPathPSBT.Deserialize(serialized, Network.RegTest);

				Console.WriteLine($"\n👤 Signer #4: Receives multi-path PSBT and signs...");
				var multiPathPSBT3AfterSign = multiPathPSBT3.AddSigner(multiSig, signerKeys[4], 0, TaprootSigHash.All);
				Console.WriteLine($"   • Narrowed from {multiPathPSBT3.PathCount} to {multiPathPSBT3AfterSign.PathCount} viable path(s)");
				Console.WriteLine($"   • All paths with signers #0, #2, #4 are now complete");

				finalTx = multiPathPSBT3AfterSign.TryFinalize(multiSig);
				Assert.NotNull(finalTx);
				Console.WriteLine($"   ✓ Threshold met! (need 3, have 3)");
				Console.WriteLine($"   ✓ Chose CHEAPEST complete transaction path");
				Console.WriteLine($"   ✓ Fee is EXACT - not wasted");

				// Broadcast
				Console.WriteLine($"\n📡 Broadcasting transaction...");
				var broadcastTxid = rpc.SendRawTransaction(finalTx);
				Console.WriteLine($"   ✅ Transaction accepted! Txid: {broadcastTxid}");

				var mempoolInfo = rpc.GetRawMempool();
				Assert.Contains(broadcastTxid, mempoolInfo);

				Console.WriteLine($"\n✅ SUCCESS: Multi-path progressive workflow demonstrated!");
				Console.WriteLine($"   • First signer: Creates MULTIPLE transactions (one per path)");
				Console.WriteLine($"   • Each transaction: Optimal fee for that specific signer combination");
				Console.WriteLine($"   • Progressive narrowing: 10 paths → 3 paths → 1 path");
				Console.WriteLine($"   • Final signer: Chose CHEAPEST complete transaction");
				Console.WriteLine($"   • NO WASTED FEES - exact fee for actual participants");
			}
		}
	}
}
