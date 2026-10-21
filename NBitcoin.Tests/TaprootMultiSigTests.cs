#if HAS_SPAN // TaprootMultiSig / DelegatedMultiSig only exist in the HAS_SPAN builds of NBitcoin (not net472)
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using NBitcoin.DataEncoders;
using NBitcoin.RPC;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using Newtonsoft.Json.Linq;
using Xunit;
using Xunit.Abstractions;

namespace NBitcoin.Tests
{
	/// <summary>
	/// TaprootMultiSig: the k-of-n Taproot multisig without owner. The internal key is the BIP327 aggregate of all
	/// the signers; every spend goes through a k-of-k script (DelegatedMultiSig's tree), signed sequentially with PSBTs.
	///
	/// The stress test spends many k-of-n schemes end to end on a Bitcoin Core 25 regtest node. Environment:
	///   TAPROOT_MULTISIG_HEAVY=1      also the schemes with 100,000+ scripts (minutes each)
	///   TAPROOT_MULTISIG_RANDOM=&lt;n&gt;   n extra random schemes (n in 3..60, at most 50,000 scripts)
	/// </summary>
	public class TaprootMultiSigTests
	{
		private readonly ITestOutputHelper _output;
		private static readonly Network Net = Network.RegTest;

		public TaprootMultiSigTests(ITestOutputHelper output)
		{
			_output = output;
		}

		private static List<Key> NewKeys(int n) => Enumerable.Range(0, n).Select(_ => new Key()).ToList();

		private static double Combinations(int n, int k)
		{
			k = Math.Min(k, n - k);
			double result = 1;
			for (int i = 0; i < k; i++)
				result = result * (n - i) / (i + 1);
			return result;
		}

		// ------------------------------------------------------------------ unit tests (no node)

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void InternalKeyIsTheBip327AggregateOfTheVectors()
		{
			// the BIP327 KeyAgg vectors: our aggregate, in the given order, is the expected key of every valid case
			var root = JObject.Parse(File.ReadAllText("data/musig/key_agg_vectors.json"));
			var pubkeys = ((JArray)root["pubkeys"]).Select(p => p.Value<string>()).ToArray();
			foreach (var item in (JArray)root["valid_test_cases"])
			{
				var keys = ((JArray)item["key_indices"]).Select(i => new PubKey(pubkeys[i.Value<int>()])).ToList();
				var internalKey = TaprootMultiSig.AggregateInternalKey(keys);
				Assert.Equal(item["expected"].Value<string>().ToLowerInvariant(), Encoders.Hex.EncodeData(internalKey.ToBytes()));
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void HasNoOwnerAndTheInternalKeyIsTheAggregateOfAllSigners()
		{
			var keys = NewKeys(5);
			var pubKeys = keys.Select(k => k.PubKey).ToList();
			var ms = new TaprootMultiSig(pubKeys, 3, Net);

			Assert.False(ms.HasOwner);
			Assert.Null(ms.OwnerPubKey);
			Assert.Equal(TaprootMultiSig.AggregateInternalKey(TaprootMultiSig.KeySort(pubKeys)), ms.InternalKey);
			// the internal key is none of the signers' keys
			Assert.DoesNotContain(pubKeys, p => p.TaprootInternalKey == ms.InternalKey);
			Assert.Equal(10, ms.Scripts.Count);

			// nobody signs the key path alone
			var tx = Net.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(Money.Coins(0.5m), new Key().GetAddress(ScriptPubKeyType.TaprootBIP86, Net));
			var coin = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1m), ms.Address));
			var builder = ms.CreateSignatureBuilder(tx, new ICoin[] { coin });
			foreach (var key in keys)
				Assert.Throws<InvalidOperationException>(() => builder.SignWithOwner(key, 0));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TheAddressDoesNotDependOnTheOrderOfTheKeys()
		{
			var rnd = new Random(7);
			var pubKeys = NewKeys(7).Select(k => k.PubKey).ToList();
			var address = new TaprootMultiSig(pubKeys, 4, Net).Address;
			for (int i = 0; i < 5; i++)
				Assert.Equal(address, new TaprootMultiSig(pubKeys.OrderBy(_ => rnd.Next()).ToList(), 4, Net).Address);

			// HD wallet: the order of the extended public keys does not matter either, at any index
			var xpubs = Enumerable.Range(0, 5).Select(_ => new ExtKey().Neuter()).ToList();
			for (uint index = 0; index < 3; index++)
			{
				var a = TaprootMultiSig.FromExtPubKeys(xpubs, 3, index, Net).Address;
				Assert.Equal(a, TaprootMultiSig.FromExtPubKeys(xpubs.OrderBy(_ => rnd.Next()).ToList(), 3, index, Net).Address);
				// the aggregate of an HD address is in the order of the extended public keys
				var ordered = DelegatedMultiSig.SortExtPubKeys(xpubs).Select(x => x.Derive(index).PubKey).ToList();
				Assert.Equal(TaprootMultiSig.AggregateInternalKey(ordered), TaprootMultiSig.FromExtPubKeys(xpubs, 3, index, Net).InternalKey);
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void SameScriptTreeAsDelegatedOnlyTheInternalKeyChanges()
		{
			var pubKeys = NewKeys(6).Select(k => k.PubKey).ToList();
			var ms = new TaprootMultiSig(pubKeys, 3, Net);
			var delegated = new DelegatedMultiSig(new Key().PubKey, pubKeys, 3, Net);
			Assert.Equal(delegated.Scripts.Select(s => s.LeafHash), ms.Scripts.Select(s => s.LeafHash));
			Assert.Equal(delegated.TaprootSpendInfo.MerkleRoot, ms.TaprootSpendInfo.MerkleRoot);
			Assert.NotEqual(delegated.Address, ms.Address);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void DescriptorsAreWellFormed()
		{
			var xpubs = Enumerable.Range(0, 3).Select(_ => new ExtKey().Neuter()).ToList();
			var ranged = TaprootMultiSig.GetRangedDescriptor(xpubs, 2, Net);
			Assert.StartsWith("tr(musig(", ranged);
			Assert.Equal(3, ranged.Split(new[] { "sortedmulti_a(2," }, StringSplitOptions.None).Length - 1);
			var ms = TaprootMultiSig.FromExtPubKeys(xpubs, 2, 0, Net);
			Assert.StartsWith("tr(" + Encoders.Hex.EncodeData(ms.InternalKey.ToBytes()) + ",", ms.GetDescriptor());
			Assert.StartsWith("tr(musig(" + string.Join(",", ms.AggregatedPubKeys.Select(p => p.ToHex())) + "),", ms.GetMuSigDescriptor());
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TheLimitOfOneScriptPerCombinationIsEnforced()
		{
			// one script per combination of k signers: 15-of-50 would need C(50,15) = 2,250,829,575,120 scripts
			var pubKeys = NewKeys(50).Select(k => k.PubKey).ToList();
			var sw = Stopwatch.StartNew();
			var ex = Assert.Throws<ArgumentException>(() => new TaprootMultiSig(pubKeys, 15, Net));
			Assert.Contains("too large", ex.Message);
			_output.WriteLine($"15-of-50 refused in {sw.ElapsedMilliseconds} ms: {ex.Message}");
		}

		// ------------------------------------------------------------------ node tests

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void BitcoinCoreDerivesTheAddressesFromTheDescriptors()
		{
			using var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Net);
			var rpc = nodeBuilder.CreateNode().CreateRPCClient();
			nodeBuilder.StartAll();
			foreach (var (k, n) in new[] { (2, 3), (3, 5), (4, 7), (2, 9), (7, 9) })
			{
				var xpubs = Enumerable.Range(0, n).Select(_ => new ExtKey().Neuter()).ToList();
				for (uint index = 0; index < 5; index++)
				{
					// Bitcoin Core 25 has no musig(): the aggregate goes as a plain x-only key (GetDescriptor)
					var ms = TaprootMultiSig.FromExtPubKeys(xpubs, k, index, Net);
					var derived = (JArray)rpc.SendCommand("deriveaddresses", ms.GetDescriptor()).Result;
					Assert.Equal(ms.Address.ToString(), derived[0].Value<string>());
					var info = (JObject)rpc.SendCommand("getdescriptorinfo", ms.GetDescriptor()).Result;
					Assert.EndsWith("#" + info["checksum"].Value<string>(), ms.GetDescriptor());
				}
				_output.WriteLine($"{k}-of-{n}: Bitcoin Core derives indexes 0-4 from the descriptors");
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void OnlyAllTheSignersTogetherCanSpendByTheKeyPath()
		{
			using var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Net);
			var rpc = nodeBuilder.CreateNode().CreateRPCClient();
			nodeBuilder.StartAll();
			rpc.Generate(Net.Consensus.CoinbaseMaturity + 1);

			var keys = NewKeys(5);
			var ms = new TaprootMultiSig(keys.Select(k => k.PubKey).ToList(), 3, Net);
			var (coin, _) = Fund(rpc, ms.Address, Money.Coins(1m));
			var tx = Net.CreateTransaction();
			tx.Inputs.Add(new TxIn(coin.Outpoint));
			tx.Outputs.Add(Money.Coins(0.9999m), rpc.GetNewAddress());

			// a MuSig2 session of the 5 signers (keys in the order of the aggregate), tweaked to the output key
			var sighash = tx.GetSignatureHashTaproot(new[] { coin.TxOut }, new TaprootExecutionData(0) { SigHash = TaprootSigHash.Default });
			var order = ms.AggregatedPubKeys.Select(p => keys.First(k => k.PubKey == p)).ToList();
			var ecPrivs = order.Select(k => ECPrivKey.Create(k.ToBytes())).ToArray();
			var ecPubs = ecPrivs.Select(p => p.CreatePubKey()).ToArray();
			var musig = new MusigContext(ecPubs, sighash.ToBytes());
			var nonces = ecPrivs.Select(p => musig.GenerateNonce(p)).ToArray();
			musig.Tweak(ms.TaprootSpendInfo.OutputPubKey.Tweak.Span);
			musig.ProcessNonces(nonces.Select(n => n.CreatePubNonce()).ToArray());
			var partials = ecPrivs.Select((p, i) => musig.Sign(p, nonces[i])).ToArray();
			var signature = musig.AggregateSignatures(partials);
			tx.Inputs[0].WitScript = new WitScript(Op.GetPushOp(signature.ToBytes()));

			var txid = rpc.SendRawTransaction(tx);
			Assert.True(InNextBlock(rpc, txid));
			_output.WriteLine($"key path signed by the 5 of 5 (MuSig2): confirmed, vsize {tx.GetVirtualSize()} (a script spend of 3-of-5 is larger)");
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void StressTest_ManySchemes_WithNodeValidation()
		{
			var schemes = new List<(int k, int n, int coins)>
			{
				(1, 2, 1), (2, 2, 1), (2, 3, 1), (2, 3, 3), (3, 5, 2), (5, 7, 1), (7, 10, 1),
				(2, 20, 1), (10, 15, 1), (15, 20, 1), (18, 20, 1),
				(3, 50, 1), (48, 50, 1), (2, 100, 1), (99, 100, 1), (100, 100, 1),
			};
			if (Environment.GetEnvironmentVariable("TAPROOT_MULTISIG_HEAVY") == "1")
				schemes.AddRange(new[] { (10, 20, 1), (25, 30, 1), (4, 50, 1) });
			var rnd = new Random();
			if (int.TryParse(Environment.GetEnvironmentVariable("TAPROOT_MULTISIG_RANDOM"), out var random))
			{
				while (random > 0)
				{
					var n = rnd.Next(3, 61);
					var k = rnd.Next(1, n + 1);
					if (Combinations(n, k) > 50000)
						continue;
					schemes.Add((k, n, 1 + rnd.Next(2)));
					random--;
				}
			}

			using var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Net);
			var rpc = nodeBuilder.CreateNode().CreateRPCClient();
			nodeBuilder.StartAll();
			rpc.Generate(Net.Consensus.CoinbaseMaturity + schemes.Sum(s => s.coins) + 10);

			_output.WriteLine("| k-of-n | scripts | coins | build | 1st signer | PSBT after 1st | all signers | vsize | estimate | confirmed |");
			_output.WriteLine("|---|---|---|---|---|---|---|---|---|---|");
			foreach (var (k, n, coins) in schemes)
				RunScheme(rpc, rnd, k, n, coins);
		}

		// One scheme end to end: build, fund, k random signers sign one after the other on a serialized PSBT (pruning the
		// scripts that can no longer complete), finalize, check the virtual size against the estimate, broadcast, mine.
		private void RunScheme(RPCClient rpc, Random rnd, int k, int n, int coinCount)
		{
			var keys = NewKeys(n);
			var sw = Stopwatch.StartNew();
			var ms = new TaprootMultiSig(keys.Select(key => key.PubKey).ToList(), k, Net);
			var buildMs = sw.ElapsedMilliseconds;

			var coins = new List<Coin>();
			for (int c = 0; c < coinCount; c++)
				coins.Add(Fund(rpc, ms.Address, Money.Coins(0.5m)).coin);

			// the k signers, in a random order; the script they will complete
			var signers = Enumerable.Range(0, n).OrderBy(_ => rnd.Next()).Take(k).ToList();
			var signerIndices = signers.Select(i => ms.SignerPubKeys.ToList().IndexOf(keys[i].PubKey)).ToHashSet();
			var scriptIndex = Enumerable.Range(0, ms.Scripts.Count).First(i => ms.GetScriptSignerIndices(i).All(signerIndices.Contains));
			var script = ms.Scripts[scriptIndex];

			// the transaction and its exact size: k 64-byte signatures + that script + its control block per input
			var tx = Net.CreateTransaction();
			tx.Version = 2;
			foreach (var coin in coins)
				tx.Inputs.Add(new TxIn(coin.Outpoint) { Sequence = 0xFFFFFFFD });
			tx.Outputs.Add(Money.Coins(0.1m), rpc.GetNewAddress());
			tx.Outputs.Add(Money.Zero, ms.Address);
			var witness = new List<byte[]>();
			for (int i = 0; i < k; i++)
				witness.Add(new byte[64]);
			witness.Add(script.Script.ToBytes());
			witness.Add(ms.TaprootSpendInfo.GetControlBlock(script).ToBytes());
			var sized = tx.Clone();
			foreach (var input in sized.Inputs)
				input.WitScript = new WitScript(witness.ToArray());
			var estimate = sized.GetVirtualSize();
			var fee = Money.Satoshis(estimate * 2);
			tx.Outputs[1].Value = coins.Sum(c => c.Amount) - Money.Coins(0.1m) - fee;

			var psbt = ms.CreatePSBT(tx, coins.ToArray());
			long firstMs = 0, firstSize = 0;
			sw.Restart();
			for (int s = 0; s < signers.Count; s++)
			{
				var signStart = sw.ElapsedMilliseconds;
				for (int i = 0; i < coins.Count; i++)
				{
					ms.SignPSBT(psbt, keys[signers[s]], i, TaprootSigHash.Default);
					ms.PrunePSBT(psbt, i);
				}
				// the next signer receives it serialized
				var text = psbt.ToBase64();
				if (s == 0)
				{
					firstMs = sw.ElapsedMilliseconds - signStart;
					firstSize = text.Length * 3 / 4;
				}
				psbt = PSBT.Parse(text, Net);
			}
			var signMs = sw.ElapsedMilliseconds;

			var final = psbt.GetGlobalTransaction();
			for (int i = 0; i < coins.Count; i++)
				final.Inputs[i].WitScript = ms.FinalizePSBT(psbt, i).Inputs[i].WitScript;
			var validator = final.CreateValidator(coins.Select(c => c.TxOut).ToArray());
			for (int i = 0; i < coins.Count; i++)
				Assert.Null(validator.ValidateInput(i).Error);
			Assert.Equal(estimate, final.GetVirtualSize());

			var txid = rpc.SendRawTransaction(final);
			Assert.True(InNextBlock(rpc, txid));
			_output.WriteLine($"| {k}-of-{n} | {ms.Scripts.Count:N0} | {coinCount} | {buildMs} ms | {firstMs} ms | {firstSize / 1024.0:N1} KB | {signMs} ms | {final.GetVirtualSize()} | {estimate} | yes |");
		}

		// mines one block and tells whether the transaction is in it
		private static bool InNextBlock(RPCClient rpc, uint256 txid)
		{
			var hash = rpc.Generate(1)[0];
			return rpc.GetBlock(hash).Transactions.Any(t => t.GetHash() == txid);
		}

		private static (Coin coin, uint256 txid) Fund(RPCClient rpc, BitcoinAddress address, Money amount)
		{
			var txid = rpc.SendToAddress(address, amount);
			var tx = rpc.GetRawTransaction(txid);
			var output = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
			rpc.Generate(1);
			return (new Coin(output), txid);
		}
	}
}
#endif
