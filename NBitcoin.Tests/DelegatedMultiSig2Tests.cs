#if HAS_SPAN // DelegatedMultiSig2 only exists in the HAS_SPAN builds of NBitcoin (not net472)
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using NBitcoin.DataEncoders;
using NBitcoin.RPC;
using NBitcoin.WalletPolicies;
using Newtonsoft.Json.Linq;
using Xunit;
using Xunit.Abstractions;

namespace NBitcoin.Tests
{
	/// <summary>
	/// DelegatedMultiSig2 (owner + k-of-n MuSig2 leaves) and TaprootMultiSig2 (no owner, key path = KeyAgg of all),
	/// signed live by the signers present with MuSig2Spend. Node tests run on an isolated regtest: Bitcoin Core 30 for
	/// the descriptors (BIP390 musig()), Core 25 for the payments.
	/// </summary>
	public class DelegatedMultiSig2Tests
	{
		private readonly ITestOutputHelper _output;
		private static readonly Network Net = Network.RegTest;

		public DelegatedMultiSig2Tests(ITestOutputHelper output)
		{
			_output = output;
		}

		private static List<Key> NewKeys(int n) => Enumerable.Range(0, n).Select(_ => new Key()).ToList();

		private static Dictionary<int, IReadOnlyList<byte[]>> Map(IEnumerable<(int signer, IReadOnlyList<byte[]> data)> items)
			=> items.ToDictionary(item => item.signer, item => item.data);

		/// <summary>
		/// The whole live signing of a payment, as the signers present would do it: <paramref name="present"/> are
		/// the private keys at each input (one list per signer present). Used by the comparison demos too.
		/// </summary>
		public static Transaction SignLive(MuSig2Spend spend, IReadOnlyDictionary<int, IReadOnlyList<Key>> present)
		{
			var secrets = present.Keys.ToDictionary(signer => signer, signer => spend.CreateNonces(signer));
			var nonces = Map(secrets.Select(s => (s.Key, s.Value.PublicNonces)));
			var partials = Map(present.Select(p => (p.Key, spend.Sign(p.Value, secrets[p.Key], nonces))));
			return spend.Finalize(nonces, partials);
		}

		/// <summary>One coin, plain keys: the k first signers (by signer index) sign the leaf of their combination.</summary>
		public static Transaction SignLive(DelegatedMultiSig2 multiSig, Transaction transaction, TxOut spent, IEnumerable<Key> signerKeys)
		{
			var keys = signerKeys.ToList();
			var present = new Dictionary<int, IReadOnlyList<Key>>();
			for (int index = 0; index < multiSig.SignerPubKeys.Count && present.Count < multiSig.RequiredSignatures; index++)
			{
				var key = keys.FirstOrDefault(k => k.PubKey.Compress() == multiSig.SignerPubKeys[index]);
				if (key != null)
					present[index] = new[] { key };
			}
			var spend = MuSig2Spend.ScriptPath(transaction, new[] { spent }, new[] { multiSig }, present.Keys);
			return SignLive(spend, present);
		}

		private static Transaction PayTx(IEnumerable<OutPoint> outpoints, Money amount)
		{
			var tx = Net.CreateTransaction();
			foreach (var outpoint in outpoints)
				tx.Inputs.Add(new TxIn(outpoint));
			tx.Outputs.Add(amount, new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Net));
			return tx;
		}

		private static string Validate(Transaction tx, TxOut[] spent)
		{
			var validator = tx.CreateValidator(spent);
			for (int i = 0; i < tx.Inputs.Count; i++)
			{
				var error = validator.ValidateInput(i).Error;
				if (error != null)
					return $"input {i}: {error}";
			}
			return null;
		}

		// ------------------------------------------------------------------ construction

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void LeavesAreTheMuSigOfEveryCombinationInADefinedTree()
		{
			var owner = new Key().PubKey;
			var keys = NewKeys(7).Select(k => k.PubKey).ToList();
			var ms = new DelegatedMultiSig2(owner, keys, 4, Net);
			Assert.Equal(35, ms.Scripts.Count);

			// signers in x-only order; combinations in lexicographic order; leaf = <KeyAgg(KeySort(keys))> OP_CHECKSIG
			var signers = keys.OrderBy(k => Encoders.Hex.EncodeData(k.TaprootInternalKey.ToBytes()), StringComparer.Ordinal).ToList();
			Assert.Equal(signers, ms.SignerPubKeys);
			var previous = new int[0];
			for (int i = 0; i < ms.Scripts.Count; i++)
			{
				var combination = ms.GetScriptSignerIndices(i).ToArray();
				Assert.True(previous.Length == 0 || Compare(previous, combination) < 0);
				previous = combination;
				var leafKeys = DelegatedMultiSig2.KeySort(combination.Select(index => signers[index]));
				Assert.Equal(leafKeys, ms.GetScriptPubKeys(i));
				var aggregate = TaprootMultiSig.AggregateInternalKey(leafKeys).ToBytes();
				Assert.Equal(new Script(Op.GetPushOp(aggregate), OpcodeType.OP_CHECKSIG), ms.Scripts[i].Script);
				Assert.Equal(i, ms.GetScriptIndex(combination.Reverse()));
			}

			// the defined tree: 35 leaves at depth 5 or 6, the same shape as DelegatedMultiSig
			var depths = ms.Scripts.Select(s => (ms.TaprootSpendInfo.GetControlBlock(s).ToBytes().Length - 33) / 32).ToList();
			Assert.All(depths, depth => Assert.InRange(depth, 5, 6));
			var delegated = new DelegatedMultiSig(owner, keys, 4, Net);
			Assert.Equal(delegated.Scripts.Select(s => (delegated.TaprootSpendInfo.GetControlBlock(s).ToBytes().Length - 33) / 32), depths);
		}

		private static int Compare(int[] a, int[] b)
		{
			for (int i = 0; i < a.Length; i++)
				if (a[i] != b[i])
					return a[i].CompareTo(b[i]);
			return 0;
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TheAddressDoesNotDependOnTheOrderOfTheKeys()
		{
			var rnd = new Random(1);
			var owner = new Key().PubKey;
			var keys = NewKeys(5).Select(k => k.PubKey).ToList();
			var address = new DelegatedMultiSig2(owner, keys, 3, Net).Address;
			Assert.Equal(address, new DelegatedMultiSig2(owner, keys.OrderBy(_ => rnd.Next()).ToList(), 3, Net).Address);
			Assert.Equal(TaprootMultiSig2.CreateAddress(keys, 3, Net), TaprootMultiSig2.CreateAddress(keys.OrderBy(_ => rnd.Next()).ToList(), 3, Net));

			var ownerXpub = new ExtKey().Neuter();
			var xpubs = Enumerable.Range(0, 5).Select(_ => new ExtKey().Neuter()).ToList();
			for (uint index = 0; index < 3; index++)
			{
				var shuffled = xpubs.OrderBy(_ => rnd.Next()).ToList();
				Assert.Equal(DelegatedMultiSig2.CreateAddress(ownerXpub, xpubs, 3, index, Net), DelegatedMultiSig2.CreateAddress(ownerXpub, shuffled, 3, index, Net));
				Assert.Equal(TaprootMultiSig2.CreateAddress(xpubs, 3, index, Net), TaprootMultiSig2.CreateAddress(shuffled, 3, index, Net));
				// HD: the signers in the order of the extended public keys at every index
				var ordered = DelegatedMultiSig.SortExtPubKeys(xpubs).Select(x => x.Derive(index).PubKey).ToList();
				Assert.Equal(ordered, DelegatedMultiSig2.FromExtPubKeys(ownerXpub, shuffled, 3, index, Net).SignerPubKeys);
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void WithoutOwnerOnlyTheInternalKeyChanges()
		{
			var keys = NewKeys(6).Select(k => k.PubKey).ToList();
			var delegated = new DelegatedMultiSig2(new Key().PubKey, keys, 3, Net);
			var ms = new TaprootMultiSig2(keys, 3, Net);
			Assert.Equal(delegated.Scripts.Select(s => s.LeafHash), ms.Scripts.Select(s => s.LeafHash));
			Assert.False(ms.HasOwner);
			Assert.Equal(TaprootMultiSig.AggregateInternalKey(TaprootMultiSig.KeySort(keys)), ms.InternalKey);
			// the leaves are not those of TaprootMultiSig (multi_a), so the addresses differ from it
			Assert.NotEqual(new TaprootMultiSig(keys, 3, Net).Address, ms.Address);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TheLimitsAreEnforced()
		{
			var owner = new Key().PubKey;
			var keys = NewKeys(50).Select(k => k.PubKey).ToList();
			Assert.Throws<ArgumentException>(() => new DelegatedMultiSig2(owner, keys.Take(3).ToList(), 1, Net)); // 1-of-n: DelegatedMultiSig
			Assert.Throws<ArgumentException>(() => new DelegatedMultiSig2(owner, keys.Take(3).ToList(), 4, Net));
			Assert.Throws<ArgumentException>(() => new DelegatedMultiSig2(owner, keys.Take(1).ToList(), 1, Net));
			Assert.Throws<ArgumentException>(() => new DelegatedMultiSig2(owner, new List<PubKey> { keys[0], keys[1], keys[0] }, 2, Net));
			var ex = Assert.Throws<ArgumentException>(() => new DelegatedMultiSig2(owner, keys, 15, Net));
			Assert.Contains("too large", ex.Message);
			var ms = new DelegatedMultiSig2(owner, keys.Take(4).ToList(), 2, Net);
			Assert.Throws<ArgumentException>(() => ms.GetScriptIndex(new[] { 0 }));
			Assert.Throws<ArgumentException>(() => ms.GetScriptIndex(new[] { 1, 1 }));
			Assert.Throws<ArgumentOutOfRangeException>(() => ms.GetScriptIndex(new[] { 0, 4 }));
		}

		// ------------------------------------------------------------------ descriptors

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TheDescriptorsGiveTheAddressUnderBip390()
		{
			// NBitcoin's parser computes musig() as BIP390 (KeySort after the derivation), checked against the BIP's
			// own vector in MiniscriptTests.CanParseMusigExpression
			var settings = new MiniscriptParsingSettings(Net) { Dialect = MiniscriptDialect.BIP388 };
			Script Parse(string descriptor) => Miniscript.Parse(descriptor.Substring(0, descriptor.IndexOf('#')), settings).ToScripts().ScriptPubKey;
			var ownerXpub = new ExtKey().Neuter();
			foreach (var (k, n) in new[] { (2, 3), (3, 5), (2, 4) })
			{
				var xpubs = Enumerable.Range(0, n).Select(_ => new ExtKey().Neuter()).ToList();
				for (uint index = 0; index < 3; index++)
				{
					DelegatedMultiSig2[] wallets = { DelegatedMultiSig2.FromExtPubKeys(ownerXpub, xpubs, k, index, Net), TaprootMultiSig2.FromExtPubKeys(xpubs, k, index, Net) };
					foreach (var ms in wallets)
					{
						Assert.Equal(ms.Address.ScriptPubKey, Parse(ms.GetDescriptor()));
						Assert.Equal(ms.Address.ScriptPubKey, Parse(ms.GetDescriptorWithoutMuSig()));
					}
				}
				var ranged = DelegatedMultiSig2.GetRangedDescriptor(ownerXpub, xpubs, k, Net);
				Assert.StartsWith($"tr({ownerXpub.ToString(Net)}/*,", ranged);
				Assert.Equal((int)DelegatedMultiSig.CalculateCombinationCount(n, k), ranged.Split(new[] { "pk(musig(" }, StringSplitOptions.None).Length - 1);
				Assert.StartsWith("tr(musig(", TaprootMultiSig2.GetRangedDescriptor(xpubs, k, Net));
			}
		}

		// ------------------------------------------------------------------ live signing (no node)

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void EveryCombinationSignsItsLeaf()
		{
			var keys = NewKeys(5);
			var ms = new DelegatedMultiSig2(new Key().PubKey, keys.Select(k => k.PubKey).ToList(), 3, Net);
			var spent = new TxOut(Money.Coins(1m), ms.Address);
			for (int scriptIndex = 0; scriptIndex < ms.Scripts.Count; scriptIndex++)
			{
				var signers = ms.GetScriptSignerIndices(scriptIndex);
				var tx = PayTx(new[] { new OutPoint(RandomUtils.GetUInt256(), 0) }, Money.Coins(0.999m));
				var spend = MuSig2Spend.ScriptPath(tx, new[] { spent }, new[] { ms }, signers);
				Assert.Equal(scriptIndex, spend.ScriptIndex);
				var present = signers.ToDictionary(s => s, s => (IReadOnlyList<Key>)new[] { keys.First(k => k.PubKey == ms.SignerPubKeys[s]) });
				var signed = SignLive(spend, present);
				Assert.Null(Validate(signed, new[] { spent }));
				Assert.Equal(spend.EstimateVirtualSize(), signed.GetVirtualSize());
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void SeveralCoinsOnSeveralAddressesOfAnHDWallet()
		{
			var ownerRoot = new ExtKey();
			var roots = Enumerable.Range(0, 4).Select(_ => new ExtKey()).ToList();
			var xpubs = roots.Select(r => r.Neuter()).ToList();
			var sorted = DelegatedMultiSig.SortExtPubKeys(xpubs);
			// the member at signer index s (the order of the extended public keys) and his keys at every input
			ExtKey Root(int signer) => roots.First(r => r.Neuter().ToBytes().SequenceEqual(sorted[signer].ToBytes()));
			var indexes = new uint[] { 0, 3, 7 };
			IReadOnlyList<Key> KeysOf(int signer) => indexes.Select(i => Root(signer).Derive(i).PrivateKey).ToArray();
			foreach (var withOwner in new[] { true, false })
			{
				var wallets = indexes.Select(i => withOwner
					? DelegatedMultiSig2.FromExtPubKeys(ownerRoot.Neuter(), xpubs, 2, i, Net)
					: TaprootMultiSig2.FromExtPubKeys(xpubs, 2, i, Net)).ToArray();
				var spent = wallets.Select(w => new TxOut(Money.Coins(0.4m), w.Address)).ToArray();
				var tx = PayTx(indexes.Select(_ => new OutPoint(RandomUtils.GetUInt256(), 1)), Money.Coins(1.19m));

				var spend = MuSig2Spend.ScriptPath(tx, spent, wallets, new[] { 3, 1 });
				var signed = SignLive(spend, new Dictionary<int, IReadOnlyList<Key>> { [1] = KeysOf(1), [3] = KeysOf(3) });
				Assert.Null(Validate(signed, spent));
				Assert.Equal(spend.EstimateVirtualSize(), signed.GetVirtualSize());

				if (withOwner)
				{
					var byOwner = DelegatedMultiSig2.SignOwnerKeyPath(tx, spent, wallets, indexes.Select(i => ownerRoot.Derive(i).PrivateKey).ToArray());
					Assert.Null(Validate(byOwner, spent));
					Assert.Equal(MuSig2Spend.EstimateVirtualSize(tx, wallets, -1), byOwner.GetVirtualSize());
					Assert.Throws<InvalidOperationException>(() => MuSig2Spend.KeyPath(tx, spent, wallets));
				}
				else
				{
					// all 4 present: the key path, one signature for the KeyAgg of every signer
					var keyPath = MuSig2Spend.KeyPath(tx, spent, wallets);
					var byAll = SignLive(keyPath, Enumerable.Range(0, 4).ToDictionary(s => s, KeysOf));
					Assert.Null(Validate(byAll, spent));
					Assert.Equal(keyPath.EstimateVirtualSize(), byAll.GetVirtualSize());
					Assert.True(byAll.GetVirtualSize() < signed.GetVirtualSize());
					Assert.Throws<InvalidOperationException>(() => DelegatedMultiSig2.SignOwnerKeyPath(tx, spent, wallets, indexes.Select(i => new Key()).ToArray()));
				}
				_output.WriteLine($"{(withOwner ? "Delegated" : "MultiSig")}2 2-of-4, 3 coins on indexes 0/3/7: script path vsize {signed.GetVirtualSize()}");
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void TheSecretNoncesAreUsedOnceForOneSpend()
		{
			var keys = NewKeys(3);
			var ms = new DelegatedMultiSig2(new Key().PubKey, keys.Select(k => k.PubKey).ToList(), 2, Net);
			Key KeyOf(int signer) => keys.First(k => k.PubKey == ms.SignerPubKeys[signer]);
			var spent = new[] { new TxOut(Money.Coins(1m), ms.Address) };
			var tx = PayTx(new[] { new OutPoint(RandomUtils.GetUInt256(), 0) }, Money.Coins(0.999m));
			var spend = MuSig2Spend.ScriptPath(tx, spent, new[] { ms }, new[] { 0, 2 });

			// a signer that is not one of the signers present
			Assert.Throws<ArgumentException>(() => spend.CreateNonces(1));

			// everybody builds the same spend from the same data: same id
			Assert.Equal(spend.Id, MuSig2Spend.ScriptPath(tx, spent, new[] { ms }, new[] { 2, 0 }).Id);
			var other = tx.Clone();
			other.Outputs[0].Value -= Money.Satoshis(1);
			var otherSpend = MuSig2Spend.ScriptPath(other, spent, new[] { ms }, new[] { 0, 2 });
			Assert.NotEqual(spend.Id, otherSpend.Id);

			var s0 = spend.CreateNonces(0);
			var s2 = spend.CreateNonces(2);
			Assert.Equal(66, s0.PublicNonces[0].Length);
			var nonces = Map(new[] { (0, s0.PublicNonces), (2, s2.PublicNonces) });

			// nonces of another spend (another transaction) are refused, and wiped
			var foreign = otherSpend.CreateNonces(0);
			Assert.Throws<ArgumentException>(() => spend.Sign(new[] { KeyOf(0) }, foreign, nonces));
			Assert.True(foreign.IsUsed);

			// the key of another signer is refused (and the nonces are gone: start again)
			var wrongKey = spend.CreateNonces(0);
			Assert.Throws<ArgumentException>(() => spend.Sign(new[] { KeyOf(2) }, wrongKey, Map(new[] { (0, wrongKey.PublicNonces), (2, s2.PublicNonces) })));
			Assert.True(wrongKey.IsUsed);

			// a set of public nonces without mine, or with a signer missing
			var missingMine = spend.CreateNonces(0);
			Assert.Throws<ArgumentException>(() => spend.Sign(new[] { KeyOf(0) }, missingMine, nonces));
			var alone = spend.CreateNonces(0);
			Assert.Throws<ArgumentException>(() => spend.Sign(new[] { KeyOf(0) }, alone, Map(new[] { (0, alone.PublicNonces) })));

			// the real round 2, then a second use of the same nonces
			var p0 = spend.Sign(new[] { KeyOf(0) }, s0, nonces);
			Assert.True(s0.IsUsed);
			Assert.Throws<InvalidOperationException>(() => spend.Sign(new[] { KeyOf(0) }, s0, nonces));
			var p2 = spend.Sign(new[] { KeyOf(2) }, s2, nonces);
			Assert.Equal(32, p2[0].Length);

			// a bad partial signature names its signer; a missing one is refused
			var bad = p2[0].ToArray();
			bad[31] ^= 1;
			var ex = Assert.Throws<InvalidOperationException>(() => spend.Finalize(nonces, Map(new[] { (0, p0), (2, (IReadOnlyList<byte[]>)new[] { bad }) })));
			Assert.Contains("signer 2", ex.Message);
			Assert.Throws<ArgumentException>(() => spend.Finalize(nonces, Map(new[] { (0, p0) })));

			var signed = spend.Finalize(nonces, Map(new[] { (0, p0), (2, p2) }));
			Assert.Null(Validate(signed, spent));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void AnInputThatIsNotOfTheWalletIsRefused()
		{
			var keys = NewKeys(3).Select(k => k.PubKey).ToList();
			var ms = new DelegatedMultiSig2(new Key().PubKey, keys, 2, Net);
			var otherWallet = new DelegatedMultiSig2(new Key().PubKey, NewKeys(4).Select(k => k.PubKey).ToList(), 2, Net);
			var tx = PayTx(new[] { new OutPoint(RandomUtils.GetUInt256(), 0), new OutPoint(RandomUtils.GetUInt256(), 0) }, Money.Coins(1m));
			var good = new TxOut(Money.Coins(1m), ms.Address);
			var stranger = new TxOut(Money.Coins(1m), new Key().PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Net));
			Assert.Throws<ArgumentException>(() => MuSig2Spend.ScriptPath(tx, new[] { good, stranger }, new[] { ms, ms }, new[] { 0, 1 }));
			Assert.Throws<ArgumentException>(() => MuSig2Spend.ScriptPath(tx, new[] { good, new TxOut(Money.Coins(1m), otherWallet.Address) }, new[] { ms, otherWallet }, new[] { 0, 1 }));
			Assert.Throws<ArgumentException>(() => MuSig2Spend.ScriptPath(tx, new[] { good }, new[] { ms }, new[] { 0, 1 }));
		}

		// ------------------------------------------------------------------ node tests (Bitcoin Core 25 regtest)

		private static Coin Fund(RPCClient rpc, BitcoinAddress address, Money amount)
		{
			var txid = rpc.SendToAddress(address, amount);
			var tx = rpc.GetRawTransaction(txid);
			var output = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
			return new Coin(output);
		}

		private static bool InNextBlock(RPCClient rpc, uint256 txid)
		{
			var block = rpc.GetBlock(rpc.Generate(1)[0]);
			return block.Transactions.Any(t => t.GetHash() == txid);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void BitcoinCoreDerivesTheAddressesFromTheDescriptors()
		{
			// Bitcoin Core 30 reads BIP390 musig(): the ranged descriptors of both wallets and every per-address one
			using var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v30_2, Net);
			var rpc = nodeBuilder.CreateNode().CreateRPCClient();
			nodeBuilder.StartAll();
			var ownerXpub = new ExtKey().Neuter();
			foreach (var (k, n) in new[] { (2, 3), (3, 5), (4, 7), (2, 9), (7, 9) })
			{
				var xpubs = Enumerable.Range(0, n).Select(_ => new ExtKey().Neuter()).ToList();
				var rangedDelegated = (JArray)rpc.SendCommand("deriveaddresses", DelegatedMultiSig2.GetRangedDescriptor(ownerXpub, xpubs, k, Net), new JArray(0, 2)).Result;
				var rangedMultiSig = (JArray)rpc.SendCommand("deriveaddresses", TaprootMultiSig2.GetRangedDescriptor(xpubs, k, Net), new JArray(0, 2)).Result;
				for (uint index = 0; index < 3; index++)
				{
					var delegated = DelegatedMultiSig2.FromExtPubKeys(ownerXpub, xpubs, k, index, Net);
					var multiSig = TaprootMultiSig2.FromExtPubKeys(xpubs, k, index, Net);
					Assert.Equal(delegated.Address.ToString(), rangedDelegated[(int)index].Value<string>());
					Assert.Equal(multiSig.Address.ToString(), rangedMultiSig[(int)index].Value<string>());
					foreach (var ms in new DelegatedMultiSig2[] { delegated, multiSig })
					{
						foreach (var descriptor in new[] { ms.GetDescriptor(), ms.GetDescriptorWithoutMuSig() })
						{
							var derived = (JArray)rpc.SendCommand("deriveaddresses", descriptor).Result;
							Assert.Equal(ms.Address.ToString(), derived[0].Value<string>());
							var info = (JObject)rpc.SendCommand("getdescriptorinfo", descriptor).Result;
							Assert.EndsWith("#" + info["checksum"].Value<string>(), descriptor);
						}
					}
				}
				_output.WriteLine($"{k}-of-{n}: Bitcoin Core 30 derives indexes 0-2 of both wallets from the ranged and the per-address descriptors");
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void PaymentsAreConfirmed()
		{
			using var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Net);
			var rpc = nodeBuilder.CreateNode().CreateRPCClient();
			nodeBuilder.StartAll();
			rpc.Generate(Net.Consensus.CoinbaseMaturity + 10);
			var feeRate = new FeeRate(Money.Satoshis(10), 1);

			var ownerRoot = new ExtKey();
			var roots = Enumerable.Range(0, 5).Select(_ => new ExtKey()).ToList();
			var xpubs = roots.Select(r => r.Neuter()).ToList();
			var sorted = DelegatedMultiSig.SortExtPubKeys(xpubs);
			ExtKey Root(int signer) => roots.First(r => r.Neuter().ToBytes().SequenceEqual(sorted[signer].ToBytes()));
			var indexes = new uint[] { 0, 1 };

			foreach (var path in new[] { "Delegated2 3-of-5 leaf", "Delegated2 owner", "MultiSig2 3-of-5 leaf", "MultiSig2 all 5 key path" })
			{
				var withOwner = path.StartsWith("Delegated2");
				var wallets = indexes.Select(i => withOwner
					? DelegatedMultiSig2.FromExtPubKeys(ownerRoot.Neuter(), xpubs, 3, i, Net)
					: TaprootMultiSig2.FromExtPubKeys(xpubs, 3, i, Net)).ToArray();
				var coins = wallets.Select(w => Fund(rpc, w.Address, Money.Coins(0.5m))).ToArray();
				rpc.Generate(1);
				var spent = coins.Select(c => c.TxOut).ToArray();
				var tx = Net.CreateTransaction();
				foreach (var coin in coins)
					tx.Inputs.Add(new TxIn(coin.Outpoint));
				tx.Outputs.Add(Money.Coins(0.3m), rpc.GetNewAddress());
				tx.Outputs.Add(Money.Zero, wallets[1].Address); // the change goes back to the wallet
				var scriptIndex = path.EndsWith("leaf") ? wallets[0].GetScriptIndex(new[] { 0, 2, 4 }) : -1;
				var vsize = MuSig2Spend.EstimateVirtualSize(tx, wallets, scriptIndex);
				tx.Outputs[1].Value = Money.Coins(1m) - Money.Coins(0.3m) - feeRate.GetFee(vsize);

				Transaction signed;
				if (path == "Delegated2 owner")
					signed = DelegatedMultiSig2.SignOwnerKeyPath(tx, spent, wallets, indexes.Select(i => ownerRoot.Derive(i).PrivateKey).ToArray());
				else
				{
					var spend = scriptIndex >= 0 ? MuSig2Spend.ScriptPath(tx, spent, wallets, new[] { 0, 2, 4 }) : MuSig2Spend.KeyPath(tx, spent, wallets);
					var present = spend.Signers.ToDictionary(s => s, s => (IReadOnlyList<Key>)indexes.Select(i => Root(s).Derive(i).PrivateKey).ToArray());
					signed = SignLive(spend, present);
				}
				var txid = rpc.SendRawTransaction(signed);
				Assert.True(InNextBlock(rpc, txid));
				Assert.Equal(vsize, signed.GetVirtualSize());
				_output.WriteLine($"{path}, 2 coins: confirmed, vsize {signed.GetVirtualSize()} = estimate");
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void LargeGroupsBuildAndSignQuickly()
		{
			using var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Net);
			var rpc = nodeBuilder.CreateNode().CreateRPCClient();
			nodeBuilder.StartAll();
			rpc.Generate(Net.Consensus.CoinbaseMaturity + 10);
			_output.WriteLine("| k-of-n | leaves | build address | live signing | vsize | confirmed |");
			_output.WriteLine("|---|---|---|---|---|---|");
			foreach (var (k, n) in new[] { (2, 3), (5, 10), (4, 16), (8, 13), (2, 60), (99, 100), (15, 20) })
			{
				var keys = NewKeys(n);
				var clock = Stopwatch.StartNew();
				var ms = new TaprootMultiSig2(keys.Select(key => key.PubKey).ToList(), k, Net);
				var build = clock.ElapsedMilliseconds;
				var coin = Fund(rpc, ms.Address, Money.Coins(0.1m));
				var tx = Net.CreateTransaction();
				tx.Inputs.Add(new TxIn(coin.Outpoint));
				tx.Outputs.Add(Money.Coins(0.099m), rpc.GetNewAddress());
				clock.Restart();
				var signed = SignLive(ms, tx, coin.TxOut, keys);
				var sign = clock.ElapsedMilliseconds;
				var txid = rpc.SendRawTransaction(signed);
				var confirmed = InNextBlock(rpc, txid);
				_output.WriteLine($"| {k}-of-{n} | {ms.Scripts.Count:N0} | {build} ms | {sign} ms | {signed.GetVirtualSize()} | {confirmed} |");
				Assert.True(confirmed);
			}
		}
	}
}
#endif
