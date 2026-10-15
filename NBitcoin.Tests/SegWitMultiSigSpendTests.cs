using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.RPC;
using Xunit;
using Xunit.Abstractions;

namespace NBitcoin.Tests
{
	/// <summary>
	/// SegWitMultiSigGroup + SegWitMultiSigSpend: the HD P2SH-P2WSH k-of-n multisig ("Legacy Multisignature" of
	/// Distributed Cryptography) with pre-signed fee levels. The unit tests need no node; the last ones start a
	/// RegTest Bitcoin Core from scratch and spend many k-of-n combinations on it.
	/// </summary>
	[Trait("UnitTest", "UnitTest")]
	public class SegWitMultiSigSpendTests
	{
		private readonly ITestOutputHelper _output;
		public SegWitMultiSigSpendTests(ITestOutputHelper output) { _output = output; }

		private static readonly Network Net = Network.RegTest;

		// a member: the receiving and change chain keys of a BIP48 account
		private sealed class Member
		{
			public ExtKey Receiving, Change;
			public Member()
			{
				var account = new ExtKey().Derive(new KeyPath("48'/1'/0'/1'"));
				Receiving = account.Derive(0);
				Change = account.Derive(1);
			}
		}

		private static (SegWitMultiSigGroup group, List<Member> members) NewGroup(int k, int n)
		{
			var members = Enumerable.Range(0, n).Select(_ => new Member()).ToList();
			return (Group(members, k), members);
		}

		private static SegWitMultiSigGroup Group(IEnumerable<Member> members, int k) =>
			new SegWitMultiSigGroup(members.Select(m => m.Receiving.Neuter()), members.Select(m => m.Change.Neuter()), k, Net);

		private static OutPoint RandomOutPoint() => new OutPoint(new uint256(RandomUtils.GetBytes(32)), 0);

		private static List<SegWitMultiSigUtxo> FakeCoins() => new List<SegWitMultiSigUtxo>
		{
			new SegWitMultiSigUtxo(RandomOutPoint(), Money.Coins(0.5m), 0, false),
			new SegWitMultiSigUtxo(RandomOutPoint(), Money.Coins(0.3m), 3, false),
			new SegWitMultiSigUtxo(RandomOutPoint(), Money.Coins(0.2m), 1, true),
		};

		// What travels between the signers is text: every PSBT is serialized and parsed again.
		private static SegWitMultiSigBundle Transport(SegWitMultiSigBundle bundle) => new SegWitMultiSigBundle
		{
			Inputs = bundle.Inputs.Select(i => new SegWitMultiSigBundleInput { Sequence = i.Sequence, IsChange = i.IsChange }).ToList(),
			Levels = bundle.Levels.Select(l => new SegWitMultiSigFeeLevel { Percent = l.Percent, Psbt = PSBT.Parse(l.Psbt.ToBase64(), Net) }).ToList()
		};

		private static BitcoinAddress NewAddress() => new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, Net);

		// ------------------------------------------------------------------ unit tests (no node)

		[Fact]
		public void AddressesDoNotDependOnTheOrderOfTheMembers()
		{
			var (group, members) = NewGroup(2, 4);
			var shuffled = Group(members.AsEnumerable().Reverse(), 2);
			foreach (var isChange in new[] { false, true })
				for (int seq = 0; seq < 5; seq++)
					Assert.Equal(group.GetMultiSig(seq, isChange).Address, shuffled.GetMultiSig(seq, isChange).Address);
			Assert.NotEqual(group.GetMultiSig(0, false).Address, group.GetMultiSig(1, false).Address);
			Assert.NotEqual(group.GetMultiSig(0, false).Address, group.GetMultiSig(0, true).Address);
			Assert.StartsWith("sh(wsh(sortedmulti(2,", group.GetDescriptor(false));
		}

		[Fact]
		public void LevelFeeIsRoundedUp()
		{
			Assert.Equal(Money.Satoshis(11000), SegWitMultiSigSpend.LevelFee(Money.Satoshis(10000), 10));
			Assert.Equal(Money.Satoshis(1113), SegWitMultiSigSpend.LevelFee(Money.Satoshis(1011), 10));   // 1112.1 -> 1113
			Assert.Equal(Money.Satoshis(20000), SegWitMultiSigSpend.LevelFee(Money.Satoshis(10000), 100));
			Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.CheckPercentages(new[] { 15 }));
			Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.CheckPercentages(new[] { 10, 10 }));
			Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.CheckPercentages(new[] { 10, 20, 30, 40 }));
			Assert.Equal(new[] { 10, 50, 100 }, SegWitMultiSigSpend.CheckPercentages(new[] { 100, 10, 50 }));
		}

		[Fact]
		public void BuildMakesOneLevelPerFee()
		{
			var (group, _) = NewGroup(2, 3);
			var dest = NewAddress();
			var change = group.GetMultiSig(2, true).Address;
			var bundle = SegWitMultiSigSpend.Build(group, FakeCoins(), dest, Money.Coins(0.7m), false, change, Money.Satoshis(10000), new[] { 50, 10 });
			var info = SegWitMultiSigSpend.Check(group, bundle);
			Assert.Equal(new[] { 0, 10, 50 }, bundle.Levels.Select(l => l.Percent));
			Assert.Equal(new[] { 10000L, 11000L, 15000L }, info.Fees.Select(f => f.Satoshi));
			Assert.Equal(Money.Coins(1.0m), info.TotalIn);
			Assert.Equal(dest.ScriptPubKey, info.PaymentScript);
			Assert.Equal(change.ScriptPubKey, info.ChangeScript);
			Assert.Empty(info.SignedBy);
			foreach (var level in bundle.Levels)
			{
				var tx = level.Psbt.GetGlobalTransaction();
				Assert.Equal(Money.Coins(0.7m), tx.Outputs[0].Value);
				Assert.All(tx.Inputs, i => Assert.Equal(SegWitMultiSigSpend.InputSequence, i.Sequence.Value));
			}

			// sending everything: no change, the amount of each level is the total minus its fee
			var all = SegWitMultiSigSpend.Build(group, FakeCoins(), dest, null, true, null, Money.Satoshis(10000), new[] { 100 });
			var allInfo = SegWitMultiSigSpend.Check(group, all);
			Assert.Null(allInfo.ChangeScript);
			Assert.Equal(Money.Coins(1.0m) - Money.Satoshis(20000), all.Levels[1].Psbt.GetGlobalTransaction().Outputs[0].Value);
		}

		[Fact]
		public void CheckRejectsATamperedBundle()
		{
			var (group, _) = NewGroup(2, 3);
			var coins = FakeCoins();
			var dest = NewAddress();
			var change = group.GetMultiSig(2, true).Address;
			SegWitMultiSigBundle Fresh(BitcoinAddress to = null, long fee = 10000, int[] percents = null) =>
				SegWitMultiSigSpend.Build(group, coins, to ?? dest, Money.Coins(0.7m), false, change, Money.Satoshis(fee), percents ?? new[] { 10, 50 });

			// a level that pays somebody else
			var b = Fresh();
			b.Levels[1].Psbt = Fresh(NewAddress()).Levels[1].Psbt;
			Assert.Contains("same address", Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.Check(group, b)).Message);

			// a level that pays more fee than its percentage says (the +100 % version labelled +10 %)
			b = Fresh();
			b.Levels[1].Psbt = Fresh(percents: new[] { 100 }).Levels[1].Psbt;
			Assert.Contains("does not pay the fee it says", Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.Check(group, b)).Message);

			// levels out of order, too many levels, the first one is not the calculated fee
			b = Fresh();
			b.Levels.Reverse();
			Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.Check(group, b));
			b = Fresh(percents: new[] { 10, 20, 30 });
			b.Levels.Add(new SegWitMultiSigFeeLevel { Percent = 40, Psbt = b.Levels[3].Psbt });
			Assert.Contains("At most", Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.Check(group, b)).Message);

			// a coin of another group
			var (other, _) = NewGroup(2, 3);
			b = Fresh();
			Assert.Contains("not a coin of this group", Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.Check(other, b)).Message);
		}

		[Fact]
		public void SigningRules()
		{
			var (group, members) = NewGroup(3, 4);
			var change = group.GetMultiSig(2, true).Address;
			var bundle = SegWitMultiSigSpend.Build(group, FakeCoins(), NewAddress(), Money.Coins(0.7m), false, change, Money.Satoshis(10000), new[] { 10, 50 });
			var stranger = new Member();

			Assert.Contains("does not belong", Assert.Throws<ArgumentException>(() =>
				SegWitMultiSigSpend.Sign(group, Transport(bundle), stranger.Receiving, stranger.Change, -1)).Message);
			// the fee is chosen by the last signer only
			Assert.Contains("chosen by the last signer", Assert.Throws<ArgumentException>(() =>
				SegWitMultiSigSpend.Sign(group, Transport(bundle), members[0].Receiving, members[0].Change, 10)).Message);

			bundle = Transport(bundle);
			var info = SegWitMultiSigSpend.Sign(group, bundle, members[0].Receiving, members[0].Change, -1);
			Assert.Equal(new[] { 0 }, info.SignedBy);
			Assert.Equal(3, bundle.Levels.Count);
			Assert.Contains("already signed", Assert.Throws<ArgumentException>(() =>
				SegWitMultiSigSpend.Sign(group, Transport(bundle), members[0].Receiving, members[0].Change, -1)).Message);
			Assert.Contains("More signatures", Assert.Throws<ArgumentException>(() =>
				SegWitMultiSigSpend.Finalize(group, bundle, 0)).Message);

			// a bundle cut down to one "chosen" level before the last signature: nobody may sign it
			var cut = Transport(bundle);
			cut.Levels = new List<SegWitMultiSigFeeLevel> { cut.Levels[2] };
			Assert.Contains("calculated fee", Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.Check(group, cut)).Message);

			// one level signed by somebody else: the levels are no longer signed by the same members
			var forged = Transport(bundle);
			for (int i = 0; i < forged.Inputs.Count; i++)
			{
				var input = forged.Inputs[i];
				forged.Levels[2].Psbt.Inputs[i].Sign((input.IsChange ? members[1].Change : members[1].Receiving).Derive((uint)input.Sequence).PrivateKey);
			}
			Assert.Contains("same members", Assert.Throws<ArgumentException>(() => SegWitMultiSigSpend.Check(group, forged)).Message);

			bundle = Transport(bundle);
			info = SegWitMultiSigSpend.Sign(group, bundle, members[2].Receiving, members[2].Change, -1);
			Assert.True(info.NextIsLast);
			bundle = Transport(bundle);
			info = SegWitMultiSigSpend.Sign(group, bundle, members[3].Receiving, members[3].Change, 50);
			Assert.True(info.Complete);
			Assert.Single(bundle.Levels);
			Assert.Equal(new[] { 0, 2, 3 }, info.SignedBy);
			var tx = SegWitMultiSigSpend.Finalize(group, bundle, 50);
			Assert.Equal(3, tx.Inputs.Count);
			Assert.Contains("all the signatures", Assert.Throws<ArgumentException>(() =>
				SegWitMultiSigSpend.Sign(group, Transport(bundle), members[1].Receiving, members[1].Change, -1)).Message);
		}

		[Fact]
		public void EveryCombinationSignsAndFinalizesOffline()
		{
			foreach (var (k, n) in new[] { (1, 2), (2, 2), (2, 3), (3, 5), (5, 10), (7, 10), (15, 15), (16, 16) })
			{
				var (group, members) = NewGroup(k, n);
				var bundle = SegWitMultiSigSpend.Build(group, FakeCoins(), NewAddress(), Money.Coins(0.7m), false,
					group.GetMultiSig(2, true).Address, Money.Satoshis(20000), new[] { 10, 50, 100 });
				var signers = members.OrderBy(_ => RandomUtils.GetInt32()).Take(k).ToList();
				for (int s = 0; s < k; s++)
				{
					bundle = Transport(bundle);
					SegWitMultiSigSpend.Sign(group, bundle, signers[s].Receiving, signers[s].Change, s == k - 1 ? 100 : -1);
				}
				var tx = SegWitMultiSigSpend.Finalize(group, bundle, 100);
				Assert.Equal(Money.Satoshis(40000), Money.Coins(1.0m) - tx.Outputs.Select(o => o.Value).Sum());
				_output.WriteLine($"{k}-of-{n}: vsize {tx.GetVirtualSize()}");
			}
		}

		// ------------------------------------------------------------------ on a RegTest node started from scratch

		private sealed class Funded
		{
			public SegWitMultiSigGroup Group;
			public List<Member> Members;
			public List<SegWitMultiSigUtxo> Coins = new List<SegWitMultiSigUtxo>();
		}

		// funds three addresses of a new group: receiving 0 and 3, change 1
		private static Funded Fund(RPCClient rpc, int k, int n)
		{
			var (group, members) = NewGroup(k, n);
			var funded = new Funded { Group = group, Members = members };
			foreach (var (seq, isChange, btc) in new[] { (0, false, 0.5m), (3, false, 0.3m), (1, true, 0.2m) })
			{
				var address = group.GetMultiSig(seq, isChange).Address;
				var txid = rpc.SendToAddress(address, Money.Coins(btc));
				var tx = rpc.GetRawTransaction(txid);
				var vout = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == address.ScriptPubKey);
				funded.Coins.Add(new SegWitMultiSigUtxo(new OutPoint(txid, vout.N), vout.TxOut.Value, seq, isChange));
			}
			rpc.Generate(1);
			return funded;
		}

		// k members sign one after the other; the last one chooses `chosen` (or, with chosen < 0, everybody signs every level)
		private static SegWitMultiSigBundle SignAll(Funded f, SegWitMultiSigBundle bundle, int chosen)
		{
			var signers = f.Members.OrderBy(_ => RandomUtils.GetInt32()).Take(f.Group.RequiredSignatures).ToList();
			for (int s = 0; s < signers.Count; s++)
			{
				bundle = Transport(bundle);
				var last = s == signers.Count - 1;
				SegWitMultiSigSpend.Sign(f.Group, bundle, signers[s].Receiving, signers[s].Change, last && chosen >= 0 ? chosen : -1);
			}
			return bundle;
		}

		[Fact]
		public void CanSpendManyCombinationsWithFeeLevelsOnANode()
		{
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var cases = new[] { (1, 2, 0), (2, 2, 10), (2, 3, 50), (3, 5, 100), (5, 10, 50), (7, 10, 0), (15, 15, 100), (16, 16, 10) };
				foreach (var (k, n, chosen) in cases)
				{
					var f = Fund(rpc, k, n);
					var dest = rpc.GetNewAddress();
					var change = f.Group.GetMultiSig(2, true).Address;
					var baseFee = Money.Satoshis(20000);
					var bundle = SegWitMultiSigSpend.Build(f.Group, f.Coins, dest, Money.Coins(0.7m), false, change, baseFee, new[] { 10, 50, 100 });
					bundle = SignAll(f, bundle, chosen);
					Assert.Single(bundle.Levels);

					var tx = SegWitMultiSigSpend.Finalize(f.Group, bundle, chosen);
					rpc.SendRawTransaction(tx);
					var entry = rpc.GetMempoolEntry(tx.GetHash());
					Assert.Equal(SegWitMultiSigSpend.LevelFee(baseFee, chosen), entry.BaseFee);
					rpc.Generate(1);
					Assert.Equal(Money.Coins(0.7m), rpc.GetReceivedByAddress(dest, 1));
					_output.WriteLine($"{k}-of-{n}: +{chosen} % chosen, fee {entry.BaseFee.Satoshi} sats, vsize {entry.VirtualSizeBytes}, confirmed");
				}

				// the change of a payment is a coin of the group: spend it, sending everything, no change
				{
					var f = Fund(rpc, 2, 3);
					var dest = rpc.GetNewAddress();
					var bundle = SegWitMultiSigSpend.Build(f.Group, f.Coins, dest, null, true, null, Money.Satoshis(20000), new[] { 50 });
					bundle = SignAll(f, bundle, 50);
					var tx = SegWitMultiSigSpend.Finalize(f.Group, bundle, 50);
					Assert.Single(tx.Outputs);
					rpc.SendRawTransaction(tx);
					rpc.Generate(1);
					Assert.Equal(Money.Coins(1.0m) - Money.Satoshis(30000), rpc.GetReceivedByAddress(dest, 1));
					_output.WriteLine("2-of-3 sending everything: confirmed");
				}

				// replace-by-fee: with every level signed, a higher level replaces a lower one in the mempool
				{
					var f = Fund(rpc, 2, 3);
					var bundle = SegWitMultiSigSpend.Build(f.Group, f.Coins, rpc.GetNewAddress(), Money.Coins(0.7m), false,
						f.Group.GetMultiSig(2, true).Address, Money.Satoshis(20000), new[] { 50 });
					bundle = SignAll(f, bundle, -1);
					Assert.Equal(2, bundle.Levels.Count);
					var low = SegWitMultiSigSpend.Finalize(f.Group, bundle, 0);
					var high = SegWitMultiSigSpend.Finalize(f.Group, bundle, 50);
					rpc.SendRawTransaction(low);
					rpc.SendRawTransaction(high);
					var mempool = rpc.GetRawMempool();
					Assert.Contains(high.GetHash(), mempool);
					Assert.DoesNotContain(low.GetHash(), mempool);
					rpc.Generate(1);
					_output.WriteLine("2-of-3: the +50 % level replaced the calculated one (RBF)");
				}

				// Bitcoin Core derives the same addresses from the descriptors
				{
					var (group, _) = NewGroup(3, 5);
					foreach (var isChange in new[] { false, true })
					{
						var derived = rpc.SendCommand("deriveaddresses", group.GetDescriptor(isChange), new[] { 0, 4 }).Result
							.Select(a => a.ToString()).ToList();
						for (int seq = 0; seq <= 4; seq++)
							Assert.Equal(group.GetMultiSig(seq, isChange).Address.ToString(), derived[seq]);
					}
					_output.WriteLine("3-of-5: Bitcoin Core derives the group addresses from both descriptors");
				}
			}
		}
	}
}
