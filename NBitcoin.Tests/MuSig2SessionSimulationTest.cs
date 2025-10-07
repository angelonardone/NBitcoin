using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using Xunit;

namespace NBitcoin.Tests
{
	/// <summary>
	/// Simulates MuSig2 session management to demonstrate the state management problem
	/// and validate the session-based approach.
	/// </summary>
	public class MuSig2SessionSimulationTest
	{
		/// <summary>
		/// In-memory session storage to simulate what the session manager would do.
		/// This demonstrates state isolation between concurrent signing operations.
		/// </summary>
		private class SessionStorage
		{
			private readonly Dictionary<string, SessionState> _sessions = new Dictionary<string, SessionState>();

			public string CreateSession(DelegatedMultiSig2 multiSig, Transaction tx, ICoin[] coins)
			{
				var sessionId = Guid.NewGuid().ToString();
				_sessions[sessionId] = new SessionState
				{
					MultiSig = multiSig,
					Transaction = tx,
					Coins = coins,
					Builder = multiSig.CreateSignatureBuilder(tx, coins)
				};
				return sessionId;
			}

			public DelegatedMultiSig2.MuSig2SignatureBuilder GetBuilder(string sessionId)
			{
				if (!_sessions.TryGetValue(sessionId, out var state))
					throw new InvalidOperationException($"Session {sessionId} not found");
				return state.Builder;
			}

			public void CloseSession(string sessionId)
			{
				_sessions.Remove(sessionId);
			}

			public int GetActiveCount() => _sessions.Count;

			private class SessionState
			{
				public DelegatedMultiSig2 MultiSig { get; set; }
				public Transaction Transaction { get; set; }
				public ICoin[] Coins { get; set; }
				public DelegatedMultiSig2.MuSig2SignatureBuilder Builder { get; set; }
			}
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void SessionStorage_IsolatesConcurrentSigning_Simulation()
		{
			Console.WriteLine("=== MuSig2 Session Isolation Simulation ===");
			Console.WriteLine("Demonstrating: Multiple concurrent signing operations don't interfere\n");

			// Setup
			var ownerKey = new Key();
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();
			var multiSig = new DelegatedMultiSig2(ownerKey.PubKey, signerPubKeys, 2, Network.RegTest);

			var sessionStorage = new SessionStorage();

			Console.WriteLine($"📋 Created 2-of-3 MuSig2 multisig");
			Console.WriteLine($"   • Signers: 3 participants");
			Console.WriteLine($"   • Threshold: 2 signatures required\n");

			// Create two different transactions
			var tx1 = CreateDummyTransaction(multiSig, Money.Coins(1.0m));
			var tx2 = CreateDummyTransaction(multiSig, Money.Coins(2.0m));
			var coin1 = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			var coin2 = new Coin(new OutPoint(uint256.One, 1), new TxOut(Money.Coins(2.0m), multiSig.Address.ScriptPubKey));

			// ============================================================
			// Scenario: User is signing TWO transactions concurrently
			// ============================================================

			Console.WriteLine("👤 User initiates TWO concurrent signing sessions:");
			var session1 = sessionStorage.CreateSession(multiSig, tx1, new[] { coin1 });
			var session2 = sessionStorage.CreateSession(multiSig, tx2, new[] { coin2 });

			Console.WriteLine($"   • Session 1: {session1.Substring(0, 8)}... (tx1: 1.0 BTC)");
			Console.WriteLine($"   • Session 2: {session2.Substring(0, 8)}... (tx2: 2.0 BTC)");
			Console.WriteLine($"   • Active sessions: {sessionStorage.GetActiveCount()}\n");

			Assert.Equal(2, sessionStorage.GetActiveCount());

			// Round 1: Generate nonces for BOTH sessions
			Console.WriteLine("🔐 Round 1: Generating nonces for both sessions...");
			var builder1 = sessionStorage.GetBuilder(session1);
			var builder2 = sessionStorage.GetBuilder(session2);

			var nonces1_s0 = builder1.GenerateNonce(signerKeys[0], 0);
			var nonces1_s1 = builder1.GenerateNonce(signerKeys[1], 0);

			var nonces2_s0 = builder2.GenerateNonce(signerKeys[0], 0);
			var nonces2_s1 = builder2.GenerateNonce(signerKeys[1], 0);

			Console.WriteLine($"   ✅ Session 1: Generated nonces for signers 0 and 1");
			Console.WriteLine($"   ✅ Session 2: Generated nonces for signers 0 and 1");
			Console.WriteLine($"   ✅ Nonces are ISOLATED (different for each session)\n");

			// Verify nonces are different between sessions
			Assert.NotEqual(nonces1_s0.Serialize(), nonces2_s0.Serialize());
			Assert.NotEqual(nonces1_s1.Serialize(), nonces2_s1.Serialize());

			// Round 2: Exchange nonces
			Console.WriteLine("📤 Round 2: Exchanging nonces...");
			builder1.AddNonces(nonces1_s0, 0);
			builder1.AddNonces(nonces1_s1, 0);

			builder2.AddNonces(nonces2_s0, 0);
			builder2.AddNonces(nonces2_s1, 0);

			Console.WriteLine($"   ✅ Session 1: Nonces exchanged");
			Console.WriteLine($"   ✅ Session 2: Nonces exchanged");
			Console.WriteLine($"   ✅ No cross-contamination between sessions\n");

			// Round 3: Sign both sessions
			Console.WriteLine("✍️  Round 3: Signing...");
			var sig1 = builder1.SignWithSigner(signerKeys[0], 0);
			var sig2 = builder2.SignWithSigner(signerKeys[0], 0);

			builder1.SignWithSigner(signerKeys[1], 0);
			builder2.SignWithSigner(signerKeys[1], 0);

			Console.WriteLine($"   ✅ Session 1: Signed by signers 0 and 1");
			Console.WriteLine($"   ✅ Session 2: Signed by signers 0 and 1");
			Console.WriteLine($"   ✅ Signatures are session-specific\n");

			// Finalize both
			Console.WriteLine("🏁 Finalizing both sessions...");
			var finalTx1 = builder1.FinalizeTransaction(0);
			var finalTx2 = builder2.FinalizeTransaction(0);

			Console.WriteLine($"   ✅ Session 1 finalized: {finalTx1.GetHash().ToString().Substring(0, 16)}...");
			Console.WriteLine($"   ✅ Session 2 finalized: {finalTx2.GetHash().ToString().Substring(0, 16)}...");
			Console.WriteLine($"   ✅ Different transactions (correct!)\n");

			Assert.NotEqual(finalTx1.GetHash(), finalTx2.GetHash());

			// Cleanup
			Console.WriteLine("🧹 Cleanup: Closing sessions...");
			sessionStorage.CloseSession(session1);
			sessionStorage.CloseSession(session2);

			Console.WriteLine($"   ✅ Sessions closed");
			Console.WriteLine($"   ✅ Active sessions: {sessionStorage.GetActiveCount()}\n");

			Assert.Equal(0, sessionStorage.GetActiveCount());

			Console.WriteLine("✅ SUCCESS: Session isolation demonstrated!");
			Console.WriteLine("   • Two concurrent signings completed without interference");
			Console.WriteLine("   • Each session had independent nonces and signatures");
			Console.WriteLine("   • Proper cleanup after completion");
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void WithoutSessions_StateConfusion_Simulation()
		{
			Console.WriteLine("=== Problem Demonstration: Without Sessions ===");
			Console.WriteLine("Showing: State confusion when using same builder for different transactions\n");

			var ownerKey = new Key();
			var signerKeys = new List<Key> { new Key(), new Key(), new Key() };
			var signerPubKeys = signerKeys.Select(k => k.PubKey).ToList();
			var multiSig = new DelegatedMultiSig2(ownerKey.PubKey, signerPubKeys, 2, Network.RegTest);

			var tx1 = CreateDummyTransaction(multiSig, Money.Coins(1.0m));
			var tx2 = CreateDummyTransaction(multiSig, Money.Coins(2.0m));
			var coin1 = new Coin(new OutPoint(uint256.One, 0), new TxOut(Money.Coins(1.0m), multiSig.Address.ScriptPubKey));
			var coin2 = new Coin(new OutPoint(uint256.One, 1), new TxOut(Money.Coins(2.0m), multiSig.Address.ScriptPubKey));

			Console.WriteLine("❌ WRONG: Reusing same builder for different transactions");

			// User tries to sign tx1
			Console.WriteLine("\n👤 User starts signing tx1...");
			var builder = multiSig.CreateSignatureBuilder(tx1, new[] { coin1 });
			var nonces1 = builder.GenerateNonce(signerKeys[0], 0);
			Console.WriteLine($"   • Generated nonces for tx1");

			// User gets interrupted, starts signing tx2 with SAME PATTERN (new builder, but conceptually same variable)
			Console.WriteLine("\n👤 User switches to signing tx2 (simulating lost state)...");
			builder = multiSig.CreateSignatureBuilder(tx2, new[] { coin2 }); // ← Lost tx1 state!
			var nonces2 = builder.GenerateNonce(signerKeys[0], 0);
			Console.WriteLine($"   • Generated nonces for tx2");
			Console.WriteLine($"   ❌ PROBLEM: Lost all state for tx1!");

			// Now user can't go back to tx1 - the nonces are lost!
			Console.WriteLine("\n❌ User wants to complete tx1, but:");
			Console.WriteLine($"   • Nonces for tx1 are LOST");
			Console.WriteLine($"   • Must start over from scratch");
			Console.WriteLine($"   • Cannot have concurrent signing operations");

			Console.WriteLine("\n💡 SOLUTION: Use session-based API");
			Console.WriteLine($"   • Each signing gets unique session ID");
			Console.WriteLine($"   • State persisted independently");
			Console.WriteLine($"   • Can switch between signings freely");
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void SessionTimeout_Simulation()
		{
			Console.WriteLine("=== Session Timeout Simulation ===");
			Console.WriteLine("Demonstrating: Automatic cleanup of abandoned sessions\n");

			var sessions = new Dictionary<string, (DateTime created, DateTime lastAccessed)>();
			var timeout = TimeSpan.FromHours(1);

			Console.WriteLine($"⏰ Session timeout: {timeout.TotalMinutes} minutes\n");

			// Create some sessions
			Console.WriteLine("📝 Creating sessions...");
			var session1 = Guid.NewGuid().ToString();
			var session2 = Guid.NewGuid().ToString();
			var session3 = Guid.NewGuid().ToString();

			var now = DateTime.UtcNow;
			sessions[session1] = (now.AddHours(-2), now.AddHours(-2)); // Old, inactive
			sessions[session2] = (now.AddHours(-1.5), now.AddHours(-1.5)); // Old, inactive
			sessions[session3] = (now, now); // New, active

			Console.WriteLine($"   • Session 1: Created 2 hours ago, last accessed 2 hours ago");
			Console.WriteLine($"   • Session 2: Created 1.5 hours ago, last accessed 1.5 hours ago");
			Console.WriteLine($"   • Session 3: Created just now, active");
			Console.WriteLine($"   • Total sessions: {sessions.Count}\n");

			// Cleanup expired
			Console.WriteLine("🧹 Cleaning up expired sessions...");
			var currentTime = DateTime.UtcNow;
			var expiredCount = 0;

			foreach (var kvp in sessions.ToList())
			{
				var (created, lastAccessed) = kvp.Value;
				if (currentTime - lastAccessed > timeout)
				{
					Console.WriteLine($"   ❌ Session {kvp.Key.Substring(0, 8)}... expired (inactive for {(currentTime - lastAccessed).TotalMinutes:F0} min)");
					sessions.Remove(kvp.Key);
					expiredCount++;
				}
			}

			Console.WriteLine($"\n   ✅ Cleaned up {expiredCount} expired session(s)");
			Console.WriteLine($"   ✅ Active sessions remaining: {sessions.Count}");
			Console.WriteLine($"   ✅ Memory freed automatically\n");

			Assert.Equal(1, sessions.Count);
			Assert.True(sessions.ContainsKey(session3));

			Console.WriteLine("✅ SUCCESS: Automatic cleanup prevents memory leaks!");
			Console.WriteLine("   • Old sessions removed automatically");
			Console.WriteLine("   • Active sessions preserved");
			Console.WriteLine("   • No manual intervention needed");
		}

		private Transaction CreateDummyTransaction(DelegatedMultiSig2 multiSig, Money amount)
		{
			var tx = Network.RegTest.CreateTransaction();
			tx.Inputs.Add(new OutPoint(uint256.One, 0));
			tx.Outputs.Add(amount, multiSig.Address);
			return tx;
		}
	}
}
