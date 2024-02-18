using System;
using System.Threading;
using NBitcoin;
using NBitcoin.Tests;

namespace NBitcoinTraining
{
	class Program
	{
		static void Main(string[] args)
		{
			// During the first run, this will take time to run, as it download bitcoin core binaries (more than 40MB)
			using (var env = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				// Removing node logs from output
				env.ConfigParameters.Add("printtoconsole", "0");

				var alice = env.CreateNode();
				var bob = env.CreateNode();
				var miner = env.CreateNode();
				env.StartAll();
				Console.WriteLine("Created 3 nodes (alice, bob, miner)");

				Console.WriteLine("Connect nodes to each other");
				miner.Sync(alice, true);
				miner.Sync(bob, true);

				Console.WriteLine("Generate 101 blocks so miner can spend money");
				var minerRPC = miner.CreateRPCClient();
				miner.Generate(101);

				var aliceRPC = alice.CreateRPCClient();
				var bobRPC = bob.CreateRPCClient();
				var bobAddress = bobRPC.GetNewAddress();

				Console.WriteLine("Alice gets money from miner");
				var aliceAddress = aliceRPC.GetNewAddress();
				minerRPC.SendToAddress(aliceAddress, Money.Coins(20m));

				Console.WriteLine("Mine a block and check that alice is now synched with the miner (same block height)");
				minerRPC.Generate(1);
				alice.Sync(miner);

				Console.WriteLine($"Alice Balance: {aliceRPC.GetBalance()}");

				Console.WriteLine("Alice send 1 BTC to bob");
				aliceRPC.SendToAddress(bobAddress, Money.Coins(1.0m));
				Console.WriteLine($"Alice mine her own transaction");
				aliceRPC.Generate(1);

				alice.Sync(bob);

				Console.WriteLine($"Alice Balance: {aliceRPC.GetBalance()}");
				Console.WriteLine($"Bob Balance: {bobRPC.GetBalance()}");
			}
		}
	}
}
