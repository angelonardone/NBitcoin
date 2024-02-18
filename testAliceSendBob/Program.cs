using System;
using System.Linq;
using System.Collections.Generic;
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

				var bob = env.CreateNode();
				var miner = env.CreateNode();
				miner.ConfigParameters.Add("txindex", "1"); // So we can query a tx from txid
				env.StartAll();
				Console.WriteLine("Created 3 nodes (alice, bob, miner)");

				Console.WriteLine("Connect nodes to each other");
				miner.Sync(bob, true);

				Console.WriteLine("Generate 101 blocks so miner can spend money");
				var minerRPC = miner.CreateRPCClient();
				miner.Generate(101);

				var bobRPC = bob.CreateRPCClient();
				var bobAddress = bobRPC.GetNewAddress();

				Console.WriteLine("Alice gets money from miner");
				var aliceKey = new Key();
				var aliceAddress = aliceKey.PubKey.GetAddress(ScriptPubKeyType.Legacy, Network.RegTest);
				var minerToAliceTxId = minerRPC.SendToAddress(aliceAddress, Money.Coins(20m));

				Console.WriteLine("Mine a block and check that alice is now synched with the miner (same block height)");
				minerRPC.Generate(1);

				var minerToAliceTx = minerRPC.GetRawTransaction(minerToAliceTxId);
				var aliceUnspentCoins = minerToAliceTx.Outputs.AsCoins()
								.Where(c => c.ScriptPubKey == aliceAddress.ScriptPubKey)
								.ToDictionary(c => c.Outpoint, c => c);

				Console.WriteLine($"Alice Balance: {aliceUnspentCoins.Select(c => c.Value.TxOut.Value).Sum()}");

				Console.WriteLine("Alice send 1 BTC to bob");

				var txBuilder = Network.RegTest.CreateTransactionBuilder();
				var aliceToBobTx = txBuilder.AddKeys(aliceKey)
						 .AddCoins(aliceUnspentCoins.Values)
						 .Send(bobAddress, Money.Coins(1.0m))
						 .SetChange(aliceAddress)
						 .SendFees(Money.Coins(0.00001m))
						 .BuildTransaction(true);

				Console.WriteLine($"Alice broadcast to miner");
				minerRPC.SendRawTransaction(aliceToBobTx);

				foreach (var input in aliceToBobTx.Inputs)
				{
					// Let's remove what alice spent
					aliceUnspentCoins.Remove(input.PrevOut);
				}
				foreach (var output in aliceToBobTx.Outputs.AsCoins())
				{
					if (output.ScriptPubKey == aliceAddress.ScriptPubKey)
					{
						// Let's add what alice received
						aliceUnspentCoins.Add(output.Outpoint, output);
					}
				}

				miner.Generate(1);
				miner.Sync(bob);

				Console.WriteLine($"Alice Balance: {aliceUnspentCoins.Select(c => c.Value.TxOut.Value).Sum()}");
				Console.WriteLine($"Bob Balance: {bobRPC.GetBalance()}");
			}
		}
	}
}
