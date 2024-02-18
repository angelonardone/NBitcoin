using System;
using System.Threading;
using System.Threading.Tasks;
using NBitcoin;
using NBitcoin.Protocol;
using NBitcoin.Protocol.Behaviors;
using NBitcoin.Tests;

namespace NBitcoinTraining
{
	class Program
	{
		// For this to build, you need to set C# 7.1 in your csproj file
		// <PropertyGroup>
		//   ...
		//   ...
		//   <LangVersion>7.1</LangVersion>
		// </PropertyGroup>
		static async Task Main(string[] args)
		{
			// During the first run, this will take time to run, as it download bitcoin core binaries (more than 40MB)
			using (var env = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				// Removing node logs from output
				env.ConfigParameters.Add("printtoconsole", "0");
				var alice = env.CreateNode();
				var miner = env.CreateNode();
				var minerRPC = miner.CreateRPCClient();
				var aliceRPC = alice.CreateRPCClient();
				env.StartAll();
				SlimChain chain = new SlimChain(env.Network.GenesisHash);
				var slimChainBehavior = new SlimChainBehavior(chain);
				var aliceNodeConnection = alice.CreateNodeClient();
				aliceNodeConnection.Behaviors.Add(slimChainBehavior);
				aliceNodeConnection.VersionHandshake();
				miner.Generate(101);
				alice.Sync(miner, true);

				await WaitInSync(alice, chain);
				System.Console.WriteLine($"SlimChain height: {chain.Height}");
			}
		}

		private static async Task WaitInSync(CoreNode node, SlimChain chain)
		{
			var rpc = node.CreateRPCClient();
			while (chain.Tip != await rpc.GetBestBlockHashAsync())
			{
				await Task.Delay(100);
			}
		}
	}
}
