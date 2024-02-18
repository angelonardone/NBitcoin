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
				var testNode = env.CreateNode();
				env.StartAll();

				var p2p = testNode.CreateNodeClient();
				p2p.VersionHandshake();
				System.Console.WriteLine("Connected via P2P!");
				testNode.Generate(101);

				var headerChain = p2p.GetSlimChain();
				System.Console.WriteLine($"Header chain retrieved with {headerChain.Height} blocks");
			}
		}
	}
}
