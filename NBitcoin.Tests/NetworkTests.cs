﻿using System.IO;
using System.Linq;
using System.Threading;
using NBitcoin;
using Xunit;
using System;

namespace NBitcoin.Tests
{
	public class NetworkTests
	{
		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void NetworkListIsInitialized()
		{
			Assert.NotEmpty(Network.GetNetworks());
		}
		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void NetworkListHasNoDuplicates()
		{
			var uniqueNetworkCount = Network.GetNetworks().Select(n => n.Name + n.ChainName).ToHashSet().Count();
			Assert.Equal(Network.GetNetworks().Count(), uniqueNetworkCount);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanGetNetworkFromName()
		{
			Assert.Equal(Network.GetNetwork("main"), Network.Main);
			Assert.Equal(Network.GetNetwork("reg"), Network.RegTest);
			Assert.Equal(Network.GetNetwork("regtest"), Network.RegTest);
			Assert.Equal(Network.GetNetwork("testnet"), Network.TestNet);
			Assert.Equal(Network.GetNetwork("testnet3"), Network.TestNet);
			Assert.Equal(Network.GetNetwork("testnet4"), Bitcoin.Instance.Testnet4);
			Assert.Equal(Network.GetNetwork("signet"), Bitcoin.Instance.Signet);
			Assert.Equal(Network.GetNetwork("mutinynet"), Bitcoin.Instance.Mutinynet);
			Assert.Null(Network.GetNetwork("invalid"));
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanGetAllShitcoins()
		{
			NBitcoin.Altcoins.AltNetworkSets.GetAll().Select(c => c.Regtest).ToList();
			NBitcoin.Altcoins.AltNetworkSets.GetAll().Select(c => c.Testnet).ToList();
			NBitcoin.Altcoins.AltNetworkSets.GetAll().Select(c => c.Mainnet).ToList();
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanCreateNetwork()
		{
			NetworkBuilder builder = new NetworkBuilder();
			builder.CopyFrom(Network.Main);
			builder.SetName(null);
			Assert.Throws<InvalidOperationException>(() => builder.BuildAndRegister());
			builder.SetName("new");
			builder.AddAlias("newalias");
			var network = builder.BuildAndRegister();
			Assert.Throws<InvalidOperationException>(() => builder.BuildAndRegister());

			Assert.Equal(network, Network.GetNetwork("new"));
			Assert.Equal(network, Network.GetNetwork("newalias"));

			CanGetNetworkFromName();

			Assert.Contains(network, Network.GetNetworks());
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void ReadMagicByteWithFirstByteDuplicated()
		{
			var bytes = Network.Main.MagicBytes.ToList();
			bytes.Insert(0, bytes.First());

			using (var memstrema = new MemoryStream(bytes.ToArray()))
			{
				var found = Network.Main.ReadMagic(memstrema, new CancellationToken());
				Assert.True(found);
			}
		}
	}
}
