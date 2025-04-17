using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.RPC;
using NBitcoin.Protocol;
using System.Net;
using NBitcoin.Scripting;
using System.Transactions;
using Transaction = NBitcoin.Transaction;
using static NBitcoin.RPC.SignRawTransactionRequest;
using static NBitcoin.Scripting.PubKeyProvider;
using System.Drawing;
using System.Reflection.Metadata;
using System.Threading;
using System.Text;

namespace angeloNBitcoin
{
	class Program
	{

		static void Main(string[] args)
		{

			From_BIP86();
		}
		static void From_BIP86()
		{
			var network = Network.Main;
			var mnemo = new Mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
			var root = mnemo.DeriveExtKey();

			var privKey = root.Derive(KeyPath.Parse("m/86'/0'/0'" + "/0/0"));
			var extPrivKey = privKey.GetWif(network).ToString();
			var masterPubKey = privKey.Neuter();
			Console.WriteLine(extPrivKey.ToString()); // "xprvA449goEeU9okwCzzZaxiy475EQGQzBkc65su82nXEvcwzfSskb2hAt2WymrjyRL6kpbVTGL3cKtp9herYXSjjQ1j4stsXXiRF7kXkCacK3T"
			Console.WriteLine(masterPubKey.ToString(network)); // "xpub6H3W6JmYJXN49h5TfcVjLC3onS6uPeUTTJoVvRC8oG9vsTn2J8LwigLzq5tHbrwAzH9DGo6ThGUdWsqce8dGfwHVBxSbixjDADGGdzF7t2B"

			var address = privKey.GetPublicKey().GetAddress(ScriptPubKeyType.TaprootBIP86, network);
			Console.WriteLine(address); // "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"

			var privateKey = privKey.PrivateKey;
			var publicKey = privateKey.PubKey;
			var netAddress = publicKey.GetAddress(ScriptPubKeyType.TaprootBIP86, network);

			Console.WriteLine(netAddress); // "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
			Console.WriteLine(netAddress.ScriptPubKey);
			var a = BitcoinAddress.Create("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", network);
			Console.WriteLine(a.Equals(TaprootAddress.Create("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", network)));

			var taproot = privateKey.CreateTaprootKeyPair();
			Console.WriteLine(privateKey.ToHex().ToString()); // "41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361"
			Console.WriteLine(publicKey.ToHex().ToString()); // "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
			Console.WriteLine(taproot.Key.ToHex().ToString()); // "41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361"
			Console.WriteLine(taproot.PubKey.ToString()); // "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
			Console.WriteLine("internal_key: " + taproot.PubKey.InternalKey.ToString()); // "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
			Console.WriteLine("output_key: " + taproot.PubKey.OutputKey.ToString()); // "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
			Console.WriteLine("output_key: " + privateKey.PubKey.GetTaprootFullPubKey());
			Console.WriteLine("internal_key: " + privateKey.PubKey.TaprootInternalKey);

			Console.WriteLine(TaprootAddress.Create("bcrt1p7n6re4ny2e7g2znucml5xczyzc6tw3lpnezeqh72sn5y0yz9kk3s9swzfp", Network.RegTest));
			Console.WriteLine(TaprootAddress.Create("bcrt1pv7t4684zpxsye63m6kjzarg3ct85lwdu0mn02lfwlfdppzv0muyquvuty9", Network.RegTest));



			var main_key = new Key(NBitcoin.DataEncoders.Encoders.Hex.DecodeData("611bf4560ecd9d966880bc1221c39aa089b9def014466f7e16ec4e0e8a99492b"));


			Console.WriteLine("taproot pubkey: " + main_key.PubKey.GetTaprootFullPubKey().ToString());
			var pub_tap_key = main_key.PubKey.GetTaprootFullPubKey();

			Console.WriteLine("taproot internal key" + pub_tap_key.InternalKey.ToString());

			var taprootaddress = TaprootAddress.Create("bcrt1pmmezxxh9n9vrp5wtkqxfy93wnp733aefkt9r2cxlqfhet603fmnscr8kg8", Network.RegTest);
			var bitcoinaddress  = BitcoinAddress.Create("bcrt1pmmezxxh9n9vrp5wtkqxfy93wnp733aefkt9r2cxlqfhet603fmnscr8kg8", Network.RegTest);
			Console.WriteLine("pubKey " + taprootaddress.PubKey.ToString());
			Console.WriteLine("pubKey  " + bitcoinaddress.ToString());



			/*
			 * 
			 * Test Vectors
				mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
				rootpriv = xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu
				rootpub  = xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8

				// Account 0, root = m/86'/0'/0'
				xprv = xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk
				xpub = xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ

				// Account 0, first receiving address = m/86'/0'/0'/0/0
				xprv         = xprvA449goEeU9okwCzzZaxiy475EQGQzBkc65su82nXEvcwzfSskb2hAt2WymrjyRL6kpbVTGL3cKtp9herYXSjjQ1j4stsXXiRF7kXkCacK3T
				xpub         = xpub6H3W6JmYJXN49h5TfcVjLC3onS6uPeUTTJoVvRC8oG9vsTn2J8LwigLzq5tHbrwAzH9DGo6ThGUdWsqce8dGfwHVBxSbixjDADGGdzF7t2B
				internal_key = cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
				output_key   = a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
				scriptPubKey = 5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
				address      = bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr

				// Account 0, second receiving address = m/86'/0'/0'/0/1
				xprv         = xprvA449goEeU9okyiF1LmKiDaTgeXvmh87DVyRd35VPbsSop8n8uALpbtrUhUXByPFKK7C2yuqrB1FrhiDkEMC4RGmA5KTwsE1aB5jRu9zHsuQ
				xpub         = xpub6H3W6JmYJXN4CCKUSnriaiQRCZmG6aq4sCMDqTu1ACyngw7HShf59hAxYjXgKDuuHThVEUzdHrc3aXCr9kfvQvZPit5dnD3K9xVRBzjK3rX
				internal_key = 83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145
				output_key   = a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb
				scriptPubKey = 5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb
				address      = bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh

				// Account 0, first change address = m/86'/0'/0'/1/0
				xprv         = xprvA3Ln3Gt3aphvUgzgEDT8vE2cYqb4PjFfpmbiFKphxLg1FjXQpkAk5M1ZKDY15bmCAHA35jTiawbFuwGtbDZogKF1WfjwxML4gK7WfYW5JRP
				xpub         = xpub6GL8SnQwRCGDhB59LEz9HMyM6sRYoByXBzXK3iEKWgCz8XrZNHUzd9L3AUBELW5NzA7dEFvMas1F84TuPH3xqdUA5tumaGWFgihJzWytXe3
				internal_key = 399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef
				output_key   = 882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc
				scriptPubKey = 5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc
				address      = bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7





			 */


		}


	}
}

