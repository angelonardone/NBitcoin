using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using System;
using QBitNinja.Client;
using QBitNinja.Client.Models;
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

namespace angeloNBitcoin
{
	class Program
	{
		public static object NodeBuilderEx { get; private set; }

		static void Main(string[] args)
		{
			//private_from_wif();
			//brain_wallet();
			//brain_wallet_2();
			//brain_wallet_3();
			//page_1();
			//page_2();
			//page_3();
			//page_4();
			//spend_your_coin();
			//spend_your_coin_2();
			//angelo_test();
			//proof_of_ownership();
			//bip38_1();
			//bip38_2();
			//bip38_angelo();
			//HD_wallet();
			//HD_wallet_2();
			//none_hardened();
			//hardened();
			//BIP39();
			//transactionbuilder();
			//test_bip32();
			//BIP39_wasabi();
			//Iancoleman_io();
			//Iancoleman_io_2();
			//asymetric_encryption();
			//check_address_on_test();
			//sign_msg();
			//rpc_transaction();
			//rpc_transaction_new_wallet();
			//get_previous_current_block();
			//create_ext_key_from_1();
			//testing_pubKey();
			//Parse_serialized_public_extended_key();
			//Parse_serialized_private_extended_key();
			//toZpriv();
			//toZpub();
			//toYpriv();
			//toYpub();
			//send_coins_youtube();
			//send_coins_angelo();
			//send_coins_angelo_old();
			//from_transaction_bulder();
			//verify_addressess();
			//test_server_node();
			rpc_all_transaction_on_block();
			//test_server_node_2();
			//getPubKeyFromAddress();
		}
		static void getPubKeyFromAddress()
		{
			Network network = Network.TestNet;
			var result = NBitcoin.BitcoinAddress.Create("mz8SWTfreWP8dePqjwBy4788RPXEwD5mTm", network);
			Console.WriteLine(result.ScriptPubKey.ToHex().ToString());

			var strPubKey = "mx3pzL6dHCt6QxxHKmSLpYv1ne9puXHH2Z";
			var pubKey = new NBitcoin.BitcoinPubKeyAddress(strPubKey, network);

			Console.WriteLine(pubKey.ScriptPubKey);



		}
		static void test_server_node()
		{

			var node = Node.Connect(Network.TestNet, "192.168.200.110:18333");
			node.VersionHandshake();
			var chain = node.GetChain();
			Console.WriteLine(chain.Height.ToString());
			Console.WriteLine(chain.GetBlock(2418116).Header.ToString());
			Console.WriteLine(chain.GetBlock(2418106).Header.ToString());
			Console.WriteLine(chain.GetBlock(2418016).Header.ToString());
			var block = chain.GetBlock(2418016);
			node.Disconnect();


		}
		static void test_server_node_2()
		{

			var node = Node.Connect(Network.Main, "localhost:8333");
			node.VersionHandshake();
			var chain = node.GetChain();
			Console.WriteLine(chain.Height.ToString());

			var block = chain.GetBlock(798230); // Block 00000000000000000002eba3c59919deb6e99fe5f8d7bccc94388ce2c2d70ec0
			Console.WriteLine(block.Height.ToString());



			node.Disconnect();


		}
		static void rpc_all_transaction_on_block()
		{
			var network = Network.TestNet;

			//var blockId = uint256.Parse("0000000000000000000048e7f9c413d5371b3088763a00ebe7f4bcaf33427ec4"); // block high 798230
			var blockId = uint256.Parse("000000000000000690c164ad8b26acac0f20b631c13997e411346fede6f044ce"); // block high 798230

			//var rpc = new RPCClient("bitcoin:angelo", "http://localhost:8332", network);
			var rpc = new RPCClient("bitcoin:angelo", "http://192.168.10.21:18332", network);
			Block blck = rpc.GetBlock(blockId);

			Console.WriteLine("BlockTime:" + blck.Header.BlockTime.ToString());
			Console.WriteLine("BlockTime ToLocalTime:" + blck.Header.BlockTime.ToLocalTime().ToString());
			Console.WriteLine("BlockTime unixtime miliseconds:" + blck.Header.BlockTime.ToUnixTimeMilliseconds().ToString());
			Console.WriteLine("GetHash:" + blck.Header.GetHash().ToString());
			Console.WriteLine("HashPrevBlock:" + blck.Header.HashPrevBlock.ToString());
			Console.WriteLine("Transactions.Count:" + blck.Transactions.Count.ToString());
			Console.WriteLine("Block GetHash: " + blck.GetHash().ToString());
			Console.WriteLine("Block GetCoinbaseHeight: " + blck.GetCoinbaseHeight().ToString());

			/*

			blck = rpc.GetBlock(uint256.Parse("000000000000000000036bf8e6438b588614ea43319951c0c2187deee453c9f0"));

			Console.WriteLine("BlockTime:" + blck.Header.BlockTime.ToString());
			Console.WriteLine("BlockTime ToLocalTime:" + blck.Header.BlockTime.ToLocalTime().ToString());
			Console.WriteLine("BlockTime unixtime miliseconds:" + blck.Header.BlockTime.ToUnixTimeMilliseconds().ToString());
			Console.WriteLine("GetHash:" + blck.Header.GetHash().ToString());
			Console.WriteLine("HashPrevBlock:" + blck.Header.HashPrevBlock.ToString());
			Console.WriteLine("Transactions.Count:" + blck.Transactions.Count.ToString());
			Console.WriteLine("Block GetHash: " + blck.GetHash().ToString());
			Console.WriteLine("Block GetCoinbaseHeight: " + blck.GetCoinbaseHeight().ToString());

			Console.WriteLine("Enter to continue");
			Console.ReadLine();
			*/
			int count_transactions = 0;
			System.Collections.Generic.List<Transaction> transactions = blck.Transactions;
			foreach (var transaction in transactions)
			{
				count_transactions += 1;
				Console.WriteLine("TransactionId: " + transaction.GetHash().ToString());
				Console.WriteLine("count inputs: " + transaction.Inputs.Count.ToString());
				Console.WriteLine("count outputs: " + transaction.Outputs.Count.ToString());


				if (transaction.IsCoinBase)
				{
					Console.WriteLine("coin base: " + transaction.IsCoinBase.ToString());
					Console.WriteLine();
				}

				Console.WriteLine();
				Console.WriteLine("############ Examing inputs #############");
				Console.WriteLine();
				var inputs = transaction.Inputs;
				foreach (TxIn input in inputs)
				{
					OutPoint previousOutpoint = input.PrevOut;
					Console.WriteLine(previousOutpoint.Hash.ToString()); // hash of prev tx
					Console.WriteLine(previousOutpoint.N.ToString()); // idx of out from prev tx, that has been spent in the current tx
					Console.WriteLine();
				}

				Console.WriteLine();
				Console.WriteLine("############ Examing outputs #############");
				Console.WriteLine();
				var outputs = transaction.Outputs;
				int outN = 0;
				foreach (TxOut output in outputs)
				{
					Money amount = output.Value;

					Console.WriteLine("Transaction: " + output.Value.ToString());
					Console.WriteLine("N: " + outN.ToString());

					Console.WriteLine("BTC: " + amount.ToDecimal(MoneyUnit.BTC).ToString());
					var paymentScript = output.ScriptPubKey;
					Console.WriteLine(paymentScript.ToString());  // It's the ScriptPubKey
					if (!paymentScript.IsUnspendable)
					{
						if (paymentScript.IsScriptType(ScriptType.MultiSig))
						{
							Console.WriteLine("Multisig" + paymentScript.ToString());
							Console.WriteLine();
						}
						else
						{
							var address = paymentScript.GetDestinationAddress(network);
							if (address == null)
							{
								Console.WriteLine(" unknown: " + paymentScript.ToHex().ToString());
								Console.WriteLine();
							}
							else
							{
								Console.WriteLine("Address: " + address.ToString());
							}
						}
					}
					else
					{
						Console.WriteLine("Unspendable" + paymentScript.ToString());
						Console.WriteLine();
					}

					string scriptType;
					if (paymentScript.IsScriptType(ScriptType.Taproot))
					{ scriptType = "Taproot"; }
					else if (paymentScript.IsScriptType(ScriptType.Witness))
					{ scriptType = "Witness"; }
					else if (paymentScript.IsScriptType(ScriptType.MultiSig))
					{ scriptType = "MultiSig"; }
					else if (paymentScript.IsScriptType(ScriptType.P2SH))
					{ scriptType = "P2SH"; }
					else if (paymentScript.IsScriptType(ScriptType.P2PKH))
					{ scriptType = "P2PKH"; }
					else if (paymentScript.IsScriptType(ScriptType.P2PK))
					{ scriptType = "P2PK"; }
					else if (paymentScript.IsScriptType(ScriptType.P2WPKH))
					{ scriptType = "P2WPKH"; }
					else if (paymentScript.IsScriptType(ScriptType.P2WSH))
					{ scriptType = "P2WSH"; }
					else { scriptType = ""; }

					Console.WriteLine("Scrypt type: " + scriptType);
					outN += 1;
				}
			}
			Console.WriteLine();
			Console.WriteLine("############ Total Number in block #############");
			Console.WriteLine("num transactions : " + count_transactions.ToString());
			Console.WriteLine("Block: " + blck.GetHash().ToString());
			Console.WriteLine("Block: " + blck.GetWeight().ToString());

		}


		static void verify_addressess()
		{
			Network network = Network.TestNet;
			/*
			string strPubKey;
			NBitcoin.BitcoinPubKeyAddress pubKey;
			NBitcoin.BitcoinScriptAddress scriptAddress;
			NBitcoin.BitcoinWitPubKeyAddress WithpubKey;

			strPubKey = "mz8SWTfreWP8dePqjwBy4788RPXEwD5mTm";
			pubKey = new NBitcoin.BitcoinPubKeyAddress(strPubKey, network);

			Console.WriteLine(pubKey.GetType().ToString());

			strPubKey = "2MwsPmjaqfvwH815uYAKUctLtXnKCb8j8dJ";
			scriptAddress = new NBitcoin.BitcoinScriptAddress(strPubKey, network);

			Console.WriteLine(scriptAddress.GetType().ToString());


			strPubKey = "tb1q506ljfgkh87emh4hk48rug6mkadjmqfpm7mj7z";
			WithpubKey = new NBitcoin.BitcoinWitPubKeyAddress(strPubKey, network);
			Console.WriteLine(WithpubKey.GetType().ToString());

			var add2 = BitcoinAddress.Create("mz8SWTfreWP8dePqjwBy4788RPXEwD5mTm", network);
			Console.WriteLine(add2.GetType().ToString());
			var add3 = BitcoinAddress.Create("2MwsPmjaqfvwH815uYAKUctLtXnKCb8j8dJ", network);
			Console.WriteLine(add3.GetType().ToString());
			Console.WriteLine(add3.ScriptPubKey.Hash.ScriptPubKey);
			Console.WriteLine(add3.ScriptPubKey.PaymentScript);
			var add4 = BitcoinAddress.Create("tb1q506ljfgkh87emh4hk48rug6mkadjmqfpm7mj7z", network);
			Console.WriteLine(add4.GetType().ToString());
			*/


			var oneKey = new NBitcoin.BitcoinSecret("cQLbXipsPCkG6i83WAaeumvPWcjmAigrQdxRP9AajAYcWraAeDy1", network);
			Console.WriteLine(oneKey.PubKeyHash);
			Console.WriteLine(oneKey.PubKeyHash.ScriptPubKey);
			Console.WriteLine(oneKey.PubKey.ScriptPubKey);
			Console.WriteLine(oneKey.PubKey.WitHash.ScriptPubKey);
			Console.WriteLine(oneKey.PubKey.WitHash);


			var privateKey = oneKey.PrivateKey;
			Console.WriteLine(privateKey.GetScriptPubKey(ScriptPubKeyType.SegwitP2SH));

			//var result = NBitcoin.Network.Parse("mz8SWTfreWP8dePqjwBy4788RPXEwD5mTm", network);
		}
		/*
				public static string ToZpub(this ExtPubKey extPubKey, Network network)
				{
					var data = extPubKey.ToBytes();
					var version = (network == Network.Main)
						? new byte[] { (0x04), (0xB2), (0x47), (0x46) }
						: new byte[] { (0x04), (0x5F), (0x1C), (0xF6) };

					return Encoders.Base58Check.EncodeData(version.Concat(data).ToArray());
				}

				public static string ToZPrv(this ExtKey extKey, Network network)
				{
					var data = extKey.ToBytes();
					var version = (network == Network.Main)
						? new byte[] { (0x04), (0xB2), (0x43), (0x0C) }
						: new byte[] { (0x04), (0x5F), (0x18), (0xBC) };

					return Encoders.Base58Check.EncodeData(version.Concat(data).ToArray());
				}
		*/
		static void toZpriv()
		{
			Network network = Network.Main;
			ExtKey extKey = ExtKey.Parse("xprv9s21ZrQH143K3jJ9HCQmAKPzGfDwGUDHfn8Jm7BFmtAizLdPaD9opjD3VDccfqyW4bKVvJya2M32NmT47s7uYM71PNWd1vQ6iBbhBRwHNin", network);
			var data = extKey.ToBytes();
			var version = (network == Network.Main)
				? new byte[] { (0x04), (0xB2), (0x43), (0x0C) }
				: new byte[] { (0x04), (0x5F), (0x18), (0xBC) };


			byte[] privebytes = new byte[version.Length + data.Length];
			System.Buffer.BlockCopy(version, 0, privebytes, 0, version.Length);
			System.Buffer.BlockCopy(data, 0, privebytes, version.Length, data.Length);

			string extParsed = Encoders.Base58Check.EncodeData(privebytes);
			//string extParsed =  Encoders.Base58Check.EncodeData(version.Concat(data).ToArray());
			Console.WriteLine(extParsed);
			// zprvAWgYBBk7JR8GkKgNwuz1aVazcbWq9iCHW1AkKty2XtvV6YFr5XUw4rXKXdXnffHLssZ7RGAgwfk89LgBZFww8pUD83uUBk35Fdiyxb9cqX5
		}
		static void toZpub()
		{
			Network network = Network.Main;
			ExtPubKey extPubKey = ExtPubKey.Parse("xpub6DDuVwnc47e3iz6eeNXqKs6eJYkisouwKFcEdgLKwVzRyekWMSmeLRE1J4QrqGD8wFMKnWQiYABCG5sc2STVT63Phvp4CYgufoC7NHnCHNT", network);
			var data = extPubKey.ToBytes();
			var version = (network == Network.Main)
						? new byte[] { (0x04), (0xB2), (0x47), (0x46) }
						: new byte[] { (0x04), (0x5F), (0x1C), (0xF6) };

			string extParsed = Encoders.Base58Check.EncodeData(version.Concat(data).ToArray());
			Console.WriteLine(extParsed);
			// zpub6rtS7H8SMUj1RaUtK675k3HeeV3cm3tw9UegCU86hWkC5rNxrm6maYYHLUL2q5WykXawHTbqTUtJ2f6jTqHX3ZQbScCuNNKtDFKQ9XBXPtj
		}
		static void toYpriv()
		{

			Network network = Network.Main;
			ExtKey extKey = ExtKey.Parse("xprv9s21ZrQH143K3jJ9HCQmAKPzGfDwGUDHfn8Jm7BFmtAizLdPaD9opjD3VDccfqyW4bKVvJya2M32NmT47s7uYM71PNWd1vQ6iBbhBRwHNin", network);
			var data = extKey.ToBytes();
			var version = (network == Network.Main)
				? new byte[] { (0x04), (0x9D), (0x78), (0x78) }
				: new byte[] { (0x04), (0x4A), (0x4E), (0x28) };

			string extParsed = Encoders.Base58Check.EncodeData(version.Concat(data).ToArray());
			Console.WriteLine(extParsed);
			// yprvABrGsX5C9janu2VG7ZCPNQVVSdNPD6CnateXYW599tYc3SScpsKNSnsBWRaCfkdRUESJfna8V1PaG44cqZXvLancFiD3bqDayufLZy1YDaw
		}
		static void toYpub()
		{
			Network network = Network.Main;
			ExtPubKey extPubKey = ExtPubKey.Parse("xpub6DDuVwnc47e3iz6eeNXqKs6eJYkisouwKFcEdgLKwVzRyekWMSmeLRE1J4QrqGD8wFMKnWQiYABCG5sc2STVT63Phvp4CYgufoC7NHnCHNT", network);
			var data = extPubKey.ToBytes();
			var version = (network == Network.Main)
						? new byte[] { (0x04), (0x9D), (0x7C), (0xB2) }
						: new byte[] { (0x04), (0x4A), (0x52), (0x62) };

			string extParsed = Encoders.Base58Check.EncodeData(version.Concat(data).ToArray());
			Console.WriteLine(extParsed);
			// ypub6Y4AocTXCoBXaHHmUjKTXxC9UWuApRuSEN8TR5EDKWNK2kZjc6wCxUt9KGNSqAs4LtU8Xz1GzpXk9NVAk8sWFKizaGWUnTWPwXFkksTMYQG
		}
		static void Parse_serialized_private_extended_key()
		{

			// on main net works BIP 49
			//string derivationScheme = "yprvABrGsX5C9janu2VG7ZCPNQVVSdNPD6CnateXYW599tYc3SScpsKNSnsBWRaCfkdRUESJfna8V1PaG44cqZXvLancFiD3bqDayufLZy1YDaw";
			//var network = Network.Main;
			// xprv9s21ZrQH143K3jJ9HCQmAKPzGfDwGUDHfn8Jm7BFmtAizLdPaD9opjD3VDccfqyW4bKVvJya2M32NmT47s7uYM71PNWd1vQ6iBbhBRwHNin-[p2sh]

			// on main net works BIP 89
			string derivationScheme = "zprvAWgYBBk7JR8GkKgNwuz1aVazcbWq9iCHW1AkKty2XtvV6YFr5XUw4rXKXdXnffHLssZ7RGAgwfk89LgBZFww8pUD83uUBk35Fdiyxb9cqX5";
			var network = Network.Main;
			// xprv9s21ZrQH143K3jJ9HCQmAKPzGfDwGUDHfn8Jm7BFmtAizLdPaD9opjD3VDccfqyW4bKVvJya2M32NmT47s7uYM71PNWd1vQ6iBbhBRwHNin-[p2sh]


			// does NOT work on Testnet
			//string derivationScheme = "vpub5ZkioviHhCB1xNbbK7fWN9e2nazVGJfvVWaMyqGS8Zd7WWMaFGuL8sDoqFzehiHcyXN1mbHRkQvNraVX8cSfWAqneNtkD4sGXjkkKEUtXb4";
			//var network = Network.TestNet;


			// https://github.com/satoshilabs/slips/blob/master/slip-0132.md

			//Unsupported Electrum
			//var p2wsh_p2sh = 0x295b43fU;
			//var p2wsh = 0x2aa7ed3U;
			Dictionary<uint, string[]> electrumMapping = new Dictionary<uint, string[]>();
			//Source https://github.com/spesmilo/electrum/blob/9edffd17542de5773e7284a8c8a2673c766bb3c3/lib/bitcoin.py

			// Private KEY
			// main net
			electrumMapping.Add(0x0488ade4U, new[] { "legacy" }); // xprv
			electrumMapping.Add(0x049d7878U, new string[] { "p2sh" }); // yprv
			electrumMapping.Add(0x04b2430cU, new string[] { }); // zprv
																// test net
			electrumMapping.Add(0x04358394U, new[] { "legacy" }); // tprv
			electrumMapping.Add(0x044a4e28U, new string[] { "p2sh" }); // uprv
			electrumMapping.Add(0x45f18bcU, new string[] { }); // vprv


			var data = Encoders.Base58Check.DecodeData(derivationScheme);
			if (data.Length < 4)
				throw new FormatException("data.Length < 4");
			var prefix = Utils.ToUInt32(data, false);
			if (!electrumMapping.TryGetValue(prefix, out string[] labels))
				throw new FormatException("!electrumMapping.TryGetValue(prefix, out string[] labels)");
			var standardPrefix = Utils.ToBytes(network == Network.Main ? 0x0488ade4U : 0x04358394U, false);

			for (int i = 0; i < 4; i++)
				data[i] = standardPrefix[i];

			derivationScheme = new BitcoinExtKey(Encoders.Base58Check.EncodeData(data), network).ToString();
			foreach (var label in labels)
			{
				derivationScheme = derivationScheme + $"-[{label}]";
			}
			Console.WriteLine(derivationScheme);
		}
		static void Parse_serialized_public_extended_key()
		{

			string derivationScheme = "vpub5UzmHJe4YPMzYL3MXiy4dvv5YPAGRU9iii8EHrfwLw2nfdMG9wVUfKi4pFeeuHbDhQqvdAh1gUZt9e6UbNfM8VrNaja2XsEd3MZfHRqDSSV";
			var network = Network.TestNet;

			// on main net works BIP 89
			//string derivationScheme = "zpub6r3UFetGQ4J7JytmatJdhAN8h6LdfbBC3TNuaEACLxCekUqdfcxh7uPbG2GkQxWUn9Y8Wazw1ibXDrXLwmmstacqFBZqV4gqsbcYFqdqc3Z";
			//var network = Network.Main;
			// xpub6CNweKYS6hD9cPWXvAjPGzB8MA3jnMCCDELU1SNRawSteHDBAJdZsn5KDcMaR9CdxsJX1dop6PtRTHJDWNwrJ7FdWWAzKF3sL9VFUi8nzk4

			// on main net works BIP 49
			//string derivationScheme = "ypub6Wk7Cr2jm5J3Q6Zb25x4wAj35ASSV3J3rJdfPvXprDiE7qaHUL8asLJhwtorq9gTCpiokasfeeNRUgEhmBMw9H2J61dm5ZS59jYvrkk9gje";
			//var network = Network.Main;
			// xpub6BuquBMpcPkZYoNUBjASj5dXuCHzYRJYwC7ScXdwUDLM4jm4Dfy2FGeZvgrGqF2XoBc117H7Bz1sbPd93UwvM3LhDfwLVecat1VHU6tQvZz-[p2sh]

			// does NOT work on Testnet
			//string derivationScheme = "vpub5ZkioviHhCB1xNbbK7fWN9e2nazVGJfvVWaMyqGS8Zd7WWMaFGuL8sDoqFzehiHcyXN1mbHRkQvNraVX8cSfWAqneNtkD4sGXjkkKEUtXb4";
			//var network = Network.TestNet;


			// https://github.com/satoshilabs/slips/blob/master/slip-0132.md

			//Unsupported Electrum
			//var p2wsh_p2sh = 0x295b43fU;
			//var p2wsh = 0x2aa7ed3U;
			Dictionary<uint, string[]> electrumMapping = new Dictionary<uint, string[]>();
			//Source https://github.com/spesmilo/electrum/blob/9edffd17542de5773e7284a8c8a2673c766bb3c3/lib/bitcoin.py

			// PUBLIC KEY
			// main net
			electrumMapping.Add(0x0488b21eU, new[] { "legacy" }); // xpub
			electrumMapping.Add(0x049d7cb2U, new string[] { "p2sh" }); // ypub
			electrumMapping.Add(0x4b24746U, new string[] { }); // zpub
															   // test net
			electrumMapping.Add(0x043587cfU, new[] { "legacy" }); // tpub
			electrumMapping.Add(0x044a5262U, new string[] { "p2sh" }); // upub
			electrumMapping.Add(0x45f1cf6U, new string[] { }); // vpub

			var data = Encoders.Base58Check.DecodeData(derivationScheme);
			if (data.Length < 4)
				throw new FormatException("data.Length < 4");
			var prefix = Utils.ToUInt32(data, false);
			if (!electrumMapping.TryGetValue(prefix, out string[] labels))
				throw new FormatException("!electrumMapping.TryGetValue(prefix, out string[] labels)");
			var standardPrefix = Utils.ToBytes(network == Network.Main ? 0x0488b21eU : 0x043587cfU, false);

			for (int i = 0; i < 4; i++)
				data[i] = standardPrefix[i];

			derivationScheme = new BitcoinExtPubKey(Encoders.Base58Check.EncodeData(data), network).ToString();
			foreach (var label in labels)
			{
				derivationScheme = derivationScheme + $"-[{label}]";
			}
			Console.WriteLine(derivationScheme);

			System.DateTimeOffset dateTimeOffset = System.DateTimeOffset.FromUnixTimeSeconds(1665754841);
			Console.WriteLine(dateTimeOffset.ToString());
			Console.WriteLine(dateTimeOffset.UtcDateTime.ToString());
		}

		static void testing_pubKey()
		{
			byte[] bytes = Encoders.Hex.DecodeData("c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948");
			Key key = new Key(bytes);
			Console.WriteLine(key.PubKey.ToString());
			Console.WriteLine(key.PubKey.ToString().Length.ToString());
			Console.WriteLine(key.PubKey.ToString().Substring(0, 62));

			OperatingSystem os = Environment.OSVersion;
			PlatformID pid = os.Platform;
			if (pid == PlatformID.Unix)
			{
				Console.WriteLine("YES it's unix");
			}
			Console.WriteLine(pid.ToString());
			bool isUnix = pid == PlatformID.Unix;
			Console.WriteLine(isUnix.ToString());


		}
		static void create_ext_key_from_1()
		{
			/*
			//public ExtKey(Key key, byte[] chainCode, byte depth, HDFingerprint fingerprint, uint child)
			byte[] Keybytes = Encoders.Hex.DecodeData("c8222b32a0189e5fa1f46700a9d0438c00feb279f0f2087cafe6f5b5ce9d224a");
			Key key = new Key(Keybytes);
			byte[] ChainCode = Encoders.Base64.DecodeData("WTf34VrZUU83e7l22AC082K3vK/VslEJPwfZUtY5R/o=");
			var fingerptr = HDFingerprint.Parse("4567db2b");
			ExtKey angelo = new ExtKey(key, ChainCode, (int)3, fingerptr, (uint)2147483648);
			//ExtKey angelo = new ExtKey(key, ChainCode);
			Console.WriteLine(angelo.PrivateKey.ToHex().ToString());
			ExtPubKey pubkey = angelo.Neuter();
			*/

			ExtPubKey pubkey = ExtPubKey.Parse("tpubDCXzCF6rKnEJWKWpQ1m5xS1K2hRc5cWJwHXnsgoq8DSdwfD5N1awJ2NtNGimFMj3NkFdHcx8qfuRZiq63w2XePbRaXxXqDrH1vvGasz7mb2", Network.TestNet);
			Console.WriteLine(pubkey.ToString(Network.TestNet)); // tpubDCXzCF6rKnEJWKWpQ1m5xS1K2hRc5cWJwHXnsgoq8DSdwfD5N1awJ2NtNGimFMj3NkFdHcx8qfuRZiq63w2XePbRaXxXqDrH1vvGasz7mb2

			string credentials = "bitcoin:angelo";
			string serverURL = "http://192.168.200.110:18332";
			RPCClient rpc = new RPCClient(credentials, serverURL, Network.TestNet);

			var extPubK = new BitcoinExtPubKey(pubkey, Network.TestNet);
			var outputDesc = OutputDescriptor.NewPKH(PubKeyProvider.NewHD(extPubK, new KeyPath("0/"), PubKeyProvider.DeriveType.UNHARDENED), Network.TestNet);

			ScanTxoutSetResponse result = rpc.StartScanTxoutSet(new NBitcoin.RPC.ScanTxoutSetParameters(outputDesc, 0, 100));

			NBitcoin.RPC.ScanTxoutOutput[] txOuts = result.Outputs;

			foreach (NBitcoin.RPC.ScanTxoutOutput output in txOuts)
			{
				Coin coin = output.Coin;
				int Height = output.Height;
				Console.WriteLine(coin.Amount.ToString() + " " + Height.ToString());
				Console.WriteLine(output.Coin.Amount.ToDecimal(NBitcoin.MoneyUnit.BTC));
				Console.WriteLine(((uint)output.Height));

				Money amount = (Money)coin.Amount;

				Console.WriteLine(amount.ToDecimal(MoneyUnit.BTC));
				var paymentScript = coin.TxOut.ScriptPubKey;
				Console.WriteLine(paymentScript);  // It's the ScriptPubKey
				var address = paymentScript.GetDestinationAddress(Network.TestNet);
				Console.WriteLine(address); // 1HfbwN6Lvma9eDsv7mdwp529tgiyfNr7jc

				Console.WriteLine(output.Coin.TxOut.ScriptPubKey.GetDestinationAddress(Network.TestNet));
				Console.WriteLine("#########################");

			}

		}
		static void get_balance_on_extended_address()
		{
			// tpubDCXzCF6rKnEJWKWpQ1m5xS1K2hRc5cWJwHXnsgoq8DSdwfD5N1awJ2NtNGimFMj3NkFdHcx8qfuRZiq63w2XePbRaXxXqDrH1vvGasz7mb2
		}
		static void get_previous_current_block()
		{
			string credentials = "bitcoin:angelo";
			string serverURL = "http://192.168.200.110:18332";
			RPCClient rpc = new RPCClient(credentials, serverURL, Network.TestNet);
			//Block blck = rpc.GetBlock(blockId);
			//BlockchainInfo blockchainInfo = rpc.GetBlockchainInfo();
			// int lastBlock = (int)blockchainInfo.Blocks;

			int lastBlock = rpc.GetBlockCount();
			Console.WriteLine("Last block on chaing: " + lastBlock);

			NBitcoin.Block blck = rpc.GetBlock(lastBlock);
			Console.WriteLine("Current block hash: " + blck.Header);
			Console.WriteLine("Current block hash: " + blck.GetHash());
			Console.WriteLine("Current block hash: " + blck.Header.GetHash());
			Console.WriteLine("Previou block hash: " + blck.Header.HashPrevBlock);
			Console.WriteLine("Previou block hash: " + blck.Header.HashPrevBlock.ToString());


		}

		static void rpc_transaction_new_wallet()
		{
			// seed
			//develop exchange hold acquire budget glory narrow ivory doll book timber forward
			var transactionId = uint256.Parse("ee8d045f8c682154a7fd62b1e4f3fb1dfc5f448fcb7e6f2a07dc34e668ed3ed7");
			var blockId = uint256.Parse("0000000000000032370212d9daeafb6e6db7728716e53b2e273421b68240bf09");


			var rpc = new RPCClient("bitcoin:angelo", "http://192.168.200.110:18332", Network.TestNet);
			//Block blck = rpc.GetBlock(blockId);
			int cnt = rpc.GetBlockCount();
			Console.WriteLine(cnt.ToString());
			Block blck = rpc.GetBlock(blockId);


			List<Transaction> transactions = blck.Transactions;
			foreach (var transaction in transactions)
			{
				Boolean isTransactionImlookingfor = transactionId.Equals(transaction.GetHash());
				if (isTransactionImlookingfor)
				{
					Console.WriteLine("TransactionId: " + transaction.GetHash().ToString());


					Console.WriteLine();
					Console.WriteLine("############ Examing inputs #############");
					Console.WriteLine();
					var inputs = transaction.Inputs;
					foreach (TxIn input in inputs)
					{
						OutPoint previousOutpoint = input.PrevOut;
						Console.WriteLine(previousOutpoint.Hash); // hash of prev tx
						Console.WriteLine(previousOutpoint.N); // idx of out from prev tx, that has been spent in the current tx
						Console.WriteLine();
					}

					Console.WriteLine();
					Console.WriteLine("############ Examing outputs #############");
					Console.WriteLine();
					var outputs = transaction.Outputs;
					foreach (TxOut output in outputs)
					{
						Money amount = output.Value;

						Console.WriteLine(amount.ToDecimal(MoneyUnit.BTC));
						var paymentScript = output.ScriptPubKey;
						Console.WriteLine(paymentScript);  // It's the ScriptPubKey
						var address = paymentScript.GetDestinationAddress(Network.TestNet);
						Console.WriteLine(address);
						Console.WriteLine();
					}
				}
			}
			Console.WriteLine();
		}
		static void rpc_transaction()
		{

			var transactionId = uint256.Parse("b3a8a68d1b7395dd279904e83e2d11e23468cd8e6b66fb182eb793fe81e44a6a");
			var blockId = uint256.Parse("000000000000023831a3c5a828613696e3822014b785d87d0b6b9590fb6b65c3");


			var rpc = new RPCClient("bitcoin:angelo", "http://192.168.200.110:18332", Network.TestNet);
			//Block blck = rpc.GetBlock(blockId);
			int cnt = rpc.GetBlockCount();
			Console.WriteLine(cnt.ToString());
			Block blck = rpc.GetBlock(blockId);


			List<Transaction> transactions = blck.Transactions;
			foreach (var transaction in transactions)
			{
				Boolean isTransactionImlookingfor = transactionId.Equals(transaction.GetHash());
				if (isTransactionImlookingfor)
				{
					Console.WriteLine("TransactionId: " + transaction.GetHash().ToString());


					Console.WriteLine();
					Console.WriteLine("############ Examing inputs #############");
					Console.WriteLine();
					var inputs = transaction.Inputs;
					foreach (TxIn input in inputs)
					{
						OutPoint previousOutpoint = input.PrevOut;
						Console.WriteLine(previousOutpoint.Hash); // hash of prev tx
						Console.WriteLine(previousOutpoint.N); // idx of out from prev tx, that has been spent in the current tx
						Console.WriteLine();
					}

					Console.WriteLine();
					Console.WriteLine("############ Examing outputs #############");
					Console.WriteLine();
					var outputs = transaction.Outputs;
					foreach (TxOut output in outputs)
					{
						Money amount = output.Value;

						Console.WriteLine(amount.ToDecimal(MoneyUnit.BTC));
						var paymentScript = output.ScriptPubKey;
						Console.WriteLine(paymentScript);  // It's the ScriptPubKey
						var address = paymentScript.GetDestinationAddress(Network.TestNet);
						Console.WriteLine(address);
						Console.WriteLine();
					}
				}
			}
		}



		static void sign_msg()
		{
			/*
			// in order to have allways the sema results I'll use brain wallets for both users
			string angeloSTR = "angelo";
			byte[] angeloBytes = Encoders.ASCII.DecodeData(angeloSTR);
			var angeloHashedText = Hashes.SHA256(angeloBytes);



			Key angelo = new Key(angeloHashedText);
			var angelo_msg = "Este es el mensaje de angelo";
			string msg_signature = angelo.SignMessage(angelo_msg);
			Console.WriteLine(msg_signature);

			bool verify_msg = angelo.PubKey.VerifyMessage(angelo_msg, msg_signature);
			Console.WriteLine("Es un mensaje de angelo? " + verify_msg);
			*/

		}
		static void check_address_on_test()
		{
			decimal totalBalance = 0;

			var netAddress = NBitcoin.BitcoinAddress.Create("mzawn7T5K4JVs9nDphnWuqvWq9ruRBz6a7", NBitcoin.Network.TestNet);
			//var client = new QBitNinja.Client.QBitNinjaClient("https://tapi.qbit.ninja/", NBitcoin.Network.TestNet);
			var client = new QBitNinja.Client.QBitNinjaClient(NBitcoin.Network.TestNet);
			var balance = client.GetBalance(netAddress, false).Result;
			for (int i = 0; i < balance.Operations.Count; i++)
			{
				totalBalance += balance.Operations[i].Amount.ToDecimal(NBitcoin.MoneyUnit.BTC);
				Console.WriteLine("Amount: " + balance.Operations[i].Amount.ToDecimal(MoneyUnit.BTC).ToString());
			}

		}
		static void asymetric_encryption()
		{
			// in order to have allways the sema results I'll use brain wallets for both users
			string angeloSTR = "angelo";
			byte[] angeloBytes = Encoders.ASCII.DecodeData(angeloSTR);
			var angeloHashedText = Hashes.SHA256(angeloBytes);

			string bobSTR = "bob";
			byte[] bobBytes = Encoders.ASCII.DecodeData(bobSTR);
			var bobHashedText = Hashes.SHA256(bobBytes);



			Key angelo = new Key(angeloHashedText);
			Key bob = new Key(bobHashedText);

			Console.WriteLine("Angelo privet Key: " + angelo.ToHex().ToString()); // b6f2920002873556366ad9f9a44711e4f34b596a892bd175427071e4064a89cc
			Console.WriteLine("Bob privet Key: " + bob.ToHex().ToString()); // 81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9

			Console.WriteLine("Angelo Public Key: " + angelo.PubKey.ToHex().ToString()); // 03f723efb7301aab8ed6f43d81c2f2d4a19aafaaf46dc9f73d0f99344a5c1deb88
			Console.WriteLine("Angelo Public Key: " + angelo.PubKey.Decompress().ToString()); // 04f723efb7301aab8ed6f43d81c2f2d4a19aafaaf46dc9f73d0f99344a5c1deb8844f787ffc941032964a242bf5fc32ff3f12ce73b7bb3c4c3193e750449c6946d

			// now I EC multiply angelo's private key with bob's public key, this will give us the shared secret
			//System.Security.Cryptography.ECCurve.CreateFromFriendlyName()
			// https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.eccurve?view=net-6.0

			var pub1 = bob.PubKey.GetSharedPubkey(angelo);
			Console.WriteLine(pub1.ToHex().ToString());

			var pub2 = angelo.PubKey.GetSharedPubkey(bob);
			Console.WriteLine(pub2.ToHex().ToString());


			//////////
			/*
			 aparentemente no funciona con el "shared" public key en Encrypt/Decrypt
			segun el codigo genera una clave Shared publica ephimera, es por eso,
			podria extender esta clase y proveer la clave publica


			string angeloEncrypted = pub1.Encrypt("mensaje en texto claro de angelo a bob");
			Console.WriteLine(angeloEncrypted);


			string angeloDecrypted = bob.Decrypt(angeloEncrypted);
			Console.WriteLine(angeloDecrypted);
			*/

			// esto si funciona
			var angeloPubKey = angelo.PubKey;
			string aa = angeloPubKey.Encrypt("mensaje en texto claro de bob a angelo");
			Console.WriteLine(aa);
			string bb = angelo.Decrypt(aa);
			Console.WriteLine(bb);


		}
		static void private_from_wif()
		{
			/*
			//Key privateKey = new Key();
			// get PrivateKey from WIF
			NBitcoin.BitcoinSecret privateKey2 = new NBitcoin.BitcoinSecret("KzKVo5PJiea5Mv3tSZWxU8tG6F9cG2EWAtWhVv5Vn6eFhiBPfFtv", Network.Main);
			var privateKey = privateKey2.PrivateKey;


			Console.WriteLine(privateKey.ToHex().ToString()); // 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b

			NBitcoin.BitcoinEncryptedSecret encripted = NBitcoin.BitcoinEncryptedSecret.Create("6PYLDgs57LTPVKhVSY5TKmFqMnfmmTsotybhUZs2pWwpf3papyGENe1WPY", Network.Main);
			NBitcoin.BitcoinSecret decryptedBitcoinPrivateKey = encripted.GetSecret("angelo");
			Console.WriteLine(decryptedBitcoinPrivateKey);  // KzKVo5PJiea5Mv3tSZWxU8tG6F9cG2EWAtWhVv5Vn6eFhiBPfFtv
			*/

			NBitcoin.BitcoinEncryptedSecret encripted = NBitcoin.BitcoinEncryptedSecret.Create("6PYRD5uJfjoCFxtVQK7Dqw7WykNqNehiURsGAbWAuuEYJJAT5hAQFzXzZJ", Network.Main);
			NBitcoin.BitcoinSecret decryptedBitcoinPrivateKey = encripted.GetSecret("angelo");
			Console.WriteLine(decryptedBitcoinPrivateKey);

			encripted = NBitcoin.BitcoinEncryptedSecret.Create("6PYNUEZiKsUaoY8JbzTwnoNvYDd7sAMzZWaDtwAnoKShrmd1thp6G6fqbP", Network.TestNet);
			decryptedBitcoinPrivateKey = encripted.GetSecret("angelo");
			Console.WriteLine(decryptedBitcoinPrivateKey);

			Key privateKey = NBitcoin.Key.Parse("6PYRD5uJfjoCFxtVQK7Dqw7WykNqNehiURsGAbWAuuEYJJAT5hAQFzXzZJ", "angelo", NBitcoin.Network.Main);
			Key privateKey2 = NBitcoin.Key.Parse("6PYNUEZiKsUaoY8JbzTwnoNvYDd7sAMzZWaDtwAnoKShrmd1thp6G6fqbP", "angelo", NBitcoin.Network.TestNet);
			Console.WriteLine(privateKey.ToHex().ToString());
			Console.WriteLine(privateKey2.ToHex().ToString());
		}

		static void brain_wallet()
		{
			string brain_text = "Satoshi Nakamoto";

			//byte[] bytes = Encoding.ASCII.GetBytes(brain_text);
			byte[] bytes = Encoders.ASCII.DecodeData(brain_text);

			var HashedText = Hashes.SHA256(bytes); // "A0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E"


			//Console.WriteLine(BitConverter.ToString(HashedText));

			Key privateKey = new Key(HashedText);
			var publicKey = privateKey.PubKey;

			var mainNetAddress = publicKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main);

			Console.WriteLine(mainNetAddress.ToString()); // 17ZYZASydeA1xyfNrcYcLyqghmK3eGJpHq



		}
		static void brain_wallet_2()
		{
			string brain_text = "Satoshi Nakamoto";
			//byte[] bytes = Encoding.ASCII.GetBytes(brain_text);
			byte[] bytes = Encoders.ASCII.DecodeData(brain_text);

			var HashedText = Hashes.SHA256(bytes); // "A0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E"


			//Console.WriteLine(BitConverter.ToString(HashedText));

			Key privateKey = new Key(HashedText);
			var publicKey = privateKey.PubKey;

			var mainNetAddress = publicKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main);

			Console.WriteLine(mainNetAddress.ToString()); // 17ZYZASydeA1xyfNrcYcLyqghmK3eGJpHq


			//var client = new QBitNinjaClient(Network.Main);
			var client = new QBitNinjaClient("http://api.qbit.ninja/", Network.Main);

			var balance = client.GetBalance(mainNetAddress, true).Result; // true = unSpent
			var balance2 = client.GetBalance(mainNetAddress, false).Result;

			if (balance.Operations.Count > 0)
			{
				// tere is balance on the address
				Console.WriteLine(balance.Operations.Count);


			}

			decimal totalBalance = 0;

			for (int i = 0; i < balance2.Operations.Count; i++)
			{
				Console.WriteLine("Amount: " + balance2.Operations[i].Amount.ToDecimal(MoneyUnit.BTC).ToString());
				Console.WriteLine("First Seen: " + balance2.Operations[i].FirstSeen);
				Console.WriteLine("TransactionID: " + balance2.Operations[i].TransactionId);
				NBitcoin.Money amount = (Money)balance2.Operations[i].Amount;
				Console.WriteLine("BTC: " + amount.ToDecimal(MoneyUnit.BTC));
				Console.WriteLine("Bit: " + amount.ToDecimal(MoneyUnit.Bit));
				Console.WriteLine("MilliBTC: " + amount.ToDecimal(MoneyUnit.MilliBTC));
				Console.WriteLine("Satoshi: " + amount.ToDecimal(MoneyUnit.Satoshi));
				totalBalance += amount.ToDecimal(MoneyUnit.BTC);
			}
			Console.WriteLine("Total BTC: " + totalBalance);




		}

		static void brain_wallet_3()
		{
			var mainNetAddress = NBitcoin.BitcoinAddress.Create("17ZYZASydeA1xyfNrcYcLyqghmK3eGJpHq", Network.Main);

			Console.WriteLine(mainNetAddress.ToString());


			var client = new QBitNinjaClient(Network.Main);
			//var client = new QBitNinjaClient("http://api.qbit.ninja/", Network.Main);
			var balance = client.GetBalance(mainNetAddress, false).Result; // true = unSpent
			if (balance.Operations.Count > 0)
			{
				Console.WriteLine(balance.Operations.Count);


			}

		}
		static void page_1()
		{
			Key privateKey = new Key();
			PubKey publicKey = privateKey.PubKey;
			Console.WriteLine("Public Key:" + publicKey); // 0251036303164f6c458e9f7abecb4e55e5ce9ec2b2f1d06d633c9653a07976560c
			Console.WriteLine("Private Key:" + privateKey.ToHex().ToString());
			Console.WriteLine(publicKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main)); // 17Wgmo6WVWP1UwEQXSpb5WK8oZm439AeF8
			Console.WriteLine(publicKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main)); // bc1qgahqfyjk3r033tglvpwuc3ahraj5h4ykrje4v4
			Console.WriteLine(publicKey.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main)); // 34VwHFWVG7gfx1DEZD87vKo3YEL7bK4S5N
			Console.WriteLine(publicKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Network.Main)); // bc1pfu2hhyhfyqrzx2avd3t9zffpmp7kxqd09x9ry3uyu32jwxxuasgqw6wwuu
			Console.WriteLine(publicKey.GetAddress(ScriptPubKeyType.Legacy, Network.TestNet)); // mn2e4rBVJXpGG3i2F1nxuRXTfZMkyZAkxe
			var publicKeyHash = publicKey.Hash;
			Console.WriteLine(publicKeyHash); // f6889b21b5540353a29ed18c45ea0031280c42cf
			var mainNetAddress = publicKeyHash.GetAddress(Network.Main);
			var testNetAddress = publicKeyHash.GetAddress(Network.TestNet);
			Console.WriteLine(mainNetAddress); // 1PUYsjwfNmX64wS368ZR5FMouTtUmvtmTY
			Console.WriteLine(testNetAddress); // n3zWAo2eBnxLr3ueohXnuAa8mTVBhxmPhq

			// page_2
			//Console.WriteLine(mainNetAddress.ScriptPubKey); // OP_DUP OP_HASH160 14836dbe7f38c5ac3d49e8d790af808a4ee9edcf OP_EQUALVERIFY OP_CHECKSIG
			//Console.WriteLine(testNetAddress.ScriptPubKey); // OP_DUP OP_HASH160 14836dbe7f38c5ac3d49e8d790af808a4ee9edcf OP_EQUALVERIFY OP_CHECKSIG


		}
		static void page_2()
		{
			var publicKeyHash = new KeyId("14836dbe7f38c5ac3d49e8d790af808a4ee9edcf");

			var testNetAddress = publicKeyHash.GetAddress(Network.TestNet);
			var mainNetAddress = publicKeyHash.GetAddress(Network.Main);

			Console.WriteLine(mainNetAddress.ScriptPubKey); // OP_DUP OP_HASH160 14836dbe7f38c5ac3d49e8d790af808a4ee9edcf OP_EQUALVERIFY OP_CHECKSIG
			Console.WriteLine(testNetAddress.ScriptPubKey); // OP_DUP OP_HASH160 14836dbe7f38c5ac3d49e8d790af808a4ee9edcf OP_EQUALVERIFY OP_CHECKSIG

			var paymentScript = publicKeyHash.ScriptPubKey;
			var sameMainNetAddress = paymentScript.GetDestinationAddress(Network.Main);
			Console.WriteLine(mainNetAddress == sameMainNetAddress); // True

			// It is also possible to retrieve the hash from the ScriptPubKey and generate a Bitcoin Address from it:

			var samePublicKeyHash = (KeyId)paymentScript.GetDestination();
			Console.WriteLine(publicKeyHash == samePublicKeyHash); // True
			var sameMainNetAddress2 = new BitcoinPubKeyAddress(samePublicKeyHash, Network.Main);
			Console.WriteLine(mainNetAddress == sameMainNetAddress2); // True

		}

		static void page_3()
		{
			Key privateKey = new Key(); // generate a random private key
			BitcoinSecret mainNetPrivateKey = privateKey.GetBitcoinSecret(Network.Main);  // generate our Bitcoin secret(also known as Wallet Import Format or simply WIF) from our private key for the mainnet
			BitcoinSecret testNetPrivateKey = privateKey.GetBitcoinSecret(Network.TestNet);  // generate our Bitcoin secret(also known as Wallet Import Format or simply WIF) from our private key for the testnet
			Console.WriteLine(mainNetPrivateKey); // L5B67zvrndS5c71EjkrTJZ99UaoVbMUAK58GKdQUfYCpAa6jypvn
			Console.WriteLine(testNetPrivateKey); // cVY5auviDh8LmYUW8AfafseD6p6uFoZrP7GjS3rzAerpRKE9Wmuz

			bool WifIsBitcoinSecret = mainNetPrivateKey == privateKey.GetWif(Network.Main);
			Console.WriteLine(WifIsBitcoinSecret); // True


			Key privateKey2 = new Key(); // generate a random private key
			BitcoinSecret bitcoinSecret = privateKey2.GetWif(Network.Main); // L5B67zvrndS5c71EjkrTJZ99UaoVbMUAK58GKdQUfYCpAa6jypvn
			Key samePrivateKey = bitcoinSecret.PrivateKey;
			Console.WriteLine(samePrivateKey == privateKey2); // True

			PubKey publicKey = privateKey2.PubKey;
			BitcoinAddress bitcoinAddress = publicKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main); // 1PUYsjwfNmX64wS368ZR5FMouTtUmvtmTY
																										 //PubKey samePublicKey = bitcoinAddress.ItIsNotPossible;

		}
		static void page_4()
		{
			
			// Create a client
			QBitNinjaClient client = new QBitNinjaClient(Network.Main);
			// Parse transaction id to NBitcoin.uint256 so the client can eat it
			var transactionId = uint256.Parse("f13dc48fb035bbf0a6e989a26b3ecb57b84f85e0836e777d6edf60d87a4a2d94");
			// Query the transaction
			GetTransactionResponse transactionResponse = client.GetTransaction(transactionId).Result;

			NBitcoin.Transaction transaction = transactionResponse.Transaction;

			Console.WriteLine(transactionResponse.TransactionId); // f13dc48fb035bbf0a6e989a26b3ecb57b84f85e0836e777d6edf60d87a4a2d94
			Console.WriteLine(transaction.GetHash()); // f13dc48fb035bbf0a6e989a26b3ecb57b84f85e0836e777d6edf60d87a4a2d94

			List<ICoin> receivedCoins = transactionResponse.ReceivedCoins;
			foreach (var coin in receivedCoins)
			{
				Money amount = (Money)coin.Amount;

				Console.WriteLine(amount.ToDecimal(MoneyUnit.BTC));
				var paymentScript = coin.TxOut.ScriptPubKey;
				Console.WriteLine(paymentScript);  // It's the ScriptPubKey
				var address = paymentScript.GetDestinationAddress(Network.Main);
				Console.WriteLine(address); // 1HfbwN6Lvma9eDsv7mdwp529tgiyfNr7jc
				Console.WriteLine();
			}

			var outputs = transaction.Outputs;
			foreach (TxOut output in outputs)
			{
				Money amount = output.Value;

				Console.WriteLine(amount.ToDecimal(MoneyUnit.BTC));
				var paymentScript = output.ScriptPubKey;
				Console.WriteLine(paymentScript);  // It's the ScriptPubKey
				var address = paymentScript.GetDestinationAddress(Network.Main);
				Console.WriteLine(address);
				Console.WriteLine();
			}

			Console.WriteLine();
			Console.WriteLine("############ Examing inputs #############");
			Console.WriteLine();
			var inputs = transaction.Inputs;
			foreach (TxIn input in inputs)
			{
				OutPoint previousOutpoint = input.PrevOut;
				Console.WriteLine(previousOutpoint.Hash); // hash of prev tx
				Console.WriteLine(previousOutpoint.N); // idx of out from prev tx, that has been spent in the current tx
				Console.WriteLine();
			}

			Console.WriteLine();
			Console.WriteLine("############ creating transaction #############");
			Console.WriteLine();
			Money twentyOneBtc = new Money(21, MoneyUnit.BTC);
			var scriptPubKey = transaction.Outputs[0].ScriptPubKey;
			TxOut txOut = transaction.Outputs.CreateNewTxOut(twentyOneBtc, scriptPubKey);

			OutPoint firstOutPoint = receivedCoins[0].Outpoint;
			Console.WriteLine(firstOutPoint.Hash); // f13dc48fb035bbf0a6e989a26b3ecb57b84f85e0836e777d6edf60d87a4a2d94
			Console.WriteLine(firstOutPoint.N); // 0

			Console.WriteLine(transaction.Inputs.Count); // 9

			OutPoint firstPreviousOutPoint = transaction.Inputs[0].PrevOut;
			var firstPreviousTransaction = client.GetTransaction(firstPreviousOutPoint.Hash).Result.Transaction;
			Console.WriteLine(firstPreviousTransaction.IsCoinBase); // False
			
		}

		static void spend_your_coin()
		{
			// Replace this with Network.Main to do this on Bitcoin MainNet
			var network = Network.TestNet;

			var privateKey = new Key();
			var bitcoinPrivateKey = privateKey.GetWif(network);
			var address = bitcoinPrivateKey.GetAddress(ScriptPubKeyType.Legacy);

			Console.WriteLine(bitcoinPrivateKey);
			Console.WriteLine(address);

			// cTwZ2RdgCSGkeehueTiG1bYgDPbA2MxxNhU1L7WDLmF6H2T3rDRK
			// mt4aVcpXuokcFSvoLV31TverNhHmqUYx1k

			// transaction ID
			// receive from faucet 0.0001 BTC
			// 66a38ec7afbe5454d41e311e3591c1f8c84a06505c2793ecf1027a46b7f4364f


		}
		static void spend_your_coin_2()
		{

			// cTwZ2RdgCSGkeehueTiG1bYgDPbA2MxxNhU1L7WDLmF6H2T3rDRK
			// mt4aVcpXuokcFSvoLV31TverNhHmqUYx1k

			// transaction ID
			// receive from faucet 0.0001 BTC
			// 66a38ec7afbe5454d41e311e3591c1f8c84a06505c2793ecf1027a46b7f4364f

			var bitcoinPrivateKey = new BitcoinSecret("cTwZ2RdgCSGkeehueTiG1bYgDPbA2MxxNhU1L7WDLmF6H2T3rDRK", Network.TestNet);
			var network = bitcoinPrivateKey.Network;
			var address = bitcoinPrivateKey.GetAddress(ScriptPubKeyType.Legacy);

			Console.WriteLine(bitcoinPrivateKey); // cN5YQMWV8y19ntovbsZSaeBxXaVPaK4n7vapp4V56CKx5LhrK2RS
			Console.WriteLine(address); // mkZzCmjAarnB31n5Ke6EZPbH64Cxexp3Jp

			var client = new QBitNinjaClient(network);
			var transactionId = uint256.Parse("66a38ec7afbe5454d41e311e3591c1f8c84a06505c2793ecf1027a46b7f4364f");
			var transactionResponse = client.GetTransaction(transactionId).Result;

			Console.WriteLine(transactionResponse.TransactionId); // 0acb6e97b228b838049ffbd528571c5e3edd003f0ca8ef61940166dc3081b78a
			Console.WriteLine(transactionResponse.Block.Confirmations); // 91


			var receivedCoins = transactionResponse.ReceivedCoins;
			OutPoint outPointToSpend = null;
			foreach (var coin in receivedCoins)
			{
				if (coin.TxOut.ScriptPubKey == bitcoinPrivateKey.GetAddress(ScriptPubKeyType.Legacy).ScriptPubKey)
				{
					outPointToSpend = coin.Outpoint;
					Console.WriteLine(coin.Amount.ToString());
				}

			}
			if (outPointToSpend == null)
				throw new Exception("TxOut doesn't contain our ScriptPubKey");
			Console.WriteLine("We want to spend {0}. outpoint:", outPointToSpend.N + 1);

			var transaction = Transaction.Create(network);
			transaction.Inputs.Add(new TxIn()
			{
				PrevOut = outPointToSpend
			});

			// 0.0001 BTC
			// back to faucet

			var faucet = BitcoinAddress.Create("tb1ql7w62elx9ucw4pj5lgw4l028hmuw80sndtntxt", Network.TestNet);
			/*
			transaction.Outputs.Add(Money.Coins(0.00004m), faucet.ScriptPubKey);
			// Send the change back
			transaction.Outputs.Add(new Money(0.000053m, MoneyUnit.BTC), bitcoinPrivateKey.PubKey.ScriptPubKey);
			*/

			// How much you want to spend
			var faucetAmount = new Money(0.00004m, MoneyUnit.BTC);

			// How much miner fee you want to pay
			/* Depending on the market price and
			 * the currently advised mining fee,
			 * you may consider to increase or decrease it.
			 */
			var minerFee = new Money(0.000007m, MoneyUnit.BTC);

			// How much you want to get back as change
			var txInAmount = (Money)receivedCoins[(int)outPointToSpend.N].Amount;
			var changeAmount = txInAmount - faucetAmount - minerFee;

			transaction.Outputs.Add(faucetAmount, faucet.ScriptPubKey);
			// Send the change back
			transaction.Outputs.Add(changeAmount, bitcoinPrivateKey.PubKey.ScriptPubKey);

			var message = "Long live NBitcoin and its makers!";
			var bytes = System.Text.Encoding.UTF8.GetBytes(message);
			transaction.Outputs.Add(Money.Zero, TxNullDataTemplate.Instance.GenerateScriptPubKey(bytes));

			// SIGN transaction

			// Get it from the public address
			//var address = BitcoinAddress.Create("mt4aVcpXuokcFSvoLV31TverNhHmqUYx1k", Network.TestNet);
			//transaction.Inputs[0].ScriptSig = address.ScriptPubKey;

			// OR we can also use the private key 
			transaction.Inputs[0].ScriptSig = bitcoinPrivateKey.GetAddress(ScriptPubKeyType.Legacy).ScriptPubKey;
			transaction.Sign(bitcoinPrivateKey, receivedCoins.ToArray());
			Console.WriteLine(transaction.ToString());


			// send transaction

			BroadcastResponse broadcastResponse = client.Broadcast(transaction).Result;

			if (!broadcastResponse.Success)
			{
				Console.Error.WriteLine("ErrorCode: " + broadcastResponse.Error.ErrorCode);
				Console.Error.WriteLine("Error message: " + broadcastResponse.Error.Reason);
			}
			else
			{
				Console.WriteLine("Success! You can check out the hash of the transaciton in any block explorer:");
				Console.WriteLine(transaction.GetHash());
				// edd0ccd527f2ee2f756f298b34d9da2857235dad13866cd4d037997a2d028d19
			}

		}
		static void angelo_test()
		{
			var bitcoinPrivateKey = new BitcoinSecret("L5DZpEdbDDhhk3EqtktmGXKv3L9GxttYTecxDhM5huLd82qd9uvo", Network.Main);
			var network = bitcoinPrivateKey.Network;
			var address = bitcoinPrivateKey.GetAddress(ScriptPubKeyType.Legacy);

			Console.WriteLine(bitcoinPrivateKey);
			Console.WriteLine(address);
		}

		static void proof_of_ownership()
		{
			/*
			var bitcoinPrivateKey = new BitcoinSecret("L5DZpEdbDDhhk3EqtktmGXKv3L9GxttYTecxDhM5huLd82qd9uvo", Network.Main);

			var message = "I am Craig Wright";
			string signature = bitcoinPrivateKey.PrivateKey.SignMessage(message);
			Console.WriteLine(signature); // IBh8OzRVicQ1BQnTUe0iid3r02Ob+mmrj/ok5rF3uQybXkC7ojphiWNCN+IDqpSKM2N11i5LDS466JLjhdNGMn4=

			var address = new BitcoinPubKeyAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Network.Main);
			bool isCraigWrightSatoshi = address.VerifyMessage(message, signature);

			Console.WriteLine("Is Craig Wright Satoshi? " + isCraigWrightSatoshi);
			*/
		}

		static void bip38_1()
		{
			var privateKey = new Key();
			var bitcoinPrivateKey = privateKey.GetWif(Network.Main);
			Console.WriteLine(bitcoinPrivateKey); // L1tZPQt7HHj5V49YtYAMSbAmwN9zRjajgXQt9gGtXhNZbcwbZk2r
			BitcoinEncryptedSecret encryptedBitcoinPrivateKey = bitcoinPrivateKey.Encrypt("password");
			Console.WriteLine(encryptedBitcoinPrivateKey); // 6PYKYQQgx947Be41aHGypBhK6TA5Xhi9TdPBkatV3fHbbKrdDoBoXFCyLK
			var decryptedBitcoinPrivateKey = encryptedBitcoinPrivateKey.GetSecret("password");
			Console.WriteLine(decryptedBitcoinPrivateKey); // L1tZPQt7HHj5V49YtYAMSbAmwN9zRjajgXQt9gGtXhNZbcwbZk2r

			Console.ReadLine();
		}
		static void bip38_2()
		{
			var passphraseCode = new BitcoinPassphraseCode("my secret", Network.Main, null);
			Console.WriteLine(passphraseCode.ToString()); // passphrasepP5eZKBNPd6oeqrcdqiCJaGdSooKxBcbmgDSq2GCZ5U7u1MBa9izNrXLaoR9YY


			// You then give this passphraseCode to a third party key generator.
			EncryptedKeyResult encryptedKeyResult = passphraseCode.GenerateEncryptedSecret();

			var generatedAddress = encryptedKeyResult.GeneratedAddress; // 1EXF1VKvjzt8AGLg2omuqspf4erj2xVYDu
			Console.WriteLine(generatedAddress.ToString());
			var encryptedKey = encryptedKeyResult.EncryptedKey; // 6PnWtBokjVKMjuSQit1h1Ph6rLMSFz2n4u3bjPJH1JMcp1WHqVSfr5ebNS
			Console.WriteLine(encryptedKey.ToString());
			var confirmationCode = encryptedKeyResult.ConfirmationCode; // cfrm38VUcrdt2zf1dCgf4e8gPNJJxnhJSdxYg6STRAEs7QuAuLJmT5W7uNqj88hzh9bBnU9GFkN
			Console.WriteLine(confirmationCode.ToString());


			var generatedAddress2 = BitcoinAddress.Create(generatedAddress.ToString(), Network.Main);
			Console.WriteLine(generatedAddress2.ToString());

			var generatedAddress3 = BitcoinAddress.Create("19vz1be1B8aqBPfbWQFrkZqqBzpVpeyA3y", Network.Main);
			BitcoinConfirmationCode confCode = new BitcoinConfirmationCode("cfrm38VURxHibP88wgF85MgyrEpKbQDpCFr8CAiHc2ghTz43WGkursNZPSz8r9adnxuBMuWF1G2", Network.Main);

			var confirmed = confCode.Check("my secret", generatedAddress);
			Console.WriteLine(confirmed.ToString());

			// As the owner, once you receive this information, you need to check that the key generator
			// did not cheat by using ConfirmationCode.Check(), then get your private key with your password
			Console.WriteLine(confirmationCode.Check("my secret", generatedAddress2)); // True

			var bitcoinPrivateKey = encryptedKey.GetSecret("my secret");
			Console.WriteLine(bitcoinPrivateKey.GetAddress(ScriptPubKeyType.Legacy) == generatedAddress); // True
			Console.WriteLine(bitcoinPrivateKey); // KzzHhrkr39a7upeqHzYNNeJuaf1SVDBpxdFDuMvFKbFhcBytDF1R
		}
		static void bip38_angelo()
		{

			var passphraseCodeGenerated = new BitcoinPassphraseCode("passphrasepP5eZKBNPd6oeqrcdqiCJaGdSooKxBcbmgDSq2GCZ5U7u1MBa9izNrXLaoR9YY", Network.Main);
			Console.WriteLine(passphraseCodeGenerated.ToString());
			EncryptedKeyResult encryptedKeyResult = passphraseCodeGenerated.GenerateEncryptedSecret();
			var generatedAddress = encryptedKeyResult.GeneratedAddress;
			var encryptedKey = encryptedKeyResult.EncryptedKey; // 6PnWtBokjVKMjuSQit1h1Ph6rLMSFz2n4u3bjPJH1JMcp1WHqVSfr5ebNS
			var confirmationCode = encryptedKeyResult.ConfirmationCode; // cfrm38VUcrdt2zf1dCgf4e8gPNJJxnhJSdxYg6STRAEs7QuAuLJmT5W7uNqj88hzh9bBnU9GFkN
			Console.WriteLine(generatedAddress.ToString());
			Console.WriteLine(confirmationCode.ToString());
			Console.WriteLine(encryptedKey.ToString());

			Console.WriteLine(encryptedKey.ToWif().ToString());

			var bitcoinPrivateKey = encryptedKey.GetSecret("my secret");
			Console.WriteLine(bitcoinPrivateKey.GetAddress(ScriptPubKeyType.Legacy) == generatedAddress);

		}
		static void HD_wallet()
		{
			/////
			// converting ExtKey to string parts and back to ExtKey
			ExtKey privateExtKey = new ExtKey();
			Console.WriteLine(privateExtKey.ToString(Network.Main));
			Key privateKey = privateExtKey.PrivateKey;
			byte[] chainCode2 = privateExtKey.ChainCode;
			string privateKeyStr = privateKey.ToHex().ToString();
			string chainCodeStr = Convert.ToBase64String(chainCode2);
			Console.WriteLine("privateKeyStr:" + privateKeyStr + " chainCodeStr:" + chainCodeStr);

			byte[] pKbytes = NBitcoin.DataEncoders.Encoders.Hex.DecodeData(privateKeyStr);
			Key privateKey2 = new NBitcoin.Key(pKbytes);
			byte[] chainCode3 = NBitcoin.DataEncoders.Encoders.Base64.DecodeData(chainCodeStr);
			ExtKey newExtKey2 = new ExtKey(privateKey2, chainCode3);
			Console.WriteLine("Final " + newExtKey2.ToString(Network.Main));
			//////
			///

			// testing publicKeys

			Console.WriteLine("1: " + privateExtKey.PrivateKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main).ScriptPubKey);
			Console.WriteLine("2: " + privateExtKey.ScriptPubKey.ToString()); // it's the same as the above and bellow
			Console.WriteLine("3: " + privateExtKey.PrivateKey.GetAddress(ScriptPubKeyType.Legacy, Network.TestNet).ScriptPubKey);
			Console.WriteLine("4: " + privateExtKey.GetWif(Network.Main).ToString());
			Console.WriteLine("5: " + privateExtKey.PrivateKey.GetWif(Network.Main).ToString());
			Console.WriteLine("6: " + privateExtKey.PrivateKey.PubKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main));
			Console.WriteLine("7: " + privateExtKey.GetPublicKey().ToString());
			Console.WriteLine("8: " + privateExtKey.PrivateKey.PubKey.ToString());


			ExtKey masterKey = new ExtKey();
			Console.WriteLine("Master key : " + masterKey.ToString(Network.Main));

			for (int i = 0; i < 5; i++)
			{
				ExtKey key = masterKey.Derive((uint)i);
				Console.WriteLine("Key " + i + " : " + key.ToString(Network.Main));
			}

			ExtKey extKey = new ExtKey();

			byte[] chainCode = extKey.ChainCode;
			Key key2 = extKey.PrivateKey;
			Console.WriteLine("key2:" + key2.ToString(Network.Main));
			ExtKey newExtKey = new ExtKey(key2, chainCode);
			Console.WriteLine("chainCode:" + BitConverter.ToString(chainCode));

			// you can “neuter” your master key, then you have a public (without private key) version of the master key.

			ExtPubKey masterPubKey2 = new ExtPubKey(masterKey.GetPublicKey(), masterKey.ChainCode);
			Console.WriteLine("MainPubKey 1" + masterPubKey2.ToString(Network.Main));

			ExtPubKey masterPubKey = masterKey.Neuter();
			Console.WriteLine("MainPubKey 2" + masterPubKey.ToString(Network.Main));

			for (int i = 0; i < 5; i++)
			{
				ExtPubKey pubkey = masterPubKey.Derive((uint)i);
				Console.WriteLine("PubKey " + i + " : " + pubkey.ToString(Network.Main));
			}

		}
		static void HD_wallet_2()
		{
			ExtKey masterKey = new ExtKey();
			ExtPubKey masterPubKey = masterKey.Neuter();

			//The payment server generate pubkey1
			ExtPubKey pubkey1 = masterPubKey.Derive(1);

			//You get the private key of pubkey1
			ExtKey key1 = masterKey.Derive(1);

			//Check it is legit
			Console.WriteLine("Generated address : " + pubkey1.PubKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main));
			Console.WriteLine("Expected address : " + key1.PrivateKey.PubKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main));

			// these are the same
			// option 1
			ExtKey parent = new ExtKey();
			ExtKey child11 = parent.Derive(1).Derive(1);
			// option 2
			ExtKey parent2 = new ExtKey();
			ExtKey child211 = parent2.Derive(new KeyPath("1/1"));
		}
		static void none_hardened()
		{
			ExtKey ceoKey = new ExtKey();
			Console.WriteLine("CEO: " + ceoKey.ToString(Network.Main));
			ExtKey accountingKey = ceoKey.Derive(0, hardened: false);

			ExtPubKey ceoPubkey = ceoKey.Neuter();

			//Recover ceo key with accounting private key and ceo public key
			ExtKey ceoKeyRecovered = accountingKey.GetParentExtKey(ceoPubkey);
			Console.WriteLine("CEO recovered: " + ceoKeyRecovered.ToString(Network.Main));

		}
		static void hardened()
		{
			ExtKey ceoKey = new ExtKey();
			Console.WriteLine("CEO: " + ceoKey.ToString(Network.Main));
			ExtKey accountingKey = ceoKey.Derive(0, hardened: true);

			ExtPubKey ceoPubkey = ceoKey.Neuter();

			ExtKey ceoKeyRecovered = accountingKey.GetParentExtKey(ceoPubkey); //Crash

			// You can also create hardened keys via the ExtKey.Derivate(KeyPath),
			// by using an apostrophe after a child’s index:

			var nonHardened = new KeyPath("1/2/3");
			var hardened = new KeyPath("1/2/3'");
		}
		static void BIP39()
		{

			//Mnemonic mnemo = new Mnemonic(Wordlist.English, WordCount.Twelve);
			Mnemonic mnemo = new Mnemonic(Wordlist.English, (WordCount)12);
			ExtKey hdRoot = mnemo.DeriveExtKey("my password");
			Console.WriteLine(mnemo.ToString());


			// recover from mnemonic
			mnemo = new Mnemonic("minute put grant neglect anxiety case globe win famous correct turn link",
				Wordlist.English);
			ExtKey hdRoot2 = mnemo.DeriveExtKey("my password");
			Console.WriteLine(hdRoot2.PrivateKey.ToString(Network.Main)); // L4MfN75YR1FrWWewJ4vKpCeUu3Kw7VfA9F1aB98YyT5yk48zpeSx

			// recover from mnemonic
			mnemo = new Mnemonic("employ churn dance mask stand exact remove address pipe science imitate mom");
			ExtKey hdRoot3 = mnemo.DeriveExtKey(); // 
			Console.WriteLine(hdRoot3.PrivateKey.GetBitcoinSecret(Network.Main).ToString()); // KwWNFvd1fBgcjaoJ1RNRdhB2Bu31fTjsLKsfo1mXnE258P3Peiwa
			Console.WriteLine(hdRoot3.PrivateKey.ToHex().ToString());

		}

		static void test_bip32()
		{
			string tempSeed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
			byte[] seed = Encoders.Hex.DecodeData(tempSeed);
			ExtKey key = ExtKey.CreateFromSeed(seed);
			ExtPubKey pubkey = key.Neuter();
			Console.WriteLine(key.ToString(Network.Main)); // xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U
			Console.WriteLine(pubkey.ToString(Network.Main)); // xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB

			string tempKeyPath;

			for (int i = 0; i < 5; i++)
			{
				tempKeyPath = "44/0/0/0/" + i.ToString();
				KeyPath tempPath = new KeyPath(tempKeyPath);
				ExtPubKey pubkey2 = pubkey.Derive(tempPath);
				Console.WriteLine("PubKey " + i + " : " + pubkey2.PubKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main));

			}

			for (int i = 0; i < 5; i++)
			{
				ExtPubKey pubkey3 = key.Derive(i, hardened: false).Neuter();
				Console.WriteLine("PubKey " + i + " : " + pubkey3.PubKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main));
			}

			for (int i = 0; i < 5; i++)
			{
				ExtKey key3 = key.Derive(i, hardened: false);
				Console.WriteLine("PubKey " + i + " : " + key3.ScriptPubKey.GetDestinationAddress(Network.Main));
			}
			// You can also create hardened keys via the ExtKey.Derivate(KeyPath),
			// by using an apostrophe after a child’s index:

			//var nonHardened = new KeyPath("1/2/3");
			//var hardened = new KeyPath("1/2/3'");

			KeyPath keyPath = new KeyPath("0/2147483647'"); // Chain m/0/2147483647'
			ExtKey derivedKey = key.Derive(keyPath);
			ExtPubKey derivedPubkey = derivedKey.Neuter();
			Console.WriteLine(derivedKey.ToString(Network.Main));
			Console.WriteLine(derivedPubkey.ToString(Network.Main));
		}
		static void BIP39_wasabi()
		{

			// recover from mnemonic
			Mnemonic mnemo = new Mnemonic("budget minimum between flower tribe gesture safe cool pioneer hurt blossom tell", Wordlist.English);
			ExtKey key = mnemo.DeriveExtKey("angelo");
			ExtPubKey pubkey = key.Neuter();
			Console.WriteLine(key.ToString(Network.Main)); // xprv9s21ZrQH143K45hZozMRSZFY4ME7aMpVMc9i1GNk4x5sb9gGF5HpMddLjvTWRpcB7fcEh3LiDKkBmWRmVsx3JLFYZR5JKwg2uMmMaVR7xn2
			Console.WriteLine(pubkey.ToString(Network.Main)); // xpub661MyMwAqRbcGZn2v1tRohCGcP4bypYLiq5JoenMdHcrTx1Qncc4uRwpbB56jUHgktHe1ndB9hjqooaMoY6ttr1zQEXN8Vn6ZGsQUN2ef5g

			KeyPath keyPath = new KeyPath("44'/0'/0'/1/0"); // Chain m/44'/0'/0'/1/0
			ExtKey derivedKey = key.Derive(keyPath);
			ExtPubKey derivedPubkey = derivedKey.Neuter();
			Console.WriteLine(derivedKey.ToString(Network.Main)); // xprvA4EZzwsTZk2htsPFGez7QYcVF34cnqUYTJXytdcEBCU14xz7MeuMKnaoYLKCsQUv6GQzYq93Tiiq14to7upfitogtkEVjK5yJhFC8fKYvvv
			Console.WriteLine(derivedPubkey.ToString(Network.Main)); // xpub6HDvQTQMQ7b17MTiNgX7mgZDo4u7CJCPpXTah21qjXzywmKFuCDbsauHPbNojcybhitKfJ1ydoMaS1ZDmtndxSvsYT5ZqKiq5rFPDFcHZNL


			Console.WriteLine(derivedKey.PrivateKey.ToHex().ToString()); // e0c9da7a8720477a2bf089396fec73aee82cdf480cb6504f8bcbecb69d1812cc
			Console.WriteLine(derivedKey.PrivateKey.PubKey.ToHex().ToString()); // 02e4f4702e1bd412578617b87ac5a04653ad457f77dd915a5069e4757bd2bdd631

		}


		static void Iancoleman_io()
		{



			// recover from mnemonic
			//Mnemonic mnemo = new Mnemonic("budget minimum between flower tribe gesture safe cool pioneer hurt blossom tell", Wordlist.English);
			//ExtKey key = mnemo.DeriveExtKey("");

			// from extended private key
			ExtKey key = ExtKey.Parse("xprv9s21ZrQH143K3jJ9HCQmAKPzGfDwGUDHfn8Jm7BFmtAizLdPaD9opjD3VDccfqyW4bKVvJya2M32NmT47s7uYM71PNWd1vQ6iBbhBRwHNin", Network.Main);


			Console.WriteLine(key.Depth.ToString());
			Console.WriteLine(key.Child.ToString());
			Console.WriteLine(key.IsHardened.ToString());
			Console.WriteLine(key.ParentFingerprint.ToString());

			// Root Key
			Console.WriteLine(key.ToString(Network.Main)); // xprv9s21ZrQH143K3jJ9HCQmAKPzGfDwGUDHfn8Jm7BFmtAizLdPaD9opjD3VDccfqyW4bKVvJya2M32NmT47s7uYM71PNWd1vQ6iBbhBRwHNin

			KeyPath keyPath3 = new KeyPath("m/44'/0'/0'");
			ExtKey derivedKey3 = key.Derive(keyPath3);
			ExtPubKey derivedPubkey3 = derivedKey3.Neuter();
			Console.WriteLine(derivedKey3.ToString(Network.Main)); // xprv9zEZ6SFiDk5kWW2BYLzpxj9ukWvEUMC5x2gdqHviPATT6rRMouTPncuXSnYUMKm4H6MrGcamyZc3XtYB1xCM3BZms97mtq7kM7JUyzkDgRb
			Console.WriteLine(derivedPubkey3.ToString(Network.Main)); // xpub6DDuVwnc47e3iz6eeNXqKs6eJYkisouwKFcEdgLKwVzRyekWMSmeLRE1J4QrqGD8wFMKnWQiYABCG5sc2STVT63Phvp4CYgufoC7NHnCHNT

			KeyPath keyPath = new KeyPath("m/44'/0'/0'/0"); // Chain m/44'/0'/0'/0
			ExtKey derivedKey = key.Derive(keyPath);
			ExtPubKey derivedPubkey = derivedKey.Neuter();
			Console.WriteLine(derivedKey.ToString(Network.Main)); // xprvA18e1pvMfM7dgXNHwfzPhP5BU4Uab5KRQSCUggfkYkuSDD9KohTqEjBh9EbHkgP45mWMgMRXanvBpQRWadFghWmjP5vAKGn12QUTDMLU6zb
			Console.WriteLine(derivedPubkey.ToString(Network.Main)); // xpub6E7zRLTFVifvu1Sm3hXQ4X1v26K4zY3Gmf85V55N76SR61UUMEn5nXWAzYWrLYBFcJyWcJfrbc8yMVRVHJLTA924x5R98XRFT9x6YcgGLqo


			KeyPath keyPath2 = new KeyPath("m/44'/0'/0'/0/0"); // Chain m/44'/0'/0'/0/0 - first external
			ExtKey derivedKey2 = key.Derive(keyPath2);

			Console.WriteLine(derivedKey2.PrivateKey.GetWif(Network.Main)); // KxYtHHeNkKB7S5ZzESmeTuR4ugenxGHzWehoG3cDKbToCqALbnuj
			Console.WriteLine(derivedKey2.PrivateKey.PubKey.ToHex().ToString()); // 03741b5435ca617d3d01b26b08fce892b96b3d2b0e7babfcbb363151cdf9c7d888
			Console.WriteLine(derivedKey2.PrivateKey.PubKey.Hash.GetAddress(Network.Main)); // 1MzKqACC7BtCjHtN8uoC2qqZRm3iPRGVwy

			// next one
			KeyPath keyPath4 = new KeyPath("1");
			Console.WriteLine(derivedPubkey.Derive(keyPath4).PubKey.Hash.GetAddress(Network.Main)); // 17A2maeHZ3TXDpthpmeq29HSC3gdXQysSh

			ExtPubKey derivedPubkey2 = ExtPubKey.Parse("xpub6E7zRLTFVifvu1Sm3hXQ4X1v26K4zY3Gmf85V55N76SR61UUMEn5nXWAzYWrLYBFcJyWcJfrbc8yMVRVHJLTA924x5R98XRFT9x6YcgGLqo", Network.Main);
			Console.WriteLine(derivedPubkey2.Derive(keyPath4).PubKey.Hash.GetAddress(Network.Main));
			Console.WriteLine(derivedPubkey2.Depth.ToString());
			Console.WriteLine(derivedPubkey2.Child.ToString());
			Console.WriteLine(derivedPubkey2.IsHardened.ToString());
			Console.WriteLine(derivedPubkey2.ParentFingerprint.ToString());

		}
		static void Iancoleman_io_2()
		{



			// recover from mnemonic
			//Mnemonic mnemo = new Mnemonic("budget minimum between flower tribe gesture safe cool pioneer hurt blossom tell", Wordlist.English);
			//ExtKey key = mnemo.DeriveExtKey("");

			// from extended private key
			ExtKey key = ExtKey.Parse("xprv9s21ZrQH143K3jJ9HCQmAKPzGfDwGUDHfn8Jm7BFmtAizLdPaD9opjD3VDccfqyW4bKVvJya2M32NmT47s7uYM71PNWd1vQ6iBbhBRwHNin", Network.Main);


			Console.WriteLine(key.Depth.ToString());
			Console.WriteLine(key.Child.ToString());
			Console.WriteLine(key.IsHardened.ToString());
			Console.WriteLine(key.ParentFingerprint.ToString());

			// Root Key
			Console.WriteLine(key.ToString(Network.Main)); // xprv9s21ZrQH143K3jJ9HCQmAKPzGfDwGUDHfn8Jm7BFmtAizLdPaD9opjD3VDccfqyW4bKVvJya2M32NmT47s7uYM71PNWd1vQ6iBbhBRwHNin

			KeyPath keyPath3 = new KeyPath("m/44'/0'/0'");
			ExtKey derivedKey3 = key.Derive(keyPath3);
			ExtPubKey derivedPubkey3 = derivedKey3.Neuter();
			Console.WriteLine(derivedKey3.ToString(Network.Main)); // xprv9zEZ6SFiDk5kWW2BYLzpxj9ukWvEUMC5x2gdqHviPATT6rRMouTPncuXSnYUMKm4H6MrGcamyZc3XtYB1xCM3BZms97mtq7kM7JUyzkDgRb
			Console.WriteLine(derivedPubkey3.ToString(Network.Main)); // xpub6DDuVwnc47e3iz6eeNXqKs6eJYkisouwKFcEdgLKwVzRyekWMSmeLRE1J4QrqGD8wFMKnWQiYABCG5sc2STVT63Phvp4CYgufoC7NHnCHNT

			KeyPath keyPath = new KeyPath("m/44'/0'/0'/0"); // Chain m/44'/0'/0'/0
			ExtKey derivedKey = key.Derive(keyPath);
			ExtPubKey derivedPubkey = derivedKey.Neuter();
			Console.WriteLine(derivedKey.ToString(Network.Main)); // xprvA18e1pvMfM7dgXNHwfzPhP5BU4Uab5KRQSCUggfkYkuSDD9KohTqEjBh9EbHkgP45mWMgMRXanvBpQRWadFghWmjP5vAKGn12QUTDMLU6zb
			Console.WriteLine(derivedPubkey.ToString(Network.Main)); // xpub6E7zRLTFVifvu1Sm3hXQ4X1v26K4zY3Gmf85V55N76SR61UUMEn5nXWAzYWrLYBFcJyWcJfrbc8yMVRVHJLTA924x5R98XRFT9x6YcgGLqo


			KeyPath keyPath2 = new KeyPath("m/44'/0'/0'/0/0"); // Chain m/44'/0'/0'/0/0 - first external
			ExtKey derivedKey2 = key.Derive(keyPath2);

			Console.WriteLine(derivedKey2.PrivateKey.GetWif(Network.Main)); // KxYtHHeNkKB7S5ZzESmeTuR4ugenxGHzWehoG3cDKbToCqALbnuj
			Console.WriteLine(derivedKey2.PrivateKey.PubKey.ToHex().ToString()); // 03741b5435ca617d3d01b26b08fce892b96b3d2b0e7babfcbb363151cdf9c7d888
			Console.WriteLine(derivedKey2.PrivateKey.PubKey.Hash.GetAddress(Network.Main)); // 1MzKqACC7BtCjHtN8uoC2qqZRm3iPRGVwy

			// next one
			KeyPath keyPath4 = new KeyPath("1");
			Console.WriteLine(derivedPubkey.Derive(keyPath4).PubKey.Hash.GetAddress(Network.Main)); // 17A2maeHZ3TXDpthpmeq29HSC3gdXQysSh

			ExtPubKey derivedPubkey2 = ExtPubKey.Parse("xpub6E7zRLTFVifvu1Sm3hXQ4X1v26K4zY3Gmf85V55N76SR61UUMEn5nXWAzYWrLYBFcJyWcJfrbc8yMVRVHJLTA924x5R98XRFT9x6YcgGLqo", Network.Main);
			Console.WriteLine(derivedPubkey2.Derive(keyPath4).PubKey.Hash.GetAddress(Network.Main));
			Console.WriteLine(derivedPubkey2.Derive(keyPath4).PubKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main));
			Console.WriteLine(derivedPubkey2.Derive(keyPath4).PubKey.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main));
			Console.WriteLine(derivedPubkey2.Derive(keyPath4).PubKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main));
			Console.WriteLine(derivedPubkey2.PubKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main).ToString());
			Console.WriteLine(derivedPubkey2.Depth.ToString());
			Console.WriteLine(derivedPubkey2.Child.ToString());
			Console.WriteLine(derivedPubkey2.IsHardened.ToString());
			Console.WriteLine(derivedPubkey2.ParentFingerprint.ToString());
			Console.WriteLine(derivedPubkey2.PubKey.ToHex().ToString());

		}
		static void send_coins_youtube()
		{
			// form angeloRandom wallet
			BitcoinSecret fromWIF = new BitcoinSecret("cQLbXipsPCkG6i83WAaeumvPWcjmAigrQdxRP9AajAYcWraAeDy1", Network.TestNet);
			var prvKey = fromWIF.PrivateKey;
			Transaction tx = Network.TestNet.CreateTransaction();
			var input = new TxIn();
			input.PrevOut = new OutPoint(new uint256("94c32e763e51c38303a0e2d22f7437d634e570c437edcdce44e588d9b17ec699"), 1); // 15.12845 mBTC
			input.ScriptSig = prvKey.GetScriptPubKey(ScriptPubKeyType.Legacy);
			tx.Inputs.Add(input);

			var output = new TxOut();

			var destination = BitcoinAddress.Create("n3RgG38YzXTswDMhVmHTCfn58wSydnFfFX", Network.TestNet);
			output.ScriptPubKey = destination.ScriptPubKey;
			Money fees = Money.Satoshis(40000);
			output.Value = Money.Coins(0.010m) - fees;
			tx.Outputs.Add(output);

			Coin[] coins = tx.Outputs.AsCoins().ToArray();
			Coin coin = coins[0];
			tx.Sign(prvKey.GetBitcoinSecret(Network.TestNet), coin);
			//new TransactionBuilder().AddKeys(bob).AddCoins(scriptCoin).SignTransaction(tx)
			Console.WriteLine(tx.ToString());

			var node = Node.Connect(Network.TestNet, "192.168.200.110:18332");
			node.VersionHandshake();
			node.SendMessage(new InvPayload(tx));
			node.SendMessage(new TxPayload(tx));
			Thread.Sleep(4000);
			node.Disconnect();

		}

		static void transactionbuilder()
		{
			/*
			Now let’s gather some Coins. For that, let us create a fake transaction with some funds on it.
			Let’s say that the transaction has a P2PKH, P2PK, and multi-sig coin of Bob and Alice.
			*/

			// Create a fake transaction
			var bob = new Key();
			var alice = new Key();

			Script bobAlice = PayToMultiSigTemplate.Instance.GenerateScriptPubKey(2, bob.PubKey, alice.PubKey);

			var init = Network.Main.CreateTransaction();
			init.Outputs.Add(Money.Coins(1m), bob.PubKey); // P2PK
			init.Outputs.Add(Money.Coins(1m), alice.PubKey.Hash); // P2PKH
			init.Outputs.Add(Money.Coins(1m), bobAlice);

			// now let's pay Satoshi
			var satoshi = new Key();

			// first they have to get the coins
			Coin[] coins = init.Outputs.AsCoins().ToArray();
			Coin bobCoin = coins[0];
			Coin aliceCoin = coins[1];
			Coin bobAliceCoin = coins[2];

			// Now let’s say bob wants to send 0.2 BTC, alice 0.3 BTC,
			// and they agree to use bobAlice to send 0.5 BTC

			var builder = Network.Main.CreateTransactionBuilder();
			Transaction tx = builder
					.AddCoins(bobCoin)
					.AddKeys(bob)
					.Send(satoshi, Money.Coins(0.2m))
					.SetChange(bob)
					.Then()
					.AddCoins(aliceCoin)
					.AddKeys(alice)
					.Send(satoshi, Money.Coins(0.3m))
					.SetChange(alice)
					.Then()
					.AddCoins(bobAliceCoin)
					.AddKeys(bob, alice)
					.Send(satoshi, Money.Coins(0.5m))
					.SetChange(bobAlice)
					.SendFees(Money.Coins(0.0001m))
					.BuildTransaction(sign: true);
			Console.WriteLine(builder.Verify(tx)); // True

			/*
			 * The nice thing about this model is that it works the same way for P2SH, 
			 * P2WSH, P2SH(P2WSH), and P2SH(P2PKH) except you need to create ScriptCoin.
			 */
			init = Network.Main.CreateTransaction();
			init.Outputs.Add(Money.Coins(1.0m), bobAlice.Hash);

			coins = init.Outputs.AsCoins().ToArray();
			ScriptCoin bobAliceScriptCoin = coins[0].ToScriptCoin(bobAlice);

			builder = Network.Main.CreateTransactionBuilder();
			tx = builder
					.AddCoins(bobAliceScriptCoin)
					.AddKeys(bob, alice)
					.Send(satoshi, Money.Coins(0.9m))
					.SetChange(bobAlice.Hash)
					.SendFees(Money.Coins(0.0001m))
					.BuildTransaction(true);
			Console.WriteLine(builder.Verify(tx)); // True
			Console.WriteLine(tx);

		}

		static void send_coins_angelo_old()
		{


			// form angeloRandom wallet
			BitcoinSecret fromWIF = new BitcoinSecret("cQLbXipsPCkG6i83WAaeumvPWcjmAigrQdxRP9AajAYcWraAeDy1", Network.TestNet);
			var prvKey = fromWIF.PrivateKey;

			var input = new TxIn();
			input.PrevOut = new OutPoint(new uint256("94c32e763e51c38303a0e2d22f7437d634e570c437edcdce44e588d9b17ec699"), 1); // 15.12845 mBTC
			input.ScriptSig = prvKey.PubKey.ScriptPubKey;


			var output = new TxOut();
			var destination = BitcoinAddress.Create("n3RgG38YzXTswDMhVmHTCfn58wSydnFfFX", Network.TestNet);
			output.ScriptPubKey = destination.ScriptPubKey;
			Money fees = Money.Satoshis(40000);
			output.Value = Money.Coins(0.010m) - fees;

			// create transaction and add inputs and outputs
			Transaction tx = Network.TestNet.CreateTransaction();
			tx.Inputs.Add(input);
			tx.Outputs.Add(output);

			Coin[] coins = tx.Outputs.AsCoins().ToArray();
			Coin coin = coins[0];
			tx.Sign(prvKey.GetBitcoinSecret(Network.TestNet), coin);

			var builder = Network.TestNet.CreateTransactionBuilder();
			builder.AddKeys(prvKey).AddCoin(coin);//.SignTransaction(tx);

			Console.WriteLine(tx.ToString());
			builder.Verify(tx);
			/*
			var node = Node.Connect(Network.TestNet, "192.168.200.110:18332");
			node.VersionHandshake();
			node.SendMessage(new InvPayload(tx));
			node.SendMessage(new TxPayload(tx));
			Thread.Sleep(4000);
			node.Disconnect();
			*/

		}
		static void send_coins_angelo()
		{


			Transaction tx = Network.TestNet.CreateTransaction();

			var input = new TxIn();
			input.PrevOut = new OutPoint(new uint256("94c32e763e51c38303a0e2d22f7437d634e570c437edcdce44e588d9b17ec699"), 1); // 15.12845 mBTC
			var privKey = new BitcoinSecret("cQLbXipsPCkG6i83WAaeumvPWcjmAigrQdxRP9AajAYcWraAeDy1", Network.TestNet);
			input.ScriptSig = privKey.PubKey.ScriptPubKey;
			tx.Inputs.Add(input);

			Console.WriteLine("Awesome, here is how your transaction looks like now:");
			Console.WriteLine(tx);



			var address = BitcoinAddress.Create("n3RgG38YzXTswDMhVmHTCfn58wSydnFfFX", Network.TestNet);
			var scriptPubKey = address.ScriptPubKey;
			Money fees = Money.Satoshis(40000);
			var amount = Money.Coins(0.010m) - fees;
			tx.Outputs.Add(new TxOut(amount, scriptPubKey));

			Console.WriteLine("Awesome, here is how your transaction looks like now:");
			Console.WriteLine();
			Console.WriteLine(tx);
			Console.WriteLine();


			var coins = tx.Inputs.Select(txin => new Coin(txin.PrevOut, new TxOut { ScriptPubKey = txin.ScriptSig }));


			tx.Sign(privKey, coins.ToArray());
			Console.WriteLine($"You signed your transaction on the {privKey.Network}");

			Console.WriteLine("Here is how your final transaction looks like:");
			Console.WriteLine();
			Console.WriteLine(tx);
			Console.WriteLine();

			Console.WriteLine("Here is the hex of your transaction:");
			Console.WriteLine();
			Console.WriteLine(tx.ToHex());


			var node = Node.Connect(Network.TestNet, "192.168.200.110:18333");
			node.VersionHandshake();
			node.SendMessage(new InvPayload(tx));
			node.SendMessage(new TxPayload(tx));
			Thread.Sleep(4000);
			node.Disconnect();



		}


		static void from_transaction_bulder()
		{
			// https://www.codeproject.com/Articles/835098/NBitcoin-Build-Them-All#simple

			BitcoinSecret aliceWif = new BitcoinSecret("cQLbXipsPCkG6i83WAaeumvPWcjmAigrQdxRP9AajAYcWraAeDy1", Network.TestNet);
			var alice = aliceWif.PrivateKey;
			//BitcoinSecret bob = new BitcoinSecret("KysJMPCkFP4SLsEQAED9CzCurJBkeVvAa4jeN1BBtYS7P5LocUBQ", Network.TestNet);
			//BitcoinSecret nico = new BitcoinSecret("L2uC8xNjmcfwje6eweucYvFsmKASbMDALy4rCJBAg8wofpH6barj", Network.TestNet);
			//BitcoinSecret satoshi = new BitcoinSecret("cPwvztN9AUUDpU3nRQSeqhU96eYK8Pw2NWpoH1SHApdXZvFkVEXt", Network.TestNet);
			var satoshi = BitcoinAddress.Create("mo7oyq1mJ2mJTi5Qy673ANJ8zUssmCDu1o", Network.TestNet);

			var aliceFunding = Network.TestNet.CreateTransaction();


			aliceFunding.Outputs.Add(new TxOut("0.45", alice.GetAddress(ScriptPubKeyType.Legacy, Network.TestNet)));
			aliceFunding.Outputs.Add(new TxOut("0.8", alice.PubKey));

			Coin[] aliceCoins = aliceFunding.Outputs.Select((o, i) => new Coin(new OutPoint(aliceFunding.GetHash(), i), o)).ToArray();

			Console.WriteLine(aliceFunding);

			var txBuilder = Network.TestNet.CreateTransactionBuilder();
			var tx = txBuilder
				.AddCoins(aliceCoins)
				.AddKeys(alice)
				.Send(satoshi.ScriptPubKey, "1.00")
				.SendFees("0.001")
				.SetChange(alice.GetAddress(ScriptPubKeyType.Legacy, Network.TestNet))
				.BuildTransaction(true);
			Console.WriteLine(tx);
			Console.WriteLine(txBuilder.Verify(tx));

			var start_tx_hex = "02000000000101fd035b752382e40609dc30778868acd21f58aa73ee3d8c3fbb264f5d223f18b50100000000feffffff0250c3000000000000160014ff5c7b3fc32488e1ae8056e03b38c5448eca990f83861f0300000000160014d2d667a23facaac10570432478f344305f83ec2c0247304402202b88430fe7295c2829d5f20a8fa1402ede85af419b2dafa262695600b9f13239022048a47f3e30ed77a883ed9c67f228145ed30089a93be10daa59e7df260378435b012103b820de626dd0961d918148742132a9671adaaf5a695e51c24556dfd7c33e5ddc1ac62300";
			Transaction tx2 = Transaction.Parse(start_tx_hex, Network.TestNet);
			Console.WriteLine(tx2);


		}

	}
}
