using System;
using System.Threading;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using NBitcoin.Crypto;
using System.Security.Cryptography;
using NBitcoin.Protocol;

namespace NBitcoinTraining
{
	class Program
	{
		//static Context ctx = Context.Instance;

		static void Main(string[] args)
		{
			//play_with_str_hex();
			creating_address_hash();

		}

		public static string ReverseHexString(string hexString)
		{
			// Validate input
			if (string.IsNullOrEmpty(hexString))
			{
				throw new ArgumentException("Hex string cannot be null or empty.");
			}

			if (hexString.Length % 2 != 0)
			{
				throw new ArgumentException("Hex string length must be even.");
			}

			char[] reversedHexArray = new char[hexString.Length];

			for (int i = 0; i < hexString.Length; i += 2)
			{
				reversedHexArray[hexString.Length - 2 - i] = hexString[i];
				reversedHexArray[hexString.Length - 1 - i] = hexString[i + 1];
			}

			return new string(reversedHexArray);
		}

		static void creating_address_hash()
		{
			Key keySpend = new Key(Encoders.Hex.DecodeData("018cf214dd328099dd9a53221050c5ba8bae5881e2a2052e9e2869c541c59852"));
			Console.WriteLine("with hash " + keySpend.PubKey.WitHash);
			var oneKey = new NBitcoin.BitcoinSecret("cMdiU1qYB1EeRLnvkXxyK56vUiK6PVRWcn3KKsWEAYfQagLNwADP", Network.RegTest);
			Console.WriteLine(oneKey.PubKeyHash);
			Console.WriteLine(oneKey.PubKeyHash.ScriptPubKey);
			Console.WriteLine(oneKey.PubKey.ScriptPubKey);
			Console.WriteLine(oneKey.PubKey.WitHash.ScriptPubKey);
			Console.WriteLine("with hash " +oneKey.PubKey.WitHash);


			var privateKey = oneKey.PrivateKey;
			Console.WriteLine(keySpend.PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86,Network.RegTest));
			Console.WriteLine(keySpend.PubKey.GetAddress(ScriptPubKeyType.TaprootBIP86, Network.RegTest).ScriptPubKey.WitHash);


			

			var netAddress = BitcoinAddress.Create("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Network.Main);
			Console.WriteLine(netAddress.ToString());
			Console.WriteLine("with hash " + netAddress.ScriptPubKey.WitHash);

			var netAddress2 = BitcoinAddress.Create("bcrt1pqzxws5wxuvhrnpu57fqyx9hlpk9m53v9ea4fm077kltd7x6a70gqfadfu9", Network.RegTest);
			Console.WriteLine(netAddress2.ToString());
			Console.WriteLine(netAddress2.ScriptPubKey.WitHash);
			Console.WriteLine(netAddress2.ScriptPubKey.WitHash.HashForLookUp);
			var nedReverse = netAddress2.ScriptPubKey.WitHash;
			Console.WriteLine(ReverseHexString(nedReverse.ToString()));

			var network = Network.TestNet;
			var netAddress3 = BitcoinAddress.Create("tb1q506ljfgkh87emh4hk48rug6mkadjmqfpm7mj7z", network);
			Console.WriteLine(network.ToString());
			Console.WriteLine(netAddress.ToString());
			Console.WriteLine("with hash " + netAddress3.ScriptPubKey.WitHash);



		}
		static void play_with_str_hex()
		{
			/*
			var input = "Hallo Hélène and Mr. Hörst";
			var ConvertStringToHexString = (string input) => String.Join("", System.Text.Encoding.UTF8.GetBytes(input).Select(b => $"{b:X2}"));
			var ConvertHexToString = (string hexInput) => System.Text.Encoding.UTF8.GetString(Enumerable.Range(0, hexInput.Length / 2).Select(_ => Convert.ToByte(hexInput.Substring(_ * 2, 2), 16)).ToArray());

			var hex = ConvertStringToHexString(input);
			var txt = ConvertHexToString(hex);
			Console.WriteLine(hex);
			Console.WriteLine(txt);
			*/

			var input = "Hallo Hélène and Mr. Hörst";

			string ConvertStringToHexString(string input)
			{
				// Convert the input string to a byte array using UTF-8 encoding
				byte[] byteArray = System.Text.Encoding.UTF8.GetBytes(input);

				// Convert each byte to its hexadecimal representation and join them into a single string
				System.Text.StringBuilder hexString = new System.Text.StringBuilder(byteArray.Length * 2);
				foreach (byte b in byteArray)
				{
					hexString.AppendFormat("{0:X2}", b);
				}

				return hexString.ToString();
			}

			string ConvertHexToString(string hexInput)
			{
				// Calculate the number of characters in the hexadecimal string
				int numberChars = hexInput.Length;

				// Convert each pair of hexadecimal characters to a byte and create a byte array
				byte[] byteArray = new byte[numberChars / 2];
				for (int i = 0; i < numberChars; i += 2)
				{
					byteArray[i / 2] = Convert.ToByte(hexInput.Substring(i, 2), 16);
				}

				// Convert the byte array back to a string using UTF-8 encoding
				string originalString = System.Text.Encoding.UTF8.GetString(byteArray);

				return originalString;
			}

			string hex = ConvertStringToHexString(input);
			Console.WriteLine($"String to HEX: {hex}");

			string output = ConvertHexToString(hex);
			Console.WriteLine($"HEX to String: {output}");


		}


	}


}
