using System;
using System.Threading;
using NBitcoin;
using NBitcoin.Tests;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;
using NBitcoin.Crypto;
using System.Security.Cryptography;
using System.Reflection.Metadata;
using Newtonsoft.Json.Linq;
using System.Reflection;


namespace NBitcoinTraining
{
	class Program
	{
		//static Context ctx = Context.Instance;

		static void Main(string[] args)
		{

			//musig_address_and_path_spend_with_huffman();
			//musig_matching_dc();
			//musig_matching_dc2();
			//CanSignUsingTapscriptAndKeySpend();
			musig_matching_3_of_5();

		}

		static void CanSignUsingTapscriptAndKeySpend()
		{
			var ctx = Context.Instance;
			var ecPrivateKeysHex = new[] {
			"527b33ce0c67ec2cc12ba7bb2e48dda66884a5c4b6d110be894a10802b21b3d6",
			"54082c2ee51166cfa4fd8c3076ee30043808b3cca351e3288360af81d3ef9f8c",
			"cba536615bbe1ae2fdf8100104829db61c8cf2a7f0bd9a225cbf09e79d83096c"
			};
			
			var ecPrivateKeys = new ECPrivKey[ecPrivateKeysHex.Length];
			ECXOnlyPubKey? xonly;
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				var ec_pkey = NBitcoin.Secp256k1.ECPrivKey.Create(privateKeyBytes);
				xonly = ec_pkey.CreatePubKey().ToXOnlyPubKey();
				Console.WriteLine($"ec_pkey_xonly: {Encoders.Hex.EncodeData(xonly.ToBytes())}");
				
				ecPrivateKeys[i] = ctx.CreateECPrivKey(privateKeyBytes);
			}

			var privateKeys = new Key[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				privateKeys[i] = new Key(privateKeyBytes);
			}

			var peers = ecPrivateKeys.Length;
			TaprootPubKey taprootPubKey = null;



			// XOnly pubKey
			var ecPubKeys = ecPrivateKeys.Select(c => c.CreateXOnlyPubKey()).ToArray();
			// pubKeys (compressd)
			//var ecPubKeys = ecPrivateKeys.Select(c => c.CreatePubKey()).ToArray();


			var howManyScripts = 3;
			var Scripts = new TapScript[howManyScripts];
			Scripts[0] = new Script(Op.GetPushOp(ecPubKeys[1].ToBytes()), OpcodeType.OP_CHECKSIG, Op.GetPushOp(ecPubKeys[2].ToBytes()), OpcodeType.OP_CHECKSIGADD, OpcodeType.OP_2, OpcodeType.OP_NUMEQUAL).ToTapScript(TapLeafVersion.C0);
			Scripts[1] = new Script(Op.GetPushOp(ecPubKeys[0].ToBytes()), OpcodeType.OP_CHECKSIG, Op.GetPushOp(ecPubKeys[1].ToBytes()), OpcodeType.OP_CHECKSIGADD, OpcodeType.OP_2, OpcodeType.OP_NUMEQUAL).ToTapScript(TapLeafVersion.C0);
			Scripts[2] = new Script(Op.GetPushOp(ecPubKeys[0].ToBytes()), OpcodeType.OP_CHECKSIG, Op.GetPushOp(ecPubKeys[2].ToBytes()), OpcodeType.OP_CHECKSIGADD, OpcodeType.OP_2, OpcodeType.OP_NUMEQUAL).ToTapScript(TapLeafVersion.C0);



			var scriptWeightsList = new List<(UInt32, TapScript)>
			{
				(30u, Scripts[0]),
				(30u, Scripts[1]),
				(30u, Scripts[2])
			};

			var scriptWeights = scriptWeightsList.ToArray();


			var keySpend = new Key(Encoders.Hex.DecodeData("c0655fae21a8b7fae19cfeac6135ded8090920f9640a148b0fd5ff9c15c6e948"));
			var KeySpendinternalPubKey = keySpend.PubKey.TaprootInternalKey;
			var treeInfo = TaprootSpendInfo.WithHuffmanTree(KeySpendinternalPubKey, scriptWeights);


			taprootPubKey = treeInfo.OutputPubKey.OutputKey;
			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{
				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(nodeBuilder.Network.Consensus.CoinbaseMaturity + 1);

				var addr = taprootPubKey.GetAddress(Network.RegTest);

				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));

				var tx = rpc.GetRawTransaction(txid);


				var psbt = PSBT.FromTransaction(tx, Network.RegTest);
				Console.WriteLine($"PSBT from transaction: {psbt.ToString()}");



				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == addr.ScriptPubKey);
				var dest = rpc.GetNewAddress();

				var sighash = TaprootSigHash.All | TaprootSigHash.AnyoneCanPay;
				var spentOutputsIn = new[] { spentOutput.TxOut };
				TaprootExecutionData extectionData;


				////////////////// FIRST PASS in order to calculate the vSize

				var spender = nodeBuilder.Network.CreateTransaction();
				spender.Inputs.Add(new OutPoint(tx, spentOutput.N));

				decimal trn_fee = 0.00000000m;
				spender.Outputs.Add(Money.Coins(0.99999900m - trn_fee), dest);


				var useKeySpend = false;
				// ADDRESS PATH
				if (useKeySpend)
					extectionData = new TaprootExecutionData(0) { SigHash = sighash };
				else
					extectionData = new TaprootExecutionData(0, Scripts[2].LeafHash) { SigHash = sighash };

				var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);

				if (useKeySpend)
				{
					var sig = keySpend.SignTaprootKeySpend(hash, treeInfo.MerkleRoot, sighash);
					spender.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig.ToBytes()));
				}
				else
				{
					// use this signatures if XOnly pubKey
					var sig11 = privateKeys[0].SignTaprootScriptSpend(hash, sighash);
					var sig22 = privateKeys[2].SignTaprootScriptSpend(hash, sighash);
					spender.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig22.ToBytes()), Op.GetPushOp(sig11.ToBytes()), Op.GetPushOp(Scripts[2].Script.ToBytes()), Op.GetPushOp(treeInfo.GetControlBlock(Scripts[2]).ToBytes()));

				}

				var validator = spender.CreateValidator(new[] { spentOutput.TxOut });
				var result = validator.ValidateInput(0);
				Console.WriteLine(spender.ToString());
				Console.WriteLine($"verify first run? {result.Error is null}");


				////////////////// SECOND PASS 

				var spender2 = Transaction.Create(Network.RegTest);
				spender2.Inputs.Add(new OutPoint(tx, spentOutput.N));

				//trn_fee = 0.00000200m;
				trn_fee = 0.00000000m;
				spender2.Outputs.Add(Money.Coins(0.99999900m - trn_fee), dest);


				//var useKeySpend = false;
				// ADDRESS PATH
				if (useKeySpend)
					extectionData = new TaprootExecutionData(0) { SigHash = sighash };
				else
					extectionData = new TaprootExecutionData(0, Scripts[2].LeafHash) { SigHash = sighash };

				hash = spender2.GetSignatureHashTaproot(spentOutputsIn, extectionData);


				if (useKeySpend)
				{
					var sig = keySpend.SignTaprootKeySpend(hash, treeInfo.MerkleRoot, sighash);
					spender2.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig.ToBytes()));
				}
				else
				{
					// use this signatures if XOnly pubKey
					var sig11 = privateKeys[0].SignTaprootScriptSpend(hash, sighash);
					var sig22 = privateKeys[2].SignTaprootScriptSpend(hash, sighash);
					spender2.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig22.ToBytes()), Op.GetPushOp(sig11.ToBytes()), Op.GetPushOp(Scripts[2].Script.ToBytes()), Op.GetPushOp(treeInfo.GetControlBlock(Scripts[2]).ToBytes()));

				}

				var validator2 = spender2.CreateValidator(new[] { spentOutput.TxOut });
				var result2 = validator2.ValidateInput(0);
				Console.WriteLine(spender2.ToString());
				Console.WriteLine($"verify second run? {result2.Error is null}");
				PSBT psbt2 = PSBT.FromTransaction(spender2, Network.RegTest);
				Console.WriteLine($"PSBT: {psbt2.ToString()}"); // no muestra los witness




				//rpc.SendRawTransaction(spender2);

			}
		}

		static void musig_address_and_path_spend_with_huffman()
		{
			var ctx = Context.Instance;

			var strmasterPubKeys = new[] {
					"tpubDEZUvCj2FMcaNc2VEmHhn9CEC7wjtoRz7uYX4jnn6hFbyVedNH4kwyY3rBdrtQmbFR7Qp4Q2VhCGsCs8PBqPReg8qH9ZTnLd4PDXL7kuoXK",
					"tpubDEbZ8cJoHhNMXYXCoCCqag11kckQxoY81sbC88Samp5ov8eRGTSZgrCfHysRo8zVf1PgyyHf3UFLAmf7kXm2FSswcs2jcXuZa8PRzjq1k4X",
					"tpubDFTd5FohLoP3ZAWyixHgvgbdCGxaPdsXRUjUeQpiE2C7o4bxBvqXz5pfq2MstMrxHVc7AeauFH3DatEjtdL7VnDXBcnm3YcrHQuQe4j1BUF"
					};

			var masterPubKeys = new ExtPubKey[strmasterPubKeys.Length];
			for (int i = 0; i < strmasterPubKeys.Length; i++)
			{
				var tempMasterKey = ExtPubKey.Parse(strmasterPubKeys[i], Network.RegTest);
				var keyPath = new NBitcoin.KeyPath("/2");
				var tempMasterKey2 = tempMasterKey.Derive(keyPath);
				masterPubKeys[i] = tempMasterKey2;
				Console.WriteLine($"masterPubKey internalTaproot: [{i}] {masterPubKeys[i].PubKey.TaprootInternalKey.ToString()}");
				Console.WriteLine($"masterPubKey taproot Full: [{i}]  {masterPubKeys[i].PubKey.GetTaprootFullPubKey().ToString()}");
				Console.WriteLine($"masterPubKey EC pubkey: [{i}]  {masterPubKeys[i].PubKey.ToString()}");
			}

			var ecPrivateKeysHex = new[] {
			"3258b375bcde67853dff6b3963b8c82eb859cedd8c48f3d2897605c324c42681",
			"409c1d0454a1ebe4b781e1c9873aa3bc70bbf16456382bd707ee96c9e43656c1",
			"bbc167fe9f0fc8429996296a2c048f2094e3440ff830256d3b7a6464b96c128c"
			};

			var ecPrivateKeys = new ECPrivKey[ecPrivateKeysHex.Length];
			var ecPubKeys = new ECXOnlyPubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				ecPrivateKeys[i] = ctx.CreateECPrivKey(privateKeyBytes);
				Console.WriteLine($"PubKey from ecPrivatekey [{i}]: {Encoders.Hex.EncodeData(ecPrivateKeys[i].CreatePubKey().ToBytes())}");
				Console.WriteLine($"XOnlyPubKey from ecPrivatekey [{i}]: {Encoders.Hex.EncodeData(ecPrivateKeys[i].CreateXOnlyPubKey().ToBytes())}");
				ecPubKeys[i] = ecPrivateKeys[i].CreateXOnlyPubKey();
				Console.WriteLine($"ecPubKeys[{i}]  {Encoders.Hex.EncodeData(ecPubKeys[i].ToBytes()).ToString()}");
			}

			var privateKeys = new Key[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				privateKeys[i] = new Key(privateKeyBytes);
				Console.WriteLine($"PubKeys[{i}]  {Encoders.Hex.EncodeData(privateKeys[i].PubKey.ToBytes()).ToString()}");
			}

			var peers = ecPrivateKeys.Length;
			TaprootPubKey taprootPubKey = null;


			var howManyScripts = 3;
			var Scripts = new TapScript[howManyScripts];
			Scripts[0] = new Script(Op.GetPushOp(ecPubKeys[1].ToBytes()), OpcodeType.OP_CHECKSIG, Op.GetPushOp(ecPubKeys[2].ToBytes()), OpcodeType.OP_CHECKSIGADD, OpcodeType.OP_2, OpcodeType.OP_NUMEQUAL).ToTapScript(TapLeafVersion.C0);
			Scripts[1] = new Script(Op.GetPushOp(ecPubKeys[0].ToBytes()), OpcodeType.OP_CHECKSIG, Op.GetPushOp(ecPubKeys[1].ToBytes()), OpcodeType.OP_CHECKSIGADD, OpcodeType.OP_2, OpcodeType.OP_NUMEQUAL).ToTapScript(TapLeafVersion.C0);
			Scripts[2] = new Script(Op.GetPushOp(ecPubKeys[0].ToBytes()), OpcodeType.OP_CHECKSIG, Op.GetPushOp(ecPubKeys[2].ToBytes()), OpcodeType.OP_CHECKSIGADD, OpcodeType.OP_2, OpcodeType.OP_NUMEQUAL).ToTapScript(TapLeafVersion.C0);



			var scriptWeightsList = new List<(UInt32, TapScript)>();
			scriptWeightsList.Add((30u, Scripts[0]));
			scriptWeightsList.Add((30u, Scripts[1]));
			scriptWeightsList.Add((30u, Scripts[2]));

			var scriptWeights = scriptWeightsList.ToArray();

			//var scriptWeights = scriptWeightsList.Select(t => (t.Item1, t.Item2)).ToArray();




			// Create a tree as shown below
			// For example, imagine this tree:
			// pubKey_1_to_2 is at depth 1 meanting pubKey0_to_1 and pubKey0_to_2 are at depth 2
			//                                       .....
			//                                     /       \
			//                                    /\       pubKey_1_to_2
			//                                   /  \       
			//                                  /    \
			//                                 /      \
			//                        pubKey0_to_1   pubKey0_to_2         

			var keySpend = new Key(Encoders.Hex.DecodeData("b992ad17a418202f7824eb55bdc2125e4133c7f3f09a4978e964b38ff7765a8c"));
			var KeySpendinternalPubKey = keySpend.PubKey.TaprootInternalKey;



			//KeySpendinternalPubKey.ComputeTapTweak(aggregatedKey.ToXOnlyPubKey().ToBytes());
			var treeInfo = TaprootSpendInfo.WithHuffmanTree(KeySpendinternalPubKey, scriptWeights);
			//var treeInfo = builder.Finalize(KeySpendinternalPubKey);

			//var treeInfo = builder.Finalize(new TaprootInternalPubKey(aggregatedKey.ToXOnlyPubKey().ToBytes()));


			taprootPubKey = treeInfo.OutputPubKey.OutputKey;


			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{



				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				var addr = taprootPubKey.GetAddress(Network.RegTest);

				rpc.Generate(1);


				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));

				var tx = rpc.GetRawTransaction(txid);
				var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == addr.ScriptPubKey);

				var spender = nodeBuilder.Network.CreateTransaction();
				spender.Inputs.Add(new OutPoint(tx, spentOutput.N));

				var dest = rpc.GetNewAddress();
				spender.Outputs.Add(Money.Coins(0.7m), dest);
				spender.Outputs.Add(Money.Coins(0.2999000m), addr);


				var sighash = TaprootSigHash.All | TaprootSigHash.AnyoneCanPay;

				var spentOutputsIn = new[] { spentOutput.TxOut };


				TaprootExecutionData extectionData;



				Boolean useKeySpend = true;
				if (useKeySpend)
				{
					extectionData = new TaprootExecutionData(0) { SigHash = sighash };
					var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
					var sig = keySpend.SignTaprootKeySpend(hash, treeInfo.MerkleRoot, sighash);
					spender.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig.ToBytes()));
				}
				else
				{
					extectionData = new TaprootExecutionData(0, Scripts[2].LeafHash) { SigHash = sighash };
					var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
					// use this signatures if XOnly pubKey
					var sig11 = privateKeys[0].SignTaprootScriptSpend(hash, sighash);
					var sig22 = privateKeys[2].SignTaprootScriptSpend(hash, sighash);
					// signatures go in reverse order of the pubKeys in script
					spender.Inputs[0].WitScript = new WitScript(Op.GetPushOp(sig22.ToBytes()), Op.GetPushOp(sig11.ToBytes()), Op.GetPushOp(Scripts[2].Script.ToBytes()), Op.GetPushOp(treeInfo.GetControlBlock(Scripts[2]).ToBytes()));

				}


				// COMMON

				Console.WriteLine(spender.ToString());
				var validator = spender.CreateValidator(new[] { spentOutput.TxOut });
				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
				Console.WriteLine("to hex: " + spender.ToHex().ToString());
				var result = validator.ValidateInput(0);
				var success = result.Error is null;
				Console.WriteLine("does validate witness? " + success);
				rpc.SendRawTransaction(spender);



			}
		}




		static void musig_matching_dc()
		{
			var ctx = Context.Instance;


			var strmasterPubKeys = new[] {
					"tpubDEZUvCj2FMcaNc2VEmHhn9CEC7wjtoRz7uYX4jnn6hFbyVedNH4kwyY3rBdrtQmbFR7Qp4Q2VhCGsCs8PBqPReg8qH9ZTnLd4PDXL7kuoXK",
					"tpubDEbZ8cJoHhNMXYXCoCCqag11kckQxoY81sbC88Samp5ov8eRGTSZgrCfHysRo8zVf1PgyyHf3UFLAmf7kXm2FSswcs2jcXuZa8PRzjq1k4X",
					"tpubDFTd5FohLoP3ZAWyixHgvgbdCGxaPdsXRUjUeQpiE2C7o4bxBvqXz5pfq2MstMrxHVc7AeauFH3DatEjtdL7VnDXBcnm3YcrHQuQe4j1BUF"
					};

			var masterPubKeys =new ExtPubKey[strmasterPubKeys.Length];
			for (int i = 0; i < strmasterPubKeys.Length; i++)
			{
				var tempMasterKey = ExtPubKey.Parse(strmasterPubKeys[i], Network.RegTest);
				var keyPath = new NBitcoin.KeyPath("/2");
				var tempMasterKey2 = tempMasterKey.Derive(keyPath);
				masterPubKeys[i] = tempMasterKey2;
				Console.WriteLine($"masterPubKey internalTaproot: [{i}] { masterPubKeys[i].PubKey.TaprootInternalKey.ToString()}");
				Console.WriteLine($"masterPubKey taproot Full: [{i}]  { masterPubKeys[i].PubKey.GetTaprootFullPubKey().ToString()}");
				Console.WriteLine($"masterPubKey EC pubkey: [{i}]  {masterPubKeys[i].PubKey.ToString()}");
			}

			var ecPrivateKeysHex = new[] {
			"3258b375bcde67853dff6b3963b8c82eb859cedd8c48f3d2897605c324c42681",
			"409c1d0454a1ebe4b781e1c9873aa3bc70bbf16456382bd707ee96c9e43656c1",
			"bbc167fe9f0fc8429996296a2c048f2094e3440ff830256d3b7a6464b96c128c"
			};

			var ecPrivateKeys = new ECPrivKey[ecPrivateKeysHex.Length];
			var ecPubKeys = new ECXOnlyPubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				ecPrivateKeys[i] = ctx.CreateECPrivKey(privateKeyBytes);
				Console.WriteLine($"PubKey from ecPrivatekey [{i}]: {Encoders.Hex.EncodeData(ecPrivateKeys[i].CreatePubKey().ToBytes())}");
				Console.WriteLine($"XOnlyPubKey from ecPrivatekey [{i}]: {Encoders.Hex.EncodeData(ecPrivateKeys[i].CreateXOnlyPubKey().ToBytes())}");
				ecPubKeys[i] = ecPrivateKeys[i].CreateXOnlyPubKey();
				Console.WriteLine($"ecPubKeys[{i}]  {Encoders.Hex.EncodeData(ecPubKeys[i].ToBytes()).ToString()}");
				var xonlypubk = NBitcoin.Secp256k1.ECPubKey.Create(NBitcoin.DataEncoders.Encoders.Hex.DecodeData(masterPubKeys[i].PubKey.ToString())).ToXOnlyPubKey();
				Console.WriteLine($"xonlyPubkey from masterpubkey[{i}]  {Encoders.Hex.EncodeData(xonlypubk.ToBytes()).ToString()}");
			}

			var privateKeys = new Key[ecPrivateKeysHex.Length];
			var pubKeys = new PubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				privateKeys[i] = new Key(privateKeyBytes);
				pubKeys[i] = privateKeys[i].PubKey;
				Console.WriteLine($"PubKeys[{i}]  {Encoders.Hex.EncodeData(privateKeys[i].PubKey.ToBytes()).ToString()}");
			}

			var peers = ecPrivateKeys.Length;
			TaprootPubKey taprootPubKey = null;



			var howManyScripts = 3;
			var probability = (uint)(100 / howManyScripts);
			var scriptWeightsList = new List<(UInt32, TapScript)>();
			var Scripts = new TapScript[howManyScripts];
			List<NBitcoin.Op> ops = new List<NBitcoin.Op>();


			// ADD the 3 tap scripts
			// each is a 2-of-2 MuSig1 tapscript

			ops.Clear();
			ops.Add(Op.GetPushOp(ecPubKeys[0].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIG);
			ops.Add(Op.GetPushOp(ecPubKeys[2].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIGADD);
			ops.Add(OpcodeType.OP_2);
			ops.Add(OpcodeType.OP_NUMEQUAL);
			Scripts[0] = new NBitcoin.Script(ops).ToTapScript(NBitcoin.TapLeafVersion.C0);
			Console.WriteLine("Script[0]: " + Scripts[0].ToString());
			scriptWeightsList.Add((probability, Scripts[0]));

			ops.Clear();
			ops.Add(Op.GetPushOp(ecPubKeys[0].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIG);
			ops.Add(Op.GetPushOp(ecPubKeys[1].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIGADD);
			ops.Add(OpcodeType.OP_2);
			ops.Add(OpcodeType.OP_NUMEQUAL);
			Scripts[1] = new Script(ops).ToTapScript(TapLeafVersion.C0);
			Console.WriteLine("Script[1]: " + Scripts[1].ToString());
			scriptWeightsList.Add((probability, Scripts[1]));

			ops.Clear();
			ops.Add(Op.GetPushOp(ecPubKeys[1].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIG);
			ops.Add(Op.GetPushOp(ecPubKeys[2].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIGADD);
			ops.Add(OpcodeType.OP_2);
			ops.Add(OpcodeType.OP_NUMEQUAL);
			Scripts[2] = new Script(ops).ToTapScript(TapLeafVersion.C0);
			Console.WriteLine("Script[2]: " + Scripts[2].ToString());
			scriptWeightsList.Add((probability, Scripts[2]));


			var scriptWeights = scriptWeightsList.ToArray();


			var all_keys = new System.Collections.Generic.List<NBitcoin.Key>();

			var keySpend = new Key(Encoders.Hex.DecodeData("b992ad17a418202f7824eb55bdc2125e4133c7f3f09a4978e964b38ff7765a8c"));

			// add twice because I'm processing to TxIns
			all_keys.Add(keySpend);
			//all_keys.Add(keySpend);

			var KeySpendinternalPubKey = keySpend.PubKey.TaprootInternalKey;

			var AllTreeInfo = new System.Collections.Generic.List<NBitcoin.TaprootSpendInfo>();


			NBitcoin.TaprootSpendInfo treeInfo;
			treeInfo = TaprootSpendInfo.WithHuffmanTree(KeySpendinternalPubKey, scriptWeights);

			// add twice because I'm processing to TxIns
			AllTreeInfo.Add(treeInfo);
			//AllTreeInfo.Add(treeInfo);


			taprootPubKey = treeInfo.OutputPubKey.OutputKey;



			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{



				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				var addr = taprootPubKey.GetAddress(Network.RegTest);
				Console.WriteLine("Address to send: " + addr.ToString());

				rpc.Generate(1);


				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));
				//var txid2 = rpc.SendToAddress(addr, Money.Coins(2.0m));

				var tx = rpc.GetRawTransaction(txid);
				//var tx2 = rpc.GetRawTransaction(txid2);
				//var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == addr.ScriptPubKey);

				var spender = nodeBuilder.Network.CreateTransaction();

				//NBitcoin.IndexedTxOut spentOutput = null;
				var spentAllOutputsIn = new List<NBitcoin.TxOut>();
				foreach (var output in tx.Outputs.AsIndexedOutputs())
				{
					if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
					{
						spender.Inputs.Add(new OutPoint(tx, output.N));
						spentAllOutputsIn.Add(output.TxOut);
						break; // Break out of the loop since you found the desired item
					}
				}

				//foreach (var output in tx2.Outputs.AsIndexedOutputs())
				//{
				//	if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
				//	{
				//		spender.Inputs.Add(new NBitcoin.OutPoint(tx2, output.N));
				//		spentAllOutputsIn.Add(output.TxOut);
				//		break; // Break out of the loop since you found the desired item
				//	}
				//}


				NBitcoin.TxOut[] spentOutputsIn = spentAllOutputsIn.ToArray();



				var dest = rpc.GetNewAddress();
				//spender.Outputs.Add(NBitcoin.Money.Coins(0.7m), dest);
				//spender.Outputs.Add(NBitcoin.Money.Coins(0.2999000m), addr);
				spender.Outputs.Add(NBitcoin.Money.Coins(0.99999830m), addr); // fee 170 satoshis = vSize


				var sighash = NBitcoin.TaprootSigHash.All | NBitcoin.TaprootSigHash.AnyoneCanPay;



				var allkeysarray = all_keys.ToArray();
				var allTreeInfoArray = AllTreeInfo.ToArray();

				////////////////////////
				///
				TaprootExecutionData extectionData;


				Boolean useKeySpend = false;
				if (useKeySpend)
				{
					// ADDRESS PATH

					for (int i = 0; i < spender.Inputs.Count; i++)
					{

						extectionData = new TaprootExecutionData(0) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
						var sig = keySpend.SignTaprootKeySpend(hash, allTreeInfoArray[i].MerkleRoot, sighash);
						spender.Inputs[i].WitScript = new NBitcoin.WitScript(NBitcoin.Op.GetPushOp(sig.ToBytes()));
					}
				}
				else
				{
					var min_num_signatures = 2;
					var sigs = new TaprootSignature[min_num_signatures];
					for (int i = 0; i < spender.Inputs.Count; i++)
					{


						extectionData = new TaprootExecutionData(0, Scripts[0].LeafHash) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
						// use this signatures if XOnly pubKey
						var sig11 = privateKeys[0].SignTaprootScriptSpend(hash, sighash);
						var strSig = Encoders.Hex.EncodeData(sig11.ToBytes()).ToString();
						sigs[0] = TaprootSignature.Parse(strSig);
						var sig22 = privateKeys[2].SignTaprootScriptSpend(hash, sighash);
						strSig = Encoders.Hex.EncodeData(sig22.ToBytes()).ToString();
						sigs[1] = TaprootSignature.Parse(strSig);
						// signatures go in reverse order of the pubKeys in script
						ops.Clear();

						for (var r = min_num_signatures - 1; r >= 0; r--)
						{
							ops.Add(Op.GetPushOp(sigs[r].ToBytes()));
							Console.WriteLine($"Signature[{r}] {sigs[r].ToString()}");
						}


						ops.Add(Op.GetPushOp(Scripts[0].Script.ToBytes()));
						ops.Add(Op.GetPushOp(allTreeInfoArray[i].GetControlBlock(Scripts[0]).ToBytes()));
						Console.WriteLine($"Script[{0}]: {Scripts[0].Script}");
						spender.Inputs[i].WitScript = new WitScript(ops.ToArray());


						Console.WriteLine("witness: " + spender.Inputs[i].WitScript.ToString());


					}
				}



				// COMMON




				Console.WriteLine(spender.ToString());
				var validator = spender.CreateValidator(spentOutputsIn);
				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
				Console.WriteLine("to hex: " + spender.ToHex().ToString());
				var result = validator.ValidateInput(0);
				var success = result.Error is null;
				Console.WriteLine("does validate witness? " + success);

				InputValidationResult[] resullts = validator.ValidateInputs();
				for ( int i = 0; i < resullts.Length; i++)
				{
					var success3 = resullts[i].Error is null;
					Console.WriteLine($"does validate witness? [{i}] " + success3);
				}

				var spender_transaction = Transaction.Parse("010000000001018a42aea2a23348236e0ced4104fba99f2c0a31c2bb72b53627c6a1550f32dbd70000000000ffffffff0156e0f50500000000225120e78c5abab86f0746163f58b7b2cd54bc8e9680cf3989a53800a8abeea9b8795e044151772e305ff3a3da335f9d4e5aaacf904bf75f82ee694ca09ea98a159c97ddcbf21aff3ae050a566143679d1d086328a65b838ebff7b2189499f9f531c7c7ac18141190f12b47d58c8b25cb787641380294280197bdc283756db8b334ffe297eb3f5e6aefb8577fabc67e6526dfed75b37fbe6dc60d71a496cdee13bfef901a5ef0681462049d82fdecefb6702790f302c07e068ad1713bae587511841cf893c3696497121ac20a6b41a37e29b4b0a8865acc62fe5cf93d71cbca3767053c698f9cb45789f86f8ba529c61c18b9be837bde24e1284b4e405ec399fe9cb7f1be7ce27de060e13e88428f997157bd2225d7288c21b35e59b4a18961b0b416592e6c8c093e4a69a417444fbb90e0698f6467795a02db71920420f69f832452aef83237001f3243e446174f407f600000000",Network.RegTest); // from genexus
				var validator2 = spender_transaction.CreateValidator(spentOutputsIn);
				var result2 = validator2.ValidateInput(0);
				var success2 = result2.Error is null;
				Console.WriteLine("does validate witness2? " + success2);
				//rpc.SendRawTransaction(spender);


			}
		}






		static void musig_matching_dc2()
		{


			var strmasterPubKeys = new[] {
					"tpubDEZUvCj2FMcaNc2VEmHhn9CEC7wjtoRz7uYX4jnn6hFbyVedNH4kwyY3rBdrtQmbFR7Qp4Q2VhCGsCs8PBqPReg8qH9ZTnLd4PDXL7kuoXK",
					"tpubDEbZ8cJoHhNMXYXCoCCqag11kckQxoY81sbC88Samp5ov8eRGTSZgrCfHysRo8zVf1PgyyHf3UFLAmf7kXm2FSswcs2jcXuZa8PRzjq1k4X",
					"tpubDFTd5FohLoP3ZAWyixHgvgbdCGxaPdsXRUjUeQpiE2C7o4bxBvqXz5pfq2MstMrxHVc7AeauFH3DatEjtdL7VnDXBcnm3YcrHQuQe4j1BUF"
					};

			var masterPubKeys = new ExtPubKey[strmasterPubKeys.Length];
			for (int i = 0; i < strmasterPubKeys.Length; i++)
			{
				var tempMasterKey = ExtPubKey.Parse(strmasterPubKeys[i], Network.RegTest);
				var keyPath = new NBitcoin.KeyPath("/2");
				var tempMasterKey2 = tempMasterKey.Derive(keyPath);
				masterPubKeys[i] = tempMasterKey2;
				Console.WriteLine($"masterPubKey internalTaproot: [{i}] {masterPubKeys[i].PubKey.TaprootInternalKey.ToString()}");
				Console.WriteLine($"masterPubKey taproot Full: [{i}]  {masterPubKeys[i].PubKey.GetTaprootFullPubKey().ToString()}");
				Console.WriteLine($"masterPubKey EC pubkey: [{i}]  {masterPubKeys[i].PubKey.ToString()}");
			}

			var ecPrivateKeysHex = new[] {
			"3258b375bcde67853dff6b3963b8c82eb859cedd8c48f3d2897605c324c42681",
			"409c1d0454a1ebe4b781e1c9873aa3bc70bbf16456382bd707ee96c9e43656c1",
			"bbc167fe9f0fc8429996296a2c048f2094e3440ff830256d3b7a6464b96c128c"
			};

			var ecPubKeys = new ECXOnlyPubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				ecPubKeys[i] = NBitcoin.Secp256k1.ECPubKey.Create(NBitcoin.DataEncoders.Encoders.Hex.DecodeData(masterPubKeys[i].PubKey.ToString())).ToXOnlyPubKey();
				Console.WriteLine($"ecPubKeys[{i}]  {Encoders.Hex.EncodeData(ecPubKeys[i].ToBytes()).ToString()}");

			}

			var all_keys = new System.Collections.Generic.List<NBitcoin.Key>();

			var privateKeys = new Key[ecPrivateKeysHex.Length];
			var pubKeys = new PubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				privateKeys[i] = new Key(privateKeyBytes);
				all_keys.Add(privateKeys[i]);
				pubKeys[i] = privateKeys[i].PubKey;
				Console.WriteLine($"PubKeys[{i}]  {Encoders.Hex.EncodeData(privateKeys[i].PubKey.ToBytes()).ToString()}");
			}

			var peers = ecPrivateKeysHex.Length;
			TaprootPubKey taprootPubKey = null;



			var howManyScripts = 3;
			var probability = (uint)(100 / howManyScripts);
			var scriptWeightsList = new List<(UInt32, TapScript)>();
			var Scripts = new TapScript[howManyScripts];
			List<NBitcoin.Op> ops = new List<NBitcoin.Op>();


			// ADD the 3 tap scripts
			// each is a 2-of-2 MuSig1 tapscript

			ops.Clear();
			ops.Add(Op.GetPushOp(ecPubKeys[0].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIG);
			ops.Add(Op.GetPushOp(ecPubKeys[2].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIGADD);
			ops.Add(OpcodeType.OP_2);
			ops.Add(OpcodeType.OP_NUMEQUAL);
			Scripts[0] = new NBitcoin.Script(ops).ToTapScript(NBitcoin.TapLeafVersion.C0);
			Console.WriteLine("Script[0]: " + Scripts[0].ToString());
			scriptWeightsList.Add((probability, Scripts[0]));

			ops.Clear();
			ops.Add(Op.GetPushOp(ecPubKeys[0].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIG);
			ops.Add(Op.GetPushOp(ecPubKeys[1].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIGADD);
			ops.Add(OpcodeType.OP_2);
			ops.Add(OpcodeType.OP_NUMEQUAL);
			Scripts[1] = new Script(ops).ToTapScript(TapLeafVersion.C0);
			Console.WriteLine("Script[1]: " + Scripts[1].ToString());
			scriptWeightsList.Add((probability, Scripts[1]));

			ops.Clear();
			ops.Add(Op.GetPushOp(ecPubKeys[1].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIG);
			ops.Add(Op.GetPushOp(ecPubKeys[2].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIGADD);
			ops.Add(OpcodeType.OP_2);
			ops.Add(OpcodeType.OP_NUMEQUAL);
			Scripts[2] = new Script(ops).ToTapScript(TapLeafVersion.C0);
			Console.WriteLine("Script[2]: " + Scripts[2].ToString());
			scriptWeightsList.Add((probability, Scripts[2]));


			var scriptWeights = scriptWeightsList.ToArray();


			var keySpend = new Key(Encoders.Hex.DecodeData("b992ad17a418202f7824eb55bdc2125e4133c7f3f09a4978e964b38ff7765a8c"));

			// add twice because I'm processing to TxIns
			// all_keys.Add(keySpend); // im adding the private key for each taproot 
			//all_keys.Add(keySpend);

			var KeySpendinternalPubKey = keySpend.PubKey.TaprootInternalKey;

			var AllTreeInfo = new System.Collections.Generic.List<NBitcoin.TaprootSpendInfo>();


			NBitcoin.TaprootSpendInfo treeInfo;
			treeInfo = TaprootSpendInfo.WithHuffmanTree(KeySpendinternalPubKey, scriptWeights);

			// add twice because I'm processing to TxIns
			AllTreeInfo.Add(treeInfo);
			//AllTreeInfo.Add(treeInfo);


			taprootPubKey = treeInfo.OutputPubKey.OutputKey;



			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{



				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				var addr = taprootPubKey.GetAddress(Network.RegTest);
				Console.WriteLine("Address to send: " + addr.ToString());

				rpc.Generate(1);


				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));
				//var txid2 = rpc.SendToAddress(addr, Money.Coins(2.0m));

				var tx = rpc.GetRawTransaction(txid);
				Console.WriteLine("input transaction: " +tx.ToString());
				//var tx2 = rpc.GetRawTransaction(txid2);
				//var spentOutput = tx.Outputs.AsIndexedOutputs().First(o => o.TxOut.ScriptPubKey == addr.ScriptPubKey);

				var spender = Transaction.Create(Network.RegTest);

				//NBitcoin.IndexedTxOut spentOutput = null;
				var spentAllOutputsIn = new List<NBitcoin.TxOut>();
				foreach (var output in tx.Outputs.AsIndexedOutputs())
				{
					if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
					{
						spender.Inputs.Add(new OutPoint(tx, output.N));
						spentAllOutputsIn.Add(output.TxOut);
						break; // Break out of the loop since you found the desired item
					}
				}

				//foreach (var output in tx2.Outputs.AsIndexedOutputs())
				//{
				//	if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
				//	{
				//		spender.Inputs.Add(new NBitcoin.OutPoint(tx2, output.N));
				//		spentAllOutputsIn.Add(output.TxOut);
				//		break; // Break out of the loop since you found the desired item
				//	}
				//}


				NBitcoin.TxOut[] spentOutputsIn = spentAllOutputsIn.ToArray();



				var dest = rpc.GetNewAddress();
				//spender.Outputs.Add(NBitcoin.Money.Coins(0.7m), dest);
				//spender.Outputs.Add(NBitcoin.Money.Coins(0.2999000m), addr);
				spender.Outputs.Add(NBitcoin.Money.Coins(0.99999830m), addr); // fee 170 satoshis = vSize


				var sighash = NBitcoin.TaprootSigHash.All | NBitcoin.TaprootSigHash.AnyoneCanPay;



				var allkeysarray = all_keys.ToArray();
				var allTreeInfoArray = AllTreeInfo.ToArray();

				////////////////////////
				///
				TaprootExecutionData extectionData;


				Boolean useKeySpend = false;
				if (useKeySpend)
				{
					// ADDRESS PATH

					for (int i = 0; i < spender.Inputs.Count; i++)
					{

						extectionData = new TaprootExecutionData(0) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
						var sig = keySpend.SignTaprootKeySpend(hash, allTreeInfoArray[i].MerkleRoot, sighash);
						spender.Inputs[i].WitScript = new NBitcoin.WitScript(NBitcoin.Op.GetPushOp(sig.ToBytes()));
					}
				}
				else
				{

					var min_num_signatures = 2;
					var sigs = new TaprootSignature[min_num_signatures];
					for (int i = 0; i < spender.Inputs.Count; i++)
					{


						extectionData = new TaprootExecutionData(0, Scripts[0].LeafHash) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
						// use this signatures if XOnly pubKey
						//var sig11 = privateKeys[0].SignTaprootScriptSpend(hash, sighash);
						var sig11 = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
						var strSig = Encoders.Hex.EncodeData(sig11.ToBytes()).ToString();
						sigs[0] = TaprootSignature.Parse(strSig);
						//var sig22 = privateKeys[2].SignTaprootScriptSpend(hash, sighash);
						var sig22 = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
						strSig = Encoders.Hex.EncodeData(sig22.ToBytes()).ToString();
						sigs[1] = TaprootSignature.Parse(strSig);
						// signatures go in reverse order of the pubKeys in script
						ops.Clear();

						for (var r = min_num_signatures - 1; r >= 0; r--)
						{
							ops.Add(Op.GetPushOp(sigs[r].ToBytes()));
							Console.WriteLine($"Signature[{r}] {sigs[r].ToString()}");
						}


						ops.Add(Op.GetPushOp(Scripts[0].Script.ToBytes()));
						ops.Add(Op.GetPushOp(allTreeInfoArray[i].GetControlBlock(Scripts[0]).ToBytes()));
						Console.WriteLine($"Script[{0}]: {Scripts[0].Script}");
						spender.Inputs[i].WitScript = new WitScript(ops.ToArray());


						Console.WriteLine("witness: " + spender.Inputs[i].WitScript.ToString());


					}
				}



				// COMMON



				Console.WriteLine(spender.ToString());
				var validator = spender.CreateValidator(spentOutputsIn);
				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
				Console.WriteLine("to hex: " + spender.ToHex().ToString());
				var result = validator.ValidateInput(0);
				var success = result.Error is null;
				Console.WriteLine("does validate witness? " + success);

				InputValidationResult[] resullts = validator.ValidateInputs();
				for (int i = 0; i < resullts.Length; i++)
				{
					var success3 = resullts[i].Error is null;
					Console.WriteLine($"does validate witness? [{i}] " + success3);
				}

				//rpc.SendRawTransaction(spender);


			}
		}


		static List<List<PubKey>> GenerateCombinations(List<PubKey> items, int combinationSize)
		{
			if (items == null || combinationSize <= 0 || combinationSize > items.Count)
				throw new ArgumentException("Invalid input: Ensure the list is not null and the combination size is valid.");

			var result = new List<List<PubKey>>();
			GenerateCombinationsRecursive(items, combinationSize, 0, new List<PubKey>(), result);
			return result;
		}

		static void GenerateCombinationsRecursive(List<PubKey> items, int combinationSize, int start, List<PubKey> current, List<List<PubKey>> result)
		{
			if (current.Count == combinationSize)
			{
				result.Add(new List<PubKey>(current));
				return;
			}

			for (int i = start; i < items.Count; i++)
			{
				current.Add(items[i]);
				GenerateCombinationsRecursive(items, combinationSize, i + 1, current, result);
				current.RemoveAt(current.Count - 1);
			}
		}

		static (List<(uint, TapScript)>, TaprootAddress) GenerateScriptPubKey(int sigCount, bool sort, Network network, PubKey owner, params PubKey[] keys)
		{
			if (keys == null)
				throw new ArgumentNullException(nameof(keys));
			if (owner == null)
				throw new ArgumentNullException(nameof(keys));
			if (sort)
				Array.Sort(keys);
			if (sigCount <= 1 || sigCount > 16)
				throw new ArgumentException("Invalid input: The number of signatures must be between 2 and 16.");

			List<List<PubKey>> combinations = new List<List<PubKey>>();

			try
			{
				combinations = GenerateCombinations(keys.ToList(), sigCount);
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error creating PubKey[] combination: {ex.Message}");
			}

			var peers = sigCount; // 3 per multisignature
			var howManyScripts = combinations.Count; // 5 combinations of 3 multisignatures
			var Scripts = new TapScript[howManyScripts];

			List<Op> ops = new List<Op>();
			var scriptWeightsList = new List<(UInt32, TapScript)>();
			var probability = (uint)(100 / howManyScripts);

			for (int i = 0; i < combinations.Count; i++)
			{
				ops.Clear();
				//Console.WriteLine($"Combination {i + 1}:");
				int p = 1;
				foreach (var pubKey in combinations[i])
				{
					//Console.WriteLine($"  {pubKey.ToString()}");
					var xonlypubk = ECPubKey.Create(Encoders.Hex.DecodeData(pubKey.ToString())).ToXOnlyPubKey();
					ops.Add(Op.GetPushOp(xonlypubk.ToBytes()));

					if ( p == combinations[i].Count )
					{
						ops.Add(OpcodeType.OP_CHECKSIGADD);
					}
					else
					{
						ops.Add(OpcodeType.OP_CHECKSIG);
					}
					p += 1;

				}

				switch (peers)
				{
					case 2:
						ops.Add(OpcodeType.OP_2);
						break;
					case 3:
						ops.Add(OpcodeType.OP_3);
						break;
					case 4:
						ops.Add(OpcodeType.OP_4);
						break;
					case 5:
						ops.Add(OpcodeType.OP_5);
						break;
					case 6:
						ops.Add(OpcodeType.OP_6);
						break;
					case 7:
						ops.Add(OpcodeType.OP_7);
						break;
					case 8:
						ops.Add(OpcodeType.OP_8);
						break;
					case 9:
						ops.Add(OpcodeType.OP_9);
						break;
					case 10:
						ops.Add(OpcodeType.OP_10);
						break;
					case 11:
						ops.Add(OpcodeType.OP_11);
						break;
					case 12:
						ops.Add(OpcodeType.OP_12);
						break;
					case 13:
						ops.Add(OpcodeType.OP_13);
						break;
					case 14:
						ops.Add(OpcodeType.OP_14);
						break;
					case 15:
						ops.Add(OpcodeType.OP_15);
						break;
					case 16:
						ops.Add(OpcodeType.OP_16);
						break;
				}
				ops.Add(OpcodeType.OP_NUMEQUAL);

				Scripts[i] = new Script(ops).ToTapScript(TapLeafVersion.C0);
				//Console.WriteLine($"Script[{i}]: {Scripts[i].ToString()}");
				scriptWeightsList.Add((probability, Scripts[i]));

			}

			var scriptWeights = scriptWeightsList.ToArray();
			var ec_PubKey = ECPubKey.Create(Encoders.Hex.DecodeData(owner.ToString()));
			var xOnlyFromPubkey = ec_PubKey.ToXOnlyPubKey();
			var tapIntFromEC = new TaprootInternalPubKey(xOnlyFromPubkey.ToBytes());
			var treeInfo = TaprootSpendInfo.WithHuffmanTree(tapIntFromEC, scriptWeights);
			var taprootPubKey = treeInfo.OutputPubKey.OutputKey;
			var addr = taprootPubKey.GetAddress(network);

			return(scriptWeightsList, addr);

		}
		static TaprootAddress GenerateScriptAddress(int sigCount, Network network, PubKey owner, params PubKey[] keys)
		{
			if (keys == null)
				throw new ArgumentNullException(nameof(keys));
			if (owner == null)
				throw new ArgumentNullException(nameof(keys));
			if (sigCount <= 1 || sigCount > 16)
				throw new ArgumentException("Invalid input: The number of signatures must be between 2 and 16.");

			var (scriptWeights, addr) = GenerateScriptPubKey(sigCount, true, network, owner, keys);

			return (addr);
		}

			static void musig_matching_3_of_5()
		{


			var strmasterPubKeys = new[] {
					"tpubDEZUvCj2FMcaNc2VEmHhn9CEC7wjtoRz7uYX4jnn6hFbyVedNH4kwyY3rBdrtQmbFR7Qp4Q2VhCGsCs8PBqPReg8qH9ZTnLd4PDXL7kuoXK",
					"tpubDEbZ8cJoHhNMXYXCoCCqag11kckQxoY81sbC88Samp5ov8eRGTSZgrCfHysRo8zVf1PgyyHf3UFLAmf7kXm2FSswcs2jcXuZa8PRzjq1k4X",
					"tpubDFTd5FohLoP3ZAWyixHgvgbdCGxaPdsXRUjUeQpiE2C7o4bxBvqXz5pfq2MstMrxHVc7AeauFH3DatEjtdL7VnDXBcnm3YcrHQuQe4j1BUF",
					"tpubDE5Bm64sjJXBXf4fTQT3JRnP3MPyaLN2X1vA5gmy4QdNoNSTxswqecEzUzBo2wKiHe49XsQZKdHFABkoWW4ZgQtgGPw7uGvhXK5WVbh3h9y",
					"tpubDEQgusD2c6KT17prVB1L9DxtGp26XfJuz3RYXvChN9TmZUm6zbdNaFbUXGuFwCWv3inFNnh45YVqM9WoVbGRU2QWdeaqF4TGt4tyxZwgdZ4"
					};

			var masterPubKeys = new ExtPubKey[strmasterPubKeys.Length];
			for (int i = 0; i < strmasterPubKeys.Length; i++)
			{
				var tempMasterKey = ExtPubKey.Parse(strmasterPubKeys[i], Network.RegTest);
				var keyPath = new NBitcoin.KeyPath("/3");
				var tempMasterKey2 = tempMasterKey.Derive(keyPath);
				masterPubKeys[i] = tempMasterKey2;
				Console.WriteLine($"masterPubKey internalTaproot: [{i}] {masterPubKeys[i].PubKey.TaprootInternalKey.ToString()}");
				Console.WriteLine($"masterPubKey taproot Full: [{i}]  {masterPubKeys[i].PubKey.GetTaprootFullPubKey().ToString()}");
				Console.WriteLine($"masterPubKey EC pubkey: [{i}]  {masterPubKeys[i].PubKey.ToString()}");
			}

			var ecPrivateKeysHex = new[] {
			"61c87e48b33e823283691e572f3ae95aa1bf71fff7c19a1173cc479ec0c2f871",
			"371c8d4f72e646e9208d04a14d135f2f2ca02c8cfd16cb69fa7f3ea29093dd94",
			"94bbe89a4878611960cbab784ad3b654e082d38079246111faf8a8eef56b96ae",
			"f9dca77a986f5f64beaaffcb2e06c46da86737b1877d0ff07b7c251c16f26d92",
			"6f2b793cc7ecc1f1cac8d7d9d9e13426b5fbf74496ca73a3bacaf025ba34713b"
			};

			var ecPubKeys = new ECXOnlyPubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				ecPubKeys[i] = NBitcoin.Secp256k1.ECPubKey.Create(NBitcoin.DataEncoders.Encoders.Hex.DecodeData(masterPubKeys[i].PubKey.ToString())).ToXOnlyPubKey();
				Console.WriteLine($"ecPubKeys[{i}]  {Encoders.Hex.EncodeData(ecPubKeys[i].ToBytes()).ToString()}");
				// ecPubkKyes are the same as masterPubKey internalTaproot from above

			}

			var all_keys = new List<NBitcoin.Key>();

			var privateKeys = new Key[ecPrivateKeysHex.Length];
			var pubKeys = new PubKey[ecPrivateKeysHex.Length];
			for (int i = 0; i < ecPrivateKeysHex.Length; i++)
			{
				byte[] privateKeyBytes = Encoders.Hex.DecodeData(ecPrivateKeysHex[i]);
				privateKeys[i] = new Key(privateKeyBytes);
				all_keys.Add(privateKeys[i]);
				pubKeys[i] = privateKeys[i].PubKey;
				Console.WriteLine($"PubKeys[{i}]  {Encoders.Hex.EncodeData(privateKeys[i].PubKey.ToBytes()).ToString()}");
				Console.WriteLine($"PubKeys Internal Taproot[{i}]  {privateKeys[i].PubKey.TaprootInternalKey.ToString()}");
			}

			var keySpend = new Key(Encoders.Hex.DecodeData("69d0f570f729fede96bc456d9a05c611a0e97a49045d5ac5250349e5d9220684"));

			var KeySpendinternalPubKey = keySpend.PubKey.TaprootInternalKey;
			var ownerPubKey = keySpend.PubKey;


			var generatedAddress = GenerateScriptAddress(3, Network.RegTest, ownerPubKey, pubKeys);
			Console.WriteLine($"GenerateScriptAddress  {generatedAddress.ToString()}");

			var (scriptWeightsGenerated, addrGenerated) = GenerateScriptPubKey(3, true, Network.RegTest, ownerPubKey, pubKeys);
			Console.WriteLine($"Are both same Taproot Address  {generatedAddress.Equals(addrGenerated)}");

			var scriptWeights2 = scriptWeightsGenerated.ToArray();







			var peers = ecPrivateKeysHex.Length;
			TaprootPubKey taprootPubKey = null;



			var howManyScripts = 3;
			var probability = (uint)(100 / howManyScripts);
			var scriptWeightsList = new List<(UInt32, TapScript)>();
			var Scripts = new TapScript[howManyScripts];
			List<NBitcoin.Op> ops = new List<NBitcoin.Op>();


			// ADD the 3 tap scripts
			// each is a 2-of-2 MuSig1 tapscript

			ops.Clear();
			ops.Add(Op.GetPushOp(ecPubKeys[0].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIG);
			ops.Add(Op.GetPushOp(ecPubKeys[2].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIGADD);
			ops.Add(OpcodeType.OP_2);
			ops.Add(OpcodeType.OP_NUMEQUAL);
			Scripts[0] = new NBitcoin.Script(ops).ToTapScript(NBitcoin.TapLeafVersion.C0);
			Console.WriteLine("Script[0]: " + Scripts[0].ToString());
			scriptWeightsList.Add((probability, Scripts[0]));

			ops.Clear();
			ops.Add(Op.GetPushOp(ecPubKeys[0].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIG);
			ops.Add(Op.GetPushOp(ecPubKeys[1].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIGADD);
			ops.Add(OpcodeType.OP_2);
			ops.Add(OpcodeType.OP_NUMEQUAL);
			Scripts[1] = new Script(ops).ToTapScript(TapLeafVersion.C0);
			Console.WriteLine("Script[1]: " + Scripts[1].ToString());
			scriptWeightsList.Add((probability, Scripts[1]));

			ops.Clear();
			ops.Add(Op.GetPushOp(ecPubKeys[1].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIG);
			ops.Add(Op.GetPushOp(ecPubKeys[2].ToBytes()));
			ops.Add(OpcodeType.OP_CHECKSIGADD);
			ops.Add(OpcodeType.OP_2);
			ops.Add(OpcodeType.OP_NUMEQUAL);
			Scripts[2] = new Script(ops).ToTapScript(TapLeafVersion.C0);
			Console.WriteLine("Script[2]: " + Scripts[2].ToString());
			scriptWeightsList.Add((probability, Scripts[2]));


			var scriptWeights = scriptWeightsList.ToArray();




			var AllTreeInfo = new System.Collections.Generic.List<NBitcoin.TaprootSpendInfo>();


			NBitcoin.TaprootSpendInfo treeInfo;
			treeInfo = TaprootSpendInfo.WithHuffmanTree(KeySpendinternalPubKey, scriptWeights);

			// add twice because I'm processing to TxIns
			AllTreeInfo.Add(treeInfo);
			//AllTreeInfo.Add(treeInfo);


			taprootPubKey = treeInfo.OutputPubKey.OutputKey;



			using (var nodeBuilder = NodeBuilder.Create(NodeDownloadData.Bitcoin.v25_0, Network.RegTest))
			{



				var rpc = nodeBuilder.CreateNode().CreateRPCClient();
				nodeBuilder.StartAll();
				rpc.Generate(102);

				var addr = taprootPubKey.GetAddress(Network.RegTest);
				Console.WriteLine("Address to send: " + addr.ToString());

				rpc.Generate(1);


				var txid = rpc.SendToAddress(addr, Money.Coins(1.0m));


				var tx = rpc.GetRawTransaction(txid);
				Console.WriteLine("input transaction: " + tx.ToString());


				var spender = Transaction.Create(Network.RegTest);

				//NBitcoin.IndexedTxOut spentOutput = null;
				var spentAllOutputsIn = new List<NBitcoin.TxOut>();
				foreach (var output in tx.Outputs.AsIndexedOutputs())
				{
					if (output.TxOut.ScriptPubKey == addr.ScriptPubKey)
					{
						spender.Inputs.Add(new OutPoint(tx, output.N));
						spentAllOutputsIn.Add(output.TxOut);
						break; // Break out of the loop since you found the desired item
					}
				}


				NBitcoin.TxOut[] spentOutputsIn = spentAllOutputsIn.ToArray();



				var dest = rpc.GetNewAddress();
				//spender.Outputs.Add(NBitcoin.Money.Coins(0.7m), dest);
				//spender.Outputs.Add(NBitcoin.Money.Coins(0.2999000m), addr);
				spender.Outputs.Add(NBitcoin.Money.Coins(0.99999830m), addr); // fee 170 satoshis = vSize


				var sighash = NBitcoin.TaprootSigHash.All | NBitcoin.TaprootSigHash.AnyoneCanPay;



				var allkeysarray = all_keys.ToArray();
				var allTreeInfoArray = AllTreeInfo.ToArray();

				////////////////////////
				///
				TaprootExecutionData extectionData;


				Boolean useKeySpend = false;
				if (useKeySpend)
				{
					// ADDRESS PATH

					for (int i = 0; i < spender.Inputs.Count; i++)
					{

						extectionData = new TaprootExecutionData(0) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
						var sig = keySpend.SignTaprootKeySpend(hash, allTreeInfoArray[i].MerkleRoot, sighash);
						spender.Inputs[i].WitScript = new NBitcoin.WitScript(NBitcoin.Op.GetPushOp(sig.ToBytes()));
					}
				}
				else
				{

					var min_num_signatures = 2;
					var sigs = new TaprootSignature[min_num_signatures];
					for (int i = 0; i < spender.Inputs.Count; i++)
					{


						extectionData = new TaprootExecutionData(0, Scripts[0].LeafHash) { SigHash = sighash };
						var hash = spender.GetSignatureHashTaproot(spentOutputsIn, extectionData);
						// use this signatures if XOnly pubKey
						//var sig11 = privateKeys[0].SignTaprootScriptSpend(hash, sighash);
						var sig11 = allkeysarray[0].SignTaprootScriptSpend(hash, sighash);
						var strSig = Encoders.Hex.EncodeData(sig11.ToBytes()).ToString();
						sigs[0] = TaprootSignature.Parse(strSig);
						//var sig22 = privateKeys[2].SignTaprootScriptSpend(hash, sighash);
						var sig22 = allkeysarray[2].SignTaprootScriptSpend(hash, sighash);
						strSig = Encoders.Hex.EncodeData(sig22.ToBytes()).ToString();
						sigs[1] = TaprootSignature.Parse(strSig);
						// signatures go in reverse order of the pubKeys in script
						ops.Clear();

						for (var r = min_num_signatures - 1; r >= 0; r--)
						{
							ops.Add(Op.GetPushOp(sigs[r].ToBytes()));
							Console.WriteLine($"Signature[{r}] {sigs[r].ToString()}");
						}


						ops.Add(Op.GetPushOp(Scripts[0].Script.ToBytes()));
						ops.Add(Op.GetPushOp(allTreeInfoArray[i].GetControlBlock(Scripts[0]).ToBytes()));
						Console.WriteLine($"Script[{0}]: {Scripts[0].Script}");
						spender.Inputs[i].WitScript = new WitScript(ops.ToArray());


						Console.WriteLine("witness: " + spender.Inputs[i].WitScript.ToString());


					}
				}



				// COMMON



				Console.WriteLine(spender.ToString());
				var validator = spender.CreateValidator(spentOutputsIn);
				Console.WriteLine("virtual size: " + spender.GetVirtualSize());
				Console.WriteLine("to hex: " + spender.ToHex().ToString());
				var result = validator.ValidateInput(0);
				var success = result.Error is null;
				Console.WriteLine("does validate witness? " + success);

				InputValidationResult[] resullts = validator.ValidateInputs();
				for (int i = 0; i < resullts.Length; i++)
				{
					var success3 = resullts[i].Error is null;
					Console.WriteLine($"does validate witness? [{i}] " + success3);
				}

				//rpc.SendRawTransaction(spender);


			}
		}

	}

}



