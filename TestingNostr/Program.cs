using System;
using System.Text;
using System.Threading;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

using Nostr.Client;
using Nostr.Client.Keys;
using Nostr.Client.Utils;
using Nostr.Client.Messages;
using Nostr.Client.Requests;
using Nostr.Client.Json;

using System.Security.Cryptography;



namespace NBitcoinTraining
{
	class Program
	{
		static void Main(string[] args)
		{
			//musig_MusigTest();
			//produceJson();
			//test_nostr();
			// test_event();
			test_event_nbitcoin();
			//work_ec();

		}

		public static int GetHexValue(char hex)
		{
			return hex - ((hex < ':') ? 48 : ((hex < 'a') ? 55 : 87));
		}
		public static byte[] ToByteArray(string hex)
		{
			if (hex.Length % 2 == 1)
			{
				throw new Exception("The binary key cannot have an odd number of digits");
			}

			byte[] array = new byte[hex.Length >> 1];
			for (int i = 0; i < hex.Length >> 1; i++)
			{
				array[i] = (byte)((GetHexValue(hex[i << 1]) << 4) + GetHexValue(hex[(i << 1) + 1]));
			}

			return array;
		}

		static void work_ec()
		{

			var pubKey = NBitcoin.Secp256k1.ECXOnlyPubKey.Create(HexExtensions.ToByteArray("89fa4b8bce7d7ba022dec50e8f7cfae055514010dc6226bb30dc8f7d17ea73fd"));
			byte[] msgBytes = ToByteArray("4f77b96427737e49a8077c959a104767c32b5e75c834cc9c249aa446e3ec9e24");
			byte[] signBytes = ToByteArray("4114bd016ad8743da9a2b695f16dc23046060241658ca375b3424d2bd7f2468080d08f8e216c808409407f05b78beb0e42e0469a6a8b92fed7f9f58aec87cacd");

			SecpSchnorrSignature.TryCreate(signBytes, out var schnorr);
			var verified = pubKey.SigVerifyBIP340(schnorr, msgBytes);
			Console.WriteLine(verified);



			string hexPrivateKey = "0cce8c841774e499b15babdd50b4c3f9c0fc828eefe1508fc4910ed5f6bea241";
			byte[] privateKeyBytes = NBitcoin.DataEncoders.Encoders.Hex.DecodeData(hexPrivateKey);
			//var ec = ECPrivKey.Create(HexExtensions.ToByteArray(hex));
			NBitcoin.Secp256k1.ECPrivKey privKey = ECPrivKey.Create(privateKeyBytes);


			var sig2 = privKey.SignBIP340(msgBytes);
			var pubKey2 = privKey.CreateXOnlyPubKey();
			Console.WriteLine(Encoders.Hex.EncodeData(pubKey2.ToBytes()));
			var verified2 = pubKey2.SigVerifyBIP340(sig2, msgBytes);
			Console.WriteLine(verified2);
			Console.WriteLine(Encoders.Hex.EncodeData(sig2.ToBytes()));


		}

		static void test_event()
		{
			DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(1702058452);
			DateTime dateTimeUtc = dateTimeOffset.UtcDateTime;

			var ev = new Nostr.Client.Messages.NostrEvent
			{
				Kind = Nostr.Client.Messages.NostrKind.ShortTextNote,
				CreatedAt = dateTimeUtc,
				Tags = new(
					new NostrEventTag("e", "4eab0a10fa8aa611d55b7f8ea41f7756c69284362a8c8cccf2ed2dc0362d7aad"),
					new NostrEventTag("p", "7f3b464b9ff3623630485060cbda3a7790131c5339a7803bde8feb79a5e1b06a")
				),
				Content = "Test message from C# client"
			};

			var key = Nostr.Client.Keys.NostrPrivateKey.FromHex("0cce8c841774e499b15babdd50b4c3f9c0fc828eefe1508fc4910ed5f6bea241");
			var signed = ev.Sign(key);


			var salida = new Nostr.Client.Requests.NostrEventRequest(signed);
			var jsonOut = Nostr.Client.Json.NostrJson.Serialize(salida);
			Console.WriteLine(jsonOut);



		}



		static void test_event_nbitcoin()
		{

			///// NBitcoin



			string eventId = "";
			string pubkey = "89fa4b8bce7d7ba022dec50e8f7cfae055514010dc6226bb30dc8f7d17ea73fd";
			long createdAt = 1702058452;
			int kind = 1;
			string content = "Test message from C# client";
			string sig = "";


			var tags = new System.Collections.Generic.List<System.Collections.Generic.List<string>>
			{
				new System.Collections.Generic.List<string> { "e", "4eab0a10fa8aa611d55b7f8ea41f7756c69284362a8c8cccf2ed2dc0362d7aad" },
				new System.Collections.Generic.List<string> { "p", "7f3b464b9ff3623630485060cbda3a7790131c5339a7803bde8feb79a5e1b06a" }
			};


			// Create a List<object> to represent the structure
			var preEventData = new System.Collections.Generic.List<object>
			{
				0,
				pubkey,
				createdAt,
				kind,
				tags,
				content
			};

			// Create a dictionary to represent the JSON structure

			var eventData = new System.Collections.Generic.Dictionary<string, object>
{
				{ "id", eventId },
				{ "pubkey", pubkey },
				{ "created_at", createdAt },
				{ "kind", kind },
				{ "tags", tags },
				{ "content", content },
				{ "sig", sig }
				}; // dictionary

			// create id
			var jsonSha = Newtonsoft.Json.JsonConvert.SerializeObject(preEventData);
			//var jsonSha = Newtonsoft.Json.JsonConvert.SerializeObject(preEventData, Newtonsoft.Json.Formatting.None);
			Console.WriteLine(jsonSha);
			byte[] msgBytes = System.Text.Encoding.UTF8.GetBytes(jsonSha);
			NBitcoin.uint256 msgHasId = new NBitcoin.uint256(NBitcoin.Crypto.Hashes.SHA256(msgBytes), false);
			NBitcoin.uint256 msgHash = new NBitcoin.uint256(NBitcoin.Crypto.Hashes.SHA256(msgBytes), true); // es igual a este: NBitcoin.uint256 msgHash3 = new NBitcoin.uint256(System.Security.Cryptography.SHA256.HashData(msgBytes));
			eventData["id"] = msgHasId.ToString();
			Console.WriteLine(msgHasId.ToString());
			Console.WriteLine(msgHash.ToString());



			// Sign the message hash
			string hexPrivateKey = "0cce8c841774e499b15babdd50b4c3f9c0fc828eefe1508fc4910ed5f6bea241";
			byte[] privateKeyBytes = NBitcoin.DataEncoders.Encoders.Hex.DecodeData(hexPrivateKey);
			NBitcoin.Key privateKey = new NBitcoin.Key(privateKeyBytes);

			var signature = privateKey.SignTaprootKeySpend(msgHash);
			eventData["sig"] = signature.ToString();

			//var msg256 = new uint256(Encoders.Hex.DecodeData("4f77b96427737e49a8077c959a104767c32b5e75c834cc9c249aa446e3ec9e24"));
			var msg256 = msgHasId;
			NBitcoin.TaprootPubKey expectedpubkey = new TaprootPubKey(Encoders.Hex.DecodeData("89fa4b8bce7d7ba022dec50e8f7cfae055514010dc6226bb30dc8f7d17ea73fd"));
			//var expectedSig = new NBitcoin.Crypto.SchnorrSignature(Encoders.Hex.DecodeData("994612de7380bcaff0c8f78f0d88eaff7e3b3332c6ff5c2e1bf2c6e173ac0fb56121616921c0dc2810567b611b63ec9f9f272d81027b07ac0e328c60110eb090"));
			var expectedSig = new NBitcoin.Crypto.SchnorrSignature(Encoders.Hex.DecodeData(signature.ToString()));

			Console.WriteLine(expectedpubkey.VerifySignature(msg256, expectedSig));

			var json = Newtonsoft.Json.JsonConvert.SerializeObject(new object[] { "EVENT", eventData });
			Console.WriteLine(json);

		}


		static void test_nostr()
		{

			var pair = NostrKeyPair.From(NostrPrivateKey.FromHex("0cce8c841774e499b15babdd50b4c3f9c0fc828eefe1508fc4910ed5f6bea241"));


			Console.WriteLine(pair.PrivateKey.Hex.ToString()); // 0cce8c841774e499b15babdd50b4c3f9c0fc828eefe1508fc4910ed5f6bea241
			Console.WriteLine(pair.PublicKey.Hex.ToString()); // 89fa4b8bce7d7ba022dec50e8f7cfae055514010dc6226bb30dc8f7d17ea73fd

			Console.WriteLine(pair.PublicKey.Bech32); // npub138ayhz7w04a6qgk7c58g7l86up24zsqsm33zdwesmj8h69l2w07s2fq397
			Console.WriteLine(pair.PrivateKey.Bech32); // nsec1pn8gepqhwnjfnv2m40w4pdxrl8q0eq5wals4pr7yjy8dta475fqsdtykud
			Console.WriteLine(NostrConverter.ToNpub(pair.PublicKey.Hex));
			Console.WriteLine(NostrConverter.ToNsec(pair.PrivateKey.Hex));


			///// NBitcoin

			byte[] bytes = NBitcoin.DataEncoders.Encoders.Hex.DecodeData("0cce8c841774e499b15babdd50b4c3f9c0fc828eefe1508fc4910ed5f6bea241");
			var privateKey = new NBitcoin.Key(bytes);
			var pair2 = privateKey.CreateTaprootKeyPair();

			Console.WriteLine(pair2.PubKey.InternalKey.ToString()); // 89fa4b8bce7d7ba022dec50e8f7cfae055514010dc6226bb30dc8f7d17ea73fd
			Console.WriteLine(pair2.PubKey.OutputKey.ToString()); // 39d7bd961dc159b46dc7ac94a305d5244797f075471192e8a52a903f3af9dadd

		}




		static void produceJson()
		{
			// Initialize variables with values
			string eventId = "4376c65d2f232afbe9b882a35baa4f6fe8667c4e684749af565f981833ed6a65";
			string pubkey = "6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93";
			int createdAt = 1673347337;
			int kind = 1;
			string content = "Walled gardens became prisons, and nostr is the first step towards tearing down the prison walls.";
			string sig = "908a15e46fb4d8675bab026fc230a0e3542bfade63da02d542fb78b2a8513fcd0092619a2c8c1221e581946e0191f2af505dfdf8657a414dbca329186f009262";

			// Create a list to represent the "tags" array
			var tags = new List<List<string>>
			{
				new List<string> { "e", "3da979448d9ba263864c4d6f14984c423a3838364ec255f03c7904b1ae77f206" },
				new List<string> { "p", "bf2376e17ba4ec269d10fcc996a4746b451152be9031fa48e74553dde5526bce" }
			};

			// Create a dictionary to represent the JSON structure
			var eventData = new Dictionary<string, object>
			{
				{ "id", eventId },
				{ "pubkey", pubkey },
				{ "created_at", createdAt },
				{ "kind", kind },
				{ "tags", tags },
				{ "content", content },
				{ "sig", sig }
			};

			eventData["id"] = "newIdValue";
			// Serialize the dictionary to JSON
			var json = JsonConvert.SerializeObject(new object[] { "EVENT", eventData });
			Console.WriteLine(json);

		}







		static void secp256k1_rand256(Span<byte> output)
		{
			// Should reproduce the secp256k1_test_rng
			RandomUtils.GetBytes(output);
		}

		static NBitcoin.Secp256k1.Scalar random_scalar_order()
		{
			Scalar num;
			Span<byte> b32 = stackalloc byte[32];
			do
			{
				b32.Clear();
				secp256k1_rand256(b32);
				num = new Scalar(b32, out var overflow);
				if (overflow != 0 || num.IsZero)
				{
					continue;
				}
				return num;
			} while (true);
		}
		static Context ctx = Context.Instance;

		static void musig_MusigTest()
		{


			foreach (var useTweak in new[] { false, true })
				foreach (var useAdaptor in new[] { false, true })
				{
					var msg32 = random_scalar_order().ToBytes();
					var tweak = random_scalar_order().ToBytes();
					var adaptor = ctx.CreateECPrivKey(random_scalar_order());
					var peers = 3;
					var privKeys = new ECPrivKey[peers];
					var privNonces = new MusigPrivNonce[peers];
					var pubNonces = new MusigPubNonce[peers];
					var musig = new MusigContext[peers];
					var sigs = new MusigPartialSignature[peers];
					var pubKeys = new ECPubKey[peers];

					for (int i = 0; i < peers; i++)
					{
						privKeys[i] = ctx.CreateECPrivKey(random_scalar_order());
						pubKeys[i] = privKeys[i].CreatePubKey();
					}

					for (int i = 0; i < peers; i++)
					{
						musig[i] = new MusigContext(pubKeys, msg32);
						privNonces[i] = musig[i].GenerateNonce((uint)i, privKeys[i]);
						pubNonces[i] = privNonces[i].CreatePubNonce();
					}

					for (int i = 0; i < peers; i++)
					{
						if (useTweak)
						{
							musig[i].Tweak(tweak);
						}
						if (useAdaptor)
						{
							musig[i].UseAdaptor(adaptor.CreatePubKey());
						}

						musig[i].ProcessNonces(pubNonces);
						sigs[i] = musig[i].Sign(privKeys[i], privNonces[i]);
					}


					// Verify all the partial sigs
					for (int i = 0; i < peers; i++)
					{
						Console.WriteLine(musig[i].Verify(pubKeys[i], pubNonces[i], sigs[i]));
					}

					// Combine
					var schnorrSig = musig[0].AggregateSignatures(sigs);

					if (useAdaptor)
						schnorrSig = musig[0].Adapt(schnorrSig, adaptor);
					// Verify resulting signature
					// SigningPubKey is the tweaked key if tweaked, or the combined key if not
					Console.WriteLine(musig[0].AggregatePubKey.ToXOnlyPubKey().SigVerifyBIP340(schnorrSig, msg32));

					byte[] msgBytes = System.Text.Encoding.UTF8.GetBytes("hola como estas");
					NBitcoin.uint256 msgHash = NBitcoin.Crypto.Hashes.DoubleSHA256(msgBytes);
					Console.WriteLine(msgHash.ToString());
				}

		}
	}


}


