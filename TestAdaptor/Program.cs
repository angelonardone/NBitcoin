using System;
using System.Text;
using System.Threading;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;


namespace NBitcoinTraining
{
	class Program
	{
		static void Main(string[] args)
		{

			musig_MusigTest();
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


			//var msg32 = random_scalar_order().ToBytes();
			//var tweak = random_scalar_order().ToBytes();
			//var adaptor = ctx.CreateECPrivKey(random_scalar_order());

			//var privKeys = new ECPrivKey[1];
			//var privNonces = new MusigPrivNonce[1];
			//var pubNonces = new MusigPubNonce[1];
			//var musig = new MusigContext[1];
			//var sigs = new MusigPartialSignature[1];
			//var pubKeys = new ECPubKey[1];




			//privKeys[0] = ctx.CreateECPrivKey(random_scalar_order());
			//pubKeys[0] = privKeys[0].CreatePubKey();


			//musig[0] = new MusigContext(pubKeys, msg32); // converti en "pbulic" este construcotr que estaba privet en MusigContext.cs
			//privNonces[0] = musig[0].GenerateNonce(0, privKeys[0]);
			//pubNonces[0] = privNonces[0].CreatePubNonce();


			//musig[0].Tweak(tweak);

			//musig[0].UseAdaptor(adaptor.CreatePubKey());

			//musig[0].ProcessNonces(pubNonces);
			//sigs[0] = musig[0].Sign(privKeys[0], privNonces[0]);


			
			//// Verify all the partial sigs

			//Console.WriteLine(musig[0].Verify(pubKeys[0], pubNonces[0], sigs[0]));


			//// Combine
			//var schnorrSig = musig[0].AggregateSignatures(sigs);
			//Console.WriteLine(Encoders.Hex.EncodeData(schnorrSig.ToBytes()));
			//schnorrSig = musig[0].Adapt(schnorrSig, adaptor);
			//Console.WriteLine(Encoders.Hex.EncodeData(schnorrSig.ToBytes()));
			//// Verify resulting signature
			//// SigningPubKey is the tweaked key if tweaked, or the combined key if not
			//Console.WriteLine(musig[0].AggregatePubKey.ToXOnlyPubKey().SigVerifyBIP340(schnorrSig, msg32));


			// Atomic swap



			var partial_sig_a = new MusigPartialSignature[2];
			var partial_sig_b = new MusigPartialSignature[2];
			var sk_a = new ECPrivKey[]
				{
						ctx.CreateECPrivKey(random_scalar_order()),
						ctx.CreateECPrivKey(random_scalar_order())
				};
			var sk_b = new ECPrivKey[]
				{
						ctx.CreateECPrivKey(random_scalar_order()),
						ctx.CreateECPrivKey(random_scalar_order())
				};
			var secnonce_a = new MusigPrivNonce[2];
			var secnonce_b = new MusigPrivNonce[2];

			var pk_a = sk_a.Select(p => p.CreatePubKey()).ToArray();
			var pk_b = sk_b.Select(p => p.CreatePubKey()).ToArray();

			var sec_adaptor = ctx.CreateECPrivKey(random_scalar_order());

			// create Hex string from ECPrivKey and back
			Console.WriteLine(Encoders.Hex.EncodeData(sec_adaptor.sec.ToBytes()));
			var sec_adaptor_2 = ctx.CreateECPrivKey(sec_adaptor.sec.ToBytes());
			Console.WriteLine(Encoders.Hex.EncodeData(sec_adaptor_2.sec.ToBytes()));
			Console.WriteLine("rebuilded key " + sec_adaptor.Equals(sec_adaptor_2));


			var pub_adaptor = sec_adaptor.CreatePubKey();
			byte[] msg32_a = Encoding.ASCII.GetBytes("this is the message blockchain a");
			byte[] msg32_b = Encoding.ASCII.GetBytes("this is the message blockchain b");
			var pre_session_a = new MusigContext(pk_a, msg32_a);
			var combined_pk_a = pre_session_a.AggregatePubKey.ToXOnlyPubKey();
			var pre_session_b = new MusigContext(pk_b, msg32_b);
			var combined_pk_b = pre_session_b.AggregatePubKey.ToXOnlyPubKey();

			for (int i = 0; i < 2; i++)
			{
				secnonce_a[i] = pre_session_a.GenerateNonce((uint)i, sk_a[i]);
				secnonce_b[i] = pre_session_b.GenerateNonce((uint)i, sk_b[i]);
			}

			var pubnonce_a = secnonce_a.Select(p => p.CreatePubNonce()).ToArray();
			var pubnonce_b = secnonce_b.Select(p => p.CreatePubNonce()).ToArray();

			/* Step 2: Exchange nonces */
			pre_session_a.UseAdaptor(pub_adaptor);
			pre_session_a.ProcessNonces(pubnonce_a);

			pre_session_b.UseAdaptor(pub_adaptor);
			pre_session_b.ProcessNonces(pubnonce_b);

			/* Step 3: Signer 0 produces partial signatures for both chains. */
			partial_sig_a[0] = pre_session_a.Sign(sk_a[0], secnonce_a[0]);
			partial_sig_b[0] = pre_session_b.Sign(sk_b[0], secnonce_b[0]);

			/* Step 4: Signer 1 receives partial signatures, verifies them and creates a
			* partial signature to send B-coins to signer 0. */
			Console.WriteLine(pre_session_a.Verify(pk_a[0], pubnonce_a[0], partial_sig_a[0]));
			Console.WriteLine(pre_session_b.Verify(pk_b[0], pubnonce_b[0], partial_sig_b[0]));
			partial_sig_b[1] = pre_session_b.Sign(sk_b[1], secnonce_b[1]);

			/* Step 5: Signer 0 adapts its own partial signature and combines it with the
			* partial signature from signer 1. This results in a complete signature which
			* is broadcasted by signer 0 to take B-coins. */
			var final_sig_b = pre_session_b.AggregateSignatures(partial_sig_b);
			final_sig_b = pre_session_b.Adapt(final_sig_b, sec_adaptor);
			Console.WriteLine(combined_pk_b.SigVerifyBIP340(final_sig_b, msg32_b));

			/* Step 6: Signer 1 extracts adaptor from the published signature, applies it to
			* other partial signature, and takes A-coins. */
			var sec_adaptor_extracted = pre_session_b.Extract(final_sig_b, partial_sig_b);
			Console.WriteLine(sec_adaptor.Equals(sec_adaptor_extracted));
			partial_sig_a[1] = pre_session_a.Sign(sk_a[1], secnonce_a[1]);
			var final_sig_a = pre_session_a.AggregateSignatures(partial_sig_a);
			final_sig_a = pre_session_a.Adapt(final_sig_a, sec_adaptor);
			Console.WriteLine(combined_pk_a.SigVerifyBIP340(final_sig_a, msg32_a));

			string hexString = "502c616d9910774e00edb71f01b951962cc44ec67072757767f3906ff82ebfe8";
			var tempBytes = NBitcoin.DataEncoders.Encoders.Hex.DecodeData(hexString);
			var base32string = NBitcoin.DataEncoders.Encoders.Base32.EncodeData(tempBytes);
			Console.WriteLine("Base32: " + base32string);


		}


	}

}


