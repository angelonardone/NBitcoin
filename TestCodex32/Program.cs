// Tests of DistricutedCryptographyLib.Codex32 (BIP-93): every test vector of the BIP, the invalid ones, and
// random split/combine round trips. No device or network needed.
//   dotnet run -c Release                 run the tests
//   dotnet run -c Release -- cases FILE   also write random cases (seed + shares) as JSON; then
//                                         python -I codex32_reference.py FILE  (the BIP reference functions)
using System.Text.Json;
using DistricutedCryptographyLib;
using NBitcoin;
using NBitcoin.DataEncoders;

int pass = 0, fail = 0;
void Check(bool ok, string what)
{
	if (ok) { pass++; Console.WriteLine($"PASS {what}"); }
	else { fail++; Console.WriteLine($"FAIL {what}"); }
}
void Throws(Action a, string what)
{
	try { a(); Check(false, what + " (no error)"); }
	catch (Exception e) when (e is FormatException || e is ArgumentException) { Check(true, $"{what}: {e.Message}"); }
}
string Hex(byte[] b) => Encoders.Hex.EncodeData(b);
byte[] FromHex(string h) => Encoders.Hex.DecodeData(h);
string Xprv(byte[] seed) => ExtKey.CreateFromSeed(seed).GetWif(Network.Main).ToString();

// ---- Test vector 1: unshared secret, 128 bits ----
{
	var s = Codex32String.Parse("ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw");
	var seed = Codex32.ToSeed(s);
	Check(Hex(seed) == "318c6318c6318c6318c6318c6318c631", "TV1 seed");
	Check(Xprv(seed) == "xprv9s21ZrQH143K3taPNekMd9oV5K6szJ8ND7vVh6fxicRUMDcChr3bFFzuxY8qP3xFFBL6DWc2uEYCfBFZ2nFWbAqKPhtCLRjgv78EZJDEfpL", "TV1 xprv");
	Check(s.Threshold == 0 && s.Identifier == "test" && s.IsSecret, "TV1 header");
	Check(s.ToString() == "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw", "TV1 re-encode");
}

// ---- Test vector 2: k=2 "random" shares, derived share and secret, upper case ----
{
	var a = Codex32String.Parse("MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM");
	var c = Codex32String.Parse("MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN");
	var list = new[] { a, c };
	Check(Codex32.Interpolate(list, 'd').ToString() == "ms12named" + "ll4f8jlh4e5vdvuldlfxu2jhdnlsm97xvenrxeg", "TV2 derived share d");
	var secret = Codex32.Combine(list);
	Check(secret.ToString() == "ms12names6xqguzttxkeqnjsjzv4jv3nz5k3kwgsphuh6evw", "TV2 secret");
	var seed = Codex32.ToSeed(secret);
	Check(Hex(seed) == "d1808e096b35b209ca12132b264662a5", "TV2 seed");
	Check(Xprv(seed) == "xprv9s21ZrQH143K2NkobdHxXeyFDqE44nJYvzLFtsriatJNWMNKznGoGgW5UMTL4fyWtajnMYb5gEc2CgaKhmsKeskoi9eTimpRv2N11THhPTU", "TV2 xprv");
	Check(Hex(Codex32.CombineSeed(new[] { "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM", "ms12namedll4f8jlh4e5vdvuldlfxu2jhdnlsm97xvenrxeg" })) == "d1808e096b35b209ca12132b264662a5", "TV2 seed from a + d (mixed case between strings)");
}

// ---- Test vector 3: existing 128-bit seed, k=3 ----
{
	var seed = FromHex("ffeeddccbbaa99887766554433221100");
	var s = Codex32.FromSeed(seed, "cash", 3);
	Check(s.ToString() == "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln", "TV3 secret from seed");
	var a = Codex32String.Parse("ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t");
	var c = Codex32String.Parse("ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr");
	var init = new[] { s, a, c };
	var d = Codex32.Interpolate(init, 'd'); var e = Codex32.Interpolate(init, 'e'); var f = Codex32.Interpolate(init, 'f');
	Check(d.ToString() == "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm", "TV3 derived d");
	Check(e.ToString() == "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9", "TV3 derived e");
	Check(f.ToString() == "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704", "TV3 derived f");
	Check(Xprv(seed) == "xprv9s21ZrQH143K266qUcrDyYJrSG7KA3A7sE5UHndYRkFzsPQ6xwUhEGK1rNuyyA57Vkc1Ma6a8boVqcKqGNximmAe9L65WsYNcNitKRPnABd", "TV3 xprv");
	var all = new[] { a, c, d, e, f };
	bool every = true;
	for (int i = 0; i < 5; i++) for (int j = i + 1; j < 5; j++) for (int k = j + 1; k < 5; k++)
		every &= Hex(Codex32.ToSeed(Codex32.Combine(new[] { all[i], all[j], all[k] }))) == "ffeeddccbbaa99887766554433221100";
	Check(every, "TV3 every 3 of the 5 shares give the seed");
	foreach (var alt in new[] { "ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r", "ms13cashsllhdmn9m42vcsamx24zrxgs3qzfatvdwq5692k6", "ms13cashsllhdmn9m42vcsamx24zrxgs3qrsx6ydhed97jx2" })
		Check(Hex(Codex32.ToSeed(Codex32String.Parse(alt))) == "ffeeddccbbaa99887766554433221100", $"TV3 other padding {alt[^6..]}");
	Check(Hex(Codex32.ToSeed(Codex32.Combine(all))) == "ffeeddccbbaa99887766554433221100", "TV3 all 5 shares (extra shares checked)");
}

// ---- Test vector 4: 256 bits, 16 valid paddings ----
{
	var seed = FromHex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
	Check(Codex32.FromSeed(seed, "leet").ToString() == "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma", "TV4 secret");
	Check(Xprv(seed) == "xprv9s21ZrQH143K3s41UCWxXTsU4TRrhkpD1t21QJETan3hjo8DP5LFdFcB5eaFtV8x6Y9aZotQyP8KByUjgLTbXCUjfu2iosTbMv98g8EQoqr", "TV4 xprv");
	var paddings = new[] { "qqtum9pgv99ycma", "qpj82dp34u6lqtd", "qzsrs4pnh7jmpj5", "qrfcpap2w8dqezy", "qy5tdvphn6znrf0", "q9dsuypw2ragmel", "qx05xupvgp4v6qx", "q8k0h5p43c2hzsk", "qgum7hplmjtr8ks", "qf9q0lpxzt5clxq", "q28y48pyqfuu7le", "qt7ly0paesr8x0f", "qvrvg7pqydv5uyz", "qd6hekpea5n0y5j", "qwcnrwpmlkmt9dt", "q0pgjxpzx0ysaam" };
	bool all = paddings.All(p => Hex(Codex32.ToSeed(Codex32String.Parse("ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzy" + p))) == Hex(seed));
	Check(all, "TV4 the 16 paddings give the same seed");
}

// ---- Test vector 5: 512 bits, long checksum ----
{
	var s = Codex32String.Parse("MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK");
	var seed = Codex32.ToSeed(s);
	Check(Hex(seed) == "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9", "TV5 seed");
	Check(Xprv(seed) == "xprv9s21ZrQH143K4UYT4rP3TZVKKbmRVmfRqTx9mG2xCy2JYipZbkLV8rwvBXsUbEv9KQiUD7oED1Wyi9evZzUn2rqK9skRgPkNaAzyw3YrpJN", "TV5 xprv");
	Check(s.ToString().ToUpperInvariant() == "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK", "TV5 re-encode (long checksum)");
}

// ---- Test vectors 6, 7, 8 ----
{
	Check(Codex32.FromSeed(FromHex("000102030405060708090a0b0c0d0e0f10111213"), "seed").ToString() == "ms10seedsqqqsyqcyq5rqwzqfpg9scrgwpugpzysn9vaqzzvs20xnl", "TV6 160 bits");
	Check(Hex(Codex32.ToSeed(Codex32String.Parse("ms10seedsyqsjygeyy5nzw2pf9g4jctfw9ucrzv3nxs6nvdau84gz0632s0xs"))) == "202122232425262728292a2b2c2d2e2f3031323334353637", "TV7 192 bits (padding 101)");
	Check(Hex(Codex32.ToSeed(Codex32String.Parse("ms10seedsgpq5ys6yg4rywjzfff95cn2wfag9z5jn2324v46ct9d9hrcduqw8c3lccl"))) == "404142434445464748494a4b4c4d4e4f505152535455565758595a5b", "TV8 224 bits (padding 1)");
}

// ---- Invalid test vectors: every one must be refused ----
{
	var invalid = new[]
	{
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghq",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghp",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxlk3yepcstwr",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx6pgnv7jnpcsp",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxx0cpvr7n4geq",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxm5252y7d3lr",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxrd9sukzl05ej",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxc55srw5jrm0",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxgc7rwhtudwc",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx4gy22afwghvs",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pe0",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pew",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxqyadsp3nywm8a",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxzvg7ar4hgaejk",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcznau0advgxqe",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxch3jrc6j5040j",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx52gxl6ppv40mcv",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx7g4g2nhhle8fk",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx63m45uj8ss4x8",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxy4r708q7kg65x",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxurfvwmdcmymdufv",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcwm4re8fs78vn",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxwqey9rfs6smenxa",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxw0a4c70rfefn4",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxk4pavy5n46nea",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx9lrwar5zwng4w",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxr335l5tv88js3",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxvu7q9nz8p7dj68v",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpq6k542scdxndq3",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxkmfw6jm270mz6ej",
			"ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxzhddxw99w7xws",
			"ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx42cux6um92rz",
			"ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxarja5kqukdhy9",
			"ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxky0ua3ha84qk8",
			"ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9eheesxadh2n2n9",
			"ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9llwmgesfulcj2z",
			"ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx02ev7caq6n9fgkf",
			"ms10fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx0z26tfn0ulw3p",
			"ms1fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxda3kr3s0s2swg",
			"0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"ms0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
			"10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
			"m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxx8t28z74x8hs4l",
			"s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxh9d0fhnvfyx3x",
			"Ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"mS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"MS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"ms10FAUXsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"ms10fauxSxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
			"ms10fauxsXXXXXXXXXXXXXXXXXXXXXXXXXXuqxkk05lyf3x2",
			"ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxUQXKK05LYF3X2",
	};
	int refused = 0;
	foreach (var v in invalid)
	{
		if (Codex32String.TryParse(v, out _)) Console.WriteLine($"  accepted (wrong): {v}");
		else refused++;
	}
	Check(refused == invalid.Length, $"invalid vectors refused: {refused}/{invalid.Length}");
}

// ---- Random round trips: every seed size, thresholds 2..9, up to 31 shares ----
var rnd = new Random(93);
var cases = new List<object>();
{
	bool ok = true; int n = 0;
	foreach (var len in Codex32.SeedLengths)
		for (int k = 2; k <= 9; k++)
			foreach (var count in new[] { k, k + 1, Math.Min(31, k + 7), 31 }.Distinct())
			{
				var seed = RandomUtils.GetBytes(len);
				var shares = Codex32.SplitSeed(seed, k, count);
				ok &= shares.Count == count;
				ok &= shares.Select(s => s[8]).SequenceEqual(Codex32.ShareIndexes.Take(count));
				ok &= shares.All(s => s.Length == shares[0].Length && s.StartsWith($"ms1{k}") && s[4..8] == shares[0][4..8]);
				// three different random subsets of k shares
				for (int t = 0; t < 3; t++)
				{
					var subset = shares.OrderBy(_ => rnd.Next()).Take(k).ToList();
					ok &= Codex32.CombineSeed(subset).AsSpan().SequenceEqual(seed);
					n++;
				}
				ok &= Codex32.CombineSeed(shares).AsSpan().SequenceEqual(seed); // all of them: extra shares checked
				cases.Add(new { seed = Hex(seed), k, shares });
			}
	Check(ok, $"random split/combine: 6 sizes x k 2..9 x counts, {n} subsets");
}

// ---- With fewer than k shares nothing about the seed comes out: k-1 shares fit any seed ----
{
	// For a fixed set of k-1 shares, every candidate secret is consistent with some k-th share: build the k-th
	// share that would make the secret equal to another seed and check that the set is valid (BIP-93 security).
	var seed = RandomUtils.GetBytes(16);
	var shares = Codex32.SplitSeed(seed, 3, 5).Select(Codex32String.Parse).ToList();
	var other = Codex32.FromSeed(RandomUtils.GetBytes(16), shares[0].Identifier, 3);
	var fake = Codex32.Interpolate(new[] { shares[0], shares[1], other }, 'z');
	var back = Codex32.ToSeed(Codex32.Combine(new[] { shares[0], shares[1], fake }));
	Check(back.AsSpan().SequenceEqual(Codex32.ToSeed(other)), "k-1 shares are consistent with any other seed");
}

// ---- Errors the application must report ----
{
	var seed = RandomUtils.GetBytes(64);
	var a = Codex32.SplitSeed(seed, 3, 5);
	var b = Codex32.SplitSeed(seed, 3, 5);
	Throws(() => Codex32.CombineSeed(a.Take(2)), "2 shares of a 3-of-5");
	Throws(() => Codex32.CombineSeed(new[] { a[0], a[1], b[2] }), "shares of two backups (different identifier)");
	Throws(() => Codex32.CombineSeed(new[] { a[0], a[0], a[1] }), "the same share twice");
	Throws(() => Codex32.CombineSeed(new[] { a[0], a[1], a[2], Codex32.SplitSeed(seed, 3, 5, a[0][4..8])[3] }), "an extra share of another split with the same identifier");
	var damaged = a[1][..20] + (a[1][20] == 'q' ? 'p' : 'q') + a[1][21..];
	Throws(() => Codex32.CombineSeed(new[] { a[0], damaged, a[2] }), "a mistyped share (checksum)");
	Throws(() => Codex32.SplitSeed(seed, 1, 3), "threshold 1");
	Throws(() => Codex32.SplitSeed(seed, 10, 12), "threshold 10");
	Throws(() => Codex32.SplitSeed(seed, 3, 32), "32 shares");
	Throws(() => Codex32.SplitSeed(seed, 3, 2), "fewer shares than the threshold");
	Throws(() => Codex32.SplitSeed(RandomUtils.GetBytes(33), 2, 3), "a 33-byte seed");
	Throws(() => Codex32.FromSeed(seed, "abc"), "an identifier of 3 characters");
	Throws(() => Codex32.FromSeed(seed, "abib"), "an identifier with 'i'");
}

// ---- BIP39 words -> seed -> codex32 -> seed -> same master as the words ----
{
	var mnemonic = new Mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
	var seed = mnemonic.DeriveSeed("a passphrase");
	var shares = Codex32.SplitSeed(seed, 2, 3);
	var back = Codex32.CombineSeed(new[] { shares[2], shares[0] });
	Check(ExtKey.CreateFromSeed(back).GetWif(Network.Main).ToString() == mnemonic.DeriveExtKey("a passphrase").GetWif(Network.Main).ToString(), "BIP39 seed (64 bytes) through 2-of-3 gives the same master");
	Check(shares[0].Length == 127, "a 64-byte seed share has 127 characters");
}

if (args.Length >= 2 && args[0] == "cases")
{
	File.WriteAllText(args[1], JsonSerializer.Serialize(cases));
	Console.WriteLine($"wrote {cases.Count} cases to {args[1]}");
}

Console.WriteLine($"\n{pass} PASS, {fail} FAIL");
return fail == 0 ? 0 : 1;
