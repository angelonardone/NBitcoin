using System.Security.Cryptography;
using System.Text;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// One codex32 string (BIP-93): "ms1" + threshold + 4-character identifier + share index + payload + checksum.
	/// Share index "s" is the secret itself; any other index is a share. Always kept and printed in lowercase.
	/// </summary>
	public sealed class Codex32String
	{
		// Data part without the checksum, as 5-bit values: [0] threshold, [1..4] identifier, [5] share index, [6..] payload.
		internal readonly byte[] Data;

		internal Codex32String(byte[] data)
		{
			Data = data;
		}

		/// <summary>0 (unshared secret) or 2..9.</summary>
		public int Threshold => Codex32.Charset[Data[0]] - '0';

		public string Identifier => new string(new[] { Codex32.Charset[Data[1]], Codex32.Charset[Data[2]], Codex32.Charset[Data[3]], Codex32.Charset[Data[4]] });

		public char ShareIndex => Codex32.Charset[Data[5]];

		public bool IsSecret => ShareIndex == 's';

		/// <summary>Number of payload characters (26 for a 16-byte seed … 103 for a 64-byte one).</summary>
		public int PayloadLength => Data.Length - 6;

		public override string ToString()
		{
			var checksum = Codex32.CreateChecksum(Data);
			var sb = new StringBuilder(3 + Data.Length + checksum.Length);
			sb.Append("ms1");
			foreach (var d in Data)
				sb.Append(Codex32.Charset[d]);
			foreach (var d in checksum)
				sb.Append(Codex32.Charset[d]);
			return sb.ToString();
		}

		/// <summary>Parses and validates a codex32 string (ms32_decode of BIP-93). Throws FormatException with the reason.</summary>
		public static Codex32String Parse(string text)
		{
			if (text == null)
				throw new FormatException("The codex32 string is empty");
			text = text.Trim();
			foreach (var ch in text)
				if (ch < 33 || ch > 126)
					throw new FormatException("The codex32 string has spaces or characters that are not allowed");
			var lower = text.ToLowerInvariant();
			if (lower != text && text.ToUpperInvariant() != text)
				throw new FormatException("The codex32 string mixes upper and lower case");
			text = lower;
			int pos = text.LastIndexOf('1');
			if (pos < 2 || Array.IndexOf(Codex32.ValidLengths, text.Length) < 0)
				throw new FormatException($"A codex32 string has {string.Join(", ", Codex32.ValidLengths)} characters (this one has {text.Length})");
			if (text.Substring(0, pos) != "ms")
				throw new FormatException("A codex32 string starts with ms1");
			var data = new byte[text.Length - pos - 1];
			for (int i = 0; i < data.Length; i++)
			{
				int v = Codex32.Charset.IndexOf(text[pos + 1 + i]);
				if (v < 0)
					throw new FormatException($"'{text[pos + 1 + i]}' is not a codex32 character");
				data[i] = (byte)v;
			}
			if (char.IsLetter(text[pos + 1]))
				throw new FormatException("The threshold of a codex32 string is a digit");
			if (text[pos + 1] == '0' && text[pos + 6] != 's')
				throw new FormatException("A codex32 string with threshold 0 must be the secret (index s)");
			if (!Codex32.VerifyChecksum(data))
				throw new FormatException("The codex32 checksum is wrong: the string is damaged or mistyped");
			int checksumLength = Codex32.HrpExpandedLength + data.Length < 94 ? 13 : 15;
			return new Codex32String(data[..^checksumLength]);
		}

		public static bool TryParse(string text, out Codex32String? value)
		{
			try
			{
				value = Parse(text);
				return true;
			}
			catch (FormatException)
			{
				value = null;
				return false;
			}
		}
	}

	/// <summary>
	/// codex32 (BIP-93): Shamir's secret sharing of a BIP32 master seed over GF(32), with a BCH checksum in every
	/// string. Wallet Backup and TEV split the wallet's master seed with it: any implementation of BIP-93 can put
	/// the shares together again and get the seed, without this application.
	///
	///   seed (16, 20, 24, 28, 32 or 64 bytes) -> codex32 secret "ms1{k}{id}s…" -> k-1 random shares + the rest by
	///   Lagrange interpolation. Any k shares give the secret back; fewer give nothing.
	///
	/// Limits of the format: threshold 2..9, at most 31 shares per backup (the share index is one character, "s" is
	/// the secret). The code follows the Python reference of the BIP line by line (checked with its test vectors).
	/// </summary>
	public static class Codex32
	{
		public const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

		/// <summary>Share indexes in the order they are handed out (bech32 letters in alphabetical order, then digits; no "s").</summary>
		public const string ShareIndexes = "acdefghjklmnpqrtuvwxyz023456789";

		public const int MinThreshold = 2;
		public const int MaxThreshold = 9;
		public const int MaxShares = 31;

		/// <summary>Master seed sizes BIP-93 accepts, in bytes.</summary>
		public static readonly int[] SeedLengths = { 16, 20, 24, 28, 32, 64 };

		internal static readonly int[] ValidLengths = { 48, 54, 61, 67, 74, 127 };

		internal const int HrpExpandedLength = 5; // bech32_hrp_expand("ms")

		// ---- checksum (BCH code), regular: 13 characters ----
		private static readonly UInt128 RegularConst = Hex("10ce0795c2fd1e62a");
		private static readonly UInt128[] RegularGen =
		{
			Hex("19dc500ce73fde210"), Hex("1bfae00def77fe529"), Hex("1fbd920fffe7bee52"), Hex("1739640bdeee3fdad"), Hex("07729a039cfc75f5a"),
		};
		private static readonly UInt128 RegularMask = Hex("0fffffffffffffff");

		// ---- checksum, long (64-byte seeds): 15 characters ----
		private static readonly UInt128 LongConst = Hex("43381e570bf4798ab26");
		private static readonly UInt128[] LongGen =
		{
			Hex("3d59d273535ea62d897"), Hex("7a9becb6361c6c51507"), Hex("543f9b7e6c38d8a2a0e"), Hex("0c577eaeccf1990d13c"), Hex("1887f74f8dc71b10651"),
		};
		private static readonly UInt128 LongMask = Hex("3fffffffffffffffff");

		private static readonly UInt128 InitialResidue = 0x23181b3;

		private static UInt128 Hex(string hex) => UInt128.Parse(hex, System.Globalization.NumberStyles.HexNumber);

		private static UInt128 Polymod(IEnumerable<byte> values, bool longChecksum)
		{
			var gen = longChecksum ? LongGen : RegularGen;
			var mask = longChecksum ? LongMask : RegularMask;
			int shift = longChecksum ? 70 : 60;
			var residue = InitialResidue;
			foreach (var v in values)
			{
				int b = (int)(residue >> shift);
				residue = ((residue & mask) << 5) ^ v;
				for (int i = 0; i < 5; i++)
					if (((b >> i) & 1) != 0)
						residue ^= gen[i];
			}
			return residue;
		}

		internal static bool VerifyChecksum(byte[] dataWithChecksum)
		{
			int expanded = HrpExpandedLength + dataWithChecksum.Length;
			if (expanded >= 96)
				return expanded <= 1023 && Polymod(dataWithChecksum, true) == LongConst;
			return expanded <= 93 && Polymod(dataWithChecksum, false) == RegularConst;
		}

		internal static byte[] CreateChecksum(byte[] data)
		{
			bool longChecksum = HrpExpandedLength + data.Length + 13 > 93;
			int n = longChecksum ? 15 : 13;
			var polymod = Polymod(data.Concat(new byte[n]), longChecksum) ^ (longChecksum ? LongConst : RegularConst);
			var result = new byte[n];
			for (int i = 0; i < n; i++)
				result[i] = (byte)((polymod >> (5 * (n - 1 - i))) & 31);
			return result;
		}

		// ---- GF(32) ----
		private static readonly byte[] Inverse =
		{
			0, 1, 20, 24, 10, 8, 12, 29, 5, 11, 4, 9, 6, 28, 26, 31,
			22, 18, 17, 23, 2, 25, 16, 19, 3, 21, 14, 30, 13, 7, 27, 15,
		};

		private static int Mul(int a, int b)
		{
			int res = 0;
			for (int i = 0; i < 5; i++)
			{
				res ^= ((b >> i) & 1) != 0 ? a : 0;
				a *= 2;
				a ^= a >= 32 ? 41 : 0;
			}
			return res;
		}

		private static int[] Lagrange(int[] indexes, int x)
		{
			int n = 1;
			var c = new int[indexes.Length];
			for (int k = 0; k < indexes.Length; k++)
			{
				int i = indexes[k];
				n = Mul(n, i ^ x);
				int m = 1;
				foreach (var j in indexes)
					m = Mul(m, (i == j ? x : i) ^ j);
				c[k] = m;
			}
			var w = new int[indexes.Length];
			for (int k = 0; k < c.Length; k++)
				w[k] = Mul(n, Inverse[c[k]]);
			return w;
		}

		/// <summary>
		/// The string with share index <paramref name="index"/> of the same set (ms32_interpolate). Needs exactly
		/// threshold-many strings with the same threshold, identifier and length, and distinct indexes.
		/// </summary>
		public static Codex32String Interpolate(IReadOnlyList<Codex32String> shares, char index)
		{
			CheckSet(shares, exact: true);
			int x = Charset.IndexOf(char.ToLowerInvariant(index));
			if (x < 0)
				throw new ArgumentException($"'{index}' is not a codex32 character", nameof(index));
			foreach (var s in shares)
				if (s.Data[5] == x)
					return new Codex32String((byte[])s.Data.Clone());
			var w = Lagrange(shares.Select(s => (int)s.Data[5]).ToArray(), x);
			var res = new byte[shares[0].Data.Length];
			for (int i = 0; i < res.Length; i++)
			{
				int n = 0;
				for (int j = 0; j < shares.Count; j++)
					n ^= Mul(w[j], shares[j].Data[i]);
				res[i] = (byte)n;
			}
			return new Codex32String(res);
		}

		private static void CheckSet(IReadOnlyList<Codex32String> shares, bool exact)
		{
			if (shares == null || shares.Count == 0)
				throw new ArgumentException("No codex32 shares");
			var first = shares[0];
			int k = first.Threshold;
			if (k < MinThreshold)
				throw new ArgumentException("These codex32 strings are not shares (threshold 0)");
			foreach (var s in shares)
			{
				if (s.Threshold != k)
					throw new ArgumentException("The codex32 shares have different thresholds: they are not of the same backup");
				if (s.Identifier != first.Identifier)
					throw new ArgumentException($"The codex32 shares have different identifiers ({first.Identifier}, {s.Identifier}): they are not of the same backup");
				if (s.Data.Length != first.Data.Length)
					throw new ArgumentException("The codex32 shares have different lengths: they are not of the same backup");
			}
			if (shares.Select(s => s.ShareIndex).Distinct().Count() != shares.Count)
				throw new ArgumentException("The same codex32 share was given twice");
			if (exact ? shares.Count != k : shares.Count < k)
				throw new ArgumentException($"{k} codex32 shares are needed, {shares.Count} were given");
		}

		/// <summary>
		/// Puts the shares together and returns the secret (index s). With more than threshold-many shares, every
		/// extra share is checked against the others: a damaged or foreign share is reported instead of being mixed in.
		/// </summary>
		public static Codex32String Combine(IEnumerable<Codex32String> shares)
		{
			var list = shares.ToList();
			CheckSet(list, exact: false);
			int k = list[0].Threshold;
			var basis = list.Take(k).ToList();
			foreach (var extra in list.Skip(k))
			{
				var expected = Interpolate(basis, extra.ShareIndex);
				if (!expected.Data.AsSpan().SequenceEqual(extra.Data))
					throw new ArgumentException($"The codex32 share {extra.ShareIndex} does not agree with the others: one of the shares is wrong");
			}
			return Interpolate(basis, 's');
		}

		/// <summary>Same as <see cref="Combine(IEnumerable{Codex32String})"/> from the strings.</summary>
		public static Codex32String Combine(IEnumerable<string> shares) => Combine(shares.Select(Codex32String.Parse));

		/// <summary>
		/// Splits a codex32 secret (index s, threshold 2..9) into <paramref name="count"/> shares, indexes a, c, d, …
		/// The first threshold-1 shares are random (cryptographic RNG), the rest are interpolated (BIP-93 "For an
		/// existing secret"). The secret itself is not among the shares.
		/// </summary>
		public static IReadOnlyList<Codex32String> Split(Codex32String secret, int count)
		{
			if (!secret.IsSecret)
				throw new ArgumentException("Only a codex32 secret (index s) can be split", nameof(secret));
			int k = secret.Threshold;
			if (k < MinThreshold || k > MaxThreshold)
				throw new ArgumentException($"The threshold goes from {MinThreshold} to {MaxThreshold}", nameof(secret));
			if (count < k || count > MaxShares)
				throw new ArgumentException($"The number of shares goes from the threshold ({k}) to {MaxShares}", nameof(count));
			var initial = new List<Codex32String> { secret };
			var shares = new List<Codex32String>();
			for (int i = 0; i < k - 1; i++)
			{
				var data = new byte[secret.Data.Length];
				Array.Copy(secret.Data, data, 5);
				data[5] = (byte)Charset.IndexOf(ShareIndexes[i]);
				for (int p = 6; p < data.Length; p++)
					data[p] = (byte)RandomNumberGenerator.GetInt32(32);
				var share = new Codex32String(data);
				initial.Add(share);
				shares.Add(share);
			}
			for (int i = k - 1; i < count; i++)
				shares.Add(Interpolate(initial, ShareIndexes[i]));
			return shares;
		}

		/// <summary>A new random identifier (4 codex32 characters): every backup gets its own.</summary>
		public static string NewIdentifier()
		{
			var c = new char[4];
			for (int i = 0; i < 4; i++)
				c[i] = Charset[RandomNumberGenerator.GetInt32(32)];
			return new string(c);
		}

		/// <summary>The codex32 secret (index s) of a BIP32 master seed ("Master seed format"; padding bits = 0).</summary>
		public static Codex32String FromSeed(byte[] seed, string identifier, int threshold = 0)
		{
			if (seed == null || Array.IndexOf(SeedLengths, seed.Length) < 0)
				throw new ArgumentException($"A codex32 master seed has {string.Join(", ", SeedLengths)} bytes", nameof(seed));
			if (threshold != 0 && (threshold < MinThreshold || threshold > MaxThreshold))
				throw new ArgumentException($"The threshold is 0 or goes from {MinThreshold} to {MaxThreshold}", nameof(threshold));
			identifier = (identifier ?? "").ToLowerInvariant();
			if (identifier.Length != 4 || identifier.Any(ch => Charset.IndexOf(ch) < 0))
				throw new ArgumentException("The identifier has 4 codex32 characters", nameof(identifier));
			int payloadLength = (seed.Length * 8 + 4) / 5;
			var data = new byte[6 + payloadLength];
			data[0] = (byte)Charset.IndexOf((char)('0' + threshold));
			for (int i = 0; i < 4; i++)
				data[1 + i] = (byte)Charset.IndexOf(identifier[i]);
			data[5] = (byte)Charset.IndexOf('s');
			int acc = 0, bits = 0, o = 6;
			foreach (var b in seed)
			{
				acc = (acc << 8) | b;
				bits += 8;
				while (bits >= 5)
				{
					bits -= 5;
					data[o++] = (byte)((acc >> bits) & 31);
				}
			}
			if (bits > 0)
				data[o++] = (byte)((acc << (5 - bits)) & 31);
			acc = 0;
			return new Codex32String(data);
		}

		/// <summary>The BIP32 master seed of a codex32 secret (index s).</summary>
		public static byte[] ToSeed(Codex32String secret)
		{
			if (!secret.IsSecret)
				throw new ArgumentException("This codex32 string is a share, not the secret (index s)", nameof(secret));
			int totalBits = secret.PayloadLength * 5;
			int length = totalBits / 8;
			if (totalBits % 8 > 4 || Array.IndexOf(SeedLengths, length) < 0)
				throw new FormatException("This codex32 secret is not a master seed of a valid size");
			var seed = new byte[length];
			int acc = 0, bits = 0, o = 0;
			for (int i = 6; i < secret.Data.Length && o < length; i++)
			{
				acc = (acc << 5) | secret.Data[i];
				bits += 5;
				if (bits >= 8)
				{
					bits -= 8;
					seed[o++] = (byte)((acc >> bits) & 0xff);
				}
			}
			acc = 0;
			return seed;
		}

		/// <summary>
		/// Splits a master seed: <paramref name="count"/> codex32 shares, any <paramref name="threshold"/> of them give
		/// the seed back. A new random identifier unless one is given.
		/// </summary>
		public static IReadOnlyList<string> SplitSeed(byte[] seed, int threshold, int count, string? identifier = null)
		{
			if (threshold < MinThreshold || threshold > MaxThreshold)
				throw new ArgumentException($"The threshold goes from {MinThreshold} to {MaxThreshold}", nameof(threshold));
			var secret = FromSeed(seed, identifier ?? NewIdentifier(), threshold);
			try
			{
				return Split(secret, count).Select(s => s.ToString()).ToList();
			}
			finally
			{
				Array.Clear(secret.Data);
			}
		}

		/// <summary>The master seed from codex32 shares (or from the secret itself, a single "ms1…s…" string).</summary>
		public static byte[] CombineSeed(IEnumerable<string> shares)
		{
			var list = shares.Select(Codex32String.Parse).ToList();
			if (list.Count == 1 && list[0].IsSecret)
				return ToSeed(list[0]);
			var secret = Combine(list);
			try
			{
				return ToSeed(secret);
			}
			finally
			{
				Array.Clear(secret.Data);
			}
		}
	}
}
