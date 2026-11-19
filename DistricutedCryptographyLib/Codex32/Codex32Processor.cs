using System.Security.Cryptography;
using System.Text.Json;
using NBitcoin.DataEncoders;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// KB entry point for Wallet Backup and TEV with codex32 (BIP-93). Seeds travel as hex, share sets as a JSON array
	/// of "ms1…" strings (a GeneXus collection's ToJson). Every method returns JSON {success, error, …}.
	///
	///   Wallet Backup:  SplitSeed(seed, k, n) -> shares for the contacts;  CombineSeed(shares) -> seed
	///   TEV:            MaskSeed(seed) -> pad + masked (2-of-2: seed = pad XOR masked)
	///                   pad: SplitSeed among the restore group; masked: encrypted with the bounty KEY
	///                   restore: CombineSeed(shares) -> pad; UnmaskSeed(pad, masked) -> seed
	/// </summary>
	public class Codex32Processor
	{
		private static string Ok(object value) => JsonSerializer.Serialize(value);

		private static string Err(string message) => JsonSerializer.Serialize(new { success = false, error = message });

		private static byte[] SeedFromHex(string seedHex, string what)
		{
			seedHex = (seedHex ?? "").Trim();
			if (seedHex.Length == 0)
				throw new ArgumentException($"The {what} is empty: this wallet has no seed on this computer");
			byte[] seed;
			try
			{
				seed = Encoders.Hex.DecodeData(seedHex);
			}
			catch (FormatException)
			{
				throw new ArgumentException($"The {what} is not hexadecimal");
			}
			if (Array.IndexOf(Codex32.SeedLengths, seed.Length) < 0)
			{
				Array.Clear(seed);
				throw new ArgumentException($"The {what} has {seed.Length} bytes; codex32 takes {string.Join(", ", Codex32.SeedLengths)}");
			}
			return seed;
		}

		/// <summary>{success, error, identifier, shares[]}: <paramref name="count"/> shares, any <paramref name="threshold"/> give the seed.</summary>
		public string SplitSeed(string seedHex, int threshold, int count)
		{
			byte[]? seed = null;
			try
			{
				if (threshold < Codex32.MinThreshold || threshold > Codex32.MaxThreshold)
					return Err($"The minimum number of shares goes from {Codex32.MinThreshold} to {Codex32.MaxThreshold} (codex32)");
				if (count < threshold || count > Codex32.MaxShares)
					return Err($"The total number of shares goes from the minimum ({threshold}) to {Codex32.MaxShares} (codex32)");
				seed = SeedFromHex(seedHex, "seed");
				var shares = Codex32.SplitSeed(seed, threshold, count);
				return Ok(new { success = true, error = "", identifier = shares[0].Substring(4, 4), shares });
			}
			catch (Exception e) when (e is ArgumentException || e is FormatException)
			{
				return Err(e.Message);
			}
			finally
			{
				if (seed != null)
					Array.Clear(seed);
			}
		}

		/// <summary>{success, error, seed}: the seed (hex) from a JSON array of codex32 shares (or the secret itself).</summary>
		public string CombineSeed(string sharesJson)
		{
			try
			{
				var shares = JsonSerializer.Deserialize<List<string>>(sharesJson ?? "") ?? new List<string>();
				shares = shares.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList();
				if (shares.Count == 0)
					return Err("No codex32 shares");
				var seed = Codex32.CombineSeed(shares);
				try
				{
					return Ok(new { success = true, error = "", seed = Encoders.Hex.EncodeData(seed) });
				}
				finally
				{
					Array.Clear(seed);
				}
			}
			catch (JsonException)
			{
				return Err("The codex32 shares are not a JSON list of strings");
			}
			catch (Exception e) when (e is ArgumentException || e is FormatException)
			{
				return Err(e.Message);
			}
		}

		/// <summary>{success, error, pad, masked}: TEV 2-of-2. pad = random bytes as long as the seed, masked = seed XOR pad.</summary>
		public string MaskSeed(string seedHex)
		{
			byte[]? seed = null, pad = null, masked = null;
			try
			{
				seed = SeedFromHex(seedHex, "seed");
				pad = RandomNumberGenerator.GetBytes(seed.Length);
				masked = new byte[seed.Length];
				for (int i = 0; i < seed.Length; i++)
					masked[i] = (byte)(seed[i] ^ pad[i]);
				return Ok(new { success = true, error = "", pad = Encoders.Hex.EncodeData(pad), masked = Encoders.Hex.EncodeData(masked) });
			}
			catch (Exception e) when (e is ArgumentException || e is FormatException)
			{
				return Err(e.Message);
			}
			finally
			{
				if (seed != null) Array.Clear(seed);
				if (pad != null) Array.Clear(pad);
				if (masked != null) Array.Clear(masked);
			}
		}

		/// <summary>{success, error, seed}: TEV restore, seed = pad XOR masked.</summary>
		public string UnmaskSeed(string padHex, string maskedHex)
		{
			byte[]? pad = null, masked = null, seed = null;
			try
			{
				pad = SeedFromHex(padHex, "first part of the vault (from the restore group)");
				masked = SeedFromHex(maskedHex, "second part of the vault (from the bounty KEY)");
				if (pad.Length != masked.Length)
					return Err("The two parts of the vault have different lengths: they are not of the same activation");
				seed = new byte[pad.Length];
				for (int i = 0; i < pad.Length; i++)
					seed[i] = (byte)(pad[i] ^ masked[i]);
				return Ok(new { success = true, error = "", seed = Encoders.Hex.EncodeData(seed) });
			}
			catch (Exception e) when (e is ArgumentException || e is FormatException)
			{
				return Err(e.Message);
			}
			finally
			{
				if (pad != null) Array.Clear(pad);
				if (masked != null) Array.Clear(masked);
				if (seed != null) Array.Clear(seed);
			}
		}
	}
}
