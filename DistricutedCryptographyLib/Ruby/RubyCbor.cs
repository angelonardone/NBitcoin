using System.Buffers.Binary;
using System.Collections;
using System.Text;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// Minimal CBOR (RFC 8949) encoder / decoder for the Ruby RPC messages.
	///
	/// Ruby (and Jade) speak CBOR maps over the serial port: { "id", "method", "params" } out and { "id", "result" |
	/// "error" } or { "log" } back. Only what those messages use is supported: unsigned / negative integers, byte and
	/// text strings, arrays, maps, false / true / null and floats (decoded only). Tags are skipped; indefinite lengths
	/// are rejected. Written here so the library does not depend on another DLL.
	///
	/// Decoded values: long (ulong when above long.MaxValue), byte[], string, List&lt;object?&gt;,
	/// Dictionary&lt;string, object?&gt; (non-text keys are turned into text), bool, double and null.
	/// </summary>
	public static class RubyCbor
	{
		// A message larger than this is rejected (Ruby messages are a few KB; a signed PSBT can be some hundred KB).
		public const int MaxMessageSize = 4 * 1024 * 1024;

		private const int MaxDepth = 32;

		public static byte[] Encode(object? value)
		{
			using var ms = new MemoryStream();
			Write(ms, value, 0);
			return ms.ToArray();
		}

		private static void WriteHead(Stream s, int major, ulong v)
		{
			var mt = (byte)(major << 5);
			Span<byte> b = stackalloc byte[9];
			if (v < 24)
			{
				s.WriteByte((byte)(mt | (byte)v));
			}
			else if (v <= byte.MaxValue)
			{
				b[0] = (byte)(mt | 24);
				b[1] = (byte)v;
				s.Write(b[..2]);
			}
			else if (v <= ushort.MaxValue)
			{
				b[0] = (byte)(mt | 25);
				BinaryPrimitives.WriteUInt16BigEndian(b[1..], (ushort)v);
				s.Write(b[..3]);
			}
			else if (v <= uint.MaxValue)
			{
				b[0] = (byte)(mt | 26);
				BinaryPrimitives.WriteUInt32BigEndian(b[1..], (uint)v);
				s.Write(b[..5]);
			}
			else
			{
				b[0] = (byte)(mt | 27);
				BinaryPrimitives.WriteUInt64BigEndian(b[1..], v);
				s.Write(b[..9]);
			}
		}

		private static void Write(Stream s, object? value, int depth)
		{
			if (depth > MaxDepth)
				throw new FormatException("CBOR: nesting too deep");

			switch (value)
			{
				case null:
					s.WriteByte(0xF6);
					return;
				case bool b:
					s.WriteByte(b ? (byte)0xF5 : (byte)0xF4);
					return;
				case ulong u:
					WriteHead(s, 0, u);
					return;
				case sbyte or byte or short or ushort or int or uint or long:
					{
						var l = Convert.ToInt64(value);
						if (l >= 0)
							WriteHead(s, 0, (ulong)l);
						else
							WriteHead(s, 1, (ulong)(-1 - l));
						return;
					}
				case string str:
					{
						var bytes = Encoding.UTF8.GetBytes(str);
						WriteHead(s, 3, (ulong)bytes.Length);
						s.Write(bytes);
						return;
					}
				case byte[] bytes:
					WriteHead(s, 2, (ulong)bytes.Length);
					s.Write(bytes);
					return;
				case IDictionary<string, object?> map:
					WriteHead(s, 5, (ulong)map.Count);
					foreach (var kv in map)
					{
						Write(s, kv.Key, depth + 1);
						Write(s, kv.Value, depth + 1);
					}
					return;
				case IEnumerable list:
					{
						var items = list.Cast<object?>().ToList();
						WriteHead(s, 4, (ulong)items.Count);
						foreach (var item in items)
							Write(s, item, depth + 1);
						return;
					}
				default:
					throw new FormatException($"CBOR: cannot encode a {value.GetType().Name}");
			}
		}

		/// <summary>
		/// Tries to decode one CBOR item from buf[start..end). Returns false (and consumes nothing) when the data ends
		/// before the item is complete, so the caller can read more bytes and try again. Throws FormatException when
		/// the data is not valid CBOR.
		/// </summary>
		public static bool TryDecode(byte[] buf, int start, int end, out object? value, out int next)
		{
			var reader = new Reader(buf, start, end);
			try
			{
				value = reader.ReadItem(0);
				next = reader.Pos;
				return true;
			}
			catch (NeedMoreDataException)
			{
				value = null;
				next = start;
				return false;
			}
		}

		public static object? Decode(byte[] data)
		{
			if (!TryDecode(data, 0, data.Length, out var value, out var next))
				throw new FormatException("CBOR: truncated data");
			if (next != data.Length)
				throw new FormatException("CBOR: trailing data");
			return value;
		}

		private sealed class NeedMoreDataException : Exception
		{
		}

		private sealed class Reader
		{
			private readonly byte[] _b;
			private readonly int _end;

			public int Pos { get; private set; }

			public Reader(byte[] b, int start, int end)
			{
				_b = b;
				Pos = start;
				_end = end;
			}

			private byte ReadByte()
			{
				if (Pos >= _end)
					throw new NeedMoreDataException();
				return _b[Pos++];
			}

			private ReadOnlySpan<byte> Take(int n)
			{
				if (n > MaxMessageSize)
					throw new FormatException("CBOR: item too large");
				if (_end - Pos < n)
					throw new NeedMoreDataException();
				var span = new ReadOnlySpan<byte>(_b, Pos, n);
				Pos += n;
				return span;
			}

			private ulong ReadArgument(int ai)
			{
				return ai switch
				{
					< 24 => (ulong)ai,
					24 => ReadByte(),
					25 => BinaryPrimitives.ReadUInt16BigEndian(Take(2)),
					26 => BinaryPrimitives.ReadUInt32BigEndian(Take(4)),
					27 => BinaryPrimitives.ReadUInt64BigEndian(Take(8)),
					31 => throw new FormatException("CBOR: indefinite lengths are not supported"),
					_ => throw new FormatException("CBOR: reserved additional info")
				};
			}

			private int ReadLength(int ai)
			{
				var v = ReadArgument(ai);
				if (v > MaxMessageSize)
					throw new FormatException("CBOR: length too large");
				return (int)v;
			}

			public object? ReadItem(int depth)
			{
				if (depth > MaxDepth)
					throw new FormatException("CBOR: nesting too deep");

				var ib = ReadByte();
				var major = ib >> 5;
				var ai = ib & 0x1F;
				switch (major)
				{
					case 0:
						{
							var v = ReadArgument(ai);
							return v <= long.MaxValue ? (long)v : v;
						}
					case 1:
						{
							var v = ReadArgument(ai);
							if (v > long.MaxValue)
								throw new FormatException("CBOR: negative integer too large");
							return -1 - (long)v;
						}
					case 2:
						return Take(ReadLength(ai)).ToArray();
					case 3:
						return Encoding.UTF8.GetString(Take(ReadLength(ai)));
					case 4:
						{
							var n = ReadLength(ai);
							var list = new List<object?>(Math.Min(n, 1024));
							for (var i = 0; i < n; i++)
								list.Add(ReadItem(depth + 1));
							return list;
						}
					case 5:
						{
							var n = ReadLength(ai);
							var map = new Dictionary<string, object?>();
							for (var i = 0; i < n; i++)
							{
								var key = ReadItem(depth + 1);
								var keyText = key as string ?? Convert.ToString(key, System.Globalization.CultureInfo.InvariantCulture) ?? "";
								map[keyText] = ReadItem(depth + 1);
							}
							return map;
						}
					case 6:
						ReadArgument(ai); // the tag number is ignored
						return ReadItem(depth + 1);
					default:
						switch (ai)
						{
							case 20:
								return false;
							case 21:
								return true;
							case 22:
							case 23:
								return null;
							case 24:
								ReadByte(); // simple value: not used by Ruby
								return null;
							case 25:
								return (double)BitConverter.UInt16BitsToHalf(BinaryPrimitives.ReadUInt16BigEndian(Take(2)));
							case 26:
								return (double)BinaryPrimitives.ReadSingleBigEndian(Take(4));
							case 27:
								return BinaryPrimitives.ReadDoubleBigEndian(Take(8));
							default:
								if (ai < 20)
									return null; // unassigned simple values
								throw new FormatException("CBOR: invalid simple value");
						}
				}
			}
		}
	}
}
