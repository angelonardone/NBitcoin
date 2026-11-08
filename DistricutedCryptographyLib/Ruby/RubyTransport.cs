using System.IO.Ports;
using System.Net.Sockets;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// The byte pipe to a Ruby: the USB serial port of a real board, or TCP for the QEMU emulator.
	/// </summary>
	public interface IRubyTransport : IDisposable
	{
		void Write(byte[] data);

		/// <summary>
		/// Reads what is available, waiting at most timeoutMs. Returns 0 when nothing arrived in that time; throws
		/// IOException when the connection is closed.
		/// </summary>
		int Read(byte[] buffer, int offset, int count, int timeoutMs);

		string Description { get; }
	}

	/// <summary>TCP transport, used by the QEMU emulator (serial over TCP, port 30121 inside the container).</summary>
	public sealed class RubyTcpTransport : IRubyTransport
	{
		private readonly TcpClient _client;
		private readonly NetworkStream _stream;

		public string Description { get; }

		public RubyTcpTransport(string host, int port, int connectTimeoutMs = 5000)
		{
			_client = new TcpClient { NoDelay = true };
			if (!_client.ConnectAsync(host, port).Wait(connectTimeoutMs))
			{
				_client.Dispose();
				throw new IOException($"Timeout connecting to Ruby at {host}:{port}");
			}
			_stream = _client.GetStream();
			Description = $"tcp:{host}:{port}";
		}

		public void Write(byte[] data)
		{
			_stream.Write(data, 0, data.Length);
			_stream.Flush();
		}

		public int Read(byte[] buffer, int offset, int count, int timeoutMs)
		{
			var socket = _client.Client;
			var micros = timeoutMs <= 0 ? 0 : timeoutMs >= int.MaxValue / 1000 ? int.MaxValue : timeoutMs * 1000;
			if (!socket.Poll(micros, SelectMode.SelectRead))
				return 0;
			var n = socket.Receive(buffer, offset, count, SocketFlags.None);
			if (n == 0)
				throw new IOException("Ruby closed the connection");
			return n;
		}

		public void Dispose()
		{
			_stream.Dispose();
			_client.Dispose();
		}
	}

	/// <summary>USB serial transport of a real Ruby board on Windows (115200 8N1); Linux and macOS: RubyUnixSerialTransport.</summary>
	public sealed class RubySerialTransport : IRubyTransport
	{
		public static (int Vid, int Pid)[] KnownUsbIds => RubySerial.KnownUsbIds;

		private readonly SerialPort _port;

		public string Description { get; }

		public RubySerialTransport(string portName, int baudRate = 115200)
		{
			_port = new SerialPort(portName, baudRate, Parity.None, 8, StopBits.One)
			{
				Handshake = Handshake.None,
				WriteTimeout = 10000,
				ReadTimeout = 1000,
				ReadBufferSize = 64 * 1024,
				WriteBufferSize = 64 * 1024
			};
			_port.Open();
			// RTS / DTR set can reset the ESP32 (they drive EN / IO0 through the USB bridge)
			_port.RtsEnable = false;
			_port.DtrEnable = false;
			Description = $"serial:{portName}";
		}

		public static string[] ListPorts() => SerialPort.GetPortNames();

		public void Write(byte[] data)
		{
			_port.Write(data, 0, data.Length);
		}

		public int Read(byte[] buffer, int offset, int count, int timeoutMs)
		{
			_port.ReadTimeout = Math.Max(timeoutMs, 1);
			try
			{
				return _port.Read(buffer, offset, count);
			}
			catch (TimeoutException)
			{
				return 0;
			}
		}

		public void Dispose()
		{
			if (_port.IsOpen)
			{
				_port.RtsEnable = false;
				_port.DtrEnable = false;
				_port.Close();
			}
			_port.Dispose();
		}
	}
}
