using System.Runtime.InteropServices;

namespace DistricutedCryptographyLib
{
	/// <summary>
	/// The serial port of a Ruby, whatever the operating system: on Windows System.IO.Ports (RubySerialTransport);
	/// on Linux and macOS our own termios transport (RubyUnixSerialTransport), so the wallet needs neither the unix
	/// build of System.IO.Ports.dll nor its native library (the KB deploys the Windows build of System.IO.Ports.dll).
	/// </summary>
	public static class RubySerial
	{
		// USB-serial bridges of the ESP32 boards that run Jade / Ruby (same list as jadepy):
		// CP210x, CH9102, FTDI, CH340, ESP32-S3 native USB (JTAG / CDC).
		public static readonly (int Vid, int Pid)[] KnownUsbIds =
		{
			(0x10c4, 0xea60), (0x1a86, 0x55d4), (0x0403, 0x6001), (0x1a86, 0x7523), (0x303a, 0x4001), (0x303a, 0x1001)
		};

		public static IRubyTransport Open(string portName) =>
			OperatingSystem.IsWindows() ? OpenWindows(portName) : new RubyUnixSerialTransport(portName);

		// in its own method: System.IO.Ports is only touched on Windows
		private static IRubyTransport OpenWindows(string portName) => new RubySerialTransport(portName);

		/// <summary>The serial ports where a Ruby may be, the likely ones first.</summary>
		public static string[] ListPorts()
		{
			if (OperatingSystem.IsWindows())
				return ListWindows();
			if (OperatingSystem.IsLinux())
				return RubyUnixSerialTransport.ListLinuxPorts();
			if (OperatingSystem.IsMacOS())
				return RubyUnixSerialTransport.ListMacPorts();
			return Array.Empty<string>();
		}

		private static string[] ListWindows() => RubySerialTransport.ListPorts();
	}

	/// <summary>
	/// USB serial transport of a real Ruby board on Linux and macOS (115200 8N1, raw), through libc: open, termios,
	/// poll, read, write. Only non-variadic libc functions are called (variadic calls such as ioctl or fcntl are not
	/// safe through P/Invoke on Apple silicon); the port stays non-blocking and poll() gives the timeouts.
	/// DTR / RTS are left as the driver sets them when the port opens (both asserted, which does not reset the
	/// ESP32: its auto-reset circuit only acts when one is asserted without the other), as pyserial / jadepy do.
	/// </summary>
	public sealed class RubyUnixSerialTransport : IRubyTransport
	{
		private int _fd;

		public string Description { get; }

		private static bool Mac => OperatingSystem.IsMacOS();

		// open() flags
		private const int O_RDWR = 2;
		private static int O_NOCTTY => Mac ? 0x20000 : 0x100;
		private static int O_NONBLOCK => Mac ? 0x4 : 0x800;

		// termios: c_cflag offset / size and the flags we add on top of cfmakeraw (glibc / musl vs Darwin)
		private static int CflagOffset => Mac ? 16 : 8;
		private static ulong CLOCAL => Mac ? 0x8000UL : 0x800UL;
		private static ulong CREAD => Mac ? 0x800UL : 0x80UL;
		private static ulong CSTOPB => Mac ? 0x400UL : 0x40UL;
		private static ulong PARENB => Mac ? 0x1000UL : 0x100UL;
		private static ulong CRTSCTS => Mac ? 0x30000UL : 0x80000000UL;
		private static int TCIOFLUSH => Mac ? 3 : 2;
		private const int TCSANOW = 0;
		private const uint LinuxB115200 = 0x1002;   // Darwin uses the plain number 115200

		private const short POLLIN = 0x1, POLLOUT = 0x4, POLLERR = 0x8, POLLHUP = 0x10, POLLNVAL = 0x20;
		private static int EAGAIN => Mac ? 35 : 11;
		private const int EINTR = 4;

		[StructLayout(LayoutKind.Sequential)]
		private struct PollFd
		{
			public int fd;
			public short events;
			public short revents;
		}

		[DllImport("libc", SetLastError = true)] private static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
		[DllImport("libc", SetLastError = true)] private static extern int close(int fd);
		[DllImport("libc", SetLastError = true)] private static extern nint read(int fd, byte[] buf, nuint count);
		[DllImport("libc", SetLastError = true)] private static extern nint write(int fd, byte[] buf, nuint count);
		[DllImport("libc", SetLastError = true)] private static extern int poll(ref PollFd fds, nuint nfds, int timeout);
		[DllImport("libc", SetLastError = true)] private static extern int tcgetattr(int fd, byte[] termios);
		[DllImport("libc", SetLastError = true)] private static extern int tcsetattr(int fd, int optionalActions, byte[] termios);
		[DllImport("libc")] private static extern void cfmakeraw(byte[] termios);
		[DllImport("libc", EntryPoint = "cfsetspeed", SetLastError = true)] private static extern int cfsetspeedLinux(byte[] termios, uint speed);
		[DllImport("libc", EntryPoint = "cfsetspeed", SetLastError = true)] private static extern int cfsetspeedMac(byte[] termios, nuint speed);
		[DllImport("libc", SetLastError = true)] private static extern int tcflush(int fd, int queueSelector);

		public RubyUnixSerialTransport(string portName)
		{
			_fd = open(portName, O_RDWR | O_NOCTTY | O_NONBLOCK);
			if (_fd < 0)
				throw new IOException($"Can not open {portName}: {Error(Marshal.GetLastPInvokeError())}");
			try
			{
				// termios is at most 72 bytes (Darwin 64-bit); a bigger buffer is harmless
				var t = new byte[256];
				Check(tcgetattr(_fd, t), "tcgetattr");
				cfmakeraw(t);
				Check(Mac ? cfsetspeedMac(t, 115200) : cfsetspeedLinux(t, LinuxB115200), "cfsetspeed");
				// 8N1 (cfmakeraw sets CS8), no flow control, ignore modem lines, enable the receiver
				var cflag = Mac ? BitConverter.ToUInt64(t, CflagOffset) : BitConverter.ToUInt32(t, CflagOffset);
				cflag = (cflag | CLOCAL | CREAD) & ~(CSTOPB | PARENB | CRTSCTS);
				if (Mac)
					BitConverter.TryWriteBytes(t.AsSpan(CflagOffset, 8), cflag);
				else
					BitConverter.TryWriteBytes(t.AsSpan(CflagOffset, 4), (uint)cflag);
				Check(tcsetattr(_fd, TCSANOW, t), "tcsetattr");
				tcflush(_fd, TCIOFLUSH);
			}
			catch
			{
				close(_fd);
				_fd = -1;
				throw;
			}
			Description = $"serial:{portName}";
		}

		public void Write(byte[] data)
		{
			var pending = data;
			var deadline = Environment.TickCount64 + 10_000;
			while (pending.Length > 0)
			{
				var n = write(_fd, pending, (nuint)pending.Length);
				if (n > 0)
				{
					pending = pending.AsSpan((int)n).ToArray();
					continue;
				}
				var err = Marshal.GetLastPInvokeError();
				if (n < 0 && err != EAGAIN && err != EINTR)
					throw new IOException($"Ruby write failed: {Error(err)}");
				var left = (int)(deadline - Environment.TickCount64);
				if (left <= 0)
					throw new TimeoutException("Ruby write timed out");
				Wait(POLLOUT, left);
			}
		}

		public int Read(byte[] buffer, int offset, int count, int timeoutMs)
		{
			if (count <= 0)
				return 0;
			if (!Wait(POLLIN, Math.Max(timeoutMs, 0)))
				return 0;
			var tmp = new byte[count];
			var n = read(_fd, tmp, (nuint)count);
			if (n > 0)
			{
				Buffer.BlockCopy(tmp, 0, buffer, offset, (int)n);
				return (int)n;
			}
			var err = Marshal.GetLastPInvokeError();
			if (n < 0 && (err == EAGAIN || err == EINTR))
				return 0;
			// 0 = end of file (the device went away), or an error
			throw new IOException(n == 0 ? "Ruby was disconnected" : $"Ruby read failed: {Error(err)}");
		}

		/// <summary>True when the port is ready for the events; false on timeout. Throws when the device is gone.</summary>
		private bool Wait(short events, int timeoutMs)
		{
			var deadline = Environment.TickCount64 + timeoutMs;
			while (true)
			{
				var pfd = new PollFd { fd = _fd, events = events };
				var left = (int)Math.Max(0, deadline - Environment.TickCount64);
				var r = poll(ref pfd, 1, left);
				if (r > 0)
				{
					if ((pfd.revents & POLLNVAL) != 0)
						throw new IOException("Ruby port is closed");
					if ((pfd.revents & (POLLERR | POLLHUP)) != 0 && (pfd.revents & events) == 0)
						throw new IOException("Ruby was disconnected");
					return true;
				}
				if (r == 0)
					return false;
				var err = Marshal.GetLastPInvokeError();
				if (err != EINTR)
					throw new IOException($"Ruby poll failed: {Error(err)}");
			}
		}

		private static void Check(int result, string call)
		{
			if (result != 0)
				throw new IOException($"{call} failed: {Error(Marshal.GetLastPInvokeError())}");
		}

		private static string Error(int errno) => errno switch
		{
			2 => "no such device (unplugged?)",
			13 => "permission denied (on Linux add the user to the 'dialout' group, then log in again)",
			16 => "the port is busy (another program has it open)",
			_ => $"errno {errno}"
		};

		public void Dispose()
		{
			if (_fd >= 0)
			{
				close(_fd);
				_fd = -1;
			}
		}

		// ---------------------------------------------------------------- ports

		/// <summary>
		/// Linux: /dev/ttyUSB* (CP210x, CH340, FTDI) and /dev/ttyACM* (CH9102, ESP32-S3 native USB); the ones whose USB
		/// VID:PID (read from /sys) is a known Ruby bridge come first, the others after (no /sys in some containers).
		/// </summary>
		public static string[] ListLinuxPorts()
		{
			var known = new List<string>();
			var other = new List<string>();
			foreach (var dev in Glob("/dev", "ttyUSB*").Concat(Glob("/dev", "ttyACM*")).OrderBy(p => p, StringComparer.Ordinal))
			{
				var id = LinuxUsbId(Path.GetFileName(dev));
				if (id != null && RubySerial.KnownUsbIds.Contains(id.Value))
					known.Add(dev);
				else
					other.Add(dev);
			}
			return known.Concat(other).ToArray();
		}

		private static (int Vid, int Pid)? LinuxUsbId(string ttyName)
		{
			try
			{
				var link = new DirectoryInfo($"/sys/class/tty/{ttyName}/device");
				var target = link.ResolveLinkTarget(true) as DirectoryInfo ?? link;
				for (var dir = target; dir != null && dir.FullName.StartsWith("/sys/", StringComparison.Ordinal); dir = dir.Parent)
				{
					var vid = Path.Combine(dir.FullName, "idVendor");
					var pid = Path.Combine(dir.FullName, "idProduct");
					if (File.Exists(vid) && File.Exists(pid))
						return (Convert.ToInt32(File.ReadAllText(vid).Trim(), 16), Convert.ToInt32(File.ReadAllText(pid).Trim(), 16));
				}
			}
			catch (Exception)
			{
				// no /sys information
			}
			return null;
		}

		/// <summary>
		/// macOS: the "call-out" devices /dev/cu.* of USB serial bridges (cu.usbserial-*, cu.wchusbserial*, cu.usbmodem*,
		/// cu.SLAB_USBtoUART*); never the tty.* twins (they wait for carrier) nor Bluetooth / debug ports.
		/// </summary>
		public static string[] ListMacPorts()
		{
			string[] likely = { "cu.wchusbserial", "cu.usbserial", "cu.usbmodem", "cu.SLAB_USBtoUART" };
			return Glob("/dev", "cu.*")
				.Where(p => likely.Any(l => Path.GetFileName(p).StartsWith(l, StringComparison.Ordinal)))
				// the WCH driver creates both cu.wchusbserialX and cu.usbserial-X for a CH9102: prefer the WCH one
				.OrderBy(p => Path.GetFileName(p).StartsWith("cu.wchusbserial", StringComparison.Ordinal) ? 0 : 1)
				.ThenBy(p => p, StringComparer.Ordinal)
				.ToArray();
		}

		private static IEnumerable<string> Glob(string dir, string pattern)
		{
			try
			{
				return Directory.GetFiles(dir, pattern);
			}
			catch (Exception)
			{
				return Array.Empty<string>();
			}
		}
	}
}
