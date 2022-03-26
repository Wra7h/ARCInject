using System;
using System.Runtime.InteropServices;

namespace Victim
{
    class Program
    {
        static void Main(string[] args)
        {
            // Fictionally, we need a space to store a restore point to try to save our process if a crash occurs.
            // So for demonstration purposes we're just gonna use VirtualAlloc to request 1 byte with PAGE_READWRITE protections.
            uint Commit = 0x1000;
            uint Reserve = 0x2000;
            uint PAGE_READWRITE = 0x4;
            IntPtr hAlloc = IntPtr.Zero;

            hAlloc = VirtualAlloc(IntPtr.Zero, 1, Commit | Reserve, PAGE_READWRITE);
            if (hAlloc == IntPtr.Zero)
            {
                Console.WriteLine("[!] VirtualAlloc failed! Press Enter to exit.");
                Console.ReadLine();
                Environment.Exit(0);
            }

            // Register the allocated space as the recovery callback for when the process crashes.
            uint ret = RegisterApplicationRecoveryCallback(hAlloc, IntPtr.Zero, 5, 0);
            if (ret == 0)
            {
                Console.WriteLine("[+] ApplicationRecoveryCallback has been set!");
                Console.WriteLine("[~] Try running the inject executable now or press enter to exit");
                Console.ReadLine();
            }

            //Cleanup the callback if the user presses "enter" before crashing this process.
            //But also if a crash happens this would never be reached.

            ret = UnregisterApplicationRecoveryCallback();
            if (ret == 0)
            {
                Console.WriteLine("[+] Successfully unregistered the recovery callback");
            }
        }

        //VirtualAlloc: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        //RegisterApplicationRecoveryCallback: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerapplicationrecoverycallback
        [DllImport("kernel32.dll")]
        static extern uint RegisterApplicationRecoveryCallback(IntPtr pRecoveryCallback, IntPtr pvParameter, int dwPingInterval, int dwFlags);

        // UnregisterApplicationRecoveryCallback: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-unregisterapplicationrecoverycallback
        [DllImport("kernel32.dll")]
        public static extern uint UnregisterApplicationRecoveryCallback();

    }
}
