# AppRecoveryCallbackInject PoC

Application's can set a recovery point that holds data or information in case the process becomes hanged or crashes unexpectedly due to an unhandled exception.

"If the application encounters an unhandled exception or becomes unresponsive, Windows Error Reporting (WER) calls the specified recovery callback. You should use the callback to save data and state information." (ref: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerapplicationrecoverycallback)

Processes can acquire the recovery callback information of other processes using GetApplicationRecoveryCallback. This will give us the address that we can overwrite with our payload. After the payload is written to the victim process, `Inject.exe` calls CreateRemoteThread to invoke a crash. I've found a few processes that knew how to handle this way of crashing the process, so you may need to get creative if you decide to play around on your own. 

At the moment it's working for simple shellcode like popping calc. This is due to the amount of space the Victim.exe requests with VirtualAlloc. Bigger request = more space to write larger payloads. The amount of space requested by a process will most likely vary process to process depending on the amount of data in wishes to save as the recovery. If you wish to play around with larger payloads, change the "1" to something bigger in the `/Victim/Program.cs` before compiling.

I wrote a gist that's a scanner to see what processes might be using these callbacks. You can find it here: https://gist.github.com/Wra7h/ec76ad51f0961969fbf52ae9adf06734

## Demo
PotatoQuality.gif
![Alt Text](/images/AppRecoverInject.gif)

Sysmon Event  
![Alt Text](/images/SysmonProcessCreation.png)

## Usage
1. Generate shellcode (if necessary): `msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -f raw -o calc.bin`
2. Execute victim.exe
3. Execute `Inject.exe <C:\path\to\calc.bin>` in cmd or PowerShell.

## Compile
The repo contains 2 things that need to be compiled: the victim executable and the inject executable. You can build the .sln in Visual Studio or do the following from cmd or PowerShell.  
1. Victim: `C:\windows\Microsoft.NET\Framework64\v3.5\csc.exe -out:Victim.exe .\Victim\Program.cs`
2. Inject: `C:\windows\Microsoft.NET\Framework64\v3.5\csc.exe -out:Inject.exe .\AppRecoveryCallbackInject\Program.cs`

### References
RegisterApplicationRecoveryCallback:  
https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerapplicationrecoverycallback  

GetApplicationRecoveryCallback:  
https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getapplicationrecoverycallback
