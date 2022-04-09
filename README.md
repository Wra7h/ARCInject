# AppRecoveryCallbackInject PoC

Application's can set a recovery point that holds data or information in case the process becomes hanged or crashes unexpectedly due to an unhandled exception.

"If the application encounters an unhandled exception or becomes unresponsive, Windows Error Reporting (WER) calls the specified recovery callback. You should use the callback to save data and state information." (ref: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerapplicationrecoverycallback)

Processes can acquire the recovery callback information of other processes using GetApplicationRecoveryCallback. This will give us the address that we can overwrite with our payload. After the payload is written to the victim process, `Inject.exe` calls CreateRemoteThread to invoke a crash. I've found a few processes that knew how to handle this way of crashing the process, so you may need to get creative if you decide to play around on your own. 

At the moment the PoC pieces are working for simple shellcode like popping calc. This is due to the amount of space the Victim.exe requests with VirtualAlloc. Bigger request = more space to write larger payloads. The amount of space requested by a process will most likely vary.  

**UPDATE**: It's even easier than I thought. Just calling the WerReportHang WinApi will trigger the execution of the payload. This version can be found under `/ARCInject/Program.cs`. So there's no need to find a crazy way to crash the process. Additionally, with the processes I've targeted during tested, there has been no need to change the memory protections with VirtualProtectEx. This API call is still in the PoC pieces, but I have removed it from the `ARCInject` project. 

I wrote a gist that's a scanner to see what processes might be using these callbacks. You can find it here:  
https://gist.github.com/Wra7h/7b6c2ad5d4970891195c167013373cc4

## Demo
PotatoQuality.gif
![Alt Text](/images/AppRecoverInject.gif)

Sysmon Event  
![Alt Text](/images/SysmonProcessCreation.png)

## PoC Usage
1. Generate shellcode (if necessary): `msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -f raw -o calc.bin`
2. Execute victim.exe
3. Execute `Inject.exe <C:\path\to\calc.bin>` in cmd or PowerShell.

## ARCInject Usage
1. Generate shellcode (if necessary): `msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -f raw -o calc.bin`
2. `.\ARCInject.exe <C:\path\to\calc.bin> <pid>`

## Compile
You can build the .sln in Visual Studio or do the following from cmd or PowerShell.  
1. Victim: `C:\windows\Microsoft.NET\Framework64\v3.5\csc.exe -out:PoC_Victim.exe .\PoC_Victim\Program.cs`
2. Inject: `C:\windows\Microsoft.NET\Framework64\v3.5\csc.exe -out:PoC_Inject.exe .\PoC_Inject\Program.cs`
3. ARCInject: `C:\windows\Microsoft.NET\Framework64\v3.5\csc.exe -out:ARCInject.exe .\ARCInject\Program.cs`

### References
RegisterApplicationRecoveryCallback:  
https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerapplicationrecoverycallback  

GetApplicationRecoveryCallback:  
https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getapplicationrecoverycallback

WerReportHang:  
https://docs.microsoft.com/en-us/windows/win32/api/errorrep/nf-errorrep-werreporthang
