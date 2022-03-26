# AppRecoveryCallbackInject

Application's can set a recovery point that holds data or information in case the process becomes hanged or crashes unexpectedly.

"If the application encounters an unhandled exception or becomes unresponsive, Windows Error Reporting (WER) calls the specified recovery callback. You should use the callback to save data and state information." (ref: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerapplicationrecoverycallback)

Processes can acquire the recovery callback information of other processes using GetApplicationRecoveryCallback. This will give us the address that we can overwrite with our payload. After the payload is written to the victim process, `Inject.exe` calls CreateRemoteThread to invoke a crash. This step isn't completely necessary as a crash could just happen if given enough time and exceptions are poorly handled by the target process. At the moment it's working for simple shellcode like popping calc.

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
RegisterApplicationRecoveryCallback: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerapplicationrecoverycallback
GetApplicationRecoveryCallback: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getapplicationrecoverycallback
