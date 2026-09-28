# WinDragon - Core module
# Constants, output helpers, native-command infrastructure and the task engine.
# Functional code in this module is a one-to-one replica of vader\Invoke-ImperialMaintenance.ps1;
# only Write-Banner / Write-Section are restyled for the WinDragon interface.

#region ---------------------------------------------------------------- Constants

if (-not (Test-Path 'variable:global:LASTEXITCODE')) { $global:LASTEXITCODE = 0 }

$script:ScriptVersion = '2.0.0'
$script:Snapshot      = $null
$script:RunLogDir     = $null
$script:StartTime     = Get-Date
$script:Results       = New-Object System.Collections.Generic.List[psobject]
$script:Findings      = New-Object System.Collections.Generic.List[string]
$script:RebootNeeded  = $false
$script:TranscriptOn  = $false
$script:DirtyVolumes  = @()

# Levels expressed as ranks so tasks can declare a minimum.
$script:LevelRank = @{ 'Audit' = 2; 'Quick' = 1; 'Standard' = 2; 'Full' = 3 }
$script:CurrentRank = $script:LevelRank[$Level]
$script:ReadOnlyRun = ($Level -eq 'Audit')

# Windows 11 servicing map. Verified against Microsoft lifecycle guidance as of September 2026.
# Home/Pro get 24 months, Enterprise/Education 36 months from GA.
$script:BuildMap = @{
    22000 = @{ Name = '21H2'; Consumer = '2023-10-10'; Commercial = '2024-10-08' }
    22621 = @{ Name = '22H2'; Consumer = '2024-10-08'; Commercial = '2025-10-14' }
    22631 = @{ Name = '23H2'; Consumer = '2025-11-11'; Commercial = '2026-11-10' }
    26100 = @{ Name = '24H2'; Consumer = '2026-10-13'; Commercial = '2027-10-12' }
    26200 = @{ Name = '25H2'; Consumer = '2027-10-12'; Commercial = '2028-10-10' }
    26300 = @{ Name = '26H2'; Consumer = '2028-10-10'; Commercial = '2029-10-09' }
}

#endregion

#region ---------------------------------------------------------------- Output helpers

function Write-Banner {
    param([string]$Text)
    $line = '=' * 78
    Write-Host ''
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host ("  {0}" -f $Text.ToUpper()) -ForegroundColor Yellow
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ("[ {0} ] " -f $Text).PadRight(78, '=') -ForegroundColor Cyan
}

function Write-Info    { param([string]$m) Write-Host "    $m" -ForegroundColor Gray }
function Write-Good    { param([string]$m) Write-Host "    $m" -ForegroundColor Green }
function Write-Warn    { param([string]$m) Write-Host "    $m" -ForegroundColor Yellow }
function Write-Bad     { param([string]$m) Write-Host "    $m" -ForegroundColor Red }

function Add-Finding {
    param([string]$Text)
    if (-not $script:Findings.Contains($Text)) { $script:Findings.Add($Text) | Out-Null }
}

function ConvertTo-Gb {
    param([double]$Bytes)
    return [math]::Round($Bytes / 1GB, 2)
}

function ConvertTo-Mb {
    param([double]$Bytes)
    return [math]::Round($Bytes / 1MB, 2)
}

#endregion

#region ---------------------------------------------------------------- Infrastructure

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsSystemAccount {
    return ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
}

function Format-NativeArgument {
    param([string]$Value)
    if ($Value -eq '' -or $Value -match '[\s"]') {
        $escaped = $Value -replace '"', '\"'
        if ($escaped -match '\\+$') { $escaped += $Matches[0] }   # don't let a trailing \ escape our closing quote
        return '"' + $escaped + '"'
    }
    return $Value
}

function Invoke-NativeCommand {
    <#
        Runs a console executable with a hard timeout and closed stdin (so an unexpected prompt
        or UI request can't hang the run forever), strips the UTF-16 NUL padding that sfc.exe/
        dism.exe emit when redirected, and returns exit code plus clean text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 1800
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $FilePath
    $psi.Arguments              = (($ArgumentList | ForEach-Object { Format-NativeArgument $_ }) -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.RedirectStandardInput  = $true
    $psi.UseShellExecute        = $false

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    try {
        $null = $proc.Start()
    } catch {
        return [pscustomobject]@{ ExitCode = -1; Output = $_.Exception.GetBaseException().Message }
    }

    $proc.StandardInput.Close()   # nothing can prompt this process and hang the run
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        try { $proc.Kill() } catch { }
        return [pscustomobject]@{ ExitCode = -1; Output = "TIMEOUT after ${TimeoutSeconds}s: $FilePath $($ArgumentList -join ' ')" }
    }

    $raw = $stdoutTask.Result + $stderrTask.Result
    $clean = ($raw -replace "`0", '') -replace "`r`n\s*`r`n", "`r`n"
    return [pscustomobject]@{ ExitCode = $proc.ExitCode; Output = $clean.Trim() }
}

function Suspend-Sleep {
    <# Keeps the machine awake for the duration of the run (ES_SYSTEM_REQUIRED | ES_CONTINUOUS). #>
    if (-not ('WinDragon.Power' -as [type])) {
        Add-Type -Namespace WinDragon -Name Power -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern uint SetThreadExecutionState(uint esFlags);
'@ -ErrorAction SilentlyContinue
    }
    try { [WinDragon.Power]::SetThreadExecutionState(0x80000001) | Out-Null } catch { }
}

function Resume-Sleep {
    try { if ('WinDragon.Power' -as [type]) { [WinDragon.Power]::SetThreadExecutionState(0x80000000) | Out-Null } } catch { }
}

function Get-PendingRebootDetail {
    $reasons = @()
    $probe = @{
        'Component Based Servicing' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        'Windows Update'            = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    }
    foreach ($key in $probe.Keys) {
        if (Test-Path $probe[$key]) { $reasons += $key }
    }
    try {
        $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        if ($sm.PSObject.Properties.Name -contains 'PendingFileRenameOperations' -and $sm.PendingFileRenameOperations) {
            $reasons += 'Pending File Rename Operations'
        }
    } catch { }
    try {
        $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction Stop).ComputerName
        $target = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction Stop).ComputerName
        if ($active -ne $target) { $reasons += 'Pending Computer Rename' }
    } catch { }
    return $reasons
}

function Get-VolumeMediaType {
    param([Parameter(Mandatory)][char]$DriveLetter)
    try {
        $partition = Get-Partition -DriveLetter $DriveLetter -ErrorAction Stop
        $disk      = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
        $physical  = Get-PhysicalDisk -ErrorAction Stop |
                     Where-Object { $_.DeviceId -eq $disk.Number.ToString() } |
                     Select-Object -First 1
        if ($physical) { return $physical.MediaType }
    } catch { }
    return 'Unknown'
}

#endregion

#region ---------------------------------------------------------------- Task engine

function New-MaintenanceTask {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][scriptblock]$Action,
        [int]$MinLevel = 2,
        [switch]$ReadOnly,
        [scriptblock]$Precondition
    )
    [pscustomobject]@{
        Name         = $Name
        Category     = $Category
        Action       = $Action
        MinLevel     = $MinLevel
        ReadOnly     = [bool]$ReadOnly
        Precondition = $Precondition
    }
}

function Test-TaskSelected {
    param(
        [Parameter(Mandatory)][object]$Task,
        [string[]]$OnlyTask = $OnlyTask,
        [string[]]$SkipTask = $SkipTask
    )

    if ($OnlyTask) {
        foreach ($pattern in $OnlyTask) { if ($Task.Name -like $pattern) { return $true } }
        return $false
    }
    if ($SkipTask) {
        foreach ($pattern in $SkipTask) { if ($Task.Name -like $pattern) { return $false } }
    }
    if ($script:ReadOnlyRun -and -not $Task.ReadOnly) { return $false }
    if ($Task.MinLevel -gt $script:CurrentRank) { return $false }
    return $true
}

function Invoke-MaintenanceTask {
    param([Parameter(Mandatory)][object]$Task)

    if (-not (Test-TaskSelected -Task $Task)) {
        $script:Results.Add([pscustomobject]@{
            Category = $Task.Category; Task = $Task.Name; Status = 'Skipped'
            Seconds  = 0.0; Detail = 'Not selected for this level'
        }) | Out-Null
        return
    }

    if ($Task.Precondition) {
        $ok = $false
        try { $ok = [bool](& $Task.Precondition) } catch { $ok = $false }
        if (-not $ok) {
            Write-Section $Task.Name
            Write-Info 'Precondition not met - skipping.'
            $script:Results.Add([pscustomobject]@{
                Category = $Task.Category; Task = $Task.Name; Status = 'Skipped'
                Seconds  = 0.0; Detail = 'Precondition not met'
            }) | Out-Null
            return
        }
    }

    Write-Section $Task.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'
    $detail = ''

    try {
        $outcome = & $Task.Action
        if ($outcome -is [hashtable]) {
            if ($outcome.ContainsKey('Status')) { $status = $outcome.Status }
            if ($outcome.ContainsKey('Detail')) { $detail = $outcome.Detail }
        }
        elseif ($outcome -is [string]) {
            $detail = $outcome
        }
    }
    catch {
        $status = 'Failed'
        $detail = $_.Exception.Message
        Write-Bad "ERROR: $detail"
        Write-Verbose $_.ScriptStackTrace
    }
    finally {
        $sw.Stop()
    }

    $script:Results.Add([pscustomobject]@{
        Category = $Task.Category
        Task     = $Task.Name
        Status   = $status
        Seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        Detail   = $detail
    }) | Out-Null

    switch ($status) {
        'OK'       { Write-Good   ("[OK]       {0} ({1}s)" -f $Task.Name, [math]::Round($sw.Elapsed.TotalSeconds,1)) }
        'Repaired' { Write-Good   ("[REPAIRED] {0} ({1}s)" -f $Task.Name, [math]::Round($sw.Elapsed.TotalSeconds,1)) }
        'Warning'  { Write-Warn   ("[WARNING]  {0} ({1}s)" -f $Task.Name, [math]::Round($sw.Elapsed.TotalSeconds,1)) }
        'Failed'   { Write-Bad    ("[FAILED]   {0} ({1}s)" -f $Task.Name, [math]::Round($sw.Elapsed.TotalSeconds,1)) }
        default    { Write-Info   ("[{0}] {1}" -f $status, $Task.Name) }
    }
}

#endregion
