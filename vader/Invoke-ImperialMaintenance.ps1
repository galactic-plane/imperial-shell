<#PSScriptInfo
.VERSION 1.0.0
.GUID 8f3c2a51-7b64-4d9e-9a2f-11c0de5ab100
.AUTHOR Vader
.COPYRIGHT (c) 2026
.TAGS Windows11 Maintenance DISM SFC CHKDSK Defender WindowsUpdate Cleanup Health
.DESCRIPTION Imperial Maintenance Protocol - end-to-end Windows 11 health, repair, cleanup and reporting.
#>

<#
.SYNOPSIS
    Imperial Maintenance Protocol - comprehensive Windows 11 maintenance, repair, cleanup and reporting.

.DESCRIPTION
    A single-pass maintenance run for Windows 11 (24H2 / 25H2 / 26H2) that executes, in the
    correct dependency order:

        1.  Pre-flight   - elevation, OS/build identification, servicing lifecycle check,
                           free space, battery, sleep suppression, system restore point.
        2.  Inventory    - hardware, firmware, storage, memory, uptime baseline.
        3.  Integrity    - DISM CheckHealth -> ScanHealth -> RestoreHealth, then SFC /scannow,
                           then component store analysis + cleanup. This order matters: SFC
                           repairs protected files FROM the component store, so the store must
                           be healthy first or SFC has no good source to copy from.
        4.  Storage      - physical disk health, SMART/reliability counters, NTFS online scan,
                           SSD ReTrim / HDD defrag, optional CHKDSK scheduling.
        5.  Servicing    - Windows Update scan (+ optional install), winget app upgrades,
                           PowerShell module/help refresh, optional Windows Update stack repair.
        6.  Security     - Defender platform/signature update, quick scan, firewall, BitLocker,
                           Secure Boot / TPM posture.
        7.  Cleanup      - temp, WER, shader cache, Delivery Optimization, Windows Update download cache,
                           Recycle Bin, DNS cache, optional Disk Cleanup (cleanmgr) profile.
        8.  Diagnostics  - critical/error event review, bugcheck + minidump review, driver problems,
                           WMI repository verification, pending-reboot detection.
        9.  Report       - console summary table, JSON result set, and a standalone HTML report.

    Everything is task-based. Each task reports OK / Repaired / Warning / Failed / Skipped with a
    duration, so a run is auditable rather than a wall of console noise.

.PARAMETER Level
    Audit    - read-only. Diagnoses and reports, changes nothing. Safe to run any time.
    Quick    - fast health pass: DISM CheckHealth, disk health, temp cleanup, update scan.
    Standard - default. Full DISM repair chain, SFC, storage optimization, cleanup, diagnostics.
    Full     - Standard plus component store cleanup, Windows Update download cache purge, deeper
               log pruning, sleep study, and an icon/thumbnail cache size report (not deleted).

.PARAMETER SkipTask
    One or more task names (or wildcards) to skip. See -ListTasks.

.PARAMETER OnlyTask
    Run only the named tasks (wildcards allowed). Overrides -Level selection, but -Level Audit
    still never runs a task that modifies the system.

.PARAMETER ListTasks
    Print the task catalogue and exit.

.PARAMETER InstallWindowsUpdates
    Download and install pending Windows Updates, including optional ones (preview cumulative
    updates, optional drivers and any optional feature update Windows Update offers). Without
    this the script only scans and reports.

.PARAMETER UpgradeApps
    Run 'winget upgrade --all' (winget source + msstore source, so Microsoft Store apps are
    included too) for installed packages. Skipped automatically under SYSTEM.

.PARAMETER IncludeDefenderScan
    Run a Microsoft Defender quick scan (signatures are always refreshed regardless).

.PARAMETER ScheduleChkdsk
    Schedule a full CHKDSK /F /R on the system volume for the next reboot. Only do this when the
    online NTFS scan reports corruption - a /R pass on a large volume can take hours.

.PARAMETER ResetComponentStoreBase
    Add /ResetBase to the component store cleanup. Reclaims the most space but makes every
    currently-installed update permanent (they can no longer be uninstalled). Full level only.

.PARAMETER RepairWindowsUpdateStack
    Stop the servicing stack, rename SoftwareDistribution and catroot2, then restart it. Use only
    when Windows Update itself is broken. Forces a reboot recommendation.

.PARAMETER UseDiskCleanup
    Drive cleanmgr.exe with a scripted sageset profile in addition to the script's own cleanup.

.PARAMETER SkipRestorePoint
    Do not attempt to create a System Restore checkpoint before making changes.

.PARAMETER DismSource
    Optional repair source for DISM /RestoreHealth (e.g. 'D:\sources\install.wim:1' or a mounted
    folder). Used when Windows Update cannot supply payload (error 0x800F081F).

.PARAMETER EventLogDays
    How many days of System/Application critical + error events to summarise. Default 7.

.PARAMETER LogRoot
    Root folder for transcripts, JSON and HTML reports. Default %ProgramData%\ImperialMaintenance.

.PARAMETER RegisterScheduledTask
    Register a weekly SYSTEM scheduled task that runs this script at Standard level, then exit.

.PARAMETER NoElevatePrompt
    Fail instead of relaunching elevated when not running as administrator.

.EXAMPLE
    .\Invoke-ImperialMaintenance.ps1 -Level Audit
    Read-only health assessment. Nothing is modified.

.EXAMPLE
    .\Invoke-ImperialMaintenance.ps1
    Standard maintenance pass with restore point, DISM/SFC repair chain, cleanup and reporting.

.EXAMPLE
    .\Invoke-ImperialMaintenance.ps1 -Level Full -InstallWindowsUpdates -UpgradeApps -IncludeDefenderScan
    The works. Expect 30-90 minutes and plan for a reboot.

.EXAMPLE
    .\Invoke-ImperialMaintenance.ps1 -OnlyTask 'DISM*','SFC*' -Verbose
    Run just the integrity repair chain.

.NOTES
    Target     : Windows 11 (build 22000+), validated against 24H2 / 25H2 / 26H2 servicing behaviour.
    Shell      : PowerShell 7.x preferred; remains compatible with Windows PowerShell 5.1.
    Privileges : Administrator required (self-elevates unless -NoElevatePrompt).
    Safety     : Supports -WhatIf / -Confirm on every mutating task.
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Audit', 'Quick', 'Standard', 'Full')]
    [string]$Level = 'Standard',

    [string[]]$SkipTask,
    [string[]]$OnlyTask,
    [switch]$ListTasks,

    [switch]$InstallWindowsUpdates,
    [switch]$UpgradeApps,
    [switch]$IncludeDefenderScan,
    [switch]$ScheduleChkdsk,
    [switch]$ResetComponentStoreBase,
    [switch]$RepairWindowsUpdateStack,
    [switch]$UseDiskCleanup,
    [switch]$SkipRestorePoint,

    [string]$DismSource,

    [ValidateRange(1, 90)]
    [int]$EventLogDays = 7,

    [string]$LogRoot = (Join-Path $env:ProgramData 'ImperialMaintenance'),

    [switch]$RegisterScheduledTask,
    [switch]$NoElevatePrompt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'Continue'

#region ---------------------------------------------------------------- Constants

if (-not (Test-Path 'variable:global:LASTEXITCODE')) { $global:LASTEXITCODE = 0 }

$script:ScriptVersion = '1.0.0'
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
    Write-Host $line -ForegroundColor DarkRed
    Write-Host ("  {0}" -f $Text.ToUpper()) -ForegroundColor Red
    Write-Host $line -ForegroundColor DarkRed
}

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ("-- {0} " -f $Text).PadRight(78, '-') -ForegroundColor DarkCyan
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
    if (-not ('Imperial.Power' -as [type])) {
        Add-Type -Namespace Imperial -Name Power -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern uint SetThreadExecutionState(uint esFlags);
'@ -ErrorAction SilentlyContinue
    }
    try { [Imperial.Power]::SetThreadExecutionState(0x80000001) | Out-Null } catch { }
}

function Resume-Sleep {
    try { if ('Imperial.Power' -as [type]) { [Imperial.Power]::SetThreadExecutionState(0x80000000) | Out-Null } } catch { }
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

    # Audit stays read-only even when -OnlyTask names a mutating task.
    if ($script:ReadOnlyRun -and -not $Task.ReadOnly) { return $false }
    if ($OnlyTask) {
        foreach ($pattern in $OnlyTask) { if ($Task.Name -like $pattern) { return $true } }
        return $false
    }
    if ($SkipTask) {
        foreach ($pattern in $SkipTask) { if ($Task.Name -like $pattern) { return $false } }
    }
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

#region ---------------------------------------------------------------- Task: inventory

function Get-SystemSnapshot {
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $bios = Get-CimInstance Win32_BIOS
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $build = [int]$cv.CurrentBuildNumber
    $ubr   = 0
    if ($cv.PSObject.Properties.Name -contains 'UBR') { $ubr = [int]$cv.UBR }

    $displayVersion = 'Unknown'
    if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') { $displayVersion = $cv.DisplayVersion }

    [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        Caption        = $os.Caption
        Edition        = $cv.EditionID
        DisplayVersion = $displayVersion
        Build          = $build
        UBR            = $ubr
        FullBuild      = "$build.$ubr"
        InstallDate    = $os.InstallDate
        LastBoot       = $os.LastBootUpTime
        UptimeHours    = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
        Cpu            = $cpu.Name.Trim()
        Cores          = $cpu.NumberOfCores
        Threads        = $cpu.NumberOfLogicalProcessors
        MemoryGb       = ConvertTo-Gb $cs.TotalPhysicalMemory
        FreeMemoryGb   = ConvertTo-Gb ($os.FreePhysicalMemory * 1KB)
        BiosVersion    = ($bios.SMBIOSBIOSVersion)
        BiosDate       = $bios.ReleaseDate
        Serial         = $bios.SerialNumber
        PowerShell     = $PSVersionTable.PSVersion.ToString()
    }
}

function Invoke-InventoryTask {
    $snap = Get-SystemSnapshot
    $script:Snapshot = $snap

    Write-Info ("Host        : {0}  ({1} {2})" -f $snap.ComputerName, $snap.Manufacturer, $snap.Model)
    Write-Info ("OS          : {0} {1} - build {2}" -f $snap.Caption, $snap.DisplayVersion, $snap.FullBuild)
    Write-Info ("Edition     : {0}" -f $snap.Edition)
    Write-Info ("CPU         : {0} ({1}C/{2}T)" -f $snap.Cpu, $snap.Cores, $snap.Threads)
    Write-Info ("Memory      : {0} GB total, {1} GB free" -f $snap.MemoryGb, $snap.FreeMemoryGb)
    Write-Info ("Firmware    : {0} ({1:yyyy-MM-dd})" -f $snap.BiosVersion, $snap.BiosDate)
    Write-Info ("Uptime      : {0} hours (last boot {1:yyyy-MM-dd HH:mm})" -f $snap.UptimeHours, $snap.LastBoot)
    Write-Info ("PowerShell  : {0}" -f $snap.PowerShell)

    if ($snap.UptimeHours -gt 336) {
        Add-Finding ("System has been up {0} hours. Long uptime defers servicing work and leaks handles - reboot soon." -f $snap.UptimeHours)
        return @{ Status = 'Warning'; Detail = "Uptime $($snap.UptimeHours)h" }
    }
    return @{ Status = 'OK'; Detail = "$($snap.Caption) $($snap.DisplayVersion) build $($snap.FullBuild)" }
}

function Invoke-LifecycleTask {
    $snap = $script:Snapshot
    if (-not $snap) { $snap = Get-SystemSnapshot; $script:Snapshot = $snap }

    if ($snap.Build -lt 22000) {
        Write-Warn 'This host is not running Windows 11. Several tasks will be skipped or behave differently.'
        return @{ Status = 'Warning'; Detail = 'Not Windows 11' }
    }

    $entry = $script:BuildMap[$snap.Build]
    if (-not $entry) {
        Write-Info ("Build {0} is not in the lifecycle map (Insider or newer than this script)." -f $snap.Build)
        return @{ Status = 'OK'; Detail = "Unmapped build $($snap.Build)" }
    }

    $isCommercial = $snap.Edition -match 'Enterprise|Education|IoTEnterprise'
    $eolString = if ($isCommercial) { $entry.Commercial } else { $entry.Consumer }
    $eol = [datetime]::ParseExact($eolString, 'yyyy-MM-dd', $null)
    $daysLeft = [math]::Round(($eol - (Get-Date)).TotalDays, 0)

    Write-Info ("Servicing   : Windows 11 {0} ({1} track)" -f $entry.Name, $(if ($isCommercial) { 'Enterprise/Education' } else { 'Home/Pro' }))
    Write-Info ("End of updates: {0:yyyy-MM-dd} ({1} days remaining)" -f $eol, $daysLeft)

    if ($daysLeft -lt 0) {
        Write-Bad 'This Windows 11 version no longer receives security updates. Upgrade immediately.'
        Add-Finding ("Windows 11 {0} is past end of servicing ({1:yyyy-MM-dd}). Upgrade to a supported feature update." -f $entry.Name, $eol)
        return @{ Status = 'Failed'; Detail = "$($entry.Name) out of support" }
    }
    if ($daysLeft -lt 120) {
        Write-Warn 'Approaching end of servicing. Plan the feature update now.'
        Add-Finding ("Windows 11 {0} loses updates on {1:yyyy-MM-dd} ({2} days). Schedule the feature update." -f $entry.Name, $eol, $daysLeft)
        return @{ Status = 'Warning'; Detail = "$($entry.Name) EOL in $daysLeft days" }
    }
    return @{ Status = 'OK'; Detail = "$($entry.Name) supported until $eolString" }
}

function Invoke-FreeSpaceTask {
    $sysDrive = $env:SystemDrive.TrimEnd(':')
    $vol = Get-Volume -DriveLetter $sysDrive -ErrorAction Stop
    $freeGb = ConvertTo-Gb $vol.SizeRemaining
    $sizeGb = ConvertTo-Gb $vol.Size
    $pct = if ($vol.Size -gt 0) { [math]::Round(($vol.SizeRemaining / $vol.Size) * 100, 1) } else { 0 }
    $script:FreeSpaceBefore = $vol.SizeRemaining

    Write-Info ("System volume {0}: {1} GB free of {2} GB ({3}%)" -f $sysDrive, $freeGb, $sizeGb, $pct)

    if ($freeGb -lt 15) {
        Write-Bad 'Under 15 GB free. Windows servicing (DISM, feature updates) needs headroom and may fail.'
        Add-Finding ("Only {0} GB free on {1}: - servicing operations need at least 15-20 GB." -f $freeGb, $sysDrive)
        return @{ Status = 'Warning'; Detail = "$freeGb GB free" }
    }
    return @{ Status = 'OK'; Detail = "$freeGb GB free ($pct%)" }
}

function Invoke-RestorePointTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($SkipRestorePoint) { return @{ Status = 'Skipped'; Detail = 'Suppressed by -SkipRestorePoint' } }

    $sysDrive = $env:SystemDrive

    if (-not $PSCmdlet.ShouldProcess($sysDrive, 'Create System Restore checkpoint')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    # Windows throttles restore points to one per 24h by default. Temporarily relax, then restore.
    $freqKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $originalFreq = $null
    try {
        if (Test-Path $freqKey) {
            $p = Get-ItemProperty -Path $freqKey -ErrorAction SilentlyContinue
            if ($p -and $p.PSObject.Properties.Name -contains 'SystemRestorePointCreationFrequency') {
                $originalFreq = $p.SystemRestorePointCreationFrequency
            }
        }
        New-ItemProperty -Path $freqKey -Name 'SystemRestorePointCreationFrequency' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    } catch { }

    try {
        $desc = "Imperial Maintenance $($script:StartTime.ToString('yyyy-MM-dd HH:mm'))"
        $r = Invoke-CimMethod -Namespace 'root/default' -ClassName SystemRestore -MethodName CreateRestorePoint -Arguments @{
            Description      = $desc
            RestorePointType = [uint32]12   # MODIFY_SETTINGS
            EventType        = [uint32]100  # BEGIN_SYSTEM_CHANGE
        } -ErrorAction Stop

        if ($r.ReturnValue -eq 0) {
            Write-Good "Restore point created: $desc"
            return @{ Status = 'OK'; Detail = $desc }
        }
        Write-Warn "CreateRestorePoint returned $($r.ReturnValue). System Protection is probably disabled on $sysDrive."
        Add-Finding "System Protection appears to be off. Enable it (System Properties > System Protection) so repairs are reversible."
        return @{ Status = 'Warning'; Detail = "ReturnValue $($r.ReturnValue)" }
    }
    catch {
        Write-Warn "Restore point unavailable: $($_.Exception.Message)"
        return @{ Status = 'Warning'; Detail = 'System Protection disabled or unavailable' }
    }
    finally {
        try {
            if ($null -ne $originalFreq) {
                Set-ItemProperty -Path $freqKey -Name 'SystemRestorePointCreationFrequency' -Value $originalFreq -ErrorAction SilentlyContinue
            } else {
                Remove-ItemProperty -Path $freqKey -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue
            }
        } catch { }
    }
}

#endregion

#region ---------------------------------------------------------------- Task: integrity (DISM / SFC)

function Invoke-DismHealthChain {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$DismSource = $DismSource)
    <#
        Mandatory order: CheckHealth (instant flag read) -> ScanHealth (full scan) -> RestoreHealth
        (repair, only if needed). SFC runs after this, never before, because SFC sources its
        replacement files from the component store DISM repairs.
    #>
    $useModule = $null -ne (Get-Command Repair-WindowsImage -ErrorAction SilentlyContinue)
    $state = 'Unknown'

    # --- 1. CheckHealth ------------------------------------------------------
    Write-Info 'Step 1/3  CheckHealth  (reads the existing corruption flag - instant)'
    if ($useModule) {
        try {
            $check = Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop
            $state = $check.ImageHealthState
        } catch {
            $useModule = $false
        }
    }
    if (-not $useModule) {
        $r = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList @('/Online', '/Cleanup-Image', '/CheckHealth')
        if ($r.Output -match 'No component store corruption detected') { $state = 'Healthy' }
        elseif ($r.Output -match 'is repairable')                      { $state = 'Repairable' }
        elseif ($r.Output -match 'not repairable')                     { $state = 'NonRepairable' }
    }
    Write-Info "          Result: $state"

    # --- 2. ScanHealth -------------------------------------------------------
    Write-Info 'Step 2/3  ScanHealth   (full component store scan - typically 3-10 minutes)'
    if ($script:ReadOnlyRun -or $PSCmdlet.ShouldProcess('Component store', 'DISM ScanHealth')) {
        if ($useModule) {
            try {
                $scan = Repair-WindowsImage -Online -ScanHealth -ErrorAction Stop
                $state = $scan.ImageHealthState
            } catch {
                $r = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList @('/Online', '/Cleanup-Image', '/ScanHealth')
                if ($r.Output -match 'No component store corruption detected') { $state = 'Healthy' }
                elseif ($r.Output -match 'is repairable')                      { $state = 'Repairable' }
                elseif ($r.Output -match 'not repairable')                     { $state = 'NonRepairable' }
            }
        } else {
            $r = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList @('/Online', '/Cleanup-Image', '/ScanHealth')
            if ($r.Output -match 'No component store corruption detected') { $state = 'Healthy' }
            elseif ($r.Output -match 'is repairable')                      { $state = 'Repairable' }
            elseif ($r.Output -match 'not repairable')                     { $state = 'NonRepairable' }
        }
    }
    Write-Info "          Result: $state"

    if ($state -eq 'Healthy') {
        Write-Good 'Component store is healthy. RestoreHealth not required.'
        return @{ Status = 'OK'; Detail = 'Component store healthy' }
    }

    if ($script:ReadOnlyRun) {
        Write-Warn "Component store state: $state. Re-run without -Level Audit to repair."
        Add-Finding "DISM reports the component store is '$state'. Run a Standard or Full pass to repair it."
        return @{ Status = 'Warning'; Detail = "Store $state (audit mode, no repair)" }
    }

    # --- 3. RestoreHealth ----------------------------------------------------
    Write-Warn "Component store reports '$state'. Running RestoreHealth (can take 10-30 minutes)."
    if (-not $PSCmdlet.ShouldProcess('Component store', 'DISM RestoreHealth')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $dismArgs = @('/Online', '/Cleanup-Image', '/RestoreHealth')
    if ($DismSource) {
        Write-Info "          Using repair source: $DismSource"
        $dismArgs += "/Source:$DismSource"
        $dismArgs += '/LimitAccess'
    }
    $restore = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList $dismArgs

    # Exit code, not the localized console text, decides success.
    if ($restore.ExitCode -in 0, 3010) {
        Write-Good 'RestoreHealth completed successfully.'
        if ($restore.ExitCode -eq 3010) { Write-Warn 'A restart is required to finish this repair.' }
        $script:RebootNeeded = $true
        return @{ Status = 'Repaired'; Detail = 'Component store repaired' }
    }

    if ($restore.Output -match '0x800f081f') {
        Write-Bad 'DISM error 0x800F081F - repair payload not found via Windows Update.'
        Add-Finding 'DISM could not obtain repair files (0x800F081F). Re-run with -DismSource pointing at a matching install.wim, e.g. -DismSource "D:\sources\install.wim:1".'
        return @{ Status = 'Failed'; Detail = '0x800F081F - source required' }
    }
    if ($restore.Output -match '0x800f0906') {
        Add-Finding 'DISM error 0x800F0906 - the host could not download source files. Check connectivity, proxy, and WSUS/"Do not connect to Windows Update" policy.'
        return @{ Status = 'Failed'; Detail = '0x800F0906 - download failure' }
    }

    Write-Bad "RestoreHealth exit code $($restore.ExitCode)."
    Write-Verbose $restore.Output
    Add-Finding 'DISM RestoreHealth failed. Review C:\Windows\Logs\DISM\dism.log and consider an in-place repair upgrade.'
    return @{ Status = 'Failed'; Detail = "Exit $($restore.ExitCode)" }
}

function Invoke-SfcTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($script:ReadOnlyRun) {
        # sfc /verifyonly is the read-only equivalent.
        Write-Info 'Audit mode: running sfc /verifyonly (no changes).'
        $r = Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\sfc.exe" -ArgumentList @('/verifyonly')
        if ($r.Output -match 'did not find any integrity violations') {
            Write-Good 'No integrity violations found.'
            return @{ Status = 'OK'; Detail = 'No integrity violations' }
        }
        Add-Finding 'SFC verification found integrity violations. Run a Standard pass to repair them.'
        return @{ Status = 'Warning'; Detail = 'Integrity violations detected' }
    }

    if (-not $PSCmdlet.ShouldProcess('Protected system files', 'sfc /scannow')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    Write-Info 'Running sfc /scannow (typically 5-20 minutes). Output is captured, not streamed.'
    $sfcStart = Get-Date
    $r = Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\sfc.exe" -ArgumentList @('/scannow')

    if ($r.Output -match 'did not find any integrity violations') {
        Write-Good 'Windows Resource Protection found no integrity violations.'
        return @{ Status = 'OK'; Detail = 'No integrity violations' }
    }
    if ($r.Output -match 'successfully repaired them') {
        Write-Good 'Corrupt files were found and repaired.'
        $script:RebootNeeded = $true
        return @{ Status = 'Repaired'; Detail = 'Corrupt files repaired' }
    }
    if ($r.Output -match 'was unable to fix') {
        Write-Bad 'SFC found corruption it could not repair.'
        Add-Finding 'SFC could not repair some files. Re-run DISM /RestoreHealth (optionally with -DismSource), then SFC again. If it still fails, perform an in-place repair upgrade.'
        return @{ Status = 'Failed'; Detail = 'Unrepairable corruption' }
    }
    if ($r.Output -match 'could not perform the requested operation') {
        Add-Finding 'SFC could not run. Try again from Safe Mode, or after a reboot to clear a pending servicing operation.'
        return @{ Status = 'Failed'; Detail = 'SFC could not run' }
    }

    # sfc.exe's console text is localized and may not match any of the phrases above on a
    # non-English install; CBS.log's own trace markers are English/technical regardless of
    # UI language, so fall back to scanning the entries this run just produced.
    $cbsPath = "$env:SystemRoot\Logs\CBS\CBS.log"
    $sinceRun = Get-Content -Path $cbsPath -Tail 20000 -ErrorAction SilentlyContinue |
                Where-Object { $_ -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})' -and [datetime]$Matches[1] -ge $sfcStart }
    $unrepairedNow = @($sinceRun | Select-String -SimpleMatch 'cannot repair member file')
    $repairedNow   = @($sinceRun | Select-String -SimpleMatch 'Repairing corrupted file')
    if ($unrepairedNow.Count -gt 0) {
        Add-Finding 'SFC could not repair some files (per CBS.log). Re-run DISM /RestoreHealth, then SFC again.'
        return @{ Status = 'Failed'; Detail = 'Unrepairable corruption (CBS.log)' }
    }
    if ($repairedNow.Count -gt 0) {
        Write-Good 'Corrupt files were found and repaired (per CBS.log).'
        $script:RebootNeeded = $true
        return @{ Status = 'Repaired'; Detail = "$($repairedNow.Count) files repaired (CBS.log)" }
    }

    Write-Warn "SFC returned an unrecognised result (exit $($r.ExitCode))."
    Write-Verbose $r.Output
    return @{ Status = 'Warning'; Detail = "Exit $($r.ExitCode)" }
}

function Invoke-CbsLogReviewTask {
    $cbs = "$env:SystemRoot\Logs\CBS\CBS.log"
    if (-not (Test-Path $cbs)) { return @{ Status = 'Skipped'; Detail = 'CBS.log not present' } }

    $tail = Get-Content -Path $cbs -Tail 6000 -ErrorAction SilentlyContinue
    if (-not $tail) { return @{ Status = 'Skipped'; Detail = 'CBS.log unreadable' } }

    $repaired   = @($tail | Select-String -SimpleMatch 'Repairing corrupted file' -ErrorAction SilentlyContinue)
    $unrepaired = @($tail | Select-String -SimpleMatch 'cannot repair member file' -ErrorAction SilentlyContinue)

    Write-Info ("CBS tail: {0} repair entries, {1} unrepairable entries." -f $repaired.Count, $unrepaired.Count)

    if ($unrepaired.Count -gt 0) {
        $names = ($unrepaired | ForEach-Object {
            if ($_.Line -match 'member file \[l:\d+(?:\{\d+\})?\][''"]([^''"]+)[''"]') { $Matches[1] } } |
            Select-Object -Unique -First 10)
        foreach ($n in $names) { Write-Bad "  unrepairable: $n" }
        Add-Finding ("CBS.log lists {0} unrepairable member file entries. Full detail: {1}" -f $unrepaired.Count, $cbs)
        return @{ Status = 'Warning'; Detail = "$($unrepaired.Count) unrepairable entries in CBS.log" }
    }
    if ($repaired.Count -gt 0) {
        return @{ Status = 'Repaired'; Detail = "$($repaired.Count) files repaired per CBS.log" }
    }
    return @{ Status = 'OK'; Detail = 'No repair activity in recent CBS.log' }
}

function Invoke-ComponentStoreTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$ResetComponentStoreBase = $ResetComponentStoreBase)

    Write-Info 'Analysing component store (WinSxS)...'
    $analyze = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList @('/Online', '/Cleanup-Image', '/AnalyzeComponentStore')

    # DISM's "cleanup recommended" advisory is localized console text and unreliable to parse,
    # so it's shown for information only; StartComponentCleanup is a safe no-op when nothing
    # needs cleaning, so we don't gate the actual cleanup decision on it.
    $actual = $null
    if ($analyze.Output -match 'Actual Size of Component Store\s*:\s*(.+)')  { $actual = $Matches[1].Trim() }
    if ($actual) { Write-Info "WinSxS actual size: $actual" }

    if ($script:ReadOnlyRun) { return @{ Status = 'OK'; Detail = "WinSxS $actual" } }

    if (-not $PSCmdlet.ShouldProcess('WinSxS component store', 'DISM StartComponentCleanup')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $cleanArgs = @('/Online', '/Cleanup-Image', '/StartComponentCleanup')
    if ($ResetComponentStoreBase) {
        Write-Warn 'ResetBase requested: installed updates will become permanent and non-uninstallable.'
        $cleanArgs += '/ResetBase'
    }
    Write-Info 'Running component cleanup (can take 10-30 minutes)...'
    $clean = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList $cleanArgs

    if ($clean.ExitCode -in 0, 3010) {
        Write-Good 'Component store cleanup completed.'
        if ($clean.ExitCode -eq 3010) { $script:RebootNeeded = $true }
        return @{ Status = 'Repaired'; Detail = "Cleanup completed (was $actual)" }
    }
    return @{ Status = 'Warning'; Detail = "StartComponentCleanup exit $($clean.ExitCode)" }
}

#endregion

#region ---------------------------------------------------------------- Task: storage

function Invoke-PhysicalDiskHealthTask {
    $disks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)
    if (-not $disks) { return @{ Status = 'Skipped'; Detail = 'No physical disks reported' } }

    $problems = 0
    $rows = foreach ($d in $disks) {
        $rc = $null
        try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }

        $wear = $null; $temp = $null; $hours = $null; $readErr = $null; $writeErr = $null
        if ($rc) {
            $wear     = $rc.Wear
            $temp     = $rc.Temperature
            $hours    = $rc.PowerOnHours
            $readErr  = $rc.ReadErrorsUncorrected
            $writeErr = $rc.WriteErrorsUncorrected
        }

        if ($d.HealthStatus -ne 'Healthy') { $problems++ }
        if ($null -ne $wear -and $wear -ge 80) { $problems++ }
        if (($null -ne $readErr -and $readErr -gt 0) -or ($null -ne $writeErr -and $writeErr -gt 0)) { $problems++ }

        [pscustomobject]@{
            Disk        = $d.FriendlyName
            Media       = $d.MediaType
            Bus         = $d.BusType
            SizeGb      = ConvertTo-Gb $d.Size
            Health      = $d.HealthStatus
            OpStatus    = ($d.OperationalStatus -join ',')
            'Wear%'     = $wear
            TempC       = $temp
            PowerOnHrs  = $hours
            UncReadErr  = $readErr
            UncWriteErr = $writeErr
        }
    }

    $rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

    # SMART predictive failure via the storage driver WMI provider.
    try {
        $smart = @(Get-CimInstance -Namespace 'root\wmi' -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop)
        foreach ($s in $smart) {
            if ($s.PredictFailure) {
                Write-Bad "SMART predictive failure asserted on $($s.InstanceName)"
                Add-Finding "SMART reports predictive failure on $($s.InstanceName). Back up now and replace the drive."
                $problems++
            }
        }
        if ($smart.Count -gt 0 -and $problems -eq 0) { Write-Good 'SMART predictive failure: clear on all reporting devices.' }
    } catch {
        Write-Info 'SMART predictive-failure provider not available for these controllers (common on NVMe/RAID).'
    }

    if ($problems -gt 0) {
        Add-Finding 'One or more drives reported degraded health, high wear, or uncorrected errors. Verify backups before doing anything else.'
        return @{ Status = 'Warning'; Detail = "$problems disk health concern(s)" }
    }
    return @{ Status = 'OK'; Detail = "$($disks.Count) disk(s) healthy" }
}

function Invoke-VolumeScanTask {
    $vols = @(Get-Volume -ErrorAction SilentlyContinue |
              Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystemType -eq 'NTFS' })
    if (-not $vols) { return @{ Status = 'Skipped'; Detail = 'No fixed NTFS volumes' } }

    $dirty = @()
    $unverified = @()
    $script:DirtyVolumes = @()
    foreach ($v in $vols) {
        Write-Info ("Online NTFS scan of {0}: ..." -f $v.DriveLetter)
        try {
            $result = Repair-Volume -DriveLetter $v.DriveLetter -Scan -ErrorAction Stop
            Write-Verbose "Repair-Volume -Scan on $($v.DriveLetter): returned type=$($result.GetType().FullName) value=$result"
            if ($result -match 'NoErrors' -or $result -eq 0) {
                Write-Good ("  {0}: clean" -f $v.DriveLetter)
            } else {
                Write-Warn ("  {0}: {1}" -f $v.DriveLetter, $result)
                $dirty += "$($v.DriveLetter): $result"
                $script:DirtyVolumes += $v.DriveLetter
            }
        } catch {
            Write-Warn ("  {0}: scan failed - {1}" -f $v.DriveLetter, $_.Exception.Message)
            $unverified += "$($v.DriveLetter): scan failed"
        }

        # fsutil's exit code is 0 (clean) or nonzero for BOTH "dirty" and unrelated errors (e.g.
        # access denied also returns 1), so a nonzero exit code alone is ambiguous. fsutil prefixes
        # genuine Win32 errors with a locale-independent "Error <n>:" marker; the real "is Dirty"
        # message has no such prefix, so use its absence to tell a real dirty bit from a failure.
        $fs = Invoke-NativeCommand -FilePath 'fsutil.exe' -ArgumentList @('dirty', 'query', "$($v.DriveLetter):")
        if ($fs.ExitCode -ne 0 -and $fs.Output -notmatch 'Error\s+\d+:') {
            Write-Warn ("  {0}: volume dirty bit is SET - CHKDSK will run at next boot." -f $v.DriveLetter)
            $dirty += "$($v.DriveLetter): dirty bit set"
            if ($script:DirtyVolumes -notcontains $v.DriveLetter) { $script:DirtyVolumes += $v.DriveLetter }
        } elseif ($fs.ExitCode -ne 0) {
            Write-Warn ("  {0}: could not query dirty bit - {1}" -f $v.DriveLetter, $fs.Output)
            $unverified += "$($v.DriveLetter): dirty-bit query failed"
        }
    }

    if ($dirty.Count -gt 0) {
        Add-Finding ("File system issues detected: {0}. Re-run with -ScheduleChkdsk to queue a full CHKDSK /F /R at next boot." -f ($dirty -join '; '))
        return @{ Status = 'Warning'; Detail = ($dirty -join '; ') }
    }
    if ($unverified.Count -gt 0) {
        Add-Finding ("Could not verify file system health on: {0}. Re-run elevated to get a real result." -f ($unverified -join '; '))
        return @{ Status = 'Warning'; Detail = ($unverified -join '; ') }
    }
    return @{ Status = 'OK'; Detail = "$($vols.Count) volume(s) clean" }
}

function Invoke-ChkdskScheduleTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$ScheduleChkdsk = $ScheduleChkdsk)

    if (-not $ScheduleChkdsk) { return @{ Status = 'Skipped'; Detail = 'Not requested (-ScheduleChkdsk)' } }

    $targets = @($script:DirtyVolumes)
    if (-not $targets) { $targets = @($env:SystemDrive.TrimEnd(':')) }

    # Writing BootExecute directly (rather than answering chkdsk's interactive Y/N prompt) avoids
    # the localized Y/N mnemonic problem and lets us verify the schedule actually took effect.
    $attempted = 0
    $scheduled = @()
    foreach ($drive in $targets) {
        $driveLetter = "$drive".TrimEnd(':')
        if (-not $PSCmdlet.ShouldProcess("${driveLetter}:", 'Schedule CHKDSK /R at next boot')) { continue }
        $attempted++

        Write-Warn "Scheduling CHKDSK /R on ${driveLetter}: for the next restart. A /R pass can take several hours."
        $bootExecKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $entry = "autocheck autochk /r \??\${driveLetter}:"
        $existing = @((Get-ItemProperty -Path $bootExecKey -Name BootExecute -ErrorAction SilentlyContinue).BootExecute)
        if ($existing -notcontains $entry) {
            Set-ItemProperty -Path $bootExecKey -Name BootExecute -Value (@($existing) + $entry) -Type MultiString
        }
        $verify = @((Get-ItemProperty -Path $bootExecKey -Name BootExecute -ErrorAction SilentlyContinue).BootExecute)
        if ($verify -contains $entry) {
            $scheduled += $driveLetter
        } else {
            Write-Bad "  could not confirm CHKDSK scheduling for ${driveLetter}:"
        }
    }

    if ($attempted -eq 0) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }
    if ($scheduled.Count -eq 0) {
        return @{ Status = 'Failed'; Detail = 'Could not confirm CHKDSK scheduling' }
    }
    $script:RebootNeeded = $true
    Add-Finding "CHKDSK /R is scheduled for $($scheduled -join ', ') at the next restart. Do not interrupt it once it begins."
    return @{ Status = 'Repaired'; Detail = "CHKDSK scheduled for $($scheduled -join ', ')" }
}

function Invoke-OptimizeVolumeTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $vols = @(Get-Volume -ErrorAction SilentlyContinue |
              Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystemType -in @('NTFS', 'ReFS') })
    if (-not $vols) { return @{ Status = 'Skipped'; Detail = 'No optimizable volumes' } }

    $actions = @()
    foreach ($v in $vols) {
        $media = Get-VolumeMediaType -DriveLetter $v.DriveLetter
        Write-Info ("{0}: media type {1}" -f $v.DriveLetter, $media)

        if ($script:ReadOnlyRun) {
            try {
                Optimize-Volume -DriveLetter $v.DriveLetter -Analyze -ErrorAction Stop -Verbose:$false
                $actions += "$($v.DriveLetter): analyzed"
            } catch { Write-Warn "  analyze failed: $($_.Exception.Message)" }
            continue
        }

        if (-not $PSCmdlet.ShouldProcess("$($v.DriveLetter):", "Optimize ($media)")) { continue }

        try {
            switch ($media) {
                'SSD' {
                    # TRIM/UNMAP. Never defrag an SSD - it burns write cycles for no benefit.
                    Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -ErrorAction Stop -Verbose:$false
                    Write-Good "  $($v.DriveLetter): ReTrim complete"
                    $actions += "$($v.DriveLetter): ReTrim"
                }
                'SCM' {
                    Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -ErrorAction Stop -Verbose:$false
                    $actions += "$($v.DriveLetter): ReTrim"
                }
                'HDD' {
                    Optimize-Volume -DriveLetter $v.DriveLetter -Defrag -ErrorAction Stop -Verbose:$false
                    Write-Good "  $($v.DriveLetter): defragmented"
                    $actions += "$($v.DriveLetter): Defrag"
                }
                default {
                    # Storage Spaces / Dev Drive / virtualized SSDs often report as unknown media.
                    # ReTrim is a documented no-op on rotational disks, so default to it instead of
                    # skipping optimization entirely.
                    try {
                        Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -ErrorAction Stop -Verbose:$false
                        Write-Info "  $($v.DriveLetter): ReTrim (media type unknown)"
                        $actions += "$($v.DriveLetter): ReTrim (unknown media)"
                    } catch {
                        Optimize-Volume -DriveLetter $v.DriveLetter -Analyze -ErrorAction Stop -Verbose:$false
                        Write-Info "  $($v.DriveLetter): analyzed only (ReTrim unsupported)"
                        $actions += "$($v.DriveLetter): analyzed"
                    }
                }
            }
        } catch {
            Write-Warn "  $($v.DriveLetter): $($_.Exception.Message)"
            $actions += "$($v.DriveLetter): failed"
        }
    }
    return @{ Status = 'OK'; Detail = ($actions -join '; ') }
}

#endregion

#region ---------------------------------------------------------------- Task: servicing

function Invoke-WindowsUpdateTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$InstallWindowsUpdates = $InstallWindowsUpdates)

    $session = $null
    try   { $session = New-Object -ComObject Microsoft.Update.Session }
    catch { return @{ Status = 'Warning'; Detail = 'Windows Update COM API unavailable' } }

    Write-Info 'Scanning Windows Update (this can take a few minutes)...'
    $searcher = $session.CreateUpdateSearcher()
    # BrowseOnly is explicit on both sides so optional updates are always part of the result.
    $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0 and BrowseOnly=0 or IsInstalled=0 and IsHidden=0 and BrowseOnly=1")
    $updates = @($searchResult.Updates)

    if ($updates.Count -eq 0) {
        Write-Good 'No pending updates.'
        return @{ Status = 'OK'; Detail = 'No pending updates' }
    }

    Write-Warn "$($updates.Count) update(s) available:"
    $updates | ForEach-Object {
        $sizeMb = 0
        try { $sizeMb = ConvertTo-Mb $_.MaxDownloadSize } catch { }
        Write-Host ("      - {0} ({1} MB)" -f $_.Title, $sizeMb) -ForegroundColor Gray
    }

    if (-not $InstallWindowsUpdates -or $script:ReadOnlyRun) {
        Add-Finding "$($updates.Count) Windows Update(s) pending. Re-run with -InstallWindowsUpdates to apply them."
        return @{ Status = 'Warning'; Detail = "$($updates.Count) pending (not installed)" }
    }
    if (Test-IsSystemAccount) {
        return @{ Status = 'Warning'; Detail = 'Update install via COM is unsupported from a service (SYSTEM) context' }
    }
    if (-not $PSCmdlet.ShouldProcess('Windows Update', "Download and install $($updates.Count) update(s)")) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $updates) {
        if (-not $u.EulaAccepted) { try { $u.AcceptEula() } catch { } }
        $toInstall.Add($u) | Out-Null
    }

    Write-Info 'Downloading...'
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $toInstall
    $dl = $downloader.Download()
    # 2 = succeeded, 3 = succeeded with errors (install whatever did download).
    if ($dl.ResultCode -notin 2, 3) {
        return @{ Status = 'Failed'; Detail = "Download result code $($dl.ResultCode)" }
    }

    Write-Info 'Installing...'
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $toInstall
    $ir = $installer.Install()

    if ($ir.RebootRequired) { $script:RebootNeeded = $true }
    switch ($ir.ResultCode) {
        2 { Write-Good 'Updates installed successfully.'
            return @{ Status = 'Repaired'; Detail = "$($updates.Count) update(s) installed" } }
        3 { Add-Finding 'Some Windows Updates installed with errors. Check Settings > Windows Update > Update history.'
            return @{ Status = 'Warning'; Detail = 'Installed with errors' } }
        default {
            return @{ Status = 'Failed'; Detail = "Install result code $($ir.ResultCode)" } }
    }
}

function Invoke-WindowsUpdateRepairTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$RepairWindowsUpdateStack = $RepairWindowsUpdateStack)

    if (-not $RepairWindowsUpdateStack) { return @{ Status = 'Skipped'; Detail = 'Not requested (-RepairWindowsUpdateStack)' } }
    if (-not $PSCmdlet.ShouldProcess('Windows Update stack', 'Reset SoftwareDistribution and catroot2')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $services = 'wuauserv', 'cryptSvc', 'bits', 'msiserver', 'usosvc'
    Write-Warn 'Stopping servicing stack services...'
    foreach ($s in $services) {
        try { Stop-Service -Name $s -Force -ErrorAction Stop; Write-Info "  stopped $s" }
        catch { Write-Info "  $s not stopped: $($_.Exception.Message)" }
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    foreach ($pair in @(
        @{ Path = "$env:SystemRoot\SoftwareDistribution"; New = "SoftwareDistribution.bak-$stamp" },
        @{ Path = "$env:SystemRoot\System32\catroot2";    New = "catroot2.bak-$stamp" })) {
        if (Test-Path $pair.Path) {
            try {
                Rename-Item -Path $pair.Path -NewName $pair.New -Force -ErrorAction Stop
                Write-Good "  renamed $($pair.Path) -> $($pair.New)"
            } catch {
                Write-Warn "  could not rename $($pair.Path): $($_.Exception.Message)"
            }
        }
    }

    $failedStarts = @()
    foreach ($s in $services) {
        try { Start-Service -Name $s -ErrorAction Stop; Write-Info "  started $s" }
        catch { Write-Bad "  FAILED to restart $s`: $($_.Exception.Message)"; $failedStarts += $s }
    }

    $script:RebootNeeded = $true
    if ($failedStarts.Count -gt 0) {
        Add-Finding "Windows Update stack reset left these services stopped: $($failedStarts -join ', '). Start them manually or reboot immediately."
        return @{ Status = 'Failed'; Detail = "Reset done but $($failedStarts -join ',') would not restart" }
    }
    Add-Finding "Windows Update stack was reset. Old folders were renamed with suffix .bak-$stamp and can be deleted once updates work."
    return @{ Status = 'Repaired'; Detail = "Stack reset (backups suffixed .bak-$stamp)" }
}

function Invoke-WingetTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$UpgradeApps = $UpgradeApps)

    if (-not $UpgradeApps) { return @{ Status = 'Skipped'; Detail = 'Not requested (-UpgradeApps)' } }
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) { return @{ Status = 'Skipped'; Detail = 'winget not installed' } }
    if (Test-IsSystemAccount) {
        return @{ Status = 'Skipped'; Detail = 'winget is unreliable under SYSTEM - run interactively' }
    }
    if (-not $PSCmdlet.ShouldProcess('Installed packages', 'winget upgrade --all (winget + msstore)')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    Write-Info 'Refreshing winget sources...'
    $null = Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @('source', 'update', '--disable-interactivity')

    Write-Info 'Listing upgradable packages (all sources)...'
    $list = Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @(
        'upgrade', '--include-unknown', '--accept-source-agreements', '--disable-interactivity')
    Write-Host $list.Output -ForegroundColor Gray

    Write-Info 'Upgrading winget-source packages...'
    $up = Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @(
        'upgrade', '--all', '--include-unknown', '--silent',
        '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')

    # A separate --source msstore pass is what actually updates installed Microsoft Store apps;
    # a plain 'winget upgrade --all' does not reliably reach them without scoping to that source.
    Write-Info 'Upgrading Microsoft Store apps (winget --source msstore)...'
    $storeUp = Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @(
        'upgrade', '--all', '--include-unknown', '--silent', '--source', 'msstore',
        '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')

    $notes = @()
    $notes += if ($up.ExitCode -eq 0) { 'winget packages upgraded' } else { "winget source exit $($up.ExitCode)" }
    $notes += if ($storeUp.ExitCode -eq 0) { 'Store apps upgraded' } else { "msstore source exit $($storeUp.ExitCode)" }

    if ($up.ExitCode -eq 0 -and $storeUp.ExitCode -eq 0) {
        return @{ Status = 'Repaired'; Detail = ($notes -join '; ') }
    }
    return @{ Status = 'Warning'; Detail = ($notes -join '; ') + ' - some packages need manual attention' }
}

function Invoke-StoreAppUpdateTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($script:ReadOnlyRun) { return @{ Status = 'Skipped'; Detail = 'Audit mode' } }
    if (Test-IsSystemAccount) { return @{ Status = 'Skipped'; Detail = 'Not applicable under SYSTEM' } }
    if (-not $PSCmdlet.ShouldProcess('Microsoft Store', 'Trigger app update scan')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }
    try {
        # Complementary to Invoke-WingetTask's 'winget upgrade --source msstore' pass: this asks
        # StorSvc to check for updates in the background for any app winget's msstore catalog
        # might not cover. It's async and best-effort, not a synchronous "update everything now".
        $ns = 'root\cimv2\mdm\dmmap'
        $cls = 'MDM_EnterpriseModernAppManagement_AppManagement01'
        $obj = Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction Stop
        $null = Invoke-CimMethod -InputObject $obj -MethodName UpdateScanMethod -ErrorAction Stop
        Write-Good 'Microsoft Store update scan triggered.'
        return @{ Status = 'OK'; Detail = 'Store update scan triggered' }
    } catch {
        return @{ Status = 'Skipped'; Detail = 'MDM bridge unavailable' }
    }
}

function Invoke-PowerShellHygieneTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($script:ReadOnlyRun) { return @{ Status = 'Skipped'; Detail = 'Audit mode' } }
    if (-not $PSCmdlet.ShouldProcess('PowerShell modules and help', 'Update')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $notes = @()
    try {
        Write-Info 'Updating PowerShell help...'
        Update-Help -Force -ErrorAction SilentlyContinue 2>$null
        $notes += 'help updated'
    } catch { $notes += 'help update partial' }

    try {
        if (Get-Command Update-PSResource -ErrorAction SilentlyContinue) {
            Write-Info 'Updating installed modules via PSResourceGet...'
            Update-PSResource -Scope CurrentUser -TrustRepository -ErrorAction SilentlyContinue
            $notes += 'modules updated (PSResourceGet)'
        } elseif (Get-Command Update-Module -ErrorAction SilentlyContinue) {
            Write-Info 'Updating installed modules via PowerShellGet...'
            Update-Module -Force -ErrorAction SilentlyContinue
            $notes += 'modules updated (PowerShellGet)'
        }
    } catch { $notes += 'module update partial' }

    return @{ Status = 'OK'; Detail = ($notes -join '; ') }
}

#endregion

#region ---------------------------------------------------------------- Task: security

function Invoke-DefenderTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$IncludeDefenderScan = $IncludeDefenderScan)

    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        return @{ Status = 'Skipped'; Detail = 'Defender cmdlets unavailable (third-party AV?)' }
    }

    # The cmdlets exist but throw when Defender is disabled/passive behind third-party AV.
    try   { $status = Get-MpComputerStatus -ErrorAction Stop }
    catch { return @{ Status = 'Skipped'; Detail = "Defender unavailable: $($_.Exception.Message)" } }
    Write-Info ("Antimalware engine : {0}" -f $status.AMEngineVersion)
    Write-Info ("Signature version  : {0} (age {1} days)" -f $status.AntivirusSignatureVersion, $status.AntivirusSignatureAge)
    Write-Info ("Real-time protection: {0}   Tamper protection: {1}" -f $status.RealTimeProtectionEnabled, $status.IsTamperProtected)

    $issues = @()
    if (-not $status.RealTimeProtectionEnabled) { $issues += 'real-time protection off' }
    if ($status.AntivirusSignatureAge -gt 3)     { $issues += "signatures $($status.AntivirusSignatureAge) days old" }

    if (-not $script:ReadOnlyRun -and $PSCmdlet.ShouldProcess('Microsoft Defender', 'Update signatures')) {
        try {
            Write-Info 'Updating Defender signatures...'
            Update-MpSignature -ErrorAction Stop
            Write-Good 'Signatures updated.'
        } catch {
            Write-Warn "Signature update failed: $($_.Exception.Message)"
            $issues += 'signature update failed'
        }
    }

    if ($IncludeDefenderScan -and -not $script:ReadOnlyRun) {
        if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Quick scan')) {
            Write-Info 'Running quick scan...'
            try { Start-MpScan -ScanType QuickScan -ErrorAction Stop; Write-Good 'Quick scan complete.' }
            catch { Write-Warn "Quick scan failed: $($_.Exception.Message)"; $issues += 'quick scan failed' }
        }
    }

    $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
                 Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) })
    if ($threats.Count -gt 0) {
        Write-Warn "$($threats.Count) threat detection(s) in the last 30 days."
        Add-Finding "Microsoft Defender logged $($threats.Count) detection(s) in the last 30 days. Review Windows Security > Protection history."
        $issues += "$($threats.Count) recent detections"
    }

    if ($issues.Count -gt 0) { return @{ Status = 'Warning'; Detail = ($issues -join '; ') } }
    return @{ Status = 'OK'; Detail = "Signatures $($status.AntivirusSignatureVersion)" }
}

function Invoke-SecurityPostureTask {
    $issues = @()

    # Firewall
    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $fw | Select-Object Name, Enabled, DefaultInboundAction | Format-Table -AutoSize | Out-String | Write-Host
        $off = @($fw | Where-Object { -not $_.Enabled })
        if ($off) { $issues += "firewall disabled on: $($off.Name -join ',')" }
    } catch { }

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        Write-Info "Secure Boot        : $sb"
        if (-not $sb) { $issues += 'Secure Boot disabled' }
    } catch { Write-Info 'Secure Boot        : not reported (legacy BIOS or unsupported)' }

    # TPM
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        Write-Info ("TPM                : present={0} ready={1} enabled={2}" -f $tpm.TpmPresent, $tpm.TpmReady, $tpm.TpmEnabled)
        if ($tpm.TpmPresent -and -not $tpm.TpmReady) { $issues += 'TPM present but not ready' }
    } catch { }

    # BitLocker
    try {
        $bl = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -eq 'OperatingSystem' })
        foreach ($v in $bl) {
            Write-Info ("BitLocker {0}      : {1} ({2}%)" -f $v.MountPoint, $v.ProtectionStatus, $v.EncryptionPercentage)
            if ($v.ProtectionStatus -ne 'On') { $issues += "BitLocker off on $($v.MountPoint)" }
        }
    } catch { Write-Info 'BitLocker          : not available on this edition' }

    # Core isolation / memory integrity
    try {
        $hvci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        $hvciOn = $hvci.SecurityServicesRunning -contains 2
        Write-Info "Memory integrity   : $(if ($hvciOn) { 'running' } else { 'not running' })"
        if (-not $hvciOn) { $issues += 'memory integrity (HVCI) not running' }
    } catch { }

    if ($issues.Count -gt 0) {
        Add-Finding ("Security posture gaps: {0}." -f ($issues -join '; '))
        return @{ Status = 'Warning'; Detail = ($issues -join '; ') }
    }
    return @{ Status = 'OK'; Detail = 'Firewall, Secure Boot, TPM, BitLocker and HVCI all nominal' }
}

#endregion

#region ---------------------------------------------------------------- Task: cleanup

function Get-FilesSkippingReparsePoints {
    <# Recurses like Get-ChildItem -Recurse, but never follows a symlink/junction - unlike
       Get-ChildItem -Recurse on Windows PowerShell 5.1, which does by default. #>
    param([Parameter(Mandatory)][string]$Path)
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($child in (Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
            if ($child.PSIsContainer) {
                if (-not ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $stack.Push($child.FullName) }
            } else {
                $child
            }
        }
    }
}

function Remove-PathContents {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Label,
        [int]$OlderThanDays = 0
    )
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }

    $cutoff = (Get-Date).AddDays(-$OlderThanDays)
    $freed = 0
    try {
        $items = Get-FilesSkippingReparsePoints -Path $Path |
                 Where-Object { $OlderThanDays -eq 0 -or $_.LastWriteTime -lt $cutoff }
        foreach ($i in $items) {
            try {
                $size = $i.Length
                Remove-Item -LiteralPath $i.FullName -Force -ErrorAction Stop
                $freed += $size
            } catch { }   # in-use files are expected; move on
        }
        # Remove now-empty directories (reparse points are left alone, never recursed into or deleted).
        Get-ChildItem -LiteralPath $Path -Force -Recurse -Directory -ErrorAction SilentlyContinue |
            Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
            Sort-Object { $_.FullName.Length } -Descending |
            ForEach-Object {
                try {
                    if (-not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue)) {
                        Remove-Item -LiteralPath $_.FullName -Force -Recurse -ErrorAction Stop
                    }
                } catch { }
            }
    } catch { }

    if ($freed -gt 0 -and $Label) {
        Write-Info ("  {0,-38} {1,8} MB" -f $Label, (ConvertTo-Mb $freed))
    }
    return $freed
}

function Invoke-CleanupTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($script:ReadOnlyRun) { return @{ Status = 'Skipped'; Detail = 'Audit mode' } }

    $sysDrive = $env:SystemDrive.TrimEnd(':')
    $before = (Get-Volume -DriveLetter $sysDrive).SizeRemaining
    $freed = 0
    $didWork = $false

    Write-Info 'Reclaiming space:'

    if (Test-IsSystemAccount) {
        Add-Finding 'Running as SYSTEM: temp/cache/Recycle Bin cleanup only touches the SYSTEM profile, not interactive users. Run interactively for real per-user cleanup.'
    }

    $targets = @(
        @{ Path = $env:TEMP;                                                     Label = 'User temp';                 Days = 0 }
        @{ Path = "$env:SystemRoot\Temp";                                        Label = 'Windows temp';              Days = 0 }
        @{ Path = "$env:LOCALAPPDATA\CrashDumps";                                Label = 'Application crash dumps';   Days = 7 }
        @{ Path = "$env:LOCALAPPDATA\D3DSCache";                                 Label = 'DirectX shader cache';      Days = 0 }
        @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\WER";                     Label = 'User error reports';        Days = 7 }
        @{ Path = "$env:ProgramData\Microsoft\Windows\WER\ReportQueue";          Label = 'WER report queue';          Days = 7 }
        @{ Path = "$env:ProgramData\Microsoft\Windows\WER\ReportArchive";        Label = 'WER report archive';        Days = 30 }
        @{ Path = "$env:SystemRoot\Prefetch";                                    Label = 'Prefetch (stale entries)';  Days = 90 }
    )

    # Full level adds heavier targets.
    if ($script:CurrentRank -ge 3) {
        $targets += @{ Path = "$env:SystemRoot\Logs\CBS";                Label = 'Old CBS logs';            Days = 30 }
        $targets += @{ Path = "$env:SystemRoot\Logs\DISM";               Label = 'Old DISM logs';           Days = 30 }
        $targets += @{ Path = "$env:SystemRoot\Panther";                 Label = 'Setup (Panther) logs';    Days = 60 }
        $targets += @{ Path = "$env:SystemRoot\SoftwareDistribution\Download"; Label = 'Windows Update cache'; Days = 10 }
        $targets += @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\IE"; Label = 'Legacy WinINet cache'; Days = 0 }
    }

    foreach ($t in $targets) {
        if ($PSCmdlet.ShouldProcess($t.Path, 'Delete contents')) {
            $didWork = $true
            $freed += Remove-PathContents -Path $t.Path -Label $t.Label -OlderThanDays $t.Days
        }
    }

    # Delivery Optimization cache (peer-to-peer update payloads).
    if ((Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) -and
        $PSCmdlet.ShouldProcess('Delivery Optimization cache', 'Purge')) {
        $didWork = $true
        try {
            Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
            Write-Info ("  {0,-38} {1}" -f 'Delivery Optimization cache', 'purged')
        } catch { }
    }

    # Recycle Bin.
    if ($PSCmdlet.ShouldProcess('Recycle Bin', 'Empty')) {
        $didWork = $true
        try {
            Clear-RecycleBin -Force -ErrorAction Stop
            Write-Info ("  {0,-38} {1}" -f 'Recycle Bin', 'emptied')
        } catch {
            Write-Info ("  {0,-38} {1}" -f 'Recycle Bin', 'already empty')
        }
    }

    # DNS resolver cache.
    if ($PSCmdlet.ShouldProcess('DNS client cache', 'Flush')) {
        $didWork = $true
        try { Clear-DnsClientCache -ErrorAction Stop; Write-Info ("  {0,-38} {1}" -f 'DNS client cache', 'flushed') } catch { }
    }

    # Icon/thumbnail cache is only measured, never deleted: Explorer holds it open while running.
    if ($script:CurrentRank -ge 3 -and -not (Test-IsSystemAccount)) {
        $iconPath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
        if (Test-Path $iconPath) {
            $stale = @(Get-ChildItem -LiteralPath $iconPath -Filter 'iconcache*' -Force -ErrorAction SilentlyContinue)
            $stale += @(Get-ChildItem -LiteralPath $iconPath -Filter 'thumbcache*' -Force -ErrorAction SilentlyContinue)
            $cacheBytes = ($stale | Measure-Object -Property Length -Sum).Sum
            if ($cacheBytes) {
                Write-Info ("  {0,-38} {1,8} MB (size only - not deleted)" -f 'Icon/thumbnail cache', (ConvertTo-Mb $cacheBytes))
            }
        }
    }

    $after = (Get-Volume -DriveLetter $sysDrive).SizeRemaining
    $deltaGb = ConvertTo-Gb $freed

    if (-not $didWork) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    Write-Good ("Reclaimed {0} GB on {1}: (volume free space changed by {2} GB)" -f $deltaGb, $sysDrive, (ConvertTo-Gb ($after - $before)))

    return @{ Status = 'OK'; Detail = "Reclaimed $deltaGb GB" }
}

function Invoke-DiskCleanupTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$UseDiskCleanup = $UseDiskCleanup)

    if (-not $UseDiskCleanup) { return @{ Status = 'Skipped'; Detail = 'Not requested (-UseDiskCleanup)' } }
    $cleanmgr = Get-Command cleanmgr.exe -ErrorAction SilentlyContinue
    if (-not $cleanmgr) {
        return @{ Status = 'Skipped'; Detail = 'cleanmgr.exe not present (deprecated in favour of Storage Sense)' }
    }
    if (-not $PSCmdlet.ShouldProcess('Disk Cleanup', 'Run scripted sageset profile')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $sageId = 7777
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    # Allow-list, not a deny-list: a missed/renamed handler in a deny-list silently stays enabled
    # and can destroy user data (e.g. the Downloads folder handler), whereas a miss here just
    # skips cleanup for that one category. Verified against actual VolumeCaches key names.
    $allow = @(
        'Temporary Files', 'Temporary Setup Files', 'Recycle Bin', 'Thumbnail Cache',
        'Delivery Optimization Files', 'Update Cleanup', 'D3D Shader Cache',
        'Windows Error Reporting Files',
        'Downloaded Program Files', 'Internet Cache Files'
    )

    $count = 0
    try {
        Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
            $leaf = Split-Path $_.PSPath -Leaf
            if ($allow -contains $leaf) {
                try {
                    New-ItemProperty -Path $_.PSPath -Name "StateFlags$sageId" -Value 2 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    $count++
                } catch { }
            } else {
                Remove-ItemProperty -Path $_.PSPath -Name "StateFlags$sageId" -ErrorAction SilentlyContinue
            }
        }

        Write-Info "Running cleanmgr with $count handlers enabled (profile $sageId)..."
        $p = Start-Process -FilePath $cleanmgr.Source -ArgumentList "/sagerun:$sageId" -PassThru -Wait -WindowStyle Hidden
        return @{ Status = 'OK'; Detail = "cleanmgr /sagerun:$sageId exit $($p.ExitCode)" }
    }
    finally {
        # Don't leave the sageset selection behind for a future manual/unrelated /sagerun:7777 to inherit.
        Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-ItemProperty -Path $_.PSPath -Name "StateFlags$sageId" -ErrorAction SilentlyContinue }
    }
}

function Invoke-StorageSenseReportTask {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
    if (Test-IsSystemAccount) { return @{ Status = 'Skipped'; Detail = 'Per-user setting; not meaningful under SYSTEM' } }
    if (-not (Test-Path $key)) {
        Add-Finding 'Storage Sense has never been configured. Settings > System > Storage > Storage Sense keeps temp files and the Recycle Bin trimmed automatically.'
        return @{ Status = 'Warning'; Detail = 'Storage Sense not configured' }
    }
    $p = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    $enabled = 0
    if ($p -and $p.PSObject.Properties.Name -contains '01') { $enabled = [int]$p.'01' }
    Write-Info "Storage Sense enabled: $([bool]$enabled)"
    if (-not $enabled) {
        Add-Finding 'Storage Sense is off. Turning it on gives you automatic, ongoing cleanup between maintenance runs.'
        return @{ Status = 'Warning'; Detail = 'Storage Sense disabled' }
    }
    return @{ Status = 'OK'; Detail = 'Storage Sense enabled' }
}

#endregion

#region ---------------------------------------------------------------- Task: diagnostics

function Invoke-EventLogReviewTask {
    $since = (Get-Date).AddDays(-$EventLogDays)
    $summary = @()

    foreach ($log in 'System', 'Application') {
        try {
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName   = $log
                Level     = 1, 2      # Critical, Error
                StartTime = $since
            } -ErrorAction Stop)
        } catch {
            continue   # no matching events
        }

        if ($events.Count -eq 0) { continue }
        Write-Info ("{0} log: {1} critical/error events in the last {2} days" -f $log, $events.Count, $EventLogDays)

        $top = $events | Group-Object -Property Id, ProviderName |
               Sort-Object Count -Descending | Select-Object -First 6
        $top | ForEach-Object {
            $sample = $_.Group[0]
            Write-Host ("      {0,4}x  Id {1,-6} {2}" -f $_.Count, $sample.Id, $sample.ProviderName) -ForegroundColor Gray
        }
        $summary += "$log=$($events.Count)"
    }

    # Unexpected shutdowns and bugchecks.
    $critical = @()
    foreach ($id in 41, 1001, 6008) {
        try {
            $e = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $id; StartTime = $since } -ErrorAction Stop)
            if ($e.Count -gt 0) { $critical += "Event $id x$($e.Count)" }
        } catch { }
    }
    if ($critical.Count -gt 0) {
        Write-Warn ("Instability indicators: {0}" -f ($critical -join ', '))
        Add-Finding ("System log shows {0} in the last {1} days (41=unexpected shutdown, 1001=bugcheck, 6008=dirty shutdown). Investigate drivers and memory." -f ($critical -join ', '), $EventLogDays)
    }

    # Minidumps.
    $dumpDir = "$env:SystemRoot\Minidump"
    if (Test-Path $dumpDir) {
        $dumps = @(Get-ChildItem -LiteralPath $dumpDir -Filter '*.dmp' -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -gt $since })
        if ($dumps.Count -gt 0) {
            Write-Warn "$($dumps.Count) crash dump(s) in $dumpDir within the window."
            $dumps | Select-Object -First 5 | ForEach-Object {
                Write-Host ("      {0:yyyy-MM-dd HH:mm}  {1}" -f $_.LastWriteTime, $_.Name) -ForegroundColor Gray
            }
            Add-Finding "Crash dumps present in $dumpDir. Analyse with WinDbg (!analyze -v) or check Reliability Monitor."
        }
    }

    if ($critical.Count -gt 0) { return @{ Status = 'Warning'; Detail = ($critical -join ', ') } }
    if ($summary.Count -eq 0)  { return @{ Status = 'OK'; Detail = "No critical/error events in $EventLogDays days" } }
    return @{ Status = 'OK'; Detail = ($summary -join ', ') }
}

function Invoke-DriverHealthTask {
    $bad = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
             Where-Object { $_.ConfigManagerErrorCode -ne 0 })

    if ($bad.Count -eq 0) {
        Write-Good 'No devices reporting a problem code.'
    } else {
        Write-Warn "$($bad.Count) device(s) reporting a problem code:"
        $bad | Select-Object -Property Name, DeviceID, ConfigManagerErrorCode, Status -First 15 |
            Format-Table -AutoSize | Out-String -Width 200 | Write-Host
        Add-Finding "$($bad.Count) device(s) have a Device Manager problem code. Update or reinstall the affected drivers."
    }

    # Surface oldest third-party drivers - a common source of instability.
    try {
        $drivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop |
                     Where-Object { $_.DriverProviderName -and $_.DriverProviderName -ne 'Microsoft' -and $_.DriverDate } |
                     Sort-Object DriverDate |
                     Select-Object -Property DeviceName, DriverProviderName, DriverVersion, DriverDate -First 8)
        if ($drivers) {
            Write-Info 'Oldest non-Microsoft drivers:'
            $drivers | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
        }
    } catch { }

    if ($bad.Count -gt 0) { return @{ Status = 'Warning'; Detail = "$($bad.Count) device problem code(s)" } }
    return @{ Status = 'OK'; Detail = 'All devices nominal' }
}

function Invoke-WmiRepositoryTask {
    $r = Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\wbem\winmgmt.exe" -ArgumentList @('/verifyrepository')
    # winmgmt's console text is localized; its exit code (0 = consistent) is not. A nonzero exit
    # code is still ambiguous though - a tool-level failure (e.g. not elevated) also returns
    # nonzero and prints an "Error code:" line, which a genuine inconsistency finding does not.
    if ($r.ExitCode -eq 0) {
        Write-Good 'WMI repository is consistent.'
        return @{ Status = 'OK'; Detail = 'WMI repository consistent' }
    }
    if ($r.Output -match 'Error code:') {
        Write-Warn "WMI repository check could not run: $($r.Output)"
        return @{ Status = 'Warning'; Detail = "Could not verify repository (exit $($r.ExitCode))" }
    }
    Write-Warn "WMI repository check: $($r.Output)"
    Add-Finding 'The WMI repository reported an inconsistency. Try "winmgmt /salvagerepository" from an elevated prompt; rebuild only as a last resort.'
    return @{ Status = 'Warning'; Detail = "WMI repository inconsistent (exit $($r.ExitCode))" }
}

function Invoke-ServiceHealthTask {
    # Services that should be running on a healthy Windows 11 client.
    $expected = @{
        'wuauserv'   = 'Windows Update'
        'WinDefend'  = 'Microsoft Defender Antivirus'
        'BFE'        = 'Base Filtering Engine'
        'Dnscache'   = 'DNS Client'
        'EventLog'   = 'Windows Event Log'
        'Winmgmt'    = 'WMI'
        'CryptSvc'   = 'Cryptographic Services'
        'TrustedInstaller' = 'Windows Modules Installer'
        'VSS'        = 'Volume Shadow Copy'
    }
    $problems = @()
    foreach ($name in $expected.Keys) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        # wuauserv and TrustedInstaller are demand-start; only flag Disabled.
        if ($svc.StartType -eq 'Disabled') {
            $problems += "$name ($($expected[$name])) is Disabled"
        }
    }

    # Informational only: plenty of Automatic services are delayed-start and legitimately idle
    # early in a session, so this is a list to eyeball, not a failure condition.
    $idle = @(Get-Service -ErrorAction SilentlyContinue |
              Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' })
    if ($idle.Count -gt 0) {
        Write-Info "$($idle.Count) Automatic service(s) not currently running (delayed-start entries are normal):"
        $idle | Select-Object -Property Name, DisplayName, Status -First 15 |
            Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    }

    if ($problems.Count -gt 0) {
        foreach ($p in $problems) { Write-Bad "  $p" }
        Add-Finding ("Core services disabled: {0}." -f ($problems -join '; '))
        return @{ Status = 'Warning'; Detail = ($problems -join '; ') }
    }
    return @{ Status = 'OK'; Detail = "Core services nominal ($($idle.Count) automatic services idle)" }
}

function Invoke-PowerConfigTask {
    $r = Invoke-NativeCommand -FilePath 'powercfg.exe' -ArgumentList @('/getactivescheme')
    Write-Info $r.Output

    # Fast startup hides a true cold boot and is a frequent cause of "the reboot didn't fix it".
    $hiberKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
    try {
        $p = Get-ItemProperty -Path $hiberKey -ErrorAction Stop
        if ($p.PSObject.Properties.Name -contains 'HiberbootEnabled' -and $p.HiberbootEnabled -eq 1) {
            Write-Info 'Fast Startup is enabled. Remember: "Shut down" then power on is NOT a full reboot - use Restart.'
        }
    } catch { }

    # Battery report on portables.
    $battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if ($battery -and -not $script:ReadOnlyRun) {
        $out = Join-Path $script:RunLogDir 'battery-report.html'
        $null = Invoke-NativeCommand -FilePath 'powercfg.exe' -ArgumentList @('/batteryreport', '/output', $out)
        if (Test-Path $out) { Write-Info "Battery report written to $out" }
    }

    # Sleep study / energy diagnostics are expensive; Full level only.
    if ($script:CurrentRank -ge 3 -and -not $script:ReadOnlyRun) {
        $sleepOut = Join-Path $script:RunLogDir 'sleepstudy.html'
        $null = Invoke-NativeCommand -FilePath 'powercfg.exe' -ArgumentList @('/sleepstudy', '/output', $sleepOut)
        if (Test-Path $sleepOut) { Write-Info "Sleep study written to $sleepOut" }
    }

    return @{ Status = 'OK'; Detail = 'Power configuration reviewed' }
}

function Invoke-StartupImpactTask {
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )
    $entries = New-Object System.Collections.Generic.List[psobject]
    foreach ($k in $runKeys) {
        if (-not (Test-Path $k)) { continue }
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }   # key exists but holds no values
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $entries.Add([pscustomobject]@{ Hive = $k.Split('\')[0]; Name = $p.Name; Command = $p.Value }) | Out-Null
        }
    }

    if ($entries.Count -gt 0) {
        Write-Info "$($entries.Count) registry Run entries:"
        $entries | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    }

    $tasks = @()
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop |
                   Where-Object {
                       $_.State -eq 'Ready' -and
                       (@($_.Triggers) | Where-Object { $_ -and $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' } | Measure-Object).Count -gt 0
                   } |
                   Select-Object -Property TaskName, TaskPath -First 15)
    } catch { }
    if ($tasks) {
        Write-Info 'Logon-triggered scheduled tasks (first 15):'
        $tasks | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    }

    if ($entries.Count -gt 15) {
        Add-Finding "$($entries.Count) programs launch at sign-in. Trim the list in Task Manager > Startup apps to cut boot time."
        return @{ Status = 'Warning'; Detail = "$($entries.Count) startup entries" }
    }
    return @{ Status = 'OK'; Detail = "$($entries.Count) startup entries" }
}

function Invoke-PendingRebootTask {
    # @() guards against PowerShell unwrapping a single-element return to a bare scalar, which
    # has no .Count on Windows PowerShell 5.1 under Set-StrictMode (PS7's .Count shim hides this).
    $reasons = @(Get-PendingRebootDetail)
    if ($reasons.Count -gt 0) {
        $script:RebootNeeded = $true
        foreach ($r in $reasons) { Write-Warn "  pending: $r" }
        Add-Finding ("A restart is pending ({0}). Servicing work will not complete until you restart." -f ($reasons -join ', '))
        return @{ Status = 'Warning'; Detail = ($reasons -join ', ') }
    }
    if ($script:RebootNeeded) {
        return @{ Status = 'Warning'; Detail = 'Reboot recommended by this run' }
    }
    Write-Good 'No pending reboot.'
    return @{ Status = 'OK'; Detail = 'No pending reboot' }
}

#endregion

#region ---------------------------------------------------------------- Reporting

function ConvertTo-HtmlSafe {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Write-HtmlReport {
    param([Parameter(Mandatory)][string]$Path)

    $snap = $script:Snapshot
    if (-not $snap) { $snap = Get-SystemSnapshot }
    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)

    $statusColor = @{
        'OK' = '#2ea043'; 'Repaired' = '#58a6ff'; 'Warning' = '#d29922'
        'Failed' = '#f85149'; 'Skipped' = '#6e7681'
    }

    $rows = foreach ($r in $script:Results) {
        $color = $statusColor[$r.Status]
        if (-not $color) { $color = '#8b949e' }
        @"
<tr>
  <td>$(ConvertTo-HtmlSafe $r.Category)</td>
  <td>$(ConvertTo-HtmlSafe $r.Task)</td>
  <td><span class="pill" style="background:$color">$($r.Status)</span></td>
  <td class="num">$($r.Seconds)</td>
  <td>$(ConvertTo-HtmlSafe ([string]$r.Detail))</td>
</tr>
"@
    }

    $findingItems = foreach ($f in $script:Findings) {
        "<li>$(ConvertTo-HtmlSafe $f)</li>"
    }
    if (-not $findingItems) { $findingItems = '<li>No action items. System is nominal.</li>' }

    $counts = $script:Results | Group-Object Status | ForEach-Object { "$($_.Name): $($_.Count)" }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Imperial Maintenance Report - $(ConvertTo-HtmlSafe $snap.ComputerName)</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:'Segoe UI',system-ui,sans-serif; margin:0; padding:32px; }
  h1 { color:#f85149; font-size:24px; margin:0 0 4px; letter-spacing:1px; }
  h2 { color:#58a6ff; font-size:16px; margin:28px 0 10px; border-bottom:1px solid #21262d; padding-bottom:6px; }
  .sub { color:#8b949e; font-size:13px; margin-bottom:20px; }
  table { border-collapse:collapse; width:100%; font-size:13px; }
  th { text-align:left; color:#8b949e; font-weight:600; padding:8px; border-bottom:1px solid #30363d; }
  td { padding:7px 8px; border-bottom:1px solid #161b22; vertical-align:top; }
  td.num { text-align:right; color:#8b949e; }
  tr:hover td { background:#161b22; }
  .pill { display:inline-block; padding:2px 9px; border-radius:10px; color:#0d1117; font-weight:700; font-size:11px; }
  .kv { display:grid; grid-template-columns:200px 1fr; gap:4px 16px; font-size:13px; }
  .kv div:nth-child(odd) { color:#8b949e; }
  ul { font-size:13px; line-height:1.7; }
  code { background:#161b22; padding:1px 5px; border-radius:4px; color:#79c0ff; }
</style></head><body>
<h1>IMPERIAL MAINTENANCE PROTOCOL</h1>
<div class="sub">$(ConvertTo-HtmlSafe $snap.ComputerName) &nbsp;|&nbsp; $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;|&nbsp; level: $Level &nbsp;|&nbsp; duration: $duration min &nbsp;|&nbsp; script v$($script:ScriptVersion)</div>

<h2>System</h2>
<div class="kv">
  <div>Operating system</div><div>$(ConvertTo-HtmlSafe "$($snap.Caption) $($snap.DisplayVersion) (build $($snap.FullBuild))")</div>
  <div>Edition</div><div>$(ConvertTo-HtmlSafe $snap.Edition)</div>
  <div>Hardware</div><div>$(ConvertTo-HtmlSafe "$($snap.Manufacturer) $($snap.Model)")</div>
  <div>Processor</div><div>$(ConvertTo-HtmlSafe $snap.Cpu) &mdash; $($snap.Cores)C / $($snap.Threads)T</div>
  <div>Memory</div><div>$($snap.MemoryGb) GB</div>
  <div>Firmware</div><div>$(ConvertTo-HtmlSafe $snap.BiosVersion)</div>
  <div>Uptime at start</div><div>$($snap.UptimeHours) hours</div>
  <div>PowerShell</div><div>$($snap.PowerShell)</div>
  <div>Restart required</div><div>$(if ($script:RebootNeeded) { '<strong style="color:#d29922">YES</strong>' } else { 'No' })</div>
</div>

<h2>Action items</h2>
<ul>
$($findingItems -join "`n")
</ul>

<h2>Task results &mdash; $($counts -join ' &nbsp;|&nbsp; ')</h2>
<table>
<thead><tr><th>Category</th><th>Task</th><th>Status</th><th>Sec</th><th>Detail</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>

</body></html>
"@

    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

function Write-RunSummary {
    Write-Banner 'Maintenance summary'

    $script:Results |
        Where-Object { $_.Status -ne 'Skipped' } |
        Select-Object Category, Task, Status, Seconds, Detail |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Host

    $skipped = @($script:Results | Where-Object { $_.Status -eq 'Skipped' })
    if ($skipped.Count -gt 0) {
        Write-Host ("  Skipped: {0} task(s) - {1}" -f $skipped.Count, (($skipped.Task) -join ', ')) -ForegroundColor DarkGray
    }

    $counts = $script:Results | Group-Object Status
    Write-Host ''
    foreach ($c in $counts) {
        $color = switch ($c.Name) {
            'OK' { 'Green' } 'Repaired' { 'Cyan' } 'Warning' { 'Yellow' }
            'Failed' { 'Red' } default { 'DarkGray' }
        }
        Write-Host ("  {0,-10} {1}" -f $c.Name, $c.Count) -ForegroundColor $color
    }

    if ($script:Findings.Count -gt 0) {
        Write-Host ''
        Write-Host '  ACTION ITEMS' -ForegroundColor Yellow
        $i = 1
        foreach ($f in $script:Findings) {
            Write-Host ("   {0}. {1}" -f $i, $f) -ForegroundColor Yellow
            $i++
        }
    } else {
        Write-Host ''
        Write-Good 'No outstanding action items. All systems nominal.'
    }

    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)
    Write-Host ''
    Write-Host ("  Elapsed: {0} minutes" -f $duration) -ForegroundColor Gray
    Write-Host ("  Reports: {0}" -f $script:RunLogDir) -ForegroundColor Gray

    if ($script:RebootNeeded) {
        Write-Host ''
        Write-Host '  ***  A RESTART IS REQUIRED TO COMPLETE THIS MAINTENANCE  ***' -ForegroundColor Red
        Write-Host '       Use Restart, not Shut Down - Fast Startup skips a true cold boot.' -ForegroundColor DarkYellow
    }
}

#endregion

#region ---------------------------------------------------------------- Scheduled task

function Register-MaintenanceTask {
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) { throw 'Cannot determine script path for scheduled task registration.' }

    # Prefer the machine-wide, version-independent PS7 install. A per-user/Store (MSIX) pwsh.exe
    # lives under a version-specific WindowsApps folder that disappears on the next PS7 update,
    # silently breaking the task, so fall back to the always-stable Windows PowerShell 5.1 instead
    # of baking in a fragile versioned path.
    $exe = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
    if (-not (Test-Path $exe)) {
        $exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        Write-Warn 'PowerShell 7 machine-wide install not found; the scheduled task will use Windows PowerShell 5.1 instead.'
    }

    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Level Standard -SkipRestorePoint' -f $scriptPath
    $action    = New-ScheduledTaskAction -Execute $exe -Argument $arguments
    $trigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd `
                    -ExecutionTimeLimit (New-TimeSpan -Hours 4) -MultipleInstances IgnoreNew `
                    -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 30)

    Register-ScheduledTask -TaskName 'Imperial Maintenance Protocol' `
        -Description 'Weekly Windows 11 integrity, storage, servicing and cleanup pass.' `
        -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    Write-Good 'Scheduled task "Imperial Maintenance Protocol" registered (Sundays 03:00, SYSTEM).'
    Write-Info 'Note: winget and per-user cleanup are skipped under SYSTEM. Run those interactively.'
}

#endregion

#region ---------------------------------------------------------------- Task catalogue

$script:TaskCatalogue = @(
    New-MaintenanceTask -Name 'System Inventory'          -Category 'Baseline'    -MinLevel 1 -ReadOnly -Action { Invoke-InventoryTask }
    New-MaintenanceTask -Name 'Servicing Lifecycle Check' -Category 'Baseline'    -MinLevel 1 -ReadOnly -Action { Invoke-LifecycleTask }
    New-MaintenanceTask -Name 'Free Space Check'          -Category 'Baseline'    -MinLevel 1 -ReadOnly -Action { Invoke-FreeSpaceTask }
    New-MaintenanceTask -Name 'System Restore Point'      -Category 'Baseline'    -MinLevel 2           -Action { Invoke-RestorePointTask }

    New-MaintenanceTask -Name 'DISM Health Chain'         -Category 'Integrity'   -MinLevel 1 -ReadOnly -Action { Invoke-DismHealthChain }
    New-MaintenanceTask -Name 'SFC System File Scan'      -Category 'Integrity'   -MinLevel 2 -ReadOnly -Action { Invoke-SfcTask }
    New-MaintenanceTask -Name 'CBS Log Review'            -Category 'Integrity'   -MinLevel 2 -ReadOnly -Action { Invoke-CbsLogReviewTask }
    New-MaintenanceTask -Name 'Component Store Cleanup'   -Category 'Integrity'   -MinLevel 3           -Action { Invoke-ComponentStoreTask }

    New-MaintenanceTask -Name 'Physical Disk Health'      -Category 'Storage'     -MinLevel 1 -ReadOnly -Action { Invoke-PhysicalDiskHealthTask }
    New-MaintenanceTask -Name 'Volume File System Scan'   -Category 'Storage'     -MinLevel 2 -ReadOnly -Action { Invoke-VolumeScanTask }
    New-MaintenanceTask -Name 'CHKDSK Scheduling'         -Category 'Storage'     -MinLevel 2           -Action { Invoke-ChkdskScheduleTask }
    New-MaintenanceTask -Name 'Volume Optimization'       -Category 'Storage'     -MinLevel 2           -Action { Invoke-OptimizeVolumeTask }

    New-MaintenanceTask -Name 'Windows Update'            -Category 'Servicing'   -MinLevel 1 -ReadOnly -Action { Invoke-WindowsUpdateTask }
    New-MaintenanceTask -Name 'Windows Update Stack Repair' -Category 'Servicing' -MinLevel 2           -Action { Invoke-WindowsUpdateRepairTask }
    New-MaintenanceTask -Name 'Store App Update Scan'     -Category 'Servicing'   -MinLevel 2           -Action { Invoke-StoreAppUpdateTask }
    New-MaintenanceTask -Name 'Winget & Store App Upgrade' -Category 'Servicing'  -MinLevel 2           -Action { Invoke-WingetTask }
    New-MaintenanceTask -Name 'PowerShell Hygiene'        -Category 'Servicing'   -MinLevel 3           -Action { Invoke-PowerShellHygieneTask }

    New-MaintenanceTask -Name 'Defender Health'           -Category 'Security'    -MinLevel 1 -ReadOnly -Action { Invoke-DefenderTask }
    New-MaintenanceTask -Name 'Security Posture'          -Category 'Security'    -MinLevel 2 -ReadOnly -Action { Invoke-SecurityPostureTask }

    New-MaintenanceTask -Name 'Temp and Cache Cleanup'    -Category 'Cleanup'     -MinLevel 1           -Action { Invoke-CleanupTask }
    New-MaintenanceTask -Name 'Disk Cleanup Profile'      -Category 'Cleanup'     -MinLevel 2           -Action { Invoke-DiskCleanupTask }
    New-MaintenanceTask -Name 'Storage Sense Review'      -Category 'Cleanup'     -MinLevel 2 -ReadOnly -Action { Invoke-StorageSenseReportTask }

    New-MaintenanceTask -Name 'Event Log Review'          -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-EventLogReviewTask }
    New-MaintenanceTask -Name 'Driver and Device Health'  -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-DriverHealthTask }
    New-MaintenanceTask -Name 'Service Health'            -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-ServiceHealthTask }
    New-MaintenanceTask -Name 'WMI Repository Check'      -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-WmiRepositoryTask }
    New-MaintenanceTask -Name 'Power Configuration'       -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-PowerConfigTask }
    New-MaintenanceTask -Name 'Startup Impact Review'     -Category 'Diagnostics' -MinLevel 3 -ReadOnly -Action { Invoke-StartupImpactTask }
    New-MaintenanceTask -Name 'Pending Reboot Check'      -Category 'Diagnostics' -MinLevel 1 -ReadOnly -Action { Invoke-PendingRebootTask }
)

#endregion

#region ---------------------------------------------------------------- Main

if ($ListTasks) {
    $script:TaskCatalogue |
        Select-Object @{ n = 'Task';     e = { $_.Name } },
                      @{ n = 'Category'; e = { $_.Category } },
                      @{ n = 'RunsAt';   e = { switch ($_.MinLevel) {
                                                   1       { 'Quick, Standard, Full' }
                                                   2       { 'Standard, Full' }
                                                   default { 'Full only' } } } },
                      @{ n = 'AuditSafe'; e = { $_.ReadOnly } } |
        Format-Table -AutoSize
    return
}

# --- Elevation -----------------------------------------------------------
if (-not (Test-Elevated)) {
    if ($NoElevatePrompt) { throw 'Administrator privileges are required. Re-run from an elevated session.' }

    Write-Warn 'Administrator privileges required. Relaunching elevated...'
    $exe = (Get-Process -Id $PID).Path
    if (-not $exe) { $exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }

    # -File cannot bind arrays ('a','b' arrives as one string) and mangles a trailing backslash,
    # so rebuild the call as single-quoted PowerShell and pass it as an encoded command.
    $command = "& '{0}'" -f ($PSCommandPath -replace "'", "''")
    foreach ($kvp in $PSBoundParameters.GetEnumerator()) {
        if ($kvp.Value -is [switch]) {
            $command += " -$($kvp.Key):`$$([bool]$kvp.Value)"
        }
        else {
            $values = @($kvp.Value | ForEach-Object { "'{0}'" -f ("$_" -replace "'", "''") })
            $command += " -$($kvp.Key) $($values -join ',')"
        }
    }
    $command += '; exit $LASTEXITCODE'
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand',
                  [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command)))
    # -Wait/-PassThru so the caller's exit code reflects the elevated run instead of "launched OK".
    $proc = Start-Process -FilePath $exe -Verb RunAs -ArgumentList $relaunch -PassThru -Wait
    exit $proc.ExitCode
}

if ($RegisterScheduledTask) {
    if ($PSCmdlet.ShouldProcess('Task Scheduler', "Register weekly 'Imperial Maintenance Protocol' task")) {
        Register-MaintenanceTask
    }
    return
}

# --- Logging -------------------------------------------------------------
$script:RunLogDir = Join-Path $LogRoot ($script:StartTime.ToString('yyyy-MM-dd_HHmmss'))
$null = New-Item -Path $script:RunLogDir -ItemType Directory -Force

try {
    Start-Transcript -Path (Join-Path $script:RunLogDir 'transcript.log') -Force | Out-Null
    $script:TranscriptOn = $true
} catch { }

Write-Banner "Imperial Maintenance Protocol v$($script:ScriptVersion)"
Write-Host ("  Level      : {0}{1}" -f $Level, $(if ($script:ReadOnlyRun) { '  (read-only - nothing will be modified)' } else { '' })) -ForegroundColor Gray
Write-Host ("  Started    : {0:yyyy-MM-dd HH:mm:ss}" -f $script:StartTime) -ForegroundColor Gray
Write-Host ("  Operator   : {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) -ForegroundColor Gray
Write-Host ("  Log folder : {0}" -f $script:RunLogDir) -ForegroundColor Gray
if (-not $script:ReadOnlyRun) {
    Write-Host '  Close open work before continuing. Some steps take 10-30 minutes each.' -ForegroundColor DarkYellow
}

Suspend-Sleep

try {
    foreach ($task in $script:TaskCatalogue) {
        Invoke-MaintenanceTask -Task $task
    }

    # --- Reports ---------------------------------------------------------
    try {
        $htmlPath = Join-Path $script:RunLogDir 'maintenance-report.html'
        Write-HtmlReport -Path $htmlPath
    } catch {
        Write-Warn "HTML report generation failed: $($_.Exception.Message)"
    }

    try {
        $jsonPath = Join-Path $script:RunLogDir 'results.json'
        [pscustomobject]@{
            ScriptVersion = $script:ScriptVersion
            StartedUtc    = $script:StartTime.ToUniversalTime().ToString('o')
            Level         = $Level
            System        = $script:Snapshot
            RebootNeeded  = $script:RebootNeeded
            Findings      = @($script:Findings)
            Results       = @($script:Results)
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    } catch {
        Write-Warn "JSON report generation failed: $($_.Exception.Message)"
    }

    Write-RunSummary
}
finally {
    Resume-Sleep
    if ($script:TranscriptOn) { try { Stop-Transcript | Out-Null } catch { } }
}

#endregion
