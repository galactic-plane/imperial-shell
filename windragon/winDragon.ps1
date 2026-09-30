# WinDragon Maintenance Script - v2.0.0
# Author: Daniel Penrod
#
# A menu-driven front end for a full, auditable Windows 11 maintenance pass. The maintenance
# engine (29 tasks across Baseline, Integrity, Storage, Servicing, Security, Cleanup and
# Diagnostics, plus console/JSON/HTML reporting) is a one-to-one replica of the Imperial
# Maintenance Protocol (vader\Invoke-ImperialMaintenance.ps1); only the interface differs.
#
# Supported Operating Systems: Windows 11 (build 22000+), validated against 24H2 / 25H2 / 26H2.
# Shell: PowerShell 7.x preferred; remains compatible with Windows PowerShell 5.1.
# Privileges: Administrator required (self-elevates unless -NoElevatePrompt).
#
# How to run
#   Interactive menu (default when none of -RunChoice / -Level / -OnlyTask is given and the host
#   can prompt; a -NonInteractive or service host runs unattended instead):
#     .\winDragon.ps1
#     Any switch passed on the command line (e.g. -UpgradeApps) pre-sets the matching menu option.
#
#   Unattended - same behaviour and parameters as Invoke-ImperialMaintenance.ps1:
#     .\winDragon.ps1 -Level Audit
#     .\winDragon.ps1 -Level Full -InstallWindowsUpdates -UpgradeApps -IncludeDefenderScan
#     .\winDragon.ps1 -OnlyTask 'DISM*','SFC*' -Verbose
#     .\winDragon.ps1 -WhatIf -Level Standard
#     .\winDragon.ps1 -ListTasks
#     .\winDragon.ps1 -RegisterScheduledTask
#
#   Unattended by menu number (used by launcher.ps1):
#     .\winDragon.ps1 -RunChoice 1    Audit pass
#     .\winDragon.ps1 -RunChoice 2    Quick pass
#     .\winDragon.ps1 -RunChoice 3    Standard pass
#     .\winDragon.ps1 -RunChoice 4    Full pass
#     .\winDragon.ps1 -RunChoice 8    List task catalogue
#     .\winDragon.ps1 -RunChoice 9    Register weekly scheduled task
#     Options 5-7 (category picker, task picker, options) are interactive-only.
#
# Notes for build.py: this file is comment-stripped line by line when bundled, so keep code
# here free of block comments and of the hash character inside strings. Module files are
# copied verbatim and are not subject to that restriction.

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

    [string]$LogRoot = (Join-Path $env:ProgramData 'WinDragonMaintenance'),

    [switch]$RegisterScheduledTask,
    [switch]$NoElevatePrompt,

    [ValidateRange(1, 10)]
    [int]$RunChoice
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'Continue'

# Constants, output helpers, native-command infrastructure and the task engine.
. $PSScriptRoot\Modules\Core.ps1
# Task implementations, grouped exactly like the vader catalogue.
. $PSScriptRoot\Modules\Baseline.ps1
. $PSScriptRoot\Modules\Integrity.ps1
. $PSScriptRoot\Modules\Storage.ps1
. $PSScriptRoot\Modules\Servicing.ps1
. $PSScriptRoot\Modules\Security.ps1
. $PSScriptRoot\Modules\Cleanup.ps1
. $PSScriptRoot\Modules\Diagnostics.ps1
# Console summary and HTML report.
. $PSScriptRoot\Modules\Reporting.ps1
# Ordered task catalogue.
. $PSScriptRoot\Modules\Catalogue.ps1
# Menu-driven WinDragon interface.
. $PSScriptRoot\Modules\Interface.ps1

# Lives in the entry script (not a module) so PSCommandPath resolves to this file, not a module.
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

    Register-ScheduledTask -TaskName 'WinDragon Maintenance Protocol' `
        -Description 'Weekly Windows 11 integrity, storage, servicing and cleanup pass.' `
        -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    Write-Good 'Scheduled task "WinDragon Maintenance Protocol" registered (Sundays 03:00, SYSTEM).'
    Write-Info 'Note: winget and per-user cleanup are skipped under SYSTEM. Run those interactively.'
}

if ($ListTasks) {
    Get-TaskCatalogueView | Format-Table -AutoSize
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
    if ($PSCmdlet.ShouldProcess('Task Scheduler', "Register weekly 'WinDragon Maintenance Protocol' task")) {
        Register-MaintenanceTask
    }
    return
}

# --- Dispatch ------------------------------------------------------------
# A host that cannot prompt (-NonInteractive, service session) runs unattended exactly like vader.
$script:CanPrompt = [Environment]::UserInteractive -and
                    -not @([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^[-/]noni' }).Count
$script:HeadlessRun = $PSBoundParameters.ContainsKey('RunChoice') -or
                      $PSBoundParameters.ContainsKey('Level') -or
                      $PSBoundParameters.ContainsKey('OnlyTask') -or
                      -not $script:CanPrompt

if (-not $script:HeadlessRun) {
    Start-InteractiveMenu
    return
}

if ($PSBoundParameters.ContainsKey('RunChoice')) {
    $null = Invoke-MenuChoice -Choice $RunChoice
    return
}

Start-MaintenanceRun
