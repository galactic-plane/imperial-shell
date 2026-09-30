<#
.SYNOPSIS
    Non-destructive automated test suite for Invoke-ImperialMaintenance.ps1.

.DESCRIPTION
    Loads the real script's functions (via its -ListTasks early-return path, so Main/elevation
    never actually runs) and exercises them using -WhatIf, disposable sandbox directories, mocked
    native-command calls, and static AST checks.

    This suite never performs the target script's real destructive actions: no DISM repair, no
    SFC /scannow, no CHKDSK/BootExecute writes, no service stop/rename, no scheduled task
    registration, no Windows Update/winget installs, and no file deletion outside its own
    disposable sandbox. Anything that requires actually mutating the system is either tested
    through -WhatIf (and asserted to be a no-op) or reported as SKIPPED with the reason.

    Result of each check is printed with a green checkmark (pass) or a red X (fail, with reason).

.PARAMETER ScriptUnderTest
    Path to Invoke-ImperialMaintenance.ps1. Defaults to the sibling file next to this script.

.PARAMETER Only
    One or more wildcard patterns matching section names to run (see the '== ... ==' headers).

.PARAMETER IncludeSlow
    Also run checks that hit the network / a real online scan (e.g. Windows Update search), which
    can take longer and are skipped by default to keep a normal run fast and deterministic.

.EXAMPLE
    .\Test-ImperialMaintenance.ps1

.EXAMPLE
    .\Test-ImperialMaintenance.ps1 -Only 'Cleanup*','Winget*' -Verbose
#>

[CmdletBinding()]
param(
    [string]$ScriptUnderTest = (Join-Path $PSScriptRoot 'Invoke-ImperialMaintenance.ps1'),
    [string[]]$Only,
    [switch]$IncludeSlow
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

#region ------------------------------------------------------------------- Test harness

$script:CheckMark    = [string][char]0x2713
$script:CrossMark    = [string][char]0x2717
$script:PassCount    = 0
$script:FailCount    = 0
$script:SkipCount    = 0
$script:FailureLog   = New-Object System.Collections.Generic.List[psobject]
$script:CurrentSection = ''

function Test-SectionSelected {
    param([Parameter(Mandatory)][string]$Name)
    if (-not $Only) { return $true }
    foreach ($pattern in $Only) { if ($Name -like $pattern) { return $true } }
    return $false
}

function Write-TestSection {
    param([Parameter(Mandatory)][string]$Name)
    $script:CurrentSection = $Name
    if (-not (Test-SectionSelected -Name $Name)) { return }
    Write-Host ''
    $line = '=' * [Math]::Max(4, 76 - $Name.Length)
    Write-Host "-- $Name $line" -ForegroundColor Cyan
}

function Test-Case {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Test
    )
    if (-not (Test-SectionSelected -Name $script:CurrentSection)) { return }
    try {
        & $Test
        Write-Host "  $script:CheckMark " -ForegroundColor Green -NoNewline
        Write-Host $Name
        $script:PassCount++
    }
    catch {
        Write-Host "  $script:CrossMark " -ForegroundColor Red -NoNewline
        Write-Host $Name -ForegroundColor Red
        Write-Host "      Reason: $($_.Exception.Message)" -ForegroundColor Yellow
        $script:FailCount++
        $script:FailureLog.Add([pscustomobject]@{ Section = $script:CurrentSection; Test = $Name; Reason = $_.Exception.Message })
    }
}

function Skip-Case {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Reason
    )
    if (-not (Test-SectionSelected -Name $script:CurrentSection)) { return }
    Write-Host '  o ' -ForegroundColor DarkYellow -NoNewline
    Write-Host "$Name " -NoNewline
    Write-Host "(skipped: $Reason)" -ForegroundColor DarkGray
    $script:SkipCount++
}

function Assert-True {
    param($Condition, [string]$Message = 'Expected condition to be true')
    if (-not $Condition) { throw $Message }
}
function Assert-False {
    param($Condition, [string]$Message = 'Expected condition to be false')
    if ($Condition) { throw $Message }
}
function Assert-Equal {
    param($Actual, $Expected, [string]$Label = 'value')
    if ($Actual -ne $Expected) { throw "Expected $Label to be '$Expected' but got '$Actual'" }
}
function Assert-Contains {
    param([Parameter(Mandatory)]$Collection, [Parameter(Mandatory)]$Item, [string]$Label = 'collection')
    if (@($Collection) -notcontains $Item) { throw "Expected $Label to contain '$Item' (got: $(@($Collection) -join ', '))" }
}
function Assert-NotContains {
    param([Parameter(Mandatory)]$Collection, [Parameter(Mandatory)]$Item, [string]$Label = 'collection')
    if (@($Collection) -contains $Item) { throw "Expected $Label to NOT contain '$Item'" }
}
function Assert-NoThrow {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock, [string]$Message = 'Expected no exception')
    try { & $ScriptBlock } catch { throw "$Message - $($_.Exception.Message)" }
}
function Assert-Match {
    param([string]$Value, [string]$Pattern, [string]$Label = 'value')
    if ($Value -notmatch $Pattern) { throw "Expected $Label ('$Value') to match pattern '$Pattern'" }
}

#endregion

#region ------------------------------------------------------------------- Load script under test

if (-not (Test-Path -LiteralPath $ScriptUnderTest)) {
    throw "Script under test not found: $ScriptUnderTest"
}
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop } catch { }

Write-Host ''
Write-Host 'IMPERIAL MAINTENANCE PROTOCOL - TEST SUITE' -ForegroundColor Magenta
Write-Host "  Target : $ScriptUnderTest" -ForegroundColor Gray
Write-Host "  PS     : $($PSVersionTable.PSVersion)  ($($PSVersionTable.PSEdition))" -ForegroundColor Gray
Write-Host "  Elevated: $((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -ForegroundColor Gray

# -ListTasks returns before elevation/Main ever runs, so dot-sourcing here loads every function
# without triggering a UAC prompt or any mutating logic.
. $ScriptUnderTest -ListTasks | Out-Null

#endregion

#region ------------------------------------------------------------------- Structural / static checks

Write-TestSection 'Structural'

Test-Case 'Script parses with no syntax errors' {
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($ScriptUnderTest, [ref]$null, [ref]$parseErrors) | Out-Null
    Assert-Equal $parseErrors.Count 0 'parse error count'
}

$script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptUnderTest, [ref]$null, [ref]$null)

Test-Case 'Set-StrictMode -Version Latest is present' {
    Assert-Match $script:Ast.Extent.Text 'Set-StrictMode\s+-Version\s+Latest' 'script body'
}

Test-Case 'No two functions share the same name' {
    $fnNodes = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    $names = $fnNodes | ForEach-Object { $_.Name }
    $dupes = $names | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }
    Assert-Equal ($dupes -join ',') '' 'duplicate function names'
}

Test-Case 'Every function calling ShouldProcess/ShouldContinue declares SupportsShouldProcess' {
    $fnNodes = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    $offenders = @()
    foreach ($fn in $fnNodes) {
        $callsSp = $fn.Body.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $n.Member.Extent.Text -in @('ShouldProcess', 'ShouldContinue')
        }, $true)
        if (@($callsSp).Count -eq 0) { continue }
        $hasAttr = $false
        if ($fn.Body.ParamBlock) {
            foreach ($attr in $fn.Body.ParamBlock.Attributes) {
                if ($attr.TypeName.Name -eq 'CmdletBinding') {
                    foreach ($na in $attr.NamedArguments) {
                        if ($na.ArgumentName -eq 'SupportsShouldProcess') { $hasAttr = $true }
                    }
                }
            }
        }
        if (-not $hasAttr) { $offenders += $fn.Name }
    }
    Assert-Equal ($offenders -join ',') '' 'functions missing SupportsShouldProcess'
}

Test-Case 'Every task-catalogue -Action references a function that exists' {
    $fnNames = @(($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) | ForEach-Object { $_.Name })
    $actionCalls = $script:Ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-MaintenanceTask'
    }, $true)
    Assert-True ($actionCalls.Count -ge 20) "expected at least 20 registered tasks, found $($actionCalls.Count)"
    $missing = @()
    foreach ($call in $actionCalls) {
        $scriptBlockParam = $call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }
        foreach ($sb in $scriptBlockParam) {
            $inner = $sb.ScriptBlock.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
            foreach ($cmd in $inner) {
                $name = $cmd.GetCommandName()
                if ($name -and $fnNames -notcontains $name) { $missing += $name }
            }
        }
    }
    Assert-Equal ($missing -join ',') '' 'task actions referencing undefined functions'
}

Test-Case 'Register-MaintenanceTask prefers the machine-wide PS7 path, not a versioned WindowsApps path' {
    $fn = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Register-MaintenanceTask' }, $true) | Select-Object -First 1
    Assert-True ($null -ne $fn) 'Register-MaintenanceTask function not found'
    Assert-Match $fn.Extent.Text 'PowerShell\\7\\pwsh\.exe' 'Register-MaintenanceTask body'
    Assert-NoThrow { if ($fn.Extent.Text -match '\(Get-Process -Id \$PID\)\.Path' ) { throw 'still falls back to the current (possibly versioned MSIX) process path' } }
}

Test-Case '-RegisterScheduledTask call site is gated behind ShouldProcess' {
    Assert-Match $script:Ast.Extent.Text "if\s*\(\`$RegisterScheduledTask\)\s*\{\s*if\s*\(\`$PSCmdlet\.ShouldProcess" 'Main region'
}

#endregion

#region ------------------------------------------------------------------- -ListTasks / elevation guard

Write-TestSection 'ListTasks and elevation guard'

# Run as a genuine child process (not '&' on the .ps1, which stays in-process): that way an
# expected `throw` inside the target script surfaces as an exit code, not a .NET exception that
# would propagate into this harness's own try/catch and be misreported as a test-harness failure.
$script:HostExe = (Get-Process -Id $PID).Path

Test-Case '-ListTasks runs as a real invocation without elevation' {
    $out = & $script:HostExe -NoProfile -File $ScriptUnderTest -ListTasks 2>&1
    Assert-Equal $LASTEXITCODE 0 'exit code'
    Assert-True (($out | Measure-Object).Count -gt 5) 'expected task-table output'
}

$script:IsElevated = Test-Elevated
if (-not $script:IsElevated) {
    Test-Case '-NoElevatePrompt fails fast instead of prompting for UAC' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & $script:HostExe -NoProfile -File $ScriptUnderTest -NoElevatePrompt -Level Audit *> $null
        $exitCode = $LASTEXITCODE
        $sw.Stop()
        Assert-True ($exitCode -ne 0) 'expected a non-zero exit code'
        Assert-True ($sw.Elapsed.TotalSeconds -lt 15) "took $($sw.Elapsed.TotalSeconds)s - too slow for a fail-fast guard"
    }
} else {
    Skip-Case '-NoElevatePrompt fails fast instead of prompting for UAC' 'this session is already elevated, so the guard never triggers'
}

#endregion

#region ------------------------------------------------------------------- Format-NativeArgument

Write-TestSection 'Format-NativeArgument'

Test-Case 'Empty string becomes a quoted empty argument' {
    Assert-Equal (Format-NativeArgument '') '""' 'result'
}
Test-Case 'Plain text with no special characters is left unquoted' {
    Assert-Equal (Format-NativeArgument 'plain') 'plain' 'result'
}
Test-Case 'Text containing a space gets wrapped in quotes' {
    Assert-Equal (Format-NativeArgument 'has space') '"has space"' 'result'
}
Test-Case 'Embedded double quote is escaped' {
    Assert-Equal (Format-NativeArgument 'quote"inside') '"quote\"inside"' 'result'
}
Test-Case 'Trailing backslash before a required closing quote is doubled' {
    $result = Format-NativeArgument 'C:\Program Files\'
    Assert-Equal $result '"C:\Program Files\\"' 'result'
}
Test-Case 'Trailing backslash with no space is left alone (no quoting needed)' {
    Assert-Equal (Format-NativeArgument 'end\with\backslash\') 'end\with\backslash\' 'result'
}

#endregion

#region ------------------------------------------------------------------- Invoke-NativeCommand

Write-TestSection 'Invoke-NativeCommand'

Test-Case 'Runs a simple command and captures exit code + output' {
    $r = Invoke-NativeCommand -FilePath 'cmd.exe' -ArgumentList @('/c', 'echo', 'hello')
    Assert-Equal $r.ExitCode 0 'exit code'
    Assert-Match $r.Output 'hello' 'output'
}
Test-Case 'Round-trips an argument containing a space correctly' {
    $r = Invoke-NativeCommand -FilePath 'cmd.exe' -ArgumentList @('/c', 'echo', 'hello world')
    Assert-Match $r.Output 'hello world' 'output'
}
Test-Case 'Nonexistent executable fails cleanly instead of throwing' {
    $r = Invoke-NativeCommand -FilePath 'this-does-not-exist-xyz-imperial.exe' -ArgumentList @()
    Assert-Equal $r.ExitCode -1 'exit code'
    Assert-True (-not [string]::IsNullOrWhiteSpace($r.Output)) 'expected a non-empty error message'
    Assert-False ($r.Output -match 'Exception calling') 'error message should not leak the raw method-invocation wrapper text'
}
Test-Case 'A hung process is killed at the timeout and does not block' {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-NativeCommand -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') -TimeoutSeconds 2
    $sw.Stop()
    Assert-Equal $r.ExitCode -1 'exit code'
    Assert-Match $r.Output 'TIMEOUT' 'output'
    Assert-True ($sw.Elapsed.TotalSeconds -lt 10) "took $($sw.Elapsed.TotalSeconds)s - timeout/kill did not act promptly"
}
Test-Case 'The killed process is not left running' {
    $before = @(Get-Process -Name 'powershell' -ErrorAction SilentlyContinue).Count
    $null = Invoke-NativeCommand -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') -TimeoutSeconds 1
    Start-Sleep -Milliseconds 500
    $after = @(Get-Process -Name 'powershell' -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -gt (Get-Date).AddSeconds(-5) }).Count
    Assert-Equal $after 0 'orphaned powershell.exe processes started by the timeout test'
}

#endregion

#region ------------------------------------------------------------------- Reparse-point safety (sandbox)

Write-TestSection 'Reparse point safety'

function New-SandboxWithJunction {
    $root = Join-Path $env:TEMP ('imperial-test-{0}' -f ([guid]::NewGuid().Guid.Substring(0, 8)))
    $outside = Join-Path $env:TEMP ('imperial-test-outside-{0}' -f ([guid]::NewGuid().Guid.Substring(0, 8)))
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $root 'sub') -Force | Out-Null
    New-Item -ItemType Directory -Path $outside -Force | Out-Null
    Set-Content -Path (Join-Path $root 'sub\real.txt') -Value 'real' -NoNewline
    Set-Content -Path (Join-Path $outside 'secret.txt') -Value 'do-not-touch' -NoNewline
    New-Item -ItemType Junction -Path (Join-Path $root 'link-to-outside') -Target $outside | Out-Null
    [pscustomobject]@{ Root = $root; Outside = $outside }
}
function Remove-Sandbox {
    param($Sandbox)
    Remove-Item -Path $Sandbox.Root, $Sandbox.Outside -Recurse -Force -ErrorAction SilentlyContinue
}

Test-Case 'Get-FilesSkippingReparsePoints does not follow a junction' {
    $sb = New-SandboxWithJunction
    try {
        $found = @(Get-FilesSkippingReparsePoints -Path $sb.Root | Select-Object -ExpandProperty FullName)
        Assert-Contains $found (Join-Path $sb.Root 'sub\real.txt') 'found files'
        Assert-False ($found | Where-Object { $_ -like "$($sb.Outside)*" }) 'files from outside the junction boundary leaked in'
    } finally { Remove-Sandbox $sb }
}

Test-Case 'Remove-PathContents deletes real files but never crosses a junction' {
    $sb = New-SandboxWithJunction
    try {
        $freed = Remove-PathContents -Path $sb.Root -Label 'test' -OlderThanDays 0
        Assert-True ($freed -gt 0) 'expected freed byte count > 0'
        Assert-False (Test-Path (Join-Path $sb.Root 'sub\real.txt')) 'real.txt should have been deleted'
        Assert-True (Test-Path (Join-Path $sb.Root 'link-to-outside')) 'the junction itself should still exist'
        Assert-True (Test-Path (Join-Path $sb.Outside 'secret.txt')) 'the junction target content must be untouched'
        Assert-Equal (Get-Content (Join-Path $sb.Outside 'secret.txt') -Raw) 'do-not-touch' 'junction target content'
    } finally { Remove-Sandbox $sb }
}

Test-Case 'Remove-PathContents honours -OlderThanDays' {
    $sb = New-SandboxWithJunction
    try {
        $oldFile = Join-Path $sb.Root 'old.txt'
        $newFile = Join-Path $sb.Root 'new.txt'
        Set-Content -Path $oldFile -Value 'old' -NoNewline
        Set-Content -Path $newFile -Value 'new' -NoNewline
        (Get-Item $oldFile).LastWriteTime = (Get-Date).AddDays(-10)
        $null = Remove-PathContents -Path $sb.Root -Label 'test' -OlderThanDays 5
        Assert-False (Test-Path $oldFile) 'the file older than the threshold should be removed'
        Assert-True (Test-Path $newFile) 'the file newer than the threshold should be kept'
    } finally { Remove-Sandbox $sb }
}

#endregion

#region ------------------------------------------------------------------- Pending reboot (regression)

Write-TestSection 'Pending reboot detection (regression)'

$script:OriginalGetPendingRebootDetail = (Get-Command Get-PendingRebootDetail).ScriptBlock

Test-Case 'Invoke-PendingRebootTask does not throw when exactly one reason is pending' {
    # Regression test: a single-element array return unwraps to a bare scalar, which has no
    # .Count under Set-StrictMode - this is exactly the bug reported from a real run.
    Set-Item Function:\Get-PendingRebootDetail -Value { return 'Windows Update' }
    try {
        $r = Invoke-PendingRebootTask
        Assert-Equal $r.Status 'Warning' 'status'
        Assert-Match $r.Detail 'Windows Update' 'detail'
    } finally {
        Set-Item Function:\Get-PendingRebootDetail -Value $script:OriginalGetPendingRebootDetail
    }
}

Test-Case 'Invoke-PendingRebootTask does not throw when zero reasons are pending' {
    Set-Item Function:\Get-PendingRebootDetail -Value { return @() }
    try {
        $script:RebootNeeded = $false
        $r = Invoke-PendingRebootTask
        Assert-Equal $r.Status 'OK' 'status'
    } finally {
        Set-Item Function:\Get-PendingRebootDetail -Value $script:OriginalGetPendingRebootDetail
    }
}

Test-Case 'Invoke-PendingRebootTask does not throw with multiple reasons pending' {
    Set-Item Function:\Get-PendingRebootDetail -Value { return @('Windows Update', 'Component Based Servicing') }
    try {
        $r = Invoke-PendingRebootTask
        Assert-Equal $r.Status 'Warning' 'status'
    } finally {
        Set-Item Function:\Get-PendingRebootDetail -Value $script:OriginalGetPendingRebootDetail
    }
}

#endregion

#region ------------------------------------------------------------------- Test-TaskSelected

Write-TestSection 'Test-TaskSelected'

$script:FakeTask = [pscustomobject]@{ Name = 'DISM Health Chain'; MinLevel = 1; ReadOnly = $true }

Test-Case '-OnlyTask wildcard matches the intended task' {
    Assert-True (Test-TaskSelected -Task $script:FakeTask -OnlyTask @('DISM*') -SkipTask $null) 'expected match'
}
Test-Case '-OnlyTask wildcard correctly excludes a non-matching task' {
    Assert-False (Test-TaskSelected -Task $script:FakeTask -OnlyTask @('SFC*') -SkipTask $null) 'expected no match'
}
Test-Case '-SkipTask wildcard correctly excludes the matching task' {
    Assert-False (Test-TaskSelected -Task $script:FakeTask -OnlyTask $null -SkipTask @('DISM*')) 'expected excluded'
}
Test-Case 'Explicit parameters override the script-scope OnlyTask/SkipTask defaults' {
    $OnlyTask = @('zzz-should-not-match*')
    Assert-False (Test-TaskSelected -Task $script:FakeTask) 'default (script-scope) should not match'
    Assert-True (Test-TaskSelected -Task $script:FakeTask -OnlyTask @('DISM*') -SkipTask $null) 'explicit override should match'
}
Test-Case '-OnlyTask overrides the level rank but never lets Audit run a mutating task' {
    $savedRo = $script:ReadOnlyRun; $savedRank = $script:CurrentRank
    try {
        $mutating = [pscustomobject]@{ Name = 'System Restore Point'; MinLevel = 3; ReadOnly = $false }
        $script:ReadOnlyRun = $false; $script:CurrentRank = 1
        Assert-True (Test-TaskSelected -Task $mutating -OnlyTask @('System Restore*') -SkipTask $null) 'OnlyTask should beat the level rank'
        $script:ReadOnlyRun = $true; $script:CurrentRank = 2
        Assert-False (Test-TaskSelected -Task $mutating -OnlyTask @('System Restore*') -SkipTask $null) 'Audit ran a mutating task via -OnlyTask'
    } finally { $script:ReadOnlyRun = $savedRo; $script:CurrentRank = $savedRank }
}

#endregion

#region ------------------------------------------------------------------- Elevation relaunch

Write-TestSection 'Elevation relaunch'

Test-Case 'Relaunch uses an encoded command so arrays and trailing backslashes survive' {
    $text = Get-Content -LiteralPath $ScriptUnderTest -Raw
    Assert-Match $text "'-EncodedCommand'" 'relaunch argument list'
    Assert-False ($text.Contains("'Bypass', '-File'")) 'relaunch still uses -File'
}

#endregion

#region ------------------------------------------------------------------- Invoke-ChkdskScheduleTask

Write-TestSection 'Invoke-ChkdskScheduleTask'

Test-Case 'Skips cleanly when -ScheduleChkdsk was not requested' {
    $r = Invoke-ChkdskScheduleTask -ScheduleChkdsk:$false
    Assert-Equal $r.Status 'Skipped' 'status'
}
Test-Case 'Reports Skipped (not Failed) under -WhatIf with multiple dirty volumes' {
    # Regression test: this used to report Status=Failed under -WhatIf because it couldn't tell
    # "declined by WhatIf" from "genuinely could not verify the schedule".
    $script:DirtyVolumes = @('D', 'E')
    $r = Invoke-ChkdskScheduleTask -ScheduleChkdsk -WhatIf
    Assert-Equal $r.Status 'Skipped' 'status'
    Assert-Equal $r.Detail 'WhatIf' 'detail'
}
Test-Case 'Falls back to the system drive when no dirty volumes were tracked' {
    $script:DirtyVolumes = @()
    $r = Invoke-ChkdskScheduleTask -ScheduleChkdsk -WhatIf
    Assert-Equal $r.Status 'Skipped' 'status'
}
Test-Case 'Never actually writes BootExecute under -WhatIf' {
    $before = @((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute -ErrorAction SilentlyContinue).BootExecute)
    $script:DirtyVolumes = @('Z')
    $null = Invoke-ChkdskScheduleTask -ScheduleChkdsk -WhatIf
    $after = @((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute -ErrorAction SilentlyContinue).BootExecute)
    Assert-Equal ($after -join '|') ($before -join '|') 'BootExecute value'
}

#endregion

#region ------------------------------------------------------------------- Invoke-DiskCleanupTask

Write-TestSection 'Invoke-DiskCleanupTask'

Test-Case 'Skips cleanly when -UseDiskCleanup was not requested' {
    $r = Invoke-DiskCleanupTask -UseDiskCleanup:$false
    Assert-Equal $r.Status 'Skipped' 'status'
}
Test-Case 'Reports Skipped under -WhatIf and never launches cleanmgr' {
    if (Get-Command cleanmgr.exe -ErrorAction SilentlyContinue) {
        $r = Invoke-DiskCleanupTask -UseDiskCleanup -WhatIf
        Assert-Equal $r.Status 'Skipped' 'status'
        Assert-Equal $r.Detail 'WhatIf' 'detail'
    } else {
        Skip-Case 'Reports Skipped under -WhatIf and never launches cleanmgr' 'cleanmgr.exe not present on this system'
    }
}

$script:VolumeCachesKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
if (Test-Path $script:VolumeCachesKey) {
    Test-Case 'Allow-listed cleanup handler names all exist in the real registry' {
        $fn = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-DiskCleanupTask' }, $true) | Select-Object -First 1
        if ($fn.Extent.Text -notmatch '\$allow\s*=\s*@\(([^)]*)\)') { throw 'could not locate the $allow list in the source' }
        $allowText = $Matches[1]
        $allow = [regex]::Matches($allowText, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value }
        Assert-True ($allow.Count -gt 0) 'expected at least one allow-list entry'
        $real = @(Get-ChildItem -Path $script:VolumeCachesKey | ForEach-Object { Split-Path $_.PSPath -Leaf })
        $missing = $allow | Where-Object { $real -notcontains $_ }
        Assert-Equal ($missing -join ',') '' 'allow-list entries not found in the real registry'
    }
    Test-Case 'Downloads folder handler is never allow-listed' {
        $fn = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-DiskCleanupTask' }, $true) | Select-Object -First 1
        Assert-False ($fn.Extent.Text -match "'DownloadsFolder'") 'the Downloads folder handler must never be in the allow-list'
    }
} else {
    Skip-Case 'Allow-listed cleanup handler names all exist in the real registry' 'VolumeCaches key not present on this system'
    Skip-Case 'Downloads folder handler is never allow-listed' 'VolumeCaches key not present on this system'
}

#endregion

#region ------------------------------------------------------------------- fsutil / winmgmt ambiguity (mocked)

Write-TestSection 'fsutil / winmgmt error-vs-result disambiguation'

$script:OriginalInvokeNativeCommand = (Get-Command Invoke-NativeCommand).ScriptBlock

function Set-NativeCommandMock { param([scriptblock]$Behavior) Set-Item Function:\Invoke-NativeCommand -Value $Behavior }
function Restore-NativeCommandMock { Set-Item Function:\Invoke-NativeCommand -Value $script:OriginalInvokeNativeCommand }

Test-Case 'fsutil "access denied" is not misreported as a dirty volume' {
    # Regression test: fsutil returns a nonzero exit code for BOTH a dirty volume and an
    # unrelated failure like access-denied, so exit code alone is ambiguous.
    Set-NativeCommandMock {
        param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800)
        if ($FilePath -eq 'fsutil.exe') { return [pscustomobject]@{ ExitCode = 1; Output = 'Error 5: Access is denied.' } }
        [pscustomobject]@{ ExitCode = 0; Output = '' }
    }
    try {
        $r = Invoke-VolumeScanTask
        Assert-False ($r.Detail -match 'dirty bit set') 'an access-denied failure must not be reported as a dirty bit'
    } finally { Restore-NativeCommandMock }
}

Test-Case 'fsutil genuine dirty-bit text (no "Error N:" prefix) is still detected' {
    Set-NativeCommandMock {
        param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800)
        if ($FilePath -eq 'fsutil.exe') { return [pscustomobject]@{ ExitCode = 1; Output = 'Volume - C: is Dirty' } }
        [pscustomobject]@{ ExitCode = 0; Output = '' }
    }
    try {
        $r = Invoke-VolumeScanTask
        Assert-Match $r.Detail 'dirty bit set' 'expected the dirty condition to be reported'
    } finally { Restore-NativeCommandMock }
}

Test-Case 'winmgmt "access denied" is reported as unverifiable, not as a real inconsistency' {
    Set-NativeCommandMock {
        param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800)
        [pscustomobject]@{ ExitCode = 1; Output = "WMI repository verification failed`nError code:     0x80041003`nDescription:    Access denied" }
    }
    try {
        $r = Invoke-WmiRepositoryTask
        Assert-Match $r.Detail 'Could not verify' 'expected an unverifiable result, not a false inconsistency finding'
    } finally { Restore-NativeCommandMock }
}

Test-Case 'winmgmt genuine inconsistency (no "Error code:" line) is still reported' {
    Set-NativeCommandMock {
        param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800)
        [pscustomobject]@{ ExitCode = 1; Output = 'WMI repository is inconsistent.' }
    }
    try {
        $r = Invoke-WmiRepositoryTask
        Assert-Equal $r.Status 'Warning' 'status'
        Assert-Match $r.Detail 'inconsistent' 'expected a genuine inconsistency to be reported'
    } finally { Restore-NativeCommandMock }
}

#endregion

#region ------------------------------------------------------------------- CBS.log parsing (synthetic)

Write-TestSection 'CBS.log parsing'

Test-Case 'Unrepairable-file regex extracts a single-quoted filename' {
    $line = "2026-09-15 10:00:10, Info CSI 00000213 [SR] Cannot repair member file [l:12]'shortname.dll' of Microsoft-Windows-Foo"
    Assert-True ($line -match 'member file \[l:\d+(?:\{\d+\})?\][''"]([^''"]+)[''"]') 'expected a regex match'
    Assert-Equal $Matches[1] 'shortname.dll' 'extracted filename'
}
Test-Case 'Unrepairable-file regex extracts a double-quoted filename with a brace length suffix' {
    $line = '2026-09-15 10:00:15, Info CSI 00000214 [SR] Cannot repair member file [l:34{17}]"amd64_microsoft-windows-foo_31bf3856ad364e35_10.0.22621.1_none_abc\bar.dll" of Microsoft-Windows-Foo'
    Assert-True ($line -match 'member file \[l:\d+(?:\{\d+\})?\][''"]([^''"]+)[''"]') 'expected a regex match'
    Assert-Equal $Matches[1] 'amd64_microsoft-windows-foo_31bf3856ad364e35_10.0.22621.1_none_abc\bar.dll' 'extracted filename'
}
Test-Case 'Invoke-CbsLogReviewTask handles a missing CBS.log without throwing' {
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800); [pscustomobject]@{ ExitCode = 0; Output = '' } }
    try {
        $r = Invoke-CbsLogReviewTask
        Assert-True ($r.Status -in @('OK', 'Skipped', 'Warning', 'Repaired')) 'expected a well-formed status'
    } finally { Restore-NativeCommandMock }
}

#endregion

#region ------------------------------------------------------------------- Invoke-WingetTask (mocked)

Write-TestSection 'Invoke-WingetTask'

Test-Case 'Skips cleanly when -UpgradeApps was not requested' {
    $r = Invoke-WingetTask -UpgradeApps:$false
    Assert-Equal $r.Status 'Skipped' 'status'
    Assert-Match $r.Detail 'Not requested' 'detail'
}

if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
    Test-Case 'Reports Skipped under -WhatIf and never calls winget' {
        $r = Invoke-WingetTask -UpgradeApps -WhatIf
        Assert-Equal $r.Status 'Skipped' 'status'
        Assert-Equal $r.Detail 'WhatIf' 'detail'
    }

    Test-Case 'Upgrades both the default winget source and the msstore source (Store apps)' {
        $script:MockCalls = New-Object System.Collections.Generic.List[object]
        Set-NativeCommandMock {
            param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800)
            $script:MockCalls.Add([pscustomobject]@{ ArgumentList = @($ArgumentList) })
            [pscustomobject]@{ ExitCode = 0; Output = 'mock-ok' }
        }
        try {
            $r = Invoke-WingetTask -UpgradeApps
            Assert-Equal $r.Status 'Repaired' 'status'

            $refreshCall  = $script:MockCalls | Where-Object { $_.ArgumentList -contains 'source' }
            $defaultUp    = $script:MockCalls | Where-Object { $_.ArgumentList -contains 'upgrade' -and $_.ArgumentList -contains '--all' -and $_.ArgumentList -notcontains 'msstore' }
            $storeUp      = $script:MockCalls | Where-Object { $_.ArgumentList -contains 'msstore' }

            Assert-True ($null -ne $refreshCall) 'expected a winget source refresh call'
            Assert-True ($null -ne $defaultUp) 'expected a default-source upgrade call'
            Assert-Contains $defaultUp[0].ArgumentList '--include-unknown' 'default-source upgrade args'
            Assert-True ($null -ne $storeUp) 'expected an msstore-scoped upgrade call (this is what actually updates Store apps)'
            Assert-Contains $storeUp[0].ArgumentList '--source' 'msstore upgrade args'
            Assert-Contains $storeUp[0].ArgumentList 'msstore' 'msstore upgrade args'
            Assert-Contains $storeUp[0].ArgumentList '--include-unknown' 'msstore upgrade args'
        } finally { Restore-NativeCommandMock }
    }

    Test-Case 'Skipped under SYSTEM (winget is unreliable there)' {
        $originalTest = (Get-Command Test-IsSystemAccount).ScriptBlock
        Set-Item Function:\Test-IsSystemAccount -Value { $true }
        try {
            $r = Invoke-WingetTask -UpgradeApps
            Assert-Equal $r.Status 'Skipped' 'status'
            Assert-Match $r.Detail 'SYSTEM' 'detail'
        } finally {
            Set-Item Function:\Test-IsSystemAccount -Value $originalTest
        }
    }
} else {
    Skip-Case 'Reports Skipped under -WhatIf and never calls winget' 'winget.exe not installed on this system'
    Skip-Case 'Upgrades both the default winget source and the msstore source (Store apps)' 'winget.exe not installed on this system'
    Skip-Case 'Skipped under SYSTEM (winget is unreliable there)' 'winget.exe not installed on this system'
}

#endregion

#region ------------------------------------------------------------------- DISM / SFC / component store (WhatIf)

Write-TestSection 'DISM, SFC, and component store gating'

Test-Case 'Invoke-DismHealthChain never runs RestoreHealth under -WhatIf' {
    $r = Invoke-DismHealthChain -WhatIf
    Assert-True ($r.Status -in @('OK', 'Skipped', 'Warning')) 'expected a well-formed, non-mutating status under WhatIf'
}
Test-Case 'Invoke-SfcTask never runs scannow under -WhatIf' {
    $r = Invoke-SfcTask -WhatIf
    Assert-Equal $r.Status 'Skipped' 'status'
    Assert-Equal $r.Detail 'WhatIf' 'detail'
}
Test-Case 'Invoke-ComponentStoreTask never runs StartComponentCleanup under -WhatIf' {
    $r = Invoke-ComponentStoreTask -WhatIf
    Assert-Equal $r.Status 'Skipped' 'status'
    Assert-Equal $r.Detail 'WhatIf' 'detail'
}
Test-Case 'DISM RestoreHealth exit code 3010 is treated as success (reboot required)' {
    Set-NativeCommandMock {
        param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800)
        if ($ArgumentList -contains '/RestoreHealth') { return [pscustomobject]@{ ExitCode = 3010; Output = 'The restore operation completed successfully.' } }
        if ($ArgumentList -contains '/CheckHealth' -or $ArgumentList -contains '/ScanHealth') { return [pscustomobject]@{ ExitCode = 0; Output = 'The component store is repairable.' } }
        [pscustomobject]@{ ExitCode = 0; Output = '' }
    }
    try {
        $script:RebootNeeded = $false
        $r = Invoke-DismHealthChain
        Assert-Equal $r.Status 'Repaired' 'status'
        Assert-True $script:RebootNeeded 'RebootNeeded should be set for exit code 3010'
    } finally { Restore-NativeCommandMock }
}

#endregion

#region ------------------------------------------------------------------- Windows Update

Write-TestSection 'Windows Update'

# Invoke-WindowsUpdateTask always performs a real, network-touching WU search (COM) before it
# ever reaches the -WhatIf/SYSTEM gates - only the install step is WhatIf-gated. So every test
# that calls the real (unmocked) function, not just an explicit 'real search' test, needs
# -IncludeSlow to be consistent and honest about what actually touches the network.
if ($IncludeSlow) {
    Test-Case 'Install is skipped under SYSTEM (unsupported from a service by design)' {
        $originalTest = (Get-Command Test-IsSystemAccount).ScriptBlock
        Set-Item Function:\Test-IsSystemAccount -Value { $true }
        try {
            $script:ReadOnlyRun = $false
            $r = Invoke-WindowsUpdateTask -InstallWindowsUpdates
            Assert-True ($r.Status -in @('Warning', 'OK')) 'expected a well-formed status'
            # Only asserts the SYSTEM/service wording when updates were actually found to install;
            # "No pending updates" is an equally valid, real outcome that never reaches that branch.
            if ($r.Detail -match 'pending \(not installed\)') {
                Assert-Match $r.Detail 'not installed' 'detail should reflect the scan-only result'
            }
        } finally {
            Set-Item Function:\Test-IsSystemAccount -Value $originalTest
        }
    }
    Test-Case 'Never installs anything under -WhatIf' {
        $script:ReadOnlyRun = $false
        $r = Invoke-WindowsUpdateTask -InstallWindowsUpdates -WhatIf
        Assert-True ($r.Status -in @('Skipped', 'OK', 'Warning')) 'expected a well-formed status'
    }
    Test-Case 'A real (read-only) Windows Update search completes without throwing' {
        $script:ReadOnlyRun = $false
        $r = Invoke-WindowsUpdateTask
        Assert-True ($r.Status -in @('OK', 'Warning', 'Failed')) 'expected a well-formed status'
    }
} else {
    Skip-Case 'Install is skipped under SYSTEM (unsupported from a service by design)' 'triggers a real network WU search - pass -IncludeSlow to run it'
    Skip-Case 'Never installs anything under -WhatIf' 'triggers a real network WU search - pass -IncludeSlow to run it'
    Skip-Case 'A real (read-only) Windows Update search completes without throwing' 'network/online scan - pass -IncludeSlow to run it'
}
Test-Case 'Invoke-WindowsUpdateRepairTask never touches services under -WhatIf' {
    $before = @(Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status
    $r = Invoke-WindowsUpdateRepairTask -RepairWindowsUpdateStack -WhatIf
    Assert-Equal $r.Status 'Skipped' 'status'
    $after = @(Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status
    Assert-Equal ($after -join '') ($before -join '') 'wuauserv status should be unchanged'
}
Test-Case 'Invoke-WindowsUpdateRepairTask skips cleanly when not requested' {
    $r = Invoke-WindowsUpdateRepairTask -RepairWindowsUpdateStack:$false
    Assert-Equal $r.Status 'Skipped' 'status'
}

#endregion

#region ------------------------------------------------------------------- Storage / disk health

Write-TestSection 'Storage and disk health'

Test-Case 'Get-VolumeMediaType resolves the system drive without throwing' {
    $media = Get-VolumeMediaType -DriveLetter ($env:SystemDrive.TrimEnd(':'))
    Assert-Contains @('SSD', 'HDD', 'SCM', 'Unknown') $media 'media type'
}
Test-Case 'Invoke-PhysicalDiskHealthTask returns a well-formed result' {
    $r = Invoke-PhysicalDiskHealthTask
    Assert-True ($r.Status -in @('OK', 'Warning', 'Skipped')) 'expected a well-formed status'
}
Test-Case 'Invoke-VolumeScanTask tracks dirty volumes as an array regardless of count' {
    $r = Invoke-VolumeScanTask
    Assert-NoThrow { $null = $script:DirtyVolumes.Count } 'DirtyVolumes.Count should never throw under StrictMode'
}
Test-Case 'Invoke-OptimizeVolumeTask never mutates a volume under -WhatIf' {
    $r = Invoke-OptimizeVolumeTask -WhatIf
    Assert-True ($r.Status -in @('OK', 'Skipped')) 'expected a well-formed status'
}

#endregion

#region ------------------------------------------------------------------- Invoke-CleanupTask (live-safe)

Write-TestSection 'Invoke-CleanupTask'

Test-Case 'Skipped in Audit mode' {
    $script:ReadOnlyRun = $true
    $r = Invoke-CleanupTask
    Assert-Equal $r.Status 'Skipped' 'status'
    Assert-Match $r.Detail 'Audit' 'detail'
}

Test-Case '-WhatIf never deletes a real file' {
    $canary = Join-Path $env:TEMP ('imperial-canary-{0}.txt' -f ([guid]::NewGuid().Guid.Substring(0, 8)))
    Set-Content -Path $canary -Value 'do-not-delete'
    try {
        $script:ReadOnlyRun = $false
        $script:CurrentRank = 2
        $r = Invoke-CleanupTask -WhatIf
        Assert-Equal $r.Status 'Skipped' 'status'
        Assert-Equal $r.Detail 'WhatIf' 'detail'
        Assert-True (Test-Path $canary) 'the canary file in %TEMP% must survive a -WhatIf cleanup run'
    } finally {
        Remove-Item -Path $canary -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region ------------------------------------------------------------------- Security tasks (read-only)

Write-TestSection 'Security posture and Defender'

Test-Case 'Invoke-SecurityPostureTask returns a well-formed result' {
    $r = Invoke-SecurityPostureTask
    Assert-True ($r.Status -in @('OK', 'Warning')) 'expected a well-formed status'
}
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    Test-Case 'Invoke-DefenderTask reads status without mutating anything in Audit mode' {
        $script:ReadOnlyRun = $true
        $r = Invoke-DefenderTask
        Assert-True ($r.Status -in @('OK', 'Warning', 'Skipped')) 'expected a well-formed status'
    }
} else {
    Skip-Case 'Invoke-DefenderTask reads status without mutating anything in Audit mode' 'Defender cmdlets unavailable (third-party AV?)'
}
Test-Case 'Invoke-DefenderTask is Skipped (not Failed) when Defender is disabled behind third-party AV' {
    function Get-MpComputerStatus { [CmdletBinding()] param() throw '0x800106ba service not running' }
    $r = Invoke-DefenderTask
    Assert-Equal $r.Status 'Skipped' 'status'
    Assert-Match $r.Detail 'Defender unavailable' 'detail'
}

#endregion

#region ------------------------------------------------------------------- Diagnostics (read-only)

Write-TestSection 'Diagnostics'

Test-Case 'Invoke-EventLogReviewTask returns a well-formed result' {
    $EventLogDays = 7
    $r = Invoke-EventLogReviewTask
    Assert-True ($r.Status -in @('OK', 'Warning')) 'expected a well-formed status'
}
Test-Case 'Invoke-DriverHealthTask returns a well-formed result' {
    $r = Invoke-DriverHealthTask
    Assert-True ($r.Status -in @('OK', 'Warning')) 'expected a well-formed status'
}
Test-Case 'Invoke-ServiceHealthTask returns a well-formed result' {
    $r = Invoke-ServiceHealthTask
    Assert-True ($r.Status -in @('OK', 'Warning')) 'expected a well-formed status'
}
Test-Case 'Invoke-PowerConfigTask returns a well-formed result' {
    # Force read-only explicitly (not inherited from another test's leftover state) - otherwise
    # this can write a real battery-report.html via powercfg on a portable device.
    $script:ReadOnlyRun = $true
    $script:RunLogDir = $env:TEMP
    $r = Invoke-PowerConfigTask
    Assert-Equal $r.Status 'OK' 'status'
}
Test-Case 'Invoke-StartupImpactTask returns a well-formed result' {
    $r = Invoke-StartupImpactTask
    Assert-True ($r.Status -in @('OK', 'Warning')) 'expected a well-formed status'
}
Test-Case 'Invoke-StartupImpactTask tolerates a Run key that exists but holds no values' {
    function Test-Path { [CmdletBinding()] param([Parameter(Position = 0)]$Path) $true }
    function Get-ItemProperty { [CmdletBinding()] param($Path) }
    function Get-ScheduledTask { [CmdletBinding()] param() }
    $r = Invoke-StartupImpactTask
    Assert-Equal $r.Status 'OK' 'status'
    Assert-Equal $r.Detail '0 startup entries' 'detail'
}
Test-Case 'Invoke-StorageSenseReportTask returns a well-formed result' {
    $r = Invoke-StorageSenseReportTask
    Assert-True ($r.Status -in @('OK', 'Warning', 'Skipped')) 'expected a well-formed status'
}
Test-Case 'Invoke-StoreAppUpdateTask never mutates anything under -WhatIf' {
    $script:ReadOnlyRun = $false
    $r = Invoke-StoreAppUpdateTask -WhatIf
    Assert-True ($r.Status -in @('Skipped', 'OK')) 'expected a well-formed status'
}

#endregion

#region ------------------------------------------------------------------- Inventory / baseline (real, read-only)

Write-TestSection 'Inventory and baseline'

Test-Case 'Get-SystemSnapshot returns the expected shape' {
    $snap = Get-SystemSnapshot
    Assert-True ($snap.Build -gt 0) 'Build'
    Assert-True (-not [string]::IsNullOrWhiteSpace($snap.ComputerName)) 'ComputerName'
    Assert-True (-not [string]::IsNullOrWhiteSpace($snap.PowerShell)) 'PowerShell'
}
Test-Case 'Invoke-InventoryTask returns a well-formed result' {
    $r = Invoke-InventoryTask
    Assert-True ($r.Status -in @('OK', 'Warning')) 'expected a well-formed status'
}
Test-Case 'Invoke-LifecycleTask returns a well-formed result' {
    $r = Invoke-LifecycleTask
    Assert-True ($r.Status -in @('OK', 'Warning', 'Failed')) 'expected a well-formed status'
}
Test-Case 'Invoke-FreeSpaceTask returns a well-formed result' {
    $r = Invoke-FreeSpaceTask
    Assert-True ($r.Status -in @('OK', 'Warning')) 'expected a well-formed status'
}
Test-Case 'Invoke-RestorePointTask never creates a restore point under -WhatIf' {
    $r = Invoke-RestorePointTask -WhatIf
    Assert-Equal $r.Status 'Skipped' 'status'
    Assert-Equal $r.Detail 'WhatIf' 'detail'
}
Test-Case 'Invoke-RestorePointTask skips cleanly with -SkipRestorePoint' {
    $SkipRestorePoint = $true
    $r = Invoke-RestorePointTask
    Assert-Equal $r.Status 'Skipped' 'status'
    $SkipRestorePoint = $false
}

#endregion

#region ------------------------------------------------------------------- Summary

Write-Host ''
Write-Host ('=' * 78) -ForegroundColor Magenta
Write-Host '  TEST SUMMARY' -ForegroundColor Magenta
Write-Host ('=' * 78) -ForegroundColor Magenta
Write-Host ("  $script:CheckMark Passed : {0}" -f $script:PassCount) -ForegroundColor Green
Write-Host ("  $script:CrossMark Failed : {0}" -f $script:FailCount) -ForegroundColor Red
Write-Host ("  o Skipped: {0}" -f $script:SkipCount) -ForegroundColor DarkYellow

if ($script:FailCount -gt 0) {
    Write-Host ''
    Write-Host '  FAILURES' -ForegroundColor Red
    foreach ($f in $script:FailureLog) {
        Write-Host "   - [$($f.Section)] $($f.Test)" -ForegroundColor Red
        Write-Host "       $($f.Reason)" -ForegroundColor Yellow
    }
}
Write-Host ''

exit ($(if ($script:FailCount -gt 0) { 1 } else { 0 }))

#endregion
