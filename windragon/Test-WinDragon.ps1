<#
.SYNOPSIS
    Non-destructive automated test suite for WinDragon (winDragon.ps1 + Modules).

.DESCRIPTION
    Proves that WinDragon is a one-to-one functional replica of the Imperial Maintenance
    Protocol (vader\Invoke-ImperialMaintenance.ps1) behind a menu-driven interface, and that
    everything still works - without actually running any maintenance item.

      * Parity     - every vader function, parameter, constant, top-level statement and task
                     catalogue entry is present in WinDragon with a token-identical
                     implementation (comments/whitespace ignored, WinDragon branding
                     normalised). Catalogue, level selection and -ListTasks output are
                     compared between two child processes.
      * Behaviour  - every task's decision logic is exercised with mocked system calls
                     (DISM, SFC, fsutil, winget, Windows Update COM, services, registry,
                     Defender, CIM ...), disposable sandboxes and -WhatIf.
      * Interface  - main menu, category/task pickers, options menu, headless -RunChoice
                     dispatch and the interactive loop are driven with scripted Read-Host input.
      * Build      - build.py is run against a temporary copy and the bundled script is
                     verified to parse, contain the same code and list the same tasks.

    Nothing here performs a real repair, scan, cleanup, update, service change, registry write,
    restore point, CHKDSK schedule or scheduled task registration. Read-only probes of the real
    machine are opt-in via -IncludeLive.

    Each check prints a green checkmark (pass) or a red X (fail, with the reason).

.PARAMETER WinDragonRoot
    Folder containing winDragon.ps1 and Modules\. Defaults to this script's folder.

.PARAMETER VaderScript
    Path to vader\Invoke-ImperialMaintenance.ps1 used as the parity reference.

.PARAMETER Only
    One or more wildcard patterns matching section names to run.

.PARAMETER IncludeLive
    Also run the read-only tasks against the real machine (inventory, disks, event logs,
    security posture, services...). Still never modifies anything.

.PARAMETER SkipBuild
    Skip the build.py bundling checks.

.EXAMPLE
    .\Test-WinDragon.ps1

.EXAMPLE
    .\Test-WinDragon.ps1 -Only 'Parity*','Interface*'
#>

[CmdletBinding()]
param(
    [string]$WinDragonRoot = $PSScriptRoot,
    [string]$VaderScript = (Join-Path (Split-Path $PSScriptRoot -Parent) 'vader\Invoke-ImperialMaintenance.ps1'),
    [string[]]$Only,
    [switch]$IncludeLive,
    [switch]$SkipBuild
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
        # Host output from the code under test is noise here; -Verbose shows it.
        if ($VerbosePreference -eq 'Continue') { & $Test } else { & $Test 6>$null }
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

function Write-TestInfo {
    param([string]$Text)
    if (-not (Test-SectionSelected -Name $script:CurrentSection)) { return }
    Write-Host "      $Text" -ForegroundColor DarkGray
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
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Collection, [Parameter(Mandatory)]$Item, [string]$Label = 'collection')
    if (@($Collection) -notcontains $Item) { throw "Expected $Label to contain '$Item' (got: $(@($Collection) -join ', '))" }
}
function Assert-NotContains {
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Collection, [Parameter(Mandatory)]$Item, [string]$Label = 'collection')
    if (@($Collection) -contains $Item) { throw "Expected $Label to NOT contain '$Item'" }
}
function Assert-NoThrow {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock, [string]$Message = 'Expected no exception')
    try { & $ScriptBlock } catch { throw "$Message - $($_.Exception.Message)" }
}
function Assert-Throws {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock, [string]$Pattern = '.', [string]$Message = 'Expected an exception')
    $threw = $false
    try { & $ScriptBlock } catch { $threw = $true; if ($_.Exception.Message -notmatch $Pattern) { throw "$Message - wrong message: $($_.Exception.Message)" } }
    if (-not $threw) { throw $Message }
}
function Assert-Match {
    param([string]$Value, [string]$Pattern, [string]$Label = 'value')
    if ($Value -notmatch $Pattern) { throw "Expected $Label ('$Value') to match pattern '$Pattern'" }
}

function New-CallLog { $script:Calls = New-Object System.Collections.Generic.List[object] }
function Add-Call { param([string]$Name, $Data) $script:Calls.Add([pscustomobject]@{ Name = $Name; Data = $Data }) }
function Get-Call { param([string]$Name) @($script:Calls | Where-Object { $_.Name -eq $Name }) }
function Get-CallCount { param([string]$Name) @($script:Calls | Where-Object { $_.Name -eq $Name }).Count }

function New-TempDir {
    $d = Join-Path $env:TEMP ('windragon-test-{0}' -f ([guid]::NewGuid().Guid.Substring(0, 8)))
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    return $d
}

#endregion

#region ------------------------------------------------------------------- Static analysis helpers

$script:MainScript  = Join-Path $WinDragonRoot 'winDragon.ps1'
$script:ModulesDir  = Join-Path $WinDragonRoot 'Modules'
$script:ModuleFiles = @(Get-ChildItem -Path $script:ModulesDir -Filter '*.ps1' | Sort-Object Name | ForEach-Object { $_.FullName })
$script:AllFiles    = @($script:MainScript) + $script:ModuleFiles
$script:HostExe     = (Get-Process -Id $PID).Path
$script:HaveVader   = Test-Path -LiteralPath $VaderScript
$script:InterfaceOnlyFunctions = @('Write-Banner', 'Write-Section')

function Get-FileAst {
    param([Parameter(Mandatory)][string]$Path)
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
    [pscustomobject]@{ Path = $Path; Ast = $ast; Tokens = $tokens; Errors = $errs }
}

function Get-NormalizedCode {
    # Token stream without comments/newlines; WinDragon branding mapped back to Imperial.
    # CRLF/LF is normalised because here-string tokens embed the file's line endings.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [switch]$Rebrand)
    $Text = $Text -replace "`r`n", "`n"
    if ($Rebrand) { $Text = ($Text -creplace 'WinDragon', 'Imperial') -creplace 'WINDRAGON', 'IMPERIAL' }
    $tokens = $null; $errs = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errs)
    $skip = @('Comment', 'NewLine', 'LineContinuation', 'EndOfInput')
    return (@($tokens | Where-Object { $skip -notcontains $_.Kind.ToString() } | ForEach-Object { $_.Text }) -join ' ')
}

function Get-FunctionDefinition {
    param([Parameter(Mandatory)][string[]]$Files)
    foreach ($f in $Files) {
        $parsed = Get-FileAst -Path $f
        $parsed.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; File = $f; Ast = $_ } }
    }
}

function Get-FlatStatement {
    param([Parameter(Mandatory)]$Statement)
    if ($Statement -is [System.Management.Automation.Language.TryStatementAst]) {
        foreach ($s in $Statement.Body.Statements) { Get-FlatStatement $s }
        foreach ($c in $Statement.CatchClauses) { foreach ($s in $c.Body.Statements) { Get-FlatStatement $s } }
        if ($Statement.Finally) { foreach ($s in $Statement.Finally.Statements) { Get-FlatStatement $s } }
    }
    elseif ($Statement -is [System.Management.Automation.Language.ForEachStatementAst]) {
        foreach ($s in $Statement.Body.Statements) { Get-FlatStatement $s }
    }
    else { $Statement }
}

# Child-process dumper: loads a script via its -ListTasks early return and emits catalogue,
# constants and per-level task selection as JSON. Runs vader and WinDragon in isolation.
$script:DumperPath = Join-Path $env:TEMP ('windragon-dumper-{0}.ps1' -f ([guid]::NewGuid().Guid.Substring(0, 8)))
Set-Content -LiteralPath $script:DumperPath -Encoding UTF8 -Value @'
param([string]$Target)
. $Target -ListTasks | Out-Null
$levels = foreach ($lvl in 'Audit', 'Quick', 'Standard', 'Full') {
    $script:CurrentRank = $script:LevelRank[$lvl]
    $script:ReadOnlyRun = ($lvl -eq 'Audit')
    $sel = @($script:TaskCatalogue | Where-Object { Test-TaskSelected -Task $_ -OnlyTask $null -SkipTask $null } | ForEach-Object { $_.Name })
    '{0}={1}' -f $lvl, ($sel -join ';')
}
[pscustomobject]@{
    Tasks     = @($script:TaskCatalogue | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.Name, $_.Category, $_.MinLevel, $_.ReadOnly, $_.Action.ToString().Trim() })
    LevelRank = @($script:LevelRank.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value })
    BuildMap  = @($script:BuildMap.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0}={1}|{2}|{3}' -f $_.Name, $_.Value.Name, $_.Value.Consumer, $_.Value.Commercial })
    Levels    = @($levels)
} | ConvertTo-Json -Depth 4 -Compress
'@

function Get-ScriptDump {
    param([Parameter(Mandatory)][string]$Path)
    $json = & $script:HostExe -NoProfile -ExecutionPolicy Bypass -File $script:DumperPath -Target $Path
    if ($LASTEXITCODE -ne 0) { throw "dumper failed for $Path (exit $LASTEXITCODE): $json" }
    return (($json | Out-String) | ConvertFrom-Json)
}

#endregion

Write-Host ''
Write-Host 'WINDRAGON - TEST SUITE' -ForegroundColor Magenta
Write-Host "  Target   : $script:MainScript" -ForegroundColor Gray
Write-Host "  Reference: $(if ($script:HaveVader) { $VaderScript } else { '(vader not found - parity checks skipped)' })" -ForegroundColor Gray
Write-Host "  PS       : $($PSVersionTable.PSVersion)  ($($PSVersionTable.PSEdition))" -ForegroundColor Gray
Write-Host "  Elevated : $((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -ForegroundColor Gray

try {

#region ------------------------------------------------------------------- Structural

Write-TestSection 'Structural'

Test-Case 'winDragon.ps1 and every module parse with no syntax errors' {
    $bad = @()
    foreach ($f in $script:AllFiles) {
        $p = Get-FileAst -Path $f
        if ($p.Errors.Count -gt 0) { $bad += "$(Split-Path $f -Leaf): $($p.Errors[0].Message)" }
    }
    Assert-Equal ($bad -join '; ') '' 'parse errors'
}

Test-Case 'All files also parse under Windows PowerShell 5.1' {
    $ps51 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path $ps51)) { throw 'powershell.exe not found' }
    $list = ($script:AllFiles | ForEach-Object { "'$_'" }) -join ','
    $cmd = "`$bad = foreach (`$f in @($list)) { `$e = `$null; [void][System.Management.Automation.Language.Parser]::ParseFile(`$f, [ref]`$null, [ref]`$e); if (`$e) { `$f + ': ' + `$e[0].Message } }; `$bad -join '; '"
    $out = & $ps51 -NoProfile -Command $cmd
    Assert-Equal (($out | Out-String).Trim()) '' 'Windows PowerShell 5.1 parse errors'
}

Test-Case 'Every script file is pure ASCII (safe for Windows PowerShell 5.1 without a BOM)' {
    $bad = @()
    foreach ($f in ($script:AllFiles + @((Join-Path $WinDragonRoot 'launcher.ps1')))) {
        $bytes = [System.IO.File]::ReadAllBytes($f)
        if (@($bytes | Where-Object { $_ -gt 127 }).Count -gt 0) { $bad += (Split-Path $f -Leaf) }
    }
    Assert-Equal ($bad -join ',') '' 'files with non-ASCII bytes'
}

Test-Case 'Set-StrictMode -Version Latest is set in winDragon.ps1' {
    Assert-Match (Get-Content -LiteralPath $script:MainScript -Raw) 'Set-StrictMode\s+-Version\s+Latest' 'winDragon.ps1'
}

Test-Case 'No two functions share the same name across winDragon.ps1 and Modules' {
    $names = @(Get-FunctionDefinition -Files $script:AllFiles | ForEach-Object { $_.Name })
    $dupes = $names | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }
    Assert-Equal ($dupes -join ',') '' 'duplicate function names'
}

Test-Case 'Every function calling ShouldProcess/ShouldContinue declares SupportsShouldProcess' {
    $offenders = @()
    foreach ($fd in Get-FunctionDefinition -Files $script:AllFiles) {
        $fn = $fd.Ast
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
                    foreach ($na in $attr.NamedArguments) { if ($na.ArgumentName -eq 'SupportsShouldProcess') { $hasAttr = $true } }
                }
            }
        }
        if (-not $hasAttr) { $offenders += $fn.Name }
    }
    Assert-Equal ($offenders -join ',') '' 'functions missing SupportsShouldProcess'
}

Test-Case 'Every task-catalogue -Action references a function that exists' {
    $fnNames = @(Get-FunctionDefinition -Files $script:AllFiles | ForEach-Object { $_.Name })
    $cat = Get-FileAst -Path (Join-Path $script:ModulesDir 'Catalogue.ps1')
    $calls = $cat.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-MaintenanceTask' }, $true)
    Assert-Equal @($calls).Count 29 'registered task count'
    $missing = @()
    foreach ($call in $calls) {
        foreach ($sb in ($call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.ScriptBlockExpressionAst] })) {
            foreach ($cmd in $sb.ScriptBlock.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $name = $cmd.GetCommandName()
                if ($name -and $fnNames -notcontains $name) { $missing += $name }
            }
        }
    }
    Assert-Equal ($missing -join ',') '' 'task actions referencing undefined functions'
}

Test-Case 'Register-MaintenanceTask lives in winDragon.ps1 so PSCommandPath is the entry script' {
    $fd = @(Get-FunctionDefinition -Files $script:AllFiles | Where-Object { $_.Name -eq 'Register-MaintenanceTask' })
    Assert-Equal $fd.Count 1 'Register-MaintenanceTask definitions'
    Assert-Equal $fd[0].File $script:MainScript 'defining file'
    Assert-Match $fd[0].Ast.Extent.Text 'PowerShell\\7\\pwsh\.exe' 'Register-MaintenanceTask body'
}

Test-Case '-RegisterScheduledTask and menu option 9 are gated behind ShouldProcess' {
    Assert-Match (Get-Content -LiteralPath $script:MainScript -Raw) "if\s*\(\`$RegisterScheduledTask\)\s*\{\s*if\s*\(\`$PSCmdlet\.ShouldProcess" 'winDragon.ps1'
    Assert-Match (Get-Content -LiteralPath (Join-Path $script:ModulesDir 'Interface.ps1') -Raw) "'9'\s*\{\s*if\s*\(\`$PSCmdlet\.ShouldProcess" 'Interface.ps1'
}

Test-Case 'winDragon.ps1 is safe for build.py comment stripping (no block comments, no hash in code)' {
    $p = Get-FileAst -Path $script:MainScript
    $block = @($p.Tokens | Where-Object { $_.Kind -eq 'Comment' -and $_.Text.StartsWith('<#') })
    Assert-Equal $block.Count 0 'block comments in winDragon.ps1'
    $hash = @($p.Tokens | Where-Object { $_.Kind -ne 'Comment' -and $_.Text.Contains('#') } | ForEach-Object { "line $($_.Extent.StartLineNumber)" })
    Assert-Equal ($hash -join ',') '' 'non-comment tokens containing a hash'
}

Test-Case 'Every module is dot-sourced exactly once with a build.py-compatible import line' {
    $lines = Get-Content -LiteralPath $script:MainScript
    $imports = @($lines | Where-Object { $_ -match '^\.\s+(.*\\Modules\\.*\.ps1)$' } | ForEach-Object { Split-Path ($Matches[1]) -Leaf })
    $modules = @($script:ModuleFiles | ForEach-Object { Split-Path $_ -Leaf })
    Assert-Equal (($imports | Sort-Object) -join ',') (($modules | Sort-Object) -join ',') 'imported modules vs Modules folder'
    Assert-Equal (@($imports | Group-Object | Where-Object { $_.Count -gt 1 }).Count) 0 'duplicate imports'
}

Test-Case 'Unattended dispatch keys off -RunChoice, -Level or -OnlyTask' {
    $text = Get-Content -LiteralPath $script:MainScript -Raw
    foreach ($k in 'RunChoice', 'Level', 'OnlyTask') { Assert-Match $text "PSBoundParameters\.ContainsKey\('$k'\)" 'dispatch block' }
}

Test-Case 'A non-interactive host runs unattended instead of opening the menu' {
    Assert-Match (Get-Content -LiteralPath $script:MainScript -Raw) '-not \$script:CanPrompt' 'dispatch block'
}

Test-Case 'Elevation relaunch uses an encoded command so arrays and trailing backslashes survive' {
    $text = Get-Content -LiteralPath $script:MainScript -Raw
    Assert-Match $text "'-EncodedCommand'" 'relaunch argument list'
    Assert-False ($text.Contains("'Bypass', '-File'")) 'relaunch still uses -File'
}

#endregion

#region ------------------------------------------------------------------- Feature parity with vader

Write-TestSection 'Parity with vader'

if ($script:HaveVader) {
    $script:VaderParsed = Get-FileAst -Path $VaderScript
    $script:VaderFns    = @(Get-FunctionDefinition -Files @($VaderScript))
    $script:WdFns       = @(Get-FunctionDefinition -Files $script:AllFiles)
    $script:WdCombined  = ' ' + ((@($script:AllFiles | ForEach-Object { Get-NormalizedCode -Text (Get-Content -LiteralPath $_ -Raw) -Rebrand })) -join ' ') + ' '

    Test-Case 'Every vader function exists in WinDragon' {
        $wdNames = @($script:WdFns | ForEach-Object { $_.Name })
        $missing = @($script:VaderFns | Where-Object { $wdNames -notcontains $_.Name } | ForEach-Object { $_.Name })
        Assert-Equal ($missing -join ',') '' 'vader functions missing from WinDragon'
        Write-TestInfo ("{0} vader functions, all present" -f $script:VaderFns.Count)
    }

    Test-Case 'Every vader function body is token-identical in WinDragon (except interface styling)' {
        $diff = @()
        foreach ($v in $script:VaderFns) {
            if ($script:InterfaceOnlyFunctions -contains $v.Name) { continue }
            $w = $script:WdFns | Where-Object { $_.Name -eq $v.Name } | Select-Object -First 1
            if (-not $w) { continue }
            $vn = Get-NormalizedCode -Text $v.Ast.Extent.Text
            $wn = Get-NormalizedCode -Text $w.Ast.Extent.Text -Rebrand
            if ($vn -cne $wn) { $diff += $v.Name }
        }
        Assert-Equal ($diff -join ',') '' 'functions whose implementation differs from vader'
        Write-TestInfo ("interface-styled only: {0}" -f ($script:InterfaceOnlyFunctions -join ', '))
    }

    Test-Case 'Interface-styled functions keep the same signature as vader' {
        foreach ($name in $script:InterfaceOnlyFunctions) {
            $v = $script:VaderFns | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            $w = $script:WdFns | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            $vp = Get-NormalizedCode -Text $v.Ast.Body.ParamBlock.Extent.Text
            $wp = Get-NormalizedCode -Text $w.Ast.Body.ParamBlock.Extent.Text
            Assert-Equal $wp $vp "$name param block"
        }
    }

    Test-Case 'WinDragon-only functions are confined to the interface module' {
        $vNames = @($script:VaderFns | ForEach-Object { $_.Name })
        $extra = @($script:WdFns | Where-Object { $vNames -notcontains $_.Name })
        $outside = @($extra | Where-Object { (Split-Path $_.File -Leaf) -ne 'Interface.ps1' } | ForEach-Object { $_.Name })
        Assert-Equal ($outside -join ',') '' 'engine functions that do not exist in vader'
        Write-TestInfo ("interface additions: {0}" -f (($extra | ForEach-Object { $_.Name }) -join ', '))
    }

    Test-Case 'Every vader parameter exists in WinDragon with identical type, validation and default' {
        $wdParams = @{}
        foreach ($p in (Get-FileAst -Path $script:MainScript).Ast.ParamBlock.Parameters) { $wdParams[$p.Name.VariablePath.UserPath] = $p }
        $diff = @()
        foreach ($p in $script:VaderParsed.Ast.ParamBlock.Parameters) {
            $n = $p.Name.VariablePath.UserPath
            if (-not $wdParams.ContainsKey($n)) { $diff += "$n (missing)"; continue }
            if ((Get-NormalizedCode -Text $p.Extent.Text) -cne (Get-NormalizedCode -Text $wdParams[$n].Extent.Text -Rebrand)) { $diff += $n }
        }
        Assert-Equal ($diff -join ',') '' 'parameters that differ'
        $vAttr = Get-NormalizedCode -Text (($script:VaderParsed.Ast.ParamBlock.Attributes | ForEach-Object { $_.Extent.Text }) -join ' ')
        $wAttr = Get-NormalizedCode -Text (((Get-FileAst -Path $script:MainScript).Ast.ParamBlock.Attributes | ForEach-Object { $_.Extent.Text }) -join ' ')
        Assert-Equal $wAttr $vAttr 'script-level CmdletBinding'
    }

    Test-Case 'Every vader top-level statement (constants, elevation, logging, reports) exists in WinDragon' {
        $missing = @()
        foreach ($s in $script:VaderParsed.Ast.EndBlock.Statements) {
            if ($s -is [System.Management.Automation.Language.FunctionDefinitionAst]) { continue }
            if ($s -is [System.Management.Automation.Language.IfStatementAst] -and $s.Clauses[0].Item1.Extent.Text -eq '$ListTasks') { continue }   # compared by output below
            if ($s -is [System.Management.Automation.Language.AssignmentStatementAst] -and $s.Left.Extent.Text -eq '$script:ScriptVersion') { continue }
            foreach ($flat in Get-FlatStatement $s) {
                $norm = Get-NormalizedCode -Text $flat.Extent.Text
                if (-not $script:WdCombined.Contains(" $norm ")) { $missing += "line $($flat.Extent.StartLineNumber): $($flat.Extent.Text.Split("`n")[0].Trim())" }
            }
        }
        Assert-Equal ($missing -join ' | ') '' 'vader statements not found in WinDragon'
    }

    $script:VaderDump = $null; $script:WdDump = $null
    Test-Case 'Task catalogues load in isolated child processes' {
        $script:VaderDump = Get-ScriptDump -Path $VaderScript
        $script:WdDump    = Get-ScriptDump -Path $script:MainScript
    }

    Test-Case 'Task catalogue is identical: 29 tasks, same order, category, level, audit-safety and action' {
        Assert-Equal @($script:WdDump.Tasks).Count 29 'WinDragon task count'
        Assert-Equal (@($script:WdDump.Tasks) -join "`n") (@($script:VaderDump.Tasks) -join "`n") 'task catalogue'
    }

    Test-Case 'Level ranks and the Windows 11 servicing lifecycle map are identical' {
        Assert-Equal (@($script:WdDump.LevelRank) -join ',') (@($script:VaderDump.LevelRank) -join ',') 'LevelRank'
        Assert-Equal (@($script:WdDump.BuildMap) -join ',') (@($script:VaderDump.BuildMap) -join ',') 'BuildMap'
    }

    Test-Case 'Each level (Audit/Quick/Standard/Full) selects exactly the same tasks' {
        Assert-Equal (@($script:WdDump.Levels) -join "`n") (@($script:VaderDump.Levels) -join "`n") 'per-level selection'
        $counts = @{}
        foreach ($l in $script:WdDump.Levels) { $k, $v = $l -split '=', 2; $counts[$k] = @($v -split ';').Count }
        Assert-Equal $counts['Audit'] 18 'Audit task count'
        Assert-Equal $counts['Quick'] 9 'Quick task count'
        Assert-Equal $counts['Standard'] 26 'Standard task count'
        Assert-Equal $counts['Full'] 29 'Full task count'
    }

    Test-Case '-ListTasks output is byte-identical to vader (PowerShell 7)' {
        $a = & $script:HostExe -NoProfile -File $VaderScript -ListTasks | Out-String
        $b = & $script:HostExe -NoProfile -File $script:MainScript -ListTasks | Out-String
        Assert-True ($a.Length -gt 100) 'vader produced no catalogue'
        Assert-True ($a -ceq $b) '-ListTasks output differs'
    }

    Test-Case '-ListTasks output is identical to vader under Windows PowerShell 5.1' {
        $ps51 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $a = & $ps51 -NoProfile -ExecutionPolicy Bypass -File $VaderScript -ListTasks | Out-String
        $b = & $ps51 -NoProfile -ExecutionPolicy Bypass -File $script:MainScript -ListTasks | Out-String
        Assert-True ($a.Length -gt 100) 'vader produced no catalogue under 5.1'
        Assert-True ($a -ceq $b) '-ListTasks output differs under 5.1'
    }

    # Printed feature map: vader capability -> how WinDragon exposes it.
    if (Test-SectionSelected -Name $script:CurrentSection) {
        Write-Host ''
        Write-Host '  Feature map (vader -> WinDragon)' -ForegroundColor Cyan
        if ($script:VaderDump) {
            foreach ($t in $script:VaderDump.Tasks) {
                $name, $cat, $min, $ro, $act = $t -split '\|'
                $levels = switch ($min) { '1' { 'menu 2,3,4' } '2' { 'menu 3,4' } default { 'menu 4' } }
                if ($ro -eq 'True' -and $min -ne '3') { $levels = "menu 1,$($levels.Substring(5))" }
                Write-Host ("    {0,-28} {1,-12} {2,-30} {3} + menu 5/6" -f $name, $cat, $act, $levels) -ForegroundColor DarkGray
            }
        }
    }
} else {
    Skip-Case 'vader parity checks' "reference script not found at $VaderScript"
}

#endregion

#region ------------------------------------------------------------------- Elevation guard (child process)

Write-TestSection 'ListTasks and elevation guard'

Test-Case '-ListTasks runs as a real invocation without elevation' {
    $out = & $script:HostExe -NoProfile -File $script:MainScript -ListTasks 2>&1
    Assert-Equal $LASTEXITCODE 0 'exit code'
    Assert-True (($out | Measure-Object).Count -gt 5) 'expected task-table output'
}

$script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $script:IsElevated) {
    foreach ($argSet in @(@('-Level', 'Audit'), @('-RunChoice', '3'), @())) {
        $label = if ($argSet.Count) { $argSet -join ' ' } else { '(interactive menu)' }
        Test-Case "-NoElevatePrompt fails fast instead of prompting for UAC: $label" {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $null = '' | & $script:HostExe -NoProfile -File $script:MainScript -NoElevatePrompt @argSet *>&1
            $exitCode = $LASTEXITCODE
            $sw.Stop()
            Assert-True ($exitCode -ne 0) 'expected a non-zero exit code'
            Assert-True ($sw.Elapsed.TotalSeconds -lt 20) "took $($sw.Elapsed.TotalSeconds)s - too slow for a fail-fast guard"
        }
    }
} else {
    Skip-Case '-NoElevatePrompt fails fast instead of prompting for UAC' 'this session is already elevated, so the guard never triggers'
}

#endregion

# Load every WinDragon function into this session. -ListTasks returns before elevation and the
# menu, so nothing runs and no UAC prompt appears.
. $script:MainScript -ListTasks | Out-Null
$ProgressPreference = 'SilentlyContinue'
$script:OriginalInvokeNativeCommand = (Get-Command Invoke-NativeCommand).ScriptBlock
function Set-NativeCommandMock { param([scriptblock]$Behavior) Set-Item Function:\Invoke-NativeCommand -Value $Behavior }
function Restore-NativeCommandMock { Set-Item Function:\Invoke-NativeCommand -Value $script:OriginalInvokeNativeCommand }
function Reset-RunState {
    param([string]$RunLevel = 'Standard')
    $script:Results      = New-Object System.Collections.Generic.List[psobject]
    $script:Findings     = New-Object System.Collections.Generic.List[string]
    $script:RebootNeeded = $false
    $script:DirtyVolumes = @()
    $script:CurrentRank  = $script:LevelRank[$RunLevel]
    $script:ReadOnlyRun  = ($RunLevel -eq 'Audit')
}

#region ------------------------------------------------------------------- Infrastructure

Write-TestSection 'Infrastructure'

Test-Case 'Format-NativeArgument: empty string becomes a quoted empty argument' { Assert-Equal (Format-NativeArgument '') '""' 'result' }
Test-Case 'Format-NativeArgument: plain text is left unquoted' { Assert-Equal (Format-NativeArgument 'plain') 'plain' 'result' }
Test-Case 'Format-NativeArgument: text with a space is quoted' { Assert-Equal (Format-NativeArgument 'has space') '"has space"' 'result' }
Test-Case 'Format-NativeArgument: embedded double quote is escaped' { Assert-Equal (Format-NativeArgument 'quote"inside') '"quote\"inside"' 'result' }
Test-Case 'Format-NativeArgument: trailing backslash before closing quote is doubled' { Assert-Equal (Format-NativeArgument 'C:\Program Files\') '"C:\Program Files\\"' 'result' }

Test-Case 'Invoke-NativeCommand captures exit code and output' {
    $r = Invoke-NativeCommand -FilePath 'cmd.exe' -ArgumentList @('/c', 'echo', 'hello world')
    Assert-Equal $r.ExitCode 0 'exit code'
    Assert-Match $r.Output 'hello world' 'output'
}
Test-Case 'Invoke-NativeCommand fails cleanly for a nonexistent executable' {
    $r = Invoke-NativeCommand -FilePath 'this-does-not-exist-xyz-windragon.exe'
    Assert-Equal $r.ExitCode -1 'exit code'
    Assert-False ($r.Output -match 'Exception calling') 'raw method-invocation text leaked'
}
Test-Case 'Invoke-NativeCommand kills a hung process at the timeout' {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-NativeCommand -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') -TimeoutSeconds 2
    $sw.Stop()
    Assert-Equal $r.ExitCode -1 'exit code'
    Assert-Match $r.Output 'TIMEOUT' 'output'
    Assert-True ($sw.Elapsed.TotalSeconds -lt 10) "took $($sw.Elapsed.TotalSeconds)s"
}
Test-Case 'Suspend-Sleep / Resume-Sleep do not throw and register WinDragon.Power' {
    Suspend-Sleep
    Resume-Sleep
    Assert-True ('WinDragon.Power' -as [type]) 'WinDragon.Power type missing'
}
Test-Case 'Get-VolumeMediaType returns a known media type for the system drive' {
    Assert-Contains @('SSD', 'HDD', 'SCM', 'Unknown', 'Unspecified') ([string](Get-VolumeMediaType -DriveLetter ($env:SystemDrive.TrimEnd(':')))) 'media type'
}

#endregion

#region ------------------------------------------------------------------- Task engine

Write-TestSection 'Task engine'

$script:FakeTask = [pscustomobject]@{ Name = 'DISM Health Chain'; MinLevel = 1; ReadOnly = $true }

Test-Case '-OnlyTask wildcard matches / excludes' {
    Assert-True (Test-TaskSelected -Task $script:FakeTask -OnlyTask @('DISM*') -SkipTask $null) 'expected match'
    Assert-False (Test-TaskSelected -Task $script:FakeTask -OnlyTask @('SFC*') -SkipTask $null) 'expected no match'
}
Test-Case '-SkipTask wildcard excludes the matching task' {
    Reset-RunState
    Assert-False (Test-TaskSelected -Task $script:FakeTask -OnlyTask $null -SkipTask @('DISM*')) 'expected excluded'
}
Test-Case '-OnlyTask overrides the level rank but never lets Audit run a mutating task' {
    $mutating = [pscustomobject]@{ Name = 'Component Store Cleanup'; MinLevel = 3; ReadOnly = $false }
    Reset-RunState -RunLevel 'Quick'
    Assert-True (Test-TaskSelected -Task $mutating -OnlyTask @('Component*') -SkipTask $null) 'OnlyTask should beat the level rank'
    Reset-RunState -RunLevel 'Audit'
    Assert-False (Test-TaskSelected -Task $mutating -OnlyTask @('Component*') -SkipTask $null) 'Audit ran a mutating task via -OnlyTask'
}
Test-Case 'Audit excludes mutating tasks; Quick excludes MinLevel 2+' {
    $mutating = [pscustomobject]@{ Name = 'x'; MinLevel = 1; ReadOnly = $false }
    Reset-RunState -RunLevel 'Audit'
    Assert-False (Test-TaskSelected -Task $mutating -OnlyTask $null -SkipTask $null) 'Audit ran a mutating task'
    Reset-RunState -RunLevel 'Quick'
    Assert-False (Test-TaskSelected -Task ([pscustomobject]@{ Name = 'y'; MinLevel = 2; ReadOnly = $true }) -OnlyTask $null -SkipTask $null) 'Quick ran a MinLevel 2 task'
}
Test-Case 'Invoke-MaintenanceTask records hashtable, string, exception, precondition and level outcomes' {
    Reset-RunState
    Invoke-MaintenanceTask -Task (New-MaintenanceTask -Name 'T1' -Category 'C' -MinLevel 1 -Action { @{ Status = 'Repaired'; Detail = 'fixed' } })
    Invoke-MaintenanceTask -Task (New-MaintenanceTask -Name 'T2' -Category 'C' -MinLevel 1 -Action { 'just text' })
    Invoke-MaintenanceTask -Task (New-MaintenanceTask -Name 'T3' -Category 'C' -MinLevel 1 -Action { throw 'kaboom' })
    Invoke-MaintenanceTask -Task (New-MaintenanceTask -Name 'T4' -Category 'C' -MinLevel 1 -Action { 'never' } -Precondition { $false })
    Invoke-MaintenanceTask -Task (New-MaintenanceTask -Name 'T5' -Category 'C' -MinLevel 3 -Action { 'never' })
    $r = @($script:Results)
    Assert-Equal $r.Count 5 'result count'
    Assert-Equal "$($r[0].Status)/$($r[0].Detail)" 'Repaired/fixed' 'T1'
    Assert-Equal "$($r[1].Status)/$($r[1].Detail)" 'OK/just text' 'T2'
    Assert-Equal "$($r[2].Status)/$($r[2].Detail)" 'Failed/kaboom' 'T3'
    Assert-Equal "$($r[3].Status)/$($r[3].Detail)" 'Skipped/Precondition not met' 'T4'
    Assert-Equal "$($r[4].Status)/$($r[4].Detail)" 'Skipped/Not selected for this level' 'T5'
}
Test-Case 'Add-Finding de-duplicates' {
    Reset-RunState
    Add-Finding 'same'; Add-Finding 'same'; Add-Finding 'other'
    Assert-Equal $script:Findings.Count 2 'finding count'
}

#endregion

#region ------------------------------------------------------------------- Baseline tasks (mocked)

Write-TestSection 'Baseline tasks'

function New-FakeSnapshot {
    param([int]$Build = 26200, [string]$Edition = 'Professional', [double]$Uptime = 10)
    [pscustomobject]@{
        ComputerName = 'TESTPC'; Caption = 'Microsoft Windows 11 Pro'; Edition = $Edition; DisplayVersion = '25H2'
        Build = $Build; UBR = 1; FullBuild = "$Build.1"; InstallDate = (Get-Date).AddYears(-1); LastBoot = (Get-Date).AddHours(-$Uptime)
        UptimeHours = $Uptime; Manufacturer = 'Contoso'; Model = 'Dragon <1>'; Cpu = 'CPU'; Cores = 8; Threads = 16
        MemoryGb = 32; FreeMemoryGb = 16; BiosVersion = '1.0'; BiosDate = (Get-Date).AddYears(-2); Serial = 'X'; PowerShell = '7.6'
    }
}

Test-Case 'Invoke-InventoryTask warns on uptime > 336h and passes otherwise' {
    function Get-SystemSnapshot { New-FakeSnapshot -Uptime $script:FakeUptime }
    Reset-RunState; $script:FakeUptime = 400
    Assert-Equal (Invoke-InventoryTask).Status 'Warning' 'long uptime'
    Assert-Equal $script:Findings.Count 1 'finding count'
    Reset-RunState; $script:FakeUptime = 10
    Assert-Equal (Invoke-InventoryTask).Status 'OK' 'short uptime'
}
Test-Case 'Invoke-LifecycleTask: pre-Win11, unmapped, EOL, near-EOL and supported builds' {
    $cases = @(
        @{ Build = 19045; Edition = 'Professional'; Expect = @('Warning') }
        @{ Build = 27999; Edition = 'Professional'; Expect = @('OK') }
        @{ Build = 22621; Edition = 'Professional'; Expect = @('Failed') }
        @{ Build = 26300; Edition = 'Professional'; Expect = @('OK') }
        @{ Build = 26100; Edition = 'Professional'; Expect = @('Warning', 'Failed') }
        @{ Build = 22631; Edition = 'Enterprise';   Expect = @('Warning', 'Failed') }
    )
    foreach ($c in $cases) {
        Reset-RunState
        $script:Snapshot = New-FakeSnapshot -Build $c.Build -Edition $c.Edition
        $r = Invoke-LifecycleTask
        Assert-Contains $c.Expect $r.Status "status for build $($c.Build) $($c.Edition)"
    }
}
Test-Case 'Invoke-FreeSpaceTask warns under 15 GB' {
    function Get-Volume { [CmdletBinding()] param([string]$DriveLetter) [pscustomobject]@{ SizeRemaining = $script:FakeFree; Size = 500GB } }
    Reset-RunState; $script:FakeFree = 10GB
    Assert-Equal (Invoke-FreeSpaceTask).Status 'Warning' 'low space'
    Reset-RunState; $script:FakeFree = 200GB
    Assert-Equal (Invoke-FreeSpaceTask).Status 'OK' 'ample space'
}
Test-Case 'Invoke-RestorePointTask: WhatIf and -SkipRestorePoint never touch the system' {
    function Invoke-CimMethod { [CmdletBinding()] param($Namespace, $ClassName, $MethodName, $Arguments, $InputObject) Add-Call 'cim' $MethodName }
    New-CallLog
    Assert-Equal (Invoke-RestorePointTask -WhatIf).Detail 'WhatIf' 'WhatIf'
    $SkipRestorePoint = $true
    Assert-Equal (Invoke-RestorePointTask).Detail 'Suppressed by -SkipRestorePoint' 'skip'
    Assert-Equal (Get-CallCount 'cim') 0 'CreateRestorePoint calls'
}
Test-Case 'Invoke-RestorePointTask relaxes then restores the 24h throttle around CreateRestorePoint' {
    function Test-Path { [CmdletBinding()] param([Parameter(Position = 0)]$Path, $LiteralPath) $true }
    function Get-ItemProperty { [CmdletBinding()] param($Path, $Name) [pscustomobject]@{ SystemRestorePointCreationFrequency = 1440 } }
    function New-ItemProperty { [CmdletBinding()] param($Path, $Name, $Value, $PropertyType, [switch]$Force) Add-Call 'new' $Value }
    function Set-ItemProperty { [CmdletBinding()] param($Path, $Name, $Value, $Type) Add-Call 'set' $Value }
    function Remove-ItemProperty { [CmdletBinding()] param($Path, $Name) Add-Call 'remove' $Name }
    function Invoke-CimMethod { [CmdletBinding()] param($Namespace, $ClassName, $MethodName, $Arguments, $InputObject) Add-Call 'cim' $Arguments; [pscustomobject]@{ ReturnValue = $script:FakeRv } }
    $SkipRestorePoint = $false
    New-CallLog; Reset-RunState; $script:FakeRv = 0
    $r = Invoke-RestorePointTask
    Assert-Equal $r.Status 'OK' 'status'
    Assert-Match $r.Detail '^WinDragon Maintenance ' 'restore point description'
    Assert-Equal (Get-Call 'new')[0].Data 0 'frequency relaxed to 0'
    Assert-Equal (Get-Call 'set')[0].Data 1440 'original frequency restored'
    Assert-Equal (Get-Call 'cim')[0].Data.RestorePointType ([uint32]12) 'restore point type'
    New-CallLog; Reset-RunState; $script:FakeRv = 1
    Assert-Equal (Invoke-RestorePointTask).Status 'Warning' 'System Protection off'
    Assert-Equal $script:Findings.Count 1 'finding count'
}

#endregion

#region ------------------------------------------------------------------- Integrity tasks (mocked)

Write-TestSection 'Integrity tasks'

Test-Case 'DISM: healthy store stops after CheckHealth/ScanHealth without RestoreHealth' {
    function Repair-WindowsImage { [CmdletBinding()] param([switch]$Online, [switch]$CheckHealth, [switch]$ScanHealth) Add-Call 'rwi' $(if ($CheckHealth) { 'Check' } else { 'Scan' }); [pscustomobject]@{ ImageHealthState = 'Healthy' } }
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) Add-Call 'native' ($ArgumentList -join ' '); [pscustomobject]@{ ExitCode = 0; Output = '' } }
    try {
        New-CallLog; Reset-RunState
        $r = Invoke-DismHealthChain
        Assert-Equal $r.Status 'OK' 'status'
        Assert-Equal ((Get-Call 'rwi' | ForEach-Object { $_.Data }) -join ',') 'Check,Scan' 'DISM module calls'
        Assert-Equal (Get-CallCount 'native') 0 'dism.exe calls'
    } finally { Restore-NativeCommandMock }
}
Test-Case 'DISM: -WhatIf runs only CheckHealth and never RestoreHealth' {
    function Repair-WindowsImage { [CmdletBinding()] param([switch]$Online, [switch]$CheckHealth, [switch]$ScanHealth) Add-Call 'rwi' $(if ($CheckHealth) { 'Check' } else { 'Scan' }); [pscustomobject]@{ ImageHealthState = 'Repairable' } }
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) Add-Call 'native' ($ArgumentList -join ' '); [pscustomobject]@{ ExitCode = 0; Output = '' } }
    try {
        New-CallLog; Reset-RunState
        $r = Invoke-DismHealthChain -WhatIf
        Assert-Equal $r.Detail 'WhatIf' 'detail'
        Assert-Equal ((Get-Call 'rwi' | ForEach-Object { $_.Data }) -join ',') 'Check' 'DISM module calls'
        Assert-Equal (Get-CallCount 'native') 0 'dism.exe calls'
    } finally { Restore-NativeCommandMock }
}
Test-Case 'DISM: Audit mode reports a repairable store without repairing it' {
    function Repair-WindowsImage { [CmdletBinding()] param([switch]$Online, [switch]$CheckHealth, [switch]$ScanHealth) [pscustomobject]@{ ImageHealthState = 'Repairable' } }
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) Add-Call 'native' ($ArgumentList -join ' '); [pscustomobject]@{ ExitCode = 0; Output = '' } }
    try {
        New-CallLog; Reset-RunState -RunLevel 'Audit'
        $r = Invoke-DismHealthChain
        Assert-Equal $r.Status 'Warning' 'status'
        Assert-Match $r.Detail 'audit mode' 'detail'
        Assert-Equal (Get-CallCount 'native') 0 'RestoreHealth calls'
    } finally { Restore-NativeCommandMock }
}
Test-Case 'DISM: RestoreHealth success (0/3010), 0x800F081F and -DismSource handling' {
    function Repair-WindowsImage { [CmdletBinding()] param([switch]$Online, [switch]$CheckHealth, [switch]$ScanHealth) throw 'module unavailable' }
    Set-NativeCommandMock {
        param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800)
        Add-Call 'native' @($ArgumentList)
        if ($ArgumentList -contains '/RestoreHealth') { return [pscustomobject]@{ ExitCode = $script:FakeExit; Output = $script:FakeOut } }
        [pscustomobject]@{ ExitCode = 0; Output = 'The component store is repairable.' }
    }
    try {
        New-CallLog; Reset-RunState; $script:FakeExit = 3010; $script:FakeOut = 'The restore operation completed successfully.'
        Assert-Equal (Invoke-DismHealthChain).Status 'Repaired' '3010 status'
        Assert-True $script:RebootNeeded 'RebootNeeded after 3010'

        New-CallLog; Reset-RunState; $script:FakeExit = 0; $script:FakeOut = 'Der Wiederherstellungsvorgang wurde erfolgreich abgeschlossen.'
        Assert-Equal (Invoke-DismHealthChain).Status 'Repaired' 'localized success (exit 0)'

        New-CallLog; Reset-RunState; $script:FakeExit = 1; $script:FakeOut = 'Error: 0x800f081f The source files could not be found.'
        $r = Invoke-DismHealthChain -DismSource 'D:\sources\install.wim:1'
        Assert-Equal $r.Status 'Failed' '0x800f081f status'
        Assert-Match ($script:Findings -join ' ') '-DismSource' 'finding mentions -DismSource'
        $restore = @(Get-Call 'native' | Where-Object { $_.Data -contains '/RestoreHealth' })[0].Data
        Assert-Contains $restore '/Source:D:\sources\install.wim:1' 'RestoreHealth args'
        Assert-Contains $restore '/LimitAccess' 'RestoreHealth args'
    } finally { Restore-NativeCommandMock }
}
Test-Case 'SFC: WhatIf never runs scannow' {
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) Add-Call 'native' $ArgumentList; [pscustomobject]@{ ExitCode = 0; Output = '' } }
    try {
        New-CallLog; Reset-RunState
        Assert-Equal (Invoke-SfcTask -WhatIf).Detail 'WhatIf' 'detail'
        Assert-Equal (Get-CallCount 'native') 0 'sfc calls'
    } finally { Restore-NativeCommandMock }
}
Test-Case 'SFC: Audit uses /verifyonly; each scannow outcome maps to the right status' {
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) Add-Call 'native' ($ArgumentList -join ' '); [pscustomobject]@{ ExitCode = 0; Output = $script:FakeOut } }
    try {
        New-CallLog; Reset-RunState -RunLevel 'Audit'; $script:FakeOut = 'found integrity violations'
        Assert-Equal (Invoke-SfcTask).Status 'Warning' 'audit violations'
        Assert-Equal (Get-Call 'native')[0].Data '/verifyonly' 'audit argument'
        $map = [ordered]@{
            'Windows Resource Protection did not find any integrity violations.' = 'OK'
            'Windows Resource Protection found corrupt files and successfully repaired them.' = 'Repaired'
            'Windows Resource Protection found corrupt files but was unable to fix some of them.' = 'Failed'
            'Windows Resource Protection could not perform the requested operation.' = 'Failed'
        }
        foreach ($k in $map.Keys) {
            Reset-RunState; $script:FakeOut = $k
            Assert-Equal (Invoke-SfcTask).Status $map[$k] "status for '$k'"
        }
    } finally { Restore-NativeCommandMock }
}
Test-Case 'SFC: localized output falls back to CBS.log entries written during this run' {
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) [pscustomobject]@{ ExitCode = 0; Output = 'texte localise inconnu' } }
    function Get-Content { [CmdletBinding()] param($Path, $Tail) $ts = (Get-Date).AddMinutes(1).ToString('yyyy-MM-dd HH:mm:ss'); "$ts, Info CSI 0001 [SR] Repairing corrupted file foo.dll" }
    try {
        Reset-RunState
        $r = Invoke-SfcTask
        Assert-Equal $r.Status 'Repaired' 'status'
        Assert-Match $r.Detail 'CBS.log' 'detail'
    } finally { Restore-NativeCommandMock }
}
Test-Case 'CBS review extracts unrepairable file names' {
    function Test-Path { [CmdletBinding()] param([Parameter(Position = 0)]$Path) $true }
    function Get-Content { [CmdletBinding()] param($Path, $Tail) @(
        "2026-09-15 10:00:10, Info CSI 00000213 [SR] Cannot repair member file [l:12]'shortname.dll' of Microsoft-Windows-Foo",
        '2026-09-15 10:00:15, Info CSI 00000214 [SR] Cannot repair member file [l:34{17}]"amd64_x\bar.dll" of Microsoft-Windows-Foo') }
    Reset-RunState
    $r = Invoke-CbsLogReviewTask
    Assert-Equal $r.Status 'Warning' 'status'
    Assert-Match $r.Detail '^2 unrepairable' 'detail'
}
Test-Case 'Component store: WhatIf, Audit, /ResetBase and exit-code handling' {
    Set-NativeCommandMock {
        param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800)
        Add-Call 'native' @($ArgumentList)
        if ($ArgumentList -contains '/AnalyzeComponentStore') { return [pscustomobject]@{ ExitCode = 0; Output = 'Actual Size of Component Store : 7.52 GB' } }
        [pscustomobject]@{ ExitCode = $script:FakeExit; Output = '' }
    }
    try {
        New-CallLog; Reset-RunState
        Assert-Equal (Invoke-ComponentStoreTask -WhatIf).Detail 'WhatIf' 'WhatIf detail'
        Assert-Equal @(Get-Call 'native' | Where-Object { $_.Data -contains '/StartComponentCleanup' }).Count 0 'cleanup under WhatIf'

        New-CallLog; Reset-RunState -RunLevel 'Audit'
        Assert-Equal (Invoke-ComponentStoreTask).Detail 'WinSxS 7.52 GB' 'audit detail'

        New-CallLog; Reset-RunState -RunLevel 'Full'; $script:FakeExit = 3010
        Assert-Equal (Invoke-ComponentStoreTask -ResetComponentStoreBase).Status 'Repaired' 'status'
        Assert-Contains @(Get-Call 'native' | Where-Object { $_.Data -contains '/StartComponentCleanup' })[0].Data '/ResetBase' 'cleanup args'
        Assert-True $script:RebootNeeded 'RebootNeeded after 3010'

        Reset-RunState -RunLevel 'Full'; $script:FakeExit = 5
        Assert-Equal (Invoke-ComponentStoreTask).Status 'Warning' 'failure status'
    } finally { Restore-NativeCommandMock }
}

#endregion

#region ------------------------------------------------------------------- Storage tasks (mocked)

Write-TestSection 'Storage tasks'

Test-Case 'Physical disk health flags wear >= 80% and passes healthy disks' {
    function Get-PhysicalDisk { [CmdletBinding()] param() [pscustomobject]@{ FriendlyName = 'NVMe'; MediaType = 'SSD'; BusType = 'NVMe'; Size = 1TB; HealthStatus = 'Healthy'; OperationalStatus = @('OK') } }
    function Get-StorageReliabilityCounter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process { [pscustomobject]@{ Wear = $script:FakeWear; Temperature = 40; PowerOnHours = 100; ReadErrorsUncorrected = 0; WriteErrorsUncorrected = 0 } } }
    function Get-CimInstance { [CmdletBinding()] param([Parameter(Position = 0)]$ClassName, $Namespace) [pscustomobject]@{ InstanceName = 'disk0'; PredictFailure = $false } }
    Reset-RunState; $script:FakeWear = 85
    Assert-Equal (Invoke-PhysicalDiskHealthTask).Status 'Warning' 'worn disk'
    Reset-RunState; $script:FakeWear = 5
    Assert-Equal (Invoke-PhysicalDiskHealthTask).Status 'OK' 'healthy disk'
}
Test-Case 'Volume scan: clean, dirty-by-scan and fsutil access-denied vs genuine dirty bit' {
    function Get-Volume { [CmdletBinding()] param() [pscustomobject]@{ DriveLetter = 'C'; DriveType = 'Fixed'; FileSystemType = 'NTFS' } }
    function Repair-Volume { [CmdletBinding()] param($DriveLetter, [switch]$Scan) $script:FakeScan }
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) $script:FakeFs }
    try {
        Reset-RunState; $script:FakeScan = 'NoErrorsFound'; $script:FakeFs = [pscustomobject]@{ ExitCode = 0; Output = 'Volume - C: is NOT Dirty' }
        Assert-Equal (Invoke-VolumeScanTask).Status 'OK' 'clean volume'

        Reset-RunState; $script:FakeScan = 'SpotFixNeeded'
        $r = Invoke-VolumeScanTask
        Assert-Equal $r.Status 'Warning' 'scan-reported problem'
        Assert-Equal (@($script:DirtyVolumes) -join ',') 'C' 'DirtyVolumes'

        Reset-RunState; $script:FakeScan = 'NoErrorsFound'; $script:FakeFs = [pscustomobject]@{ ExitCode = 1; Output = 'Error 5: Access is denied.' }
        Assert-False ((Invoke-VolumeScanTask).Detail -match 'dirty bit set') 'access denied reported as dirty'

        Reset-RunState; $script:FakeFs = [pscustomobject]@{ ExitCode = 1; Output = 'Volume - C: is Dirty' }
        Assert-Match (Invoke-VolumeScanTask).Detail 'dirty bit set' 'genuine dirty bit'
    } finally { Restore-NativeCommandMock }
}
Test-Case 'CHKDSK: not requested, WhatIf, and an idempotent BootExecute schedule (in-memory registry)' {
    function Get-ItemProperty { [CmdletBinding()] param($Path, $Name) [pscustomobject]@{ BootExecute = $script:FakeBoot } }
    function Set-ItemProperty { [CmdletBinding()] param($Path, $Name, $Value, $Type) Add-Call 'set' $Type; $script:FakeBoot = @($Value) }
    New-CallLog; Reset-RunState; $script:FakeBoot = @('autocheck autochk *')
    Assert-Equal (Invoke-ChkdskScheduleTask -ScheduleChkdsk:$false).Status 'Skipped' 'not requested'
    $script:DirtyVolumes = @('D', 'E')
    Assert-Equal (Invoke-ChkdskScheduleTask -ScheduleChkdsk -WhatIf).Detail 'WhatIf' 'WhatIf detail'
    Assert-Equal (Get-CallCount 'set') 0 'registry writes under WhatIf'

    $script:DirtyVolumes = @('D')
    $r = Invoke-ChkdskScheduleTask -ScheduleChkdsk
    Assert-Equal $r.Status 'Repaired' 'status'
    Assert-Contains $script:FakeBoot 'autocheck autochk /r \??\D:' 'BootExecute'
    Assert-Contains $script:FakeBoot 'autocheck autochk *' 'BootExecute keeps the default entry'
    Assert-Equal (Get-Call 'set')[0].Data 'MultiString' 'registry value type'
    Assert-True $script:RebootNeeded 'RebootNeeded'
    $null = Invoke-ChkdskScheduleTask -ScheduleChkdsk
    Assert-Equal @($script:FakeBoot | Where-Object { $_ -eq 'autocheck autochk /r \??\D:' }).Count 1 'entry duplicated on re-run'
}
Test-Case 'Volume optimization: SSD ReTrim, HDD Defrag, unknown ReTrim, Audit analyze-only, WhatIf no-op' {
    function Get-Volume { [CmdletBinding()] param() @(
        [pscustomobject]@{ DriveLetter = 'C'; DriveType = 'Fixed'; FileSystemType = 'NTFS' }
        [pscustomobject]@{ DriveLetter = 'D'; DriveType = 'Fixed'; FileSystemType = 'NTFS' }
        [pscustomobject]@{ DriveLetter = 'E'; DriveType = 'Fixed'; FileSystemType = 'ReFS' }
        [pscustomobject]@{ DriveLetter = 'F'; DriveType = 'Removable'; FileSystemType = 'FAT32' }) }
    function Get-VolumeMediaType { param([char]$DriveLetter) switch ($DriveLetter) { 'C' { 'SSD' } 'D' { 'HDD' } default { 'Unknown' } } }
    function Optimize-Volume { [CmdletBinding()] param($DriveLetter, [switch]$ReTrim, [switch]$Defrag, [switch]$Analyze)
        $op = if ($ReTrim) { 'ReTrim' } elseif ($Defrag) { 'Defrag' } else { 'Analyze' }; Add-Call 'opt' "$($DriveLetter):$op" }
    New-CallLog; Reset-RunState
    $null = Invoke-OptimizeVolumeTask
    Assert-Equal ((Get-Call 'opt' | ForEach-Object { $_.Data }) -join ',') 'C:ReTrim,D:Defrag,E:ReTrim' 'optimize operations'
    New-CallLog; Reset-RunState -RunLevel 'Audit'
    $null = Invoke-OptimizeVolumeTask
    Assert-Equal ((Get-Call 'opt' | ForEach-Object { $_.Data }) -join ',') 'C:Analyze,D:Analyze,E:Analyze' 'audit operations'
    New-CallLog; Reset-RunState
    $null = Invoke-OptimizeVolumeTask -WhatIf
    Assert-Equal (Get-CallCount 'opt') 0 'operations under WhatIf'
}

#endregion

#region ------------------------------------------------------------------- Servicing tasks (mocked)

Write-TestSection 'Servicing tasks'

function New-FakeWuSession {
    param([object[]]$Updates = @(), [int]$DownloadCode = 2, [int]$InstallCode = 2, [bool]$RebootRequired = $false)
    $state = @{ Updates = $Updates; DownloadCode = $DownloadCode; InstallCode = $InstallCode; Reboot = $RebootRequired; Installed = $false }
    $session = [pscustomobject]@{ State = $state }
    $session | Add-Member -MemberType ScriptMethod -Name CreateUpdateSearcher -Value {
        $s = [pscustomobject]@{ State = $this.State }
        $s | Add-Member -MemberType ScriptMethod -Name Search -Value { param($criteria) [pscustomobject]@{ Updates = $this.State.Updates } }
        $s
    }
    $session | Add-Member -MemberType ScriptMethod -Name CreateUpdateDownloader -Value {
        $d = [pscustomobject]@{ State = $this.State; Updates = $null }
        $d | Add-Member -MemberType ScriptMethod -Name Download -Value { [pscustomobject]@{ ResultCode = $this.State.DownloadCode } }
        $d
    }
    $session | Add-Member -MemberType ScriptMethod -Name CreateUpdateInstaller -Value {
        $i = [pscustomobject]@{ State = $this.State; Updates = $null }
        $i | Add-Member -MemberType ScriptMethod -Name Install -Value { $this.State.Installed = $true; [pscustomobject]@{ ResultCode = $this.State.InstallCode; RebootRequired = $this.State.Reboot } }
        $i
    }
    $session
}
$script:FakeUpdates = @(
    [pscustomobject]@{ Title = 'Cumulative Update KB0000001'; MaxDownloadSize = 300MB; EulaAccepted = $true }
    [pscustomobject]@{ Title = 'Defender Platform KB0000002'; MaxDownloadSize = 10MB; EulaAccepted = $true }
)
$script:WuMock = {
    function New-Object {
        [CmdletBinding()]
        param([string]$ComObject, [Parameter(Position = 0)][string]$TypeName, [Parameter(Position = 1)][object[]]$ArgumentList)
        if ($ComObject -eq 'Microsoft.Update.Session') { return $script:FakeSession }
        if ($ComObject -eq 'Microsoft.Update.UpdateColl') {
            $c = [pscustomobject]@{ Items = (Microsoft.PowerShell.Utility\New-Object System.Collections.ArrayList) }
            $c | Add-Member -MemberType ScriptMethod -Name Add -Value { param($u) $this.Items.Add($u) }
            return $c
        }
        Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
    }
}

Test-Case 'Windows Update: no pending updates -> OK' {
    . $script:WuMock
    Reset-RunState; $script:FakeSession = New-FakeWuSession
    Assert-Equal (Invoke-WindowsUpdateTask).Status 'OK' 'status'
}
Test-Case 'Windows Update: search explicitly includes optional (BrowseOnly) updates' {
    $text = (Get-FunctionDefinition -Files $script:AllFiles | Where-Object { $_.Name -eq 'Invoke-WindowsUpdateTask' }).Ast.Extent.Text
    Assert-Match $text 'BrowseOnly=0 or IsInstalled=0 and IsHidden=0 and BrowseOnly=1' 'search criteria'
}
Test-Case 'Windows Update: pending updates are reported but not installed by default or in Audit' {
    . $script:WuMock
    Reset-RunState; $script:FakeSession = New-FakeWuSession -Updates $script:FakeUpdates
    $r = Invoke-WindowsUpdateTask
    Assert-Equal $r.Detail '2 pending (not installed)' 'detail'
    Assert-False $script:FakeSession.State.Installed 'installed without -InstallWindowsUpdates'
    Reset-RunState -RunLevel 'Audit'
    $null = Invoke-WindowsUpdateTask -InstallWindowsUpdates
    Assert-False $script:FakeSession.State.Installed 'installed in Audit mode'
}
Test-Case 'Windows Update: WhatIf and SYSTEM context never install' {
    . $script:WuMock
    Reset-RunState; $script:FakeSession = New-FakeWuSession -Updates $script:FakeUpdates
    Assert-Equal (Invoke-WindowsUpdateTask -InstallWindowsUpdates -WhatIf).Detail 'WhatIf' 'WhatIf detail'
    function Test-IsSystemAccount { $true }
    Assert-Match (Invoke-WindowsUpdateTask -InstallWindowsUpdates).Detail 'SYSTEM' 'SYSTEM detail'
    Assert-False $script:FakeSession.State.Installed 'installed under WhatIf/SYSTEM'
}
Test-Case 'Windows Update: install success, reboot flag, partial and download failure' {
    . $script:WuMock
    Reset-RunState; $script:FakeSession = New-FakeWuSession -Updates $script:FakeUpdates -RebootRequired $true
    Assert-Equal (Invoke-WindowsUpdateTask -InstallWindowsUpdates).Status 'Repaired' 'success'
    Assert-True $script:RebootNeeded 'RebootNeeded'
    Reset-RunState; $script:FakeSession = New-FakeWuSession -Updates $script:FakeUpdates -InstallCode 3
    Assert-Equal (Invoke-WindowsUpdateTask -InstallWindowsUpdates).Detail 'Installed with errors' 'partial'
    Reset-RunState; $script:FakeSession = New-FakeWuSession -Updates $script:FakeUpdates -DownloadCode 4
    Assert-Equal (Invoke-WindowsUpdateTask -InstallWindowsUpdates).Status 'Failed' 'download failure'
    Reset-RunState; $script:FakeSession = New-FakeWuSession -Updates $script:FakeUpdates -DownloadCode 3
    Assert-Equal (Invoke-WindowsUpdateTask -InstallWindowsUpdates).Status 'Repaired' 'partial download still installs'
    Assert-True $script:FakeSession.State.Installed 'install skipped after a partial download'
}
Test-Case 'Windows Update stack repair: not requested and WhatIf touch nothing' {
    function Stop-Service { [CmdletBinding()] param($Name, [switch]$Force) Add-Call 'stop' $Name }
    New-CallLog
    Assert-Equal (Invoke-WindowsUpdateRepairTask -RepairWindowsUpdateStack:$false).Status 'Skipped' 'not requested'
    Assert-Equal (Invoke-WindowsUpdateRepairTask -RepairWindowsUpdateStack -WhatIf).Detail 'WhatIf' 'WhatIf'
    Assert-Equal (Get-CallCount 'stop') 0 'services stopped'
}
Test-Case 'Windows Update stack repair: stops 5 services, renames 2 folders, restarts, reports failures' {
    function Stop-Service { [CmdletBinding()] param($Name, [switch]$Force) Add-Call 'stop' $Name }
    function Start-Service { [CmdletBinding()] param($Name) if ($Name -eq $script:FailStart) { throw 'refused' }; Add-Call 'start' $Name }
    function Test-Path { [CmdletBinding()] param([Parameter(Position = 0)]$Path) $true }
    function Rename-Item { [CmdletBinding()] param($Path, $NewName, [switch]$Force) Add-Call 'rename' $NewName }
    New-CallLog; Reset-RunState; $script:FailStart = ''
    $r = Invoke-WindowsUpdateRepairTask -RepairWindowsUpdateStack
    Assert-Equal $r.Status 'Repaired' 'status'
    Assert-Equal ((Get-Call 'stop' | ForEach-Object { $_.Data }) -join ',') 'wuauserv,cryptSvc,bits,msiserver,usosvc' 'stopped services'
    Assert-Equal ((Get-Call 'start' | ForEach-Object { $_.Data }) -join ',') 'wuauserv,cryptSvc,bits,msiserver,usosvc' 'started services'
    Assert-Equal (Get-CallCount 'rename') 2 'renamed folders'
    Assert-Match ((Get-Call 'rename' | ForEach-Object { $_.Data }) -join ',') '^SoftwareDistribution\.bak-\d{8}-\d{6},catroot2\.bak-\d{8}-\d{6}$' 'backup names'
    New-CallLog; Reset-RunState; $script:FailStart = 'bits'
    $r = Invoke-WindowsUpdateRepairTask -RepairWindowsUpdateStack
    Assert-Equal $r.Status 'Failed' 'status with a service that will not restart'
    Assert-Match $r.Detail 'bits' 'detail'
}
if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
    Test-Case 'winget: skipped unless requested, WhatIf no-op, SYSTEM skipped' {
        Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) Add-Call 'native' $ArgumentList; [pscustomobject]@{ ExitCode = 0; Output = '' } }
        try {
            New-CallLog
            Assert-Match (Invoke-WingetTask -UpgradeApps:$false).Detail 'Not requested' 'not requested'
            Assert-Equal (Invoke-WingetTask -UpgradeApps -WhatIf).Detail 'WhatIf' 'WhatIf'
            function Test-IsSystemAccount { $true }
            Assert-Match (Invoke-WingetTask -UpgradeApps).Detail 'SYSTEM' 'SYSTEM'
            Assert-Equal (Get-CallCount 'native') 0 'winget calls'
        } finally { Restore-NativeCommandMock }
    }
    Test-Case 'winget: refreshes sources, upgrades the winget source and the msstore source' {
        Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) Add-Call 'native' @($ArgumentList); [pscustomobject]@{ ExitCode = $script:FakeExit; Output = 'mock' } }
        try {
            New-CallLog; $script:FakeExit = 0
            Assert-Equal (Invoke-WingetTask -UpgradeApps).Status 'Repaired' 'status'
            $argLines = @(Get-Call 'native' | ForEach-Object { $_.Data -join ' ' })
            Assert-Match $argLines[0] '^source update' 'first call'
            Assert-Equal (@($argLines | Where-Object { $_ -match '--all' -and $_ -notmatch '--silent' }).Count) 0 'listing call must not upgrade (--all without --silent)'
            Assert-True (@($argLines | Where-Object { $_ -match '--silent' -and $_ -notmatch 'msstore' }).Count -eq 1) 'winget-source upgrade call'
            Assert-True (@($argLines | Where-Object { $_ -match '--source msstore' -and $_ -match '--include-unknown' }).Count -eq 1) 'msstore upgrade call'
            New-CallLog; $script:FakeExit = 1
            Assert-Equal (Invoke-WingetTask -UpgradeApps).Status 'Warning' 'failure status'
        } finally { Restore-NativeCommandMock }
    }
} else {
    Skip-Case 'winget task checks' 'winget.exe not installed on this system'
}
Test-Case 'Store update scan: Audit/WhatIf skip; MDM bridge success and absence' {
    function Get-CimInstance { [CmdletBinding()] param($Namespace, $ClassName) if ($script:NoMdm) { throw 'no mdm' }; [pscustomobject]@{} }
    function Invoke-CimMethod { [CmdletBinding()] param($InputObject, $MethodName) Add-Call 'cim' $MethodName }
    New-CallLog; Reset-RunState -RunLevel 'Audit'
    Assert-Equal (Invoke-StoreAppUpdateTask).Detail 'Audit mode' 'audit'
    Reset-RunState
    Assert-Equal (Invoke-StoreAppUpdateTask -WhatIf).Detail 'WhatIf' 'WhatIf'
    Assert-Equal (Get-CallCount 'cim') 0 'calls before real run'
    $script:NoMdm = $false
    Assert-Equal (Invoke-StoreAppUpdateTask).Status 'OK' 'MDM ok'
    Assert-Equal (Get-Call 'cim')[0].Data 'UpdateScanMethod' 'method'
    $script:NoMdm = $true
    Assert-Equal (Invoke-StoreAppUpdateTask).Detail 'MDM bridge unavailable' 'no MDM'
}
Test-Case 'PowerShell hygiene: Audit/WhatIf skip; updates help and modules via PSResourceGet' {
    function Update-Help { [CmdletBinding()] param([switch]$Force) Add-Call 'help' $true }
    function Update-PSResource { [CmdletBinding()] param($Scope, [switch]$TrustRepository) Add-Call 'psres' $Scope }
    New-CallLog; Reset-RunState -RunLevel 'Audit'
    Assert-Equal (Invoke-PowerShellHygieneTask).Status 'Skipped' 'audit'
    Reset-RunState -RunLevel 'Full'
    Assert-Equal (Invoke-PowerShellHygieneTask -WhatIf).Detail 'WhatIf' 'WhatIf'
    Assert-Equal $script:Calls.Count 0 'calls under WhatIf'
    Assert-Equal (Invoke-PowerShellHygieneTask).Detail 'help updated; modules updated (PSResourceGet)' 'detail'
    Assert-Equal (Get-Call 'psres')[0].Data 'CurrentUser' 'scope'
}

#endregion

#region ------------------------------------------------------------------- Security tasks (mocked)

Write-TestSection 'Security tasks'

Test-Case 'Defender: Audit reads status only; stale signatures / RTP off / detections are warnings' {
    function Get-MpComputerStatus { [CmdletBinding()] param() [pscustomobject]@{ AMEngineVersion = '1'; AntivirusSignatureVersion = '1.2'; AntivirusSignatureAge = $script:FakeAge; RealTimeProtectionEnabled = $script:FakeRtp; IsTamperProtected = $true } }
    function Update-MpSignature { [CmdletBinding()] param() Add-Call 'sig' $true }
    function Start-MpScan { [CmdletBinding()] param($ScanType) Add-Call 'scan' $ScanType }
    function Get-MpThreatDetection { [CmdletBinding()] param() $script:FakeThreats }
    New-CallLog; Reset-RunState -RunLevel 'Audit'; $script:FakeAge = 0; $script:FakeRtp = $true; $script:FakeThreats = @()
    Assert-Equal (Invoke-DefenderTask -IncludeDefenderScan).Status 'OK' 'audit status'
    Assert-Equal $script:Calls.Count 0 'mutating Defender calls in Audit'

    New-CallLog; Reset-RunState
    $null = Invoke-DefenderTask -IncludeDefenderScan
    Assert-Equal (Get-CallCount 'sig') 1 'signature update'
    Assert-Equal (Get-Call 'scan')[0].Data 'QuickScan' 'scan type'
    New-CallLog
    $null = Invoke-DefenderTask
    Assert-Equal (Get-CallCount 'scan') 0 'scan without -IncludeDefenderScan'

    Reset-RunState; $script:FakeAge = 5; $script:FakeRtp = $false; $script:FakeThreats = @([pscustomobject]@{ InitialDetectionTime = (Get-Date).AddDays(-1) })
    $r = Invoke-DefenderTask -WhatIf
    Assert-Equal $r.Status 'Warning' 'status'
    Assert-Match $r.Detail 'real-time protection off; signatures 5 days old; 1 recent detections' 'detail'
}
Test-Case 'Defender: Skipped (not Failed) when Defender is disabled behind third-party AV' {
    function Get-MpComputerStatus { [CmdletBinding()] param() throw '0x800106ba service not running' }
    Reset-RunState
    $r = Invoke-DefenderTask
    Assert-Equal $r.Status 'Skipped' 'status'
    Assert-Match $r.Detail 'Defender unavailable' 'detail'
}
Test-Case 'Security posture: nominal vs firewall/BitLocker/HVCI gaps' {
    function Get-NetFirewallProfile { [CmdletBinding()] param() @(
        [pscustomobject]@{ Name = 'Domain'; Enabled = $true; DefaultInboundAction = 'Block' }
        [pscustomobject]@{ Name = 'Public'; Enabled = $script:FakeFw; DefaultInboundAction = 'Block' }) }
    function Confirm-SecureBootUEFI { [CmdletBinding()] param() $true }
    function Get-Tpm { [CmdletBinding()] param() [pscustomobject]@{ TpmPresent = $true; TpmReady = $true; TpmEnabled = $true } }
    function Get-BitLockerVolume { [CmdletBinding()] param() [pscustomobject]@{ VolumeType = 'OperatingSystem'; MountPoint = 'C:'; ProtectionStatus = $script:FakeBl; EncryptionPercentage = 100 } }
    function Get-CimInstance { [CmdletBinding()] param($ClassName, $Namespace) [pscustomobject]@{ SecurityServicesRunning = $script:FakeHvci } }
    Reset-RunState; $script:FakeFw = $true; $script:FakeBl = 'On'; $script:FakeHvci = @(2)
    Assert-Equal (Invoke-SecurityPostureTask).Status 'OK' 'nominal'
    Reset-RunState; $script:FakeFw = $false; $script:FakeBl = 'Off'; $script:FakeHvci = @(0)
    $r = Invoke-SecurityPostureTask
    Assert-Equal $r.Status 'Warning' 'status'
    Assert-Match $r.Detail 'firewall disabled on: Public; BitLocker off on C:; memory integrity' 'detail'
}

#endregion

#region ------------------------------------------------------------------- Cleanup tasks (sandbox / mocked)

Write-TestSection 'Cleanup tasks'

function New-SandboxWithJunction {
    $root = New-TempDir
    $outside = New-TempDir
    New-Item -ItemType Directory -Path (Join-Path $root 'sub') -Force | Out-Null
    Set-Content -Path (Join-Path $root 'sub\real.txt') -Value 'real' -NoNewline
    Set-Content -Path (Join-Path $outside 'secret.txt') -Value 'do-not-touch' -NoNewline
    New-Item -ItemType Junction -Path (Join-Path $root 'link-to-outside') -Target $outside | Out-Null
    [pscustomobject]@{ Root = $root; Outside = $outside }
}
function Remove-Sandbox { param($Sandbox) Remove-Item -Path $Sandbox.Root, $Sandbox.Outside -Recurse -Force -ErrorAction SilentlyContinue }

Test-Case 'Get-FilesSkippingReparsePoints does not follow a junction' {
    $sb = New-SandboxWithJunction
    try {
        $found = @(Get-FilesSkippingReparsePoints -Path $sb.Root | ForEach-Object { $_.FullName })
        Assert-Contains $found (Join-Path $sb.Root 'sub\real.txt') 'found files'
        Assert-False ($found | Where-Object { $_ -like "$($sb.Outside)*" }) 'files outside the junction leaked in'
    } finally { Remove-Sandbox $sb }
}
Test-Case 'Remove-PathContents deletes sandbox files but never crosses a junction' {
    $sb = New-SandboxWithJunction
    try {
        $freed = Remove-PathContents -Path $sb.Root -Label 'test'
        Assert-True ($freed -gt 0) 'expected freed bytes'
        Assert-False (Test-Path (Join-Path $sb.Root 'sub\real.txt')) 'real.txt should be deleted'
        Assert-True (Test-Path (Join-Path $sb.Root 'link-to-outside')) 'junction should remain'
        Assert-Equal (Get-Content (Join-Path $sb.Outside 'secret.txt') -Raw) 'do-not-touch' 'junction target content'
    } finally { Remove-Sandbox $sb }
}
Test-Case 'Remove-PathContents honours -OlderThanDays' {
    $sb = New-SandboxWithJunction
    try {
        $old = Join-Path $sb.Root 'old.txt'; $new = Join-Path $sb.Root 'new.txt'
        Set-Content -Path $old -Value 'old'; Set-Content -Path $new -Value 'new'
        (Get-Item $old).LastWriteTime = (Get-Date).AddDays(-10)
        $null = Remove-PathContents -Path $sb.Root -Label 'test' -OlderThanDays 5
        Assert-False (Test-Path $old) 'old file kept'
        Assert-True (Test-Path $new) 'new file removed'
    } finally { Remove-Sandbox $sb }
}
Test-Case 'Cleanup: Audit skips; -WhatIf never deletes a real %TEMP% canary' {
    Reset-RunState -RunLevel 'Audit'
    Assert-Equal (Invoke-CleanupTask).Detail 'Audit mode' 'audit'
    $canary = Join-Path $env:TEMP ('windragon-canary-{0}.txt' -f ([guid]::NewGuid().Guid.Substring(0, 8)))
    Set-Content -Path $canary -Value 'do-not-delete'
    try {
        Reset-RunState
        Assert-Equal (Invoke-CleanupTask -WhatIf).Detail 'WhatIf' 'WhatIf'
        Assert-True (Test-Path $canary) 'canary deleted under -WhatIf'
    } finally { Remove-Item -Path $canary -Force -ErrorAction SilentlyContinue }
}
Test-Case 'Cleanup: Standard targets 8 locations, Full 13, plus DO cache, Recycle Bin and DNS (mocked)' {
    function Get-Volume { [CmdletBinding()] param($DriveLetter) [pscustomobject]@{ SizeRemaining = 100GB } }
    function Remove-PathContents { param($Path, $Label, $OlderThanDays) Add-Call 'rm' "$Label|$OlderThanDays"; 1MB }
    function Delete-DeliveryOptimizationCache { [CmdletBinding()] param([switch]$Force) Add-Call 'do' $true }
    function Clear-RecycleBin { [CmdletBinding()] param([switch]$Force) Add-Call 'bin' $true }
    function Clear-DnsClientCache { [CmdletBinding()] param() Add-Call 'dns' $true }
    function Test-IsSystemAccount { $false }
    function Get-ChildItem { [CmdletBinding()] param($LiteralPath, $Filter, [switch]$Force) @([pscustomobject]@{ Length = 1MB }, [pscustomobject]@{ Length = 1MB }) }
    New-CallLog; Reset-RunState
    $r = Invoke-CleanupTask
    Assert-Equal $r.Status 'OK' 'status'
    Assert-Equal (Get-CallCount 'rm') 8 'Standard targets'
    Assert-Contains (Get-Call 'rm' | ForEach-Object { $_.Data }) 'Prefetch (stale entries)|90' 'Standard targets'
    Assert-Equal "$(Get-CallCount 'do')$(Get-CallCount 'bin')$(Get-CallCount 'dns')" '111' 'DO/RecycleBin/DNS calls'
    New-CallLog; Reset-RunState -RunLevel 'Full'
    $null = Invoke-CleanupTask
    Assert-Equal (Get-CallCount 'rm') 13 'Full targets'
    Assert-Contains (Get-Call 'rm' | ForEach-Object { $_.Data }) 'Windows Update cache|10' 'Full targets'
}
Test-Case 'Disk Cleanup: skipped unless requested, WhatIf no-op' {
    function Start-Process { [CmdletBinding()] param($FilePath, $ArgumentList, [switch]$PassThru, [switch]$Wait, $WindowStyle) Add-Call 'proc' $ArgumentList }
    New-CallLog
    Assert-Equal (Invoke-DiskCleanupTask -UseDiskCleanup:$false).Status 'Skipped' 'not requested'
    $r = Invoke-DiskCleanupTask -UseDiskCleanup -WhatIf
    Assert-Equal $r.Status 'Skipped' 'WhatIf status'
    Assert-Equal (Get-CallCount 'proc') 0 'cleanmgr launched'
}
if (Get-Command cleanmgr.exe -ErrorAction SilentlyContinue) {
    Test-Case 'Disk Cleanup: flags only allow-listed handlers (never DownloadsFolder) and always clears them' {
        function Get-ChildItem { [CmdletBinding()] param($Path) foreach ($n in 'Temporary Files', 'DownloadsFolder', 'Recycle Bin', 'Update Cleanup', 'Some Vendor Handler') {
            [pscustomobject]@{ PSPath = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$n" } } }
        function New-ItemProperty { [CmdletBinding()] param($Path, $Name, $Value, $PropertyType, [switch]$Force) Add-Call 'flag' (Split-Path $Path -Leaf) }
        function Remove-ItemProperty { [CmdletBinding()] param($Path, $Name) Add-Call 'unflag' (Split-Path $Path -Leaf) }
        function Start-Process { [CmdletBinding()] param($FilePath, $ArgumentList, [switch]$PassThru, [switch]$Wait, $WindowStyle) Add-Call 'proc' $ArgumentList; [pscustomobject]@{ ExitCode = 0 } }
        New-CallLog
        $r = Invoke-DiskCleanupTask -UseDiskCleanup
        Assert-Equal $r.Status 'OK' 'status'
        Assert-Equal ((Get-Call 'flag' | ForEach-Object { $_.Data }) -join ',') 'Temporary Files,Recycle Bin,Update Cleanup' 'flagged handlers'
        Assert-Equal (Get-Call 'proc')[0].Data '/sagerun:7777' 'cleanmgr args'
        Assert-Equal @(Get-Call 'unflag' | Where-Object { $_.Data -eq 'Temporary Files' }).Count 1 'StateFlags removed afterwards'
    }
} else {
    Skip-Case 'Disk Cleanup allow-list behaviour' 'cleanmgr.exe not present on this system'
}
Test-Case 'Disk Cleanup allow-list is identical to vader and excludes DownloadsFolder' {
    $text = (Get-FunctionDefinition -Files $script:AllFiles | Where-Object { $_.Name -eq 'Invoke-DiskCleanupTask' }).Ast.Extent.Text
    Assert-False ($text -match "'DownloadsFolder'") 'DownloadsFolder is allow-listed'
}
Test-Case 'Storage Sense: not configured, disabled and enabled' {
    function Test-IsSystemAccount { $false }
    function Test-Path { [CmdletBinding()] param([Parameter(Position = 0)]$Path) $script:FakeSsExists }
    function Get-ItemProperty { [CmdletBinding()] param($Path) [pscustomobject]@{ '01' = $script:FakeSs } }
    Reset-RunState; $script:FakeSsExists = $false
    Assert-Equal (Invoke-StorageSenseReportTask).Detail 'Storage Sense not configured' 'missing'
    Reset-RunState; $script:FakeSsExists = $true; $script:FakeSs = 0
    Assert-Equal (Invoke-StorageSenseReportTask).Detail 'Storage Sense disabled' 'disabled'
    Reset-RunState; $script:FakeSs = 1
    Assert-Equal (Invoke-StorageSenseReportTask).Status 'OK' 'enabled'
}

#endregion

#region ------------------------------------------------------------------- Diagnostics tasks (mocked)

Write-TestSection 'Diagnostics tasks'

Test-Case 'Event log review: counts errors and flags unexpected shutdowns (41/1001/6008)' {
    function Get-WinEvent { [CmdletBinding()] param([hashtable]$FilterHashtable)
        if ($FilterHashtable.ContainsKey('Id')) { if ($FilterHashtable.Id -eq 41) { return @([pscustomobject]@{ Id = 41 }, [pscustomobject]@{ Id = 41 }) }; throw 'none' }
        if ($FilterHashtable.LogName -eq 'System') { return @(1..3 | ForEach-Object { [pscustomobject]@{ Id = 7; ProviderName = 'disk' } }) }
        throw 'No events were found' }
    Reset-RunState; $EventLogDays = 7
    $r = Invoke-EventLogReviewTask
    Assert-Equal $r.Status 'Warning' 'status'
    Assert-Equal $r.Detail 'Event 41 x2' 'detail'
}
Test-Case 'Driver health: device problem codes are warnings' {
    function Get-CimInstance { [CmdletBinding()] param([Parameter(Position = 0)]$ClassName)
        if ($ClassName -eq 'Win32_PnPEntity') { return @([pscustomobject]@{ Name = 'ok'; DeviceID = '1'; ConfigManagerErrorCode = 0; Status = 'OK' }, [pscustomobject]@{ Name = 'bad'; DeviceID = '2'; ConfigManagerErrorCode = 28; Status = 'Error' }) }
        @([pscustomobject]@{ DeviceName = 'Old'; DriverProviderName = 'Vendor'; DriverVersion = '1'; DriverDate = (Get-Date).AddYears(-8) }) }
    Reset-RunState
    Assert-Equal (Invoke-DriverHealthTask).Detail '1 device problem code(s)' 'detail'
}
Test-Case 'Service health: a Disabled core service is a warning' {
    function Get-Service { [CmdletBinding()] param($Name)
        if ($Name) { return [pscustomobject]@{ Name = $Name; StartType = $(if ($Name -eq 'WinDefend') { 'Disabled' } else { 'Manual' }) } }
        @([pscustomobject]@{ Name = 'Idle'; DisplayName = 'Idle svc'; Status = 'Stopped'; StartType = 'Automatic' }) }
    Reset-RunState
    $r = Invoke-ServiceHealthTask
    Assert-Equal $r.Status 'Warning' 'status'
    Assert-Match $r.Detail 'WinDefend \(Microsoft Defender Antivirus\) is Disabled' 'detail'
}
Test-Case 'WMI repository: consistent, access denied (unverifiable) and genuinely inconsistent' {
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) $script:FakeWmi }
    try {
        Reset-RunState; $script:FakeWmi = [pscustomobject]@{ ExitCode = 0; Output = 'WMI repository is consistent' }
        Assert-Equal (Invoke-WmiRepositoryTask).Status 'OK' 'consistent'
        Reset-RunState; $script:FakeWmi = [pscustomobject]@{ ExitCode = 1; Output = "failed`nError code:     0x80041003" }
        Assert-Match (Invoke-WmiRepositoryTask).Detail 'Could not verify' 'access denied'
        Assert-Equal $script:Findings.Count 0 'false inconsistency finding'
        Reset-RunState; $script:FakeWmi = [pscustomobject]@{ ExitCode = 1; Output = 'WMI repository is inconsistent.' }
        Assert-Match (Invoke-WmiRepositoryTask).Detail 'inconsistent' 'inconsistent'
    } finally { Restore-NativeCommandMock }
}
Test-Case 'Power configuration: battery report and Full-level sleep study go to the run log folder' {
    Set-NativeCommandMock { param($FilePath, $ArgumentList = @(), $TimeoutSeconds = 1800) Add-Call 'native' ($ArgumentList -join ' '); [pscustomobject]@{ ExitCode = 0; Output = 'Power Scheme GUID: x (Balanced)' } }
    function Get-CimInstance { [CmdletBinding()] param([Parameter(Position = 0)]$ClassName) [pscustomobject]@{ Name = 'Battery' } }
    try {
        $dir = New-TempDir; $script:RunLogDir = $dir
        New-CallLog; Reset-RunState -RunLevel 'Audit'
        $null = Invoke-PowerConfigTask
        Assert-Equal ((Get-Call 'native' | ForEach-Object { $_.Data }) -join ',') '/getactivescheme' 'Audit calls'
        New-CallLog; Reset-RunState -RunLevel 'Full'
        Assert-Equal (Invoke-PowerConfigTask).Status 'OK' 'status'
        $calls = @(Get-Call 'native' | ForEach-Object { $_.Data })
        Assert-Equal $calls.Count 3 'Full calls'
        Assert-True ($calls[1] -like "/batteryreport /output $dir*") 'battery report path'
        Assert-True ($calls[2] -like "/sleepstudy /output $dir*") 'sleep study path'
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    } finally { Restore-NativeCommandMock }
}
Test-Case 'Startup impact: more than 15 Run entries is a warning' {
    function Test-Path { [CmdletBinding()] param([Parameter(Position = 0)]$Path) $Path -like 'HKLM:\SOFTWARE\Microsoft*' }
    function Get-ItemProperty { [CmdletBinding()] param($Path) $o = [ordered]@{ PSPath = 'x' }; 1..16 | ForEach-Object { $o["App$_"] = "app$_.exe" }; [pscustomobject]$o }
    function Get-ScheduledTask { [CmdletBinding()] param() @() }
    Reset-RunState
    Assert-Equal (Invoke-StartupImpactTask).Detail '16 startup entries' 'detail'
}
Test-Case 'Startup impact: a Run key with no values does not fail the task (StrictMode regression)' {
    function Test-Path { [CmdletBinding()] param([Parameter(Position = 0)]$Path) $true }
    function Get-ItemProperty { [CmdletBinding()] param($Path) }
    function Get-ScheduledTask { [CmdletBinding()] param() @() }
    Reset-RunState
    $r = Invoke-StartupImpactTask
    Assert-Equal $r.Status 'OK' 'status'
    Assert-Equal $r.Detail '0 startup entries' 'detail'
}
Test-Case 'Pending reboot: zero, one (StrictMode regression) and multiple reasons' {
    Set-Item Function:\Get-PendingRebootDetail -Value { return @() }
    Reset-RunState
    Assert-Equal (Invoke-PendingRebootTask).Status 'OK' 'zero'
    Set-Item Function:\Get-PendingRebootDetail -Value { return 'Windows Update' }
    Assert-Equal (Invoke-PendingRebootTask).Detail 'Windows Update' 'one'
    Set-Item Function:\Get-PendingRebootDetail -Value { return @('Windows Update', 'Component Based Servicing') }
    Assert-Equal (Invoke-PendingRebootTask).Status 'Warning' 'multiple'
    Reset-RunState; $script:RebootNeeded = $true
    Set-Item Function:\Get-PendingRebootDetail -Value { return @() }
    Assert-Equal (Invoke-PendingRebootTask).Detail 'Reboot recommended by this run' 'run-requested reboot'
}

#endregion

#region ------------------------------------------------------------------- Reporting and scheduling

Write-TestSection 'Reporting and scheduling'

Test-Case 'ConvertTo-HtmlSafe escapes markup' {
    Assert-Equal (ConvertTo-HtmlSafe '<a href="x">&</a>') '&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;' 'escaped'
    Assert-Equal (ConvertTo-HtmlSafe $null) '' 'null'
}
Test-Case 'Write-HtmlReport writes a WinDragon report with escaped task and finding text' {
    Reset-RunState
    $script:Snapshot = New-FakeSnapshot
    $script:Results.Add([pscustomobject]@{ Category = 'C'; Task = '<script>'; Status = 'OK'; Seconds = 1; Detail = 'a & b' })
    Add-Finding 'Finding <b>bold</b>'
    $path = Join-Path (New-TempDir) 'r.html'
    Write-HtmlReport -Path $path
    $html = Get-Content -LiteralPath $path -Raw
    Assert-Match $html 'WinDragon Maintenance Report - TESTPC' 'title'
    Assert-Match $html '&lt;script&gt;' 'escaped task'
    Assert-Match $html 'Finding &lt;b&gt;bold&lt;/b&gt;' 'escaped finding'
    Assert-False ($html -match '<script>') 'unescaped script tag'
    Remove-Item (Split-Path $path) -Recurse -Force
}
Test-Case 'Write-HtmlReport escapes firmware/WMI-sourced system fields' {
    Reset-RunState
    $script:Snapshot = New-FakeSnapshot
    $script:Snapshot.Model = '<img src=x onerror=alert(1)>'
    $path = Join-Path (New-TempDir) 'r.html'
    Write-HtmlReport -Path $path
    $html = Get-Content -LiteralPath $path -Raw
    Assert-Match $html '&lt;img src=x onerror=alert\(1\)&gt;' 'escaped model'
    Assert-False ($html -match '<img') 'unescaped model markup'
    Remove-Item (Split-Path $path) -Recurse -Force
}
Test-Case 'Write-RunSummary renders without throwing (with and without findings / reboot)' {
    Reset-RunState
    Assert-NoThrow { Write-RunSummary }
    $script:Results.Add([pscustomobject]@{ Category = 'C'; Task = 'T'; Status = 'Failed'; Seconds = 1; Detail = 'x' })
    Add-Finding 'f'; $script:RebootNeeded = $true
    Assert-NoThrow { Write-RunSummary }
}
Test-Case 'Register-MaintenanceTask registers winDragon.ps1 weekly as SYSTEM at Standard level (mocked)' {
    function New-ScheduledTaskAction { [CmdletBinding()] param($Execute, $Argument) Add-Call 'action' $Argument; 'action' }
    function New-ScheduledTaskTrigger { [CmdletBinding()] param([switch]$Weekly, $DaysOfWeek, $At) Add-Call 'trigger' "$DaysOfWeek"; 'trigger' }
    function New-ScheduledTaskPrincipal { [CmdletBinding()] param($UserId, $LogonType, $RunLevel) Add-Call 'principal' "$UserId/$RunLevel"; 'principal' }
    function New-ScheduledTaskSettingsSet { [CmdletBinding()] param([switch]$StartWhenAvailable, [switch]$DontStopOnIdleEnd, $ExecutionTimeLimit, $MultipleInstances, $RestartCount, $RestartInterval) 'settings' }
    function Register-ScheduledTask { [CmdletBinding()] param($TaskName, $Description, $Action, $Trigger, $Principal, $Settings, [switch]$Force) Add-Call 'register' $TaskName }
    New-CallLog
    Register-MaintenanceTask
    Assert-Equal (Get-Call 'register')[0].Data 'WinDragon Maintenance Protocol' 'task name'
    Assert-Equal (Get-Call 'principal')[0].Data 'SYSTEM/Highest' 'principal'
    Assert-Equal (Get-Call 'trigger')[0].Data 'Sunday' 'trigger day'
    $arg = (Get-Call 'action')[0].Data
    Assert-True ($arg.Contains(('-File "{0}"' -f $script:MainScript))) "scheduled script path is not winDragon.ps1: $arg"
    Assert-Match $arg '-Level Standard -SkipRestorePoint$' 'arguments'
}

#endregion

#region ------------------------------------------------------------------- Interface (scripted input)

Write-TestSection 'Interface'

$script:OriginalResetConsole = (Get-Command ResetConsoleScreen).ScriptBlock
Set-Item Function:\ResetConsoleScreen -Value { }   # keep the test console readable

function Set-Input {
    param([string[]]$Answers)
    $script:InputQueue = New-Object System.Collections.Generic.Queue[string]
    foreach ($a in $Answers) { $script:InputQueue.Enqueue($a) }
}
function Save-Options {
    $script:SavedOptions = @{}
    foreach ($n in 'Level', 'OnlyTask', 'SkipTask', 'DismSource', 'EventLogDays', 'LogRoot', 'InstallWindowsUpdates', 'UpgradeApps', 'IncludeDefenderScan', 'ScheduleChkdsk', 'ResetComponentStoreBase', 'RepairWindowsUpdateStack', 'UseDiskCleanup', 'SkipRestorePoint') {
        $script:SavedOptions[$n] = Get-Variable -Name $n -Scope Script -ValueOnly
    }
}
function Restore-Options {
    $script:WhatIfPreference = $false
    $script:ConfirmPreference = 'High'
    $script:VerbosePreference = 'SilentlyContinue'
    foreach ($k in $script:SavedOptions.Keys) { Set-Variable -Name $k -Scope Script -Value $script:SavedOptions[$k] -WhatIf:$false -Confirm:$false }
}
# Scripted Read-Host plus a recording stand-in for the real maintenance pass.
$script:InterfaceMocks = {
    function Read-Host { [CmdletBinding()] param([Parameter(Position = 0)]$Prompt)
        if ($script:InputQueue.Count -eq 0) { throw "Unexpected prompt: $Prompt" }
        $script:InputQueue.Dequeue() }
    function Start-MaintenanceRun {
        $script:Runs.Add([pscustomobject]@{
            Level = $Level; OnlyTask = @($OnlyTask | Where-Object { $_ }); SkipTask = @($SkipTask | Where-Object { $_ })
            WhatIf = [bool]$WhatIfPreference; UpgradeApps = [bool]$UpgradeApps; DismSource = $DismSource
        }) }
    function Register-MaintenanceTask { $script:Runs.Add([pscustomobject]@{ Level = 'REGISTER'; OnlyTask = @(); SkipTask = @(); WhatIf = $false; UpgradeApps = $false; DismSource = '' }) }
    $script:Runs = New-Object System.Collections.Generic.List[object]
}

Test-Case 'Main menu offers options 1-10 and Show-Menu returns the typed choice' {
    . $script:InterfaceMocks
    Assert-Equal ((Get-MainMenuItem | ForEach-Object { $_.Key }) -join ',') '1,2,3,4,5,6,7,8,9,10' 'menu keys'
    Set-Input '4'
    Assert-Equal (Show-Menu) '4' 'returned choice'
}
Test-Case 'Menu 1-4 run full Audit/Quick/Standard/Full passes and restore the configured level' {
    . $script:InterfaceMocks
    Save-Options
    try {
        $script:Level = 'Standard'
        foreach ($k in '1', '2', '3', '4') { Assert-True (Invoke-MenuChoice -Choice $k -Interactive) "pause after $k" }
        Assert-Equal (($script:Runs | ForEach-Object { $_.Level }) -join ',') 'Audit,Quick,Standard,Full' 'run levels'
        Assert-Equal $Level 'Standard' 'configured level restored'
        Assert-Equal (@($script:Runs | Where-Object { $_.OnlyTask.Count -gt 0 }).Count) 0 'OnlyTask set on a full pass'
    } finally { Restore-Options }
}
Test-Case 'Menu 8 lists the catalogue; 9 registers the task; 9 with -WhatIf does not; invalid input is rejected' {
    . $script:InterfaceMocks
    Assert-True (Invoke-MenuChoice -Choice '8' -Interactive) 'pause after 8'
    Assert-True (Invoke-MenuChoice -Choice '9' -Interactive -WhatIf) 'pause after 9'
    Assert-Equal $script:Runs.Count 0 'registered under WhatIf'
    $null = Invoke-MenuChoice -Choice '9' -Interactive
    Assert-Equal (($script:Runs | ForEach-Object { $_.Level }) -join ',') 'REGISTER' 'register call'
    Assert-True (Invoke-MenuChoice -Choice '42' -Interactive) 'invalid choice'
    Assert-Equal $script:Runs.Count 1 'runs after invalid choice'
}
Test-Case 'Headless -RunChoice rejects the interactive-only options 5, 6 and 7' {
    . $script:InterfaceMocks
    foreach ($k in '5', '6', '7') { Assert-Throws { Invoke-MenuChoice -Choice $k } 'interactive' "RunChoice $k" }
    Assert-Equal $script:Runs.Count 0 'runs'
}
Test-Case 'Menu 5 runs exactly one category as -OnlyTask and restores -OnlyTask afterwards' {
    . $script:InterfaceMocks
    Save-Options
    try {
        Set-Input '2'
        Assert-True (Invoke-MenuChoice -Choice '5' -Interactive) 'pause'
        Assert-Equal ($script:Runs[0].OnlyTask -join ',') 'DISM Health Chain,SFC System File Scan,CBS Log Review,Component Store Cleanup' 'Integrity tasks'
        Assert-Equal @($OnlyTask | Where-Object { $_ }).Count 0 'OnlyTask restored'
        Set-Input '0'
        Assert-False (Invoke-MenuChoice -Choice '5' -Interactive) 'back returns without pause'
        Set-Input '99'
        $null = Invoke-MenuChoice -Choice '5' -Interactive
        Assert-Equal $script:Runs.Count 1 'runs after back/invalid'
    } finally { Restore-Options }
}
Test-Case 'Every category maps to exactly its catalogue tasks' {
    . $script:InterfaceMocks
    $cats = @($script:TaskCatalogue | ForEach-Object { $_.Category } | Select-Object -Unique)
    Assert-Equal ($cats -join ',') 'Baseline,Integrity,Storage,Servicing,Security,Cleanup,Diagnostics' 'categories'
    for ($i = 0; $i -lt $cats.Count; $i++) {
        Set-Input "$($i + 1)"
        $null = Show-CategoryMenu
        $expected = @($script:TaskCatalogue | Where-Object { $_.Category -eq $cats[$i] } | ForEach-Object { $_.Name })
        Assert-Equal ($script:Runs[$i].OnlyTask -join ',') ($expected -join ',') "category $($cats[$i])"
    }
}
Test-Case 'Menu 6 runs the picked tasks (numbers and ranges) as -OnlyTask; bad input runs nothing' {
    . $script:InterfaceMocks
    Save-Options
    try {
        Set-Input '1, 5-6'
        $null = Invoke-MenuChoice -Choice '6' -Interactive
        Assert-Equal ($script:Runs[0].OnlyTask -join ',') 'System Inventory,DISM Health Chain,SFC System File Scan' 'picked tasks'
        foreach ($bad in 'abc', '30', ',') {
            Set-Input $bad
            $null = Invoke-MenuChoice -Choice '6' -Interactive
        }
        Assert-Equal $script:Runs.Count 1 'runs after bad input'
    } finally { Restore-Options }
}
Test-Case 'ConvertFrom-TaskSelection parses lists and ranges and rejects out-of-range input' {
    Assert-Equal ((ConvertFrom-TaskSelection -Selection '3,1,2-3' -Max 29) -join ',') '1,2,3' 'list + range'
    Assert-Equal ((ConvertFrom-TaskSelection -Selection '7-5' -Max 29) -join ',') '5,6,7' 'reversed range'
    Assert-Equal ((ConvertFrom-TaskSelection -Selection '29' -Max 29) -join ',') '29' 'upper bound'
    Assert-Throws { ConvertFrom-TaskSelection -Selection '0' -Max 29 } 'out of range' 'zero'
    Assert-Throws { ConvertFrom-TaskSelection -Selection '30' -Max 29 } 'out of range' 'too high'
    Assert-Throws { ConvertFrom-TaskSelection -Selection '1;2' -Max 29 } 'Invalid selection' 'bad separator'
}
Test-Case 'Options menu toggles every vader switch parameter on and off' {
    . $script:InterfaceMocks
    Save-Options
    try {
        $defs = @(Get-SwitchOptionDefinition)
        for ($i = 0; $i -lt $defs.Count; $i++) {
            if ($defs[$i].Kind -ne 'Switch') { continue }
            $name = $defs[$i].Name
            Set-Input "$($i + 1)", '0'; Show-OptionsMenu
            Assert-True (Get-Variable -Name $name -Scope Script -ValueOnly) "$name on"
            Set-Input "$($i + 1)", '0'; Show-OptionsMenu
            Assert-False (Get-Variable -Name $name -Scope Script -ValueOnly) "$name off"
        }
    } finally { Restore-Options }
}
Test-Case 'Every vader switch/value parameter is reachable from the menu' {
    $defs = @(Get-SwitchOptionDefinition | ForEach-Object { $_.Name })
    $menuOnly = @{ ListTasks = 'menu 8'; RegisterScheduledTask = 'menu 9'; OnlyTask = 'menu 5/6'; Level = 'menu 1-4 + options'
                   SkipTask = 'options'; DismSource = 'options'; EventLogDays = 'options'; LogRoot = 'options'; NoElevatePrompt = 'command line (before the menu)' }
    $params = if ($script:HaveVader) { @((Get-FileAst -Path $VaderScript).Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) } else { @() }
    $unmapped = @($params | Where-Object { $defs -notcontains $_ -and -not $menuOnly.ContainsKey($_) })
    Assert-Equal ($unmapped -join ',') '' 'vader parameters with no interface path'
    foreach ($p in 'WhatIf', 'Confirm', 'Verbose') { Assert-Contains $defs $p 'common-parameter toggles' }
}
Test-Case 'Options: WhatIf toggle makes the next run a preview; Confirm/Verbose toggles set preferences' {
    . $script:InterfaceMocks
    Save-Options
    try {
        $defs = @(Get-SwitchOptionDefinition)
        $idx = { param($n) [array]::IndexOf(@($defs | ForEach-Object { $_.Name }), $n) + 1 }
        Set-Input "$(& $idx 'WhatIf')", "$(& $idx 'UpgradeApps')", '0'; Show-OptionsMenu
        Assert-True $WhatIfPreference 'WhatIfPreference'
        Assert-True $UpgradeApps 'UpgradeApps toggled while WhatIf is on'
        $null = Invoke-MenuChoice -Choice '3' -Interactive
        $script:WhatIfPreference = $false
        Assert-True $script:Runs[0].WhatIf 'WhatIf carried into run'
        Assert-True $script:Runs[0].UpgradeApps 'UpgradeApps carried into run'
        Set-Input "$(& $idx 'Verbose')", '0'; Show-OptionsMenu
        Assert-Equal $VerbosePreference 'Continue' 'VerbosePreference'
        Set-Input "$(& $idx 'Confirm')", '0'; Show-OptionsMenu
        Assert-Equal $ConfirmPreference 'Medium' 'ConfirmPreference'
        Assert-Match (Get-ActiveOptionSummary) '-UpgradeApps' 'summary'
    } finally { Restore-Options }
}
Test-Case 'Options: WhatIf is honoured by a real ShouldProcess-gated task' {
    Save-Options
    try {
        Reset-RunState
        $script:WhatIfPreference = $true
        $r = Invoke-SfcTask
        $script:WhatIfPreference = $false
        Assert-Equal $r.Detail 'WhatIf' 'sfc under menu WhatIf'
    } finally { Restore-Options }
}
Test-Case 'Options: level, DISM source, event log days, reports folder and skip list; bad values rejected' {
    . $script:InterfaceMocks
    Save-Options
    try {
        $b = @(Get-SwitchOptionDefinition).Count
        Set-Input "$($b + 1)", 'full', '0'; Show-OptionsMenu
        Assert-Equal $Level 'Full' 'level (canonical casing)'
        Set-Input "$($b + 1)", 'bogus', '', '0'; Show-OptionsMenu
        Assert-Equal $Level 'Full' 'level after bad input'
        Set-Input "$($b + 2)", 'D:\sources\install.wim:1', '0'; Show-OptionsMenu
        Assert-Equal $DismSource 'D:\sources\install.wim:1' 'DismSource'
        Set-Input "$($b + 3)", '30', '0'; Show-OptionsMenu
        Assert-Equal $EventLogDays 30 'EventLogDays'
        Set-Input "$($b + 3)", '500', '', '0'; Show-OptionsMenu
        Assert-Equal $EventLogDays 30 'EventLogDays after bad input'
        Set-Input "$($b + 4)", 'C:\WinDragonReports', '0'; Show-OptionsMenu
        Assert-Equal $LogRoot 'C:\WinDragonReports' 'LogRoot'
        Set-Input "$($b + 5)", 'DISM*, SFC*', '0'; Show-OptionsMenu
        Assert-Equal ($SkipTask -join '|') 'DISM*|SFC*' 'SkipTask'
        $null = Invoke-MenuChoice -Choice '3' -Interactive
        Assert-Equal ($script:Runs[0].SkipTask -join '|') 'DISM*|SFC*' 'SkipTask carried into run'
        Assert-Equal $script:Runs[0].DismSource 'D:\sources\install.wim:1' 'DismSource carried into run'
        Set-Input "$($b + 5)", '', '0'; Show-OptionsMenu
        Assert-Equal @($SkipTask | Where-Object { $_ }).Count 0 'SkipTask cleared'
        Set-Input '77', '', '0'; Show-OptionsMenu
        Assert-Equal $script:InputQueue.Count 0 'unconsumed input'
    } finally { Restore-Options }
}
Test-Case 'Interactive loop: declining the disclaimer exits without running anything' {
    . $script:InterfaceMocks
    Set-Input 'n'
    Start-InteractiveMenu
    Assert-Equal $script:Runs.Count 0 'runs'
}
Test-Case 'Interactive loop: accept, run Standard, invalid choice, then exit' {
    . $script:InterfaceMocks
    Save-Options
    try {
        Set-Input 'Y', '3', '', '42', '', '10'
        Start-InteractiveMenu
        Assert-Equal (($script:Runs | ForEach-Object { $_.Level }) -join ',') 'Standard' 'runs'
        Assert-Equal $script:InputQueue.Count 0 'unconsumed input'
    } finally { Restore-Options }
}
Test-Case 'Interactive loop survives a failing action and keeps the menu alive' {
    . $script:InterfaceMocks
    function Start-MaintenanceRun { throw 'simulated failure' }
    Set-Input 'Y', '1', '', '10'
    Assert-NoThrow { Start-InteractiveMenu } 'menu loop crashed'
    Assert-Equal $script:InputQueue.Count 0 'unconsumed input'
}
Test-Case 'ResetConsoleScreen swallows redirected-console errors' {
    Assert-Match $script:OriginalResetConsole.ToString() 'try\s*\{\s*\[System\.Console\]::Clear\(\)\s*\}\s*catch' 'ResetConsoleScreen body'
}

#endregion

#region ------------------------------------------------------------------- End-to-end pass (fake catalogue)

Write-TestSection 'End-to-end pass'

Test-Case 'Start-MaintenanceRun writes transcript, results.json and HTML; state resets between runs' {
    function Get-SystemSnapshot { New-FakeSnapshot }
    Save-Options
    $savedCatalogue = $script:TaskCatalogue
    $root1 = New-TempDir; $root2 = New-TempDir
    try {
        $script:TaskCatalogue = @(
            New-MaintenanceTask -Name 'Fake OK'     -Category 'Test' -MinLevel 1 -ReadOnly -Action { @{ Status = 'OK'; Detail = 'fine' } }
            New-MaintenanceTask -Name 'Fake Repair' -Category 'Test' -MinLevel 1 -Action { $script:RebootNeeded = $true; Add-Finding 'Fake <finding>'; @{ Status = 'Repaired'; Detail = '<b>x</b>' } }
            New-MaintenanceTask -Name 'Fake Full'   -Category 'Test' -MinLevel 3 -ReadOnly -Action { @{ Status = 'OK' } }
            New-MaintenanceTask -Name 'Fake Boom'   -Category 'Test' -MinLevel 1 -ReadOnly -Action { throw 'boom' }
        )
        $script:LogRoot = $root1; $script:Level = 'Standard'
        Start-MaintenanceRun
        $dir = @(Get-ChildItem -LiteralPath $root1 -Directory)[0].FullName
        foreach ($f in 'transcript.log', 'results.json', 'maintenance-report.html') { Assert-True (Test-Path (Join-Path $dir $f)) "$f missing" }
        $json = Get-Content -LiteralPath (Join-Path $dir 'results.json') -Raw | ConvertFrom-Json
        Assert-Equal (($json.Results | ForEach-Object { $_.Status }) -join ',') 'OK,Repaired,Skipped,Failed' 'statuses'
        Assert-Equal $json.Level 'Standard' 'level'
        Assert-True $json.RebootNeeded 'RebootNeeded'
        Assert-Equal (@($json.Findings) -join '') 'Fake <finding>' 'findings'
        $html = Get-Content -LiteralPath (Join-Path $dir 'maintenance-report.html') -Raw
        Assert-Match $html '&lt;b&gt;x&lt;/b&gt;' 'escaped detail'

        $script:LogRoot = $root2
        $null = Start-LevelRun -RunLevel 'Audit'
        $dir2 = @(Get-ChildItem -LiteralPath $root2 -Directory)[0].FullName
        $json2 = Get-Content -LiteralPath (Join-Path $dir2 'results.json') -Raw | ConvertFrom-Json
        Assert-Equal @($json2.Results).Count 4 'results reset between runs'
        Assert-Equal (($json2.Results | ForEach-Object { $_.Status }) -join ',') 'OK,Skipped,Skipped,Failed' 'Audit statuses'
        Assert-False $json2.RebootNeeded 'RebootNeeded reset'
        Assert-Equal @($json2.Findings).Count 0 'findings reset'
        Assert-Equal $json2.Level 'Audit' 'level'
        Assert-Equal $Level 'Standard' 'configured level restored'
    } finally {
        $script:TaskCatalogue = $savedCatalogue
        Restore-Options
        try { Stop-Transcript | Out-Null } catch { }
        Remove-Item $root1, $root2 -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region ------------------------------------------------------------------- Launcher

Write-TestSection 'Launcher'

Test-Case 'launcher.ps1 parses and every button maps to a headless-capable -RunChoice' {
    $p = Get-FileAst -Path (Join-Path $WinDragonRoot 'launcher.ps1')
    Assert-Equal $p.Errors.Count 0 'parse errors'
    $choices = @([regex]::Matches((Get-Content -LiteralPath (Join-Path $WinDragonRoot 'launcher.ps1') -Raw), 'RunChoice\s*=\s*(\d+)') | ForEach-Object { $_.Groups[1].Value })
    Assert-Equal ($choices -join ',') '1,2,3,4,8,9' 'launcher RunChoice values'
    foreach ($c in $choices) { Assert-NotContains @('5', '6', '7') $c 'interactive-only choice on a button' }
}

#endregion

#region ------------------------------------------------------------------- Build (build.py)

Write-TestSection 'Build'

$python = Get-Command python -ErrorAction SilentlyContinue
if ($SkipBuild) {
    Skip-Case 'build.py bundling' '-SkipBuild'
} elseif (-not $python) {
    Skip-Case 'build.py bundling' 'python not found'
} else {
    $script:BuildDir = New-TempDir
    Test-Case 'build.py bundles winDragon.ps1 + Modules in a temporary copy' {
        Copy-Item -Path (Join-Path $WinDragonRoot 'winDragon.ps1'), (Join-Path $WinDragonRoot 'launcher.ps1'), (Join-Path $WinDragonRoot 'build.py') -Destination $script:BuildDir
        Copy-Item -Path $script:ModulesDir -Destination (Join-Path $script:BuildDir 'Modules') -Recurse
        Push-Location $script:BuildDir
        try { $out = & $python.Source build.py 2>&1; $code = $LASTEXITCODE } finally { Pop-Location }
        Assert-Equal $code 0 "build.py exit code ($out)"
        $script:Built = @(Get-ChildItem -Path (Join-Path $script:BuildDir 'build') -Filter 'winDragon_*.ps1')[0].FullName
        Assert-True (Test-Path $script:Built) 'bundled script missing'
    }
    Test-Case 'Bundled script parses, inlines every module and keeps every function token-identical' {
        $p = Get-FileAst -Path $script:Built
        Assert-Equal $p.Errors.Count 0 'parse errors'
        Assert-False ((Get-Content -LiteralPath $script:Built -Raw) -match '(?m)^\.\s+\$PSScriptRoot\\Modules') 'module import left in bundle'
        $builtFns = @(Get-FunctionDefinition -Files @($script:Built))
        $diff = @()
        foreach ($fd in Get-FunctionDefinition -Files $script:AllFiles) {
            $b = $builtFns | Where-Object { $_.Name -eq $fd.Name } | Select-Object -First 1
            if (-not $b) { $diff += "$($fd.Name) (missing)"; continue }
            if ((Get-NormalizedCode -Text $fd.Ast.Extent.Text) -cne (Get-NormalizedCode -Text $b.Ast.Extent.Text)) { $diff += $fd.Name }
        }
        Assert-Equal ($diff -join ',') '' 'functions changed by bundling'
    }
    Test-Case 'Bundled script -ListTasks matches the modular script' {
        $a = & $script:HostExe -NoProfile -File $script:MainScript -ListTasks | Out-String
        $b = & $script:HostExe -NoProfile -File $script:Built -ListTasks | Out-String
        Assert-True ($a -ceq $b) '-ListTasks output differs'
    }
    Test-Case 'Bundled launcher downloads the bundled script' {
        $l = Get-Content -LiteralPath (Join-Path $script:BuildDir 'build\launcher.ps1') -Raw
        Assert-Match $l ([regex]::Escape((Split-Path $script:Built -Leaf))) 'launcher URL'
        Assert-Equal (Get-FileAst -Path (Join-Path $script:BuildDir 'build\launcher.ps1')).Errors.Count 0 'launcher parse errors'
    }
}

#endregion

#region ------------------------------------------------------------------- Live read-only probes (opt-in)

Write-TestSection 'Live read-only probes'

if ($IncludeLive) {
    Set-Item Function:\ResetConsoleScreen -Value $script:OriginalResetConsole
    foreach ($fn in 'Invoke-InventoryTask', 'Invoke-FreeSpaceTask', 'Invoke-LifecycleTask', 'Invoke-PhysicalDiskHealthTask', 'Invoke-SecurityPostureTask',
                    'Invoke-EventLogReviewTask', 'Invoke-DriverHealthTask', 'Invoke-ServiceHealthTask', 'Invoke-StartupImpactTask', 'Invoke-StorageSenseReportTask', 'Invoke-CbsLogReviewTask') {
        Test-Case "$fn returns a well-formed result against the real machine" {
            Reset-RunState -RunLevel 'Audit'; $EventLogDays = 7
            $r = & $fn
            Assert-Contains @('OK', 'Warning', 'Failed', 'Skipped', 'Repaired') $r.Status 'status'
        }
    }
} else {
    Skip-Case 'Read-only tasks against the real machine' 'pass -IncludeLive to run them'
}

#endregion

}
finally {
    Remove-Item -LiteralPath $script:DumperPath -Force -ErrorAction SilentlyContinue
    if ((Test-Path variable:script:BuildDir) -and $script:BuildDir) { Remove-Item -LiteralPath $script:BuildDir -Recurse -Force -ErrorAction SilentlyContinue }
}

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
