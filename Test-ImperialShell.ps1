<#
.SYNOPSIS
    Non-destructive test suite for setup-imperial-shell.ps1 and Freya (freya\imperial.py).

.DESCRIPTION
    Dot-sources the setup script (which only loads its functions) and exercises them against
    disposable temp folders, a throwaway HKCU registry key and a mocked winget. Nothing is
    installed, no profile outside the temp folder is touched and no elevation is requested.

    Also runs the Python unit tests (freya\test_imperial.py) and compiles imperial.py with the
    Python it can find, and checks that the installed vader / WinDragon layout still runs
    (-ListTasks, which needs no elevation).

.PARAMETER Only
    One or more wildcard patterns matching section names to run.

.EXAMPLE
    .\Test-ImperialShell.ps1

.EXAMPLE
    .\Test-ImperialShell.ps1 -Only 'Profile*','Payload*'
#>

[CmdletBinding()]
param(
    [string[]]$Only
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

#region ------------------------------------------------------------------- Test harness

$script:CheckMark      = [string][char]0x2713
$script:CrossMark      = [string][char]0x2717
$script:PassCount      = 0
$script:FailCount      = 0
$script:SkipCount      = 0
$script:FailureLog     = New-Object System.Collections.Generic.List[psobject]
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
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Reason)
    if (-not (Test-SectionSelected -Name $script:CurrentSection)) { return }
    Write-Host '  - ' -ForegroundColor DarkGray -NoNewline
    Write-Host "$Name (skipped: $Reason)" -ForegroundColor DarkGray
    $script:SkipCount++
}

function Assert-True {
    param([bool]$Condition, [string]$Message = 'Expected condition to be true')
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -ne $Actual) {
        $detail = "Expected [$Expected] but got [$Actual]"
        if ($Message) { $detail = "$Message - $detail" }
        throw $detail
    }
}

function New-TempFolder {
    $path = Join-Path ([IO.Path]::GetTempPath()) ("imperial-shell-test-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

#endregion

$RepoRoot    = $PSScriptRoot
$SetupScript = Join-Path $RepoRoot 'setup-imperial-shell.ps1'
$TempRoot    = New-TempFolder

# Only loads the functions; the script returns before its main entry point when dot-sourced.
. $SetupScript

try {

#region ------------------------------------------------------------------- Static checks

Write-TestSection 'Static'

Test-Case 'setup script parses without errors' {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($SetupScript, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count ($errors | ForEach-Object Message | Out-String)
}

Test-Case 'setup script is ASCII-only (parses in Windows PowerShell 5.1 without a BOM)' {
    $bytes = [IO.File]::ReadAllBytes($SetupScript)
    $offending = @($bytes | Where-Object { $_ -gt 127 }).Count
    Assert-Equal 0 $offending 'Non-ASCII bytes found'
}

Test-Case 'setup script parses in Windows PowerShell 5.1' {
    $ps51 = Get-Command powershell.exe -CommandType Application -ErrorAction SilentlyContinue
    if (-not $ps51) { throw 'powershell.exe not found' }
    $check = "`$t=`$null;`$e=`$null;[void][Management.Automation.Language.Parser]::ParseFile('$SetupScript',[ref]`$t,[ref]`$e);`$e.Count"
    $count = & $ps51.Source -NoProfile -NonInteractive -Command $check
    Assert-Equal '0' ([string]$count).Trim()
}

Test-Case 'no Invoke-Expression and no -File relaunch (arrays / trailing \ break it)' {
    $source = Get-Content -LiteralPath $SetupScript -Raw
    Assert-True ($source -notmatch 'Invoke-Expression|\biex\b') 'Invoke-Expression found'
    Assert-True ($source -notmatch '-File\s+`?"\$PSCommandPath') 'Relaunch still uses -File'
}

Test-Case 'dot-sourcing loads functions without running setup' {
    foreach ($name in 'Invoke-ImperialSetup', 'Install-WingetPackage', 'Set-ProfileBlock', 'Copy-ImperialPayload') {
        Assert-True ([bool](Get-Command $name -CommandType Function -ErrorAction SilentlyContinue)) "$name not loaded"
    }
    Assert-True ($null -eq $script:LogFile) 'Setup started logging while dot-sourced'
}

$analyzer = Get-Module -ListAvailable PSScriptAnalyzer | Select-Object -First 1
if ($analyzer) {
    Test-Case 'PSScriptAnalyzer reports no errors or warnings' {
        # Write-Host is the installer UI; the Write-Log finding comes from a stale PowerShell 6.1 profile.
        $excluded = 'PSAvoidUsingWriteHost', 'PSUseShouldProcessForStateChangingFunctions', 'PSAvoidOverwritingBuiltInCmdlets'
        $findings = @(Invoke-ScriptAnalyzer -Path $SetupScript -Severity Error, Warning -ExcludeRule $excluded)
        Assert-Equal 0 $findings.Count (($findings | ForEach-Object { "$($_.RuleName) line $($_.Line)" }) -join '; ')
    }
}
else {
    Skip-Case 'PSScriptAnalyzer reports no errors or warnings' 'PSScriptAnalyzer module not installed'
}

#endregion

#region ------------------------------------------------------------------- Elevation relaunch

Write-TestSection 'Relaunch'

Test-Case 'relaunch arguments use -EncodedCommand with -NoProfile' {
    $relaunchArgs = New-RelaunchArgumentList -ScriptPath 'C:\x\setup.ps1' -InstallPath 'C:\y'
    Assert-Equal '-NoProfile' $relaunchArgs[0]
    Assert-Equal '-EncodedCommand' $relaunchArgs[3]
    $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($relaunchArgs[4]))
    Assert-Equal "& 'C:\x\setup.ps1' -InstallPath 'C:\y' -Relaunched; exit `$LASTEXITCODE" $decoded
}

Test-Case 'relaunch round-trips awkward paths and the exit code through a real pwsh' {
    $dir = Join-Path $TempRoot "it's a dir"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $probe = Join-Path $dir 'probe.ps1'
    Set-Content -LiteralPath $probe -Value 'param([string]$InstallPath, [switch]$Relaunched) "$InstallPath|$Relaunched"; exit 7'
    $install = "C:\Some Folder\O'Brien\"
    $relaunchArgs = New-RelaunchArgumentList -ScriptPath $probe -InstallPath $install
    $output = & (Get-PwshPath) @relaunchArgs
    Assert-Equal 7 $LASTEXITCODE 'exit code'
    Assert-Equal "$install|True" ([string]$output)
}

Test-Case 'Get-PwshPath finds PowerShell 7' {
    $path = Get-PwshPath
    Assert-True ($path -and (Test-Path -LiteralPath $path)) "pwsh not found: $path"
}

#endregion

#region ------------------------------------------------------------------- PATH and winget

Write-TestSection 'Winget'

Test-Case 'Update-SessionPath merges without dropping or duplicating entries' {
    $saved = $env:Path
    try {
        $env:Path = 'C:\session-only;C:\shared'
        Update-SessionPath -MachinePath 'C:\shared;C:\machine' -UserPath 'C:\user;;C:\SHARED'
        Assert-Equal 'C:\session-only;C:\shared;C:\machine;C:\user' $env:Path
    }
    finally { $env:Path = $saved }
}

Test-Case 'winget no-op exit codes count as success' {
    Assert-True (Test-WingetSuccess -ExitCode 0)
    Assert-True (Test-WingetSuccess -ExitCode 0x8A15002B)
    Assert-True (Test-WingetSuccess -ExitCode 0x8A150061)
    Assert-True (-not (Test-WingetSuccess -ExitCode 1))
    Assert-True (-not (Test-WingetSuccess -ExitCode 0x8A150014))
}

$script:WingetCalls = New-Object System.Collections.Generic.List[string]
$script:WingetListExit = 0
$script:WingetActionExit = 0
function winget {
    $script:WingetCalls.Add(($args -join ' '))
    $global:LASTEXITCODE = if ($args[0] -eq 'list') { $script:WingetListExit } else { $script:WingetActionExit }
}
function Update-SessionPath { }

Test-Case 'installed package is upgraded, not reinstalled' {
    $script:WingetCalls.Clear(); $script:WingetListExit = 0; $script:WingetActionExit = 0x8A15002B
    $result = Install-WingetPackage -Id 'Ollama.Ollama' -Name 'Ollama' 6>$null
    Assert-Equal $true $result
    Assert-Equal 2 $script:WingetCalls.Count
    Assert-True ($script:WingetCalls[1] -like 'upgrade --id Ollama.Ollama --exact --source winget*--silent*') $script:WingetCalls[1]
}

Test-Case 'missing package is installed' {
    $script:WingetCalls.Clear(); $script:WingetListExit = 0x8A150014; $script:WingetActionExit = 0
    $result = Install-WingetPackage -Id 'Python.Python.3.12' -Name 'Python' 6>$null
    Assert-Equal $true $result
    Assert-True ($script:WingetCalls[1] -like 'install --id Python.Python.3.12 --exact*--accept-package-agreements*') $script:WingetCalls[1]
}

Test-Case 'failed install returns $false and is logged' {
    $script:WingetCalls.Clear(); $script:WingetListExit = 0x8A150014; $script:WingetActionExit = 1603
    $script:ErrorLogFile = Join-Path $TempRoot 'winget-errors.txt'
    try {
        $result = Install-WingetPackage -Id 'Bad.Package' -Name 'Bad' 6>$null
        Assert-Equal $false $result
        Assert-True ((Get-Content -LiteralPath $script:ErrorLogFile -Raw) -match 'install Bad.Package failed with exit code 1603')
    }
    finally { $script:ErrorLogFile = $null }
}

Remove-Item Function:\winget, Function:\Update-SessionPath
. $SetupScript

#endregion

#region ------------------------------------------------------------------- sudo

Write-TestSection 'Sudo'

$testKey = 'HKCU:\Software\ImperialShellTest-' + [guid]::NewGuid().ToString('N')
Test-Case 'Get-SudoState reads the mode and sudo.exe presence' {
    try {
        $fakeSudo = Join-Path $TempRoot 'sudo.exe'
        Set-Content -LiteralPath $fakeSudo -Value ''
        $missing = Get-SudoState -SudoPath (Join-Path $TempRoot 'nope.exe') -RegistryPath $testKey
        Assert-Equal $false $missing.Available
        Assert-Equal 0 $missing.Mode
        New-Item -Path $testKey -Force | Out-Null
        New-ItemProperty -Path $testKey -Name Enabled -Value 3 -PropertyType DWord | Out-Null
        $inline = Get-SudoState -SudoPath $fakeSudo -RegistryPath $testKey
        Assert-Equal $true $inline.Available
        Assert-Equal 3 $inline.Mode
    }
    finally { Remove-Item -Path $testKey -Recurse -Force -ErrorAction SilentlyContinue }
}

Test-Case 'Get-SudoState works against the real system (read-only)' {
    $state = Get-SudoState
    Assert-True ($state.Mode -in 0, 1, 2, 3) "Unexpected mode $($state.Mode)"
    Assert-True ($state.Available -is [bool])
}

#endregion

#region ------------------------------------------------------------------- Python discovery

Write-TestSection 'Python'

Test-Case 'Get-PythonVersion rejects missing and non-Python paths' {
    Assert-True ($null -eq (Get-PythonVersion -Path (Join-Path $TempRoot 'missing.exe')))
    Assert-True ($null -eq (Get-PythonVersion -Path (Join-Path $env:SystemRoot 'System32\whoami.exe')))
}

$anyPython = Get-Command python -CommandType Application -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1
if ($anyPython) {
    Test-Case 'Get-PythonVersion reads a real interpreter' {
        Assert-True ((Get-PythonVersion -Path $anyPython.Source) -match '^3\.\d+$')
    }
}
else {
    Skip-Case 'Get-PythonVersion reads a real interpreter' 'no Python on PATH'
}

Test-Case 'Find-Python only returns a matching version' {
    $found = Find-Python
    if ($found) { Assert-Equal $script:PythonVersion (Get-PythonVersion -Path $found) }
    Assert-True ($null -eq (Find-Python -Version '2.1')) 'Found a Python 2.1'
}

#endregion

#region ------------------------------------------------------------------- Profile

Write-TestSection 'Profile'

Test-Case 'profile block defines deathstar with quoted paths' {
    $block = Get-ProfileBlock -InstallPath "C:\Users\O'Neil\.imperial-shell"
    Assert-True ($block.StartsWith($script:ProfileStart)) 'Missing start marker'
    Assert-True ($block.TrimEnd().EndsWith($script:ProfileEnd)) 'Missing end marker'
    Assert-True ($block.Contains("& 'C:\Users\O''Neil\.imperial-shell\venv\Scripts\python.exe' 'C:\Users\O''Neil\.imperial-shell\imperial.py' @args")) $block
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($block, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count
}

Test-Case 'profile block is appended once, updated in place and keeps other content' {
    $profilePath = Join-Path $TempRoot 'profile\new\profile.ps1'
    Set-ProfileBlock -ProfilePath $profilePath -Block (Get-ProfileBlock -InstallPath 'C:\one')
    $first = [IO.File]::ReadAllText($profilePath)
    Assert-True ($first.Contains("'C:\one\imperial.py'"))

    Add-Content -LiteralPath $profilePath -Value 'Set-Alias ll Get-ChildItem'
    Set-ProfileBlock -ProfilePath $profilePath -Block (Get-ProfileBlock -InstallPath 'C:\two')
    Set-ProfileBlock -ProfilePath $profilePath -Block (Get-ProfileBlock -InstallPath 'C:\two')
    $content = [IO.File]::ReadAllText($profilePath)
    Assert-Equal 1 ([regex]::Matches($content, [regex]::Escape($script:ProfileStart))).Count 'marker count'
    Assert-True (-not $content.Contains('C:\one')) 'Old path left behind'
    Assert-True ($content.Contains("'C:\two\imperial.py'")) 'New path missing'
    Assert-True ($content.Contains('Set-Alias ll Get-ChildItem')) 'User content lost'
}

Test-Case 'legacy unmarked deathstar block is migrated' {
    $profilePath = Join-Path $TempRoot 'profile\legacy\profile.ps1'
    New-Item -ItemType Directory -Force -Path (Split-Path $profilePath) | Out-Null
    $legacy = @(
        'Import-Module posh-git'
        ''
        '# Imperial-Shell - Freya Protocol Voice AI Assistant'
        'function deathstar {'
        '    & "C:\old\venv\Scripts\python.exe" "C:\old\imperial.py"'
        '}'
        ''
        'Set-Location C:\code'
    ) -join "`r`n"
    [IO.File]::WriteAllText($profilePath, $legacy)
    Set-ProfileBlock -ProfilePath $profilePath -Block (Get-ProfileBlock -InstallPath 'C:\new')
    $content = [IO.File]::ReadAllText($profilePath)
    Assert-Equal 1 ([regex]::Matches($content, 'function deathstar')).Count 'deathstar definitions'
    Assert-True (-not $content.Contains('C:\old')) 'Legacy block left behind'
    Assert-True ($content.Contains('Import-Module posh-git') -and $content.Contains('Set-Location C:\code')) 'User content lost'
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count
}

#endregion

#region ------------------------------------------------------------------- Payload

Write-TestSection 'Payload'

$installRoot = Join-Path $TempRoot 'install'
Test-Case 'payload copies Freya, audio and both protocols' {
    New-Item -ItemType Directory -Force -Path (Join-Path $installRoot 'windragon') | Out-Null
    Set-Content -LiteralPath (Join-Path $installRoot 'windragon\stale.ps1') -Value 'old'
    Copy-ImperialPayload -SourceRoot $RepoRoot -Destination $installRoot 6>$null
    foreach ($relative in 'imperial.py', 'requirements.txt', 'imperial_march.mp3', 'order66.mp3',
        'vader\Invoke-ImperialMaintenance.ps1', 'windragon\winDragon.ps1', 'windragon\launcher.ps1',
        'windragon\Modules\Core.ps1', 'windragon\Modules\Interface.ps1') {
        Assert-True (Test-Path -LiteralPath (Join-Path $installRoot $relative)) "$relative missing"
    }
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $installRoot 'windragon\stale.ps1'))) 'Stale file survived'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $installRoot 'windragon\Test-WinDragon.ps1'))) 'Test suite was installed'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $installRoot 'windragon\build'))) 'Build output was installed'
    $sourceModules = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'windragon\Modules') -File).Count
    Assert-Equal $sourceModules @(Get-ChildItem -LiteralPath (Join-Path $installRoot 'windragon\Modules') -File).Count 'module count'
}

Test-Case 'payload refuses to install over the repository' {
    $threw = $false
    try { Copy-ImperialPayload -SourceRoot $RepoRoot -Destination "$RepoRoot\" 6>$null } catch { $threw = $_.Exception.Message -like '*must not be the repository*' }
    Assert-True $threw
}

Test-Case 'payload reports missing source files' {
    $threw = $false
    try { Copy-ImperialPayload -SourceRoot (New-TempFolder) -Destination (Join-Path $TempRoot 'x') 6>$null } catch { $threw = $_.Exception.Message -like '*freya\imperial.py*' }
    Assert-True $threw
}

foreach ($protocol in @(
        @{ Name = 'vader'; Script = 'vader\Invoke-ImperialMaintenance.ps1' }
        @{ Name = 'WinDragon'; Script = 'windragon\winDragon.ps1' })) {
    Test-Case "installed $($protocol.Name) runs from the install layout (-ListTasks)" {
        $protocolScript = Join-Path $installRoot $protocol.Script
        $output = & (Get-PwshPath) -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $protocolScript -ListTasks 2>&1 | Out-String
        Assert-Equal 0 $LASTEXITCODE "exit code; output: $output"
        Assert-True ($output -match 'DISM') 'Task catalogue not printed'
    }
}

#endregion

#region ------------------------------------------------------------------- Freya (Python)

Write-TestSection 'Freya'

$testPython = if ($anyPython) { $anyPython.Source } else { $null }
if ($testPython) {
    Test-Case 'Freya unit tests pass (freya\test_imperial.py)' {
        $output = & $testPython -W error::ResourceWarning -m unittest discover -s (Join-Path $RepoRoot 'freya') -p 'test_*.py' 2>&1 | Out-String
        Assert-Equal 0 $LASTEXITCODE $output
    }
}
else {
    Skip-Case 'Freya unit tests pass (freya\test_imperial.py)' 'no Python on PATH'
}

$py312 = Find-Python
$pyCompile = if ($py312) { $py312 } else { $testPython }
if ($pyCompile) {
    Test-Case "imperial.py compiles with Python $(Get-PythonVersion -Path $pyCompile)" {
        $target = Join-Path $RepoRoot 'freya\imperial.py'
        $output = & $pyCompile -c "import ast, sys; ast.parse(open(sys.argv[1], encoding='utf-8').read())" $target 2>&1 | Out-String
        Assert-Equal 0 $LASTEXITCODE $output
    }
}

Test-Case 'requirements pin open-interpreter and keep pkg_resources available' {
    $requirements = Get-Content -LiteralPath (Join-Path $RepoRoot 'freya\requirements.txt')
    Assert-True (@($requirements -match '^open-interpreter').Count -eq 1)
    Assert-True (@($requirements -match '^setuptools<81').Count -eq 1)
}

#endregion

}
finally {
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ('=' * 80) -ForegroundColor Cyan
$summaryColor = if ($script:FailCount -gt 0) { 'Red' } else { 'Green' }
Write-Host ("Passed: {0}   Failed: {1}   Skipped: {2}" -f $script:PassCount, $script:FailCount, $script:SkipCount) -ForegroundColor $summaryColor
foreach ($failure in $script:FailureLog) {
    Write-Host "  [$($failure.Section)] $($failure.Test): $($failure.Reason)" -ForegroundColor Red
}
exit ([int]($script:FailCount -gt 0))
