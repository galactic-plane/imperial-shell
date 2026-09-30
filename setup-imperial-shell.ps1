<#
.SYNOPSIS
    Installs Imperial Shell: the Freya AI maintenance assistant plus the vader and WinDragon
    maintenance protocols.

.DESCRIPTION
    Idempotent - re-running upgrades every component in place and refreshes the installed files.

      1. Enables Windows sudo in inline mode (Windows 11 24H2+), so Freya can capture elevated output.
      2. Installs/upgrades Python 3.12, Ollama and fastfetch with winget.
      3. Starts the Ollama service and pulls the phi4:14b model (~9 GB).
      4. Copies Freya (freya\imperial.py), the audio files and the vader / WinDragon protocols
         into the install folder.
      5. Creates a Python 3.12 virtual environment and installs freya\requirements.txt.
      6. Adds a managed 'deathstar' function to the PowerShell 7 profile.

    Needs Administrator rights and PowerShell 7; when either is missing the script relaunches
    itself elevated in pwsh. Logs go to <InstallPath>\setup-log.txt and setup-errors.txt.

.PARAMETER InstallPath
    Installation folder. Default: %USERPROFILE%\.imperial-shell

.PARAMETER Relaunched
    Internal. Set on the elevated relaunch so the window waits before closing.

.EXAMPLE
    .\setup-imperial-shell.ps1
#>

[CmdletBinding()]
param(
    [string]$InstallPath = (Join-Path $env:USERPROFILE '.imperial-shell'),

    [switch]$Relaunched
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ---------------------------------------------------------------- Constants

$script:ModelName        = 'phi4:14b'
# open-interpreter pins tiktoken 0.7, which has no prebuilt wheels beyond Python 3.12.
$script:PythonVersion    = '3.12'
$script:OllamaUrl        = 'http://localhost:11434'
$script:SudoRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo'
$script:ProfileStart     = '# >>> imperial-shell >>>'
$script:ProfileEnd       = '# <<< imperial-shell <<<'
# winget exit codes that mean "nothing to do" rather than failure.
$script:WingetNoOpCodes  = @(
    -1978335189  # 0x8A15002B UPDATE_NOT_APPLICABLE
    -1978335135  # 0x8A150061 PACKAGE_ALREADY_INSTALLED
)
$script:LogFile      = $null
$script:ErrorLogFile = $null

# Source stays ASCII-only so Windows PowerShell 5.1 can parse it without a BOM.
$script:Rule  = ([string][char]0x2550) * 47
$script:Tick  = [string][char]0x2713
$script:Alert = [string][char]0x26A0

#endregion

#region ---------------------------------------------------------------- Output helpers

function Write-Log {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Color
    if ($script:LogFile) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" | Out-File -FilePath $script:LogFile -Append -Encoding utf8
    }
}

function Write-ErrorLog {
    param([Parameter(Mandatory)][string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: $Message"
    foreach ($file in @($script:ErrorLogFile, $script:LogFile)) {
        if ($file) { $line | Out-File -FilePath $file -Append -Encoding utf8 }
    }
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Log "[*] $Message" Green
}

function Write-Banner {
    param([Parameter(Mandatory)][string[]]$Lines, [ConsoleColor]$Color = 'White')
    Write-Host $script:Rule -ForegroundColor Red
    foreach ($line in $Lines) { Write-Host "  $line" -ForegroundColor $Color }
    Write-Host $script:Rule -ForegroundColor Red
    Write-Host ''
}

#endregion

#region ---------------------------------------------------------------- Elevation

function Test-IsAdmin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PwshPath {
    $cmd = Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    $default = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
    if (Test-Path -LiteralPath $default) { return $default }
    return $null
}

function ConvertTo-SingleQuoted {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    return "'" + ($Value -replace "'", "''") + "'"
}

function New-RelaunchArgumentList {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$InstallPath
    )
    # -EncodedCommand survives paths with spaces, quotes or a trailing backslash; -File does not.
    $command = "& $(ConvertTo-SingleQuoted $ScriptPath) -InstallPath $(ConvertTo-SingleQuoted $InstallPath) -Relaunched; exit `$LASTEXITCODE"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    return @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
}

#endregion

#region ---------------------------------------------------------------- Environment and winget

function Update-SessionPath {
    param(
        [string]$MachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine'),
        [string]$UserPath    = [Environment]::GetEnvironmentVariable('Path', 'User')
    )
    # Merge rather than overwrite, so entries added earlier in this session survive.
    $entries = New-Object System.Collections.Generic.List[string]
    foreach ($entry in ((@($env:Path, $MachinePath, $UserPath) -join ';') -split ';')) {
        $trimmed = $entry.Trim()
        if ($trimmed -and -not ($entries -contains $trimmed)) { $entries.Add($trimmed) }
    }
    $env:Path = $entries -join ';'
}

function Test-WingetSuccess {
    param([Parameter(Mandatory)][int]$ExitCode)
    return ($ExitCode -eq 0) -or ($script:WingetNoOpCodes -contains $ExitCode)
}

function Install-WingetPackage {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name
    )
    $common = @('--id', $Id, '--exact', '--source', 'winget', '--accept-source-agreements', '--disable-interactivity')
    & winget list @common *> $null
    $installed = ($LASTEXITCODE -eq 0)
    if ($installed) {
        Write-Log "    $Name found, checking for updates..." Gray
        & winget upgrade @common --silent --accept-package-agreements | Out-Host
        $action = 'upgrade'
    }
    else {
        Write-Log "    Installing $Name..." Gray
        & winget install @common --silent --accept-package-agreements | Out-Host
        $action = 'install'
    }
    $code = $LASTEXITCODE
    Update-SessionPath
    if (Test-WingetSuccess -ExitCode $code) {
        Write-Log "    $script:Tick $Name ready" Gray
        return $true
    }
    Write-ErrorLog "winget $action $Id failed with exit code $code"
    Write-Log "    $script:Alert $Name $action failed (winget exit code $code)" Yellow
    return $false
}

#endregion

#region ---------------------------------------------------------------- sudo

function Get-SudoState {
    param(
        [string]$SudoPath     = (Join-Path $env:SystemRoot 'System32\sudo.exe'),
        [string]$RegistryPath = $script:SudoRegistryPath
    )
    $mode = 0
    $value = Get-ItemProperty -LiteralPath $RegistryPath -Name Enabled -ErrorAction SilentlyContinue
    if ($value) { $mode = [int]$value.Enabled }
    return [pscustomobject]@{
        Available = (Test-Path -LiteralPath $SudoPath)
        Path      = $SudoPath
        # 0 disabled, 1 new window, 2 input disabled, 3 inline
        Mode      = $mode
    }
}

function Enable-Sudo {
    $state = Get-SudoState
    if (-not $state.Available) {
        Write-Log "    $script:Alert sudo is not available on build $([Environment]::OSVersion.Version.Build); it ships with Windows 11 24H2 (build 26100) and later." Yellow
        Write-Log '    Freya will run admin commands only when started from an elevated terminal.' Gray
        return $false
    }
    if ($state.Mode -eq 3) {
        Write-Log "    $script:Tick sudo already enabled (inline mode)" Gray
        return $true
    }
    # Freya captures command output, which only works in inline mode (not "new window").
    Write-Log '    Switching sudo to inline mode so Freya can capture elevated command output...' Gray
    & $state.Path config --enable normal *> $null
    if ((Get-SudoState).Mode -ne 3) {
        try {
            if (-not (Test-Path -LiteralPath $script:SudoRegistryPath)) { New-Item -Path $script:SudoRegistryPath -Force | Out-Null }
            Set-ItemProperty -LiteralPath $script:SudoRegistryPath -Name Enabled -Value 3 -Type DWord
        }
        catch {
            Write-ErrorLog "Failed to enable sudo: $($_.Exception.Message)"
        }
    }
    if ((Get-SudoState).Mode -eq 3) {
        Write-Log "    $script:Tick sudo enabled (inline mode)" Gray
        return $true
    }
    Write-Log "    $script:Alert Could not enable sudo. Enable it in Settings > System > Advanced > Enable sudo (Inline)." Yellow
    return $false
}

#endregion

#region ---------------------------------------------------------------- Python

function Get-PythonVersion {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    # The WindowsApps python.exe alias exits non-zero here, so it is never mistaken for a real install.
    $version = & $Path -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $version) { return $null }
    return ([string]($version | Select-Object -First 1)).Trim()
}

function Find-Python {
    param([string]$Version = $script:PythonVersion)
    $candidates = New-Object System.Collections.Generic.List[string]
    if (Get-Command py -CommandType Application -ErrorAction SilentlyContinue) {
        $exe = & py "-$Version" -c 'import sys; print(sys.executable)' 2>$null
        if ($LASTEXITCODE -eq 0 -and $exe) { $candidates.Add(([string]($exe | Select-Object -First 1)).Trim()) }
    }
    $folder = 'Python' + ($Version -replace '\.', '')
    $candidates.Add((Join-Path $env:LOCALAPPDATA "Programs\Python\$folder\python.exe"))
    $candidates.Add((Join-Path $env:ProgramFiles "$folder\python.exe"))
    foreach ($candidate in $candidates) {
        if ((Get-PythonVersion -Path $candidate) -eq $Version) { return $candidate }
    }
    return $null
}

function Initialize-Venv {
    param(
        [Parameter(Mandatory)][string]$PythonExe,
        [Parameter(Mandatory)][string]$VenvPath
    )
    $venvPython = Join-Path $VenvPath 'Scripts\python.exe'
    if (Test-Path -LiteralPath $VenvPath) {
        $current = Get-PythonVersion -Path $venvPython
        if ($current -eq $script:PythonVersion) {
            & $venvPython -m pip --version *> $null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "    $script:Tick Virtual environment ready (Python $current)" Gray
                return $venvPython
            }
        }
        $found = if ($current) { $current } else { 'unusable' }
        Write-Log "    Virtual environment is $found, not a healthy Python $script:PythonVersion - recreating..." Yellow
        Remove-Item -LiteralPath $VenvPath -Recurse -Force
    }
    & $PythonExe -m venv $VenvPath | Out-Host
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython)) {
        throw "Failed to create the virtual environment at $VenvPath"
    }
    Write-Log "    $script:Tick Virtual environment created (Python $script:PythonVersion)" Gray
    return $venvPython
}

function Install-PythonDependency {
    param(
        [Parameter(Mandatory)][string]$VenvPython,
        [Parameter(Mandatory)][string]$RequirementsFile
    )
    # pip.exe cannot replace itself on Windows; 'python -m pip' can.
    Write-Log '    Upgrading pip and wheel...' Gray
    & $VenvPython -m pip install --upgrade --quiet --disable-pip-version-check pip wheel | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "pip self-upgrade failed (exit code $LASTEXITCODE)" }

    Write-Log '    Installing/upgrading Freya dependencies (open-interpreter, edge-tts, pygame, ...)...' Gray
    & $VenvPython -m pip install --upgrade --disable-pip-version-check -r $RequirementsFile | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Python dependency installation failed (pip exit code $LASTEXITCODE)" }

    Write-Log '    Installing/upgrading PyAudio (optional, for microphone input)...' Gray
    & $VenvPython -m pip install --upgrade --quiet --disable-pip-version-check pyaudio | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorLog "PyAudio installation failed (pip exit code $LASTEXITCODE)"
        Write-Log "    $script:Alert PyAudio failed to install - voice questions are unavailable, typed input still works" Yellow
    }
    Write-Log "    $script:Tick Python packages up to date" Gray
}

#endregion

#region ---------------------------------------------------------------- Ollama

function Test-OllamaApi {
    try {
        Invoke-RestMethod -Uri "$script:OllamaUrl/api/tags" -TimeoutSec 3 | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Start-OllamaService {
    if (Test-OllamaApi) {
        Write-Log "    $script:Tick Ollama service already running" Gray
        return $true
    }
    try {
        Start-Process -FilePath 'ollama' -ArgumentList 'serve' -WindowStyle Hidden
    }
    catch {
        Write-ErrorLog "Could not start 'ollama serve': $($_.Exception.Message)"
    }
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        if (Test-OllamaApi) {
            Write-Log "    $script:Tick Ollama service started" Gray
            return $true
        }
    }
    Write-Log "    $script:Alert Ollama did not respond on $script:OllamaUrl. Run 'ollama serve' in another terminal." Yellow
    return $false
}

function Install-OllamaModel {
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        & ollama pull $script:ModelName | Out-Host
        if ($LASTEXITCODE -eq 0) {
            Write-Log "    $script:Tick Model $script:ModelName is up to date" Gray
            return $true
        }
        if ($attempt -lt 3) {
            Write-Log "    Model pull failed (attempt $attempt of 3), retrying..." Yellow
            Start-Sleep -Seconds 5
        }
    }
    Write-ErrorLog "ollama pull $script:ModelName failed after 3 attempts"
    Write-Log "    $script:Alert Failed to pull $script:ModelName. Check your connection, then run 'ollama pull $script:ModelName'." Yellow
    return $false
}

#endregion

#region ---------------------------------------------------------------- Payload and profile

function Copy-ImperialPayload {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$Destination
    )
    $required = @(
        @{ From = 'freya\imperial.py';                    To = 'imperial.py' }
        @{ From = 'freya\requirements.txt';               To = 'requirements.txt' }
        @{ From = 'vader\Invoke-ImperialMaintenance.ps1'; To = 'vader\Invoke-ImperialMaintenance.ps1' }
        @{ From = 'windragon\winDragon.ps1';              To = 'windragon\winDragon.ps1' }
        @{ From = 'windragon\launcher.ps1';               To = 'windragon\launcher.ps1' }
        @{ From = 'windragon\Modules';                    To = 'windragon\Modules' }
    )
    $optional = @(
        @{ File = 'imperial_march.mp3'; Feature = 'Login music' }
        @{ File = 'order66.mp3';        Feature = 'The Order 66 lockout sound' }
    )

    $sourceFull = [IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
    $destFull   = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    if ($sourceFull -eq $destFull) { throw "InstallPath must not be the repository folder ($sourceFull)." }

    $missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $SourceRoot $_.From)) } | ForEach-Object { $_.From })
    if ($missing.Count -gt 0) {
        throw "Setup files missing from ${SourceRoot}: $($missing -join ', '). Run setup from a full copy of the repository."
    }

    # Setup owns the protocol folders; clear them so files removed upstream don't linger.
    foreach ($dir in 'vader', 'windragon') {
        $target = Join-Path $Destination $dir
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
    }
    foreach ($item in $required) {
        $target = Join-Path $Destination $item.To
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -LiteralPath (Join-Path $SourceRoot $item.From) -Destination $target -Recurse -Force
        Write-Log "    $script:Tick $($item.To)" Gray
    }
    foreach ($item in $optional) {
        $source = Join-Path $SourceRoot $item.File
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $Destination $item.File) -Force
            Write-Log "    $script:Tick $($item.File)" Gray
        }
        else {
            Write-Log "    $script:Alert $($item.File) not found - $($item.Feature) will be unavailable" Yellow
        }
    }

    # Drop the downloaded-from-internet mark so the protocols run under RemoteSigned too.
    $scripts = @(Get-ChildItem -LiteralPath (Join-Path $Destination 'vader'), (Join-Path $Destination 'windragon') -Recurse -File)
    $scripts += Get-Item -LiteralPath (Join-Path $Destination 'imperial.py')
    $scripts | Unblock-File
}

function Get-ProfileBlock {
    param([Parameter(Mandatory)][string]$InstallPath)
    $python = ConvertTo-SingleQuoted (Join-Path $InstallPath 'venv\Scripts\python.exe')
    $app    = ConvertTo-SingleQuoted (Join-Path $InstallPath 'imperial.py')
    return @(
        $script:ProfileStart
        '# Imperial-Shell - Freya Protocol AI assistant (managed by setup-imperial-shell.ps1)'
        'function deathstar {'
        "    & $python $app @args"
        '}'
        $script:ProfileEnd
    ) -join [Environment]::NewLine
}

function Set-ProfileBlock {
    param(
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][string]$Block
    )
    $dir = Split-Path -Parent $ProfilePath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $content = ''
    if (Test-Path -LiteralPath $ProfilePath) { $content = [IO.File]::ReadAllText($ProfilePath) }

    # Unmarked block written by earlier versions of this script.
    $legacy = '(?ms)^[ \t]*# Imperial-Shell - Freya Protocol Voice AI Assistant\r?\nfunction deathstar \{.*?^\}[ \t]*(\r?\n)?'
    $content = [regex]::Replace($content, $legacy, '')

    $managed = [regex]::new('(?s)' + [regex]::Escape($script:ProfileStart) + '.*?' + [regex]::Escape($script:ProfileEnd))
    $match = $managed.Match($content)
    if ($match.Success) {
        $content = $content.Substring(0, $match.Index) + $Block + $content.Substring($match.Index + $match.Length)
    }
    else {
        $content = $content.TrimEnd()
        if ($content) { $content += [Environment]::NewLine + [Environment]::NewLine }
        $content += $Block + [Environment]::NewLine
    }
    [IO.File]::WriteAllText($ProfilePath, $content, (New-Object System.Text.UTF8Encoding($true)))
}

#endregion

#region ---------------------------------------------------------------- Main

function Invoke-ImperialSetup {
    param(
        [Parameter(Mandatory)][string]$InstallPath,
        [Parameter(Mandatory)][string]$SourceRoot
    )
    New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
    $script:LogFile      = Join-Path $InstallPath 'setup-log.txt'
    $script:ErrorLogFile = Join-Path $InstallPath 'setup-errors.txt'
    Remove-Item -LiteralPath $script:LogFile, $script:ErrorLogFile -ErrorAction SilentlyContinue

    Write-Banner -Lines @(
        'IMPERIAL SHELL INITIALIZATION SEQUENCE'
        "The Empire's command system is coming online..."
        '[Running with Administrator privileges]'
    )
    Write-Log "Starting Imperial Shell setup (PowerShell $($PSVersionTable.PSVersion), Windows build $([Environment]::OSVersion.Version.Build))" Green
    Write-Log "Install path: $InstallPath" Gray
    Write-Log "Log file: $script:LogFile" Gray

    Write-Step 'Checking winget...'
    if (-not (Get-Command winget -CommandType Application -ErrorAction SilentlyContinue)) {
        throw 'winget was not found. Install "App Installer" from the Microsoft Store, then re-run setup.'
    }
    Write-Log "    $script:Tick winget available" Gray

    Write-Step 'Checking sudo configuration...'
    $null = Enable-Sudo

    Write-Step "Checking Python $script:PythonVersion..."
    $null = Install-WingetPackage -Id "Python.Python.$script:PythonVersion" -Name "Python $script:PythonVersion"
    $python = Find-Python
    if (-not $python) {
        throw "Python $script:PythonVersion was not found after installation. Install it from https://www.python.org and re-run setup."
    }
    Write-Log "    Using: $python" Gray

    Write-Step 'Checking Ollama...'
    $null = Install-WingetPackage -Id 'Ollama.Ollama' -Name 'Ollama'
    if (-not (Get-Command ollama -CommandType Application -ErrorAction SilentlyContinue)) {
        throw 'Ollama is not on PATH after installation. Install it from https://ollama.com and re-run setup.'
    }

    Write-Step 'Checking fastfetch (used by the System and Hardware menus)...'
    $null = Install-WingetPackage -Id 'Fastfetch-cli.Fastfetch' -Name 'fastfetch'

    Write-Step 'Starting Ollama service...'
    if (Start-OllamaService) {
        Write-Step "Checking AI model ($script:ModelName, ~9 GB on first download)..."
        $null = Install-OllamaModel
    }
    else {
        Write-Log "    Skipping model download; run 'ollama pull $script:ModelName' once Ollama is running." Yellow
    }

    Write-Step 'Installing Freya and the maintenance protocols...'
    Copy-ImperialPayload -SourceRoot $SourceRoot -Destination $InstallPath

    Write-Step 'Setting up Python virtual environment...'
    $venvPython = Initialize-Venv -PythonExe $python -VenvPath (Join-Path $InstallPath 'venv')

    Write-Step 'Checking Python dependencies...'
    Install-PythonDependency -VenvPython $venvPython -RequirementsFile (Join-Path $InstallPath 'requirements.txt')

    Write-Step "Adding the 'deathstar' command to your PowerShell profile..."
    $profilePath = $PROFILE.CurrentUserAllHosts
    Set-ProfileBlock -ProfilePath $profilePath -Block (Get-ProfileBlock -InstallPath $InstallPath)
    Write-Log "    $script:Tick $profilePath" Gray

    Write-Host ''
    Write-Banner -Color Green -Lines @("$script:Tick IMPERIAL SHELL INSTALLATION COMPLETE")
    Write-Host 'To activate Imperial Shell:' -ForegroundColor White
    Write-Host '  1. Open a new PowerShell 7 window' -ForegroundColor Cyan
    Write-Host '  2. Run: deathstar' -ForegroundColor Red
    Write-Host '  3. Main menu 16 / 17 launch the vader and WinDragon maintenance protocols' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Long live the Empire!' -ForegroundColor Red
    Write-Host ''
    Write-Log 'Setup completed successfully.' Green
    Write-Log "  - Setup log: $script:LogFile" Gray
    if (Test-Path -LiteralPath $script:ErrorLogFile) {
        Write-Log "  - Warnings/errors: $script:ErrorLogFile" Yellow
    }
}

#endregion

# Dot-sourcing (as Test-ImperialShell.ps1 does) only loads the functions above.
if ($MyInvocation.InvocationName -eq '.') { return }

if (-not (Test-IsAdmin) -or $PSVersionTable.PSVersion.Major -lt 7) {
    if ($Relaunched) {
        Write-Host 'Setup still lacks Administrator rights or PowerShell 7 after relaunching.' -ForegroundColor Red
        exit 1
    }
    Write-Banner -Color Yellow -Lines @('IMPERIAL SHELL REQUIRES ELEVATION (PowerShell 7 as Administrator)')
    $pwsh = Get-PwshPath
    if (-not $pwsh) {
        Write-Host 'PowerShell 7 is required. Install it, then re-run setup:' -ForegroundColor Red
        Write-Host '  winget install --id Microsoft.PowerShell --exact --source winget' -ForegroundColor Yellow
        exit 1
    }
    if (-not $PSCommandPath) {
        Write-Host 'Save setup-imperial-shell.ps1 to disk and run it from there.' -ForegroundColor Red
        exit 1
    }
    Write-Host 'Requesting elevation in a new PowerShell 7 window...' -ForegroundColor Cyan
    try {
        $process = Start-Process -FilePath $pwsh -ArgumentList (New-RelaunchArgumentList -ScriptPath $PSCommandPath -InstallPath $InstallPath) -Verb RunAs -PassThru -Wait
        $color = if ($process.ExitCode -eq 0) { 'Green' } else { 'Red' }
        Write-Host "Setup finished in the elevated window (exit code $($process.ExitCode))." -ForegroundColor $color
        Write-Host "Log: $(Join-Path $InstallPath 'setup-log.txt')" -ForegroundColor Gray
        exit $process.ExitCode
    }
    catch {
        Write-Host "Elevation was cancelled or failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'Right-click PowerShell 7 > Run as Administrator, then run this script again.' -ForegroundColor Yellow
        exit 1
    }
}

$exitCode = 0
try {
    Invoke-ImperialSetup -InstallPath $InstallPath -SourceRoot $PSScriptRoot
}
catch {
    $exitCode = 1
    Write-ErrorLog "$($_.Exception.Message)`n$($_.ScriptStackTrace)"
    Write-Host ''
    Write-Host "$script:Alert SETUP FAILED: $($_.Exception.Message)" -ForegroundColor Red
    if ($script:ErrorLogFile) { Write-Host "Details: $script:ErrorLogFile" -ForegroundColor Yellow }
}
if ($Relaunched) { $null = Read-Host 'Press Enter to close this window' }
exit $exitCode
