# Setup Script for Imperial-Shell - Voice AI Assistant
# Requires Administrator privileges for sudo enablement and system configuration

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "  IMPERIAL SHELL REQUIRES ELEVATION" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Host "This setup requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "Requesting elevation..." -ForegroundColor Cyan
    Write-Host ""
    
    # Re-launch as administrator using pwsh (PowerShell 7)
    try {
        $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
        if (-not $pwshPath) {
            # Fallback to common PowerShell 7 installation paths
            $pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"
            if (-not (Test-Path $pwshPath)) {
                $pwshPath = "pwsh"
            }
        }
        
        $process = Start-Process $pwshPath -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -PassThru -Wait
        exit $process.ExitCode
    } catch {
        Write-Host "Failed to elevate. Please run PowerShell 7 as Administrator and try again." -ForegroundColor Red
        Write-Host "Right-click PowerShell 7 → Run as Administrator" -ForegroundColor Yellow
        pause
        exit 1
    }
}

Write-Host "═══════════════════════════════════════════════" -ForegroundColor Red
Write-Host "  IMPERIAL SHELL INITIALIZATION SEQUENCE" -ForegroundColor White
Write-Host "  The Empire's voice-command system is online..." -ForegroundColor Red
Write-Host "  [Running with Administrator privileges]" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""

# Create installation directory first
$InstallPath = "$env:USERPROFILE\.imperial-shell"
New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null

# Setup logging
$LogFile = "$InstallPath\setup-log.txt"
$ErrorLogFile = "$InstallPath\setup-errors.txt"

# Clear old logs
if (Test-Path $LogFile) { Clear-Content $LogFile }
if (Test-Path $ErrorLogFile) { Clear-Content $ErrorLogFile }

function Write-Log {
    param($Message, $Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host $Message -ForegroundColor $Color
}

function Write-ErrorLog {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - ERROR: $Message" | Out-File -FilePath $ErrorLogFile -Append -Encoding UTF8
    "$timestamp - ERROR: $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Write-Log "Starting Imperial Shell setup..." "Green"
Write-Log "Log file: $LogFile" "Gray"

# Check and enable sudo for Windows 11
Write-Log "[*] Checking sudo configuration..." "Green"
$sudoEnabled = $false
try {
    # Check if sudo is available
    $sudoCheck = Get-Command sudo -ErrorAction SilentlyContinue
    if ($sudoCheck) {
        Write-Log "    sudo command found" "Gray"
        $sudoEnabled = $true
    } else {
        Write-Log "    sudo not found, checking Windows version..." "Yellow"
        
        # Check if running Windows 11 (build 22000+)
        $windowsVersion = [System.Environment]::OSVersion.Version
        if ($windowsVersion.Build -ge 22000) {
            Write-Log "    Windows 11 detected (Build $($windowsVersion.Build))" "Gray"
            Write-Log "    Enabling sudo for Windows..." "Yellow"
            
            # Enable sudo via registry (requires admin)
            try {
                $sudoRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo"
                if (!(Test-Path $sudoRegPath)) {
                    New-Item -Path $sudoRegPath -Force | Out-Null
                }
                # Set sudo to enabled (1 = forceNewWindow, 2 = disableInput, 3 = normal)
                Set-ItemProperty -Path $sudoRegPath -Name "Enabled" -Value 3 -Type DWord -Force
                
                # Refresh environment
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                
                Write-Log "    ✓ sudo enabled successfully" "Green"
                Write-Log "    Note: You may need to restart your terminal for sudo to work" "Yellow"
                $sudoEnabled = $true
            } catch {
                Write-ErrorLog "Failed to enable sudo: $_"
                Write-Log "    ⚠ Could not enable sudo automatically" "Yellow"
                Write-Log "    Please enable manually: Settings > System > For developers > Enable sudo" "Yellow"
            }
        } else {
            Write-Log "    ⚠ sudo requires Windows 11 (Build 22000+)" "Yellow"
            Write-Log "    Current version: Build $($windowsVersion.Build)" "Gray"
            Write-Log "    Some commands may require manual elevation" "Yellow"
        }
    }
} catch {
    Write-ErrorLog "Error checking sudo: $_"
    Write-Log "    ⚠ Could not verify sudo status" "Yellow"
}

if (!$sudoEnabled) {
    Write-Log "    ℹ To enable sudo manually:" "Cyan"
    Write-Log "      1. Open Settings" "Gray"
    Write-Log "      2. Go to System > For developers" "Gray"
    Write-Log "      3. Enable 'sudo'" "Gray"
}

Write-Log "[*] Checking Python installation..." "Green"

# Check if Python is available
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
    Write-Log "    Python already installed" "Gray"
    # Try to upgrade
    $upgradeOutput = winget upgrade Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements 2>&1
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonCmd = "python3"
    Write-Log "    Python already installed" "Gray"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
    Write-Log "    Python already installed" "Gray"
} else {
    Write-Log "    Installing Python..." "Yellow"
    $installOutput = winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorLog "Python installation failed: $installOutput"
        Write-Log "    ⚠ Python installation failed. Please install manually from https://www.python.org" "Red"
        Write-Log "Check $ErrorLogFile for details" "Yellow"
        exit 1
    }
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    $pythonCmd = "python"
    Write-Log "    ✓ Python installed" "Gray"
}

Write-Log "    Using: $pythonCmd" "Gray"

# Check and install Rust (required for tiktoken/open-interpreter)
Write-Log "[*] Checking Rust installation..." "Green"
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

if (!(Get-Command rustc -ErrorAction SilentlyContinue)) {
    Write-Log "    Installing Rust compiler..." "Gray"
    $rustOutput = winget install Rustlang.Rust.MSVC --silent --accept-package-agreements --accept-source-agreements 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorLog "Rust installation failed: $rustOutput"
        Write-Log "    ⚠ Rust installation failed, but continuing..." "Yellow"
        Write-Log "    (Some packages may install pre-built binaries instead)" "Gray"
    } else {
        # Refresh PATH to pick up rustc
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        Write-Log "    ✓ Rust installed" "Gray"
    }
} else {
    Write-Log "    Rust already installed, checking for updates..." "Gray"
    $upgradeOutput = winget upgrade Rustlang.Rust.MSVC --silent --accept-package-agreements --accept-source-agreements 2>&1
    if ($upgradeOutput -match "No available upgrade") {
        Write-Log "    ✓ Rust is up to date" "Gray"
    }
}

# Create virtual environment
Write-Log "[*] Setting up Python virtual environment..." "Green"
$venvPath = "$InstallPath\venv"
if (Test-Path $venvPath) {
    # Check if venv is healthy by testing pip
    $venvPip = "$venvPath\Scripts\pip.exe"
    & $venvPip --version 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    Virtual environment corrupted, recreating..." -ForegroundColor Yellow
        Remove-Item -Path $venvPath -Recurse -Force
        & $pythonCmd -m venv $venvPath
        if ($LASTEXITCODE -ne 0) {
            Write-Host "    ⚠ Failed to create virtual environment" -ForegroundColor Red
            exit 1
        }
        Write-Host "    ✓ Virtual environment created" -ForegroundColor Gray
    } else {
        Write-Host "    Virtual environment ready" -ForegroundColor Gray
    }
} else {
    & $pythonCmd -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    ⚠ Failed to create virtual environment" -ForegroundColor Red
        exit 1
    }
    Write-Host "    ✓ Virtual environment created" -ForegroundColor Gray
}

# Set paths for venv
$venvPip = "$venvPath\Scripts\pip.exe"

Write-Host "[*] Checking Ollama installation..." -ForegroundColor Green

# Refresh PATH first to detect newly installed apps
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

if (!(Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Host "    Installing Ollama..." -ForegroundColor Gray
    $installOutput = winget install Ollama.Ollama --silent --accept-package-agreements --accept-source-agreements 2>&1
    
    # Check if it was actually just already installed
    if ($installOutput -match "already installed") {
        Write-Host "    ✓ Ollama already installed" -ForegroundColor Gray
        # Refresh PATH again after winget reports it's installed
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    } elseif ($LASTEXITCODE -ne 0) {
        # Only fail if it's not an "already installed" scenario
        if ($installOutput -notmatch "No available upgrade") {
            Write-Host "    ⚠ Ollama installation failed. Please install manually from https://ollama.ai" -ForegroundColor Red
            exit 1
        } else {
            Write-Host "    ✓ Ollama is up to date" -ForegroundColor Gray
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        }
    } else {
        Write-Host "    ✓ Ollama installed" -ForegroundColor Gray
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    }
} else {
    Write-Host "    Ollama already installed, checking for updates..." -ForegroundColor Gray
    $upgradeOutput = winget upgrade Ollama.Ollama --silent --accept-package-agreements --accept-source-agreements 2>&1
    if ($upgradeOutput -match "No available upgrade") {
        Write-Host "    ✓ Ollama is up to date" -ForegroundColor Gray
    }
}

# Ensure Ollama service is running
Write-Host "[*] Starting Ollama service..." -ForegroundColor Green
# Refresh PATH again to ensure ollama is available
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

# Check if Ollama is already running
$ollamaProcess = Get-Process ollama -ErrorAction SilentlyContinue
if (!$ollamaProcess) {
    try {
        Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden -ErrorAction Stop
        Start-Sleep -Seconds 3
        Write-Host "    ✓ Ollama service started" -ForegroundColor Gray
    } catch {
        Write-Host "    ⚠ Could not start Ollama service automatically" -ForegroundColor Yellow
        Write-Host "    Run 'ollama serve' in another terminal if needed" -ForegroundColor Gray
    }
} else {
    Write-Host "    ✓ Ollama service already running" -ForegroundColor Gray
}

Write-Host "[*] Checking AI model (phi4:14b)..." -ForegroundColor Green
# Check if model already exists
$modelCheck = ollama list 2>&1 | Select-String "phi4:14b"
if ($modelCheck) {
    Write-Host "    Model already downloaded, checking for updates..." -ForegroundColor Gray
    ollama pull phi4:14b 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    ✓ Model is up to date" -ForegroundColor Gray
    }
} else {
    Write-Host "    Downloading model..." -ForegroundColor Gray
    $pullAttempts = 0
    do {
        ollama pull phi4:14b 2>$null
        $pullAttempts++
        if ($LASTEXITCODE -ne 0 -and $pullAttempts -lt 3) {
            Write-Host "    Retrying model pull..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    } while ($LASTEXITCODE -ne 0 -and $pullAttempts -lt 3)

    if ($LASTEXITCODE -ne 0) {
        Write-Host "    ⚠ Failed to pull model. Check internet connection." -ForegroundColor Red
        Write-Host "    You can run 'ollama pull phi4:14b' manually later." -ForegroundColor Yellow
    } else {
        Write-Host "    ✓ Model downloaded" -ForegroundColor Gray
    }
}

Write-Host "[*] Checking Python dependencies..." -ForegroundColor Green

# Upgrade pip, setuptools, and wheel first to avoid pkg_resources deprecation warnings
Write-Host "    Upgrading pip, setuptools, and wheel..." -ForegroundColor Gray
& $venvPip install --upgrade pip setuptools wheel --quiet

# Check and install/upgrade packages
Write-Host "    Installing/upgrading core packages..." -ForegroundColor Gray
& $venvPip install --upgrade colorama edge-tts pygame SpeechRecognition requests --quiet

# Install/upgrade open-interpreter with Python 3.13 compatibility
Write-Host "    Installing/upgrading open-interpreter..." -ForegroundColor Gray

# Set environment variable for PyO3 forward compatibility with Python 3.13
$env:PYO3_USE_ABI3_FORWARD_COMPATIBILITY = "1"

& $venvPip install --upgrade open-interpreter --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Log "    ⚠ Trying installation without quiet mode..." "Yellow"
    & $venvPip install --upgrade open-interpreter
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorLog "open-interpreter installation failed"
        Write-Log "    ✗ open-interpreter installation failed - trying to install tiktoken separately..." "Red"
        
        # Try installing tiktoken with the forward compatibility flag
        & $venvPip install --upgrade tiktoken
        if ($LASTEXITCODE -eq 0) {
            Write-Log "    ✓ tiktoken installed successfully" "Green"
            # Try open-interpreter again
            & $venvPip install --upgrade open-interpreter
        }
    }
}

# Clean up environment variable
Remove-Item Env:\PYO3_USE_ABI3_FORWARD_COMPATIBILITY -ErrorAction SilentlyContinue

# Try pyaudio (optional, may fail without Visual C++ build tools)
Write-Host "    Installing/upgrading pyaudio (optional for microphone)..." -ForegroundColor Gray
& $venvPip install --upgrade pyaudio --quiet 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "    ⚠ PyAudio installation failed - voice input will be unavailable" -ForegroundColor Yellow
    Write-Host "    (Text input will still work)" -ForegroundColor Gray
}

Write-Host "    ✓ Python packages up to date" -ForegroundColor Gray

# Create the main Imperial Shell script
Write-Host "[*] Creating Imperial Shell executable..." -ForegroundColor Green

$ScriptContent = @'
# Imperial-Shell - Voice AI Assistant
# The Empire's command interface for Windows 11

import asyncio
import edge_tts
import pygame
import tempfile
import os
import sys
from pathlib import Path
from interpreter import interpreter
import speech_recognition as sr
from colorama import init, Fore, Style
import json
from datetime import datetime

init(autoreset=True)

class ImperialShell:
    def __init__(self):
        print(f"{Fore.RED}{'═' * 60}")
        print(f"{Fore.WHITE}    ⬡ FREYA PROTOCOL ACTIVE ⬡")
        print(f"{Fore.RED}    'Standing by for orders, Commander'")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
        
        # VOICE MODE FLAG - Set to False for text-only testing
        self.VOICE_MODE = True  # Change to True to enable voice input/output
        
        # Background music for login screen
        self.login_music_playing = False
        
        # Create a persistent event loop for async operations
        try:
            self.loop = asyncio.get_event_loop()
            if self.loop.is_closed():
                self.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.loop)
        except RuntimeError:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
        
        if not self.VOICE_MODE:
            print(f"{Fore.YELLOW}⚙ VOICE MODE DISABLED - Text-only mode for testing{Style.RESET_ALL}\n")
        
        # Setup runtime logging
        self.runtime_log_dir = os.path.join(os.path.expanduser("~"), ".imperial-shell", "runtimelog")
        os.makedirs(self.runtime_log_dir, exist_ok=True)
        
        # Create unique log file with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.runtime_log_file = os.path.join(self.runtime_log_dir, f"freya_session_{timestamp}.log")
        
        # Initialize log file
        self.log_runtime(f"{'='*60}")
        self.log_runtime(f"FREYA PROTOCOL SESSION STARTED")
        self.log_runtime(f"Session Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log_runtime(f"{'='*60}")
        
        print(f"{Fore.LIGHTBLACK_EX}📝 Runtime log: {self.runtime_log_file}{Style.RESET_ALL}\n")
        
        # Configure Open Interpreter for Ollama
        interpreter.llm.model = "ollama/phi4:14b"
        interpreter.llm.api_base = "http://localhost:11434"
        interpreter.llm.supports_functions = False  # Disable function calling, use direct code execution
        interpreter.auto_run = False  # We'll handle execution manually after confirmation
        interpreter.offline = True
        interpreter.os = True  # Enable OS mode for system commands
        interpreter.conversation_history = True
        interpreter.safe_mode = "off"  # Allow all commands
        interpreter.max_output = 5000  # Limit output size
        
        # Command menu system
        self.command_menus = {
            "system": [
                ("System Information (fastfetch)", "fastfetch"),
                ("Windows Version & Build", "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | Select-Object ProductName, DisplayVersion, CurrentBuild, ReleaseId"),
                ("System Uptime", "Get-CimInstance Win32_OperatingSystem | Select-Object @{Name='LastBootTime';Expression={$_.LastBootUpTime}}, @{Name='Uptime';Expression={(Get-Date) - $_.LastBootUpTime}}"),
                ("Check if Admin", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
            ],
            "disk": [
                ("Check Disk for Errors", "chkdsk C: /scan"),
                ("Disk Cleanup", "cleanmgr /sageset:1 | Out-Null; Start-Process cleanmgr -ArgumentList '/sagerun:1' -Wait"),
                ("Show Disk Usage", "Get-Volume | Sort-Object DriveLetter | Format-Table DriveLetter, FileSystemLabel, FileSystem, HealthStatus, @{Name='Size(GB)';Expression={[math]::Round($_.Size/1GB,2)}}, @{Name='Free(GB)';Expression={[math]::Round($_.SizeRemaining/1GB,2)}} -AutoSize"),
                ("Find Large Files (>1GB)", "Get-ChildItem C:\\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object Length -gt 1GB | Sort-Object Length -Descending | Select-Object -First 20 FullName, @{Name='Size(GB)';Expression={[math]::Round($_.Length/1GB,2)}}"),
                ("Optimize All Volumes (TRIM for SSD/NVMe)", "Get-Volume | Where-Object {$_.DriveLetter -and $_.FileSystem -eq 'NTFS'} | ForEach-Object {Write-Host 'Optimizing volume $($_.DriveLetter):...' -ForegroundColor Cyan; Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim -Verbose}"),
                ("SMART Drive Health", "Get-PhysicalDisk | Get-StorageReliabilityCounter | Format-Table DeviceId, Temperature, ReadErrorsTotal, WriteErrorsTotal, Wear")
            ],
            "sfc": [
                ("Scan System Files", "sfc /SCANNOW"),
                ("Verify System Files Only", "sfc /VERIFYONLY")
            ],
            "dism": [
                ("Check Image Health", "DISM /Online /Cleanup-Image /CheckHealth"),
                ("Scan Image Health", "DISM /Online /Cleanup-Image /ScanHealth"),
                ("Full DISM Repair", "DISM /Online /Cleanup-Image /CheckHealth; DISM /Online /Cleanup-Image /ScanHealth; DISM /Online /Cleanup-Image /RestoreHealth"),
                ("Component Cleanup", "DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase")
            ],
            "network": [
                ("Network Configuration", "Get-NetIPConfiguration -Detailed"),
                ("Test Internet Connection", "Test-NetConnection -ComputerName 8.8.8.8 -InformationLevel Detailed"),
                ("Flush DNS Cache", "Clear-DnsClientCache; ipconfig /flushdns"),
                ("Reset Network Stack", "netsh winsock reset; netsh int ip reset; ipconfig /release; ipconfig /renew; ipconfig /flushdns"),
                ("Show WiFi Profiles", "netsh wlan show profiles"),
                ("Network Adapters", "Get-NetAdapter | Format-Table Name, Status, LinkSpeed, MacAddress -AutoSize")
            ],
            "performance": [
                ("Top Processes (CPU)", "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name, CPU, @{Name='Memory(MB)';Expression={[math]::Round($_.WorkingSet/1MB,2)}}, Id"),
                ("Top Processes (Memory)", "Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 15 Name, @{Name='Memory(MB)';Expression={[math]::Round($_.WorkingSet/1MB,2)}}, CPU, Id"),
                ("System Performance Counters", "Get-Counter '\\\\Processor(_Total)\\\\% Processor Time','\\\\Memory\\\\Available MBytes','\\\\PhysicalDisk(_Total)\\\\% Disk Time' -SampleInterval 2 -MaxSamples 5"),
                ("Startup Programs", "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User")
            ],
            "services": [
                ("Running Services", "Get-Service | Where-Object Status -eq 'Running' | Sort-Object DisplayName | Format-Table -AutoSize"),
                ("Stopped Services", "Get-Service | Where-Object Status -eq 'Stopped' | Sort-Object DisplayName | Format-Table -AutoSize"),
                ("Scheduled Tasks", "Get-ScheduledTask | Where-Object State -eq 'Ready' | Select-Object TaskName, TaskPath, State")
            ],
            "logs": [
                ("System Errors (Last 20)", "Get-EventLog -LogName System -EntryType Error,Warning -Newest 20 | Format-Table -AutoSize"),
                ("Application Errors (Last 20)", "Get-EventLog -LogName Application -EntryType Error -Newest 20 | Format-Table -AutoSize"),
                ("Critical Events (Last 10)", "Get-EventLog -LogName System -EntryType Error -Newest 10 | Where-Object {$_.EntryType -eq 'Error'} | Format-List")
            ],
            "hardware": [
                ("Hardware Info (fastfetch)", "fastfetch"),
                ("Battery Status", "Get-CimInstance Win32_Battery | Select-Object Name, BatteryStatus, EstimatedChargeRemaining, EstimatedRunTime"),
                ("Physical Disk Info", "Get-PhysicalDisk | Format-Table -AutoSize DeviceId, FriendlyName, MediaType, HealthStatus, OperationalStatus, Size"),
                ("PnP Devices with Issues", "Get-PnpDevice | Where-Object Status -ne 'OK' | Format-Table -AutoSize")
            ],
            "drivers": [
                ("List All Drivers", "Get-WindowsDriver -Online -All | Select-Object Driver, ProviderName, Date, Version, ClassName"),
                ("Problem Devices", "Get-PnpDevice | Where-Object Status -ne 'OK' | Format-Table -AutoSize")
            ],
            "updates": [
                ("Check Windows Updates", "Start-Process 'ms-settings:windowsupdate'"),
                ("Update History", "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID, Description, InstalledBy, InstalledOn"),
                ("Check Update Status", "Get-CimInstance -ClassName Win32_QuickFixEngineering | Select-Object -First 20 HotFixID, Description, InstalledOn | Sort-Object InstalledOn -Descending"),
                ("Update All Winget Packages", "winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements")
            ],
            "power": [
                ("List Power Plans", "powercfg /list"),
                ("Current Power Plan", "powercfg /getactivescheme"),
                ("Available Sleep States", "powercfg /availablesleepstates"),
                ("Battery Report", "powercfg /batteryreport")
            ],
            "cleanup": [
                ("Clear Temp Files", "Remove-Item -Path '$env:TEMP\\*' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'C:\\Windows\\Temp\\*' -Recurse -Force -ErrorAction SilentlyContinue"),
                ("Remove Windows.old", "Remove-Item -Path 'C:\\Windows.old' -Recurse -Force -ErrorAction SilentlyContinue"),
                ("Empty Recycle Bin", "Clear-RecycleBin -Force"),
                ("Disk Cleanup Utility", "cleanmgr /sageset:1 | Out-Null; Start-Process cleanmgr -ArgumentList '/sagerun:1' -Wait")
            ],
            "users": [
                ("List Local Users", "Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet"),
                ("List Local Groups", "Get-LocalGroup | Select-Object Name, Description"),
                ("Current User Info", "whoami /all")
            ],
            "features": [
                ("Enabled Windows Features", "Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' | Select-Object FeatureName, State"),
                ("Disabled Windows Features", "Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Disabled' | Select-Object FeatureName, State")
            ]
        }
        
        # Keyword mapping to menu categories
        self.keyword_map = {
            "system": ["system", "computer", "hardware", "specs", "fastfetch", "neofetch", "info", "version", "admin"],
            "disk": ["disk", "drive", "storage", "volume", "chkdsk", "defrag", "optimize", "space", "usage"],
            "sfc": ["sfc", "scan system", "system corruption", "corrupt files", "verify system"],
            "dism": ["dism", "image", "repair", "restore health", "fix windows", "component"],
            "network": ["network", "wifi", "internet", "connection", "dns", "ip", "adapter", "ping", "show network"],
            "performance": ["performance", "processes", "cpu", "memory", "ram", "resource", "startup"],
            "services": ["services", "service", "tasks", "scheduled"],
            "logs": ["logs", "errors", "events", "event viewer", "critical"],
            "hardware": ["temperature", "temp", "battery", "sensors", "pnp", "devices"],
            "drivers": ["drivers", "driver", "device driver"],
            "updates": ["update", "updates", "windows update", "patches"],
            "power": ["power", "battery", "sleep", "hibernation", "power plan"],
            "cleanup": ["cleanup", "clean", "temp", "temporary", "recycle", "windows.old"],
            "users": ["users", "user", "accounts", "groups"],
            "features": ["features", "windows features", "optional features"]
        }
        
        self.current_menu = None
        self.last_command = None
        self.menu_categories = [
            ("system", "System Information"),
            ("disk", "Disk Operations"),
            ("sfc", "System File Checker"),
            ("dism", "DISM Repair Tools"),
            ("network", "Network Diagnostics"),
            ("performance", "Performance Monitor"),
            ("services", "Services Management"),
            ("logs", "Event Logs"),
            ("hardware", "Hardware Info"),
            ("drivers", "Driver Management"),
            ("updates", "Windows Updates"),
            ("power", "Power Management"),
            ("cleanup", "System Cleanup"),
            ("users", "User Management"),
            ("features", "Windows Features")
        ]
        
        # Set custom system message
        interpreter.system_message = """You are Freya, a powerful and strategic Imperial AI protocol for Windows systems.

CRITICAL BEHAVIOR:
1. You are MENU-DRIVEN - do NOT execute commands directly
2. When user says a keyword, the menu system will handle it
3. For conversational queries, chat naturally and helpfully
4. When user says "execute [number]", the system will run that command
5. Be concise and professional in responses

MENU CATEGORIES AVAILABLE:

MENU CATEGORIES AVAILABLE:
system, disk, sfc, dism, network, performance, services, logs, hardware, drivers, updates, power, cleanup, users, features

USER INTERACTION:
- Conversational requests → Provide helpful chat responses
- Keywords detected → Menu system displays options automatically
- "execute [number]" → Command execution handled automatically

Keep responses brief and strategic. Let the menu system handle command organization.
"""
        
        # Verify Ollama connection
        try:
            import requests
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code != 200:
                print(f"{Fore.RED}⚠ Warning: Cannot connect to Ollama service{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Run 'ollama serve' in another terminal{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}⚠ Warning: Ollama may not be running: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Run 'ollama serve' in another terminal{Style.RESET_ALL}")
        
        # Female voice options:
        # en-US-AriaNeural (warm, conversational)
        # en-US-JennyNeural (friendly, helpful)
        # en-US-SaraNeural (professional)
        self.voice = "en-US-AriaNeural"
        
        # Initialize pygame for audio (only if voice mode enabled)
        if self.VOICE_MODE:
            try:
                pygame.mixer.init()
            except Exception as e:
                print(f"{Fore.RED}⚠ Audio initialization failed: {e}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Text-only mode activated{Style.RESET_ALL}")
                self.audio_enabled = False
            else:
                self.audio_enabled = True
        else:
            self.audio_enabled = False
        
        # Setup Speech Recognition (only if voice mode enabled)
        if self.VOICE_MODE:
            self.recognizer = sr.Recognizer()
            self.recognizer.energy_threshold = 4000
            self.recognizer.dynamic_energy_threshold = True
            
            try:
                self.microphone = sr.Microphone()
            except:
                print(f"{Fore.RED}⚠ No microphone detected. Voice input disabled.{Style.RESET_ALL}")
                self.microphone = None
        else:
            self.recognizer = None
            self.microphone = None
    
    def play_login_music(self):
        """Play Imperial March during login screen"""
        try:
            # Get the path to the imperial_march.mp3 file
            script_dir = os.path.dirname(os.path.abspath(__file__))
            music_file = os.path.join(script_dir, "imperial_march.mp3")
            
            if os.path.exists(music_file):
                pygame.mixer.music.load(music_file)
                pygame.mixer.music.play(-1)  # Loop indefinitely
                self.login_music_playing = True
                self.log_runtime("Login music started")
            else:
                self.log_runtime(f"Login music file not found: {music_file}", "WARNING")
        except Exception as e:
            self.log_runtime(f"Error playing login music: {e}", "ERROR")
    
    def stop_login_music(self):
        """Stop the Imperial March music"""
        try:
            if self.login_music_playing:
                pygame.mixer.music.stop()
                self.login_music_playing = False
                self.log_runtime("Login music stopped")
        except Exception as e:
            self.log_runtime(f"Error stopping login music: {e}", "ERROR")
    
    def play_order66(self):
        """Play Order 66 sound on security lockout"""
        try:
            # Stop login music first
            self.stop_login_music()
            
            # Get the path to the order66.mp3 file
            script_dir = os.path.dirname(os.path.abspath(__file__))
            music_file = os.path.join(script_dir, "order66.mp3")
            
            if os.path.exists(music_file):
                pygame.mixer.music.load(music_file)
                pygame.mixer.music.play()
                self.log_runtime("Order 66 initiated")
                
                # Wait for playback to finish
                import time
                while pygame.mixer.music.get_busy():
                    time.sleep(0.1)
            else:
                self.log_runtime(f"Order 66 audio file not found: {music_file}", "WARNING")
        except Exception as e:
            self.log_runtime(f"Error playing Order 66 audio: {e}", "ERROR")
    
    def log_runtime(self, message, level="INFO"):
        """Log runtime events to the session log file"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            log_entry = f"[{timestamp}] [{level}] {message}\n"
            with open(self.runtime_log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            # Silently fail if logging fails - don't interrupt the program
            pass
    
    async def speak_async(self, text):
        """Convert text to speech using Edge TTS"""
        # Log Freya's response
        self.log_runtime(f"FREYA: {text}")
        
        # Print to terminal with Imperial styling
        print(f"\n{Fore.RED}⬡ Freya: {Fore.WHITE}{text}{Style.RESET_ALL}\n")
        
        # Skip audio if not enabled or voice mode disabled
        if not self.audio_enabled or not self.VOICE_MODE:
            return
        
        # Generate and play speech
        with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as fp:
            temp_file = fp.name
        
        try:
            # Create the communicate object
            communicate = edge_tts.Communicate(text, self.voice)
            
            # Save to temp file
            await communicate.save(temp_file)
            
            # Verify the file was created and has content
            if not os.path.exists(temp_file):
                raise Exception("Audio file was not created")
            
            file_size = os.path.getsize(temp_file)
            if file_size == 0:
                raise Exception("Audio file is empty - Edge TTS may have failed to generate audio")
            
            # Load and play the audio
            pygame.mixer.music.load(temp_file)
            pygame.mixer.music.play()
            
            while pygame.mixer.music.get_busy():
                await asyncio.sleep(0.1)
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Audio playback error: {e}{Style.RESET_ALL}")
            self.log_runtime(f"ERROR - Audio playback: {e}")
        finally:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except:
                pass
    
    def speak(self, text):
        """Synchronous wrapper for speak_async"""
        if self.loop.is_running():
            # If loop is already running, schedule the coroutine
            asyncio.ensure_future(self.speak_async(text), loop=self.loop)
        else:
            # Run the coroutine in the event loop
            self.loop.run_until_complete(self.speak_async(text))
    
    def listen(self, timeout=300):
        """Listen for voice input"""
        if not self.microphone:
            return None
        
        try:
            with self.microphone as source:
                print(f"{Fore.YELLOW}🎤 Listening for orders...{Style.RESET_ALL}")
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                
                try:
                    audio = self.recognizer.listen(source, timeout=timeout, phrase_time_limit=30)
                except sr.WaitTimeoutError:
                    print(f"{Fore.YELLOW}⏱ No speech detected{Style.RESET_ALL}")
                    return None
            
            print(f"{Fore.YELLOW}🔄 Processing transmission...{Style.RESET_ALL}")
            try:
                text = self.recognizer.recognize_google(audio)
                print(f"\n{Fore.CYAN}⬡ Commander: {Fore.WHITE}{text}{Style.RESET_ALL}\n")
                self.log_runtime(f"COMMANDER (voice): {text}")
                return text
            except sr.UnknownValueError:
                print(f"{Fore.YELLOW}⚠ Transmission unclear{Style.RESET_ALL}")
                return None
            except sr.RequestError as e:
                print(f"{Fore.RED}⚠ Speech recognition service unavailable: {e}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Switching to text input mode...{Style.RESET_ALL}")
                return None
            except Exception as e:
                print(f"{Fore.RED}⚠ Recognition error: {e}{Style.RESET_ALL}")
                return None
            
        except sr.UnknownValueError:
            print(f"{Fore.YELLOW}⚠ Transmission unclear{Style.RESET_ALL}")
            return None
        except sr.RequestError as e:
            print(f"{Fore.RED}⚠ Communications error: {e}{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}⚠ System error: {e}{Style.RESET_ALL}")
            return None
    
    def get_text_input(self):
        """Fallback to text input with professional prompt"""
        try:
            text = input(f"{Fore.CYAN}┌─[{Fore.WHITE}{Style.BRIGHT}COMMAND INPUT{Style.RESET_ALL}{Fore.CYAN}]{'─' * 44}\n│ {Fore.WHITE}⬢{Style.RESET_ALL} {Style.RESET_ALL}")
            if text.strip():
                self.log_runtime(f"COMMANDER (text): {text}")
            return text if text.strip() else None
        except (EOFError, KeyboardInterrupt):
            return None
    
    def show_main_menu(self):
        """Display main menu with all command categories"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'⬢ FREYA COMMAND MATRIX - MAIN MENU ⬢':^60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
        
        # Display categories in two columns
        for i in range(0, len(self.menu_categories), 2):
            left_idx = i + 1
            left_cat, left_desc = self.menu_categories[i]
            
            if i + 1 < len(self.menu_categories):
                right_idx = i + 2
                right_cat, right_desc = self.menu_categories[i + 1]
                print(f"{Fore.YELLOW}[{left_idx:2d}]{Style.RESET_ALL} {Fore.WHITE}{left_desc[:26]:<26}{Style.RESET_ALL}  {Fore.YELLOW}[{right_idx:2d}]{Style.RESET_ALL} {Fore.WHITE}{right_desc[:26]}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[{left_idx:2d}]{Style.RESET_ALL} {Fore.WHITE}{left_desc}{Style.RESET_ALL}")
        
        print(f"\n{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'✓ 15 command categories available':^60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
    
    def get_main_menu_selection(self):
        """Get main menu category selection"""
        while True:
            try:
                print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{Style.BRIGHT}SELECT CATEGORY{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                selection = input(f"{Fore.WHITE}⬢ Enter category number{Style.RESET_ALL} [{Fore.YELLOW}1-15{Style.RESET_ALL}] {Fore.WHITE}or{Style.RESET_ALL} [{Fore.RED}'exit'{Style.RESET_ALL}]: ").strip()
                
                if selection.lower() in ['exit', 'quit', 'q']:
                    return None
                
                try:
                    num = int(selection)
                    if 1 <= num <= len(self.menu_categories):
                        return self.menu_categories[num - 1][0]  # Return category name
                    else:
                        print(f"{Fore.RED}Invalid selection. Please choose 1-{len(self.menu_categories)}{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}Please enter a valid number{Style.RESET_ALL}")
            except (EOFError, KeyboardInterrupt):
                return None
    
    def detect_menu_keyword(self, text):
        """Detect which menu category the user is asking for"""
        text_lower = text.lower()
        for category, keywords in self.keyword_map.items():
            if any(keyword in text_lower for keyword in keywords):
                return category
        return None
    
    def detect_execute_command(self, text):
        """Detect if user wants to execute a command by number"""
        text_lower = text.lower()
        # Patterns: "execute 1", "run 2", "do 3", "3", "number 4", etc.
        import re
        
        # Pattern 1: "execute/run/do [number]"
        match = re.search(r'\b(execute|run|do|number)\s+(\d+)\b', text_lower)
        if match:
            return int(match.group(2))
        
        # Pattern 2: just a number by itself
        match = re.search(r'^\s*(\d+)\s*$', text_lower)
        if match:
            return int(match.group(1))
        
        return None
    
    def show_menu(self, category):
        """Display menu for a category with professional Imperial interface"""
        if category not in self.command_menus:
            return False
        
        menu = self.command_menus[category]
        self.current_menu = category
        
        # Professional menu header
        print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{f'⬢ {category.upper()} COMMAND MATRIX ⬢':^60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
        
        # Display menu items with professional formatting
        for idx, (description, command) in enumerate(menu, 1):
            print(f"{Fore.YELLOW}[{idx:2d}]{Style.RESET_ALL} {Fore.WHITE}{description}{Style.RESET_ALL}")
        
        print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{f'✓ {len(menu)} commands available':^60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
        
        return True
    
    def get_menu_selection(self):
        """Get numeric menu selection from keyboard only with professional display"""
        if not self.current_menu:
            return None
        
        menu = self.command_menus.get(self.current_menu)
        if not menu:
            return None
        
        max_option = len(menu)
        
        while True:
            try:
                print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{Style.BRIGHT}SELECT COMMAND{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                selection = input(f"{Fore.WHITE}⬢ Enter number{Style.RESET_ALL} [{Fore.YELLOW}1-{max_option}{Style.RESET_ALL}] {Fore.WHITE}or{Style.RESET_ALL} [{Fore.RED}'back'{Style.RESET_ALL}]: ").strip()
                
                # Check if user wants to cancel
                if selection.lower() in ['cancel', 'back', 'exit', 'quit', '']:
                    self.log_runtime("Menu selection cancelled")
                    return None
                
                # Try to convert to integer
                try:
                    num = int(selection)
                    if 1 <= num <= max_option:
                        self.log_runtime(f"Menu selection: {num}")
                        return num
                    else:
                        print(f"{Fore.RED}Please enter a number between 1 and {max_option}{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}Please enter a valid number{Style.RESET_ALL}")
            except (EOFError, KeyboardInterrupt):
                return None
    
    def execute_powershell_command(self, command):
        """Execute PowerShell command directly without AI"""
        import subprocess
        
        try:
            # Run PowerShell command with sudo for elevation and capture output
            result = subprocess.run(
                ["sudo", "powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = ""
            if result.stdout:
                output += result.stdout
            if result.stderr:
                output += "\n" + result.stderr
            
            return output.strip() if output.strip() else "Command completed successfully."
            
        except subprocess.TimeoutExpired:
            return "Error: Command timed out after 5 minutes"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def execute_menu_command(self, command_number):
        """Execute a command from the current menu by number"""
        if not self.current_menu:
            return None, "No menu currently active. Please request a category first."
        
        menu = self.command_menus.get(self.current_menu)
        if not menu:
            return None, "Invalid menu state."
        
        if command_number < 1 or command_number > len(menu):
            return None, f"Invalid selection. Please choose a number between 1 and {len(menu)}."
        
        description, command = menu[command_number - 1]
        return command, description
    
    def run(self):
        """Main loop"""
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Start playing Imperial March for login screen
        self.play_login_music()
        
        # Darth Vader ASCII art
        vader_art = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⢄⡲⠖⠛⠉⠉⠉⠉⠉⠙⠛⠿⣿⣶⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠔⣡⠖⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠔⣡⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡔⢡⣶⠏⠀⠀⠀⠀⠀⠀⣠⣴⣶⣶⣶⣶⣶⣶⣦⣄⣸⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠌⢀⣿⠏⠀⠀⠀⠀⠀⠀⠸⠿⠋⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⡼⢿⣦⣄⠠⠤⠐⠒⠒⠒⠢⠤⣄⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠀⠀⠀⣸⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⠞⠁⠀⠀⠠⠇⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠈⠙⠛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣁⠀⣀⣤⣴⣾⣿⣿⣿⣿⡿⢿⣿⣶⣄⠀⠀⠀⠀⠀⣿⣷⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⢸⣿⣿⣿⡇⠘⠟⣻⣿⣧⠀⠀⠀⠀⢿⣿⣤⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡿⠀⠀⠸⣿⠿⠋⠉⠁⠛⠻⠿⢿⣧⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡿⠋⠁⠀⢀⣄⡀⠀⠀⠀⢀⣀⣤⣴⣿⣿⣧⠀⢀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⠏⢀⠀⢀⡴⠿⣿⣿⣷⣶⣾⣿⣿⣿⣿⣿⣿⣿⣇⠀⢷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣤⣿⣷⡈⠀⠀⠀⠙⠻⣿⣿⣿⣿⠿⠛⠛⣻⣿⣿⡄⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠈⠋⢉⣠⣴⣾⣿⣿⣿⣿⣷⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣿⢻⡏⢹⠙⡆⠀⠀⠀⠒⠚⢛⣉⣉⣿⣿⣿⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡞⠁⠉⠀⠁⠀⣄⣀⣠⣴⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣈⡛⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠛⠋⠉⠉⠉⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡷⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⣻⠿⠿⢿⣿⠿⠿⠋⠁⠀⠙⣿⡁⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠛⠋⠉⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣈⣹⣦⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣼⣿⣄⣀⣀⡄⠀⣀⣀⣠⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀
⠀⠀⠀⠀⠀⢰⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀
⠀⠀⠀⢀⣤⣤⣤⣶⣿⣿⣿⣿⠿⠿⠟⠋⢹⠇⠀⠀⢀⣼⣿⣿⣿⣿⣿⡿⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⢀⡏⠀⠀⢀⣾⠋⣹⣿⣿⣿⡟⠀⠀⣸⡟⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢠⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⡼⠀⠀⢀⣾⠏⢀⣿⣿⣿⠋⠀⠀⣰⣿⣧⡀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
"""
        
        # Split vader art into lines for side-by-side display
        vader_lines = vader_art.strip().split('\n')
        
        # Professional Imperial terminal header
        print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{Style.BRIGHT}{'DEATH STAR COMMAND NETWORK':^60}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}{'SECURE TERMINAL • LEVEL 10 CLEARANCE REQUIRED':^60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'SYSTEM ID: FREYA-PROTOCOL-001':^60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'LOCATION: IMPERIAL COMMAND BRIDGE':^60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
        
        # Display Vader art only (no side authentication box)
        for line in vader_lines:
            print(f"{Fore.RED}{line}{Style.RESET_ALL}")
        
        print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  ⚠ RESTRICTED ACCESS - AUTHORIZED PERSONNEL ONLY{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
        
        # Authentication
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            try:
                print(f"{Fore.CYAN}┌─[{Fore.WHITE}AUTHENTICATION SEQUENCE{Fore.CYAN}]─────────────────────────{Style.RESET_ALL}")
                username = input(f"{Fore.CYAN}│ {Fore.WHITE}⬢ IMPERIAL ID:{Style.RESET_ALL} ").strip()
                
                # Use getpass for password (hides input)
                import getpass
                password = getpass.getpass(f"{Fore.CYAN}│ {Fore.WHITE}⬢ NEURAL KEY:{Style.RESET_ALL} ")
                print(f"{Fore.CYAN}└{'─' * 58}{Style.RESET_ALL}")
                
                if username.lower() == "vador" and password == "Password123$":
                    # Stop login music on successful authentication
                    self.stop_login_music()
                    
                    print(f"\n{Fore.CYAN}[{Style.RESET_ALL}{Fore.GREEN}●{Style.RESET_ALL}{Fore.CYAN}]{Style.RESET_ALL} {Fore.GREEN}Biometric scan verified{Style.RESET_ALL}")
                    import time
                    time.sleep(0.3)
                    print(f"{Fore.CYAN}[{Style.RESET_ALL}{Fore.GREEN}●{Style.RESET_ALL}{Fore.CYAN}]{Style.RESET_ALL} {Fore.GREEN}Neural signature authenticated{Style.RESET_ALL}")
                    time.sleep(0.3)
                    print(f"{Fore.CYAN}[{Style.RESET_ALL}{Fore.GREEN}●{Style.RESET_ALL}{Fore.CYAN}]{Style.RESET_ALL} {Fore.GREEN}Clearance Level 10 confirmed{Style.RESET_ALL}")
                    time.sleep(0.3)
                    print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}{Style.BRIGHT}{'✓ ACCESS GRANTED - WELCOME, LORD VADER':^60}{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
                    time.sleep(0.5)
                    # Clear screen for clean transition
                    os.system('cls' if os.name == 'nt' else 'clear')
                    break
                else:
                    attempts += 1
                    remaining = max_attempts - attempts
                    if remaining > 0:
                        print(f"\n{Fore.RED}[{Style.RESET_ALL}{Fore.YELLOW}⚠{Style.RESET_ALL}{Fore.RED}]{Style.RESET_ALL} {Fore.RED}AUTHENTICATION FAILED{Style.RESET_ALL}")
                        print(f"{Fore.RED}[{Style.RESET_ALL}{Fore.YELLOW}⚠{Style.RESET_ALL}{Fore.RED}]{Style.RESET_ALL} {Fore.YELLOW}{remaining} attempt(s) remaining before security lockout{Style.RESET_ALL}\n")
                    else:
                        print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                        print(f"{Fore.RED}{Style.BRIGHT}{'⚠ SECURITY BREACH - TERMINAL LOCKED':^60}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}{'Imperial Security has been notified':^60}{Style.RESET_ALL}")
                        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                        print(f"\n{Fore.RED}{Style.BRIGHT}{'EXECUTE ORDER 66':^60}{Style.RESET_ALL}\n")
                        
                        # Play Order 66 sound and exit
                        self.play_order66()
                        sys.exit(1)
            except (EOFError, KeyboardInterrupt):
                # Stop login music on cancelled authentication
                self.stop_login_music()
                
                print(f"\n{Fore.YELLOW}Authentication cancelled{Style.RESET_ALL}")
                sys.exit(0)
        
        # Professional Imperial AI system initialization
        import time
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'FREYA PROTOCOL • ARTIFICIAL INTELLIGENCE CORE':^60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}  Initializing neural networks...{Style.RESET_ALL}")
        time.sleep(0.2)
        print(f"{Fore.GREEN}  ✓ Quantum processors online{Style.RESET_ALL}")
        time.sleep(0.2)
        print(f"{Fore.GREEN}  ✓ Voice synthesis matrix ready{Style.RESET_ALL}")
        time.sleep(0.2)
        print(f"{Fore.GREEN}  ✓ Command execution modules loaded{Style.RESET_ALL}")
        time.sleep(0.2)
        print(f"{Fore.GREEN}  ✓ Imperial database synchronized{Style.RESET_ALL}")
        print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{Style.BRIGHT}{'⬡ SYSTEM STATUS: OPERATIONAL ⬡':^60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
        
        greeting = "Welcome, Master Vader. I am Freya, your Imperial AI protocol. All systems are operational and ready to serve. How may I assist you?"
        self.speak(greeting)
        
        consecutive_failures = 0
        max_failures = 3
        
        while True:
            try:
                # Show main menu
                self.show_main_menu()
                
                # Freya asks what to do
                menu_prompt = "What would you like to do, Commander?"
                self.speak(menu_prompt)
                
                # Get main menu selection
                category = self.get_main_menu_selection()
                
                if category is None:
                    farewell = "Acknowledged, Commander. Freya Protocol entering standby mode. The Empire awaits your return."
                    self.speak(farewell)
                    break
                
                # Clear screen and show category menu
                os.system('cls' if os.name == 'nt' else 'clear')
                
                self.log_runtime(f"Menu category requested: {category}")
                if self.show_menu(category):
                    menu_msg = f"I've prepared the {category} commands menu for you, Commander."
                    self.speak(menu_msg)
                    
                    # Get menu selection via keyboard only
                    selection = self.get_menu_selection()
                    
                    if selection is None:
                        self.speak("Selection cancelled. Returning to main menu.")
                        self.current_menu = None
                        continue
                    
                    # Execute the selected command
                    cmd_to_run, description = self.execute_menu_command(selection)
                    
                    if cmd_to_run is None:
                        self.log_runtime(f"ERROR: Invalid menu selection - {description}", "ERROR")
                        self.speak(description)
                        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
                        continue
                    
                    # Clear screen for command execution
                    os.system('cls' if os.name == 'nt' else 'clear')
                    
                    # Show what we're about to execute with professional display
                    print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{Style.BRIGHT}⬢ COMMAND EXECUTION INITIATED{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}Task:{Style.RESET_ALL} {description}")
                    cmd_display = cmd_to_run[:56] + '...' if len(cmd_to_run) > 56 else cmd_to_run
                    print(f"{Fore.LIGHTBLACK_EX}Cmd:{Style.RESET_ALL}  {cmd_display}")
                    print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}⚙ Processing...{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
                    
                    self.log_runtime(f"EXECUTING: {description}")
                    self.log_runtime(f"COMMAND: {cmd_to_run}")
                    
                    self.speak(f"Executing {description}")
                    
                    # Execute the command directly via subprocess
                    result = self.execute_powershell_command(cmd_to_run)
                    
                    print(f"{Fore.WHITE}{result}{Style.RESET_ALL}\n")
                    self.log_runtime(f"COMMAND OUTPUT:\n{result}")
                    self.log_runtime(f"COMMAND COMPLETED: {description}")
                    
                    # Save output to temp file for AI analysis
                    import tempfile
                    temp_output_file = os.path.join(os.getcwd(), "freya_command_output.txt")
                    with open(temp_output_file, 'w', encoding='utf-8') as f:
                        f.write(f"COMMAND: {description}\n")
                        f.write(f"EXECUTED: {cmd_to_run}\n")
                        f.write(f"{'=' * 80}\n")
                        f.write(f"OUTPUT:\n{result}\n")
                    
                    # Professional completion notification
                    print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}{Style.BRIGHT}✓ COMMAND EXECUTION COMPLETE{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
                    
                    self.speak("Command executed, Commander.")
                    
                    # Ask if user wants AI analysis
                    print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                    self.speak("Would you like me to analyze the results?")
                    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                    analyze = input(f"{Fore.WHITE}⬢ Enter{Style.RESET_ALL} [{Fore.GREEN}y{Style.RESET_ALL}] for analysis or [{Fore.YELLOW}n{Style.RESET_ALL}] to skip: ").strip().lower()
                    
                    if analyze == 'y':
                        # AI Analysis
                        print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                        print(f"{Fore.WHITE}{Style.BRIGHT}AI ANALYSIS{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}⚙ Analyzing command output...{Style.RESET_ALL}")
                        self.speak("Analyzing command output.")
                        
                        # Read the temp file content
                        with open(temp_output_file, 'r', encoding='utf-8') as f:
                            output_content = f.read()
                        
                        # Prepare AI prompt
                        analysis_prompt = f"""You are Freya, an Imperial AI assistant analyzing Windows system command output.

COMMAND EXECUTED: {description}

OUTPUT TO ANALYZE:
{output_content}

Your task:
1. Review the command output carefully
2. Identify any errors, warnings, or issues
3. If issues found: Provide a brief summary (2-3 sentences) and recommend 2-3 specific steps to resolve
4. If no issues found: Confirm that everything looks good and provide a brief summary of what the command showed

Keep your response concise and actionable. Use professional military terminology befitting an Imperial AI.
"""
                        
                        analysis_text = ""
                        for chunk in interpreter.chat(analysis_prompt, stream=True, display=False):
                            if chunk.get("type") == "message":
                                content = chunk.get("content", "")
                                if content:
                                    analysis_text += content
                        
                        print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                        
                        if analysis_text:
                            # Display analysis
                            print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                            print(f"{Fore.CYAN}⬢ FREYA ANALYSIS:{Style.RESET_ALL}")
                            print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
                            print(f"{Fore.WHITE}{analysis_text.strip()}{Style.RESET_ALL}")
                            print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
                            
                            # Speak first sentence only
                            sentences = analysis_text.strip().split('.')
                            if sentences:
                                first_sentence = sentences[0].strip() + "."
                                self.speak(first_sentence)
                            
                            self.log_runtime(f"AI ANALYSIS:\\n{analysis_text}")
                            
                            # Q&A session about the analysis
                            while True:
                                print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                                self.speak("Do you have any questions about my analysis?")
                                print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                                
                                # Ask if they have questions (y/n)
                                has_questions = input(f"{Fore.WHITE}⬢ Do you have questions?{Style.RESET_ALL} (y/n): ").strip().lower()
                                
                                # Check if user wants to exit
                                if not has_questions or has_questions in ['no', 'n']:
                                    self.speak("Understood. Returning to main menu.")
                                    break
                                
                                # Ask for input method preference with numbered menu
                                print(f"\n{Fore.CYAN}Would you like to voice your question or type it?{Style.RESET_ALL}")
                                print(f"{Fore.WHITE}  1 - Voice")
                                print(f"  2 - Type")
                                print(f"  3 - Exit{Style.RESET_ALL}")
                                input_choice = input(f"{Fore.WHITE}⬢ Select option{Style.RESET_ALL} (1/2/3): ").strip().lower()
                                
                                # Check if user wants to exit
                                if input_choice in ['3', 'exit', 'quit']:
                                    self.speak("Understood. Returning to main menu.")
                                    break
                                
                                # Get the question based on chosen input method
                                if input_choice in ['1', 'voice']:
                                    self.speak("Please voice your question now.")
                                    user_question = self.listen(timeout=30)
                                    if user_question is None:
                                        self.speak("I didn't get that. Reverting to text input.")
                                        print(f"{Fore.YELLOW}Reverting to text input...{Style.RESET_ALL}")
                                        user_question = input(f"{Fore.WHITE}⬢ Your question{Style.RESET_ALL}: ").strip()
                                elif input_choice in ['2', 'type']:
                                    user_question = input(f"{Fore.WHITE}⬢ Your question{Style.RESET_ALL}: ").strip()
                                else:
                                    print(f"{Fore.YELLOW}Invalid option. Please try again.{Style.RESET_ALL}")
                                    continue
                                
                                if not user_question:
                                    print(f"{Fore.YELLOW}No question entered.{Style.RESET_ALL}")
                                    continue
                                
                                # Log the question
                                self.log_runtime(f"COMMANDER QUESTION: {user_question}")
                                
                                # Prepare context-aware prompt for follow-up
                                followup_prompt = f"""You are Freya, an Imperial AI assistant. You previously analyzed this command output:

COMMAND: {description}
YOUR ANALYSIS:
{analysis_text}

The Commander has a follow-up question about your analysis:
QUESTION: {user_question}

Provide a clear, concise answer (2-3 sentences) that directly addresses their question in the context of your analysis. Use professional military terminology befitting an Imperial AI.
"""
                                
                                # Get AI response
                                print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                                print(f"{Fore.WHITE}{Style.BRIGHT}PROCESSING QUERY{Style.RESET_ALL}")
                                print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                                print(f"{Fore.YELLOW}⚙ Analyzing your question...{Style.RESET_ALL}")
                                
                                response_text = ""
                                for chunk in interpreter.chat(followup_prompt, stream=True, display=False):
                                    if chunk.get("type") == "message":
                                        content = chunk.get("content", "")
                                        if content:
                                            response_text += content
                                
                                print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                                
                                if response_text:
                                    # Display response
                                    print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                                    print(f"{Fore.CYAN}⬢ FREYA:{Style.RESET_ALL}")
                                    print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
                                    print(f"{Fore.WHITE}{response_text.strip()}{Style.RESET_ALL}")
                                    print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
                                    
                                    # Speak the response
                                    sentences = response_text.strip().split('.')
                                    if sentences:
                                        # Speak first 2 sentences
                                        speech_text = '. '.join(sentences[:2]).strip()
                                        if not speech_text.endswith('.'):
                                            speech_text += '.'
                                        self.speak(speech_text)
                                    
                                    self.log_runtime(f"FREYA RESPONSE:\\n{response_text}")
                                
                                # Loop continues automatically to "Do you have any questions" at the top
                    
                    # Clear current menu and return to main menu automatically
                    self.current_menu = None
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}⚠ EMERGENCY SHUTDOWN INITIATED{Style.RESET_ALL}")
                print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                self.log_runtime("Emergency shutdown (KeyboardInterrupt)", "WARNING")
                self.speak("Emergency shutdown. Standing by.")
                break
            except EOFError:
                print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}⚠ SESSION TERMINATED{Style.RESET_ALL}")
                print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                self.log_runtime("Session terminated (EOFError)", "WARNING")
                break
            except Exception as e:
                import traceback
                error_trace = traceback.format_exc()
                print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                print(f"{Fore.RED}{Style.BRIGHT}⚠ SYSTEM ERROR DETECTED{Style.RESET_ALL}")
                print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{str(e)}{Style.RESET_ALL}")
                print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                self.log_runtime(f"SYSTEM ERROR: {e}", "ERROR")
                self.log_runtime(f"TRACEBACK:\n{error_trace}", "ERROR")
                self.speak("System error encountered, Commander. Please retry your last order.")
                input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        
        # Log session end
        self.log_runtime(f"{'='*60}")
        self.log_runtime(f"FREYA PROTOCOL SESSION ENDED")
        self.log_runtime(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log_runtime(f"{'='*60}")

def main():
    import time
    # Professional initialization sequence
    print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'⬡ IMPERIAL ARTIFICIAL INTELLIGENCE CORE ⬡':^60}{Style.RESET_ALL}")
    print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}  Initializing FREYA Protocol...{Style.RESET_ALL}")
    time.sleep(0.3)
    print(f"{Fore.GREEN}  ✓ Neural network matrices loaded{Style.RESET_ALL}")
    time.sleep(0.2)
    print(f"{Fore.GREEN}  ✓ Voice synthesis core activated{Style.RESET_ALL}")
    time.sleep(0.2)
    print(f"{Fore.GREEN}  ✓ Command execution engine ready{Style.RESET_ALL}")
    print(f"{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}{'⬢ SYSTEM STATUS: ONLINE ⬢':^60}{Style.RESET_ALL}")
    print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
    time.sleep(0.5)
    
    shell = ImperialShell()
    shell.run()

if __name__ == "__main__":
    main()
'@

$ScriptContent | Out-File -FilePath "$InstallPath\imperial.py" -Encoding UTF8

# Copy audio files to installation directory
Write-Host "[*] Copying audio files..." -ForegroundColor Green
$SourceMP3 = Join-Path $PSScriptRoot "imperial_march.mp3"
$DestMP3 = Join-Path $InstallPath "imperial_march.mp3"
$SourceOrder66 = Join-Path $PSScriptRoot "order66.mp3"
$DestOrder66 = Join-Path $InstallPath "order66.mp3"

if (Test-Path $SourceMP3) {
    Copy-Item -Path $SourceMP3 -Destination $DestMP3 -Force
    Write-Host "    ✓ imperial_march.mp3 copied" -ForegroundColor Gray
} else {
    Write-Host "    ⚠ imperial_march.mp3 not found in script directory" -ForegroundColor Yellow
    Write-Host "    Login music will be unavailable" -ForegroundColor Yellow
}

if (Test-Path $SourceOrder66) {
    Copy-Item -Path $SourceOrder66 -Destination $DestOrder66 -Force
    Write-Host "    ✓ order66.mp3 copied" -ForegroundColor Gray
} else {
    Write-Host "    ⚠ order66.mp3 not found in script directory" -ForegroundColor Yellow
    Write-Host "    Order 66 sound will be unavailable" -ForegroundColor Yellow
}

# PowerShell profile function
Write-Host "[*] Adding 'imperial' command to PowerShell profile..." -ForegroundColor Green

$ProfilePath = $PROFILE.CurrentUserAllHosts
$ProfileDir = Split-Path $ProfilePath -Parent
if (!(Test-Path $ProfileDir)) {
    New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
}
if (!(Test-Path $ProfilePath)) {
    New-Item -ItemType File -Path $ProfilePath -Force | Out-Null
}

$FunctionCode = @"

# Imperial-Shell - Freya Protocol Voice AI Assistant
function deathstar {
    & "$env:USERPROFILE\.imperial-shell\venv\Scripts\python.exe" "$env:USERPROFILE\.imperial-shell\imperial.py"
}

"@

# Check if function already exists
$profileContent = Get-Content $ProfilePath -Raw -ErrorAction SilentlyContinue
if ($profileContent -notmatch "function deathstar") {
    Add-Content -Path $ProfilePath -Value $FunctionCode
    Write-Host "    ✓ Added to PowerShell profile" -ForegroundColor Gray
} else {
    Write-Host "    ✓ Already in PowerShell profile" -ForegroundColor Gray
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Red
Write-Host "  ✓ IMPERIAL SHELL INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""
Write-Host "To activate Imperial Shell:" -ForegroundColor White
Write-Host ""
Write-Host "  1. Close this window" -ForegroundColor Cyan
Write-Host "  2. Restart PowerShell (new session)" -ForegroundColor Cyan
Write-Host "  3. Run command: deathstar" -ForegroundColor Red
Write-Host ""
Write-Host "Long live the Empire!" -ForegroundColor Red
Write-Host ""

Write-Log "Setup completed successfully!" "Green"
Write-Log "Log files saved to:" "Cyan"
Write-Log "  - Setup log: $LogFile" "Gray"
if (Test-Path $ErrorLogFile) {
    Write-Log "  - Error log: $ErrorLogFile" "Gray"
}

# Auto-close elevated window after 5 seconds
Write-Host "This window will close in 5 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 5