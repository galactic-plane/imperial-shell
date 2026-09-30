# Imperial-Shell - Voice AI Assistant
# The Empire's command interface for Windows 11

import asyncio
import base64
import getpass
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime

import edge_tts
import pygame
import speech_recognition as sr
from colorama import init, Fore, Style
from interpreter import interpreter

init(autoreset=True)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(os.path.expanduser("~"), ".imperial-shell", "runtimelog")
MODEL = "phi4:14b"
OLLAMA_URL = "http://localhost:11434"

# DISM /RestoreHealth and SFC /SCANNOW routinely run for 10-30 minutes.
COMMAND_TIMEOUT_SECONDS = 2 * 60 * 60
# phi4 has a 16K token context; keep command output in a prompt well below that.
MAX_ANALYSIS_CHARS = 12000

# Maintenance protocols shipped alongside Freya; launched in their own PowerShell window.
PROTOCOLS = {
    "vader": {
        "title": "Vader - Imperial Maintenance Protocol",
        "script": os.path.join("vader", "Invoke-ImperialMaintenance.ps1"),
        "options": [
            ("Audit - read-only health assessment", ["-Level", "Audit"], True),
            ("Quick - fast health pass", ["-Level", "Quick"], True),
            ("Standard - DISM/SFC repair, storage, cleanup, diagnostics", ["-Level", "Standard"], True),
            ("Full - Standard + component store and deep cleanup", ["-Level", "Full"], True),
            ("Preview a Standard run (-WhatIf, changes nothing)", ["-Level", "Standard", "-WhatIf"], True),
            ("List the task catalogue", ["-ListTasks"], False),
        ],
    },
    "windragon": {
        "title": "WinDragon - menu-driven maintenance",
        "script": os.path.join("windragon", "winDragon.ps1"),
        "options": None,
    },
}


def find_powershell():
    """Prefer PowerShell 7 for launched protocols; both scripts also support Windows PowerShell 5.1."""
    return shutil.which("pwsh") or shutil.which("powershell") or "powershell.exe"


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def encode_powershell_command(command):
    """Encode a command for -EncodedCommand so no quoting survives the trip through sudo/argv."""
    prelude = "$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; "
    return base64.b64encode((prelude + command).encode("utf-16-le")).decode("ascii")


def build_command_argv(command, elevated, sudo_path):
    """Menu commands target Windows PowerShell 5.1 (Get-EventLog and friends don't exist in 7)."""
    argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-EncodedCommand", encode_powershell_command(command)]
    if not elevated and sudo_path:
        argv.insert(0, sudo_path)
    return argv


def clean_output(text):
    # sfc.exe writes UTF-16 to pipes; once re-decoded the NULs are all that's left of it.
    return text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")


def run_streaming(argv, timeout=COMMAND_TIMEOUT_SECONDS, echo=print):
    """Run argv, echoing output live while also capturing it. Returns (output, exit_code, timed_out)."""
    lines = []
    timed_out = threading.Event()
    with subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
    ) as process:
        def _kill():
            timed_out.set()
            process.kill()

        timer = threading.Timer(timeout, _kill)
        timer.start()
        try:
            for line in process.stdout:
                line = clean_output(line).rstrip("\n")
                lines.append(line)
                if echo:
                    echo(line)
            process.wait()
        finally:
            timer.cancel()
    return "\n".join(lines).strip(), process.returncode, timed_out.is_set()


def build_protocol_launch(app_dir, key, extra_args):
    """Return (script_path, argument string) for launching a protocol in a new PowerShell window."""
    script = os.path.join(app_dir, PROTOCOLS[key]["script"])
    args = ["-NoExit", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script] + list(extra_args)
    return script, subprocess.list2cmdline(args)


def launch_protocol(app_dir, key, extra_args=(), elevate=True):
    """Open a protocol in a new PowerShell window. Returns (ok, message)."""
    shell = find_powershell()
    script, params = build_protocol_launch(app_dir, key, extra_args)
    if not os.path.isfile(script):
        return False, f"{PROTOCOLS[key]['title']} is not installed ({script}). Re-run setup-imperial-shell.ps1."
    workdir = os.path.dirname(script)
    if elevate and not is_admin():
        import ctypes
        # ShellExecute 'runas' shows the UAC prompt and always opens a new console window.
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", shell, params, workdir, 1)
        if rc <= 32:
            return False, "Launch cancelled or elevation was denied."
        return True, f"{PROTOCOLS[key]['title']} launched in a new elevated PowerShell window."
    subprocess.Popen(f'"{shell}" {params}', cwd=workdir, creationflags=subprocess.CREATE_NEW_CONSOLE)
    return True, f"{PROTOCOLS[key]['title']} launched in a new PowerShell window."


def truncate_for_prompt(text, limit=MAX_ANALYSIS_CHARS):
    if len(text) <= limit:
        return text
    # The tail usually carries the verdict (SFC/DISM summaries, errors), so keep it.
    return f"[... {len(text) - limit} earlier characters omitted ...]\n" + text[-limit:]


class ImperialShell:
    def __init__(self):
        print(f"{Fore.RED}{'═' * 60}")
        print(f"{Fore.WHITE}    ⬡ FREYA PROTOCOL ACTIVE ⬡")
        print(f"{Fore.RED}    'Standing by for orders, Commander'")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
        
        # Set FREYA_VOICE=0 for text-only mode (no TTS, microphone or music).
        self.VOICE_MODE = os.environ.get("FREYA_VOICE", "1") != "0"
        
        # Background music for login screen
        self.login_music_playing = False
        
        # Persistent event loop for the async TTS calls
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        if not self.VOICE_MODE:
            print(f"{Fore.YELLOW}⚙ VOICE MODE DISABLED - Text-only mode{Style.RESET_ALL}\n")
        
        # Setup runtime logging
        self.runtime_log_dir = LOG_DIR
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
        # Freya only analyses output here; the menu system runs every command itself.
        interpreter.llm.model = f"ollama/{MODEL}"
        interpreter.llm.api_base = OLLAMA_URL
        interpreter.llm.supports_functions = False
        interpreter.llm.context_window = 16000
        interpreter.llm.max_tokens = 1200
        interpreter.auto_run = False
        interpreter.offline = True
        interpreter.max_output = 5000
        
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
                ("Optimize All Volumes (TRIM for SSD, defrag for HDD)", "Get-Volume | Where-Object {$_.DriveLetter -and $_.FileSystem -eq 'NTFS' -and $_.DriveType -eq 'Fixed'} | ForEach-Object {Write-Output \"Optimizing volume $($_.DriveLetter):...\"; Optimize-Volume -DriveLetter $_.DriveLetter -Verbose}"),
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
                ("System Performance Counters", "Get-Counter '\\Processor(_Total)\\% Processor Time','\\Memory\\Available MBytes','\\PhysicalDisk(_Total)\\% Disk Time' -SampleInterval 2 -MaxSamples 5"),
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
                ("Clear Temp Files", "Remove-Item -Path (Join-Path $env:TEMP '*') -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path (Join-Path $env:SystemRoot 'Temp\\*') -Recurse -Force -ErrorAction SilentlyContinue"),
                ("Remove Windows.old", "$p = Join-Path $env:SystemDrive 'Windows.old'; if (-not (Test-Path -LiteralPath $p)) { 'Windows.old is not present.' } else { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue; if (Test-Path -LiteralPath $p) { 'Some Windows.old files are protected. Finish in Settings > System > Storage > Temporary files > Previous Windows installation(s).' } else { 'Windows.old removed.' } }"),
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
        
        # Irreversible or disruptive commands ask for confirmation before running.
        self.confirm_required = {
            "Reset Network Stack",
            "Component Cleanup",
            "Clear Temp Files",
            "Remove Windows.old",
            "Empty Recycle Bin",
            "Update All Winget Packages",
        }
        
        self.current_menu = None
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
        # Listed after the command categories on the main menu.
        self.protocol_entries = [(key, PROTOCOLS[key]["title"]) for key in ("vader", "windragon")]
        
        interpreter.system_message = """You are Freya, a powerful and strategic Imperial AI protocol for Windows systems.

Your role is to analyse the output of Windows maintenance commands that the Commander has already run
from Freya's menu, and to answer follow-up questions about that analysis.

RULES:
1. Never write or run code. The menu system executes every command itself.
2. Answer in plain prose, concisely and professionally.
3. When you recommend an action, name the Freya menu category or the exact Windows command to use.
"""
        
        # Verify Ollama connection
        try:
            import requests
            response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
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
            except Exception:
                print(f"{Fore.RED}⚠ No microphone detected. Voice input disabled.{Style.RESET_ALL}")
                self.microphone = None
        else:
            self.recognizer = None
            self.microphone = None
    
    def play_login_music(self):
        """Play Imperial March during login screen"""
        if not self.audio_enabled:
            return
        try:
            music_file = os.path.join(APP_DIR, "imperial_march.mp3")
            
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
        if not self.audio_enabled:
            return
        try:
            # Stop login music first
            self.stop_login_music()
            
            music_file = os.path.join(APP_DIR, "order66.mp3")
            
            if os.path.exists(music_file):
                pygame.mixer.music.load(music_file)
                pygame.mixer.music.play()
                self.log_runtime("Order 66 initiated")
                
                # Wait for playback to finish
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
        except OSError:
            # Logging must never interrupt the session
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
            # pygame keeps the file open until unloaded, which blocks the delete below on Windows
            pygame.mixer.music.unload()
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Audio playback error: {e}{Style.RESET_ALL}")
            self.log_runtime(f"ERROR - Audio playback: {e}")
        finally:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except OSError:
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
    
    def show_main_menu(self):
        """Display main menu with all command categories and the maintenance protocols"""
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
        print(f"{Fore.CYAN}{Style.BRIGHT}IMPERIAL MAINTENANCE PROTOCOLS{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}(open in a new PowerShell window){Style.RESET_ALL}")
        for offset, (key, title) in enumerate(self.protocol_entries, len(self.menu_categories) + 1):
            print(f"{Fore.YELLOW}[{offset:2d}]{Style.RESET_ALL} {Fore.WHITE}Launch {title}{Style.RESET_ALL}")
        
        print(f"\n{Fore.RED}{'─' * 60}{Style.RESET_ALL}")
        summary = f"✓ {len(self.menu_categories)} command categories, {len(self.protocol_entries)} protocols available"
        print(f"{Fore.GREEN}{summary:^60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
    
    def main_menu_keys(self):
        """Selectable main menu keys, in display order (categories, then protocols)."""
        return [key for key, _ in self.menu_categories] + [key for key, _ in self.protocol_entries]
    
    def get_main_menu_selection(self):
        """Get main menu selection: a command category key or a protocol key"""
        keys = self.main_menu_keys()
        while True:
            try:
                print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{Style.BRIGHT}SELECT CATEGORY{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
                selection = input(f"{Fore.WHITE}⬢ Enter menu number{Style.RESET_ALL} [{Fore.YELLOW}1-{len(keys)}{Style.RESET_ALL}] {Fore.WHITE}or{Style.RESET_ALL} [{Fore.RED}'exit'{Style.RESET_ALL}]: ").strip()
                
                if selection.lower() in ['exit', 'quit', 'q']:
                    return None
                
                try:
                    num = int(selection)
                    if 1 <= num <= len(keys):
                        return keys[num - 1]
                    else:
                        print(f"{Fore.RED}Invalid selection. Please choose 1-{len(keys)}{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}Please enter a valid number{Style.RESET_ALL}")
            except (EOFError, KeyboardInterrupt):
                return None
    
    def show_protocol_menu(self, key):
        """Launch vader or WinDragon in a new PowerShell window, picking a run level for vader."""
        protocol = PROTOCOLS[key]
        extra_args, elevate = [], True
        if protocol["options"]:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{Style.BRIGHT}{'⬢ ' + protocol['title'].upper() + ' ⬢':^60}{Style.RESET_ALL}")
            print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
            for idx, (label, _, _) in enumerate(protocol["options"], 1):
                print(f"{Fore.YELLOW}[{idx:2d}]{Style.RESET_ALL} {Fore.WHITE}{label}{Style.RESET_ALL}")
            print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}\n")
            count = len(protocol["options"])
            while True:
                selection = input(f"{Fore.WHITE}⬢ Enter number{Style.RESET_ALL} [{Fore.YELLOW}1-{count}{Style.RESET_ALL}] {Fore.WHITE}or{Style.RESET_ALL} [{Fore.RED}'back'{Style.RESET_ALL}]: ").strip().lower()
                if selection in ['', 'back', 'cancel', 'exit', 'quit']:
                    self.log_runtime(f"Protocol launch cancelled: {key}")
                    return
                if selection.isdigit() and 1 <= int(selection) <= count:
                    _, extra_args, elevate = protocol["options"][int(selection) - 1]
                    break
                print(f"{Fore.RED}Please enter a number between 1 and {count}{Style.RESET_ALL}")
        
        self.log_runtime(f"LAUNCHING PROTOCOL: {key} {' '.join(extra_args)}")
        try:
            ok, message = launch_protocol(APP_DIR, key, extra_args, elevate)
        except OSError as e:
            ok, message = False, f"Launch failed: {e}"
        self.log_runtime(message, "INFO" if ok else "ERROR")
        self.speak(message if ok else f"{message} Returning to main menu.")
        input(f"\n{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
    
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
        """Run a menu command (elevated via sudo when needed), streaming its output live."""
        elevated = is_admin()
        sudo_path = None if elevated else shutil.which("sudo")
        if not elevated and not sudo_path:
            print(f"{Fore.YELLOW}⚠ sudo is unavailable - running without elevation; admin-only commands may fail.{Style.RESET_ALL}\n")
        argv = build_command_argv(command, elevated, sudo_path)
        
        try:
            output, exit_code, timed_out = run_streaming(argv)
        except OSError as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            return f"Error: {e}"
        
        # Output was already echoed live; only the trailer still needs showing.
        if timed_out:
            note = f"Error: Command timed out after {COMMAND_TIMEOUT_SECONDS // 60} minutes"
        elif exit_code:
            note = f"(exit code {exit_code})"
        elif not output:
            note = "Command completed successfully."
        else:
            note = ""
        if note:
            print(f"{Fore.YELLOW}{note}{Style.RESET_ALL}")
        return "\n".join(part for part in (output, note) if part)
    
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
                password = getpass.getpass(f"{Fore.CYAN}│ {Fore.WHITE}⬢ NEURAL KEY:{Style.RESET_ALL} ")
                print(f"{Fore.CYAN}└{'─' * 58}{Style.RESET_ALL}")
                
                if username.lower() == "vader" and password == "Password123$":
                    # Stop login music on successful authentication
                    self.stop_login_music()
                    
                    print(f"\n{Fore.CYAN}[{Style.RESET_ALL}{Fore.GREEN}●{Style.RESET_ALL}{Fore.CYAN}]{Style.RESET_ALL} {Fore.GREEN}Biometric scan verified{Style.RESET_ALL}")
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
                
                if category in PROTOCOLS:
                    self.show_protocol_menu(category)
                    continue
                
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
                    
                    if description in self.confirm_required:
                        self.speak(f"{description} modifies the system. Confirm your order, Commander.")
                        confirm = input(f"{Fore.YELLOW}⚠ {description} modifies the system. Proceed?{Style.RESET_ALL} (y/N): ").strip().lower()
                        if confirm not in ('y', 'yes'):
                            self.log_runtime(f"CANCELLED: {description}")
                            self.speak("Order rescinded. Returning to main menu.")
                            self.current_menu = None
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
                    
                    # Execute the command directly via subprocess (output streams live)
                    result = self.execute_powershell_command(cmd_to_run)
                    print()
                    self.log_runtime(f"COMMAND OUTPUT:\n{result}")
                    self.log_runtime(f"COMMAND COMPLETED: {description}")
                    
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
                        
                        output_content = f"EXECUTED: {cmd_to_run}\n{'=' * 80}\nOUTPUT:\n{truncate_for_prompt(result)}"
                        # Each analysis starts a fresh conversation; follow-ups below build on it.
                        interpreter.messages = []
                        
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
                            
                            self.log_runtime(f"AI ANALYSIS:\n{analysis_text}")
                            
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
                                    
                                    self.log_runtime(f"FREYA RESPONSE:\n{response_text}")
                                
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
