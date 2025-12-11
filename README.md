# 🎯 Freya Imperial Shell

<div align="center">

![Platform](https://img.shields.io/badge/platform-Windows%2011-blue?style=for-the-badge&logo=windows11)
![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-5391FE?style=for-the-badge&logo=powershell)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Ollama%20%7C%20Phi--4-FF6F00?style=for-the-badge&logo=ai)
![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)

</div>

> **An intelligent Windows maintenance assistant with AI analysis, powered by local AI**

Freya is an Imperial-themed AI assistant that combines intelligent command analysis, natural language processing, and voice synthesis to provide a comprehensive Windows system maintenance experience. Built with PowerShell 7+ compatibility and utilizing local AI models through Ollama for complete privacy and offline operation.

---

## ✨ Features

### Core Capabilities
- 🤖 **Local AI Intelligence** - Powered by Microsoft Phi-4 (14B) via Ollama - completely offline
- 🧠 **AI Command Analysis** - Freya analyzes command output and answers questions about results
- 💬 **Interactive Q&A** - Ask follow-up questions about any command execution
- 🛠️ **System Maintenance** - 15 categories with 55 Windows maintenance commands
- 📋 **Menu-Driven Interface** - Easy keyboard-based navigation through organized command menus
- 🔐 **Elevated Permissions** - Automatic sudo elevation for admin tasks on Windows 11
- 📝 **Complete Session Logging** - Every interaction, command, and AI response logged
- 🎨 **Imperial Theme** - Immersive Star Wars interface with Darth Vader ASCII art and audio
- 🎵 **Immersive Audio** - Imperial March plays during login, Order 66 executes on security lockout
- 🔊 **Voice Synthesis** - Freya speaks all responses using Edge TTS with natural voice
- 🔄 **Intelligent Workflow** - Seamless flow from command execution to AI analysis to Q&A

---

## 🚀 Quick Start

### Prerequisites

- **Windows 11** (Build 22000+) - For sudo support
- **PowerShell 7+** - Modern PowerShell
- **Internet connection** - For initial setup, voice synthesis, and voice recognition
- **Microphone** - Optional, for voice input during Q&A sessions
- **Speakers/Headphones** - For audio features and voice responses

### Automatic Installation

1. **Clone the repository:**
```powershell
git clone https://github.com/yourusername/imperial-shell.git
cd imperial-shell
```

2. **Run the setup script as Administrator:**
```powershell
.\setup-imperial-shell.ps1
```

The automated setup script will:
- ✅ Enable Windows 11 `sudo` command
- ✅ Install Python 3.12 (if needed)
- ✅ Install Rust compiler (required for some Python packages)
- ✅ Install Ollama AI runtime
- ✅ Download Microsoft Phi-4 14B model (~9GB)
- ✅ Create Python virtual environment
- ✅ Install all Python dependencies (Open Interpreter, Edge TTS, SpeechRecognition, pygame, etc.)
- ✅ Create the Freya application script
- ✅ Copy audio files (imperial_march.mp3, order66.mp3)
- ✅ Add `deathstar` command to your PowerShell profile
- ✅ Configure complete logging system

**Installation Time:** ~15-20 minutes depending on internet speed

3. **Reload your PowerShell profile:**
```powershell
. $PROFILE
```
*Or simply restart your PowerShell terminal*

4. **Launch Freya:**
```powershell
deathstar
```

### First Run

When you first launch Freya, you'll see:
- Imperial ASCII art banner with background music (Imperial March)
- System initialization messages
- Voice synthesis test (Freya introduces herself)
- Authentication prompt

**Default Credentials:**
- **Username:** `vador`
- **Password:** `Password123$`

⚠️ **Warning:** Enter the wrong password 3 times and Order 66 will be executed!

---

## 🎮 Using Freya

### Input Methods

Freya uses **keyboard-based menu navigation** for command selection:
- **Main Menu:** Enter a number (1-15) to select a category
- **Command Selection:** Enter a number to execute a command
- **Text Input:** Type questions during AI Q&A sessions
- **Voice Input:** Speak questions during Q&A sessions (optional, requires microphone)

### Basic Workflow

1. **Select a Command Category** (keyboard)
   - View the main menu with 15 categories
   - Type a number (1-15) to open that category's menu
   - Or type `exit` to quit

2. **Select a Command** (keyboard)
   - View available commands in the category
   - Type the number of the command you want
   - Or type `back` to return to main menu

3. **Command Execution**
   - Freya executes the command with sudo elevation
   - Full verbose output displayed in real-time
   - Command and output logged to session file

4. **AI Analysis** (optional)
   - Choose `y` to get AI analysis of command output
   - Freya summarizes what happened in plain English
   - Choose `n` to skip analysis

5. **Interactive Q&A** (optional)
   - Choose `y` to ask questions about the analysis
   - Select input method: 1 (Voice), 2 (Type), or 3 (Exit)
   - Voice option uses microphone and speech recognition
   - Type option uses keyboard input
   - Ask unlimited follow-up questions
   - Choose `n` when done to return to main menu

---

## 📂 Command Categories

The following command categories are available in Freya:

| # | Category | Commands | Description |
|---|----------|----------|-------------|
| 1 | **System** | 4 commands | System info (fastfetch), Windows version, uptime, admin check |
| 2 | **Disk** | 6 commands | Disk errors, cleanup, usage, large files, TRIM, SMART health |
| 3 | **SFC** | 2 commands | System file integrity scan and verification |
| 4 | **DISM** | 4 commands | Windows image health check, scan, repair, cleanup |
| 5 | **Network** | 6 commands | IP config, DNS flush, connectivity test, WiFi profiles |
| 6 | **Performance** | 4 commands | Top processes by CPU/memory, counters, startup programs |
| 7 | **Services** | 3 commands | Running/stopped services, scheduled tasks |
| 8 | **Logs** | 3 commands | System/application errors, critical events |
| 9 | **Hardware** | 4 commands | Hardware info, battery status, physical disks, device issues |
| 10 | **Drivers** | 2 commands | List all drivers, identify problem devices |
| 11 | **Updates** | 4 commands | Windows Update, update history, winget package updates |
| 12 | **Power** | 4 commands | Power plans, battery report, sleep states |
| 13 | **Cleanup** | 4 commands | Clear temp files, remove Windows.old, empty recycle bin |
| 14 | **Users** | 3 commands | List local users/groups, current user info |
| 15 | **Features** | 2 commands | Enabled/disabled Windows optional features |

**Total:** 55 maintenance commands across 15 categories

---

### Example Session

```
════════════════════════════════════════════════════════════
            DEATH STAR COMMAND NETWORK
        SECURE TERMINAL • LEVEL 10 CLEARANCE REQUIRED
────────────────────────────────────────────────────────────
           SYSTEM ID: FREYA-PROTOCOL-001
          LOCATION: IMPERIAL COMMAND BRIDGE
════════════════════════════════════════════════════════════

[Darth Vader ASCII art displayed]
[♫ Imperial March playing in background ♫]

════════════════════════════════════════════════════════════
  ⚠ RESTRICTED ACCESS - AUTHORIZED PERSONNEL ONLY
════════════════════════════════════════════════════════════

┌─[AUTHENTICATION SEQUENCE]─────────────────────────
│ ⬢ IMPERIAL ID: vador
│ ⬢ NEURAL KEY: ********
└──────────────────────────────────────────────────

[●] Biometric scan verified
[●] Neural signature authenticated
[●] Clearance Level 10 confirmed

════════════════════════════════════════════════════════════
           ✓ ACCESS GRANTED - WELCOME, LORD VADER
════════════════════════════════════════════════════════════

[♫ Music stops ♫]

════════════════════════════════════════════════════════════
      FREYA PROTOCOL • ARTIFICIAL INTELLIGENCE CORE
────────────────────────────────────────────────────────────
  Initializing neural networks...
  ✓ Quantum processors online
  ✓ Voice synthesis matrix ready
  ✓ Command execution modules loaded
  ✓ Imperial database synchronized
────────────────────────────────────────────────────────────
           ⬡ SYSTEM STATUS: OPERATIONAL ⬡
════════════════════════════════════════════════════════════

⬡ Freya: Welcome, Master Vader. I am Freya, your Imperial AI 
         protocol. All systems are operational and ready to serve.
         How may I assist you?

════════════════════════════════════════════════════════════
               ⬡ IMPERIAL COMMAND MATRIX ⬡
════════════════════════════════════════════════════════════
[ 1] System Information
[ 2] Disk Management
[ 3] System File Checker
[ 4] DISM Repair
[ 5] Network Diagnostics
[ 6] Performance Monitoring
[ 7] Services Management
[ 8] System Logs
[ 9] Hardware Sensors
[10] Driver Management
[11] Windows Updates
[12] Power Management
[13] Disk Cleanup
[14] User Management
[15] Windows Features
────────────────────────────────────────────────────────────
                  ✓ 15 categories available
════════════════════════════════════════════════════════════

⬡ Freya: What would you like to do, Commander?

────────────────────────────────────────────────────────────
⬢ Enter category number [1-15] or ['exit']: 2

════════════════════════════════════════════════════════════
             ⬢ DISK COMMAND MATRIX ⬢
════════════════════════════════════════════════════════════
[ 1] Check Disk for Errors
[ 2] Disk Cleanup
[ 3] Show Disk Usage
[ 4] Find Large Files (>1GB)
[ 5] Optimize All Volumes (TRIM for SSD/NVMe)
[ 6] SMART Drive Health
────────────────────────────────────────────────────────────
                  ✓ 6 commands available
════════════════════════════════════════════════════════════

⬡ Freya: I've prepared the disk commands menu for you, Commander.

────────────────────────────────────────────────────────────
                    SELECT COMMAND
────────────────────────────────────────────────────────────
⬢ Enter number [1-6] or ['back']: 5

════════════════════════════════════════════════════════════
              ⬢ COMMAND EXECUTION INITIATED
────────────────────────────────────────────────────────────
Task: Optimize All Volumes (TRIM for SSD/NVMe)
Cmd:  Get-Volume | Where-Object {$_.DriveLetter -and $_.File...
────────────────────────────────────────────────────────────
⚙ Processing...
════════════════════════════════════════════════════════════

[Command output displays here...]

════════════════════════════════════════════════════════════
              ✓ COMMAND EXECUTION COMPLETE
════════════════════════════════════════════════════════════

⬡ Freya: Command executed, Commander.

────────────────────────────────────────────────────────────
⬢ Enter [y] for analysis or [n] to skip: y

────────────────────────────────────────────────────────────
                     AI ANALYSIS
────────────────────────────────────────────────────────────
⚙ Analyzing command output...

⬡ Freya: The TRIM optimization has been successfully completed for 
         all your SSD and NVMe volumes. This process helps maintain 
         optimal performance by informing the drive which data blocks 
         are no longer in use...

────────────────────────────────────────────────────────────
⬢ Enter [y] to continue Q&A or [n] to return: y

⬡ Freya: How may I clarify this analysis for you?

⬢ Your question: What does TRIM actually do?

⬡ Freya: TRIM is a command that tells your SSD which blocks of data
         are no longer needed. When you delete files, the file system
         marks them as deleted, but the SSD doesn't know until TRIM
         informs it. This allows the drive to erase those blocks in
         advance, improving write performance and extending drive life...

⬢ Enter [y] to continue Q&A or [n] to return: n

⬡ Freya: Acknowledged, Commander. Freya Protocol entering standby mode.
         The Empire awaits your return.
```

---

## 📂 Command Categories

| Category | Description | Example Commands |
|----------|-------------|------------------|
| **System** | System info, uptime, admin check | fastfetch, Windows version |
| **Disk** | Disk health, cleanup, optimization | TRIM, SMART status, disk usage |
| **Network** | Network diagnostics | IP config, DNS flush, ping test |
| **Performance** | Resource monitoring | Top processes, CPU/memory usage |
| **SFC** | System file integrity | System file scan |
| **DISM** | Windows image repair | Health check, restore image |
| **Services** | Windows services | Running services, scheduled tasks |
| **Logs** | Event logs | System errors, application logs |
| **Hardware** | Hardware sensors | Temperature, battery status |
| **Drivers** | Driver management | List drivers, problem devices |
| **Updates** | Windows Update | Check/install updates |
| **Power** | Power management | Power plans, battery report |
| **Cleanup** | Disk cleanup | Temp files, recycle bin |
| **Users** | User management | Local users, groups |
| **Features** | Windows features | Enabled/disabled features |

---

## 🔧 Configuration & Customization

### Voice Mode Toggle

Voice synthesis (Freya speaking) is always enabled. The VOICE_MODE flag in the script controls whether voice INPUT (microphone) is available for Q&A sessions.

Edit `$env:USERPROFILE\.imperial-shell\imperial.py` if needed:

```python
def __init__(self):
    # ...
    self.VOICE_MODE = True  # Change to False to disable voice input
```

**Voice capabilities:**
- Freya's spoken responses and greetings (always enabled)
- Q&A session voice input (controlled by VOICE_MODE, requires microphone)

### Changing the AI Model

The AI model can be changed by editing `imperial.py`:

```python
interpreter.llm.model = "ollama/phi4:14b"
```

**Recommended Models:**

| Model | Size | Quality | Speed | Use Case |
|-------|------|---------|-------|----------|
| `llama3.2:3b` | 2.0GB | Good | Fast | Quick responses, limited RAM |
| `qwen2.5:7b` | 4.7GB | Great | Medium | Balanced performance ⭐ |
| `phi4:14b` | 9.1GB | Excellent | Medium | Best quality (default) ⭐⭐ |
| `llama3.3:70b` | 43GB | Superior | Slow | Maximum intelligence |

**To download a different model:**
```powershell
ollama pull llama3.2:3b
```

---

### Custom Voice Settings

Freya uses Edge TTS with the voice `en-US-AriaNeural`. To change:

Edit the `speak_async()` method in `imperial.py`:
```python
self.voice = "en-GB-SoniaNeural"  # British female
self.voice = "en-US-GuyNeural"    # US male
self.voice = "en-AU-NatashaNeural" # Australian female
```

---

### Logging Configuration

**Log Location:**
```
C:\Users\<YourUsername>\.imperial-shell\runtimelog\
```

**Log File Format:**
```
freya_session_YYYYMMDD_HHMMSS.log
```

**What Gets Logged:**
- Timestamp for every event
- Text inputs
- Menu selections  
- Command executions
- Full command output
- AI analysis responses
- Q&A interactions
- Errors and warnings

**Setup Logs:**
- `$env:USERPROFILE\.imperial-shell\setup-log.txt` - Installation progress
- `$env:USERPROFILE\.imperial-shell\setup-errors.txt` - Installation errors

---

## 🛠️ Technical Details

### Technology Stack

**Core Runtime:**
- **Python 3.12+** - Application runtime
- **PowerShell 7+** - Command execution and Windows integration
- **Open Interpreter** - AI command execution and code interpretation framework

**AI & Intelligence:**
- **Ollama** - Local LLM inference engine (runs completely offline)
- **Microsoft Phi-4 14B** - Primary AI model for analysis and Q&A
- **Context-aware prompting** - Maintains conversation context across Q&A sessions

**Voice & Audio:**
- **Edge TTS** - High-quality text-to-speech synthesis
- **SpeechRecognition** - Voice command input (Google Speech API)
- **PyAudio** - Audio stream processing
- **Pygame** - Audio playback engine

**UI & Display:**
- **Colorama** - Cross-platform colored terminal output
- **Custom ASCII art** - Imperial theming
- **Getpass** - Secure password input

**Utilities:**
- **Requests** - HTTP client for API calls
- **Rust** - Required for some Python package compilation

### System Architecture

```
┌─────────────────────────────────────────────────────┐
│           User (Keyboard Input + Audio)             │
└────────────────────┬────────────────────────────────┘
                     │
         ┌───────────▼──────────┐
         │   Freya Controller   │
         │  (Command Routing)   │
         └───────────┬──────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼────┐    ┌──────▼──────┐   ┌───▼────┐
│ Menu   │    │  PowerShell │   │  AI    │
│ System │    │   Commands  │   │Analysis│
│(Keybd) │    │  (w/ sudo)  │   │  Q&A   │
└───┬────┘    └──────┬──────┘   └───┬────┘
    │                │                │
    │         ┌──────▼──────┐         │
    │         │   Command   │         │
    │         │   Output    │         │
    │         └──────┬──────┘         │
    │                │                │
    │         ┌──────▼──────┐         │
    └─────────►  Ollama AI  ◄─────────┘
              │  (Phi-4)    │
              │  Local LLM  │
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │  Edge TTS   │
              │  (Voice     │
              │  Synthesis) │
              └──────┬──────┘
                     │
         ┌───────────▼──────────┐
         │  Audio Playback      │
         │  - Freya responses   │
         │  - Imperial March    │
         │  - Order 66          │
         └──────────────────────┘
                     │
              ┌──────▼──────┐
              │ User Output │
              │   + Logs    │
              └─────────────┘
```

### Directory Structure

```
imperial-shell/                    # Git repository
├── setup-imperial-shell.ps1       # Main setup script (creates everything)
├── README.md                      # This documentation
└── .gitignore                     # Git ignore rules

C:\Users\<YourUsername>\.imperial-shell\  # Installation directory
├── imperial.py                    # Main Freya application (auto-generated)
├── venv/                          # Python virtual environment
│   ├── Scripts/                   # Executable scripts
│   └── Lib/                       # Python packages
├── runtimelog/                    # Session logs directory
│   └── freya_session_*.log        # Individual session logs
├── setup-log.txt                  # Setup installation log
└── setup-errors.txt               # Setup error log

PowerShell Profile                 # Auto-modified during setup
└── function deathstar { ... }     # Quick launch command
```

### AI Analysis System

Freya's AI analysis works in two stages:

**1. Command Output Analysis:**
- Captures full command output
- Sends to Ollama with context about the command
- Generates human-readable summary
- Speaks key findings

**2. Interactive Q&A:**
- Maintains conversation context
- Remembers the original command and analysis
- Answers follow-up questions in context
- Supports unlimited questions per command

**Example AI Prompt Flow:**
```python
# Initial Analysis
f"""You are Freya, an Imperial AI. Analyze this command output:
COMMAND: {description}
OUTPUT: {output}
Provide a brief summary..."""

# Follow-up Question
f"""You previously analyzed: {command}
YOUR ANALYSIS: {previous_analysis}
QUESTION: {user_question}
Provide a clear answer in context..."""
```

---

## 🎯 Example Workflow

```
You: "disk"
Freya: "I've prepared the disk commands menu for you, Commander."

[Menu displays with 6 options]

You: [Type] "5"
Freya: "Executing Optimize All Volumes (TRIM for SSD/NVMe)"

[Command executes with verbose output]

Freya: "Command executed, Commander."
```

---

## 🔐 Security Notes

- Commands run with **sudo elevation** for admin tasks
- All commands are logged for audit purposes
- Voice recognition uses Google Speech API (requires internet)
- AI model runs **locally** via Ollama (no cloud processing)

---

## 🐛 Troubleshooting

### Common Issues

#### Ollama Service Not Running
**Error:** "Failed to connect to Ollama"

**Solution:**
```powershell
# Start Ollama service
ollama serve

# In another terminal, verify it's running
ollama list
```

**Auto-start on boot (optional):**
Create a scheduled task or add to startup

---

#### Model Not Downloaded
**Error:** "Model phi4:14b not found"

**Solution:**
```powershell
# Download the model manually
ollama pull phi4:14b

# Verify download
ollama list
```

---

---

#### Permission Errors / Sudo Not Working
**Error:** "sudo command not found" or permission denied

**Solutions:**

1. **Enable sudo manually (Windows 11):**
   - Open Settings → System → For Developers
   - Enable "sudo for Windows"

2. **Run as Administrator:**
   - Right-click PowerShell 7
   - Choose "Run as Administrator"

3. **Check Windows version:**
   ```powershell
   [System.Environment]::OSVersion.Version
   # Build should be 22000 or higher for sudo support
   ```

---

#### Python Module Import Errors
**Error:** "ModuleNotFoundError: No module named 'xyz'"

**Solution:**
```powershell
# Activate virtual environment
& $env:USERPROFILE\.imperial-shell\venv\Scripts\Activate.ps1

# Reinstall requirements
pip install --upgrade open-interpreter colorama edge-tts pygame SpeechRecognition requests

# Deactivate
deactivate
```

---

#### Slow AI Responses
**Issue:** AI takes too long to respond

**Solutions:**

1. **Switch to smaller model:**
   ```powershell
   ollama pull llama3.2:3b
   ```
   Edit `imperial.py`: `interpreter.llm.model = "ollama/llama3.2:3b"`

2. **Check system resources:**
   - AI models need significant RAM
   - Phi-4 14B: ~16GB RAM recommended
   - Close other applications

3. **Verify Ollama performance:**
   ```powershell
   ollama run phi4:14b "test"
   # Should respond in 1-3 seconds
   ```

---

#### TTS (Text-to-Speech) Not Working
**Symptoms:** No audio output from Freya

**Solutions:**

1. **Check audio output:**
   - Verify speakers/headphones connected
   - Test with other audio

2. **Reinstall Edge TTS:**
   ```powershell
   & $env:USERPROFILE\.imperial-shell\venv\Scripts\Activate.ps1
   pip install --upgrade edge-tts pygame
   ```

3. **Check for file permissions:**
   - Ensure `$env:USERPROFILE\.imperial-shell\runtimelog\` is writable

---

#### Setup Script Fails
**Error during installation**

**Check logs:**
```powershell
# View setup log
cat ~/.imperial-shell/setup-log.txt

# View errors
cat ~/.imperial-shell/setup-errors.txt
```

**Common fixes:**
- Ensure running as Administrator
- Check internet connection
- Disable antivirus temporarily
- Ensure sufficient disk space (~15GB)

---

### Getting Help

**Check logs first:**
```powershell
# Setup issues
cat $env:USERPROFILE\.imperial-shell\setup-log.txt
cat $env:USERPROFILE\.imperial-shell\setup-errors.txt

# Runtime issues  
cat $env:USERPROFILE\.imperial-shell\runtimelog\freya_session_*.log | Select-Object -Last 100
```

**Reset and reinstall:**
```powershell
# Remove installation directory
Remove-Item -Recurse -Force $env:USERPROFILE\.imperial-shell

# Remove from profile (edit the CurrentUserAllHosts profile)
notepad $PROFILE.CurrentUserAllHosts
# Delete the "Imperial-Shell" function block

# Re-run setup
.\setup-imperial-shell.ps1
```

---

## 🎯 What Makes Freya Special

### Intelligence Layer
Unlike simple command launchers, Freya **understands** what commands do:
- Analyzes output in real-time
- Explains results in plain English
- Answers questions about command execution
- Provides context-aware recommendations

### Complete Privacy
- **100% local AI** - No cloud services for AI processing
- **Offline AI** - Ollama runs completely offline
- **Voice services** - Speech recognition and synthesis require internet (Google API, Edge TTS)
- **Your data stays yours** - All analysis happens on your machine

### Adaptive Input
- **Menu navigation** - Keyboard-only for reliable command selection
- **Q&A sessions** - Choose between voice or text input per question
- **Voice fallback** - Voice recognition failures automatically revert to typing
- **Flexible interaction** - Switch input methods based on your preference

### Imperial Experience
- Immersive Star Wars themed interface
- Darth Vader ASCII art
- Military-style command structure  
- "Commander" honorific in all interactions
- Authentic Imperial atmosphere

---

---

## 🔐 Security & Privacy

### Data Handling
- **Command Logs:** Stored locally in `$env:USERPROFILE\.imperial-shell\runtimelog\`
- **AI Processing:** 100% local via Ollama (no data sent to cloud)
- **Voice Synthesis:** Uses Edge TTS (Microsoft cloud service for speech generation)
- **Credentials:** Stored in script (hardcoded - suitable for personal use)
- **Audio Files:** Stored locally (imperial_march.mp3, order66.mp3)

### Privilege Escalation
- Uses Windows 11 `sudo` for elevation
- Only elevates when needed per command
- All elevated actions logged
- User remains in control

### Network Access
- **Setup:** Requires internet for downloads
- **Runtime:** Requires internet for voice features (speech recognition via Google API, synthesis via Edge TTS)
- **AI:** No internet needed (fully local via Ollama)
- **Offline mode:** AI analysis works offline; voice input/output requires internet

### Recommendations for Enhanced Security
1. Change default credentials in `imperial.py`
2. Review command list - disable unwanted categories
3. Run in isolated environment for testing
4. Regularly review session logs
5. Understand that voice synthesis uses Microsoft Edge TTS cloud service

---

## 🚀 Advanced Usage

### Creating Custom Command Categories

Edit `imperial.py` to add new categories:

```python
"custom": {
    "description": "Custom maintenance commands",
    "commands": {
        "1": {
            "desc": "My Custom Command",
            "cmd": "powershell -Command 'Your-Command-Here'"
        }
    }
}
```

### Scheduling Automated Maintenance

Since Freya requires keyboard input for navigation, you can run PowerShell commands directly for automation:

```powershell
# maintenance-routine.ps1
Write-Host "Starting automated maintenance..." -ForegroundColor Cyan

# Clear temp files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# TRIM optimization for SSDs
Get-Volume | Where-Object {$_.DriveLetter -and $_.FileSystem -eq 'NTFS'} | ForEach-Object {
    Write-Host "Optimizing volume $($_.DriveLetter):..." -ForegroundColor Cyan
    Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim -Verbose
}

# System file check
sfc /SCANNOW

Write-Host "Maintenance complete!" -ForegroundColor Green
```

You can then schedule this with Task Scheduler for automated maintenance.

---

## 📊 System Requirements

### Minimum
- **OS:** Windows 11 Build 22000+
- **RAM:** 12GB (for Phi-4 14B model)
- **Storage:** 15GB free space
- **CPU:** Modern multi-core processor (4+ cores recommended)
- **PowerShell:** 7.0 or higher

### Recommended
- **OS:** Windows 11 22H2 or later
- **RAM:** 16GB or more
- **Storage:** SSD with 20GB+ free space
- **CPU:** 6+ core processor with good single-thread performance
- **PowerShell:** Latest version (7.4+)
- **Microphone:** For voice commands

### Optional
- **GPU:** Not utilized (CPU-only inference)
- **Internet:** Only for setup and voice recognition

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

### Potential Enhancements
- [ ] Add more command categories (Registry, Backups, Security)
- [ ] Multi-language support
- [ ] Custom voice personality options
- [ ] Command history and favorites
- [ ] Automated maintenance scheduling
- [ ] GUI overlay option
- [ ] Plugin system for extensions
- [ ] Multi-user support with profiles
- [ ] Enhanced error recovery
- [ ] Command chaining capability

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Test thoroughly on Windows 11
4. Ensure PowerShell 7+ compatibility
5. Update documentation
6. Submit a pull request

---

## 📄 License

This project is provided as-is for personal and educational use. 

**Use Responsibly:** System maintenance commands can affect system stability. Always understand what a command does before executing it.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgments

### Powered By
- **[Open Interpreter](https://github.com/KillianLucas/open-interpreter)** - AI code execution framework
- **[Ollama](https://ollama.ai/)** - Local LLM runtime
- **[Microsoft Phi-4](https://huggingface.co/microsoft/phi-4)** - 14B parameter language model
- **[Edge TTS](https://github.com/rany2/edge-tts)** - Microsoft Edge text-to-speech
- **[SpeechRecognition](https://pypi.org/project/SpeechRecognition/)** - Multi-engine speech recognition

### Inspiration
- **Star Wars Universe** - Imperial theme and aesthetic
- **Jarvis/TARS** - AI assistant interaction paradigms
- **PowerShell Community** - Windows automation expertise

---

## 📞 Support

**Issues?** Check troubleshooting section first

**Found a bug?** Open an issue with:
- Windows version and build
- PowerShell version
- Steps to reproduce
- Relevant log excerpts

**Feature requests?** Open an issue describing:
- Use case
- Expected behavior
- Potential implementation approach

---

## 🎖️ Credits

**Created by:** Daniel Penrod  
**Last Updated:** December 11, 2025 7:58 AM EST

---

<div align="center">

**⚔️ Long live the Empire! ⚔️**

*"The power to maintain your system is insignificant next to the power of the Force... and Freya."*

Made with 🖤 for the Galactic Empire

</div>
