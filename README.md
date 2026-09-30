# Freya Imperial Shell

<div align="center">

![Platform](https://img.shields.io/badge/platform-Windows%2011-blue?style=for-the-badge&logo=windows11)
![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-5391FE?style=for-the-badge&logo=powershell)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Ollama%20%7C%20Phi--4-FF6F00?style=for-the-badge&logo=ai)
![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)

</div>

> An Imperial-themed Windows 11 maintenance suite: an AI assistant plus two full maintenance engines, all running locally

Imperial Shell has three parts:

| Component | What it is | Docs |
|---|---|---|
| **Freya** | Voice-enabled AI assistant. Menu-driven Windows maintenance commands, with local AI (Phi-4 via Ollama) analysing the output and answering follow-up questions. Launched with `deathstar`. | this file |
| **vader** | *Imperial Maintenance Protocol* - a single-file, auditable maintenance pass (29 tasks: DISM/SFC repair, storage, Windows Update/winget, security, cleanup, diagnostics) with JSON and HTML reports. | [vader/README.md](vader/README.md) |
| **WinDragon** | A menu-driven, one-to-one replica of the vader engine. | [windragon/README.md](windragon/README.md) |

Freya can launch vader or WinDragon in a new PowerShell window straight from its main menu.

---

## Features

- **Local AI** - Microsoft Phi-4 (14B) through Ollama; command output never leaves the machine.
- **AI command analysis** - Freya reviews each command's output, flags problems and suggests fixes, then takes follow-up questions (typed or spoken).
- **55 maintenance commands in 15 categories** - system, disk, SFC, DISM, network, performance, services, event logs, hardware, drivers, updates, power, cleanup, users, Windows features.
- **Maintenance protocols** - main menu items 16 and 17 open vader (pick Audit / Quick / Standard / Full / Preview / List tasks) or WinDragon's own menu in a new, elevated PowerShell window.
- **Live output** - command output streams as it runs; long jobs (DISM, SFC) get up to 2 hours.
- **Automatic elevation** - commands run through Windows `sudo` (inline mode), or directly when Freya is already elevated.
- **Safety prompts** - disruptive commands (network reset, component cleanup, temp/Recycle Bin/Windows.old removal, winget upgrade-all) ask for confirmation first.
- **Session logging** - every command, output, AI answer and protocol launch is logged.
- **Imperial theme** - Vader ASCII art, the Imperial March at login, Order 66 on lockout, and Edge TTS voice responses.

---

## Quick Start

### Prerequisites

- **Windows 11** - `sudo` needs 24H2 (build 26100) or later; on older builds Freya still works when started from an elevated terminal.
- **PowerShell 7+** - `winget install --id Microsoft.PowerShell --exact --source winget`
- **winget** (App Installer) - ships with Windows 11.
- **~12 GB free disk space** - mostly the Phi-4 model (~9 GB).
- **Internet connection** - for setup, voice synthesis and voice recognition. The AI itself runs offline.
- Optional: microphone (spoken questions), speakers/headphones (voice and music).

### Installation

1. **Clone the repository:**

   ```powershell
   git clone https://github.com/galactic-plane/imperial-shell.git
   cd imperial-shell
   ```

2. **Run the setup script** (from any PowerShell; it relaunches itself as Administrator in PowerShell 7):

   ```powershell
   .\setup-imperial-shell.ps1
   ```

   If script execution is blocked, run `pwsh -ExecutionPolicy Bypass -File .\setup-imperial-shell.ps1`.

3. **Open a new PowerShell 7 window and launch Freya:**

   ```powershell
   deathstar
   ```

Setup is idempotent: re-run it at any time to upgrade Python packages, Ollama, the model and the installed copies of Freya, vader and WinDragon.

### What setup does

| Step | Detail |
|---|---|
| Elevation | Relaunches itself elevated in PowerShell 7 (`-EncodedCommand`, so any install path is safe). The elevated window waits for Enter before closing. |
| sudo | Enables Windows `sudo` in **inline** mode (Freya must capture elevated output; "new window" mode can't). Skipped with a notice before 24H2. |
| Python 3.12 | Installs/upgrades via winget. Pinned to 3.12 because open-interpreter's `tiktoken` pin has no prebuilt wheels for newer Pythons - no Rust or C++ toolchain is needed. |
| Ollama + model | Installs/upgrades Ollama, starts the service if needed and pulls `phi4:14b` (3 attempts). |
| fastfetch | Installed for the System/Hardware "fastfetch" commands. |
| Payload | Copies `freya/imperial.py`, `freya/requirements.txt`, the audio files and the vader / WinDragon runtime files to the install folder, clearing stale protocol files. |
| Virtual environment | Creates (or repairs) a Python 3.12 venv and installs `freya/requirements.txt`; PyAudio is optional. |
| Profile | Adds a marker-delimited `deathstar` function to `$PROFILE.CurrentUserAllHosts`. Re-runs update it in place; the unmarked block from older versions is migrated. |

The default install path is `%USERPROFILE%\.imperial-shell`; pass `-InstallPath <folder>` to change it.

> **Note:** Elevation must happen as *your* account. If UAC asks for a different administrator's credentials, setup installs into that account's profile instead.

---

## Using Freya

### Login

The login screen plays the Imperial March. Default credentials:

- **Username:** `vader`
- **Password:** `Password123$`

Three wrong attempts execute Order 66. The login is part of the theme, **not a security control** - anyone who can run `deathstar` can read the credentials in `imperial.py`.

### Main menu

| # | Category | # | Category |
|---|---|---|---|
| 1 | System Information | 2 | Disk Operations |
| 3 | System File Checker | 4 | DISM Repair Tools |
| 5 | Network Diagnostics | 6 | Performance Monitor |
| 7 | Services Management | 8 | Event Logs |
| 9 | Hardware Info | 10 | Driver Management |
| 11 | Windows Updates | 12 | Power Management |
| 13 | System Cleanup | 14 | User Management |
| 15 | Windows Features | | |
| **16** | **Launch Vader - Imperial Maintenance Protocol** | **17** | **Launch WinDragon** |

Type `exit` (or `q`) to leave.

**Categories 1-15:** pick a command, it runs (elevated via `sudo`) with live output, then Freya offers an AI analysis followed by a Q&A loop (voice or typed).

**16 - vader:** choose a run, which opens in a new elevated PowerShell window (`-NoExit`, so the summary stays on screen):

| Option | Runs |
|---|---|
| Audit | `Invoke-ImperialMaintenance.ps1 -Level Audit` (read-only) |
| Quick | `-Level Quick` |
| Standard | `-Level Standard` |
| Full | `-Level Full` |
| Preview | `-Level Standard -WhatIf` (changes nothing) |
| List tasks | `-ListTasks` (no elevation) |

**17 - WinDragon:** opens `winDragon.ps1` and its interactive menu in a new elevated PowerShell window.

The UAC prompt appears once per launch; declining it returns you to the main menu. Both protocols prefer PowerShell 7 and fall back to Windows PowerShell 5.1. For the full switch set (e.g. `-InstallWindowsUpdates`, `-UpgradeApps`), run them directly - see [vader/README.md](vader/README.md) and [windragon/README.md](windragon/README.md).

### Text-only mode

Set `FREYA_VOICE=0` to skip TTS, the microphone and music:

```powershell
$env:FREYA_VOICE = '0'; deathstar
```

---

## Files and logs

| Location | Contents |
|---|---|
| `%USERPROFILE%\.imperial-shell\imperial.py` | Freya (copied from `freya/imperial.py`) |
| `%USERPROFILE%\.imperial-shell\venv\` | Python 3.12 virtual environment |
| `%USERPROFILE%\.imperial-shell\vader\`, `windragon\` | Installed maintenance protocols |
| `%USERPROFILE%\.imperial-shell\setup-log.txt` / `setup-errors.txt` | Setup log and warnings/errors |
| `%USERPROFILE%\.imperial-shell\runtimelog\freya_session_*.log` | One log per Freya session |
| `%ProgramData%\ImperialMaintenance\` | vader reports (transcript, JSON, HTML) |
| `%ProgramData%\WinDragonMaintenance\` | WinDragon reports |

### Repository layout

```
setup-imperial-shell.ps1     Installer
Test-ImperialShell.ps1       Test suite for the installer and Freya
imperial_march.mp3           Login music
order66.mp3                  Lockout sound
freya/
    imperial.py              Freya application
    requirements.txt         Python dependencies
    test_imperial.py         Freya unit tests
vader/                       Imperial Maintenance Protocol (+ its tests)
windragon/                   WinDragon (+ its tests, build script and WPF launcher)
```

---

## Testing

All suites are non-destructive: system calls are mocked, file work uses temp folders, and nothing is installed or elevated.

```powershell
# Installer + Freya (also runs the Python tests and PSScriptAnalyzer when installed)
pwsh -NoProfile -File .\Test-ImperialShell.ps1

# Freya only (any Python 3.9+; third-party modules are stubbed)
python -m unittest discover -s freya -p "test_*.py"

# The maintenance protocols
pwsh -NoProfile -File .\vader\Test-ImperialMaintenance.ps1
pwsh -NoProfile -File .\windragon\Test-WinDragon.ps1
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `deathstar` not found | Open a new PowerShell 7 window, or run `. $PROFILE.CurrentUserAllHosts`. |
| "Ollama may not be running" | Start the Ollama app or run `ollama serve`, then `ollama pull phi4:14b`. |
| "sudo is unavailable" | Enable sudo in Settings > System > Advanced (24H2+), or start `deathstar` from an elevated terminal. |
| Commands produce no output | sudo is in "new window" mode - re-run setup or choose *Inline* in Settings > System > Advanced. |
| No voice input | PyAudio failed to install or no microphone - typed questions still work. |
| Setup failed | See `setup-errors.txt` in the install folder, fix the cause, re-run setup. |

### Uninstall

1. Delete `%USERPROFILE%\.imperial-shell`.
2. Remove the block between `# >>> imperial-shell >>>` and `# <<< imperial-shell <<<` from your PowerShell profile.
3. Optionally uninstall Ollama, Python 3.12 and fastfetch with `winget uninstall`.

---

## Security notes

- Freya's menu commands run elevated. Read the command shown before execution; disruptive ones ask for confirmation.
- `sudo` inline mode lets an elevated process share your console. Microsoft documents this as less isolated than "new window" mode; setup enables it because Freya needs the output.
- The AI only analyses output. It is configured not to generate or run code (`auto_run` off, no OS mode).
- Voice recognition sends audio to Google's speech API; TTS uses Microsoft Edge's online service. Typed input and the AI stay local.

---

## Acknowledgments

### Powered By
- **[Open Interpreter](https://github.com/KillianLucas/open-interpreter)** - AI code execution framework
- **[Ollama](https://ollama.ai/)** - Local LLM runtime
- **[Microsoft Phi-4](https://huggingface.co/microsoft/phi-4)** - 14B parameter language model
- **[Edge TTS](https://github.com/rany2/edge-tts)** - Microsoft Edge text-to-speech
- **[SpeechRecognition](https://pypi.org/project/SpeechRecognition/)** - Multi-engine speech recognition
- **[fastfetch](https://github.com/fastfetch-cli/fastfetch)** - System information display

### Inspiration
- **Star Wars Universe** - Imperial theme and aesthetic
- **Jarvis/TARS** - AI assistant interaction paradigms
- **PowerShell Community** - Windows automation expertise

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. WinDragon is licensed separately under the GNU GPL v3 - see [windragon/LICENSE](windragon/LICENSE).

**Use Responsibly:** System maintenance commands can affect system stability. Always understand what a command does before executing it.

<div align="center">

**Long live the Empire!**

*"The power to maintain your system is insignificant next to the power of the Force... and Freya."*

Made with love for the Galactic Empire

</div>
