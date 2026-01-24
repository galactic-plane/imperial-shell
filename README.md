# Freya Imperial Shell

<div align="center">

![Platform](https://img.shields.io/badge/platform-Windows%2011-blue?style=for-the-badge&logo=windows11)
![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-5391FE?style=for-the-badge&logo=powershell)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Ollama%20%7C%20Phi--4-FF6F00?style=for-the-badge&logo=ai)
![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)

</div>

> An intelligent Windows maintenance assistant with AI analysis, powered by local AI

Freya is an Imperial-themed AI assistant that combines intelligent command analysis, natural language processing, and voice synthesis to provide a comprehensive Windows system maintenance experience. Built with PowerShell 7+ compatibility and utilizing local AI models through Ollama for complete privacy and offline operation.

---

## Features

### Core Capabilities
- **Local AI Intelligence** - Powered by Microsoft Phi-4 (14B) via Ollama - completely offline
- **AI Command Analysis** - Freya analyzes command output and answers questions about results
- **Interactive Q&A** - Ask follow-up questions about any command execution
- **System Maintenance** - 15 categories with 55 Windows maintenance commands
- **Menu-Driven Interface** - Easy keyboard-based navigation through organized command menus
- **Elevated Permissions** - Automatic sudo elevation for admin tasks on Windows 11
- **Complete Session Logging** - Every interaction, command, and AI response logged
- **Imperial Theme** - Immersive Star Wars interface with Darth Vader ASCII art and audio
- **Immersive Audio** - Imperial March plays during login, Order 66 executes on security lockout
- **Voice Synthesis** - Freya speaks all responses using Edge TTS with natural voice
- **Intelligent Workflow** - Seamless flow from command execution to AI analysis to Q&A

---

## Quick Start

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

> **Note:** Replace `yourusername` with your actual GitHub username if you've forked this repository.

2. **Run the setup script as Administrator:**
```powershell
.\setup-imperial-shell.ps1
```

The automated setup script will:
- Enable Windows 11 `sudo` command
- Install Python 3.12 (if needed)
- Install Rust compiler (required for some Python packages)
- Install Ollama AI runtime
- Download Microsoft Phi-4 14B model (~9GB)
- Create Python virtual environment
- Install all Python dependencies (Open Interpreter, Edge TTS, SpeechRecognition, pygame, etc.)
- Create the Freya application script
- Copy audio files (imperial_march.mp3, order66.mp3)
- Add `deathstar` command to your PowerShell profile
- Configure complete logging system

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

**Warning:** Enter the wrong password 3 times and Order 66 will be executed!

---

## Acknowledgments

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Use Responsibly:** System maintenance commands can affect system stability. Always understand what a command does before executing it.

<div align="center">

**Long live the Empire!**

*"The power to maintain your system is insignificant next to the power of the Force... and Freya."*

Made with love for the Galactic Empire

</div>
