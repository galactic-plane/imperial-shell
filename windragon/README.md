![WinDragon](/img/windragon.jpeg)

# WinDragon Maintenance Script - v2.0.0

A menu-driven front end for a full, auditable Windows 11 maintenance pass: restore point,
DISM/SFC integrity repair, storage health and optimization, Windows Update / winget / Microsoft
Store servicing, security posture checks, cleanup and diagnostics - followed by a console summary,
a JSON result set and a standalone HTML report.

The maintenance engine is a **one-to-one replica** of the Imperial Maintenance Protocol
([../vader/Invoke-ImperialMaintenance.ps1](../vader/Invoke-ImperialMaintenance.ps1)): the same 29
tasks, levels, parameters, safety gates and reports. Only the interface differs. `Test-WinDragon.ps1`
proves the parity mechanically (see [Testing](#testing)).

## Requirements

- Windows 11 (build 22000+), validated against 24H2 / 25H2 / 26H2 servicing behaviour.
- PowerShell 7.x preferred; Windows PowerShell 5.1 supported.
- Administrator privileges. The script self-elevates unless `-NoElevatePrompt` is passed.

## Running it

### Interactive menu

```powershell
.\winDragon.ps1
```

After the disclaimer, the menu offers:

| # | Option | Equivalent vader invocation |
|---|---|---|
| 1 | Audit - read-only health assessment | `-Level Audit` |
| 2 | Quick - fast health pass | `-Level Quick` |
| 3 | Standard - full DISM/SFC repair chain, storage, cleanup, diagnostics | `-Level Standard` |
| 4 | Full - Standard + component store cleanup, deep cleanup | `-Level Full` |
| 5 | Run One Category... | `-OnlyTask <every task in the category>` |
| 6 | Run Selected Tasks... (e.g. `1,3,5-7`) | `-OnlyTask <picked tasks>` |
| 7 | Options | the switches and values below |
| 8 | List Task Catalogue | `-ListTasks` |
| 9 | Register Weekly Scheduled Task | `-RegisterScheduledTask` |
| 10 | Exit | |

Options 5 and 6 run at the "level for custom runs" shown in the menu header (default Standard).
Options 1-4 are one-shot passes and don't change that setting. With the level set to Audit,
options 5 and 6 skip any picked task that would modify the system, exactly like vader.

In a host that cannot prompt (`-NonInteractive`, a service session) the menu is not shown and
the script runs unattended with the given parameters, exactly like vader.

**Options menu** - toggles and values that apply to every run started from the menu:

| Option | Parameter |
|---|---|
| Install Windows Updates (incl. optional) | `-InstallWindowsUpdates` |
| Upgrade apps (winget + Microsoft Store) | `-UpgradeApps` |
| Run a Defender quick scan | `-IncludeDefenderScan` |
| Schedule CHKDSK /R at next boot | `-ScheduleChkdsk` |
| Reset component store base (Full) | `-ResetComponentStoreBase` |
| Repair the Windows Update stack | `-RepairWindowsUpdateStack` |
| Also run Disk Cleanup (cleanmgr) | `-UseDiskCleanup` |
| Skip the System Restore point | `-SkipRestorePoint` |
| Preview only - change nothing | `-WhatIf` |
| Confirm each change | `-Confirm` |
| Verbose output | `-Verbose` |
| Level for custom runs | `-Level` |
| DISM repair source | `-DismSource` |
| Event log days | `-EventLogDays` |
| Reports folder | `-LogRoot` |
| Skip tasks (wildcards) | `-SkipTask` |

Any of these passed on the command line pre-sets the menu, e.g. `.\winDragon.ps1 -UpgradeApps`.

### Unattended

Passing `-Level`, `-OnlyTask` or `-RunChoice` skips the menu and runs immediately, exactly like
the vader script:

```powershell
.\winDragon.ps1 -Level Audit
.\winDragon.ps1 -Level Full -InstallWindowsUpdates -UpgradeApps -IncludeDefenderScan
.\winDragon.ps1 -OnlyTask 'DISM*','SFC*' -Verbose
.\winDragon.ps1 -Level Standard -WhatIf
.\winDragon.ps1 -ListTasks                 # no elevation needed
.\winDragon.ps1 -RegisterScheduledTask

# By menu number (used by launcher.ps1): 1-4 = Audit/Quick/Standard/Full, 8 = list, 9 = schedule.
.\winDragon.ps1 -RunChoice 3
```

`launcher.ps1` is a small WPF window with one button per unattended menu option.

## Parameters

| Parameter | Description |
|---|---|
| `-Level` | `Audit` (read-only) / `Quick` / `Standard` (default) / `Full`. |
| `-SkipTask <string[]>` | Task names or wildcards to skip. |
| `-OnlyTask <string[]>` | Run only the named tasks (wildcards allowed). Overrides `-Level` selection, but `-Level Audit` still never runs a task that modifies the system. |
| `-ListTasks` | Print the task catalogue and exit. |
| `-InstallWindowsUpdates` | Download and install pending Windows Updates, including optional ones (preview cumulative updates, optional drivers, optional feature updates). Default is scan-only. |
| `-UpgradeApps` | `winget upgrade --all` against the `winget` and `msstore` sources. Skipped under SYSTEM. |
| `-IncludeDefenderScan` | Run a Microsoft Defender quick scan (signatures always refresh). |
| `-ScheduleChkdsk` | Schedule `autochk /r` at next boot for volumes the scan reports as dirty. |
| `-ResetComponentStoreBase` | Add `/ResetBase` to component store cleanup (updates become permanent). |
| `-RepairWindowsUpdateStack` | Stop the servicing stack, rename SoftwareDistribution/catroot2, restart it. |
| `-UseDiskCleanup` | Also run `cleanmgr.exe` with a scripted, allow-listed sageset profile. |
| `-SkipRestorePoint` | Don't create a System Restore checkpoint first. |
| `-DismSource <string>` | Repair source for DISM `/RestoreHealth`, e.g. `D:\sources\install.wim:1`. |
| `-EventLogDays <int>` | Days of critical/error events to summarise (1-90, default 7). |
| `-LogRoot <string>` | Reports root. Default `%ProgramData%\WinDragonMaintenance`. |
| `-RegisterScheduledTask` | Register a weekly SYSTEM task (Sundays 03:00, Standard level) and exit. |
| `-NoElevatePrompt` | Fail instead of relaunching elevated. |
| `-RunChoice <1-10>` | Run a menu option unattended (5-7 are interactive-only). |

`-WhatIf`, `-Confirm` and `-Verbose` are supported on every mutating task.

## Task catalogue

| Category | Tasks |
|---|---|
| Baseline | System Inventory, Servicing Lifecycle Check, Free Space Check, System Restore Point |
| Integrity | DISM Health Chain (CheckHealth -> ScanHealth -> RestoreHealth), SFC System File Scan, CBS Log Review, Component Store Cleanup (Full) |
| Storage | Physical Disk Health, Volume File System Scan, CHKDSK Scheduling, Volume Optimization |
| Servicing | Windows Update, Windows Update Stack Repair, Store App Update Scan, Winget & Store App Upgrade, PowerShell Hygiene (Full) |
| Security | Defender Health, Security Posture (firewall, Secure Boot, TPM, BitLocker, HVCI) |
| Cleanup | Temp and Cache Cleanup, Disk Cleanup Profile, Storage Sense Review |
| Diagnostics | Event Log Review, Driver and Device Health, Service Health, WMI Repository Check, Power Configuration, Startup Impact Review (Full), Pending Reboot Check |

Audit runs 18 tasks, Quick 9, Standard 26, Full 29. Menu option 8 shows the live list.

## Output

Each run creates `<LogRoot>\<yyyy-MM-dd_HHmmss>\` containing `transcript.log`, `results.json`,
`maintenance-report.html`, and on portables `battery-report.html` / `sleepstudy.html`.

## Layout

| File | Contents |
|---|---|
| `winDragon.ps1` | Parameters, module loading, elevation, scheduled-task registration, dispatch |
| `Modules/Core.ps1` | Constants, output helpers, native-command runner, task engine |
| `Modules/Baseline.ps1` ... `Diagnostics.ps1` | Task implementations, one module per category |
| `Modules/Reporting.ps1` | Console summary and HTML report |
| `Modules/Catalogue.ps1` | Ordered task catalogue |
| `Modules/Interface.ps1` | Dragon banner, menus, options, maintenance-run orchestration |
| `build.py` | Bundles everything into `build/winDragon_<version>.ps1` plus a web launcher |
| `Test-WinDragon.ps1` | Automated, non-destructive test suite |

## Testing

```powershell
.\Test-WinDragon.ps1                          # full suite
.\Test-WinDragon.ps1 -Only 'Parity*','Interface'
.\Test-WinDragon.ps1 -IncludeLive             # also run read-only tasks against this machine
```

The suite never performs a real repair, scan, cleanup, update, service change, registry write,
restore point, CHKDSK schedule or scheduled task registration. It checks:

- **Parity with vader** - every vader function, parameter, constant and top-level statement exists
  in WinDragon with a token-identical implementation (comments/whitespace ignored, branding
  normalised; only `Write-Banner`/`Write-Section` are restyled). The catalogue, lifecycle map and
  per-level task selection are compared across isolated processes, and `-ListTasks` output is
  compared byte-for-byte under PowerShell 7 and Windows PowerShell 5.1.
- **Task behaviour** - each task's decision logic with mocked DISM/SFC/fsutil/winget, Windows
  Update COM, services, registry, Defender and CIM, plus sandboxed file cleanup and `-WhatIf`.
- **Interface** - menus, pickers, options and the interactive loop driven by scripted input.
- **End-to-end** - a pass over a fake catalogue that writes real transcript/JSON/HTML reports.
- **Build** - `build.py` run against a temporary copy; the bundle must parse, keep every function
  identical and list the same tasks.

Exit code is `0` when everything passed or was skipped, `1` otherwise.

## Disclaimer
You are running this script at your own risk. Please ensure you have backups of your important data before running any maintenance tasks.

## License
This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.
