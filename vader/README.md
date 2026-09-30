# Imperial Maintenance Protocol

A single-file PowerShell script that runs a full, auditable Windows 11 maintenance pass: system
restore point, DISM/SFC integrity repair, storage health and optimization, Windows Update/winget
servicing, security posture checks, cleanup, and diagnostics — then produces a console summary,
JSON result set, and a standalone HTML report.

```
Invoke-ImperialMaintenance.ps1
```

## Requirements

- Windows 11 (build 22000+), validated against 24H2 / 25H2 / 26H2 servicing behaviour.
- PowerShell 7.x preferred; Windows PowerShell 5.1 supported as a fallback.
- Administrator privileges. The script self-elevates by relaunching itself unless `-NoElevatePrompt`
  is passed, in which case it fails fast instead of prompting.

## Quick start

```powershell
# Read-only health assessment. Nothing is modified.
.\Invoke-ImperialMaintenance.ps1 -Level Audit

# Default: restore point, DISM/SFC repair chain, cleanup, diagnostics.
.\Invoke-ImperialMaintenance.ps1

# Everything, including installs/upgrades. Expect 30-90 minutes and a reboot afterwards.
.\Invoke-ImperialMaintenance.ps1 -Level Full -InstallWindowsUpdates -UpgradeApps -IncludeDefenderScan

# Preview what a run would do without changing anything.
.\Invoke-ImperialMaintenance.ps1 -WhatIf

# Just the integrity repair chain.
.\Invoke-ImperialMaintenance.ps1 -OnlyTask 'DISM*','SFC*' -Verbose

# See the full task catalogue without running anything (no elevation needed).
.\Invoke-ImperialMaintenance.ps1 -ListTasks
```

## Safety model

- **`-Level Audit`** is read-only by design — every task it runs is diagnostic only.
- **`-WhatIf` / `-Confirm`** are supported on every mutating task, including per-target-path
  previews in the cleanup task (each file location, the Recycle Bin, DNS cache flush, and the
  Delivery Optimization purge are gated individually).
- A **System Restore point** is created before repairs run (unless `-SkipRestorePoint`).
- Every task reports `OK` / `Repaired` / `Warning` / `Failed` / `Skipped` with a duration, so a run
  is auditable rather than a wall of console noise — see the console summary, `results.json`, and
  `maintenance-report.html` after each run.
- Native tool calls (`dism.exe`, `sfc.exe`, `fsutil.exe`, `winget.exe`, ...) run with a timeout and
  closed stdin, so an unexpected prompt or a hung tool can't stall the whole pass indefinitely.

## Parameters

| Parameter | Description |
|---|---|
| `-Level` | `Audit` (read-only) / `Quick` / `Standard` (default) / `Full`. Controls which tasks run. |
| `-SkipTask <string[]>` | Task names or wildcards to skip. See `-ListTasks`. |
| `-OnlyTask <string[]>` | Run only the named tasks (wildcards allowed). Overrides `-Level` selection, but `-Level Audit` still never runs a task that modifies the system. |
| `-ListTasks` | Print the task catalogue and exit. No elevation required. |
| `-InstallWindowsUpdates` | Download and install pending Windows Updates (default is scan-only). |
| `-UpgradeApps` | Run `winget upgrade --all` (winget source + `msstore` source, so Microsoft Store apps are covered too). Skipped automatically under SYSTEM. |
| `-IncludeDefenderScan` | Run a Microsoft Defender quick scan (signatures always refresh regardless). |
| `-ScheduleChkdsk` | Schedule `autochk /r` at next boot for any volume the scan reports as dirty. |
| `-ResetComponentStoreBase` | Add `/ResetBase` to component store cleanup (updates become permanent). Full level only. |
| `-RepairWindowsUpdateStack` | Stop the servicing stack, rename SoftwareDistribution/catroot2, restart it. Forces a reboot recommendation. |
| `-UseDiskCleanup` | Also drive `cleanmgr.exe` via a scripted, allow-listed sageset profile. |
| `-SkipRestorePoint` | Don't create a System Restore checkpoint before making changes. |
| `-DismSource <string>` | Repair source for DISM `/RestoreHealth` (e.g. `D:\sources\install.wim:1`) when Windows Update can't supply payload. |
| `-EventLogDays <int>` | Days of System/Application critical+error events to summarise. Default 7 (1-90). |
| `-LogRoot <string>` | Root folder for transcripts, JSON and HTML reports. Default `%ProgramData%\ImperialMaintenance`. |
| `-RegisterScheduledTask` | Register a weekly SYSTEM scheduled task (Sundays 03:00) at Standard level, then exit. |
| `-NoElevatePrompt` | Fail instead of relaunching elevated when not running as Administrator. |

Standard PowerShell common parameters (`-WhatIf`, `-Confirm`, `-Verbose`, etc.) are also supported.

## Task catalogue

Tasks run in this order, grouped by category. `RunsAt` shows which `-Level` includes the task;
`AuditSafe` tasks are read-only and also run under `-Level Audit`.

**Baseline** — System Inventory, Servicing Lifecycle Check, Free Space Check, System Restore Point

**Integrity** — DISM Health Chain (CheckHealth → ScanHealth → RestoreHealth), SFC System File Scan,
CBS Log Review, Component Store Cleanup (Full only)

**Storage** — Physical Disk Health, Volume File System Scan, CHKDSK Scheduling, Volume Optimization

**Servicing** — Windows Update, Windows Update Stack Repair, Store App Update Scan, Winget & Store
App Upgrade (`winget upgrade --all` against both the `winget` and `msstore` sources), PowerShell
Hygiene (Full only)

**Security** — Defender Health, Security Posture (firewall, Secure Boot, TPM, BitLocker, HVCI)

**Cleanup** — Temp and Cache Cleanup, Disk Cleanup Profile, Storage Sense Review

**Diagnostics** — Event Log Review, Driver and Device Health, Service Health, WMI Repository Check,
Power Configuration, Startup Impact Review (Full only), Pending Reboot Check

Run `.\Invoke-ImperialMaintenance.ps1 -ListTasks` for the live, authoritative list with each task's
level and audit-safety.

## Output

Each run creates a timestamped folder under `-LogRoot` (default
`%ProgramData%\ImperialMaintenance\<yyyy-MM-dd_HHmmss>\`) containing:

- `transcript.log` — full console transcript
- `results.json` — structured task results, findings, and system snapshot
- `maintenance-report.html` — standalone HTML report
- `battery-report.html` / `sleepstudy.html` — on portables, when applicable

## Scheduling

`-RegisterScheduledTask` registers a weekly task (Sundays 03:00, running as SYSTEM at `Standard`
level with `-SkipRestorePoint`). Note that under SYSTEM, per-user operations (winget, Defender
quick scan initiation quirks, per-user temp/cache cleanup, Recycle Bin) only affect the SYSTEM
profile — run those interactively for real per-user cleanup.

## Notes

- Some operations can run for a long time: DISM `/RestoreHealth` (10-30 min), `sfc /scannow`
  (5-20 min), full CHKDSK `/R` passes (hours) — only `-ScheduleChkdsk` queues the last one, it
  doesn't run during the pass itself.
- A restart is often required to complete servicing work; the script tracks this and calls it out
  clearly in the summary and reports. Use **Restart**, not Shut Down — Fast Startup skips a true
  cold boot.

## Testing

`Test-ImperialMaintenance.ps1` is an automated test suite for this script. It loads the real
functions (via the `-ListTasks` early-return path, so Main/elevation never runs) and exercises
them with `-WhatIf`, disposable sandbox directories, mocked native-command calls, and static AST
checks. Each check prints a green checkmark (pass) or a red X (fail, with the reason).

It never performs the script's destructive actions: no DISM repair, no `sfc /scannow`, no
`BootExecute`/registry mutation, no service stop/rename, no scheduled task registration, no
`winget upgrade` (mocked), and no file deletion outside a disposable sandbox it creates and
cleans up itself.

It is **not** network/IO-silent, though: it runs plenty of real read-only queries against the
actual machine (disk, firewall, TPM, BitLocker, event log, services, registry), performs a real
`Repair-Volume -Scan` (Microsoft's own online, non-mutating NTFS scan) against every real fixed
volume, and briefly spawns/kills a couple of real `powershell.exe` processes to test the timeout
logic. Windows Update search (network-touching, COM-based) is opt-in via `-IncludeSlow` and
skipped by default.

```powershell
# Run the full suite.
.\Test-ImperialMaintenance.ps1

# Run only matching sections.
.\Test-ImperialMaintenance.ps1 -Only 'Cleanup*','Winget*'

# Also run the real (read-only) Windows Update search, skipped by default to avoid network calls.
.\Test-ImperialMaintenance.ps1 -IncludeSlow
```

Exit code is `0` when everything passed/skipped, `1` if anything failed.

