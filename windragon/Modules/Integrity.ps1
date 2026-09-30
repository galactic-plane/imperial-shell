# WinDragon - Integrity module
# DISM health chain, SFC, CBS.log review and component store cleanup.
# One-to-one replica of the "Task: integrity (DISM / SFC)" region of vader\Invoke-ImperialMaintenance.ps1.

#region ---------------------------------------------------------------- Task: integrity (DISM / SFC)

function Invoke-DismHealthChain {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$DismSource = $DismSource)
    <#
        Mandatory order: CheckHealth (instant flag read) -> ScanHealth (full scan) -> RestoreHealth
        (repair, only if needed). SFC runs after this, never before, because SFC sources its
        replacement files from the component store DISM repairs.
    #>
    $useModule = $null -ne (Get-Command Repair-WindowsImage -ErrorAction SilentlyContinue)
    $state = 'Unknown'

    # --- 1. CheckHealth ------------------------------------------------------
    Write-Info 'Step 1/3  CheckHealth  (reads the existing corruption flag - instant)'
    if ($useModule) {
        try {
            $check = Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop
            $state = $check.ImageHealthState
        } catch {
            $useModule = $false
        }
    }
    if (-not $useModule) {
        $r = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList @('/Online', '/Cleanup-Image', '/CheckHealth')
        if ($r.Output -match 'No component store corruption detected') { $state = 'Healthy' }
        elseif ($r.Output -match 'is repairable')                      { $state = 'Repairable' }
        elseif ($r.Output -match 'not repairable')                     { $state = 'NonRepairable' }
    }
    Write-Info "          Result: $state"

    # --- 2. ScanHealth -------------------------------------------------------
    Write-Info 'Step 2/3  ScanHealth   (full component store scan - typically 3-10 minutes)'
    if ($script:ReadOnlyRun -or $PSCmdlet.ShouldProcess('Component store', 'DISM ScanHealth')) {
        if ($useModule) {
            try {
                $scan = Repair-WindowsImage -Online -ScanHealth -ErrorAction Stop
                $state = $scan.ImageHealthState
            } catch {
                $r = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList @('/Online', '/Cleanup-Image', '/ScanHealth')
                if ($r.Output -match 'No component store corruption detected') { $state = 'Healthy' }
                elseif ($r.Output -match 'is repairable')                      { $state = 'Repairable' }
                elseif ($r.Output -match 'not repairable')                     { $state = 'NonRepairable' }
            }
        } else {
            $r = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList @('/Online', '/Cleanup-Image', '/ScanHealth')
            if ($r.Output -match 'No component store corruption detected') { $state = 'Healthy' }
            elseif ($r.Output -match 'is repairable')                      { $state = 'Repairable' }
            elseif ($r.Output -match 'not repairable')                     { $state = 'NonRepairable' }
        }
    }
    Write-Info "          Result: $state"

    if ($state -eq 'Healthy') {
        Write-Good 'Component store is healthy. RestoreHealth not required.'
        return @{ Status = 'OK'; Detail = 'Component store healthy' }
    }

    if ($script:ReadOnlyRun) {
        Write-Warn "Component store state: $state. Re-run without -Level Audit to repair."
        Add-Finding "DISM reports the component store is '$state'. Run a Standard or Full pass to repair it."
        return @{ Status = 'Warning'; Detail = "Store $state (audit mode, no repair)" }
    }

    # --- 3. RestoreHealth ----------------------------------------------------
    Write-Warn "Component store reports '$state'. Running RestoreHealth (can take 10-30 minutes)."
    if (-not $PSCmdlet.ShouldProcess('Component store', 'DISM RestoreHealth')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $dismArgs = @('/Online', '/Cleanup-Image', '/RestoreHealth')
    if ($DismSource) {
        Write-Info "          Using repair source: $DismSource"
        $dismArgs += "/Source:$DismSource"
        $dismArgs += '/LimitAccess'
    }
    $restore = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList $dismArgs

    # Exit code, not the localized console text, decides success.
    if ($restore.ExitCode -in 0, 3010) {
        Write-Good 'RestoreHealth completed successfully.'
        if ($restore.ExitCode -eq 3010) { Write-Warn 'A restart is required to finish this repair.' }
        $script:RebootNeeded = $true
        return @{ Status = 'Repaired'; Detail = 'Component store repaired' }
    }

    if ($restore.Output -match '0x800f081f') {
        Write-Bad 'DISM error 0x800F081F - repair payload not found via Windows Update.'
        Add-Finding 'DISM could not obtain repair files (0x800F081F). Re-run with -DismSource pointing at a matching install.wim, e.g. -DismSource "D:\sources\install.wim:1".'
        return @{ Status = 'Failed'; Detail = '0x800F081F - source required' }
    }
    if ($restore.Output -match '0x800f0906') {
        Add-Finding 'DISM error 0x800F0906 - the host could not download source files. Check connectivity, proxy, and WSUS/"Do not connect to Windows Update" policy.'
        return @{ Status = 'Failed'; Detail = '0x800F0906 - download failure' }
    }

    Write-Bad "RestoreHealth exit code $($restore.ExitCode)."
    Write-Verbose $restore.Output
    Add-Finding 'DISM RestoreHealth failed. Review C:\Windows\Logs\DISM\dism.log and consider an in-place repair upgrade.'
    return @{ Status = 'Failed'; Detail = "Exit $($restore.ExitCode)" }
}

function Invoke-SfcTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($script:ReadOnlyRun) {
        # sfc /verifyonly is the read-only equivalent.
        Write-Info 'Audit mode: running sfc /verifyonly (no changes).'
        $r = Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\sfc.exe" -ArgumentList @('/verifyonly')
        if ($r.Output -match 'did not find any integrity violations') {
            Write-Good 'No integrity violations found.'
            return @{ Status = 'OK'; Detail = 'No integrity violations' }
        }
        Add-Finding 'SFC verification found integrity violations. Run a Standard pass to repair them.'
        return @{ Status = 'Warning'; Detail = 'Integrity violations detected' }
    }

    if (-not $PSCmdlet.ShouldProcess('Protected system files', 'sfc /scannow')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    Write-Info 'Running sfc /scannow (typically 5-20 minutes). Output is captured, not streamed.'
    $sfcStart = Get-Date
    $r = Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\sfc.exe" -ArgumentList @('/scannow')

    if ($r.Output -match 'did not find any integrity violations') {
        Write-Good 'Windows Resource Protection found no integrity violations.'
        return @{ Status = 'OK'; Detail = 'No integrity violations' }
    }
    if ($r.Output -match 'successfully repaired them') {
        Write-Good 'Corrupt files were found and repaired.'
        $script:RebootNeeded = $true
        return @{ Status = 'Repaired'; Detail = 'Corrupt files repaired' }
    }
    if ($r.Output -match 'was unable to fix') {
        Write-Bad 'SFC found corruption it could not repair.'
        Add-Finding 'SFC could not repair some files. Re-run DISM /RestoreHealth (optionally with -DismSource), then SFC again. If it still fails, perform an in-place repair upgrade.'
        return @{ Status = 'Failed'; Detail = 'Unrepairable corruption' }
    }
    if ($r.Output -match 'could not perform the requested operation') {
        Add-Finding 'SFC could not run. Try again from Safe Mode, or after a reboot to clear a pending servicing operation.'
        return @{ Status = 'Failed'; Detail = 'SFC could not run' }
    }

    # sfc.exe's console text is localized and may not match any of the phrases above on a
    # non-English install; CBS.log's own trace markers are English/technical regardless of
    # UI language, so fall back to scanning the entries this run just produced.
    $cbsPath = "$env:SystemRoot\Logs\CBS\CBS.log"
    $sinceRun = Get-Content -Path $cbsPath -Tail 20000 -ErrorAction SilentlyContinue |
                Where-Object { $_ -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})' -and [datetime]$Matches[1] -ge $sfcStart }
    $unrepairedNow = @($sinceRun | Select-String -SimpleMatch 'cannot repair member file')
    $repairedNow   = @($sinceRun | Select-String -SimpleMatch 'Repairing corrupted file')
    if ($unrepairedNow.Count -gt 0) {
        Add-Finding 'SFC could not repair some files (per CBS.log). Re-run DISM /RestoreHealth, then SFC again.'
        return @{ Status = 'Failed'; Detail = 'Unrepairable corruption (CBS.log)' }
    }
    if ($repairedNow.Count -gt 0) {
        Write-Good 'Corrupt files were found and repaired (per CBS.log).'
        $script:RebootNeeded = $true
        return @{ Status = 'Repaired'; Detail = "$($repairedNow.Count) files repaired (CBS.log)" }
    }

    Write-Warn "SFC returned an unrecognised result (exit $($r.ExitCode))."
    Write-Verbose $r.Output
    return @{ Status = 'Warning'; Detail = "Exit $($r.ExitCode)" }
}

function Invoke-CbsLogReviewTask {
    $cbs = "$env:SystemRoot\Logs\CBS\CBS.log"
    if (-not (Test-Path $cbs)) { return @{ Status = 'Skipped'; Detail = 'CBS.log not present' } }

    $tail = Get-Content -Path $cbs -Tail 6000 -ErrorAction SilentlyContinue
    if (-not $tail) { return @{ Status = 'Skipped'; Detail = 'CBS.log unreadable' } }

    $repaired   = @($tail | Select-String -SimpleMatch 'Repairing corrupted file' -ErrorAction SilentlyContinue)
    $unrepaired = @($tail | Select-String -SimpleMatch 'cannot repair member file' -ErrorAction SilentlyContinue)

    Write-Info ("CBS tail: {0} repair entries, {1} unrepairable entries." -f $repaired.Count, $unrepaired.Count)

    if ($unrepaired.Count -gt 0) {
        $names = ($unrepaired | ForEach-Object {
            if ($_.Line -match 'member file \[l:\d+(?:\{\d+\})?\][''"]([^''"]+)[''"]') { $Matches[1] } } |
            Select-Object -Unique -First 10)
        foreach ($n in $names) { Write-Bad "  unrepairable: $n" }
        Add-Finding ("CBS.log lists {0} unrepairable member file entries. Full detail: {1}" -f $unrepaired.Count, $cbs)
        return @{ Status = 'Warning'; Detail = "$($unrepaired.Count) unrepairable entries in CBS.log" }
    }
    if ($repaired.Count -gt 0) {
        return @{ Status = 'Repaired'; Detail = "$($repaired.Count) files repaired per CBS.log" }
    }
    return @{ Status = 'OK'; Detail = 'No repair activity in recent CBS.log' }
}

function Invoke-ComponentStoreTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$ResetComponentStoreBase = $ResetComponentStoreBase)

    Write-Info 'Analysing component store (WinSxS)...'
    $analyze = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList @('/Online', '/Cleanup-Image', '/AnalyzeComponentStore')

    # DISM's "cleanup recommended" advisory is localized console text and unreliable to parse,
    # so it's shown for information only; StartComponentCleanup is a safe no-op when nothing
    # needs cleaning, so we don't gate the actual cleanup decision on it.
    $actual = $null
    if ($analyze.Output -match 'Actual Size of Component Store\s*:\s*(.+)')  { $actual = $Matches[1].Trim() }
    if ($actual) { Write-Info "WinSxS actual size: $actual" }

    if ($script:ReadOnlyRun) { return @{ Status = 'OK'; Detail = "WinSxS $actual" } }

    if (-not $PSCmdlet.ShouldProcess('WinSxS component store', 'DISM StartComponentCleanup')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $cleanArgs = @('/Online', '/Cleanup-Image', '/StartComponentCleanup')
    if ($ResetComponentStoreBase) {
        Write-Warn 'ResetBase requested: installed updates will become permanent and non-uninstallable.'
        $cleanArgs += '/ResetBase'
    }
    Write-Info 'Running component cleanup (can take 10-30 minutes)...'
    $clean = Invoke-NativeCommand -FilePath 'dism.exe' -ArgumentList $cleanArgs

    if ($clean.ExitCode -in 0, 3010) {
        Write-Good 'Component store cleanup completed.'
        if ($clean.ExitCode -eq 3010) { $script:RebootNeeded = $true }
        return @{ Status = 'Repaired'; Detail = "Cleanup completed (was $actual)" }
    }
    return @{ Status = 'Warning'; Detail = "StartComponentCleanup exit $($clean.ExitCode)" }
}

#endregion
