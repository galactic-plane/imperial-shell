# WinDragon - Diagnostics module
# Event log review, driver/device health, WMI repository, service health, power configuration,
# startup impact and pending reboot detection.
# One-to-one replica of the "Task: diagnostics" region of vader\Invoke-ImperialMaintenance.ps1.

#region ---------------------------------------------------------------- Task: diagnostics

function Invoke-EventLogReviewTask {
    $since = (Get-Date).AddDays(-$EventLogDays)
    $summary = @()

    foreach ($log in 'System', 'Application') {
        try {
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName   = $log
                Level     = 1, 2      # Critical, Error
                StartTime = $since
            } -ErrorAction Stop)
        } catch {
            continue   # no matching events
        }

        if ($events.Count -eq 0) { continue }
        Write-Info ("{0} log: {1} critical/error events in the last {2} days" -f $log, $events.Count, $EventLogDays)

        $top = $events | Group-Object -Property Id, ProviderName |
               Sort-Object Count -Descending | Select-Object -First 6
        $top | ForEach-Object {
            $sample = $_.Group[0]
            Write-Host ("      {0,4}x  Id {1,-6} {2}" -f $_.Count, $sample.Id, $sample.ProviderName) -ForegroundColor Gray
        }
        $summary += "$log=$($events.Count)"
    }

    # Unexpected shutdowns and bugchecks.
    $critical = @()
    foreach ($id in 41, 1001, 6008) {
        try {
            $e = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $id; StartTime = $since } -ErrorAction Stop)
            if ($e.Count -gt 0) { $critical += "Event $id x$($e.Count)" }
        } catch { }
    }
    if ($critical.Count -gt 0) {
        Write-Warn ("Instability indicators: {0}" -f ($critical -join ', '))
        Add-Finding ("System log shows {0} in the last {1} days (41=unexpected shutdown, 1001=bugcheck, 6008=dirty shutdown). Investigate drivers and memory." -f ($critical -join ', '), $EventLogDays)
    }

    # Minidumps.
    $dumpDir = "$env:SystemRoot\Minidump"
    if (Test-Path $dumpDir) {
        $dumps = @(Get-ChildItem -LiteralPath $dumpDir -Filter '*.dmp' -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -gt $since })
        if ($dumps.Count -gt 0) {
            Write-Warn "$($dumps.Count) crash dump(s) in $dumpDir within the window."
            $dumps | Select-Object -First 5 | ForEach-Object {
                Write-Host ("      {0:yyyy-MM-dd HH:mm}  {1}" -f $_.LastWriteTime, $_.Name) -ForegroundColor Gray
            }
            Add-Finding "Crash dumps present in $dumpDir. Analyse with WinDbg (!analyze -v) or check Reliability Monitor."
        }
    }

    if ($critical.Count -gt 0) { return @{ Status = 'Warning'; Detail = ($critical -join ', ') } }
    if ($summary.Count -eq 0)  { return @{ Status = 'OK'; Detail = "No critical/error events in $EventLogDays days" } }
    return @{ Status = 'OK'; Detail = ($summary -join ', ') }
}

function Invoke-DriverHealthTask {
    $bad = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
             Where-Object { $_.ConfigManagerErrorCode -ne 0 })

    if ($bad.Count -eq 0) {
        Write-Good 'No devices reporting a problem code.'
    } else {
        Write-Warn "$($bad.Count) device(s) reporting a problem code:"
        $bad | Select-Object -Property Name, DeviceID, ConfigManagerErrorCode, Status -First 15 |
            Format-Table -AutoSize | Out-String -Width 200 | Write-Host
        Add-Finding "$($bad.Count) device(s) have a Device Manager problem code. Update or reinstall the affected drivers."
    }

    # Surface oldest third-party drivers - a common source of instability.
    try {
        $drivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop |
                     Where-Object { $_.DriverProviderName -and $_.DriverProviderName -ne 'Microsoft' -and $_.DriverDate } |
                     Sort-Object DriverDate |
                     Select-Object -Property DeviceName, DriverProviderName, DriverVersion, DriverDate -First 8)
        if ($drivers) {
            Write-Info 'Oldest non-Microsoft drivers:'
            $drivers | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
        }
    } catch { }

    if ($bad.Count -gt 0) { return @{ Status = 'Warning'; Detail = "$($bad.Count) device problem code(s)" } }
    return @{ Status = 'OK'; Detail = 'All devices nominal' }
}

function Invoke-WmiRepositoryTask {
    $r = Invoke-NativeCommand -FilePath "$env:SystemRoot\System32\wbem\winmgmt.exe" -ArgumentList @('/verifyrepository')
    # winmgmt's console text is localized; its exit code (0 = consistent) is not. A nonzero exit
    # code is still ambiguous though - a tool-level failure (e.g. not elevated) also returns
    # nonzero and prints an "Error code:" line, which a genuine inconsistency finding does not.
    if ($r.ExitCode -eq 0) {
        Write-Good 'WMI repository is consistent.'
        return @{ Status = 'OK'; Detail = 'WMI repository consistent' }
    }
    if ($r.Output -match 'Error code:') {
        Write-Warn "WMI repository check could not run: $($r.Output)"
        return @{ Status = 'Warning'; Detail = "Could not verify repository (exit $($r.ExitCode))" }
    }
    Write-Warn "WMI repository check: $($r.Output)"
    Add-Finding 'The WMI repository reported an inconsistency. Try "winmgmt /salvagerepository" from an elevated prompt; rebuild only as a last resort.'
    return @{ Status = 'Warning'; Detail = "WMI repository inconsistent (exit $($r.ExitCode))" }
}

function Invoke-ServiceHealthTask {
    # Services that should be running on a healthy Windows 11 client.
    $expected = @{
        'wuauserv'   = 'Windows Update'
        'WinDefend'  = 'Microsoft Defender Antivirus'
        'BFE'        = 'Base Filtering Engine'
        'Dnscache'   = 'DNS Client'
        'EventLog'   = 'Windows Event Log'
        'Winmgmt'    = 'WMI'
        'CryptSvc'   = 'Cryptographic Services'
        'TrustedInstaller' = 'Windows Modules Installer'
        'VSS'        = 'Volume Shadow Copy'
    }
    $problems = @()
    foreach ($name in $expected.Keys) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        # wuauserv and TrustedInstaller are demand-start; only flag Disabled.
        if ($svc.StartType -eq 'Disabled') {
            $problems += "$name ($($expected[$name])) is Disabled"
        }
    }

    # Informational only: plenty of Automatic services are delayed-start and legitimately idle
    # early in a session, so this is a list to eyeball, not a failure condition.
    $idle = @(Get-Service -ErrorAction SilentlyContinue |
              Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' })
    if ($idle.Count -gt 0) {
        Write-Info "$($idle.Count) Automatic service(s) not currently running (delayed-start entries are normal):"
        $idle | Select-Object -Property Name, DisplayName, Status -First 15 |
            Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    }

    if ($problems.Count -gt 0) {
        foreach ($p in $problems) { Write-Bad "  $p" }
        Add-Finding ("Core services disabled: {0}." -f ($problems -join '; '))
        return @{ Status = 'Warning'; Detail = ($problems -join '; ') }
    }
    return @{ Status = 'OK'; Detail = "Core services nominal ($($idle.Count) automatic services idle)" }
}

function Invoke-PowerConfigTask {
    $r = Invoke-NativeCommand -FilePath 'powercfg.exe' -ArgumentList @('/getactivescheme')
    Write-Info $r.Output

    # Fast startup hides a true cold boot and is a frequent cause of "the reboot didn't fix it".
    $hiberKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
    try {
        $p = Get-ItemProperty -Path $hiberKey -ErrorAction Stop
        if ($p.PSObject.Properties.Name -contains 'HiberbootEnabled' -and $p.HiberbootEnabled -eq 1) {
            Write-Info 'Fast Startup is enabled. Remember: "Shut down" then power on is NOT a full reboot - use Restart.'
        }
    } catch { }

    # Battery report on portables.
    $battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if ($battery -and -not $script:ReadOnlyRun) {
        $out = Join-Path $script:RunLogDir 'battery-report.html'
        $null = Invoke-NativeCommand -FilePath 'powercfg.exe' -ArgumentList @('/batteryreport', '/output', $out)
        if (Test-Path $out) { Write-Info "Battery report written to $out" }
    }

    # Sleep study / energy diagnostics are expensive; Full level only.
    if ($script:CurrentRank -ge 3 -and -not $script:ReadOnlyRun) {
        $sleepOut = Join-Path $script:RunLogDir 'sleepstudy.html'
        $null = Invoke-NativeCommand -FilePath 'powercfg.exe' -ArgumentList @('/sleepstudy', '/output', $sleepOut)
        if (Test-Path $sleepOut) { Write-Info "Sleep study written to $sleepOut" }
    }

    return @{ Status = 'OK'; Detail = 'Power configuration reviewed' }
}

function Invoke-StartupImpactTask {
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )
    $entries = New-Object System.Collections.Generic.List[psobject]
    foreach ($k in $runKeys) {
        if (-not (Test-Path $k)) { continue }
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }   # key exists but holds no values
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $entries.Add([pscustomobject]@{ Hive = $k.Split('\')[0]; Name = $p.Name; Command = $p.Value }) | Out-Null
        }
    }

    if ($entries.Count -gt 0) {
        Write-Info "$($entries.Count) registry Run entries:"
        $entries | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    }

    $tasks = @()
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop |
                   Where-Object {
                       $_.State -eq 'Ready' -and
                       (@($_.Triggers) | Where-Object { $_ -and $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' } | Measure-Object).Count -gt 0
                   } |
                   Select-Object -Property TaskName, TaskPath -First 15)
    } catch { }
    if ($tasks) {
        Write-Info 'Logon-triggered scheduled tasks (first 15):'
        $tasks | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    }

    if ($entries.Count -gt 15) {
        Add-Finding "$($entries.Count) programs launch at sign-in. Trim the list in Task Manager > Startup apps to cut boot time."
        return @{ Status = 'Warning'; Detail = "$($entries.Count) startup entries" }
    }
    return @{ Status = 'OK'; Detail = "$($entries.Count) startup entries" }
}

function Invoke-PendingRebootTask {
    # @() guards against PowerShell unwrapping a single-element return to a bare scalar, which
    # has no .Count on Windows PowerShell 5.1 under Set-StrictMode (PS7's .Count shim hides this).
    $reasons = @(Get-PendingRebootDetail)
    if ($reasons.Count -gt 0) {
        $script:RebootNeeded = $true
        foreach ($r in $reasons) { Write-Warn "  pending: $r" }
        Add-Finding ("A restart is pending ({0}). Servicing work will not complete until you restart." -f ($reasons -join ', '))
        return @{ Status = 'Warning'; Detail = ($reasons -join ', ') }
    }
    if ($script:RebootNeeded) {
        return @{ Status = 'Warning'; Detail = 'Reboot recommended by this run' }
    }
    Write-Good 'No pending reboot.'
    return @{ Status = 'OK'; Detail = 'No pending reboot' }
}

#endregion
