# WinDragon - Baseline module
# System inventory, servicing lifecycle, free space and restore point tasks.
# One-to-one replica of the "Task: inventory" region of vader\Invoke-ImperialMaintenance.ps1.

#region ---------------------------------------------------------------- Task: inventory

function Get-SystemSnapshot {
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $bios = Get-CimInstance Win32_BIOS
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $build = [int]$cv.CurrentBuildNumber
    $ubr   = 0
    if ($cv.PSObject.Properties.Name -contains 'UBR') { $ubr = [int]$cv.UBR }

    $displayVersion = 'Unknown'
    if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') { $displayVersion = $cv.DisplayVersion }

    [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        Caption        = $os.Caption
        Edition        = $cv.EditionID
        DisplayVersion = $displayVersion
        Build          = $build
        UBR            = $ubr
        FullBuild      = "$build.$ubr"
        InstallDate    = $os.InstallDate
        LastBoot       = $os.LastBootUpTime
        UptimeHours    = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
        Cpu            = $cpu.Name.Trim()
        Cores          = $cpu.NumberOfCores
        Threads        = $cpu.NumberOfLogicalProcessors
        MemoryGb       = ConvertTo-Gb $cs.TotalPhysicalMemory
        FreeMemoryGb   = ConvertTo-Gb ($os.FreePhysicalMemory * 1KB)
        BiosVersion    = ($bios.SMBIOSBIOSVersion)
        BiosDate       = $bios.ReleaseDate
        Serial         = $bios.SerialNumber
        PowerShell     = $PSVersionTable.PSVersion.ToString()
    }
}

function Invoke-InventoryTask {
    $snap = Get-SystemSnapshot
    $script:Snapshot = $snap

    Write-Info ("Host        : {0}  ({1} {2})" -f $snap.ComputerName, $snap.Manufacturer, $snap.Model)
    Write-Info ("OS          : {0} {1} - build {2}" -f $snap.Caption, $snap.DisplayVersion, $snap.FullBuild)
    Write-Info ("Edition     : {0}" -f $snap.Edition)
    Write-Info ("CPU         : {0} ({1}C/{2}T)" -f $snap.Cpu, $snap.Cores, $snap.Threads)
    Write-Info ("Memory      : {0} GB total, {1} GB free" -f $snap.MemoryGb, $snap.FreeMemoryGb)
    Write-Info ("Firmware    : {0} ({1:yyyy-MM-dd})" -f $snap.BiosVersion, $snap.BiosDate)
    Write-Info ("Uptime      : {0} hours (last boot {1:yyyy-MM-dd HH:mm})" -f $snap.UptimeHours, $snap.LastBoot)
    Write-Info ("PowerShell  : {0}" -f $snap.PowerShell)

    if ($snap.UptimeHours -gt 336) {
        Add-Finding ("System has been up {0} hours. Long uptime defers servicing work and leaks handles - reboot soon." -f $snap.UptimeHours)
        return @{ Status = 'Warning'; Detail = "Uptime $($snap.UptimeHours)h" }
    }
    return @{ Status = 'OK'; Detail = "$($snap.Caption) $($snap.DisplayVersion) build $($snap.FullBuild)" }
}

function Invoke-LifecycleTask {
    $snap = $script:Snapshot
    if (-not $snap) { $snap = Get-SystemSnapshot; $script:Snapshot = $snap }

    if ($snap.Build -lt 22000) {
        Write-Warn 'This host is not running Windows 11. Several tasks will be skipped or behave differently.'
        return @{ Status = 'Warning'; Detail = 'Not Windows 11' }
    }

    $entry = $script:BuildMap[$snap.Build]
    if (-not $entry) {
        Write-Info ("Build {0} is not in the lifecycle map (Insider or newer than this script)." -f $snap.Build)
        return @{ Status = 'OK'; Detail = "Unmapped build $($snap.Build)" }
    }

    $isCommercial = $snap.Edition -match 'Enterprise|Education|IoTEnterprise'
    $eolString = if ($isCommercial) { $entry.Commercial } else { $entry.Consumer }
    $eol = [datetime]::ParseExact($eolString, 'yyyy-MM-dd', $null)
    $daysLeft = [math]::Round(($eol - (Get-Date)).TotalDays, 0)

    Write-Info ("Servicing   : Windows 11 {0} ({1} track)" -f $entry.Name, $(if ($isCommercial) { 'Enterprise/Education' } else { 'Home/Pro' }))
    Write-Info ("End of updates: {0:yyyy-MM-dd} ({1} days remaining)" -f $eol, $daysLeft)

    if ($daysLeft -lt 0) {
        Write-Bad 'This Windows 11 version no longer receives security updates. Upgrade immediately.'
        Add-Finding ("Windows 11 {0} is past end of servicing ({1:yyyy-MM-dd}). Upgrade to a supported feature update." -f $entry.Name, $eol)
        return @{ Status = 'Failed'; Detail = "$($entry.Name) out of support" }
    }
    if ($daysLeft -lt 120) {
        Write-Warn 'Approaching end of servicing. Plan the feature update now.'
        Add-Finding ("Windows 11 {0} loses updates on {1:yyyy-MM-dd} ({2} days). Schedule the feature update." -f $entry.Name, $eol, $daysLeft)
        return @{ Status = 'Warning'; Detail = "$($entry.Name) EOL in $daysLeft days" }
    }
    return @{ Status = 'OK'; Detail = "$($entry.Name) supported until $eolString" }
}

function Invoke-FreeSpaceTask {
    $sysDrive = $env:SystemDrive.TrimEnd(':')
    $vol = Get-Volume -DriveLetter $sysDrive -ErrorAction Stop
    $freeGb = ConvertTo-Gb $vol.SizeRemaining
    $sizeGb = ConvertTo-Gb $vol.Size
    $pct = if ($vol.Size -gt 0) { [math]::Round(($vol.SizeRemaining / $vol.Size) * 100, 1) } else { 0 }
    $script:FreeSpaceBefore = $vol.SizeRemaining

    Write-Info ("System volume {0}: {1} GB free of {2} GB ({3}%)" -f $sysDrive, $freeGb, $sizeGb, $pct)

    if ($freeGb -lt 15) {
        Write-Bad 'Under 15 GB free. Windows servicing (DISM, feature updates) needs headroom and may fail.'
        Add-Finding ("Only {0} GB free on {1}: - servicing operations need at least 15-20 GB." -f $freeGb, $sysDrive)
        return @{ Status = 'Warning'; Detail = "$freeGb GB free" }
    }
    return @{ Status = 'OK'; Detail = "$freeGb GB free ($pct%)" }
}

function Invoke-RestorePointTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($SkipRestorePoint) { return @{ Status = 'Skipped'; Detail = 'Suppressed by -SkipRestorePoint' } }

    $sysDrive = $env:SystemDrive

    if (-not $PSCmdlet.ShouldProcess($sysDrive, 'Create System Restore checkpoint')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    # Windows throttles restore points to one per 24h by default. Temporarily relax, then restore.
    $freqKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $originalFreq = $null
    try {
        if (Test-Path $freqKey) {
            $p = Get-ItemProperty -Path $freqKey -ErrorAction SilentlyContinue
            if ($p -and $p.PSObject.Properties.Name -contains 'SystemRestorePointCreationFrequency') {
                $originalFreq = $p.SystemRestorePointCreationFrequency
            }
        }
        New-ItemProperty -Path $freqKey -Name 'SystemRestorePointCreationFrequency' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    } catch { }

    try {
        $desc = "WinDragon Maintenance $($script:StartTime.ToString('yyyy-MM-dd HH:mm'))"
        $r = Invoke-CimMethod -Namespace 'root/default' -ClassName SystemRestore -MethodName CreateRestorePoint -Arguments @{
            Description      = $desc
            RestorePointType = [uint32]12   # MODIFY_SETTINGS
            EventType        = [uint32]100  # BEGIN_SYSTEM_CHANGE
        } -ErrorAction Stop

        if ($r.ReturnValue -eq 0) {
            Write-Good "Restore point created: $desc"
            return @{ Status = 'OK'; Detail = $desc }
        }
        Write-Warn "CreateRestorePoint returned $($r.ReturnValue). System Protection is probably disabled on $sysDrive."
        Add-Finding "System Protection appears to be off. Enable it (System Properties > System Protection) so repairs are reversible."
        return @{ Status = 'Warning'; Detail = "ReturnValue $($r.ReturnValue)" }
    }
    catch {
        Write-Warn "Restore point unavailable: $($_.Exception.Message)"
        return @{ Status = 'Warning'; Detail = 'System Protection disabled or unavailable' }
    }
    finally {
        try {
            if ($null -ne $originalFreq) {
                Set-ItemProperty -Path $freqKey -Name 'SystemRestorePointCreationFrequency' -Value $originalFreq -ErrorAction SilentlyContinue
            } else {
                Remove-ItemProperty -Path $freqKey -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue
            }
        } catch { }
    }
}

#endregion
