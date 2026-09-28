# WinDragon - Storage module
# Physical disk health, NTFS online scan, CHKDSK scheduling and volume optimization.
# One-to-one replica of the "Task: storage" region of vader\Invoke-ImperialMaintenance.ps1.

#region ---------------------------------------------------------------- Task: storage

function Invoke-PhysicalDiskHealthTask {
    $disks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)
    if (-not $disks) { return @{ Status = 'Skipped'; Detail = 'No physical disks reported' } }

    $problems = 0
    $rows = foreach ($d in $disks) {
        $rc = $null
        try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }

        $wear = $null; $temp = $null; $hours = $null; $readErr = $null; $writeErr = $null
        if ($rc) {
            $wear     = $rc.Wear
            $temp     = $rc.Temperature
            $hours    = $rc.PowerOnHours
            $readErr  = $rc.ReadErrorsUncorrected
            $writeErr = $rc.WriteErrorsUncorrected
        }

        if ($d.HealthStatus -ne 'Healthy') { $problems++ }
        if ($null -ne $wear -and $wear -ge 80) { $problems++ }
        if (($null -ne $readErr -and $readErr -gt 0) -or ($null -ne $writeErr -and $writeErr -gt 0)) { $problems++ }

        [pscustomobject]@{
            Disk        = $d.FriendlyName
            Media       = $d.MediaType
            Bus         = $d.BusType
            SizeGb      = ConvertTo-Gb $d.Size
            Health      = $d.HealthStatus
            OpStatus    = ($d.OperationalStatus -join ',')
            'Wear%'     = $wear
            TempC       = $temp
            PowerOnHrs  = $hours
            UncReadErr  = $readErr
            UncWriteErr = $writeErr
        }
    }

    $rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

    # SMART predictive failure via the storage driver WMI provider.
    try {
        $smart = @(Get-CimInstance -Namespace 'root\wmi' -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop)
        foreach ($s in $smart) {
            if ($s.PredictFailure) {
                Write-Bad "SMART predictive failure asserted on $($s.InstanceName)"
                Add-Finding "SMART reports predictive failure on $($s.InstanceName). Back up now and replace the drive."
                $problems++
            }
        }
        if ($smart.Count -gt 0 -and $problems -eq 0) { Write-Good 'SMART predictive failure: clear on all reporting devices.' }
    } catch {
        Write-Info 'SMART predictive-failure provider not available for these controllers (common on NVMe/RAID).'
    }

    if ($problems -gt 0) {
        Add-Finding 'One or more drives reported degraded health, high wear, or uncorrected errors. Verify backups before doing anything else.'
        return @{ Status = 'Warning'; Detail = "$problems disk health concern(s)" }
    }
    return @{ Status = 'OK'; Detail = "$($disks.Count) disk(s) healthy" }
}

function Invoke-VolumeScanTask {
    $vols = @(Get-Volume -ErrorAction SilentlyContinue |
              Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystemType -eq 'NTFS' })
    if (-not $vols) { return @{ Status = 'Skipped'; Detail = 'No fixed NTFS volumes' } }

    $dirty = @()
    $unverified = @()
    $script:DirtyVolumes = @()
    foreach ($v in $vols) {
        Write-Info ("Online NTFS scan of {0}: ..." -f $v.DriveLetter)
        try {
            $result = Repair-Volume -DriveLetter $v.DriveLetter -Scan -ErrorAction Stop
            Write-Verbose "Repair-Volume -Scan on $($v.DriveLetter): returned type=$($result.GetType().FullName) value=$result"
            if ($result -match 'NoErrors' -or $result -eq 0) {
                Write-Good ("  {0}: clean" -f $v.DriveLetter)
            } else {
                Write-Warn ("  {0}: {1}" -f $v.DriveLetter, $result)
                $dirty += "$($v.DriveLetter): $result"
                $script:DirtyVolumes += $v.DriveLetter
            }
        } catch {
            Write-Warn ("  {0}: scan failed - {1}" -f $v.DriveLetter, $_.Exception.Message)
            $unverified += "$($v.DriveLetter): scan failed"
        }

        # fsutil's exit code is 0 (clean) or nonzero for BOTH "dirty" and unrelated errors (e.g.
        # access denied also returns 1), so a nonzero exit code alone is ambiguous. fsutil prefixes
        # genuine Win32 errors with a locale-independent "Error <n>:" marker; the real "is Dirty"
        # message has no such prefix, so use its absence to tell a real dirty bit from a failure.
        $fs = Invoke-NativeCommand -FilePath 'fsutil.exe' -ArgumentList @('dirty', 'query', "$($v.DriveLetter):")
        if ($fs.ExitCode -ne 0 -and $fs.Output -notmatch 'Error\s+\d+:') {
            Write-Warn ("  {0}: volume dirty bit is SET - CHKDSK will run at next boot." -f $v.DriveLetter)
            $dirty += "$($v.DriveLetter): dirty bit set"
            if ($script:DirtyVolumes -notcontains $v.DriveLetter) { $script:DirtyVolumes += $v.DriveLetter }
        } elseif ($fs.ExitCode -ne 0) {
            Write-Warn ("  {0}: could not query dirty bit - {1}" -f $v.DriveLetter, $fs.Output)
            $unverified += "$($v.DriveLetter): dirty-bit query failed"
        }
    }

    if ($dirty.Count -gt 0) {
        Add-Finding ("File system issues detected: {0}. Re-run with -ScheduleChkdsk to queue a full CHKDSK /F /R at next boot." -f ($dirty -join '; '))
        return @{ Status = 'Warning'; Detail = ($dirty -join '; ') }
    }
    if ($unverified.Count -gt 0) {
        Add-Finding ("Could not verify file system health on: {0}. Re-run elevated to get a real result." -f ($unverified -join '; '))
        return @{ Status = 'Warning'; Detail = ($unverified -join '; ') }
    }
    return @{ Status = 'OK'; Detail = "$($vols.Count) volume(s) clean" }
}

function Invoke-ChkdskScheduleTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$ScheduleChkdsk = $ScheduleChkdsk)

    if (-not $ScheduleChkdsk) { return @{ Status = 'Skipped'; Detail = 'Not requested (-ScheduleChkdsk)' } }

    $targets = @($script:DirtyVolumes)
    if (-not $targets) { $targets = @($env:SystemDrive.TrimEnd(':')) }

    # Writing BootExecute directly (rather than answering chkdsk's interactive Y/N prompt) avoids
    # the localized Y/N mnemonic problem and lets us verify the schedule actually took effect.
    $attempted = 0
    $scheduled = @()
    foreach ($drive in $targets) {
        $driveLetter = "$drive".TrimEnd(':')
        if (-not $PSCmdlet.ShouldProcess("${driveLetter}:", 'Schedule CHKDSK /R at next boot')) { continue }
        $attempted++

        Write-Warn "Scheduling CHKDSK /R on ${driveLetter}: for the next restart. A /R pass can take several hours."
        $bootExecKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $entry = "autocheck autochk /r \??\${driveLetter}:"
        $existing = @((Get-ItemProperty -Path $bootExecKey -Name BootExecute -ErrorAction SilentlyContinue).BootExecute)
        if ($existing -notcontains $entry) {
            Set-ItemProperty -Path $bootExecKey -Name BootExecute -Value (@($existing) + $entry) -Type MultiString
        }
        $verify = @((Get-ItemProperty -Path $bootExecKey -Name BootExecute -ErrorAction SilentlyContinue).BootExecute)
        if ($verify -contains $entry) {
            $scheduled += $driveLetter
        } else {
            Write-Bad "  could not confirm CHKDSK scheduling for ${driveLetter}:"
        }
    }

    if ($attempted -eq 0) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }
    if ($scheduled.Count -eq 0) {
        return @{ Status = 'Failed'; Detail = 'Could not confirm CHKDSK scheduling' }
    }
    $script:RebootNeeded = $true
    Add-Finding "CHKDSK /R is scheduled for $($scheduled -join ', ') at the next restart. Do not interrupt it once it begins."
    return @{ Status = 'Repaired'; Detail = "CHKDSK scheduled for $($scheduled -join ', ')" }
}

function Invoke-OptimizeVolumeTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $vols = @(Get-Volume -ErrorAction SilentlyContinue |
              Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystemType -in @('NTFS', 'ReFS') })
    if (-not $vols) { return @{ Status = 'Skipped'; Detail = 'No optimizable volumes' } }

    $actions = @()
    foreach ($v in $vols) {
        $media = Get-VolumeMediaType -DriveLetter $v.DriveLetter
        Write-Info ("{0}: media type {1}" -f $v.DriveLetter, $media)

        if ($script:ReadOnlyRun) {
            try {
                Optimize-Volume -DriveLetter $v.DriveLetter -Analyze -ErrorAction Stop -Verbose:$false
                $actions += "$($v.DriveLetter): analyzed"
            } catch { Write-Warn "  analyze failed: $($_.Exception.Message)" }
            continue
        }

        if (-not $PSCmdlet.ShouldProcess("$($v.DriveLetter):", "Optimize ($media)")) { continue }

        try {
            switch ($media) {
                'SSD' {
                    # TRIM/UNMAP. Never defrag an SSD - it burns write cycles for no benefit.
                    Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -ErrorAction Stop -Verbose:$false
                    Write-Good "  $($v.DriveLetter): ReTrim complete"
                    $actions += "$($v.DriveLetter): ReTrim"
                }
                'SCM' {
                    Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -ErrorAction Stop -Verbose:$false
                    $actions += "$($v.DriveLetter): ReTrim"
                }
                'HDD' {
                    Optimize-Volume -DriveLetter $v.DriveLetter -Defrag -ErrorAction Stop -Verbose:$false
                    Write-Good "  $($v.DriveLetter): defragmented"
                    $actions += "$($v.DriveLetter): Defrag"
                }
                default {
                    # Storage Spaces / Dev Drive / virtualized SSDs often report as unknown media.
                    # ReTrim is a documented no-op on rotational disks, so default to it instead of
                    # skipping optimization entirely.
                    try {
                        Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -ErrorAction Stop -Verbose:$false
                        Write-Info "  $($v.DriveLetter): ReTrim (media type unknown)"
                        $actions += "$($v.DriveLetter): ReTrim (unknown media)"
                    } catch {
                        Optimize-Volume -DriveLetter $v.DriveLetter -Analyze -ErrorAction Stop -Verbose:$false
                        Write-Info "  $($v.DriveLetter): analyzed only (ReTrim unsupported)"
                        $actions += "$($v.DriveLetter): analyzed"
                    }
                }
            }
        } catch {
            Write-Warn "  $($v.DriveLetter): $($_.Exception.Message)"
            $actions += "$($v.DriveLetter): failed"
        }
    }
    return @{ Status = 'OK'; Detail = ($actions -join '; ') }
}

#endregion
