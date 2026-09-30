# WinDragon - Security module
# Microsoft Defender health/signatures/quick scan and security posture review.
# One-to-one replica of the "Task: security" region of vader\Invoke-ImperialMaintenance.ps1.

#region ---------------------------------------------------------------- Task: security

function Invoke-DefenderTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$IncludeDefenderScan = $IncludeDefenderScan)

    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        return @{ Status = 'Skipped'; Detail = 'Defender cmdlets unavailable (third-party AV?)' }
    }

    # The cmdlets exist but throw when Defender is disabled/passive behind third-party AV.
    try   { $status = Get-MpComputerStatus -ErrorAction Stop }
    catch { return @{ Status = 'Skipped'; Detail = "Defender unavailable: $($_.Exception.Message)" } }
    Write-Info ("Antimalware engine : {0}" -f $status.AMEngineVersion)
    Write-Info ("Signature version  : {0} (age {1} days)" -f $status.AntivirusSignatureVersion, $status.AntivirusSignatureAge)
    Write-Info ("Real-time protection: {0}   Tamper protection: {1}" -f $status.RealTimeProtectionEnabled, $status.IsTamperProtected)

    $issues = @()
    if (-not $status.RealTimeProtectionEnabled) { $issues += 'real-time protection off' }
    if ($status.AntivirusSignatureAge -gt 3)     { $issues += "signatures $($status.AntivirusSignatureAge) days old" }

    if (-not $script:ReadOnlyRun -and $PSCmdlet.ShouldProcess('Microsoft Defender', 'Update signatures')) {
        try {
            Write-Info 'Updating Defender signatures...'
            Update-MpSignature -ErrorAction Stop
            Write-Good 'Signatures updated.'
        } catch {
            Write-Warn "Signature update failed: $($_.Exception.Message)"
            $issues += 'signature update failed'
        }
    }

    if ($IncludeDefenderScan -and -not $script:ReadOnlyRun) {
        if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Quick scan')) {
            Write-Info 'Running quick scan...'
            try { Start-MpScan -ScanType QuickScan -ErrorAction Stop; Write-Good 'Quick scan complete.' }
            catch { Write-Warn "Quick scan failed: $($_.Exception.Message)"; $issues += 'quick scan failed' }
        }
    }

    $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
                 Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) })
    if ($threats.Count -gt 0) {
        Write-Warn "$($threats.Count) threat detection(s) in the last 30 days."
        Add-Finding "Microsoft Defender logged $($threats.Count) detection(s) in the last 30 days. Review Windows Security > Protection history."
        $issues += "$($threats.Count) recent detections"
    }

    if ($issues.Count -gt 0) { return @{ Status = 'Warning'; Detail = ($issues -join '; ') } }
    return @{ Status = 'OK'; Detail = "Signatures $($status.AntivirusSignatureVersion)" }
}

function Invoke-SecurityPostureTask {
    $issues = @()

    # Firewall
    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $fw | Select-Object Name, Enabled, DefaultInboundAction | Format-Table -AutoSize | Out-String | Write-Host
        $off = @($fw | Where-Object { -not $_.Enabled })
        if ($off) { $issues += "firewall disabled on: $($off.Name -join ',')" }
    } catch { }

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        Write-Info "Secure Boot        : $sb"
        if (-not $sb) { $issues += 'Secure Boot disabled' }
    } catch { Write-Info 'Secure Boot        : not reported (legacy BIOS or unsupported)' }

    # TPM
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        Write-Info ("TPM                : present={0} ready={1} enabled={2}" -f $tpm.TpmPresent, $tpm.TpmReady, $tpm.TpmEnabled)
        if ($tpm.TpmPresent -and -not $tpm.TpmReady) { $issues += 'TPM present but not ready' }
    } catch { }

    # BitLocker
    try {
        $bl = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -eq 'OperatingSystem' })
        foreach ($v in $bl) {
            Write-Info ("BitLocker {0}      : {1} ({2}%)" -f $v.MountPoint, $v.ProtectionStatus, $v.EncryptionPercentage)
            if ($v.ProtectionStatus -ne 'On') { $issues += "BitLocker off on $($v.MountPoint)" }
        }
    } catch { Write-Info 'BitLocker          : not available on this edition' }

    # Core isolation / memory integrity
    try {
        $hvci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        $hvciOn = $hvci.SecurityServicesRunning -contains 2
        Write-Info "Memory integrity   : $(if ($hvciOn) { 'running' } else { 'not running' })"
        if (-not $hvciOn) { $issues += 'memory integrity (HVCI) not running' }
    } catch { }

    if ($issues.Count -gt 0) {
        Add-Finding ("Security posture gaps: {0}." -f ($issues -join '; '))
        return @{ Status = 'Warning'; Detail = ($issues -join '; ') }
    }
    return @{ Status = 'OK'; Detail = 'Firewall, Secure Boot, TPM, BitLocker and HVCI all nominal' }
}

#endregion
