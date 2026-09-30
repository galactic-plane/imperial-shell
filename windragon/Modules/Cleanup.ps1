# WinDragon - Cleanup module
# Reparse-point-safe temp/cache cleanup, scripted Disk Cleanup profile and Storage Sense review.
# One-to-one replica of the "Task: cleanup" region of vader\Invoke-ImperialMaintenance.ps1.

#region ---------------------------------------------------------------- Task: cleanup

function Get-FilesSkippingReparsePoints {
    <# Recurses like Get-ChildItem -Recurse, but never follows a symlink/junction - unlike
       Get-ChildItem -Recurse on Windows PowerShell 5.1, which does by default. #>
    param([Parameter(Mandatory)][string]$Path)
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($child in (Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
            if ($child.PSIsContainer) {
                if (-not ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $stack.Push($child.FullName) }
            } else {
                $child
            }
        }
    }
}

function Remove-PathContents {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Label,
        [int]$OlderThanDays = 0
    )
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }

    $cutoff = (Get-Date).AddDays(-$OlderThanDays)
    $freed = 0
    try {
        $items = Get-FilesSkippingReparsePoints -Path $Path |
                 Where-Object { $OlderThanDays -eq 0 -or $_.LastWriteTime -lt $cutoff }
        foreach ($i in $items) {
            try {
                $size = $i.Length
                Remove-Item -LiteralPath $i.FullName -Force -ErrorAction Stop
                $freed += $size
            } catch { }   # in-use files are expected; move on
        }
        # Remove now-empty directories (reparse points are left alone, never recursed into or deleted).
        Get-ChildItem -LiteralPath $Path -Force -Recurse -Directory -ErrorAction SilentlyContinue |
            Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
            Sort-Object { $_.FullName.Length } -Descending |
            ForEach-Object {
                try {
                    if (-not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue)) {
                        Remove-Item -LiteralPath $_.FullName -Force -Recurse -ErrorAction Stop
                    }
                } catch { }
            }
    } catch { }

    if ($freed -gt 0 -and $Label) {
        Write-Info ("  {0,-38} {1,8} MB" -f $Label, (ConvertTo-Mb $freed))
    }
    return $freed
}

function Invoke-CleanupTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($script:ReadOnlyRun) { return @{ Status = 'Skipped'; Detail = 'Audit mode' } }

    $sysDrive = $env:SystemDrive.TrimEnd(':')
    $before = (Get-Volume -DriveLetter $sysDrive).SizeRemaining
    $freed = 0
    $didWork = $false

    Write-Info 'Reclaiming space:'

    if (Test-IsSystemAccount) {
        Add-Finding 'Running as SYSTEM: temp/cache/Recycle Bin cleanup only touches the SYSTEM profile, not interactive users. Run interactively for real per-user cleanup.'
    }

    $targets = @(
        @{ Path = $env:TEMP;                                                     Label = 'User temp';                 Days = 0 }
        @{ Path = "$env:SystemRoot\Temp";                                        Label = 'Windows temp';              Days = 0 }
        @{ Path = "$env:LOCALAPPDATA\CrashDumps";                                Label = 'Application crash dumps';   Days = 7 }
        @{ Path = "$env:LOCALAPPDATA\D3DSCache";                                 Label = 'DirectX shader cache';      Days = 0 }
        @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\WER";                     Label = 'User error reports';        Days = 7 }
        @{ Path = "$env:ProgramData\Microsoft\Windows\WER\ReportQueue";          Label = 'WER report queue';          Days = 7 }
        @{ Path = "$env:ProgramData\Microsoft\Windows\WER\ReportArchive";        Label = 'WER report archive';        Days = 30 }
        @{ Path = "$env:SystemRoot\Prefetch";                                    Label = 'Prefetch (stale entries)';  Days = 90 }
    )

    # Full level adds heavier targets.
    if ($script:CurrentRank -ge 3) {
        $targets += @{ Path = "$env:SystemRoot\Logs\CBS";                Label = 'Old CBS logs';            Days = 30 }
        $targets += @{ Path = "$env:SystemRoot\Logs\DISM";               Label = 'Old DISM logs';           Days = 30 }
        $targets += @{ Path = "$env:SystemRoot\Panther";                 Label = 'Setup (Panther) logs';    Days = 60 }
        $targets += @{ Path = "$env:SystemRoot\SoftwareDistribution\Download"; Label = 'Windows Update cache'; Days = 10 }
        $targets += @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\IE"; Label = 'Legacy WinINet cache'; Days = 0 }
    }

    foreach ($t in $targets) {
        if ($PSCmdlet.ShouldProcess($t.Path, 'Delete contents')) {
            $didWork = $true
            $freed += Remove-PathContents -Path $t.Path -Label $t.Label -OlderThanDays $t.Days
        }
    }

    # Delivery Optimization cache (peer-to-peer update payloads).
    if ((Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) -and
        $PSCmdlet.ShouldProcess('Delivery Optimization cache', 'Purge')) {
        $didWork = $true
        try {
            Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
            Write-Info ("  {0,-38} {1}" -f 'Delivery Optimization cache', 'purged')
        } catch { }
    }

    # Recycle Bin.
    if ($PSCmdlet.ShouldProcess('Recycle Bin', 'Empty')) {
        $didWork = $true
        try {
            Clear-RecycleBin -Force -ErrorAction Stop
            Write-Info ("  {0,-38} {1}" -f 'Recycle Bin', 'emptied')
        } catch {
            Write-Info ("  {0,-38} {1}" -f 'Recycle Bin', 'already empty')
        }
    }

    # DNS resolver cache.
    if ($PSCmdlet.ShouldProcess('DNS client cache', 'Flush')) {
        $didWork = $true
        try { Clear-DnsClientCache -ErrorAction Stop; Write-Info ("  {0,-38} {1}" -f 'DNS client cache', 'flushed') } catch { }
    }

    # Icon/thumbnail cache is only measured, never deleted: Explorer holds it open while running.
    if ($script:CurrentRank -ge 3 -and -not (Test-IsSystemAccount)) {
        $iconPath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
        if (Test-Path $iconPath) {
            $stale = @(Get-ChildItem -LiteralPath $iconPath -Filter 'iconcache*' -Force -ErrorAction SilentlyContinue)
            $stale += @(Get-ChildItem -LiteralPath $iconPath -Filter 'thumbcache*' -Force -ErrorAction SilentlyContinue)
            $cacheBytes = ($stale | Measure-Object -Property Length -Sum).Sum
            if ($cacheBytes) {
                Write-Info ("  {0,-38} {1,8} MB (size only - not deleted)" -f 'Icon/thumbnail cache', (ConvertTo-Mb $cacheBytes))
            }
        }
    }

    $after = (Get-Volume -DriveLetter $sysDrive).SizeRemaining
    $deltaGb = ConvertTo-Gb $freed

    if (-not $didWork) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    Write-Good ("Reclaimed {0} GB on {1}: (volume free space changed by {2} GB)" -f $deltaGb, $sysDrive, (ConvertTo-Gb ($after - $before)))

    return @{ Status = 'OK'; Detail = "Reclaimed $deltaGb GB" }
}

function Invoke-DiskCleanupTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$UseDiskCleanup = $UseDiskCleanup)

    if (-not $UseDiskCleanup) { return @{ Status = 'Skipped'; Detail = 'Not requested (-UseDiskCleanup)' } }
    $cleanmgr = Get-Command cleanmgr.exe -ErrorAction SilentlyContinue
    if (-not $cleanmgr) {
        return @{ Status = 'Skipped'; Detail = 'cleanmgr.exe not present (deprecated in favour of Storage Sense)' }
    }
    if (-not $PSCmdlet.ShouldProcess('Disk Cleanup', 'Run scripted sageset profile')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $sageId = 7777
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    # Allow-list, not a deny-list: a missed/renamed handler in a deny-list silently stays enabled
    # and can destroy user data (e.g. the Downloads folder handler), whereas a miss here just
    # skips cleanup for that one category. Verified against actual VolumeCaches key names.
    $allow = @(
        'Temporary Files', 'Temporary Setup Files', 'Recycle Bin', 'Thumbnail Cache',
        'Delivery Optimization Files', 'Update Cleanup', 'D3D Shader Cache',
        'Windows Error Reporting Files',
        'Downloaded Program Files', 'Internet Cache Files'
    )

    $count = 0
    try {
        Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
            $leaf = Split-Path $_.PSPath -Leaf
            if ($allow -contains $leaf) {
                try {
                    New-ItemProperty -Path $_.PSPath -Name "StateFlags$sageId" -Value 2 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    $count++
                } catch { }
            } else {
                Remove-ItemProperty -Path $_.PSPath -Name "StateFlags$sageId" -ErrorAction SilentlyContinue
            }
        }

        Write-Info "Running cleanmgr with $count handlers enabled (profile $sageId)..."
        $p = Start-Process -FilePath $cleanmgr.Source -ArgumentList "/sagerun:$sageId" -PassThru -Wait -WindowStyle Hidden
        return @{ Status = 'OK'; Detail = "cleanmgr /sagerun:$sageId exit $($p.ExitCode)" }
    }
    finally {
        # Don't leave the sageset selection behind for a future manual/unrelated /sagerun:7777 to inherit.
        Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-ItemProperty -Path $_.PSPath -Name "StateFlags$sageId" -ErrorAction SilentlyContinue }
    }
}

function Invoke-StorageSenseReportTask {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
    if (Test-IsSystemAccount) { return @{ Status = 'Skipped'; Detail = 'Per-user setting; not meaningful under SYSTEM' } }
    if (-not (Test-Path $key)) {
        Add-Finding 'Storage Sense has never been configured. Settings > System > Storage > Storage Sense keeps temp files and the Recycle Bin trimmed automatically.'
        return @{ Status = 'Warning'; Detail = 'Storage Sense not configured' }
    }
    $p = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    $enabled = 0
    if ($p -and $p.PSObject.Properties.Name -contains '01') { $enabled = [int]$p.'01' }
    Write-Info "Storage Sense enabled: $([bool]$enabled)"
    if (-not $enabled) {
        Add-Finding 'Storage Sense is off. Turning it on gives you automatic, ongoing cleanup between maintenance runs.'
        return @{ Status = 'Warning'; Detail = 'Storage Sense disabled' }
    }
    return @{ Status = 'OK'; Detail = 'Storage Sense enabled' }
}

#endregion
