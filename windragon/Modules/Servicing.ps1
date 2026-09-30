# WinDragon - Servicing module
# Windows Update scan/install, Windows Update stack repair, winget + Microsoft Store upgrades,
# Store update scan and PowerShell module/help hygiene.
# One-to-one replica of the "Task: servicing" region of vader\Invoke-ImperialMaintenance.ps1.

#region ---------------------------------------------------------------- Task: servicing

function Invoke-WindowsUpdateTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$InstallWindowsUpdates = $InstallWindowsUpdates)

    $session = $null
    try   { $session = New-Object -ComObject Microsoft.Update.Session }
    catch { return @{ Status = 'Warning'; Detail = 'Windows Update COM API unavailable' } }

    Write-Info 'Scanning Windows Update (this can take a few minutes)...'
    $searcher = $session.CreateUpdateSearcher()
    $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0")
    $updates = @($searchResult.Updates)

    if ($updates.Count -eq 0) {
        Write-Good 'No pending updates.'
        return @{ Status = 'OK'; Detail = 'No pending updates' }
    }

    Write-Warn "$($updates.Count) update(s) available:"
    $updates | ForEach-Object {
        $sizeMb = 0
        try { $sizeMb = ConvertTo-Mb $_.MaxDownloadSize } catch { }
        Write-Host ("      - {0} ({1} MB)" -f $_.Title, $sizeMb) -ForegroundColor Gray
    }

    if (-not $InstallWindowsUpdates -or $script:ReadOnlyRun) {
        Add-Finding "$($updates.Count) Windows Update(s) pending. Re-run with -InstallWindowsUpdates to apply them."
        return @{ Status = 'Warning'; Detail = "$($updates.Count) pending (not installed)" }
    }
    if (Test-IsSystemAccount) {
        return @{ Status = 'Warning'; Detail = 'Update install via COM is unsupported from a service (SYSTEM) context' }
    }
    if (-not $PSCmdlet.ShouldProcess('Windows Update', "Download and install $($updates.Count) update(s)")) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $updates) {
        if (-not $u.EulaAccepted) { try { $u.AcceptEula() } catch { } }
        $toInstall.Add($u) | Out-Null
    }

    Write-Info 'Downloading...'
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $toInstall
    $dl = $downloader.Download()
    # 2 = succeeded, 3 = succeeded with errors (install whatever did download).
    if ($dl.ResultCode -notin 2, 3) {
        return @{ Status = 'Failed'; Detail = "Download result code $($dl.ResultCode)" }
    }

    Write-Info 'Installing...'
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $toInstall
    $ir = $installer.Install()

    if ($ir.RebootRequired) { $script:RebootNeeded = $true }
    switch ($ir.ResultCode) {
        2 { Write-Good 'Updates installed successfully.'
            return @{ Status = 'Repaired'; Detail = "$($updates.Count) update(s) installed" } }
        3 { Add-Finding 'Some Windows Updates installed with errors. Check Settings > Windows Update > Update history.'
            return @{ Status = 'Warning'; Detail = 'Installed with errors' } }
        default {
            return @{ Status = 'Failed'; Detail = "Install result code $($ir.ResultCode)" } }
    }
}

function Invoke-WindowsUpdateRepairTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$RepairWindowsUpdateStack = $RepairWindowsUpdateStack)

    if (-not $RepairWindowsUpdateStack) { return @{ Status = 'Skipped'; Detail = 'Not requested (-RepairWindowsUpdateStack)' } }
    if (-not $PSCmdlet.ShouldProcess('Windows Update stack', 'Reset SoftwareDistribution and catroot2')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $services = 'wuauserv', 'cryptSvc', 'bits', 'msiserver', 'usosvc'
    Write-Warn 'Stopping servicing stack services...'
    foreach ($s in $services) {
        try { Stop-Service -Name $s -Force -ErrorAction Stop; Write-Info "  stopped $s" }
        catch { Write-Info "  $s not stopped: $($_.Exception.Message)" }
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    foreach ($pair in @(
        @{ Path = "$env:SystemRoot\SoftwareDistribution"; New = "SoftwareDistribution.bak-$stamp" },
        @{ Path = "$env:SystemRoot\System32\catroot2";    New = "catroot2.bak-$stamp" })) {
        if (Test-Path $pair.Path) {
            try {
                Rename-Item -Path $pair.Path -NewName $pair.New -Force -ErrorAction Stop
                Write-Good "  renamed $($pair.Path) -> $($pair.New)"
            } catch {
                Write-Warn "  could not rename $($pair.Path): $($_.Exception.Message)"
            }
        }
    }

    $failedStarts = @()
    foreach ($s in $services) {
        try { Start-Service -Name $s -ErrorAction Stop; Write-Info "  started $s" }
        catch { Write-Bad "  FAILED to restart $s`: $($_.Exception.Message)"; $failedStarts += $s }
    }

    $script:RebootNeeded = $true
    if ($failedStarts.Count -gt 0) {
        Add-Finding "Windows Update stack reset left these services stopped: $($failedStarts -join ', '). Start them manually or reboot immediately."
        return @{ Status = 'Failed'; Detail = "Reset done but $($failedStarts -join ',') would not restart" }
    }
    Add-Finding "Windows Update stack was reset. Old folders were renamed with suffix .bak-$stamp and can be deleted once updates work."
    return @{ Status = 'Repaired'; Detail = "Stack reset (backups suffixed .bak-$stamp)" }
}

function Invoke-WingetTask {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$UpgradeApps = $UpgradeApps)

    if (-not $UpgradeApps) { return @{ Status = 'Skipped'; Detail = 'Not requested (-UpgradeApps)' } }
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) { return @{ Status = 'Skipped'; Detail = 'winget not installed' } }
    if (Test-IsSystemAccount) {
        return @{ Status = 'Skipped'; Detail = 'winget is unreliable under SYSTEM - run interactively' }
    }
    if (-not $PSCmdlet.ShouldProcess('Installed packages', 'winget upgrade --all (winget + msstore)')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    Write-Info 'Refreshing winget sources...'
    $null = Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @('source', 'update', '--disable-interactivity')

    Write-Info 'Listing upgradable packages (all sources)...'
    $list = Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @(
        'upgrade', '--include-unknown', '--accept-source-agreements', '--disable-interactivity')
    Write-Host $list.Output -ForegroundColor Gray

    Write-Info 'Upgrading winget-source packages...'
    $up = Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @(
        'upgrade', '--all', '--include-unknown', '--silent',
        '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')

    # A separate --source msstore pass is what actually updates installed Microsoft Store apps;
    # a plain 'winget upgrade --all' does not reliably reach them without scoping to that source.
    Write-Info 'Upgrading Microsoft Store apps (winget --source msstore)...'
    $storeUp = Invoke-NativeCommand -FilePath $winget.Source -ArgumentList @(
        'upgrade', '--all', '--include-unknown', '--silent', '--source', 'msstore',
        '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')

    $notes = @()
    $notes += if ($up.ExitCode -eq 0) { 'winget packages upgraded' } else { "winget source exit $($up.ExitCode)" }
    $notes += if ($storeUp.ExitCode -eq 0) { 'Store apps upgraded' } else { "msstore source exit $($storeUp.ExitCode)" }

    if ($up.ExitCode -eq 0 -and $storeUp.ExitCode -eq 0) {
        return @{ Status = 'Repaired'; Detail = ($notes -join '; ') }
    }
    return @{ Status = 'Warning'; Detail = ($notes -join '; ') + ' - some packages need manual attention' }
}

function Invoke-StoreAppUpdateTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($script:ReadOnlyRun) { return @{ Status = 'Skipped'; Detail = 'Audit mode' } }
    if (Test-IsSystemAccount) { return @{ Status = 'Skipped'; Detail = 'Not applicable under SYSTEM' } }
    if (-not $PSCmdlet.ShouldProcess('Microsoft Store', 'Trigger app update scan')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }
    try {
        # Complementary to Invoke-WingetTask's 'winget upgrade --source msstore' pass: this asks
        # StorSvc to check for updates in the background for any app winget's msstore catalog
        # might not cover. It's async and best-effort, not a synchronous "update everything now".
        $ns = 'root\cimv2\mdm\dmmap'
        $cls = 'MDM_EnterpriseModernAppManagement_AppManagement01'
        $obj = Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction Stop
        $null = Invoke-CimMethod -InputObject $obj -MethodName UpdateScanMethod -ErrorAction Stop
        Write-Good 'Microsoft Store update scan triggered.'
        return @{ Status = 'OK'; Detail = 'Store update scan triggered' }
    } catch {
        return @{ Status = 'Skipped'; Detail = 'MDM bridge unavailable' }
    }
}

function Invoke-PowerShellHygieneTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($script:ReadOnlyRun) { return @{ Status = 'Skipped'; Detail = 'Audit mode' } }
    if (-not $PSCmdlet.ShouldProcess('PowerShell modules and help', 'Update')) {
        return @{ Status = 'Skipped'; Detail = 'WhatIf' }
    }

    $notes = @()
    try {
        Write-Info 'Updating PowerShell help...'
        Update-Help -Force -ErrorAction SilentlyContinue 2>$null
        $notes += 'help updated'
    } catch { $notes += 'help update partial' }

    try {
        if (Get-Command Update-PSResource -ErrorAction SilentlyContinue) {
            Write-Info 'Updating installed modules via PSResourceGet...'
            Update-PSResource -Scope CurrentUser -TrustRepository -ErrorAction SilentlyContinue
            $notes += 'modules updated (PSResourceGet)'
        } elseif (Get-Command Update-Module -ErrorAction SilentlyContinue) {
            Write-Info 'Updating installed modules via PowerShellGet...'
            Update-Module -Force -ErrorAction SilentlyContinue
            $notes += 'modules updated (PowerShellGet)'
        }
    } catch { $notes += 'module update partial' }

    return @{ Status = 'OK'; Detail = ($notes -join '; ') }
}

#endregion
