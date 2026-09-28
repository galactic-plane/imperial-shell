# WinDragon - Interface module
# The menu-driven WinDragon front end. Everything here is presentation and dispatch only:
# every maintenance action is delegated to the task engine / catalogue, which are one-to-one
# replicas of vader\Invoke-ImperialMaintenance.ps1.

#region ---------------------------------------------------------------- Console helpers

function ResetConsoleScreen {
    # Clear() throws when output is redirected (scheduled task, CI, test harness); that's harmless.
    try { [System.Console]::Clear() } catch { }
}

function Show-Dragon {
    $dragon = @'
                         ___====-_  _-====___
                   _--^^^#####//      \\#####^^^--_
                _-^##########// (    ) \\##########^-_
               -############//  |\^^/|  \\############-
             _/############//   (@::@)   \\############\_
            /#############((     \\//     ))#############\
           -###############\\    (oo)    //###############-
          -#################\\  / "  \  //#################-
         -###################\/      \//###################-
        _#/|##########/\######(   /\   )######/\##########|\#_
       |/ |#/#\#/#\/  \#/#\##\  \ \_/ /  ##/#\/#\/  \#/\#/ #\|
       ||/  V  '  `-'  V  \#\|  |\| | |\ |#/V  `-'   '  V  \||
       |||                \#|   | | | | \|#/               |||
       |||                 V    | | | |  V                |||
       |||                      ' | | '                   |||
       |||                       "  '                     |||
       |||                                               |||
       |||                                               |||
       |||                                               |||
     , |'|                                               |'| ,
    /.\/ /                                               \ \'.\
   /// //                                                 \ \\\\
  ||| '\'                                                 /'/ |||
                _   _   _   _   _   _   _   _   _
               / \ / \ / \ / \ / \ / \ / \ / \ / \
              ( W | i | n | D | r | a | g | o | n )
               \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/
'@
    Write-Host $dragon -ForegroundColor Cyan
    Write-Host ("                                                         v{0}" -f $script:ScriptVersion) -ForegroundColor DarkCyan
}

function Show-Message {
    param([ValidateNotNullOrEmpty()][string]$Message)
    $border = '-' * ($Message.Length + 2)
    Write-Host "+$border+" -ForegroundColor White
    Write-Host "  $Message " -ForegroundColor Cyan
    Write-Host "+$border+" -ForegroundColor White
}

function Show-Error {
    param([ValidateNotNullOrEmpty()][string]$Message)
    $border = '-' * ($Message.Length + 2)
    Write-Host "+$border+" -ForegroundColor Red
    Write-Host "  $Message " -ForegroundColor Red
    Write-Host "+$border+" -ForegroundColor Red
}

function Wait-ForKey {
    $null = Read-Host 'Press Enter to return to the menu'
}

#endregion

#region ---------------------------------------------------------------- Catalogue and option views

function Get-TaskCatalogueView {
    $script:TaskCatalogue |
        Select-Object @{ n = 'Task';     e = { $_.Name } },
                      @{ n = 'Category'; e = { $_.Category } },
                      @{ n = 'RunsAt';   e = { switch ($_.MinLevel) {
                                                   1       { 'Quick, Standard, Full' }
                                                   2       { 'Standard, Full' }
                                                   default { 'Full only' } } } },
                      @{ n = 'AuditSafe'; e = { $_.ReadOnly } }
}

function Get-MainMenuItem {
    @(
        [pscustomobject]@{ Key = '1';  Label = 'Audit     - Read-only health assessment (nothing is modified)' }
        [pscustomobject]@{ Key = '2';  Label = 'Quick     - Fast health pass (DISM check, disks, temp cleanup, updates)' }
        [pscustomobject]@{ Key = '3';  Label = 'Standard  - Full DISM/SFC repair chain, storage, cleanup, diagnostics' }
        [pscustomobject]@{ Key = '4';  Label = 'Full      - Standard + component store cleanup and deep cleanup' }
        [pscustomobject]@{ Key = '5';  Label = 'Run One Category...' }
        [pscustomobject]@{ Key = '6';  Label = 'Run Selected Tasks...' }
        [pscustomobject]@{ Key = '7';  Label = 'Options (updates, apps, Defender, CHKDSK, WhatIf, logs...)' }
        [pscustomobject]@{ Key = '8';  Label = 'List Task Catalogue' }
        [pscustomobject]@{ Key = '9';  Label = 'Register Weekly Scheduled Task' }
        [pscustomobject]@{ Key = '10'; Label = 'Exit' }
    )
}

function Get-SwitchOptionDefinition {
    @(
        [pscustomobject]@{ Kind = 'Switch';     Name = 'InstallWindowsUpdates';    Flag = '-InstallWindowsUpdates';    Label = 'Install pending Windows Updates' }
        [pscustomobject]@{ Kind = 'Switch';     Name = 'UpgradeApps';              Flag = '-UpgradeApps';              Label = 'Upgrade apps (winget + Microsoft Store)' }
        [pscustomobject]@{ Kind = 'Switch';     Name = 'IncludeDefenderScan';      Flag = '-IncludeDefenderScan';      Label = 'Run a Defender quick scan' }
        [pscustomobject]@{ Kind = 'Switch';     Name = 'ScheduleChkdsk';           Flag = '-ScheduleChkdsk';           Label = 'Schedule CHKDSK /R at next boot' }
        [pscustomobject]@{ Kind = 'Switch';     Name = 'ResetComponentStoreBase';  Flag = '-ResetComponentStoreBase';  Label = 'Reset component store base (Full)' }
        [pscustomobject]@{ Kind = 'Switch';     Name = 'RepairWindowsUpdateStack'; Flag = '-RepairWindowsUpdateStack'; Label = 'Repair the Windows Update stack' }
        [pscustomobject]@{ Kind = 'Switch';     Name = 'UseDiskCleanup';           Flag = '-UseDiskCleanup';           Label = 'Also run Disk Cleanup (cleanmgr)' }
        [pscustomobject]@{ Kind = 'Switch';     Name = 'SkipRestorePoint';         Flag = '-SkipRestorePoint';         Label = 'Skip the System Restore point' }
        [pscustomobject]@{ Kind = 'Preference'; Name = 'WhatIf';                   Flag = '-WhatIf';                   Label = 'Preview only - change nothing' }
        [pscustomobject]@{ Kind = 'Preference'; Name = 'Confirm';                  Flag = '-Confirm';                  Label = 'Confirm each change' }
        [pscustomobject]@{ Kind = 'Preference'; Name = 'Verbose';                  Flag = '-Verbose';                  Label = 'Verbose output' }
    )
}

function Get-SwitchOptionState {
    param([Parameter(Mandatory)][object]$Option)
    switch ($Option.Kind) {
        'Switch' { return [bool](Get-Variable -Name $Option.Name -Scope Script -ValueOnly) }
        default {
            switch ($Option.Name) {
                'WhatIf'  { return [bool]$WhatIfPreference }
                'Confirm' { return ($ConfirmPreference -in @('Low', 'Medium')) }
                'Verbose' { return ($VerbosePreference -eq 'Continue') }
            }
        }
    }
    return $false
}

function Set-SwitchOptionState {
    param([Parameter(Mandatory)][object]$Option, [Parameter(Mandatory)][bool]$Enabled)
    switch ($Option.Kind) {
        # -WhatIf/-Confirm:$false so toggling options still works once preview/confirm mode is on.
        'Switch' { Set-Variable -Name $Option.Name -Scope Script -Value ([switch]$Enabled) -WhatIf:$false -Confirm:$false }
        default {
            switch ($Option.Name) {
                'WhatIf'  { $script:WhatIfPreference = $Enabled }
                'Confirm' { $script:ConfirmPreference = $(if ($Enabled) { 'Medium' } else { 'High' }) }
                'Verbose' { $script:VerbosePreference = $(if ($Enabled) { 'Continue' } else { 'SilentlyContinue' }) }
            }
        }
    }
}

function Get-ActiveOptionSummary {
    $active = @(Get-SwitchOptionDefinition | Where-Object { Get-SwitchOptionState -Option $_ } | ForEach-Object { $_.Flag })
    if ($DismSource)          { $active += "-DismSource $DismSource" }
    if ($SkipTask)            { $active += "-SkipTask $($SkipTask -join ',')" }
    if ($EventLogDays -ne 7)  { $active += "-EventLogDays $EventLogDays" }
    if ($active.Count -eq 0)  { return '(none)' }
    return ($active -join ' ')
}

function ConvertFrom-TaskSelection {
    # Parses "1,3,5-7" into distinct, ordered 1-based indexes within 1..Max.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Selection, [Parameter(Mandatory)][int]$Max)
    $picked = New-Object System.Collections.Generic.List[int]
    foreach ($token in ($Selection -split ',')) {
        $t = $token.Trim()
        if ($t -eq '') { continue }
        if ($t -match '^(\d+)\s*-\s*(\d+)$') {
            $from = [int]$Matches[1]; $to = [int]$Matches[2]
            if ($from -gt $to) { $swap = $from; $from = $to; $to = $swap }
            $range = $from..$to
        } elseif ($t -match '^\d+$') {
            $range = @([int]$t)
        } else {
            throw "Invalid selection '$t'. Use numbers, commas and ranges such as 1,3,5-7."
        }
        foreach ($n in $range) {
            if ($n -lt 1 -or $n -gt $Max) { throw "Task number $n is out of range (1-$Max)." }
            if (-not $picked.Contains($n)) { $picked.Add($n) }
        }
    }
    return ,@($picked | Sort-Object)
}

#endregion

#region ---------------------------------------------------------------- Maintenance runs

function Start-MaintenanceRun {
    # The vader Main body, made re-entrant so the menu can run several passes per session.
    $script:StartTime     = Get-Date
    $script:Snapshot      = $null
    $script:Results       = New-Object System.Collections.Generic.List[psobject]
    $script:Findings      = New-Object System.Collections.Generic.List[string]
    $script:RebootNeeded  = $false
    $script:TranscriptOn  = $false
    $script:DirtyVolumes  = @()
    $script:CurrentRank   = $script:LevelRank[$Level]
    $script:ReadOnlyRun   = ($Level -eq 'Audit')

    # --- Logging -------------------------------------------------------------
    $script:RunLogDir = Join-Path $LogRoot ($script:StartTime.ToString('yyyy-MM-dd_HHmmss'))
    $null = New-Item -Path $script:RunLogDir -ItemType Directory -Force

    try {
        Start-Transcript -Path (Join-Path $script:RunLogDir 'transcript.log') -Force | Out-Null
        $script:TranscriptOn = $true
    } catch { }

    Write-Banner "WinDragon Maintenance Protocol v$($script:ScriptVersion)"
    Write-Host ("  Level      : {0}{1}" -f $Level, $(if ($script:ReadOnlyRun) { '  (read-only - nothing will be modified)' } else { '' })) -ForegroundColor Gray
    Write-Host ("  Started    : {0:yyyy-MM-dd HH:mm:ss}" -f $script:StartTime) -ForegroundColor Gray
    Write-Host ("  Operator   : {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) -ForegroundColor Gray
    Write-Host ("  Log folder : {0}" -f $script:RunLogDir) -ForegroundColor Gray
    if (-not $script:ReadOnlyRun) {
        Write-Host '  Close open work before continuing. Some steps take 10-30 minutes each.' -ForegroundColor DarkYellow
    }

    Suspend-Sleep

    try {
        $total = @($script:TaskCatalogue).Count
        $index = 0
        foreach ($task in $script:TaskCatalogue) {
            $index++
            Write-Progress -Activity 'WinDragon maintenance pass' -Status ("[{0}/{1}] {2}" -f $index, $total, $task.Name) -PercentComplete ([int](($index - 1) * 100 / [math]::Max(1, $total)))
            Invoke-MaintenanceTask -Task $task
        }
        Write-Progress -Activity 'WinDragon maintenance pass' -Completed

        # --- Reports ---------------------------------------------------------
        try {
            $htmlPath = Join-Path $script:RunLogDir 'maintenance-report.html'
            Write-HtmlReport -Path $htmlPath
        } catch {
            Write-Warn "HTML report generation failed: $($_.Exception.Message)"
        }

        try {
            $jsonPath = Join-Path $script:RunLogDir 'results.json'
            [pscustomobject]@{
                ScriptVersion = $script:ScriptVersion
                StartedUtc    = $script:StartTime.ToUniversalTime().ToString('o')
                Level         = $Level
                System        = $script:Snapshot
                RebootNeeded  = $script:RebootNeeded
                Findings      = @($script:Findings)
                Results       = @($script:Results)
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        } catch {
            Write-Warn "JSON report generation failed: $($_.Exception.Message)"
        }

        Write-RunSummary
    }
    finally {
        Resume-Sleep
        if ($script:TranscriptOn) { try { Stop-Transcript | Out-Null } catch { } }
    }
}

function Start-LevelRun {
    # One-shot full pass at the given level; the configured level for custom runs is restored.
    param([Parameter(Mandatory)][ValidateSet('Audit', 'Quick', 'Standard', 'Full')][string]$RunLevel)
    $previous = $script:Level
    try {
        $script:Level = $RunLevel
        Start-MaintenanceRun
    }
    finally {
        $script:Level = $previous
    }
}

function Invoke-ScopedRun {
    # Equivalent to -OnlyTask '<name>','<name>' at the configured level.
    param([Parameter(Mandatory)][string[]]$TaskNames)
    $previous = $script:OnlyTask
    try {
        $script:OnlyTask = $TaskNames
        Start-MaintenanceRun
    }
    finally {
        $script:OnlyTask = $previous
    }
}

#endregion

#region ---------------------------------------------------------------- Menus

function Show-Menu {
    ResetConsoleScreen
    Show-Dragon
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host '                     SYSTEM MAINTENANCE MENU' -ForegroundColor Yellow
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host ''
    Write-Host ("  Level for custom runs : {0}" -f $Level) -ForegroundColor Gray
    Write-Host ("  Active options        : {0}" -f (Get-ActiveOptionSummary)) -ForegroundColor Gray
    Write-Host ("  Reports folder        : {0}" -f $LogRoot) -ForegroundColor Gray
    Write-Host ''
    Write-Host 'Please select an option:' -ForegroundColor Green
    Write-Host ''
    foreach ($item in Get-MainMenuItem) {
        Write-Host ("  {0,2}. {1}" -f $item.Key, $item.Label) -ForegroundColor White
    }
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    $choice = Read-Host 'Enter the number of your choice'
    return $choice
}

function Show-CategoryMenu {
    $categories = @($script:TaskCatalogue | ForEach-Object { $_.Category } | Select-Object -Unique)
    ResetConsoleScreen
    Show-Message ("Run one category at level {0}" -f $Level)
    Write-Host ''
    for ($i = 0; $i -lt $categories.Count; $i++) {
        $names = @($script:TaskCatalogue | Where-Object { $_.Category -eq $categories[$i] } | ForEach-Object { $_.Name })
        Write-Host ("  {0,2}. {1,-12} {2}" -f ($i + 1), $categories[$i], ($names -join ', ')) -ForegroundColor White
    }
    Write-Host '   0. Back' -ForegroundColor White
    Write-Host ''
    $sel = "$(Read-Host 'Select a category')".Trim()
    if ($sel -eq '' -or $sel -eq '0') { return $false }
    $n = 0
    if (-not [int]::TryParse($sel, [ref]$n) -or $n -lt 1 -or $n -gt $categories.Count) {
        Show-Error "Invalid category '$sel'."
        return $true
    }
    $names = @($script:TaskCatalogue | Where-Object { $_.Category -eq $categories[$n - 1] } | ForEach-Object { $_.Name })
    Invoke-ScopedRun -TaskNames $names
    return $true
}

function Show-TaskPicker {
    $tasks = @($script:TaskCatalogue)
    ResetConsoleScreen
    Show-Message ("Run selected tasks at level {0}" -f $Level)
    Write-Host ''
    for ($i = 0; $i -lt $tasks.Count; $i++) {
        $flag = if ($tasks[$i].ReadOnly) { 'audit-safe' } else { 'modifies system' }
        Write-Host ("  {0,2}. {1,-28} {2,-12} {3}" -f ($i + 1), $tasks[$i].Name, $tasks[$i].Category, $flag) -ForegroundColor White
    }
    Write-Host '   0. Back' -ForegroundColor White
    Write-Host ''
    $sel = "$(Read-Host 'Enter task numbers (e.g. 1,3,5-7)')".Trim()
    if ($sel -eq '' -or $sel -eq '0') { return $false }
    try {
        $indexes = ConvertFrom-TaskSelection -Selection $sel -Max $tasks.Count
    } catch {
        Show-Error $_.Exception.Message
        return $true
    }
    if (@($indexes).Count -eq 0) {
        Show-Error 'No tasks selected.'
        return $true
    }
    $names = @($indexes | ForEach-Object { $tasks[$_ - 1].Name })
    Invoke-ScopedRun -TaskNames $names
    return $true
}

function Show-OptionsMenu {
    while ($true) {
        $defs = @(Get-SwitchOptionDefinition)
        ResetConsoleScreen
        Show-Message 'Options - these apply to every run started from the menu'
        Write-Host ''
        for ($i = 0; $i -lt $defs.Count; $i++) {
            $mark = if (Get-SwitchOptionState -Option $defs[$i]) { 'X' } else { ' ' }
            Write-Host ("  {0,2}. [{1}] {2,-42} {3}" -f ($i + 1), $mark, $defs[$i].Label, $defs[$i].Flag) -ForegroundColor White
        }
        $base = $defs.Count
        $dismText = if ($DismSource) { $DismSource } else { '(Windows Update)' }
        $skipText = if ($SkipTask) { $SkipTask -join ', ' } else { '(none)' }
        Write-Host ("  {0,2}. Level for custom runs      : {1}" -f ($base + 1), $Level) -ForegroundColor White
        Write-Host ("  {0,2}. DISM repair source         : {1}" -f ($base + 2), $dismText) -ForegroundColor White
        Write-Host ("  {0,2}. Event log days             : {1}" -f ($base + 3), $EventLogDays) -ForegroundColor White
        Write-Host ("  {0,2}. Reports folder             : {1}" -f ($base + 4), $LogRoot) -ForegroundColor White
        Write-Host ("  {0,2}. Skip tasks (wildcards)     : {1}" -f ($base + 5), $skipText) -ForegroundColor White
        Write-Host '   0. Back to main menu' -ForegroundColor White
        Write-Host ''

        $sel = "$(Read-Host 'Select an option to change')".Trim()
        if ($sel -eq '' -or $sel -eq '0') { return }
        $n = 0
        if (-not [int]::TryParse($sel, [ref]$n) -or $n -lt 1 -or $n -gt ($base + 5)) {
            Show-Error "Invalid option '$sel'."
            Wait-ForKey
            continue
        }

        if ($n -le $base) {
            $opt = $defs[$n - 1]
            Set-SwitchOptionState -Option $opt -Enabled (-not (Get-SwitchOptionState -Option $opt))
            continue
        }

        try {
            switch ($n - $base) {
                1 {
                    $value = "$(Read-Host 'Level [Audit/Quick/Standard/Full]')".Trim()
                    $match = @('Audit', 'Quick', 'Standard', 'Full') | Where-Object { $_ -eq $value }
                    if (-not $match) { throw "Unknown level '$value'." }
                    $script:Level = @($match)[0]
                }
                2 {
                    $script:DismSource = "$(Read-Host 'DISM repair source, e.g. D:\sources\install.wim:1 (blank = Windows Update)')".Trim()
                }
                3 {
                    $value = "$(Read-Host 'Days of event log history to review (1-90)')".Trim()
                    $days = 0
                    if (-not [int]::TryParse($value, [ref]$days) -or $days -lt 1 -or $days -gt 90) { throw "Event log days must be a number from 1 to 90." }
                    $script:EventLogDays = $days
                }
                4 {
                    $value = "$(Read-Host 'Reports folder')".Trim()
                    if (-not $value) { throw 'Reports folder cannot be empty.' }
                    $script:LogRoot = $value
                }
                5 {
                    $value = "$(Read-Host 'Task names or wildcards to skip, comma separated (blank = none)')"
                    $patterns = @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    $script:SkipTask = if ($patterns.Count -gt 0) { [string[]]$patterns } else { $null }
                }
            }
        } catch {
            Show-Error $_.Exception.Message
            Wait-ForKey
        }
    }
}

function Invoke-MenuChoice {
    # Returns $true when the caller should pause so the user can read the output.
    [CmdletBinding(SupportsShouldProcess)]
    param([AllowEmptyString()][string]$Choice, [switch]$Interactive)

    $key = "$Choice".Trim()
    if (-not $Interactive -and $key -in @('5', '6', '7')) {
        throw "Menu option $key is interactive. Use -OnlyTask / -SkipTask and the matching switches instead."
    }

    switch ($key) {
        '1'  { Start-LevelRun -RunLevel 'Audit';    return $true }
        '2'  { Start-LevelRun -RunLevel 'Quick';    return $true }
        '3'  { Start-LevelRun -RunLevel 'Standard'; return $true }
        '4'  { Start-LevelRun -RunLevel 'Full';     return $true }
        '5'  { return [bool](Show-CategoryMenu) }
        '6'  { return [bool](Show-TaskPicker) }
        '7'  { Show-OptionsMenu; return $false }
        '8'  {
            Get-TaskCatalogueView | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
            return $true
        }
        '9'  {
            if ($PSCmdlet.ShouldProcess('Task Scheduler', "Register weekly 'WinDragon Maintenance Protocol' task")) {
                Register-MaintenanceTask
            }
            return $true
        }
        '10' { return $false }
        default {
            Show-Error "Invalid selection '$key'. Please choose an option from the menu."
            return $true
        }
    }
}

function Start-InteractiveMenu {
    ResetConsoleScreen
    Show-Dragon
    Write-Host ''
    Show-Message 'Disclaimer: You are running this script at your own risk.'
    Write-Host ''
    $confirmation = Read-Host "Please type 'Y' to confirm"
    if ($confirmation -ne 'Y') {
        Show-Error 'User did not confirm. Exiting script.'
        return
    }

    while ($true) {
        $choice = "$(Show-Menu)".Trim()
        if ($choice -eq '10') {
            ResetConsoleScreen
            return
        }
        $pause = $true
        try {
            $pause = [bool](Invoke-MenuChoice -Choice $choice -Interactive | Select-Object -Last 1)
        } catch {
            Show-Error ("Menu action failed: {0}" -f $_.Exception.Message)
        }
        if ($pause) { Wait-ForKey }
    }
}

#endregion
