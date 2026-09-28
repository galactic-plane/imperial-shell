# WinDragon - Task catalogue
# The ordered task list executed by every maintenance pass. Identical to the vader catalogue:
# same names, categories, minimum levels, audit-safety flags and actions.

#region ---------------------------------------------------------------- Task catalogue

$script:TaskCatalogue = @(
    New-MaintenanceTask -Name 'System Inventory'          -Category 'Baseline'    -MinLevel 1 -ReadOnly -Action { Invoke-InventoryTask }
    New-MaintenanceTask -Name 'Servicing Lifecycle Check' -Category 'Baseline'    -MinLevel 1 -ReadOnly -Action { Invoke-LifecycleTask }
    New-MaintenanceTask -Name 'Free Space Check'          -Category 'Baseline'    -MinLevel 1 -ReadOnly -Action { Invoke-FreeSpaceTask }
    New-MaintenanceTask -Name 'System Restore Point'      -Category 'Baseline'    -MinLevel 2           -Action { Invoke-RestorePointTask }

    New-MaintenanceTask -Name 'DISM Health Chain'         -Category 'Integrity'   -MinLevel 1 -ReadOnly -Action { Invoke-DismHealthChain }
    New-MaintenanceTask -Name 'SFC System File Scan'      -Category 'Integrity'   -MinLevel 2 -ReadOnly -Action { Invoke-SfcTask }
    New-MaintenanceTask -Name 'CBS Log Review'            -Category 'Integrity'   -MinLevel 2 -ReadOnly -Action { Invoke-CbsLogReviewTask }
    New-MaintenanceTask -Name 'Component Store Cleanup'   -Category 'Integrity'   -MinLevel 3           -Action { Invoke-ComponentStoreTask }

    New-MaintenanceTask -Name 'Physical Disk Health'      -Category 'Storage'     -MinLevel 1 -ReadOnly -Action { Invoke-PhysicalDiskHealthTask }
    New-MaintenanceTask -Name 'Volume File System Scan'   -Category 'Storage'     -MinLevel 2 -ReadOnly -Action { Invoke-VolumeScanTask }
    New-MaintenanceTask -Name 'CHKDSK Scheduling'         -Category 'Storage'     -MinLevel 2           -Action { Invoke-ChkdskScheduleTask }
    New-MaintenanceTask -Name 'Volume Optimization'       -Category 'Storage'     -MinLevel 2           -Action { Invoke-OptimizeVolumeTask }

    New-MaintenanceTask -Name 'Windows Update'            -Category 'Servicing'   -MinLevel 1 -ReadOnly -Action { Invoke-WindowsUpdateTask }
    New-MaintenanceTask -Name 'Windows Update Stack Repair' -Category 'Servicing' -MinLevel 2           -Action { Invoke-WindowsUpdateRepairTask }
    New-MaintenanceTask -Name 'Store App Update Scan'     -Category 'Servicing'   -MinLevel 2           -Action { Invoke-StoreAppUpdateTask }
    New-MaintenanceTask -Name 'Winget & Store App Upgrade' -Category 'Servicing'  -MinLevel 2           -Action { Invoke-WingetTask }
    New-MaintenanceTask -Name 'PowerShell Hygiene'        -Category 'Servicing'   -MinLevel 3           -Action { Invoke-PowerShellHygieneTask }

    New-MaintenanceTask -Name 'Defender Health'           -Category 'Security'    -MinLevel 1 -ReadOnly -Action { Invoke-DefenderTask }
    New-MaintenanceTask -Name 'Security Posture'          -Category 'Security'    -MinLevel 2 -ReadOnly -Action { Invoke-SecurityPostureTask }

    New-MaintenanceTask -Name 'Temp and Cache Cleanup'    -Category 'Cleanup'     -MinLevel 1           -Action { Invoke-CleanupTask }
    New-MaintenanceTask -Name 'Disk Cleanup Profile'      -Category 'Cleanup'     -MinLevel 2           -Action { Invoke-DiskCleanupTask }
    New-MaintenanceTask -Name 'Storage Sense Review'      -Category 'Cleanup'     -MinLevel 2 -ReadOnly -Action { Invoke-StorageSenseReportTask }

    New-MaintenanceTask -Name 'Event Log Review'          -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-EventLogReviewTask }
    New-MaintenanceTask -Name 'Driver and Device Health'  -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-DriverHealthTask }
    New-MaintenanceTask -Name 'Service Health'            -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-ServiceHealthTask }
    New-MaintenanceTask -Name 'WMI Repository Check'      -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-WmiRepositoryTask }
    New-MaintenanceTask -Name 'Power Configuration'       -Category 'Diagnostics' -MinLevel 2 -ReadOnly -Action { Invoke-PowerConfigTask }
    New-MaintenanceTask -Name 'Startup Impact Review'     -Category 'Diagnostics' -MinLevel 3 -ReadOnly -Action { Invoke-StartupImpactTask }
    New-MaintenanceTask -Name 'Pending Reboot Check'      -Category 'Diagnostics' -MinLevel 1 -ReadOnly -Action { Invoke-PendingRebootTask }
)

#endregion
