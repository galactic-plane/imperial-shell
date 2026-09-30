# WinDragon - Reporting module
# Console summary and standalone HTML report.
# One-to-one replica of the "Reporting" region of vader\Invoke-ImperialMaintenance.ps1 (rebranded).

#region ---------------------------------------------------------------- Reporting

function ConvertTo-HtmlSafe {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Write-HtmlReport {
    param([Parameter(Mandatory)][string]$Path)

    $snap = $script:Snapshot
    if (-not $snap) { $snap = Get-SystemSnapshot }
    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)

    $statusColor = @{
        'OK' = '#2ea043'; 'Repaired' = '#58a6ff'; 'Warning' = '#d29922'
        'Failed' = '#f85149'; 'Skipped' = '#6e7681'
    }

    $rows = foreach ($r in $script:Results) {
        $color = $statusColor[$r.Status]
        if (-not $color) { $color = '#8b949e' }
        @"
<tr>
  <td>$(ConvertTo-HtmlSafe $r.Category)</td>
  <td>$(ConvertTo-HtmlSafe $r.Task)</td>
  <td><span class="pill" style="background:$color">$($r.Status)</span></td>
  <td class="num">$($r.Seconds)</td>
  <td>$(ConvertTo-HtmlSafe ([string]$r.Detail))</td>
</tr>
"@
    }

    $findingItems = foreach ($f in $script:Findings) {
        "<li>$(ConvertTo-HtmlSafe $f)</li>"
    }
    if (-not $findingItems) { $findingItems = '<li>No action items. System is nominal.</li>' }

    $counts = $script:Results | Group-Object Status | ForEach-Object { "$($_.Name): $($_.Count)" }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WinDragon Maintenance Report - $(ConvertTo-HtmlSafe $snap.ComputerName)</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:'Segoe UI',system-ui,sans-serif; margin:0; padding:32px; }
  h1 { color:#f85149; font-size:24px; margin:0 0 4px; letter-spacing:1px; }
  h2 { color:#58a6ff; font-size:16px; margin:28px 0 10px; border-bottom:1px solid #21262d; padding-bottom:6px; }
  .sub { color:#8b949e; font-size:13px; margin-bottom:20px; }
  table { border-collapse:collapse; width:100%; font-size:13px; }
  th { text-align:left; color:#8b949e; font-weight:600; padding:8px; border-bottom:1px solid #30363d; }
  td { padding:7px 8px; border-bottom:1px solid #161b22; vertical-align:top; }
  td.num { text-align:right; color:#8b949e; }
  tr:hover td { background:#161b22; }
  .pill { display:inline-block; padding:2px 9px; border-radius:10px; color:#0d1117; font-weight:700; font-size:11px; }
  .kv { display:grid; grid-template-columns:200px 1fr; gap:4px 16px; font-size:13px; }
  .kv div:nth-child(odd) { color:#8b949e; }
  ul { font-size:13px; line-height:1.7; }
  code { background:#161b22; padding:1px 5px; border-radius:4px; color:#79c0ff; }
</style></head><body>
<h1>WINDRAGON MAINTENANCE PROTOCOL</h1>
<div class="sub">$(ConvertTo-HtmlSafe $snap.ComputerName) &nbsp;|&nbsp; $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;|&nbsp; level: $Level &nbsp;|&nbsp; duration: $duration min &nbsp;|&nbsp; script v$($script:ScriptVersion)</div>

<h2>System</h2>
<div class="kv">
  <div>Operating system</div><div>$(ConvertTo-HtmlSafe "$($snap.Caption) $($snap.DisplayVersion) (build $($snap.FullBuild))")</div>
  <div>Edition</div><div>$(ConvertTo-HtmlSafe $snap.Edition)</div>
  <div>Hardware</div><div>$(ConvertTo-HtmlSafe "$($snap.Manufacturer) $($snap.Model)")</div>
  <div>Processor</div><div>$(ConvertTo-HtmlSafe $snap.Cpu) &mdash; $($snap.Cores)C / $($snap.Threads)T</div>
  <div>Memory</div><div>$($snap.MemoryGb) GB</div>
  <div>Firmware</div><div>$(ConvertTo-HtmlSafe $snap.BiosVersion)</div>
  <div>Uptime at start</div><div>$($snap.UptimeHours) hours</div>
  <div>PowerShell</div><div>$($snap.PowerShell)</div>
  <div>Restart required</div><div>$(if ($script:RebootNeeded) { '<strong style="color:#d29922">YES</strong>' } else { 'No' })</div>
</div>

<h2>Action items</h2>
<ul>
$($findingItems -join "`n")
</ul>

<h2>Task results &mdash; $($counts -join ' &nbsp;|&nbsp; ')</h2>
<table>
<thead><tr><th>Category</th><th>Task</th><th>Status</th><th>Sec</th><th>Detail</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>

</body></html>
"@

    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

function Write-RunSummary {
    Write-Banner 'Maintenance summary'

    $script:Results |
        Where-Object { $_.Status -ne 'Skipped' } |
        Select-Object Category, Task, Status, Seconds, Detail |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Host

    $skipped = @($script:Results | Where-Object { $_.Status -eq 'Skipped' })
    if ($skipped.Count -gt 0) {
        Write-Host ("  Skipped: {0} task(s) - {1}" -f $skipped.Count, (($skipped.Task) -join ', ')) -ForegroundColor DarkGray
    }

    $counts = $script:Results | Group-Object Status
    Write-Host ''
    foreach ($c in $counts) {
        $color = switch ($c.Name) {
            'OK' { 'Green' } 'Repaired' { 'Cyan' } 'Warning' { 'Yellow' }
            'Failed' { 'Red' } default { 'DarkGray' }
        }
        Write-Host ("  {0,-10} {1}" -f $c.Name, $c.Count) -ForegroundColor $color
    }

    if ($script:Findings.Count -gt 0) {
        Write-Host ''
        Write-Host '  ACTION ITEMS' -ForegroundColor Yellow
        $i = 1
        foreach ($f in $script:Findings) {
            Write-Host ("   {0}. {1}" -f $i, $f) -ForegroundColor Yellow
            $i++
        }
    } else {
        Write-Host ''
        Write-Good 'No outstanding action items. All systems nominal.'
    }

    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)
    Write-Host ''
    Write-Host ("  Elapsed: {0} minutes" -f $duration) -ForegroundColor Gray
    Write-Host ("  Reports: {0}" -f $script:RunLogDir) -ForegroundColor Gray

    if ($script:RebootNeeded) {
        Write-Host ''
        Write-Host '  ***  A RESTART IS REQUIRED TO COMPLETE THIS MAINTENANCE  ***' -ForegroundColor Red
        Write-Host '       Use Restart, not Shut Down - Fast Startup skips a true cold boot.' -ForegroundColor DarkYellow
    }
}

#endregion
