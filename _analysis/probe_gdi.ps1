param(
    [int]$Minutes = 25,
    [int]$IntervalSec = 2,
    [string]$Out = 'D:\XiuXian\_analysis\probe_gdi.csv'
)

Add-Type -Namespace W -Name U -MemberDefinition @'
[DllImport("user32.dll")] public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);
'@

$deadline = (Get-Date).AddMinutes($Minutes)
"ts,elapsed_s,pid,gdi,user,handles,priv_mb,ws_mb,threads,title" | Set-Content -Path $Out -Encoding utf8
$t0 = $null

while ((Get-Date) -lt $deadline) {
    $p = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -like '*修仙*' -or $_.MainWindowTitle -like '*修仙*'
    } | Select-Object -First 1

    if ($p) {
        if (-not $t0) { $t0 = Get-Date }
        try {
            $gdi  = [W.U]::GetGuiResources($p.Handle, 0)
            $user = [W.U]::GetGuiResources($p.Handle, 1)
        } catch { $gdi = -1; $user = -1 }
        $el = [int]((Get-Date) - $t0).TotalSeconds
        $line = '{0},{1},{2},{3},{4},{5},{6},{7},{8},"{9}"' -f `
            (Get-Date -Format 'HH:mm:ss'), $el, $p.Id, $gdi, $user, `
            $p.HandleCount, [math]::Round($p.PrivateMemorySize64/1MB,1), `
            [math]::Round($p.WorkingSet64/1MB,1), $p.Threads.Count, $p.MainWindowTitle
        Add-Content -Path $Out -Value $line -Encoding utf8
        Write-Output $line
    } else {
        $t0 = $null
        Write-Output ("{0},-,-,-,-,-,-,-,-," -f (Get-Date -Format 'HH:mm:ss'))
    }
    Start-Sleep -Seconds $IntervalSec
}
Write-Output 'probe finished'
