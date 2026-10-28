param(
    [int]$Minutes = 20,
    [int]$IntervalSec = 5,
    [string]$Out = 'D:\XiuXian\_analysis\probe_gdi2.csv'
)

Add-Type -Namespace W -Name U -MemberDefinition @'
[DllImport("user32.dll")] public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);
'@

$deadline = (Get-Date).AddMinutes($Minutes)
"ts,elapsed_s,pid,gdi,dgdi,user,handles,priv_mb,ws_mb" | Set-Content -Path $Out -Encoding utf8
$t0 = $null
$lastGdi = $null

while ((Get-Date) -lt $deadline) {
    $p = $null
    foreach ($q in (Get-Process -ErrorAction SilentlyContinue)) {
        try { if ($q.Path -like 'D:\XiuXian\*.exe') { $p = $q; break } } catch { }
    }
    if ($p) {
        if (-not $t0) { $t0 = Get-Date; $lastGdi = $null }
        try {
            $gdi  = [W.U]::GetGuiResources($p.Handle, 0)
            $user = [W.U]::GetGuiResources($p.Handle, 1)
        } catch { $gdi = -1; $user = -1 }
        $d = if ($lastGdi -ne $null) { $gdi - $lastGdi } else { 0 }
        $lastGdi = $gdi
        $el = [int]((Get-Date) - $t0).TotalSeconds
        $line = '{0},{1},{2},{3},{4},{5},{6},{7:N1},{8:N1}' -f `
            (Get-Date -Format 'HH:mm:ss'), $el, $p.Id, $gdi, $d, $user, `
            $p.HandleCount, ($p.PrivateMemorySize64/1MB), ($p.WorkingSet64/1MB)
        Add-Content -Path $Out -Value $line -Encoding utf8
        Write-Output $line
    } else {
        $t0 = $null; $lastGdi = $null
        Write-Output ("{0},-,-,-,-,-,-,-,-" -f (Get-Date -Format 'HH:mm:ss'))
    }
    Start-Sleep -Seconds $IntervalSec
}
Write-Output 'probe finished'
