# MITRE ATT&CK xəritələməsi (avtomatik, `deploy/sigma_convert.py`)

| SIEM | Qayda | Səviyyə | Texnikalar | Test əmri |
|---|---|---|---|---|
| Wazuh | Certutil URL Download (Security 4688) | 11 | T1105 | `certutil -urlcache -split -f http://127.0.0.1:9/soc.txt %TEMP%\soc.txt` |
| Wazuh | Credential Dumping Command Keywords (Security 4688) | 13 | T1003 | `cmd.exe /c echo sekurlsa::logonpasswords   (yalniz echo)` |
| Wazuh | Mshta Script or URL Execution (Security 4688) | 11 | T1218.005 | `mshta.exe vbscript:Close(Execute("x=1"))` |
| Wazuh | Regsvr32 Remote Scriptlet (Security 4688) | 11 | T1218.010 | `regsvr32 /s /n /u /i:http://127.0.0.1:9/x.sct scrobj.dll` |
| Wazuh | Local Account Discovery (net user/localgroup) | 5 | T1087.001 | `net user ; net localgroup administrators` |
| Wazuh | Member Added to Local Administrators (4732) | 13 | T1098 | `net localgroup Administrators soclabtest /add` |
| Wazuh | Bitsadmin Transfer Job | 8 | T1197 | `bitsadmin /transfer soclab /download /priority low http://127.0.0.1:9/x %TEMP%\x.tmp` |
| Wazuh | Certutil URL Download | 11 | T1105 | `certutil -urlcache -split -f http://127.0.0.1:9/soc.txt %TEMP%\soc.txt` |
| Wazuh | Defender Tampering via Set-MpPreference | 13 | T1562.001 | `cmd.exe /c echo Set-MpPreference -DisableRealtimeMonitoring $true   (yalniz echo - Defender dəyişmir)` |
| Wazuh | Executable Dropped in User Temp | 5 | T1105 | `Copy-Item C:\Windows\System32\whoami.exe $env:TEMP\socupdate.exe` |
| Wazuh | Multiple Failed Logons (4625) - Brute Force | 11 | T1110 | `net use \\127.0.0.1\IPC$ /user:soclabbad WrongPass123  (6 dəfə)` |
| Wazuh | Windows Firewall Disabled via netsh | 13 | T1562.004 | `cmd.exe /c echo netsh advfirewall set allprofiles state off   (yalniz echo)` |
| Wazuh | Credential Dumping Command Keywords | 13 | T1003 | `cmd.exe /c echo sekurlsa::logonpasswords   (yalniz echo)` |
| Wazuh | Mshta Script or URL Execution | 11 | T1218.005 | `mshta.exe vbscript:Close(Execute("x=1"))` |
| Wazuh | New Local User Created (4720) | 11 | T1136.001 | `net user soclabtest S0cLab!2026x /add` |
| Wazuh | PowerShell Download Cradle | 11 | T1105, T1059.001 | `powershell -NoProfile -Command "echo (New-Object Net.WebClient).DownloadString"   (yükləmə yoxdur)` |
| Wazuh | PowerShell Encoded Command | 11 | T1059.001, T1027 | `powershell.exe -NoProfile -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHMAbwBjACcA` |
| Wazuh | System Owner / Information Discovery | 5 | T1033, T1082 | `whoami /priv ; systeminfo` |
| Wazuh | Registry Run Key Persistence | 11 | T1547.001 | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SOCTest /t REG_SZ /d C:\Windows\System32\calc.exe /f` |
| Wazuh | Regsvr32 Remote Scriptlet (Squiblydoo) | 11 | T1218.010 | `regsvr32 /s /n /u /i:http://127.0.0.1:9/x.sct scrobj.dll` |
| Wazuh | Scheduled Task Creation (schtasks) | 11 | T1053.005 | `schtasks /create /tn SOCTest /tr cmd.exe /sc once /st 23:59 /f` |
| Wazuh | Service Creation (sc.exe) | 11 | T1543.003 | `sc create SOCTestSvc binPath= "C:\Windows\System32\cmd.exe"` |
| Wazuh | Shadow Copy Deletion (vssadmin) | 13 | T1490 | `vssadmin delete shadows /for=Z: /quiet   (Z: yoxdur - zərərsiz)` |
| Wazuh | Windows Event Log Clearing (wevtutil) | 11 | T1070.001 | `wevtutil cl SOCNoSuchLog   (log yoxdur - zərərsiz)` |
| Wazuh | Shell Spawned by WMI Provider Host | 11 | T1047 | `Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd.exe /c echo soc'}` |
| Elastic | Cloud Access Key Created | medium | T1098.001 | `python3 deploy/gen_logs.py cloud-attack` |
| Elastic | Cloud Root Console Login Without MFA | critical | T1078.004 | `python3 deploy/gen_logs.py cloud-attack` |
| Elastic | CloudTrail Logging Tampering | critical | T1562.008 | `python3 deploy/gen_logs.py cloud-attack` |
| Elastic | Email With Dangerous Attachment | high | T1566.001 | `python3 deploy/gen_logs.py email-phish` |
| Elastic | Linux Auth - Failed Password Burst | high | T1110.001 | `python3 deploy/gen_logs.py linux-auth-fail` |
| Elastic | Port Scan Detected (Firewall DENY burst) | medium | T1046 | `python3 deploy/gen_logs.py net-scan` |
| Elastic | Web Login Brute Force (401 burst) | high | T1110 | `python3 deploy/gen_logs.py web-brute` |
| Elastic | Web Vulnerability Scanner User-Agent | medium | T1595.002 | `python3 deploy/gen_logs.py web-scanner` |
| Elastic | Web SQL Injection Attempt | high | T1190 | `python3 deploy/gen_logs.py web-sqli` |
| Elastic | Web XSS Attempt | medium | T1190 | `python3 deploy/gen_logs.py web-xss` |
| Elastic | Certutil URL Download (Security 4688) | high | T1105 | `certutil -urlcache -split -f http://127.0.0.1:9/soc.txt %TEMP%\soc.txt` |
| Elastic | Credential Dumping Command Keywords (Security 4688) | critical | T1003 | `cmd.exe /c echo sekurlsa::logonpasswords   (yalniz echo)` |
| Elastic | Mshta Script or URL Execution (Security 4688) | high | T1218.005 | `mshta.exe vbscript:Close(Execute("x=1"))` |
| Elastic | Regsvr32 Remote Scriptlet (Security 4688) | high | T1218.010 | `regsvr32 /s /n /u /i:http://127.0.0.1:9/x.sct scrobj.dll` |
| Elastic | Certutil URL Download | high | T1105 | `certutil -urlcache -split -f http://127.0.0.1:9/soc.txt %TEMP%\soc.txt` |
| Elastic | Suspiciously Long DNS Query (DNS Tunneling) | medium | T1071.004 | `Resolve-DnsName (("a"*40)+"."+("b"*40)+".example.com")` |
| Elastic | Event Logs Cleared (1102/104) | high | T1070.001 | `Clear-EventLog -LogName Application (yalniz lab ucun, test edilmir)` |
| Elastic | Failed Logons Threshold (4625) | medium | T1110 | `net use \\127.0.0.1\IPC$ /user:soclabbad WrongPass123  (6 dəfə)` |
| Elastic | LSASS Process Access | critical | T1003.001 | `(Sysmon Event 10 data boşluğu - Bölmə 11 H5)` |
| Elastic | New Local User Created (4720) | medium | T1136.001 | `net user soclabtest S0cLab!2026x /add` |
| Elastic | Interactive Logon Outside Working Hours | low | T1078 | `(real giriş: iş stansiyasını 23:00 sonra kilid açmaq)` |
| Elastic | PowerShell Encoded Command | high | T1059.001, T1027 | `powershell.exe -NoProfile -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHMAbwBjACcA` |
| Elastic | Registry Run Key Persistence | medium | T1547.001 | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SOCTest /t REG_SZ /d C:\Windows\System32\calc.exe /f` |
| Elastic | Scheduled Task Creation | medium | T1053.005 | `schtasks /create /tn SOCTest /tr cmd.exe /sc once /st 23:59 /f` |

**Cəmi unikal texnika:** 32 (T1003, T1003.001, T1027, T1033, T1046, T1047, T1053.005, T1059.001, T1070.001, T1071.004, T1078, T1078.004, T1082, T1087.001, T1098, T1098.001, T1105, T1110, T1110.001, T1136.001, T1190, T1197, T1218.005, T1218.010, T1490, T1543.003, T1547.001, T1562.001, T1562.004, T1562.008, T1566.001, T1595.002)
