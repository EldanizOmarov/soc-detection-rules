# Log Routing (6.2)

Butun menbeler Logstash-dan kecir (repo: `logstash/pipeline/*.conf`):

| Menbe | Giris | Indeks |
|-------|-------|--------|
| Windows Sysmon / PowerShell / sistem (Winlogbeat) | beats :5044 | soc-endpoint-* |
| Windows Security auth hadiseleri + Linux auth.log | beats :5044 / file | soc-auth-* |
| Firewall syslog, Sysmon 3/22 | tcp :5140 / beats | soc-network-* |
| nginx access log | file | soc-web-* |
| Mail gateway | tcp :5141 | soc-email-* |
| CloudTrail formatli JSON | tcp :5142 | soc-cloud-* |

## Asagi deyerli filtr (30-lowvalue.conf)
- Security 5152/5156/5157/5158 (WFP), 4656/4658/4690/4663 (obyekt/handle)
- DEBUG mesajlar, Linux CRON sessiyalari, firewall ALLOW
- Bu hadiseler SIEM-e YAZILMIR, `file` output ile gzip cold storage-a yazilir.

## Deyisiklik idareetmesi
Routing deyisikliyi git commit ile versiyalanir, Logstash `config.reload.automatic` ile 5 san erzinde API/restart olmadan tetbiq edir.
