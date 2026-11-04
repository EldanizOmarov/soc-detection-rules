# Bildiris, korelyasiya ve ticket siyaseti (6.4)

Menbe: `notify/policy.json` (her iki SIEM ucun tek siyaset, GitHub-da versiyalanir). Sirlar (Telegram/GitHub token) git-de DEYIL: `/root/.soc-secrets/notify.env`.

## Seviyye -> kanal

| Seviyye | Wazuh level | Elastic severity | Telegram | Email (MailHog) | Ticket (GitHub Issue) |
|---|---|---|---|---|---|
| Kritik | >= 13 | critical | + | + | + |
| Yuksek | 11-12 | high | + | - | + |
| Orta | 8-10 | medium | - | + | - |
| Asagi | < 8 | low | - | - | - (yalniz dashboard) |

## Korelyasiya / qruplasdirma
- **Qayda seviyyesinde:** Wazuh `frequency/timeframe` (meselen 100490: 120 san-de 5 ugursuz giris), Elastic `threshold` / `new_terms` qaydalari tek-tek hadiseleri tek alert-e cevirir.
- **Bildiris seviyyesinde (throttle):** eyni qayda + agent ucun Telegram/Email 5 deq (Elastic email 15 deq), ticket 1 saat pencerede bir defe gonderilir; pencere erzinde tekrarlar sayilir ve novbeti mesajda "+N tekrar" kimi gosterilir. Elastic tarafinda eyni pencere `elastic-notify` servisinde tetbiq olunur.

## Alert -> ticket avtomatlasdirmasi
- Wazuh: `integratord` -> `custom-soc-notify` (GitHub Issues API). Eyni basliqli ACIQ issue varsa yenisi acilmir, serh elave olunur (dublikat ticket yoxdur).
- Elastic: `elastic-notify` servisi -> GitHub Issues API (eyni dedup mentiqi). Labels: `soc-alert`, `wazuh|elastic`, `sev-<seviyye>`.
- Qapanma: issue-nu analitik arasdirmadan sonra el ile baglayir (MTTR olcmesi ucun acilis/baglanis vaxti istifade olunur).

## Kanallar
- Telegram: bot -> SOC chat (anlik, kritik/yuksek).
- Email: Wazuh script ve `elastic-notify` -> MailHog SMTP (`soc-team@lab.local`, UI: http://localhost:8025).
- Ticket: GitHub Issues (`EldanizOmarov/soc-detection-rules`).

## Elastic ucun qeyd (lisenziya)
Elastic BASIC lisenziyasi Kibana `.webhook` ve `.email` connector-larini desteklemir (HTTP 403: *Action type is disabled because your basic license does not support it*). Buna gore Elastic bildirisleri `notify/elastic/elastic-notify.py` servisi (systemd: `soc-elastic-notify`) ile gonderilir: `.alerts-security.alerts-*` indeksini her 30 saniyeden bir yoxlayir ve eyni `policy.json` siyasetini tetbiq edir. Servis kodu GitHub-da versiyalanir.
