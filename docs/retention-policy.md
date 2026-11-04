# Log Retention Policy (yazili siyaset) - 6.1

| Faza | Muddet | Yer | Emeliyyat | Meqsed |
|------|--------|-----|-----------|--------|
| Hot  | 0-7 gun   | Elasticsearch (soc-*)  | indeksleme + axtaris, priority 100 | Real vaxt aşkarlama, dashboard, alert |
| Warm | 7-30 gun  | Elasticsearch (soc-*)  | forcemerge 1 seqment, readonly, priority 50 | Arasdirma, tarixce sorgulari |
| Cold | 30-365 gun| Elasticsearch (priority 0) + gzip arxiv | az sorgulanan, priority 0 | Uygunluq (compliance), gec aşkarlanan insident |
| Delete | 365 gun | - | indeks silinir | Saxlama limitinin sonu |

- Siyaset ES-de `soc-logs-policy` ILM adi ile API ile tetbiq olunur (`deploy/soc_deploy.py es`), menbe: `elasticsearch/ilm/soc-logs-policy.json`.
- Asagi deyerli (filtrlenen) loglar SIEM-e getmir, `/var/log/cold_storage/<tip>-<tarix>.log.gz` kimi arxivlenir.
- Wazuh (ikinci SIEM) ucun saxlama: `wazuh-alerts-4.x-*` gunluk indeksler, `wazuh-archives` ve alerts faylı logrotate ile 365 gun.
