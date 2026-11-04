import json, os, sys, time, datetime
sys.path.insert(0, "/root/soc-detection-rules/deploy")
from soc_deploy import call
Q = [("certutil proses (Sysmon 1)", 'event.code:1 AND winlog.event_data.Image:*certutil.exe'),
     ("mshta proses", 'event.code:1 AND winlog.event_data.Image:*mshta.exe'),
     ("regsvr32 proses", 'event.code:1 AND winlog.event_data.Image:*regsvr32.exe'),
     ("WMI ana proses (ParentImage wmiprvse)", 'event.code:1 AND winlog.event_data.ParentImage:*wmiprvse.exe'),
     ("komanda setrinde sekurlsa", 'winlog.event_data.CommandLine:*sekurlsa*'),
     ("Sysmon 11 socupdate.exe", 'event.code:11 AND winlog.event_data.TargetFilename:*socupdate*'),
     ("Sysmon 13 RunKey", 'event.code:13 AND winlog.event_data.RuleName:*RunKey*'),
     ("Security 4732", 'event.code:4732'),
     ("Security 4625", 'event.code:4625')]
print("== ELASTIC: hadise gelibmi? (son 40 deq) ==")
for name, q in Q:
    c, r = call("POST", "/soc-*/_count", {"query": {"bool": {"must": [{"query_string": {"query": q}}], "filter": [{"range": {"@timestamp": {"gte": "now-40m"}}}]}}})
    print("  %-42s %s" % (name, r.get("count", r)))
print("\n== WAZUH alerts.json: hedef hadiselere hansi qayda cavab verib (son 40 deq) ==")
keys = ("certutil", "mshta", "regsvr32", "wmiprvse", "sekurlsa", "socupdate", "RunKey", "4732", "soclabtest")
since = time.time() - 40 * 60
seen = {}
for line in open("/var/ossec/logs/alerts/alerts.json", errors="replace"):
    if not any(k in line for k in keys):
        continue
    try:
        a = json.loads(line); ts = datetime.datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except Exception:
        continue
    if ts < since:
        continue
    ed = a.get("data", {}).get("win", {}).get("eventdata", {})
    sample = (ed.get("commandLine") or ed.get("targetObject") or ed.get("targetFilename") or ed.get("targetUserName") or "")[:70]
    k = (a["rule"]["id"], a["rule"]["description"][:50])
    seen.setdefault(k, [0, sample])[0] += 1
for (rid, d), (n, s) in sorted(seen.items()):
    print("  rule %-7s x%-3d %-50s | %s" % (rid, n, d, s))
