#!/usr/bin/env python3
"""Hucum testlerinin neticesi: hansi SIGMA qaydalari alert verdi. Istifade: python3 deploy/check_alerts.py [deqiqe=30]"""
import datetime, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soc_deploy import call, ROOT  # noqa: E402

MIN = int(sys.argv[1]) if len(sys.argv) > 1 else 30
ALERTS = os.environ.get("WAZUH_ALERTS", "/var/ossec/logs/alerts/alerts.json")


def wazuh():
    idx = {m["id"]: m for m in json.load(open(os.path.join(ROOT, "build/wazuh_index.json")))}
    since = time.time() - MIN * 60
    cnt, last, other = {}, {}, {}
    if not os.path.exists(ALERTS):
        print("alerts.json tapilmadi:", ALERTS)
        return
    for line in open(ALERTS, errors="replace"):
        if '"rule"' not in line:
            continue
        try:
            a = json.loads(line)
            ts = datetime.datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
        except Exception:
            continue
        if ts < since:
            continue
        rid = int(a["rule"]["id"])
        if rid in idx:
            cnt[rid] = cnt.get(rid, 0) + 1
            last[rid] = a["timestamp"][11:19]
        elif "sysmon_event1" in a["rule"].get("groups", []) or a["rule"]["id"] in ("60109", "60154", "60117", "60122"):
            k = (a["rule"]["id"], a["rule"]["description"][:55])
            other[k] = other.get(k, 0) + 1
    print("== WAZUH (son %d deq) ==" % MIN)
    fired = 0
    for rid in sorted(idx):
        m = idx[rid]
        c = cnt.get(rid, 0)
        fired += bool(c)
        print("  %s %d  lvl=%-2d %-52s %s" % ("ALERT" if c else "  -  ", rid, m["level"], m["title"][:52], ("x%d son %s" % (c, last[rid])) if c else ""))
    print("  -> %d / %d Wazuh SIGMA qaydasi isledi" % (fired, len(idx)))
    if other:
        print("  (eyni hadiselerde isleyen dahili qaydalar - kolge suphesi ucun:)")
        for (i, d), c in sorted(other.items(), key=lambda x: -x[1])[:8]:
            print("     built-in %s x%d  %s" % (i, c, d))


def elastic():
    body = {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-%dm" % MIN}}},
            "aggs": {"r": {"terms": {"field": "kibana.alert.rule.name", "size": 100}, "aggs": {"last": {"max": {"field": "@timestamp"}}}}}}
    code, res = call("POST", "/.alerts-security.alerts-*/_search", body)
    print("\n== ELASTIC (son %d deq) ==" % MIN)
    if code != 200:
        print("  alert indeksi oxunmadi:", code, str(res)[:200])
        return
    got = {b["key"]: b for b in res["aggregations"]["r"]["buckets"]}
    idx = json.load(open(os.path.join(ROOT, "build/elastic_index.json")))
    names = [m["name"] for m in idx] + ["Hunt - Yeni proses (New Terms: Image)"]
    fired = 0
    for n in sorted(names):
        b = got.get(n)
        fired += bool(b)
        print("  %s %-62s %s" % ("ALERT" if b else "  -  ", n[:62], ("x%d" % b["doc_count"]) if b else ""))
    print("  -> %d / %d Elastic qaydasi alert verdi" % (fired, len(names)))


wazuh()
elastic()
