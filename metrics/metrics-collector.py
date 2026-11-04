#!/usr/bin/env python3
"""MTTD / MTTR toplayicisi -> Elasticsearch indeksi soc-metrics (Kibana dashboard-u oxuyur).
 - MTTD (Elastic): alert @timestamp - kibana.alert.original_time (hadise bas verib -> alert yaranib)
 - MTTD (Wazuh):   alert timestamp - win.system.systemTime (yalniz level>=8 Windows alert-leri)
 - Ticket/MTTR:    GitHub Issues (label soc-alert, test olmayan): yaranma -> baglanma muddeti
Sirlar: /root/.soc-secrets/notify.env (git-de deyil)."""
import base64, datetime, json, os, sys, time, urllib.error, urllib.request

ENV_PATH, STACK_ENV = "/root/.soc-secrets/notify.env", "/root/elastic-stack/.env"
STATE, LOG = "/var/lib/soc-notify/metrics-state.json", "/var/log/soc-metrics.log"
ES = os.environ.get("ES_URL", "http://127.0.0.1:9201")
WZ_ALERTS = "/var/ossec/logs/alerts/alerts.json"
POLL, TICKET_EVERY = 30, 120


def log(m):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), m)
    print(line, flush=True)
    try:
        open(LOG, "a").write(line + "\n")
    except Exception:
        pass


def kv(path):
    d = {}
    for l in open(path):
        l = l.strip()
        if l and not l.startswith("#") and "=" in l:
            k, v = l.split("=", 1)
            d[k.strip()] = v.strip().strip('"')
    return d


def http(method, url, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    r.add_header("User-Agent", "soc-lab-metrics")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:200]}
    except Exception as e:
        return 0, {"error": str(e)}


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_ts(s):
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        frac = rest
        tz = ""
        for sep in ("+", "-"):
            if sep in rest:
                frac, tz = rest.split(sep, 1)
                tz = sep + tz
                break
        s = "%s.%s%s" % (head, (frac + "000000")[:6], tz)
        return datetime.datetime.fromisoformat(s)
    return datetime.datetime.fromisoformat(s)


def put(auth, doc_id, doc):
    return http("PUT", "%s/soc-metrics/_doc/%s" % (ES, doc_id), doc, auth)


def ensure_template(auth):
    http("PUT", ES + "/_index_template/soc-metrics", {
        "index_patterns": ["soc-metrics"], "priority": 300,
        "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0}, "mappings": {"properties": {
            "@timestamp": {"type": "date"}, "metric": {"type": "keyword"}, "siem": {"type": "keyword"},
            "severity": {"type": "keyword"}, "rule": {"type": "keyword"}, "state": {"type": "keyword"},
            "value_s": {"type": "double"}}}}}, auth)


def elastic_mttd(auth, st):
    cur = st.get("el_cursor") or iso(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=3))
    c, r = http("POST", ES + "/.alerts-security.alerts-*/_search",
                {"size": 500, "sort": [{"@timestamp": "asc"}], "query": {"range": {"@timestamp": {"gt": cur}}}}, auth)
    if c != 200:
        return
    n = 0
    for h in r.get("hits", {}).get("hits", []):
        a = h["_source"]
        cur = max(cur, a.get("@timestamp", cur))
        ot = a.get("kibana.alert.original_time")
        if not ot:
            continue
        v = (parse_ts(a["@timestamp"]) - parse_ts(ot)).total_seconds()
        put(auth, "el-" + h["_id"], {"@timestamp": a["@timestamp"], "metric": "mttd", "siem": "elastic", "value_s": max(v, 0),
                                     "severity": a.get("kibana.alert.severity", ""), "rule": a.get("kibana.alert.rule.name", "")})
        n += 1
    st["el_cursor"] = cur
    if n:
        log("MTTD elastic: %d yeni" % n)


def wazuh_mttd(auth, st):
    if not os.path.exists(WZ_ALERTS):
        return
    size = os.path.getsize(WZ_ALERTS)
    off = st.get("wz_off", 0)
    horizon = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=3)
    if off > size or st.get("wz_off") is None:
        off = 0
    n = 0
    with open(WZ_ALERTS, "rb") as f:
        f.seek(off)
        for raw in f:
            if not raw.endswith(b"\n"):
                break
            off += len(raw)
            if b"systemTime" not in raw:
                continue
            try:
                a = json.loads(raw)
                lvl = int(a["rule"]["level"])
                ts = parse_ts(a["timestamp"])
                if lvl < 8 or ts < horizon:
                    continue
                et = parse_ts(a["data"]["win"]["system"]["systemTime"])
            except Exception:
                continue
            put(auth, "wz-" + str(a.get("id")), {"@timestamp": iso(ts), "metric": "mttd", "siem": "wazuh", "value_s": max((ts - et).total_seconds(), 0),
                                                 "severity": "critical" if lvl >= 13 else "high" if lvl >= 11 else "medium",
                                                 "rule": a["rule"].get("description", "")})
            n += 1
    st["wz_off"] = off
    if n:
        log("MTTD wazuh: %d yeni" % n)


def tickets(auth, env, st):
    if time.time() - st.get("tk_ts", 0) < TICKET_EVERY or not env.get("GITHUB_TOKEN"):
        return
    st["tk_ts"] = time.time()
    gh = {"Authorization": "Bearer " + env["GITHUB_TOKEN"], "Accept": "application/vnd.github+json"}
    c, lst = http("GET", "https://api.github.com/repos/%s/issues?state=all&labels=soc-alert&per_page=100" % env["GITHUB_REPO"], None, gh)
    if c != 200 or not isinstance(lst, list):
        log("GitHub xetasi HTTP %s" % c)
        return
    for i in lst:
        labs = [l["name"] for l in i.get("labels", [])]
        if "test" in labs or "pull_request" in i:
            continue
        sev = next((l[4:] for l in labs if l.startswith("sev-")), "")
        siem = "wazuh" if "wazuh" in labs else "elastic" if "elastic" in labs else "other"
        doc = {"@timestamp": i["created_at"], "metric": "ticket", "siem": siem, "severity": sev, "state": i["state"], "rule": i["title"][:120], "value_s": 0}
        if i["state"] == "closed" and i.get("closed_at"):
            doc["value_s"] = (parse_ts(i["closed_at"]) - parse_ts(i["created_at"])).total_seconds()
        put(auth, "tk-%d" % i["number"], doc)


def main():
    env = kv(ENV_PATH)
    auth = {"Authorization": "Basic " + base64.b64encode(("elastic:" + kv(STACK_ENV)["ELASTIC_PASSWORD"]).encode()).decode()}
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    try:
        st = json.load(open(STATE))
    except Exception:
        st = {}
    ensure_template(auth)
    log("metrics-collector basladi")
    while True:
        for fn in (lambda: elastic_mttd(auth, st), lambda: wazuh_mttd(auth, st), lambda: tickets(auth, env, st)):
            try:
                fn()
            except Exception as e:
                log("XETA %s" % e)
        json.dump(st, open(STATE, "w"))
        time.sleep(POLL)


if __name__ == "__main__":
    main()
