#!/usr/bin/env python3
"""SOC deploy - Elasticsearch obyektlerini (ILM, ingest pipeline, index template) API ile tetbiq edir.
Hec bir obyekt UI-dan yazilmir; menbe GitHub reposundur.

Istifade:
  python3 deploy/soc_deploy.py es       # ILM + ingest + 6 template -> ES API
  python3 deploy/soc_deploy.py status   # indekslər, ILM fazalari, Logstash sayğaclari, cold storage
"""
import base64, glob, gzip, json, os, sys, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ES = os.environ.get("ES_URL", "http://127.0.0.1:9201")
LS = os.environ.get("LS_URL", "http://127.0.0.1:9600")
COLD = os.environ.get("COLD_DIR", "/var/log/cold_storage")


def password():
    pw = os.environ.get("ELASTIC_PASSWORD")
    if pw:
        return pw
    for p in ("/root/elastic-stack/.env", os.path.join(ROOT, ".env")):
        if os.path.exists(p):
            for line in open(p):
                if line.startswith("ELASTIC_PASSWORD="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    sys.exit("XETA: ELASTIC_PASSWORD tapilmadi (/root/elastic-stack/.env)")


def call(method, path, body=None, base=None, auth=True):
    base = base or ES
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(base + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if auth:
        tok = base64.b64encode(("elastic:" + password()).encode()).decode()
        r.add_header("Authorization", "Basic " + tok)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}
    except Exception as e:
        return 0, {"error": str(e)}


def load(path):
    with open(path) as f:
        return json.load(f)


def deploy_es():
    ok = True
    items = [("PUT", "/_ilm/policy/soc-logs-policy", os.path.join(ROOT, "elasticsearch/ilm/soc-logs-policy.json")),
             ("PUT", "/_ingest/pipeline/soc-enrich", os.path.join(ROOT, "elasticsearch/ingest/soc-enrich.json"))]
    for f in sorted(glob.glob(os.path.join(ROOT, "elasticsearch/templates/*.json"))):
        name = os.path.basename(f)[:-5]
        items.append(("PUT", "/_index_template/" + name, f))
    for m, path, f in items:
        code, res = call(m, path, load(f))
        good = code in (200, 201) and res.get("acknowledged", False)
        ok &= good
        print(("OK    " if good else "FAIL  ") + path + "  (" + os.path.relpath(f, ROOT) + ")" + ("" if good else "  -> " + json.dumps(res)[:300]))
    print("\nNetice:", "BUTUN OBYEKTLER TETBIQ OLUNDU" if ok else "XETA VAR")
    return 0 if ok else 1


def cold_stats():
    rows = []
    for f in sorted(glob.glob(os.path.join(COLD, "*.gz"))):
        n = 0
        try:
            with gzip.open(f, "rt", errors="replace") as g:
                for _ in g:
                    n += 1
        except Exception:
            n = -1
        rows.append((os.path.basename(f), os.path.getsize(f), n))
    return rows


def status():
    print("== Elasticsearch ==")
    code, h = call("GET", "/_cluster/health")
    print("cluster:", h.get("status"), "| node count:", h.get("number_of_nodes"))
    print("\n== soc-* indekslər (6 dedicated indeks) ==")
    code, idx = call("GET", "/_cat/indices/soc-*?format=json&h=index,docs.count,store.size,health&s=index")
    if isinstance(idx, list) and idx:
        for i in idx:
            print("  %-34s docs=%-8s size=%-8s %s" % (i["index"], i["docs.count"], i["store.size"], i["health"]))
    else:
        print("  hele indeks yoxdur (log gelmeyib)")
    print("\n== ILM (hot/warm/cold/delete) ==")
    code, pol = call("GET", "/_ilm/policy/soc-logs-policy")
    ph = pol.get("soc-logs-policy", {}).get("policy", {}).get("phases", {})
    for k in ("hot", "warm", "cold", "delete"):
        if k in ph:
            print("  %-7s min_age=%s" % (k, ph[k].get("min_age")))
    code, ex = call("GET", "/soc-*/_ilm/explain?only_managed=true")
    for name, v in sorted(ex.get("indices", {}).items()):
        print("  %-34s faza=%s policy=%s" % (name, v.get("phase"), v.get("policy")))
    print("\n== Logstash router ==")
    code, st = call("GET", "/_node/stats/events", base=LS, auth=False)
    if code == 200:
        e = st.get("events", {})
        print("  in=%s filtered=%s out=%s" % (e.get("in"), e.get("filtered"), e.get("out")))
    else:
        print("  Logstash API cavab vermir (basladi mi?)", code)
    print("\n== Cold storage (suzulen loglar, arxiv) ==")
    rows = cold_stats()
    if rows:
        for n, sz, c in rows:
            print("  %-36s %8d bayt  %6d hadise" % (n, sz, c))
    else:
        print("  hele arxiv fayli yoxdur")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "es"
    sys.exit(deploy_es() if cmd == "es" else status() if cmd == "status" else print(__doc__) or 1)
