#!/usr/bin/env python3
"""Elastic SIEM: build/elastic/*.json + elastic/native/*.json qaydalarini Kibana Detection Engine API ile tetbiq edir.
UI-da qayda yazilmir; menbe GitHub (sigma/elastic/*.yml). Idempotent: movcud rule_id -> PUT (yenilenir)."""
import base64, glob, json, os, sys, urllib.error, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soc_deploy import password, ROOT  # noqa: E402
from notify_common import load_env, elastic_actions  # noqa: E402

KB = os.environ.get("KIBANA_URL", "http://127.0.0.1:5601")
AUTH = "Basic " + base64.b64encode(("elastic:" + password()).encode()).decode()


def kb(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(KB + path, data=data, method=method)
    r.add_header("kbn-xsrf", "true")
    r.add_header("Content-Type", "application/json")
    r.add_header("Authorization", AUTH)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
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


def main():
    code, st = kb("GET", "/api/status")
    if code != 200:
        sys.exit("XETA: Kibana cavab vermir (%s) %s" % (code, str(st)[:200]))
    kb("POST", "/api/detection_engine/index")  # alert indeksi (movcudsa xeta qaytarmir/ignore)
    files = sorted(glob.glob(os.path.join(ROOT, "build/elastic/*.json")) + glob.glob(os.path.join(ROOT, "elastic/native/*.json")))
    ok = fail = 0
    env = load_env()
    c_code, _ = kb("GET", "/api/actions/connector/soc-telegram")
    notify = c_code == 200
    print("Bildiris connector-lari: %s" % ("var -> rule actions elave olunur" if notify else "yoxdur (actions elave edilmir)"))
    for f in files:
        body = json.load(open(f, encoding="utf-8"))
        if notify:
            body["actions"] = elastic_actions(body, env)
        code, res = kb("POST", "/api/detection_engine/rules", body)
        action = "yaradildi"
        if code == 409:
            code, res = kb("PUT", "/api/detection_engine/rules", body)
            action = "yenilendi"
        good = code in (200, 201)
        ok += good
        fail += (not good)
        print("%s %-8s %-62s %s" % ("OK  " if good else "FAIL", action if good else "", body["name"][:62], "" if good else json.dumps(res)[:240]))
    code, res = kb("GET", "/api/detection_engine/rules/_find?per_page=200&filter=alert.attributes.tags:SOC")
    print("\nNetice: %d ugurlu, %d xetali | Kibana-da SOC qaydalari: %s (enabled: %s)" % (
        ok, fail, res.get("total"), sum(1 for r in res.get("data", []) if r.get("enabled"))))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
