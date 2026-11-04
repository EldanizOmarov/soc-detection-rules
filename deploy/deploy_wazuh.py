#!/usr/bin/env python3
"""Wazuh SIEM: build/wazuh/sigma_rules.xml -> Wazuh API (PUT /rules/files) -> konfiqurasiya yoxlamasi -> manager restart -> yuklenme testi.
Parollar ekrana cixmir: wazuh-wui melumatlari Dashboard konfiqurasiyasindan oxunur (yaxud WAZUH_API_USER/WAZUH_API_PASSWORD)."""
import base64, json, os, re, ssl, sys, time, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000")
CTX = ssl._create_unverified_context()
RULE_FILE = "sigma_rules.xml"


def creds():
    u, p = os.environ.get("WAZUH_API_USER"), os.environ.get("WAZUH_API_PASSWORD")
    if u and p:
        return u, p
    for path in ("/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml", "/root/elastic-stack/.env"):
        if os.path.exists(path):
            t = open(path).read()
            mu = re.search(r"(?:username:\s*|WAZUH_API_USER=)[\"']?([^\s\"']+)", t)
            mp = re.search(r"(?:password:\s*|WAZUH_API_PASSWORD=)[\"']?([^\"'\n]+)", t)
            if mu and mp:
                return mu.group(1).strip(), mp.group(1).strip()
    sys.exit("XETA: Wazuh API melumatlari tapilmadi (WAZUH_API_USER / WAZUH_API_PASSWORD teyin edin)")


def call(method, path, token=None, body=None, basic=None, ctype="application/json", timeout=120):
    r = urllib.request.Request(API + path, data=body, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if basic:
        r.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % basic).encode()).decode())
    r.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=CTX) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
    except Exception as e:
        return {"error": -1, "message": str(e)}
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def main():
    u, p = creds()
    r = urllib.request.Request(API + "/security/user/authenticate?raw=true", method="POST")
    r.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % (u, p)).encode()).decode())
    try:
        token = urllib.request.urlopen(r, timeout=30, context=CTX).read().decode().strip()
    except Exception as e:
        sys.exit("XETA: Wazuh API autentifikasiya olmadi: %s" % e)
    print("Wazuh API: giris OK (istifadeci: %s)" % u)
    xml = open(os.path.join(ROOT, "build/wazuh/sigma_rules.xml"), "rb").read()
    expected = len(json.load(open(os.path.join(ROOT, "build/wazuh_index.json"))))
    res = call("PUT", "/rules/files/%s?overwrite=true" % RULE_FILE, token, xml, ctype="application/octet-stream")
    if res.get("error", 1) != 0:
        sys.exit("XETA: qayda faylı qəbul edilmədi: %s" % json.dumps(res)[:500])
    print("PUT /rules/files/%s -> OK (%d qayda)" % (RULE_FILE, expected))
    v = call("GET", "/manager/configuration/validation", token)
    status = (v.get("data", {}).get("affected_items") or [{}])[0].get("status")
    print("Konfiqurasiya yoxlamasi:", status)
    if status != "OK":
        sys.exit("XETA: konfiqurasiya yanlisdir: %s" % json.dumps(v)[:500])
    print("Manager restart...")
    call("PUT", "/manager/restart", token)
    time.sleep(10)
    for i in range(40):
        time.sleep(5)
        try:
            urllib.request.urlopen(urllib.request.Request(API + "/", headers={"Authorization": "Bearer " + token}), timeout=10, context=CTX)
        except urllib.error.HTTPError:
            pass
        except Exception:
            continue
        res = call("GET", "/rules?filename=%s&limit=1" % RULE_FILE, token, timeout=30)
        n = res.get("data", {}).get("total_affected_items")
        if n is not None:
            print("Yuklenmis SIGMA qaydalari (Wazuh-da): %s / %d" % (n, expected))
            return 0 if n == expected else 1
    print("XETA: restartdan sonra qaydalar yoxlanmadi")
    return 1


if __name__ == "__main__":
    sys.exit(main())
