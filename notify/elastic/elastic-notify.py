#!/usr/bin/env python3
"""Elastic SIEM -> Telegram / Email (MailHog) / GitHub Issue. Eyni siyaset (notify/policy.json) Wazuh ile.
Niye ayri servis: Elastic BASIC lisenziyasi Kibana webhook/email connector-larini desteklemir (.webhook/.email = 403).
Mexanizm: .alerts-security.alerts-* indeksini yoxlayir (30 san), yeni alert-leri severity siyasetine gore gonderir.
Qruplasdirma: eyni qayda+host ucun throttle penceresi; ticket: eyni basliqli aciq issue varsa serh. Sirlar git-de DEYIL."""
import base64, json, os, smtplib, sys, time, urllib.error, urllib.request
from email.mime.text import MIMEText

REPO_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENV_PATH = "/root/.soc-secrets/notify.env"
STACK_ENV = "/root/elastic-stack/.env"
STATE = "/var/lib/soc-notify/elastic-state.json"
LOG = "/var/log/soc-notify-elastic.log"
ES = os.environ.get("ES_URL", "http://127.0.0.1:9201")
POLL = 30


def log(m):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), m)
    print(line, flush=True)
    try:
        open(LOG, "a").write(line + "\n")
    except Exception:
        pass


def load_kv(path):
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
    r.add_header("User-Agent", "soc-lab-notify")
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


def get(d, path, default=""):
    """Duz ('a.b.c') ve ya ic-ice acar ile deyer oxu."""
    if path in d:
        return d[path]
    cur = d
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}


def save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(st, open(STATE, "w"))


def throttled(st, key, window, now):
    s = st.get(key, {"ts": 0, "sup": 0})
    if now - s["ts"] < window:
        s["sup"] += 1
        st[key] = s
        return True, 0
    sup = s["sup"]
    st[key] = {"ts": now, "sup": 0}
    return False, sup


ICON = {"critical": "\U0001F6A8", "high": "\U0001F534", "medium": "\U0001F7E0", "low": ""}


def notify(env, pol, st, name, sev, host, mitre, detail, ts, test=False):
    chans = pol["channels"].get(sev, [])
    now = time.time()
    pre = "[TEST] " if test else ""
    det = "\n".join(x for x in ("Host: " + host, "Severity: " + sev.upper(), "MITRE: " + mitre if mitre else "",
                                detail, "Vaxt: " + ts) if x)
    for ch in chans:
        skip, sup = throttled(st, "%s|%s|%s%s" % (ch, name, host, "|t" if test else ""), 0 if test else pol["throttle_seconds"][ch], now)
        if skip:
            log("throttle %s %s %s" % (ch, name, host))
            continue
        extra = "\n(+%d tekrar son pencerede)" % sup if sup else ""
        try:
            if ch == "telegram":
                c, r = http("POST", "https://api.telegram.org/bot%s/sendMessage" % env["TELEGRAM_TOKEN"],
                            {"chat_id": env["TELEGRAM_CHAT_ID"], "text": "%s %s[Elastic] %s\n%s%s" % (ICON.get(sev, ""), pre, name, det, extra)})
            elif ch == "email":
                m = MIMEText(det + extra + "\n\nSIEM: Kibana http://localhost:5601", "plain", "utf-8")
                m["Subject"], m["From"], m["To"] = "%s[SOC][%s] %s @ %s" % (pre, sev.upper(), name, host), env["MAIL_FROM"], env["MAIL_TO"]
                s = smtplib.SMTP(env.get("SMTP_HOST", "127.0.0.1"), int(env.get("SMTP_PORT", "1025")), timeout=10)
                s.send_message(m); s.quit()
                c, r = 250, {}
            else:
                gh = {"Authorization": "Bearer " + env["GITHUB_TOKEN"], "Accept": "application/vnd.github+json"}
                api = "https://api.github.com/repos/%s" % env["GITHUB_REPO"]
                title = "%s[SOC][Elastic] %s @ %s" % (pre, name, host)
                c, lst = http("GET", api + "/issues?state=open&labels=soc-alert&per_page=100", None, gh)
                found = next((i for i in lst if i.get("title") == title), None) if isinstance(lst, list) else None
                if found:
                    c, r = http("POST", "%s/issues/%d/comments" % (api, found["number"]), {"body": det + extra}, gh)
                else:
                    labels = ["soc-alert", "elastic", "sev-" + sev] + (["test"] if test else [])
                    c, r = http("POST", api + "/issues", {"title": title, "body": det + extra, "labels": labels}, gh)
                    if test and c == 201:
                        http("PATCH", "%s/issues/%d" % (api, r["number"]), {"state": "closed"}, gh)
            log("%s %s @ %s -> HTTP %s %s" % (ch, name, host, c, "" if c in (200, 201, 250) else str(r)[:120]))
        except Exception as e:
            log("%s XETA %s" % (ch, e))


def main():
    env, pol = load_kv(ENV_PATH), json.load(open(os.path.join(REPO_DIR, "notify/policy.json")))
    if "--test" in sys.argv:
        st = {}
        notify(env, pol, st, "SIGMA - Shadow Copy Deletion (TEST)", "critical", "ELDANIZ", "T1490",
               "Komanda: vssadmin delete shadows /all", time.strftime("%Y-%m-%dT%H:%M:%S%z"), test=True)
        return
    auth = {"Authorization": "Basic " + base64.b64encode(("elastic:" + load_kv(STACK_ENV)["ELASTIC_PASSWORD"]).encode()).decode()}
    st = load_state()
    cursor = st.get("_cursor") or time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    log("elastic-notify basladi, cursor=%s" % cursor)
    while True:
        c, r = http("POST", ES + "/.alerts-security.alerts-*/_search",
                    {"size": 200, "sort": [{"@timestamp": "asc"}], "query": {"range": {"@timestamp": {"gt": cursor}}}}, auth)
        if c == 200:
            for h in r.get("hits", {}).get("hits", []):
                a = h["_source"]
                cursor = max(cursor, a.get("@timestamp", cursor))
                name = get(a, "kibana.alert.rule.name", "?")
                sev = get(a, "kibana.alert.severity", "low")
                host = get(a, "host.name") or get(a, "source.ip") or "n/a"
                techs = get(a, "kibana.alert.rule.parameters.threat", [])
                mitre = ",".join(sorted({t.get("id", "") for th in techs if isinstance(th, dict) for t in th.get("technique", [])}))
                notify(env, pol, st, name, sev, str(host), mitre, "Sebeb: " + str(get(a, "kibana.alert.reason", ""))[:300], a.get("@timestamp", ""))
            st["_cursor"] = cursor
            save_state(st)
        elif c not in (404,):
            log("ES sorgu xetasi HTTP %s %s" % (c, str(r)[:120]))
        time.sleep(POLL)


if __name__ == "__main__":
    main()
