#!/usr/bin/env python3
"""Wazuh -> Telegram / Email (MailHog) / GitHub Issue. Siyaset: soc-notify-policy.json (seviyyeye gore kanal).
Korelyasiya/qruplasdirma: eyni qayda+agent ucun throttle pencereside (tekrarlar sayilir, novbeti mesajda '+N tekrar').
Ticket: eyni basliqli ACIQ issue varsa yeni acmir, serh elave edir. Sirlar: soc-notify.env (git-de DEYIL)."""
import json, os, smtplib, sys, time, urllib.error, urllib.request
from email.mime.text import MIMEText

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = "/var/ossec/logs/soc-notify.log"
STATE = "/var/ossec/logs/soc-notify-state.json"


def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def load_env():
    env = {}
    for line in open(os.path.join(BASE, "soc-notify.env")):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def http(method, url, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    r.add_header("User-Agent", "soc-lab-notify")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:200]}
    except Exception as e:
        return 0, {"error": str(e)}


def severity(level, pol):
    m = pol["wazuh_min_levels"]
    return "critical" if level >= m["critical"] else "high" if level >= m["high"] else "medium" if level >= m["medium"] else "low"


def throttled(state, key, window, now):
    s = state.get(key, {"ts": 0, "sup": 0})
    if now - s["ts"] < window:
        s["sup"] += 1
        state[key] = s
        return True, 0
    sup = s["sup"]
    state[key] = {"ts": now, "sup": 0}
    return False, sup


def main():
    alert = json.load(open(sys.argv[1]))
    test = len(sys.argv) > 4 and sys.argv[4] == "test"
    env, pol = load_env(), json.load(open(os.path.join(BASE, "soc-notify-policy.json")))
    rule, agent = alert.get("rule", {}), alert.get("agent", {}).get("name", "?")
    level, rid, desc = int(rule.get("level", 0)), str(rule.get("id", "?")), rule.get("description", "?")
    sev = severity(level, pol)
    chans = pol["channels"].get(sev, [])
    if not chans:
        return
    ev = alert.get("data", {}).get("win", {}).get("eventdata", {})
    mitre = ",".join(rule.get("mitre", {}).get("id", []))
    icon = {"critical": "\U0001F6A8", "high": "\U0001F534", "medium": "\U0001F7E0"}.get(sev, "")
    pre = "[TEST] " if test else ""
    det = "\n".join(x for x in (
        "Agent: " + agent, "Qayda: %s (level %d, %s)" % (rid, level, sev.upper()),
        "MITRE: " + mitre if mitre else "", "Proses: " + ev.get("image", "") if ev.get("image") else "",
        "Komanda: " + ev.get("commandLine", "")[:300] if ev.get("commandLine") else "",
        "Vaxt: " + str(alert.get("timestamp", ""))) if x)
    state = {}
    try:
        state = json.load(open(STATE))
    except Exception:
        pass
    now, key = time.time(), "|%s|%s" % (rid, agent)
    for ch in chans:
        skip, sup = throttled(state, ch + key + ("|test" if test else ""), 0 if test else pol["throttle_seconds"][ch], now)
        if skip:
            log("throttle %s %s %s" % (ch, rid, agent))
            continue
        extra = "\n(+%d tekrar son pencerede)" % sup if sup else ""
        try:
            if ch == "telegram":
                c, r = http("POST", "https://api.telegram.org/bot%s/sendMessage" % env["TELEGRAM_TOKEN"],
                            {"chat_id": env["TELEGRAM_CHAT_ID"], "text": "%s%s[Wazuh] %s\n%s%s%s" % (icon, " " + pre if pre else "", desc, det, extra, "")})
            elif ch == "email":
                m = MIMEText(det + extra + "\n\nSIEM: Wazuh Dashboard https://localhost", "plain", "utf-8")
                m["Subject"], m["From"], m["To"] = "%s[SOC][%s] %s @ %s" % (pre, sev.upper(), desc, agent), env["MAIL_FROM"], env["MAIL_TO"]
                s = smtplib.SMTP(env.get("SMTP_HOST", "127.0.0.1"), int(env.get("SMTP_PORT", "1025")), timeout=10)
                s.send_message(m); s.quit()
                c, r = 250, {}
            else:
                gh = {"Authorization": "Bearer " + env["GITHUB_TOKEN"], "Accept": "application/vnd.github+json"}
                api = "https://api.github.com/repos/%s" % env["GITHUB_REPO"]
                title = "%s[SOC][Wazuh] %s @ %s" % (pre, desc, agent)
                c, lst = http("GET", api + "/issues?state=open&labels=soc-alert&per_page=100", None, gh)
                found = next((i for i in lst if i.get("title") == title), None) if isinstance(lst, list) else None
                body = det + extra
                if found:
                    c, r = http("POST", "%s/issues/%d/comments" % (api, found["number"]), {"body": body}, gh)
                else:
                    labels = ["soc-alert", "wazuh", "sev-" + sev] + (["test"] if test else [])
                    c, r = http("POST", api + "/issues", {"title": title, "body": body, "labels": labels}, gh)
                    if test and c == 201:
                        http("PATCH", "%s/issues/%d" % (api, r["number"]), {"state": "closed"}, gh)
            log("%s rule=%s agent=%s -> HTTP %s %s" % (ch, rid, agent, c, "" if c in (200, 201, 250) else str(r)[:120]))
        except Exception as e:
            log("%s XETA %s" % (ch, e))
    try:
        json.dump(state, open(STATE, "w"))
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL %s" % e)
    sys.exit(0)
