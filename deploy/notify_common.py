"""Bildiris ortaq kodu (secrets + siyaset + Elastic rule actions). Sirlar git-de DEYIL: /root/.soc-secrets/notify.env"""
import json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECDIR = "/root/.soc-secrets"
ENV_PATH = os.path.join(SECDIR, "notify.env")


def load_env(path=ENV_PATH):
    env = {}
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def policy():
    return json.load(open(os.path.join(ROOT, "notify/policy.json")))


ICON = {"critical": "\U0001F6A8", "high": "\U0001F534", "medium": "\U0001F7E0", "low": ""}


def elastic_actions(body, env):
    """Rule severity-ye gore Kibana connector actions (summary + throttle = qruplasdirma)."""
    pol = policy()
    sev = body.get("severity", "low")
    name = body["name"]
    mitre = ",".join(sorted({t.get("id", "") for th in body.get("threat", []) for t in th.get("technique", [])}))
    cnt = "{{alerts.new.count}}"
    text = "%s [Elastic] %s\nSeverity: %s | MITRE: %s\nYeni alert sayi: %s\n{{rule.url}}" % (ICON.get(sev, ""), name, sev.upper(), mitre, cnt)
    acts = []
    for ch in pol["channels"].get(sev, []):
        fr = {"summary": True, "notifyWhen": "onThrottleInterval", "throttle": pol["elastic_throttle"][ch]}
        if ch == "telegram":
            p, t = {"body": json.dumps({"chat_id": env.get("TELEGRAM_CHAT_ID", ""), "text": text})}, ".webhook"
            cid = "soc-telegram"
        elif ch == "email":
            p, t = {"to": [env.get("MAIL_TO", "soc-team@lab.local")], "subject": "[SOC][%s] %s" % (sev.upper(), name), "message": text}, ".email"
            cid = "soc-email"
        else:
            p, t = {"body": json.dumps({"title": "[SOC][Elastic] " + name, "body": text, "labels": ["soc-alert", "elastic", "sev-" + sev]})}, ".webhook"
            cid = "soc-ticket"
        acts.append({"group": "default", "id": cid, "action_type_id": t, "params": p, "frequency": fr})
    return acts
