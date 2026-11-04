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
