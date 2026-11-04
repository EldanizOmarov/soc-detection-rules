#!/usr/bin/env python3
"""6.4 bildirisler. Istifade:
  deploy_notify.py init      - Telegram token/chat_id + GitHub token (gizli sorgu) -> /root/.soc-secrets/notify.env (git-de DEYIL)
  deploy_notify.py ossec     - Wazuh ossec.conf-a <integration> blokunu elave edir (idempotent)"""
import getpass, json, os, subprocess, sys, time, urllib.error, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from notify_common import SECDIR, ENV_PATH, load_env  # noqa: E402

REPO = "EldanizOmarov/soc-detection-rules"


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


def git_cached_token():
    try:
        out = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n\n", text=True, capture_output=True,
                             timeout=10, env=dict(os.environ, GIT_TERMINAL_PROMPT="0")).stdout
        return dict(l.split("=", 1) for l in out.splitlines() if "=" in l).get("password", "")
    except Exception:
        return ""


def init():
    env = load_env()
    if env.get("TELEGRAM_TOKEN") and env.get("GITHUB_TOKEN") and "--force" not in sys.argv:
        print("Sirlar artiq var (%s) - yeniden istifade olunur. Deyismek ucun: init --force" % ENV_PATH)
        return 0
    os.makedirs(SECDIR, mode=0o700, exist_ok=True)
    print("Telegram: @BotFather-dan aldigin bot token-i yaz (ekranda gorunmur).")
    tok = getpass.getpass("Telegram bot token: ").strip()
    c, r = http("GET", "https://api.telegram.org/bot%s/getMe" % tok)
    if c != 200:
        print("XETA: token yanlisdir (%s %s)" % (c, r)); return 1
    print("Bot tapildi: @%s" % r["result"]["username"])
    chat = ""
    for _ in range(4):
        c, r = http("GET", "https://api.telegram.org/bot%s/getUpdates" % tok)
        msgs = [u.get("message") or u.get("channel_post") for u in r.get("result", [])] if c == 200 else []
        msgs = [m for m in msgs if m]
        if msgs:
            chat = str(msgs[-1]["chat"]["id"]); break
        input("Telegramda botu ac, ona /start yaz, sonra buraya qayit ve ENTER bas: ")
    if not chat:
        print("XETA: chat_id tapilmadi"); return 1
    print("Chat ID tapildi: %s" % chat)
    print("\nGitHub token (Issues yazmaq ucun). ENTER = push zamani artiq daxil etdiyin token-i istifade et.")
    gh = getpass.getpass("GitHub token (ENTER=movcud): ").strip() or git_cached_token()
    if not gh:
        print("XETA: GitHub token tapilmadi"); return 1
    c, r = http("GET", "https://api.github.com/repos/" + REPO, None, {"Authorization": "Bearer " + gh, "Accept": "application/vnd.github+json"})
    if c != 200 or not r.get("permissions", {}).get("push") or not r.get("has_issues"):
        print("XETA: GitHub token repoya yaza bilmir ve ya Issues sonudur (HTTP %s). Token ucun: Issues=Read/Write icazesi." % c); return 1
    print("GitHub OK (repo: %s, %s)" % (REPO, "public" if not r.get("private") else "private"))
    with open(ENV_PATH, "w") as f:
        f.write("TELEGRAM_TOKEN=%s\nTELEGRAM_CHAT_ID=%s\nGITHUB_TOKEN=%s\nGITHUB_REPO=%s\n"
                "SMTP_HOST=127.0.0.1\nSMTP_PORT=1025\nMAIL_TO=soc-team@lab.local\nMAIL_FROM=soc-alert@lab.local\n" % (tok, chat, gh, REPO))
    os.chmod(ENV_PATH, 0o600)
    print("Yazildi: %s (chmod 600, git-de deyil)" % ENV_PATH)
    return 0


BLOCK = """
  <!-- SOC 6.4: bildiris + ticket (policy: notify/policy.json) -->
  <integration>
    <name>custom-soc-notify</name>
    <hook_url>https://api.telegram.org</hook_url>
    <level>8</level>
    <alert_format>json</alert_format>
  </integration>
"""


def ossec():
    p = "/var/ossec/etc/ossec.conf"
    s = open(p, encoding="utf-8").read()
    if "custom-soc-notify" in s:
        print("ossec.conf: integration bloku artiq var"); return 0
    bak = "%s.bak-%s" % (p, time.strftime("%Y%m%d%H%M%S"))
    open(bak, "w", encoding="utf-8").write(s)
    i = s.rfind("</ossec_config>")
    open(p, "w", encoding="utf-8").write(s[:i] + BLOCK + s[i:])
    print("ossec.conf: integration bloku elave olundu (backup: %s)" % bak)
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    fn = {"init": init, "ossec": ossec}.get(cmd)
    sys.exit(fn() if fn else print(__doc__) or 1)
