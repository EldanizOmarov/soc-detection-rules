#!/usr/bin/env python3
"""Lab log generatoru (SIMULYASIYA). Network/email/cloud menbeleri bu lab-da real cihaz deyil,
ona gore formatlari real sistemlere uygun olan hadiseler Logstash-a gonderilir.
Web ucun ise real HTTP sorgulari nginx-e gonderilir (X-Forwarded-For ile fərqli IP-ler).

Istifade:  python3 deploy/gen_logs.py <ssenari> [--host 127.0.0.1]
Ssenariler:
  net-scan  net-normal  email-phish  email-normal  cloud-attack  cloud-normal
  web-normal web-sqli web-xss web-scanner web-brute
  all-attacks            (butun hucum ssenarileri ardicil)
  steady --eps 50 --seconds 60   (sabit axin, EPS olcmesi ucun; ~80% asagi deyerli ALLOW)
"""
import argparse, datetime, http.client, json, random, socket, sys, time, urllib.parse

ATTACKERS = ["77.88.55.60", "114.114.114.114", "212.58.244.20", "31.13.65.36", "8.8.8.8", "1.1.1.1"]
INTERNAL = ["10.10.1.5", "10.10.1.20", "10.10.2.15", "172.27.80.1"]


def ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def tcp_send(host, port, lines):
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(("\n".join(lines) + "\n").encode())


def net_line(src, dst, dport, action):
    return "%s fw01 action=%s proto=TCP src=%s dst=%s dport=%d" % (ts(), action, src, dst, dport)


def net_scan(h):
    src = random.choice(ATTACKERS)
    lines = [net_line(src, "10.10.1.5", p, "DENY") for p in random.sample(range(1, 1024), 80)]
    tcp_send(h, 5140, lines)
    print("net-scan: %s -> 10.10.1.5, 80 ferqli port (DENY)" % src)


def net_normal(h, n=200):
    lines = [net_line(random.choice(INTERNAL), random.choice(["93.184.216.34", "142.250.74.14"]), random.choice([80, 443]), "ALLOW") for _ in range(n)]
    tcp_send(h, 5140, lines)
    print("net-normal: %d ALLOW hadise (asagi deyerli, cold storage-a getməli)" % n)


def mail_line(frm, to, subj, att, src, status="delivered"):
    return '%s mailgw postfix/smtp: from=<%s> to=<%s> subject="%s" attachment="%s" client=%s status=%s' % (ts(), frm, to, subj, att, src, status)


def email_phish(h):
    src = random.choice(ATTACKERS)
    rows = [("billing@paypa1-secure.com", "Urgent: invoice overdue", "invoice_4471.exe"),
            ("hr@company-payroll.net", "Salary update - open now", "salary.docm"),
            ("support@micros0ft-help.com", "Password expires today", "reset.js"),
            ("noreply@dhl-track.info", "Parcel on hold", "label.iso"),
            ("it@corp-helpdesk.org", "Mandatory security update", "update.scr")]
    tcp_send(h, 5141, [mail_line(f, "eldaniz@lab.local", s, a, src) for f, s, a in rows])
    print("email-phish: %d zererli qosma (exe/docm/js/iso/scr) src=%s" % (len(rows), src))


def email_normal(h):
    rows = [("colleague@lab.local", "Meeting notes", "notes.pdf"), ("boss@lab.local", "Q4 plan", "plan.xlsx"), ("hr@lab.local", "Holiday schedule", "schedule.pdf")]
    tcp_send(h, 5141, [mail_line(f, "eldaniz@lab.local", s, a, "10.10.2.15") for f, s, a in rows])
    print("email-normal: %d adi mektub" % len(rows))


def cloud_event(name, src, user, utype="IAMUser", mfa="Yes", source="signin.amazonaws.com"):
    return json.dumps({"eventTime": ts(), "eventSource": source, "eventName": name, "awsRegion": "eu-central-1",
                       "sourceIPAddress": src, "userIdentity": {"type": utype, "userName": user},
                       "additionalEventData": {"MFAUsed": mfa}})


def cloud_attack(h):
    src = random.choice(ATTACKERS)
    ev = [cloud_event("ConsoleLogin", src, "root", utype="Root", mfa="No"),
          cloud_event("CreateAccessKey", src, "admin-svc", source="iam.amazonaws.com"),
          cloud_event("StopLogging", src, "admin-svc", source="cloudtrail.amazonaws.com"),
          cloud_event("DeleteTrail", src, "admin-svc", source="cloudtrail.amazonaws.com")]
    tcp_send(h, 5142, ev)
    print("cloud-attack: root login (MFA yox), CreateAccessKey, StopLogging, DeleteTrail src=%s" % src)


def cloud_normal(h):
    ev = [cloud_event("ConsoleLogin", "10.10.1.5", "eldaniz", mfa="Yes"), cloud_event("DescribeInstances", "10.10.1.5", "eldaniz", source="ec2.amazonaws.com")]
    tcp_send(h, 5142, ev)
    print("cloud-normal: 2 adi hadise")


def http_req(h, method, path, xff, ua="Mozilla/5.0"):
    c = http.client.HTTPConnection(h, 8080, timeout=10)
    c.request(method, path, headers={"X-Forwarded-For": xff, "User-Agent": ua})
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def web_normal(h):
    for i in range(20):
        http_req(h, "GET", random.choice(["/", "/search?q=hello", "/search?q=weather+baku"]), random.choice(ATTACKERS + INTERNAL))
    print("web-normal: 20 adi sorgu")


def web_sqli(h):
    src = random.choice(ATTACKERS)
    for q in ["' OR 1=1--", "1 UNION SELECT username,password FROM users", "1; DROP TABLE users", "admin'--", "' OR 'a'='a"]:
        http_req(h, "GET", "/search?q=" + urllib.parse.quote(q), src)
    print("web-sqli: 5 SQL injection sorgusu src=%s" % src)


def web_xss(h):
    src = random.choice(ATTACKERS)
    for q in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><svg onload=alert(1)>"]:
        http_req(h, "GET", "/search?q=" + urllib.parse.quote(q), src)
    print("web-xss: 3 XSS sorgusu src=%s" % src)


def web_scanner(h):
    src = random.choice(ATTACKERS)
    for ua in ["sqlmap/1.7.2#stable", "Nikto/2.1.6", "masscan/1.3"]:
        for p in ["/admin", "/.env", "/wp-login.php", "/phpmyadmin"]:
            http_req(h, "GET", p, src, ua)
    print("web-scanner: sqlmap/Nikto/masscan user-agent, 12 sorgu src=%s" % src)


def web_brute(h):
    src = random.choice(ATTACKERS)
    for _ in range(30):
        http_req(h, "POST", "/login", src)
    print("web-brute: 30 ugursuz /login (401) src=%s" % src)


def steady(h, eps, seconds):
    end = time.time() + seconds
    sent = 0
    while time.time() < end:
        t0 = time.time()
        lines = []
        for _ in range(eps):
            if random.random() < 0.8:
                lines.append(net_line(random.choice(INTERNAL), "93.184.216.34", random.choice([80, 443]), "ALLOW"))
            else:
                lines.append(net_line(random.choice(ATTACKERS), random.choice(INTERNAL), random.choice([22, 23, 3389, 445]), "DENY"))
        tcp_send(h, 5140, lines)
        sent += len(lines)
        time.sleep(max(0, 1 - (time.time() - t0)))
    print("steady: %d hadise gonderildi (%d EPS x %ds), ~80%% ALLOW" % (sent, eps, seconds))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--eps", type=int, default=50)
    ap.add_argument("--seconds", type=int, default=60)
    a = ap.parse_args()
    h = a.host
    table = {"net-scan": net_scan, "net-normal": net_normal, "email-phish": email_phish, "email-normal": email_normal,
             "cloud-attack": cloud_attack, "cloud-normal": cloud_normal, "web-normal": web_normal, "web-sqli": web_sqli,
             "web-xss": web_xss, "web-scanner": web_scanner, "web-brute": web_brute}
    if a.scenario == "all-attacks":
        for k in ("net-scan", "email-phish", "cloud-attack", "web-sqli", "web-xss", "web-scanner", "web-brute"):
            table[k](h)
            time.sleep(1)
    elif a.scenario == "steady":
        steady(h, a.eps, a.seconds)
    elif a.scenario in table:
        table[a.scenario](h)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
