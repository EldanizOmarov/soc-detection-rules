#!/usr/bin/env python3
"""EPS hesabati: Logstash sayğaclari + ES sayi + cold storage ile real olcme.
Istifade:  python3 deploy/eps_report.py [saniye=30]
(olcme penceresinde log axini olmalidir, meselen: gen_logs.py steady --eps 50 --seconds 40)"""
import sys, time
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
from soc_deploy import call, cold_stats, LS


def ls_events():
    c, r = call("GET", "/_node/stats/events", base=LS, auth=False)
    e = r.get("events", {}) if c == 200 else {}
    return e.get("in", 0), e.get("out", 0)


def es_count():
    c, r = call("GET", "/soc-*/_count")
    return r.get("count", 0) if c == 200 else 0


def cold_lines():
    return sum(max(c, 0) for _, _, c in cold_stats())


def main():
    win = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    i0, o0 = ls_events(); e0 = es_count(); c0 = cold_lines()
    t0 = time.time()
    print("Olcme %d saniye... (bu muddet erzinde log axini gonderin)" % win)
    time.sleep(win)
    i1, o1 = ls_events(); e1 = es_count(); c1 = cold_lines()
    dt = time.time() - t0
    d_in, d_es, d_cold = i1 - i0, e1 - e0, c1 - c0
    eps_in = d_in / dt
    print("\n===== EPS HESABATI (real olcme) =====")
    print("Pencere                          : %.1f san" % dt)
    print("Logstash-a daxil olan (IN)        : %d hadise  = %.1f EPS" % (d_in, eps_in))
    print("SIEM-e (Elasticsearch) yazilan    : %d hadise  = %.1f EPS" % (d_es, d_es / dt))
    print("Cold storage-a arxivlenen         : %d hadise  = %.1f EPS" % (d_cold, d_cold / dt))
    if d_in > 0:
        print("Filtrasiya ile SIEM-den kenar     : %.1f %% hecm" % (100.0 * d_cold / d_in))
    c, idx = call("GET", "/_cat/indices/soc-*?format=json&bytes=b&h=docs.count,store.size")
    docs = sum(int(i["docs.count"] or 0) for i in idx) if isinstance(idx, list) else 0
    size = sum(int(i["store.size"] or 0) for i in idx) if isinstance(idx, list) else 0
    avg = (size / docs) if docs else 0
    print("\n===== HECM PROQNOZU =====")
    print("Orta sened olcusu (ES)            : %.0f bayt" % avg)
    for name, eps in (("Filtrsiz (hamisi SIEM-e)", eps_in), ("Filtrle (yalniz deyerli)", d_es / dt)):
        per_day = eps * 86400
        gb = per_day * avg / 1e9
        print("%-34s: %.0f hadise/gun, ~%.3f GB/gun, 365 gun ~%.1f GB" % (name, per_day, gb, gb * 365))
    print("\nQeyd: nəticə sabit axinla alinmis lab olcmesidir; real mühitdə pik EPS x 1.5 ehtiyat ilə planlasdirilir.")


if __name__ == "__main__":
    main()
