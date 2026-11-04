#!/usr/bin/env python3
"""Kibana dashboard-lari (Vega-Lite) kod kimi: GitHub-da versiyalanir, Saved Objects API ile yuklenir (UI-da el ile deyil).
Dashboard-lar: SOC - Overview, Web, Endpoint, Identity, Network. Auto-refresh 10 san (real-time). Cixis: dashboards/elastic/*.json"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soc_deploy import ROOT  # noqa: E402

OUT = os.path.join(ROOT, "dashboards", "elastic")
SCHEMA = "https://vega.github.io/schema/vega-lite/v5.json"
ALERTS = ".alerts-security.alerts-*"


def url(index, aggs, flt=None, tf="@timestamp"):
    a = aggs if not flt else {"f": {"filter": flt, "aggs": aggs}}
    return {"%context%": True, "%timefield%": tf, "index": index, "body": {"size": 0, "aggs": a}}


def prefix(flt):
    return "aggregations.f." if flt else "aggregations."


def vl(title, data, mark, encoding, transform=None, layer=None):
    s = {"$schema": SCHEMA, "title": {"text": title, "fontSize": 13}, "autosize": {"type": "fit", "contains": "padding"}, "data": data}
    if transform:
        s["transform"] = transform
    if layer:
        s["layer"] = layer
    else:
        s["mark"] = mark
        s["encoding"] = encoding
    return s


def bar_terms(title, index, field, size=10, flt=None, color=None):
    d = {"url": url(index, {"b": {"terms": {"field": field, "size": size}}}, flt), "format": {"property": prefix(flt) + "b.buckets"}}
    enc = {"y": {"field": "key", "type": "nominal", "sort": "-x", "title": None, "axis": {"labelLimit": 220}},
           "x": {"field": "doc_count", "type": "quantitative", "title": "say"},
           "tooltip": [{"field": "key", "title": "deyer"}, {"field": "doc_count", "title": "say"}]}
    return vl(title, d, {"type": "bar", "color": color or "#4c78a8"}, enc)


def ts_bar(title, index, split=None, flt=None, size=6, extra_agg=None):
    inner = {"t": {"date_histogram": {"field": "@timestamp", "fixed_interval": "5m"}}}
    if split:
        inner["t"]["aggs"] = {"s": {"terms": {"field": split, "size": size}}}
    d = {"url": url(index, inner, flt), "format": {"property": prefix(flt) + "t.buckets"}}
    if not split:
        return vl(title, d, {"type": "bar", "color": "#4c78a8"},
                  {"x": {"field": "key", "type": "temporal", "title": None}, "y": {"field": "doc_count", "type": "quantitative", "title": "say"}})
    tr = [{"flatten": ["s.buckets"], "as": ["sb"]}, {"calculate": "datum.sb.key", "as": "grup"}, {"calculate": "datum.sb.doc_count", "as": "say"}]
    return vl(title, d, {"type": "bar"},
              {"x": {"field": "key", "type": "temporal", "title": None}, "y": {"field": "say", "type": "quantitative", "title": "say", "stack": True},
               "color": {"field": "grup", "type": "nominal", "title": None}, "tooltip": [{"field": "grup"}, {"field": "say"}]}, tr)


def kpi(title, index, flt=None, color="#e45756"):
    d = {"url": url(index, {"b": {"terms": {"field": "_index", "size": 50}}}, flt), "format": {"property": prefix(flt) + "b.buckets"}}
    return vl(title, d, {"type": "text", "fontSize": 54, "fontWeight": "bold", "color": color},
              {"text": {"field": "n", "type": "quantitative", "format": ","}}, [{"aggregate": [{"op": "sum", "field": "doc_count", "as": "n"}]}])


def avg_by(title, index, group, field, flt, unit_div=1, unit="san", color="#f58518"):
    aggs = {"b": {"terms": {"field": group, "size": 10}, "aggs": {"v": {"avg": {"field": field}}}}}
    d = {"url": url(index, aggs, flt), "format": {"property": prefix(flt) + "b.buckets"}}
    tr = [{"calculate": "datum.v.value / %s" % unit_div, "as": "val"}]
    base = {"y": {"field": "key", "type": "nominal", "title": None}, "x": {"field": "val", "type": "quantitative", "title": "orta (%s)" % unit}}
    layer = [{"mark": {"type": "bar", "color": color}, "encoding": base},
             {"mark": {"type": "text", "align": "left", "dx": 4}, "encoding": dict(base, text={"field": "val", "type": "quantitative", "format": ".1f"})}]
    return vl(title, d, None, None, tr, layer)


def geo_map(title, index, flt):
    aggs = {"c": {"terms": {"field": "source.geo.country_name", "size": 100}, "aggs": {"loc": {"geo_centroid": {"field": "source.geo.location"}}}}}
    return {
        "$schema": "https://vega.github.io/schema/vega/v5.json", "title": {"text": title},
        "config": {"kibana": {"type": "map", "mapStyle": True, "latitude": 30, "longitude": 15, "zoom": 1.5, "controlsDirection": "vertical"}},
        "data": [{"name": "table", "url": url(index, aggs, flt), "format": {"property": "aggregations.f.c.buckets"},
                  "transform": [{"type": "geopoint", "projection": "projection", "fields": ["loc.location.lon", "loc.location.lat"], "as": ["x", "y"]}]}],
        "scales": [{"name": "r", "type": "sqrt", "domain": {"data": "table", "field": "doc_count"}, "range": [150, 4000]}],
        "marks": [{"type": "symbol", "from": {"data": "table"}, "encode": {"update": {
            "x": {"field": "x"}, "y": {"field": "y"}, "size": {"scale": "r", "field": "doc_count"}, "shape": {"value": "circle"},
            "fill": {"value": "#e45756"}, "fillOpacity": {"value": 0.55}, "stroke": {"value": "#b22222"}, "strokeWidth": {"value": 1.5},
            "tooltip": {"signal": "{'olke': datum.key, 'hadise': datum.doc_count}"}}}}]}


def build():
    """-> ({vis_id: (title, spec)}, {dash_id: (title, [(vis_id, w, h)])})"""
    V = {}

    def add(i, title, spec):
        V["soc-vis-" + i] = (title, spec)
        return "soc-vis-" + i

    W, E, A, N, M = "soc-web-*", "soc-endpoint-*", "soc-auth-*", "soc-network-*", "soc-metrics"
    ALLSRC = {"exists": {"field": "source.geo.location"}}
    dash = {}

    # ---------------- Overview ----------------
    dash["soc-dash-overview"] = ("SOC - Overview (alert, MTTD/MTTR, hucum xeritesi)", [
        (add("ov-total", "Umumi alert", kpi("Umumi alert (Elastic)", ALERTS)), 12, 8),
        (add("ov-crit", "Kritik+Yuksek", kpi("Kritik + yuksek alert", ALERTS, {"terms": {"kibana.alert.severity": ["critical", "high"]}}, "#b22222")), 12, 8),
        (add("ov-tick-open", "Aciq ticket", kpi("Aciq ticket (GitHub)", M, {"bool": {"filter": [{"term": {"metric": "ticket"}}, {"term": {"state": "open"}}]}}, "#f58518")), 12, 8),
        (add("ov-tick-closed", "Baglanmis ticket", kpi("Baglanmis ticket", M, {"bool": {"filter": [{"term": {"metric": "ticket"}}, {"term": {"state": "closed"}}]}}, "#54a24b")), 12, 8),
        (add("ov-alerts-time", "Alert-ler zamana gore", ts_bar("Alert-ler (severity uzre)", ALERTS, "kibana.alert.severity", None, 4)), 48, 14),
        (add("ov-top-rules", "Top qaydalar", bar_terms("Top 10 qayda", ALERTS, "kibana.alert.rule.name", 10)), 24, 14),
        (add("ov-mitre", "MITRE taktikalar", bar_terms("MITRE taktikalari", ALERTS, "kibana.alert.rule.threat.tactic.name", 10, None, "#72b7b2")), 24, 14),
        (add("ov-mttd", "MTTD", avg_by("MTTD - hadise -> alert (san, SIEM uzre)", M, "siem", "value_s", {"term": {"metric": "mttd"}}, 1, "san")), 24, 12),
        (add("ov-mttr", "MTTR", avg_by("MTTR - ticket acilis -> baglanis (deq)", M, "siem", "value_s",
                                       {"bool": {"filter": [{"term": {"metric": "ticket"}}, {"term": {"state": "closed"}}]}}, 60, "deq", "#54a24b")), 24, 12),
        (add("ov-geo", "Hucum xeritesi", geo_map("Hucum menbelerinin cografi xeritesi (butun menbeler)", "soc-*", ALLSRC)), 48, 22),
    ])
    # ---------------- Web ----------------
    dash["soc-dash-web"] = ("SOC - Web (nginx)", [
        (add("web-total", "Web sorgulari", kpi("Web sorgulari", W)), 12, 8),
        (add("web-4xx", "4xx", kpi("4xx cavablar", W, {"range": {"http.response.status_code": {"gte": 400, "lt": 500}}}, "#f58518")), 12, 8),
        (add("web-401", "401", kpi("401 (brute force)", W, {"term": {"http.response.status_code": 401}}, "#b22222")), 12, 8),
        (add("web-ips", "Menbe IP sayi", kpi("Sorgu (X-Forwarded-For olan)", W, {"exists": {"field": "source.ip"}}, "#4c78a8")), 12, 8),
        (add("web-time", "Sorgular", ts_bar("Sorgular (status uzre)", W, "http.response.status_code", None, 6)), 48, 14),
        (add("web-ip", "Top IP", bar_terms("Top menbe IP", W, "source.ip", 10)), 24, 14),
        (add("web-ua", "Top UA", bar_terms("Top User-Agent", W, "user_agent.original", 10, None, "#b279a2")), 24, 14),
        (add("web-url", "Top URL", bar_terms("Top URL", W, "url.original", 10, None, "#72b7b2")), 24, 14),
        (add("web-country", "Olkeler", bar_terms("Menbe olkeler", W, "source.geo.country_name", 10, None, "#e45756")), 24, 14),
        (add("web-geo", "Web geo", geo_map("Web hucum menbeleri", W, ALLSRC)), 48, 20),
    ])
    # ---------------- Endpoint ----------------
    dash["soc-dash-endpoint"] = ("SOC - Endpoint (Sysmon, Security, PowerShell)", [
        (add("ep-total", "Endpoint hadiseler", kpi("Endpoint hadiseler", E)), 12, 8),
        (add("ep-4688", "Yeni proses 4688", kpi("Yeni proses (4688)", E, {"term": {"event.code": "4688"}}, "#4c78a8")), 12, 8),
        (add("ep-ps", "PowerShell 4104", kpi("PowerShell Script Block (4104)", E, {"term": {"event.code": "4104"}}, "#f58518")), 12, 8),
        (add("ep-sysmon1", "Sysmon proses", kpi("Sysmon proses (1)", E, {"term": {"event.code": "1"}}, "#54a24b")), 12, 8),
        (add("ep-time", "Hadiseler", ts_bar("Hadiseler (event.code uzre)", E, "event.code", None, 6)), 48, 14),
        (add("ep-host", "Top host", bar_terms("Top host", E, "host.name", 10)), 24, 14),
        (add("ep-img", "Top proses", bar_terms("Top proses (Sysmon 1)", E, "winlog.event_data.Image", 10, {"term": {"event.code": "1"}}, "#b279a2")), 24, 14),
        (add("ep-proc4688", "4688 proseslar", bar_terms("Yeni proseslar (4688)", E, "winlog.event_data.NewProcessName", 10, {"term": {"event.code": "4688"}}, "#72b7b2")), 24, 14),
        (add("ep-codes", "Hadise novleri", bar_terms("Hadise novleri (event.code)", E, "event.code", 12, None, "#e45756")), 24, 14),
    ])
    # ---------------- Identity ----------------
    dash["soc-dash-identity"] = ("SOC - Identity (Windows + Linux giris)", [
        (add("id-ok", "Ugurlu giris", kpi("Ugurlu giris (4624)", A, {"term": {"event.code": "4624"}}, "#54a24b")), 12, 8),
        (add("id-fail", "Ugursuz giris", kpi("Ugursuz giris (4625)", A, {"term": {"event.code": "4625"}}, "#b22222")), 12, 8),
        (add("id-linux", "Ugursuz giris umumi", kpi("Ugursuz giris (Linux + Windows)", A, {"term": {"event.outcome": "failure"}}, "#f58518")), 12, 8),
        (add("id-newuser", "Yeni istifadeci", kpi("Yeni istifadeci (4720)", A, {"term": {"event.code": "4720"}}, "#4c78a8")), 12, 8),
        (add("id-time", "Giris hadiseleri", ts_bar("Giris hadiseleri (event.code uzre)", A, "event.code", None, 6)), 48, 14),
        (add("id-users", "Ugursuz istifadeciler", bar_terms("Ugursuz giris - istifadeci (4625)", A, "winlog.event_data.TargetUserName", 10, {"term": {"event.code": "4625"}}, "#b22222")), 24, 14),
        (add("id-lt", "Logon tipi", bar_terms("Logon tipi (4624)", A, "winlog.event_data.LogonType", 8, {"term": {"event.code": "4624"}}, "#72b7b2")), 24, 14),
        (add("id-ip", "Ugursuz IP", bar_terms("Ugursuz giris menbe IP", A, "source.ip", 10, {"term": {"event.outcome": "failure"}}, "#f58518")), 24, 14),
        (add("id-geo", "Identity geo", geo_map("Ugursuz giris menbeleri", A, ALLSRC)), 24, 14),
    ])
    # ---------------- Network ----------------
    dash["soc-dash-network"] = ("SOC - Network (firewall, Sysmon 3/22)", [
        (add("nw-total", "Sebeke hadiseleri", kpi("Sebeke hadiseleri", N)), 12, 8),
        (add("nw-deny", "DENY", kpi("Firewall DENY", N, {"term": {"event.action": "deny"}}, "#b22222")), 12, 8),
        (add("nw-s3", "Sysmon 3", kpi("Sysmon 3 (sebeke baglantisi)", N, {"term": {"event.code": "3"}}, "#4c78a8")), 12, 8),
        (add("nw-s22", "Sysmon 22", kpi("Sysmon 22 (DNS)", N, {"term": {"event.code": "22"}}, "#54a24b")), 12, 8),
        (add("nw-time", "Firewall", ts_bar("Firewall (action uzre)", N, "event.action", {"exists": {"field": "observer.name"}}, 4)), 48, 14),
        (add("nw-src", "Top DENY IP", bar_terms("Top DENY menbe IP", N, "source.ip", 10, {"term": {"event.action": "deny"}}, "#b22222")), 24, 14),
        (add("nw-port", "Top port", bar_terms("Top hedef port", N, "destination.port", 10, {"exists": {"field": "observer.name"}}, "#f58518")), 24, 14),
        (add("nw-proc", "Sysmon 3 proses", bar_terms("Sebekeye cixan proseslar (Sysmon 3)", N, "winlog.event_data.Image", 10, {"term": {"event.code": "3"}}, "#b279a2")), 24, 14),
        (add("nw-dns", "DNS", bar_terms("Sorgulanan domenler (Sysmon 22)", N, "winlog.event_data.QueryName", 10, {"term": {"event.code": "22"}}, "#72b7b2")), 24, 14),
        (add("nw-geo", "Network geo", geo_map("Firewall hucum menbeleri", N, ALLSRC)), 48, 20),
    ])
    return V, dash


def so_vis(i, title, spec):
    return {"attributes": {"title": title, "description": "", "version": 1, "uiStateJSON": "{}",
                           "visState": json.dumps({"title": title, "type": "vega", "aggs": [], "params": {"spec": json.dumps(spec, indent=1)}}),
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}}}


def so_dash(title, panels):
    pj, refs, x, y, rowh = [], [], 0, 0, 0
    for n, (vid, w, h) in enumerate(panels):
        if x + w > 48:
            x, y, rowh = 0, y + rowh, 0
        pj.append({"version": "8.11.3", "type": "visualization", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(n)},
                   "panelIndex": str(n), "embeddableConfig": {}, "panelRefName": "panel_%d" % n})
        refs.append({"name": "panel_%d" % n, "type": "visualization", "id": vid})
        x, rowh = x + w, max(rowh, h)
    return {"attributes": {"title": title, "description": "Kod kimi: GitHub -> API. Real-time (10 san refresh).", "hits": 0,
                           "panelsJSON": json.dumps(pj), "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True, "syncTooltips": False, "hidePanelTitles": True}),
                           "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now", "refreshInterval": {"pause": False, "value": 10000},
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}},
            "references": refs}


def main():
    from deploy_elastic import kb
    V, D = build()
    os.makedirs(OUT, exist_ok=True)
    # Kibana 8.11 data view olmadan dashboard acmir -> indekslere data view-lar
    for dv in ("soc-endpoint", "soc-network", "soc-web", "soc-email", "soc-auth", "soc-cloud", "soc-metrics"):
        title = dv if dv == "soc-metrics" else dv + "-*"
        c, r = kb("POST", "/api/data_views/data_view", {"override": True, "data_view": {"id": dv, "title": title, "name": dv, "timeFieldName": "@timestamp"}})
        print("%s data view %-14s HTTP %s" % ("OK  " if c in (200, 201) else "FAIL", title, c))
    ok = bad = 0
    for vid, (title, spec) in V.items():
        body = so_vis(vid, title, spec)
        json.dump(dict(body, id=vid, type="visualization"), open(os.path.join(OUT, vid + ".json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        c, r = kb("POST", "/api/saved_objects/visualization/%s?overwrite=true" % vid, body)
        good = c in (200, 201)
        ok += good; bad += (not good)
        if not good:
            print("FAIL vis %-22s HTTP %s %s" % (vid, c, json.dumps(r)[:200]))
    for did, (title, panels) in D.items():
        body = so_dash(title, panels)
        json.dump(dict(body, id=did, type="dashboard"), open(os.path.join(OUT, did + ".json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        c, r = kb("POST", "/api/saved_objects/dashboard/%s?overwrite=true" % did, body)
        good = c in (200, 201)
        ok += good; bad += (not good)
        print("%s dashboard %-20s %s %s" % ("OK  " if good else "FAIL", did, title, "" if good else "HTTP %s %s" % (c, json.dumps(r)[:200])))
    print("\nNetice: %d ugurlu, %d xetali  (vis=%d, dashboard=%d)" % (ok, bad, len(V), len(D)))
    print("Acin: http://localhost:5601/app/dashboards  -> 'SOC - ...'")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
