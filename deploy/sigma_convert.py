#!/usr/bin/env python3
"""SIGMA -> Elastic (Lucene / Kibana Detection API JSON) ve Wazuh (XML) konverteri.

Istifade (repo kokunden):
  python3 deploy/sigma_convert.py all        # her iki SIEM + docs/mitre-mapping.md
  python3 deploy/sigma_convert.py elastic
  python3 deploy/sigma_convert.py wazuh

Desteklenen SIGMA: map/list selection, modifier-ler (contains, startswith, endswith, all, re, lt, lte, gt, gte),
wildcard (* ?), condition: and/or/not, "1 of x*", "all of them", agregasiya: "| count() [by f1,f2] >= N" + timeframe.
Elastic ucun x_elastic_filter, Wazuh ucun x_wazuh_if_sid, x_wazuh_base_sid, x_wazuh_id acarlari ile override olunur.
"""
import glob
import itertools
import json
import os
import re
import sys
from xml.sax.saxutils import escape

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_URL = "https://github.com/EldanizOmarov/soc-detection-rules/blob/main/"

LEVEL_ES = {"informational": ("low", 5), "low": ("low", 21), "medium": ("medium", 47), "high": ("high", 73), "critical": ("critical", 99)}
LEVEL_WZ = {"informational": 3, "low": 5, "medium": 8, "high": 11, "critical": 13}

TACTICS = {
    "reconnaissance": ("TA0043", "Reconnaissance"), "initial_access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"), "persistence": ("TA0003", "Persistence"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"), "defense_evasion": ("TA0005", "Defense Evasion"),
    "credential_access": ("TA0006", "Credential Access"), "discovery": ("TA0007", "Discovery"),
    "lateral_movement": ("TA0008", "Lateral Movement"), "collection": ("TA0009", "Collection"),
    "exfiltration": ("TA0010", "Exfiltration"), "command_and_control": ("TA0011", "Command and Control"),
    "impact": ("TA0040", "Impact"),
}
# technique -> (ad, taktika)
TECH = {
    "T1059": ("Command and Scripting Interpreter", "execution"), "T1059.001": ("PowerShell", "execution"),
    "T1027": ("Obfuscated Files or Information", "defense_evasion"),
    "T1110": ("Brute Force", "credential_access"), "T1110.001": ("Password Guessing", "credential_access"),
    "T1053": ("Scheduled Task/Job", "persistence"), "T1053.005": ("Scheduled Task", "persistence"),
    "T1105": ("Ingress Tool Transfer", "command_and_control"),
    "T1003": ("OS Credential Dumping", "credential_access"), "T1003.001": ("LSASS Memory", "credential_access"),
    "T1136": ("Create Account", "persistence"), "T1136.001": ("Local Account", "persistence"),
    "T1070": ("Indicator Removal", "defense_evasion"), "T1070.001": ("Clear Windows Event Logs", "defense_evasion"),
    "T1547": ("Boot or Logon Autostart Execution", "persistence"), "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1078": ("Valid Accounts", "initial_access"), "T1078.004": ("Cloud Accounts", "initial_access"),
    "T1071": ("Application Layer Protocol", "command_and_control"), "T1071.004": ("DNS", "command_and_control"),
    "T1046": ("Network Service Discovery", "discovery"),
    "T1190": ("Exploit Public-Facing Application", "initial_access"),
    "T1595": ("Active Scanning", "reconnaissance"), "T1595.002": ("Vulnerability Scanning", "reconnaissance"),
    "T1566": ("Phishing", "initial_access"), "T1566.001": ("Spearphishing Attachment", "initial_access"),
    "T1562": ("Impair Defenses", "defense_evasion"), "T1562.001": ("Disable or Modify Tools", "defense_evasion"),
    "T1562.004": ("Disable or Modify System Firewall", "defense_evasion"), "T1562.008": ("Disable or Modify Cloud Logs", "defense_evasion"),
    "T1098": ("Account Manipulation", "persistence"), "T1098.001": ("Additional Cloud Credentials", "persistence"),
    "T1197": ("BITS Jobs", "defense_evasion"),
    "T1218": ("System Binary Proxy Execution", "defense_evasion"), "T1218.005": ("Mshta", "defense_evasion"), "T1218.010": ("Regsvr32", "defense_evasion"),
    "T1490": ("Inhibit System Recovery", "impact"),
    "T1543": ("Create or Modify System Process", "persistence"), "T1543.003": ("Windows Service", "persistence"),
    "T1047": ("Windows Management Instrumentation", "execution"),
    "T1087": ("Account Discovery", "discovery"), "T1087.001": ("Local Account", "discovery"),
    "T1033": ("System Owner/User Discovery", "discovery"), "T1082": ("System Information Discovery", "discovery"),
}

ES_FIELD_MAP = {
    "EventID": "event.code", "Channel": "winlog.channel", "Computer": "host.name", "Provider_Name": "winlog.provider_name",
    "c-uri": "url.original", "cs-uri-query": "url.original", "c-useragent": "user_agent.original",
    "sc-status": "http.response.status_code", "c-ip": "source.ip", "cs-method": "http.request.method",
    "attachment_ext": "email.attachments.file.extension", "sender": "email.from.address", "subject": "email.subject",
    "eventName": "event.action", "eventSource": "event.provider", "sourceIPAddress": "source.ip",
    "userIdentityType": "aws.cloudtrail.user_identity.type", "MFAUsed": "aws.cloudtrail.mfa_used",
    "action": "event.action", "DestinationPort": "destination.port", "src_ip": "source.ip",
    "process": "process.name", "message": "soc.msg",
}
WZ_FIELD_MAP = {"EventID": "win.system.eventID", "Channel": "win.system.channel", "Computer": "win.system.computer",
                "Provider_Name": "win.system.providerName"}
WZ_PARENT = {"process_creation": "61603", "network_connection": "61605", "image_load": "61609", "process_access": "61612",
             "file_event": "61613", "registry_set": "61615", "registry_event": "61615", "dns_query": "61650"}
ES_SYSMON_CODE = {"process_creation": "1", "network_connection": "3", "process_access": "10", "file_event": "11",
                  "registry_set": "13", "registry_event": "13", "dns_query": "22", "image_load": "7"}


# --------------------------------------------------------------------------- parsing
class Cond:
    __slots__ = ("field", "op", "vals", "neg")

    def __init__(self, field, op, vals, neg=False):
        self.field, self.op, self.vals, self.neg = field, op, vals, neg

    def flip(self):
        return Cond(self.field, self.op, self.vals, not self.neg)


def _s(v):
    return str(v)


def parse_selection(sel):
    """-> DNF: list of conjunctions (list[Cond])"""
    if isinstance(sel, dict):
        conj = []
        for key, val in sel.items():
            parts = key.split("|")
            field, mods = parts[0], parts[1:]
            vals = [_s(v) for v in (val if isinstance(val, list) else [val])]
            op = "eq"
            for m in mods:
                if m in ("contains", "startswith", "endswith", "re", "lt", "lte", "gt", "gte"):
                    op = m
                elif m != "all":
                    raise ValueError("desteklenmeyen modifier: " + m)
            if "all" in mods:
                conj.extend(Cond(field, op, [v]) for v in vals)
            else:
                conj.append(Cond(field, op, vals))
        return [conj]
    if isinstance(sel, list) and all(isinstance(x, dict) for x in sel):
        out = []
        for x in sel:
            out.extend(parse_selection(x))
        return out
    raise ValueError("desteklenmeyen selection tipi (keyword list istifade etmeyin)")


TOKEN = re.compile(r"\(|\)|[^\s()]+")


def parse_condition(text, sel_names):
    """-> (AST, agg|None). AST: ('sel',n) ('and',[..]) ('or',[..]) ('not',x)"""
    agg = None
    if "|" in text:
        text, agg_text = [t.strip() for t in text.split("|", 1)]
        m = re.match(r"count\(\s*\)\s*(?:by\s+([\w.\-, ]+?))?\s*(>=|>|<=|<|==|=)\s*(\d+)$", agg_text)
        if not m:
            raise ValueError("desteklenmeyen agregasiya: " + agg_text)
        by = [x.strip() for x in m.group(1).split(",")] if m.group(1) else []
        n, op = int(m.group(3)), m.group(2)
        if op in (">",):
            n += 1
        elif op not in (">=", "==", "="):
            raise ValueError("yalniz > ve >= desteklenir")
        agg = {"by": by, "count": n}
    toks = TOKEN.findall(text)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def nxt():
        t = peek()
        pos[0] += 1
        return t

    def expand(pattern):
        if pattern == "them":
            return list(sel_names)
        rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        got = [n for n in sel_names if rx.match(n)]
        if not got:
            raise ValueError("pattern hec bir selection-a uygun deyil: " + pattern)
        return got

    def atom():
        t = nxt()
        if t == "(":
            e = or_()
            if nxt() != ")":
                raise ValueError("')' gozlenilirdi")
            return e
        if t in ("1", "all") and peek() == "of":
            nxt()
            names = expand(nxt())
            kind = "or" if t == "1" else "and"
            return (kind, [("sel", n) for n in names]) if len(names) > 1 else ("sel", names[0])
        if t not in sel_names:
            raise ValueError("namelum selection: " + str(t))
        return ("sel", t)

    def not_():
        if peek() == "not":
            nxt()
            return ("not", not_())
        return atom()

    def and_():
        items = [not_()]
        while peek() == "and":
            nxt()
            items.append(not_())
        return items[0] if len(items) == 1 else ("and", items)

    def or_():
        items = [and_()]
        while peek() == "or":
            nxt()
            items.append(and_())
        return items[0] if len(items) == 1 else ("or", items)

    ast = or_()
    if peek() is not None:
        raise ValueError("condition sonu gozlenilmirdi: " + str(peek()))
    return ast, agg


def _prod(lists):
    res = [[]]
    for lst in lists:
        res = [r + x for r in res for x in lst]
    return res


def dnf(node, sels, neg=False):
    t = node[0]
    if t == "sel":
        d = sels[node[1]]
        if not neg:
            return [list(c) for c in d]
        res = [[]]
        for conj in d:
            alts = [[c.flip()] for c in conj]
            res = [r + a for r in res for a in alts]
        return res
    if t == "not":
        return dnf(node[1], sels, not neg)
    kids = node[1]
    if (t == "and") != neg:
        return _prod([dnf(k, sels, neg) for k in kids])
    out = []
    for k in kids:
        out.extend(dnf(k, sels, neg))
    return out


def load_rules(directory):
    rules = []
    for path in sorted(glob.glob(os.path.join(directory, "*.yml"))):
        with open(path, encoding="utf-8") as f:
            r = yaml.safe_load(f)
        det = r["detection"]
        cond_text = det["condition"]
        if isinstance(cond_text, list):
            cond_text = " or ".join("(%s)" % c for c in cond_text)
        sels = {k: parse_selection(v) for k, v in det.items() if k not in ("condition", "timeframe")}
        ast, agg = parse_condition(cond_text, list(sels))
        if agg:
            tf = str(det.get("timeframe", "5m"))
            m = re.match(r"^(\d+)([smh])$", tf)
            agg["seconds"] = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]
            agg["tf"] = tf
        r["_path"] = os.path.relpath(path, ROOT)
        r["_file"] = os.path.basename(path)
        r["_sels"], r["_ast"], r["_agg"] = sels, ast, agg
        rules.append(r)
    return rules


def mitre(rule):
    tags = rule.get("tags", [])
    tech = [m.group(1).upper() for t in tags for m in [re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", t)] if m]
    tact = [t.split(".", 1)[1] for t in tags if t.startswith("attack.") and t.split(".", 1)[1] in TACTICS]
    return tech, tact


# --------------------------------------------------------------------------- Elastic
def lesc(s):
    return re.sub(r'([+\-=&|><!(){}\[\]^"~*?:\\/ ])', r"\\\1", s)


def lterm(v, op):
    v = v.lower()
    out = "".join(p if p in ("*", "?") else lesc(p) for p in re.split(r"([*?])", v))
    if op == "contains":
        return "*" + out + "*"
    if op == "startswith":
        return out + "*"
    if op == "endswith":
        return "*" + out
    return out


def es_field(f, ls):
    if f in ES_FIELD_MAP:
        return ES_FIELD_MAP[f]
    if "." in f:
        return f
    if ls.get("product") == "windows":
        return "winlog.event_data." + f
    return f


def es_cond(c, ls):
    fld = es_field(c.field, ls)
    parts = []
    for v in c.vals:
        if c.op in ("lt", "lte", "gt", "gte"):
            parts.append({"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}[c.op] + v)
        elif c.op == "re":
            parts.append("/" + v.lower() + "/")
        else:
            parts.append(lterm(v, c.op))
    body = parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"
    e = "%s:%s" % (fld, body)
    return ("NOT " + e) if c.neg else e


def es_sel(name, sels, ls):
    alts = []
    for conj in sels[name]:
        alts.append("(" + " AND ".join(es_cond(c, ls) for c in conj) + ")")
    return alts[0] if len(alts) == 1 else "(" + " OR ".join(alts) + ")"


def es_tree(node, sels, ls):
    t = node[0]
    if t == "sel":
        return es_sel(node[1], sels, ls)
    if t == "or":
        return "(" + " OR ".join(es_tree(k, sels, ls) for k in node[1]) + ")"
    if t == "not":
        return "NOT " + es_tree(node[1], sels, ls)
    pos = [k for k in node[1] if k[0] != "not"]
    neg = [k[1] for k in node[1] if k[0] == "not"]
    if not pos:
        raise ValueError("yalniz NOT-dan ibaret AND desteklenmir")
    s = " AND ".join(es_tree(k, sels, ls) for k in pos)
    for n in neg:
        s += " AND NOT " + es_tree(n, sels, ls)
    return "(" + s + ")"


def es_filter(rule):
    if rule.get("x_elastic_filter"):
        return rule["x_elastic_filter"]
    ls = rule.get("logsource", {})
    cat, prod, svc = ls.get("category"), ls.get("product"), ls.get("service")
    if cat in ES_SYSMON_CODE:
        return "event.code:%s AND winlog.channel:%s" % (ES_SYSMON_CODE[cat], lesc("microsoft-windows-sysmon/operational"))
    if prod == "windows" and svc in ("security", "system"):
        return "winlog.channel:%s" % svc
    if prod == "webserver":
        return "soc.source_type:web"
    if prod == "mail":
        return "soc.source_type:email"
    if prod == "aws":
        return "soc.source_type:cloud"
    if prod == "linux" and svc == "auth":
        return "soc.source_type:auth AND _exists_:soc.msg"
    if prod == "firewall":
        return "soc.source_type:network AND _exists_:observer.name"
    return None


def threat_block(rule):
    tech, _ = mitre(rule)
    by_tactic = {}
    for t in tech:
        base = t.split(".")[0]
        tname, tactic = TECH.get(t, (t, None))
        tactic = tactic or TECH.get(base, (None, "execution"))[1]
        ent = by_tactic.setdefault(tactic, {})
        b = ent.setdefault(base, {"id": base, "name": TECH.get(base, (base,))[0],
                                  "reference": "https://attack.mitre.org/techniques/%s/" % base, "subtechnique": []})
        if "." in t:
            b["subtechnique"].append({"id": t, "name": tname,
                                      "reference": "https://attack.mitre.org/techniques/%s/%s/" % tuple(t.split("."))})
    out = []
    for tactic, techs in by_tactic.items():
        tid, tn = TACTICS[tactic]
        out.append({"framework": "MITRE ATT&CK", "tactic": {"id": tid, "name": tn, "reference": "https://attack.mitre.org/tactics/%s/" % tid},
                    "technique": [{k: v for k, v in tt.items() if not (k == "subtechnique" and not v)} for tt in techs.values()]})
    return out


def to_elastic(rule):
    ls = rule.get("logsource", {})
    q = es_tree(rule["_ast"], rule["_sels"], ls)
    flt = es_filter(rule)
    if flt:
        q = "(%s) AND %s" % (q, flt)
    sev, risk = LEVEL_ES[rule.get("level", "medium")]
    tech, tact = mitre(rule)
    agg = rule["_agg"]
    body = {
        "rule_id": rule["id"], "name": "SIGMA - " + rule["title"], "description": rule["description"].strip(),
        "risk_score": risk, "severity": sev, "type": "threshold" if agg else "query", "query": q, "language": "lucene",
        "index": ["soc-*"], "interval": "1m", "from": "now-%ds" % ((agg["seconds"] + 120) if agg else 360), "to": "now",
        "enabled": True, "max_signals": 100, "author": [rule.get("author", "Eldaniz Omarov")],
        "tags": ["SOC", "SIGMA", "Elastic"] + ["attack." + t for t in tact] + tech,
        "false_positives": rule.get("falsepositives", []), "threat": threat_block(rule),
        "references": [REPO_URL + rule["_path"].replace(os.sep, "/")], "license": "MIT",
    }
    if agg:
        body["threshold"] = {"field": [es_field(f, ls) for f in agg["by"]], "value": agg["count"]}
    return body


# --------------------------------------------------------------------------- Wazuh
def pesc(s):
    return re.sub(r"([\\.^$|?*+()\[\]{}])", r"\\\1", s)


def wz_regex(c):
    alts = []
    for v in c.vals:
        if c.op == "re":
            alts.append(v)
            continue
        body = "".join(".*" if p == "*" else "." if p == "?" else pesc(p) for p in re.split(r"([*?])", v))
        alts.append({"eq": "^%s$", "contains": "%s", "startswith": "^%s", "endswith": "%s$"}[c.op] % body)
    return "(?i)" + (alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")")


def wz_field(f):
    if f in WZ_FIELD_MAP:
        return WZ_FIELD_MAP[f]
    if f.startswith("win."):
        return f
    return "win.eventdata." + f[0].lower() + f[1:]


def wz_parent(rule):
    if rule.get("x_wazuh_if_sid"):
        return str(rule["x_wazuh_if_sid"])
    ls = rule.get("logsource", {})
    if ls.get("category") in WZ_PARENT:
        return WZ_PARENT[ls["category"]]
    if ls.get("service") == "security":
        return "60103"
    if ls.get("service") == "system":
        return "60002"
    raise ValueError("Wazuh parent teyin oluna bilmedi: " + rule["title"])


def wz_fields_xml(conj):
    lines = []
    for c in conj:
        if c.op in ("lt", "lte", "gt", "gte"):
            raise ValueError("Wazuh ucun ededi muqayise desteklenmir")
        neg = ' negate="yes"' if c.neg else ""
        lines.append('    <field name="%s" type="pcre2"%s>%s</field>' % (wz_field(c.field), neg, escape(wz_regex(c))))
    return lines


def to_wazuh(rule, start_id):
    """-> (xml_blok, [meta])"""
    level = LEVEL_WZ[rule.get("level", "medium")]
    tech, tact = mitre(rule)
    desc = escape("SIGMA: " + rule["title"])
    mit = "    <mitre>\n" + "".join("      <id>%s</id>\n" % t for t in tech) + "    </mitre>\n" if tech else ""
    grp = "    <group>sigma,sigma_%s,%s</group>\n" % (rule.get("level", "medium"), "".join("attack." + t + "," for t in tact))
    agg = rule["_agg"]
    out, meta, rid = [], [], start_id
    alts = dnf(rule["_ast"], rule["_sels"])
    parent = wz_parent(rule)
    base_ids = []
    for conj in alts:
        if agg and rule.get("x_wazuh_base_sid"):
            base_ids.append(str(rule["x_wazuh_base_sid"]))
            continue
        lvl = 0 if agg else level
        x = '  <rule id="%d" level="%d">\n    <if_sid>%s</if_sid>\n' % (rid, lvl, parent)
        x += "\n".join(wz_fields_xml(conj)) + "\n"
        x += "    <description>%s%s</description>\n" % (desc, " (baza)" if agg else "")
        if not agg:
            x += mit + grp
        x += "  </rule>\n"
        out.append(x)
        if agg:
            base_ids.append(str(rid))
        else:
            meta.append({"id": rid, "level": level, "title": rule["title"], "file": rule["_path"], "mitre": tech})
        rid += 1
    if agg:
        for b in base_ids:
            sf = "".join("    <same_field>%s</same_field>\n" % wz_field(f) for f in agg["by"])
            x = '  <rule id="%d" level="%d" frequency="%d" timeframe="%d">\n    <if_matched_sid>%s</if_matched_sid>\n%s' % (
                rid, level, agg["count"], agg["seconds"], b, sf)
            x += "    <description>%s (%d hadise / %s)</description>\n%s%s  </rule>\n" % (desc, agg["count"], agg["tf"], mit, grp)
            out.append(x)
            meta.append({"id": rid, "level": level, "title": rule["title"], "file": rule["_path"], "mitre": tech})
            rid += 1
    return "".join(out), meta, rid


# --------------------------------------------------------------------------- build
def build_elastic():
    rules = load_rules(os.path.join(ROOT, "sigma", "elastic"))
    outdir = os.path.join(ROOT, "build", "elastic")
    os.makedirs(outdir, exist_ok=True)
    for old in glob.glob(os.path.join(outdir, "*.json")):
        os.remove(old)
    index = []
    for r in rules:
        body = to_elastic(r)
        name = os.path.splitext(r["_file"])[0] + ".json"
        with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
            json.dump(body, f, indent=2, ensure_ascii=False)
        index.append({"rule_id": r["id"], "name": body["name"], "level": r.get("level"), "type": body["type"],
                      "file": r["_path"], "mitre": mitre(r)[0], "test": r.get("x_test", "")})
    with open(os.path.join(ROOT, "build", "elastic_index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    print("Elastic: %d SIGMA qaydasi -> build/elastic/*.json" % len(rules))
    return index


def build_wazuh():
    rules = load_rules(os.path.join(ROOT, "sigma", "wazuh"))
    xml = ['<!-- AVTOMATIK YARADILIB: deploy/sigma_convert.py (menbe: sigma/wazuh/*.yml). Əl ilə redaktə etməyin. -->\n<group name="sigma,">\n']
    meta_all = []
    for r in rules:
        sid = int(r.get("x_wazuh_id", 0))
        if not sid:
            raise ValueError("x_wazuh_id yoxdur: " + r["_file"])
        block, meta, _ = to_wazuh(r, sid)
        xml.append("  <!-- %s [%s] -->\n" % (escape(r["title"]).replace("--", "-"), r["_file"]))
        xml.append(block)
        for m in meta:
            m["test"] = r.get("x_test", "")
        meta_all.extend(meta)
    xml.append("</group>\n")
    ids = [m["id"] for m in meta_all]
    assert len(ids) == len(set(ids)), "tekrar rule id"
    outdir = os.path.join(ROOT, "build", "wazuh")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "sigma_rules.xml"), "w", encoding="utf-8") as f:
        f.write("".join(xml))
    with open(os.path.join(ROOT, "build", "wazuh_index.json"), "w", encoding="utf-8") as f:
        json.dump(meta_all, f, indent=2, ensure_ascii=False)
    print("Wazuh: %d SIGMA qaydasi -> %d Wazuh qaydasi -> build/wazuh/sigma_rules.xml" % (len(rules), len(meta_all)))
    return meta_all


def build_docs(wz, es):
    lines = ["# MITRE ATT&CK xəritələməsi (avtomatik, `deploy/sigma_convert.py`)\n",
             "| SIEM | Qayda | Səviyyə | Texnikalar | Test əmri |", "|---|---|---|---|---|"]
    seen = set()
    for m in wz:
        if m["title"] in seen:
            continue
        seen.add(m["title"])
        lines.append("| Wazuh | %s | %s | %s | `%s` |" % (m["title"], m["level"], ", ".join(m["mitre"]), (m.get("test") or "").replace("|", "/")))
    for m in es:
        lines.append("| Elastic | %s | %s | %s | `%s` |" % (m["name"][8:], m["level"], ", ".join(m["mitre"]), (m.get("test") or "").replace("|", "/")))
    techs = sorted({t for m in wz for t in m["mitre"]} | {t for m in es for t in m["mitre"]})
    lines += ["", "**Cəmi unikal texnika:** %d (%s)" % (len(techs), ", ".join(techs)), ""]
    os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
    with open(os.path.join(ROOT, "docs", "mitre-mapping.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("docs/mitre-mapping.md yazildi (%d unikal texnika)" % len(techs))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd in ("all", "elastic", "wazuh"):
        es = build_elastic() if cmd in ("all", "elastic") else []
        wz = build_wazuh() if cmd in ("all", "wazuh") else []
        if cmd == "all":
            build_docs(wz, es)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
