#!/usr/bin/env python3
"""
report.py - Build the Markdown report and HTML dashboard.

Reads the CSV produced by parse_nmap.py and uses the port reference from
analyze_ports.py (analyze_row), so analysis logic lives in one place only.
"""

import csv
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_ports import NOT_DETERMINED, analyze_row  # noqa: E402

RISK_ORDER = ["High", "Medium", "Low", "Unknown"]


# ----------------------------------------------------------------- data ----
def load_rows(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_xml_extras(xml_path):
    """Counts of ports Nmap collapsed into <extraports> (usually closed/filtered), plus duration."""
    extra, elapsed = Counter(), ""
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return extra, elapsed
    for ep in root.iter("extraports"):
        extra[ep.get("state", "")] += int(ep.get("count", 0) or 0)
    fin = root.find("runstats/finished")
    if fin is not None:
        elapsed = fin.get("elapsed", "")
    return extra, elapsed


def bucket(state):
    if state == "open":
        return "open"
    if state == "closed":
        return "closed"
    return "filtered"


def build_context(target, rows, xml_path, nmap_version, nmap_cmd, timestamp):
    """Assemble everything the report and dashboard need."""
    extra, elapsed = read_xml_extras(xml_path)

    states = Counter(bucket(r["state"]) for r in rows)
    for st, n in extra.items():
        states[bucket(st)] += n

    ports = []
    for r in rows:
        info = analyze_row(r)
        is_open = r["state"] == "open"
        ports.append({
            "port": int(r["port"]),
            "protocol": r["protocol"],
            "state": r["state"],
            "service": r["service"] or "unknown",
            "version": f"{r['product']} {r['version']}".strip(),
            "name": info["name"],
            "risk": info["exposure"] if is_open else "n/a",
            "function": info["function"],
            "benefit": info["benefit"],
            "threats": info["threats"],
            "considerations": info["considerations"],
            "defenses": info["defenses"],
        })
    ports.sort(key=lambda p: p["port"])

    open_ports = [p for p in ports if p["state"] == "open"]
    risk = Counter(p["risk"] for p in open_ports)
    counts = {
        "total": sum(states.values()),
        "open": len(open_ports),
        "filtered": states["filtered"],
        "closed": states["closed"],
        "high": risk["High"],
        "medium": risk["Medium"],
        "low": risk["Low"],
        "unknown": risk["Unknown"],
    }
    return {
        "target": target,           # url, hostname, ip, safe_name
        "timestamp": timestamp,
        "nmap_version": nmap_version,
        "nmap_command": nmap_cmd,
        "elapsed": elapsed,
        "counts": counts,
        "ports": ports,
        "assessment": assessment_text(counts),
        "recommendations": recommendations(open_ports),
    }


def assessment_text(c):
    if c["open"] == 0:
        return ("No open ports were found among the ports scanned. This suggests a small exposed attack "
                "surface from the scanner's network position, but firewalls can hide services and a single "
                "scan is only a snapshot.")
    text = (f"{c['open']} open port(s) were found: {c['high']} High, {c['medium']} Medium, "
            f"{c['low']} Low and {c['unknown']} Unknown exposure. ")
    if c["high"]:
        text += ("High-exposure services (such as databases, remote desktop or file sharing) should "
                 "rarely be reachable from untrusted networks and deserve priority review. ")
    elif c["medium"] or c["unknown"]:
        text += "Medium or unidentified services should be reviewed to confirm they are intended and hardened. "
    else:
        text += "The exposed services are of the kind normally expected on a public website. "
    text += ("These ratings are preliminary exposure indicators based on port type, not confirmed "
             "vulnerabilities. Declaring a misconfiguration or vulnerability requires further authorized "
             "investigation.")
    return text


def recommendations(open_ports):
    """Prioritised per-port recommendations (highest exposure first), plus general advice."""
    ordered = sorted(open_ports, key=lambda p: (RISK_ORDER.index(p["risk"]), p["port"]))
    per_port = [{"title": f"Port {p['port']}/{p['protocol']} ({p['name']}) - {p['risk']} exposure",
                 "items": p["defenses"]} for p in ordered]
    general = [
        "Close or firewall every port that is not required for the service to function.",
        "Restrict administrative services (SSH, RDP, databases) to trusted IPs or a VPN.",
        "Use encrypted protocols (HTTPS, SSH, SFTP) instead of clear-text ones.",
        "Keep all exposed software patched and compare detected versions with vendor advisories.",
        "Repeat authorized scans regularly and compare results to detect unexpected changes.",
    ]
    return {"per_port": per_port, "general": general}


# ------------------------------------------------------------- markdown ----
def md(text):
    """Keep one-line values safe inside Markdown."""
    return str(text).replace("\r", " ").replace("\n", " ").strip()


def write_markdown(ctx, path):
    t, c = ctx["target"], ctx["counts"]
    L = ["# Website Port Security Analysis Report", "",
         "## Target Information", "",
         f"- **Target URL:** {md(t['url'])}",
         f"- **Hostname:** {md(t['hostname'])}",
         f"- **Resolved IP:** {t['ip']}",
         f"- **Scan timestamp:** {ctx['timestamp']}",
         f"- **Tool:** {md(ctx['nmap_version'])}",
         f"- **Command:** `{md(ctx['nmap_command'])}`",
         f"- **Scan duration (s):** {ctx['elapsed'] or 'n/a'}", "",
         "> Only scan systems you own or have explicit written permission to test.", "",
         "## Scan Summary", "",
         "| Metric | Count |", "|---|---|",
         f"| Total ports examined | {c['total']} |",
         f"| Open | {c['open']} |",
         f"| Filtered | {c['filtered']} |",
         f"| Closed | {c['closed']} |",
         f"| High exposure | {c['high']} |",
         f"| Medium exposure | {c['medium']} |",
         f"| Low exposure | {c['low']} |",
         f"| Unknown exposure | {c['unknown']} |", "",
         "## Open Ports", ""]

    open_ports = [p for p in ctx["ports"] if p["state"] == "open"]
    if open_ports:
        L += ["| Port | Protocol | Service | Version | Risk |", "|---|---|---|---|---|"]
        L += [f"| {p['port']} | {p['protocol']} | {md(p['service'])} | {md(p['version']) or '-'} | {p['risk']} |"
              for p in open_ports]
    else:
        L.append("No open ports were found.")

    L += ["", "## Detailed Port Analysis", ""]
    if not open_ports:
        L += ["Not applicable: no open ports.", ""]
    for p in open_ports:
        L += [f"### Port {p['port']}/{p['protocol']} - {p['name']}", "",
              f"- **Port:** {p['port']}",
              f"- **Protocol:** {p['protocol']}",
              f"- **Service:** {md(p['service'])}",
              f"- **Version:** {md(p['version']) or 'not identified'}",
              f"- **Function:** {p['function']}",
              f"- **Benefits/Legitimate Use:** {p['benefit']}",
              "- **Security Threats:**"]
        L += [f"  - {x}" for x in p["threats"]]
        L += [f"- **Risk Level:** {p['risk']} (preliminary exposure rating)",
              f"- **Considerations:** {p['considerations']}",
              f"- **Misconfiguration / vulnerability status:** {NOT_DETERMINED}",
              "- **Recommendation:**"]
        L += [f"  - {x}" for x in p["defenses"]]
        L.append("")

    L += ["## Overall Security Assessment", "", ctx["assessment"], "",
          "## Recommendations", ""]
    for g in ctx["recommendations"]["per_port"]:
        L += [f"**{g['title']}**", ""] + [f"- {i}" for i in g["items"]] + [""]
    L += ["**General**", ""] + [f"- {i}" for i in ctx["recommendations"]["general"]] + [""]
    L += ["---", "*Generated by Website Port Security Analyzer. Reconnaissance and analysis only.*", ""]

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(L), encoding="utf-8")


# ------------------------------------------------------------ dashboard ----
DASHBOARD_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Port Security Dashboard</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--text:#1c2430;--muted:#667085;--border:#e3e8ef;--head:#14213d;
--high:#d92d20;--med:#f79009;--low:#12b76a;--unk:#667085;--accent:#2e6bd6}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--card:#18202b;--text:#e6eaf0;--muted:#98a2b3;--border:#2a3441;--head:#0b1220}}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
header{background:var(--head);color:#fff;padding:22px 32px}
header h1{margin:0;font-size:1.4rem}header p{margin:4px 0 0;opacity:.75;font-size:.9rem}
main{max-width:1250px;margin:0 auto;padding:24px 20px 60px}
h2{font-size:1.1rem;margin:32px 0 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card .label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.card .value{font-size:1.5rem;font-weight:700;margin-top:2px;word-break:break-word}
.card .value.small{font-size:1rem;font-weight:600}
.high .value{color:var(--high)}.medium .value{color:var(--med)}.low .value{color:var(--low)}.unknown .value{color:var(--unk)}
.bar{display:flex;height:26px;border-radius:6px;overflow:hidden;background:var(--border)}
.bar div{height:100%}
.legend{display:flex;gap:18px;flex-wrap:wrap;margin-top:10px;font-size:.88rem}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.toolbar button,.toolbar input{padding:7px 12px;border:1px solid var(--border);background:var(--card);color:var(--text);border-radius:6px;font-size:.85rem}
.toolbar button{cursor:pointer}.toolbar button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.toolbar input{margin-left:auto;min-width:200px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--border);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{padding:9px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--border)}
th{background:var(--bg);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);white-space:nowrap}
td.long{min-width:220px;max-width:320px}
tr:last-child td{border-bottom:0}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:.75rem;font-weight:600;color:#fff}
.b-High{background:var(--high)}.b-Medium{background:var(--med)}.b-Low{background:var(--low)}.b-Unknown{background:var(--unk)}
.b-na{background:transparent;color:var(--muted);border:1px solid var(--border)}
.details{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:14px}
.details h3{margin:0 0 6px;font-size:1rem}
.details h4{margin:12px 0 4px;font-size:.78rem;text-transform:uppercase;color:var(--muted);letter-spacing:.04em}
.details p,.details ul{margin:0;font-size:.88rem}.details ul{padding-left:18px}
.note{font-size:.85rem;color:var(--muted);background:var(--card);border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:6px;padding:10px 14px;margin-top:14px}
.empty{padding:22px;text-align:center;color:var(--muted)}
footer{text-align:center;color:var(--muted);font-size:.8rem;margin-top:40px}
</style>
</head>
<body>
<header><h1>Website Port Security Analyzer</h1><p id="subtitle"></p></header>
<main>
<h2 style="margin-top:0">Target</h2>
<div class="grid" id="target"></div>

<h2>Scan Summary</h2>
<div class="grid" id="summary"></div>

<h2>Risk Distribution (open ports)</h2>
<div class="card"><div class="bar" id="bar"></div><div class="legend" id="legend"></div></div>
<div class="note" id="assessment"></div>

<h2>Ports</h2>
<div class="toolbar" id="toolbar"></div>
<div class="wrap"><table>
<thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>State</th><th>Risk</th><th>Function</th><th>Threats</th><th>Recommendation</th></tr></thead>
<tbody id="rows"></tbody></table></div>

<h2>Port and Service Details</h2>
<div class="details" id="details"></div>

<h2>Security Recommendations</h2>
<div class="details" id="recs"></div>

<footer>Reconnaissance and analysis only. Risk levels are preliminary exposure ratings, not confirmed vulnerabilities.</footer>
</main>
<script type="application/json" id="data">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById('data').textContent);
const C = D.counts;
function el(tag, cls, text){const e=document.createElement(tag); if(cls)e.className=cls; if(text!==undefined)e.textContent=text; return e;}
function card(label, value, cls, small){const c=el('div','card '+(cls||'')); c.append(el('div','label',label)); c.append(el('div','value'+(small?' small':''),String(value))); return c;}
function badge(risk){return el('span','badge '+(risk==='n/a'?'b-na':'b-'+risk), risk);}
function list(items){const u=el('ul'); items.forEach(i=>u.append(el('li',null,i))); return u;}

document.getElementById('subtitle').textContent = D.target.hostname + ' - scanned ' + D.timestamp;

const t = document.getElementById('target');
[['Target URL',D.target.url],['Hostname',D.target.hostname],['Resolved IP',D.target.ip],['Scan timestamp',D.timestamp]]
  .forEach(([l,v])=>t.append(card(l,v,'',true)));

const s = document.getElementById('summary');
[['Total ports examined',C.total],['Open',C.open],['Filtered',C.filtered],['Closed',C.closed]].forEach(([l,v])=>s.append(card(l,v)));
[['High risk',C.high,'high'],['Medium risk',C.medium,'medium'],['Low risk',C.low,'low'],['Unknown risk',C.unknown,'unknown']]
  .forEach(([l,v,c])=>s.append(card(l,v,c)));

const bar=document.getElementById('bar'), legend=document.getElementById('legend');
[['High',C.high,'var(--high)'],['Medium',C.medium,'var(--med)'],['Low',C.low,'var(--low)'],['Unknown',C.unknown,'var(--unk)']].forEach(([n,v,col])=>{
  if(v>0){const d=el('div'); d.style.width=(v/C.open*100)+'%'; d.style.background=col; d.title=n+': '+v; bar.append(d);}
  const li=el('span'); const dot=el('span','dot'); dot.style.background=col; li.append(dot, document.createTextNode(n+': '+v)); legend.append(li);
});
if(C.open===0){bar.append(el('div','empty','No open ports found'));}
document.getElementById('assessment').textContent = D.assessment;

let filter='open', query='';
const filters=[['open','Open'],['all','All listed'],['High','High'],['Medium','Medium'],['Low','Low'],['Unknown','Unknown']];
const tb=document.getElementById('toolbar');
filters.forEach(([k,label])=>{const b=el('button',k===filter?'on':'',label); b.onclick=()=>{filter=k; [...tb.querySelectorAll('button')].forEach(x=>x.className=''); b.className='on'; renderRows();}; tb.append(b);});
const search=el('input'); search.placeholder='Search port or service...'; search.oninput=()=>{query=search.value.toLowerCase(); renderRows();}; tb.append(search);

function renderRows(){
  const body=document.getElementById('rows'); body.replaceChildren();
  const rows=D.ports.filter(p=>{
    if(filter==='open'&&p.state!=='open')return false;
    if(['High','Medium','Low','Unknown'].includes(filter)&&!(p.state==='open'&&p.risk===filter))return false;
    return !query||(p.port+' '+p.service+' '+p.version+' '+p.name).toLowerCase().includes(query);
  });
  if(!rows.length){const tr=el('tr'); const td=el('td','empty','No ports match this view.'); td.colSpan=9; tr.append(td); body.append(tr); return;}
  rows.forEach(p=>{
    const tr=el('tr');
    [p.port,p.protocol,p.service,p.version||'-',p.state].forEach(v=>tr.append(el('td',null,String(v))));
    const r=el('td'); r.append(badge(p.risk)); tr.append(r);
    tr.append(el('td','long',p.function));
    const th=el('td','long'); th.append(list(p.threats.slice(0,3))); tr.append(th);
    const rc=el('td','long'); rc.append(list(p.defenses.slice(0,2))); tr.append(rc);
    body.append(tr);
  });
}
renderRows();

const det=document.getElementById('details');
const openPorts=D.ports.filter(p=>p.state==='open');
if(!openPorts.length) det.append(el('div','card empty','No open ports to analyze.'));
openPorts.forEach(p=>{
  const c=el('div','card');
  const h=el('h3',null,p.port+'/'+p.protocol+' - '+p.name+' '); h.append(badge(p.risk)); c.append(h);
  c.append(el('p',null,'Service: '+p.service+(p.version?' ('+p.version+')':'')));
  c.append(el('h4',null,'Function')); c.append(el('p',null,p.function));
  c.append(el('h4',null,'Benefits / legitimate use')); c.append(el('p',null,p.benefit));
  c.append(el('h4',null,'Potential threats')); c.append(list(p.threats));
  c.append(el('h4',null,'Considerations')); c.append(el('p',null,p.considerations));
  c.append(el('h4',null,'Recommended measures')); c.append(list(p.defenses));
  det.append(c);
});

const recs=document.getElementById('recs');
D.recommendations.per_port.forEach(g=>{const c=el('div','card'); c.append(el('h3',null,g.title)); c.append(list(g.items)); recs.append(c);});
const gc=el('div','card'); gc.append(el('h3',null,'General recommendations')); gc.append(list(D.recommendations.general)); recs.append(gc);
</script>
</body>
</html>
"""


def write_dashboard(ctx, path):
    data = json.dumps(ctx, ensure_ascii=False)
    # Make the JSON safe to embed inside a <script> block.
    data = data.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    html = DASHBOARD_TEMPLATE.replace("__DATA__", data)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")