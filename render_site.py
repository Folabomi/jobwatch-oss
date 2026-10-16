#!/usr/bin/env python3
"""Render jobwatch_state.json into a static page for a static host.

Emits two objects so the site's strict CSP is satisfied: the HTML carries inline
CSS (style-src allows 'unsafe-inline') and the script is external (script-src is
'self' plus one fixed hash, so an inline <script> would be blocked).
"""

import argparse
import html
import json
import os
import re
import sys
from datetime import datetime

SITE_CITY = "your city"
SITE_RUN_TIME = "06:20"

SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jobwatch_state.json")
APPS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "applications.json")
ORGS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "organizations.json")
HIDDEN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dismissed.json")

from sanitizer import SanitizerBlocked, sanitize, sanitize_records, scan_public_text  # noqa: E402
from taxonomy import (  # noqa: E402 - constants live in one place now
    ACTION_STATUSES,
    ARCH_LABELS,
    COMPETENCIES,
    FALLBACK_COMPETENCY,
    FIT_LABELS,
    INDUSTRY_LABELS,
    INTL,
    RESUMES,
    SECTOR_LABELS,
    LEVEL_MOVE_LABELS,
    FIT_GAUGE,
    SKILLS,
    geo_note,
    SKILL_BANDS,
    SECTOR_OF_INDUSTRY,
    STATUS_META,
    TIER_DIRECT,
    TIER_META,
    TIER_RARE,
    TIER_WIDE,
    US,
    level_move,
)

COMPETENCY_BY_KEY = {c["key"]: c for c in COMPETENCIES}
FALLBACK_COMPETENCY = {
    "key": "general",
    "label": "Security engineering, unclassified",
    "cv": "general",
    "terms": (),
}


def competency_for(title):
    """Classify a title into exactly one competency. First match wins."""
    lowered = (title or "").lower()
    for competency in COMPETENCIES:
        if any(term in lowered for term in competency["terms"]):
            return competency
    return FALLBACK_COMPETENCY


TIER_META = {
    "rare": {"bar": "████████", "label": "Names the discipline", "rank": 3},
    "direct": {"bar": "██████░░", "label": "Traffic adjacent", "rank": 2},
    "wide": {"bar": "████░░░░", "label": "Wide term", "rank": 1},
}

INTL = (
    "united kingdom", "london", "ireland", "dublin", "israel", "tel aviv", "india",
    "hyderabad", "mumbai", "new delhi", "japan", "tokyo", "australia", "sydney",
    "singapore", "switzerland", "zurich", "sweden", "stockholm", "germany",
    "hamburg", "berlin", "canada", "toronto", "romania", "china", "beijing",
    "taiwan", "vietnam", "korea", "france", "paris", "netherlands", "amsterdam",
    "spain", "poland", "brazil", "mexico", "gbr", "ire", "rou", "isr",
)
US = (
    "united states", "usa", "us -", "us,", "remote us", "us remote", "seattle",
    "san francisco", "new york", "austin", "sunnyvale", "san mateo", "santa clara",
    "mountain view", "ann arbor", "san jose", "washington, d", "atlanta", "denver",
    "boston", "chicago", "los angeles", "san diego", "bellevue", "redmond",
    "silver spring", "reston", "arlington", "mclean", "herndon", "michigan",
    "california", "texas", "virginia", ", ca", ", wa", ", ny", ", tx", ", mi", ", ga",
)


def esc_html(value):
    """Everything interpolated into the HTML goes through this. applications.json
    is hand-pasted from recruiter mail, so it is untrusted for markup purposes."""
    return html.escape("" if value is None else str(value), quote=True)


def normalize_term(term):
    """findall keeps the plural suffix, so map 'threats' back to 'threat'."""
    lowered = term.lower()
    for pool in (TIER_RARE, TIER_DIRECT, TIER_WIDE):
        for base in pool:
            if lowered.startswith(base):
                return base
    return lowered


def tier_for(terms):
    bases = {normalize_term(t) for t in terms}
    if bases & set(TIER_RARE):
        return "rare"
    if bases & set(TIER_DIRECT):
        return "direct"
    return "wide"


def place_for(location):
    text = (location or "").lower()
    if not text:
        return "unclear"
    if "remote" in text:
        return "remote"
    if re.match(r"^\d+\s+locations?$", text.strip()):
        return "multi"
    if any(marker in text for marker in INTL):
        return "intl"
    if any(marker in text for marker in US):
        return "us"
    return "unclear"


def build_rows(state, apps=()):
    by_key = {}
    for app in apps:
        if app.get("match"):
            by_key[(app["company"], app["match"])] = app
    rows = []
    for job in state.get("jobs", {}).values():
        terms = sorted({normalize_term(t) for t in job.get("terms", [])})
        tier = tier_for(job.get("terms", []))
        rows.append(
            {
                "id": job["id"],
                "company": job["company"],
                "title": job["title"],
                "location": job.get("location") or "",
                "url": job["url"],
                "board": job.get("board", ""),
                "terms": terms,
                "tier": tier,
                "sde": bool(job.get("flags")),
                "place": place_for(job.get("location")),
                "since": (job.get("first_seen") or "")[:10],
                "status": (by_key.get((job["company"], job["title"])) or {}).get("status"),
                "competency": competency_for(job["title"])["key"],
                "resume": competency_for(job["title"])["cv"],
                "pay": ([job.get("pay_low"), job.get("pay_high")]
                        if job.get("pay_low") else None),
                "skills": job.get("skills") or [],
                "jd_seen": bool(job.get("jd_seen")),
            }
        )
    rows.sort(key=lambda r: (-TIER_META[r["tier"]]["rank"], r["company"], r["title"]))
    return rows


CSS = """
:root{
  color-scheme:dark;
  --paper:#101418; --card:#191F26; --ink:#F2F5F8; --ink-2:#B9C4CE;
  --rule:#2E3843; --rule-hard:#55636F;
  --hot:#F08A7A; --cool:#6FD0DC; --gold:#E0B45E;
  --chip-on-ink:#101418; --code-bg:#262F39;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--paper); color:var(--ink);
  font-family:'IBM Plex Sans',system-ui,-apple-system,sans-serif;
  font-size:15px; line-height:1.5; -webkit-font-smoothing:antialiased;
}
.wrap{max-width:1080px;margin:0 auto;padding:28px 18px 80px}
header{border-bottom:2px solid var(--ink);padding-bottom:14px}
.eyebrow{font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--ink-2);margin-bottom:8px}
h1{font-size:clamp(26px,5.2vw,40px);line-height:1.05;font-weight:700;margin:0 0 10px;
  letter-spacing:-.02em;text-wrap:balance}
.thesis{max-width:62ch;color:var(--ink-2);font-size:15px;margin:0}
.thesis strong{color:var(--ink);font-weight:600}
.stats{display:flex;flex-wrap:wrap;gap:26px;margin:16px 0 0;padding:0;list-style:none}
.stats li{font-family:'IBM Plex Mono',monospace}
.stats b{display:block;font-size:26px;font-weight:600;letter-spacing:-.02em;
  font-variant-numeric:tabular-nums;color:var(--ink)}
.stats span{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-2)}
.controls{position:sticky;top:0;z-index:20;background:var(--paper);
  padding:12px 0 10px;border-bottom:1px solid var(--rule);margin-bottom:18px}
.ctl-row{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.ctl-row + .ctl-row{margin-top:8px}
.ctl-label{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.12em;
  text-transform:uppercase;color:var(--ink-2);width:56px;flex:none}
select.chip{max-width:100%}
button.chip,select.chip{font-family:'IBM Plex Mono',monospace;font-size:12px;
  background:transparent;color:var(--ink-2);border:1px solid var(--rule-hard);
  border-radius:2px;padding:5px 10px;cursor:pointer;transition:all .12s}
button.chip:hover,select.chip:hover{border-color:var(--ink);color:var(--ink)}
button.chip[aria-pressed="true"]{background:var(--ink);color:var(--chip-on-ink);border-color:var(--ink)}
button.chip:focus-visible,select.chip:focus-visible,a:focus-visible{outline:2px solid var(--cool);outline-offset:2px}
.count{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--ink-2);
  margin-left:auto;letter-spacing:.06em;font-variant-numeric:tabular-nums}
.thead{display:grid;grid-template-columns:1fr 130px 168px;gap:12px;
  font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.12em;
  text-transform:uppercase;color:var(--ink-2);padding:0 0 6px;border-bottom:1px solid var(--rule-hard)}
.row{display:grid;grid-template-columns:1fr 130px 168px;gap:12px;padding:14px 0;
  border-bottom:1px solid var(--rule);align-items:start}
@media(max-width:720px){.thead{display:none}.row{grid-template-columns:1fr;gap:8px;padding:16px 0}}
.org{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--cool);
  margin:0 0 3px;letter-spacing:.02em}
.title{font-weight:600;font-size:16px;margin:0 0 6px;letter-spacing:-.01em;max-width:58ch}
.terms{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--ink-2);margin:0}
.comp{color:var(--ink);font-weight:500}
.gauge{font-family:'IBM Plex Mono',monospace;font-size:13px;line-height:1.2;white-space:nowrap}
.gauge .bar{letter-spacing:-1px}
.g-rare .bar{color:var(--hot)}
.g-direct .bar{color:var(--gold)}
.g-wide .bar{color:var(--ink-2)}
.gauge .lab{display:block;font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--ink-2);margin-top:2px}
.loc{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--ink-2);margin:0 0 8px}
.sde{display:inline-block;font-family:'IBM Plex Mono',monospace;font-size:10px;
  letter-spacing:.1em;text-transform:uppercase;color:var(--gold);border:1px solid var(--gold);
  padding:1px 6px;border-radius:2px;margin-left:8px;vertical-align:2px}
a.act{font-family:'IBM Plex Mono',monospace;font-size:11px;text-decoration:none;color:var(--hot);
  border:1px solid var(--hot);border-radius:2px;padding:4px 8px;transition:all .12s;
  white-space:nowrap;display:inline-block;font-weight:600}
a.act:hover{background:var(--hot);color:var(--chip-on-ink)}
a.act.alt{color:var(--cool);border-color:var(--cool);font-weight:400}
.act.muted{background:transparent;color:var(--ink-2);border:1px solid var(--rule-hard);
  border-radius:2px;padding:4px 8px;font-family:'IBM Plex Mono',monospace;font-size:11px;
  cursor:pointer;white-space:nowrap}
.act.muted:hover{border-color:var(--ink);color:var(--ink)}
a.act.alt:hover{background:var(--cool);color:var(--chip-on-ink)}
.acts{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 6px}
.since{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--ink-2);margin:6px 0 0}
.pay{font-family:'IBM Plex Mono',monospace;font-size:12.5px;margin:0 0 8px;
  font-variant-numeric:tabular-nums}
.pay b{color:var(--gold);font-weight:600}
.paynote{display:block;font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--ink-2);margin-top:1px}
section.panel{margin-top:36px}
h2{font-size:13px;font-family:'IBM Plex Mono',monospace;letter-spacing:.14em;
  text-transform:uppercase;color:var(--ink);margin:0 0 4px;font-weight:600}
.sub{color:var(--ink-2);font-size:14px;margin:0 0 14px;max-width:62ch}
.box{background:var(--card);border:1px solid var(--rule);border-radius:3px;
  padding:14px 16px;margin-bottom:10px}
.box h3{font-size:14px;margin:0 0 6px;font-weight:600}
.box p{margin:0 0 8px;color:var(--ink-2);font-size:14px}
.box p:last-child{margin-bottom:0}
code{font-family:'IBM Plex Mono',monospace;font-size:12.5px;background:var(--code-bg);
  padding:2px 5px;border-radius:2px;color:var(--ink)}
.scroll{overflow-x:auto}
table.boards{border-collapse:collapse;width:100%;font-family:'IBM Plex Mono',monospace;font-size:12px}
table.boards th{text-align:left;font-size:10px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--ink-2);font-weight:500;padding:0 14px 6px 0;border-bottom:1px solid var(--rule-hard);white-space:nowrap}
table.boards td{padding:7px 14px 7px 0;border-bottom:1px solid var(--rule);white-space:nowrap}
table.boards td.n{text-align:right;font-variant-numeric:tabular-nums}
.ok{color:var(--cool)}
.zero{color:var(--gold)}
.fail{color:var(--hot)}
.empty{font-family:'IBM Plex Mono',monospace;font-size:13px;color:var(--ink-2);
  padding:36px 0;border-bottom:1px solid var(--rule)}
footer{margin-top:44px;padding-top:14px;border-top:2px solid var(--ink);
  font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--ink-2);max-width:70ch;line-height:1.7}
.orgcard{display:grid;grid-template-columns:1fr 130px 210px;gap:12px;
  border-bottom:1px solid var(--rule);padding:20px 0;align-items:start}
.orgmain{min-width:0}
.orgside{min-width:0}
.orgcard .reqs{grid-column:1 / -1}
@media(max-width:720px){.orgcard{grid-template-columns:1fr}}
.opennow{font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:.1em;
  text-transform:uppercase;color:var(--chip-on-ink);background:var(--hot);
  border-radius:2px;padding:2px 6px}
.g-fit-core .bar{color:var(--hot)}
.g-fit-strong .bar{color:var(--gold)}
.g-fit-adj .bar{color:var(--ink-2)}
.paynote2{font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:var(--ink-2);margin:2px 0 0}
.tax{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--ink-2);margin:6px 0 0;line-height:1.5}
.orgside .acts{margin:10px 0 0;flex-direction:column;align-items:stretch}
.orgside .acts a.act{text-align:center}
.seen{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--ink-2);
  margin:10px 0 0;padding-left:10px;border-left:2px solid var(--rule)}
.orghead{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px}
.orghead h3{font-size:19px;font-weight:700;margin:0;letter-spacing:-.01em}
.tags{display:flex;flex-wrap:wrap;gap:5px}
.tag{font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:.1em;
  text-transform:uppercase;color:var(--ink-2);border:1px solid var(--rule-hard);
  border-radius:2px;padding:2px 6px}
.tag.t-core{color:var(--hot);border-color:var(--hot)}
.tag.t-strong{color:var(--gold);border-color:var(--gold)}
.tag.t-cust{color:var(--chip-on-ink);background:var(--cool);border-color:var(--cool)}
.tag.t-aws{color:var(--cool);border-color:var(--cool)}
.tag.t-rival{color:var(--hot);border-color:var(--hot)}
.tag.t-pivot{color:var(--gold);border-color:var(--gold)}
.tag.t-gate{color:var(--chip-on-ink);background:var(--hot);border-color:var(--hot)}
.tag.t-up{color:var(--cool);border-color:var(--cool)}
.orgcard .team{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--cool);
  margin:6px 0 0;letter-spacing:.02em}
.orgcard .why{margin:6px 0 0;color:var(--ink-2);font-size:14px;max-width:74ch}
.orgmeta{display:flex;flex-wrap:wrap;gap:14px;margin:8px 0 0;
  font-family:'IBM Plex Mono',monospace;font-size:11.5px}
.orgcard .team .tags{display:inline-flex;flex-wrap:wrap;gap:5px;margin-left:6px;vertical-align:middle}
.mkt{color:var(--gold)} .mkt b{font-weight:600} .mkt i{font-style:normal;color:var(--ink-2)}
.mkt.none{color:var(--ink-2)}
.lvl2{color:var(--ink-2)}
.orgmeta .lvl{color:var(--ink-2)} .orgmeta .lvl i{font-style:normal}
.orgacts{margin:10px 0 0}
.noreq{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--ink-2);
  margin:12px 0 0;padding-left:12px;border-left:2px solid var(--rule)}
.reqs{margin:12px 0 0;padding-left:14px;border-left:2px solid var(--rule)}
.req{display:grid;grid-template-columns:1fr 130px 168px;gap:12px;padding:12px 0;
  border-top:1px solid var(--rule);align-items:start}
.req:first-child{border-top:none}
@media(max-width:720px){.req{grid-template-columns:1fr;gap:8px}}
.stat-badge{display:inline-block;font-family:'IBM Plex Mono',monospace;font-size:10px;
  letter-spacing:.1em;text-transform:uppercase;padding:1px 6px;border-radius:2px;
  margin-left:8px;vertical-align:2px}
.st-good{color:var(--chip-on-ink);background:var(--cool);font-weight:600}
.st-ok{color:var(--cool);border:1px solid var(--cool)}
.st-no{color:var(--ink-2);border:1px solid var(--rule-hard)}
.st-warn{color:var(--chip-on-ink);background:var(--hot)}
.alert{background:var(--card);border:1px solid var(--hot);border-left:3px solid var(--hot);
  border-radius:3px;padding:14px 16px;margin:18px 0 0}
.alert h3{font-size:14px;margin:0 0 6px;font-weight:600;color:var(--hot)}
.alert ul{margin:0;padding-left:18px;color:var(--ink-2);font-size:14px}
.alert li{margin:0 0 4px}
.alert li:last-child{margin:0}
table.apps{border-collapse:collapse;width:100%;font-family:'IBM Plex Mono',monospace;font-size:12px}
table.apps th{text-align:left;font-size:10px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--ink-2);font-weight:500;padding:0 14px 6px 0;border-bottom:1px solid var(--rule-hard);white-space:nowrap}
table.apps td{padding:8px 14px 8px 0;border-bottom:1px solid var(--rule);vertical-align:top}
table.apps td.w{white-space:nowrap}
table.apps td.note{font-family:'IBM Plex Sans',sans-serif;font-size:13px;color:var(--ink-2);
  white-space:normal;min-width:230px}
.hint2{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--ink-2);
  letter-spacing:.04em}
.hint{display:none;font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:var(--ink-2);
  margin:8px 0 0;letter-spacing:.06em}
/* Touch targets. 27px chips are fine with a mouse and too small with a thumb,
   so anything tappable gets a 44px minimum on coarse pointers and narrow screens. */
@media(pointer:coarse),(max-width:720px){
  button.chip,select.chip{min-height:44px;padding:11px 13px;font-size:12.5px}
  a.act{min-height:44px;padding:13px 15px;font-size:12px}
  .ctl-label{width:100%;margin-bottom:2px}
  /* a select sizes to its widest option, which can exceed a phone viewport */
  select.chip{width:100%;max-width:100%}
  /* Four filter rows at 44px each would pin most of a phone screen and sit on
     top of the first result, so the bar scrolls away on narrow screens. */
  .controls{position:static}
  .ctl-row{gap:8px}
  .count{margin-left:0}
  .hint{display:block}
}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
"""

JS = """
var TIER = %(tier)s;
var ORGS = %(orgs)s;
var STATUS = %(status)s;
var RESUMES = %(resumes)s;
var COMPS = %(comps)s;
var MOVES = %(moves)s;
var FITG = %(fitgauge)s;
var DISMISSED = %(dismissed)s;

// Level is gated, not scored: "inscope" is the default and excludes down-levels.
// Facets OR within a row and AND across rows. An empty array means no filter on
// that facet, which is what the "All" chip restores.
var multi = {sector:[], fit:[], arch:[], move:[], place:[], app:[], tier:[], rel:[]};
// Thresholds are nested ranges, so multi-select would be meaningless. Single only.
var state = {paytier:'all', ind:'all', comp:'all', co:'all'};
var toggles = {traffic:false, customer:false, open:false, banded:false, sde:false};
var showHidden = false;

// No backend exists: the page is a static object behind a CSP with
// connect-src 'self' and form-action 'none', so nothing can be POSTed. Hides
// live in localStorage, seeded from a committed dismissed.json baseline so a
// decision survives clearing the browser and reaches other devices once
// exported.
var HIDE_KEY = 'jobwatch.hidden.v1';

function loadHidden(){
  var out = {};
  DISMISSED.forEach(function(id){ out[id] = 'file'; });
  try {
    JSON.parse(localStorage.getItem(HIDE_KEY) || '[]').forEach(function(id){
      if(!out[id]) out[id] = 'local';
    });
  } catch(e){}
  return out;
}

var hidden = loadHidden();

function persistHidden(){
  var local = Object.keys(hidden).filter(function(id){ return hidden[id] === 'local'; });
  try { localStorage.setItem(HIDE_KEY, JSON.stringify(local)); } catch(e){}
}

function hideReq(id){ hidden[id] = 'local'; persistHidden(); render(); }
function restoreReq(id){
  if(hidden[id] === 'file') return;   // committed hides are cleared in the file
  delete hidden[id]; persistHidden(); render();
}

function facetOk(name, value){
  var sel = multi[name];
  return !sel.length || sel.indexOf(value) >= 0;
}

function safeUrl(u){
  u = String(u || '');
  return /^https?:\/\//i.test(u) ? u : '#';
}

function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function money(n){ return '$' + Math.round(n/1000) + 'K'; }

// Expanding an opaque "38 Locations" is correct for US eligibility and useless
// to read. Show a couple and count the rest.
function shortLoc(loc){
  var parts = String(loc || '').split(';').map(function(x){ return x.trim(); }).filter(Boolean);
  if(parts.length <= 3) return parts.join('; ');
  return parts.slice(0, 2).join('; ') + ' and ' + (parts.length - 2) + ' more sites';
}

function orgOk(o){
  if(!facetOk('sector', o.sector)) return false;
  if(!facetOk('fit', o.fit)) return false;
  if(!facetOk('arch', o.arch)) return false;
  if(state.ind !== 'all' && o.industry !== state.ind) return false;
  if(state.co !== 'all' && o.name !== state.co) return false;
  if(multi.rel.length){
    var relOk = multi.rel.some(function(r){
      return o.relationship === r || o.relationship === 'both';
    });
    if(!relOk) return false;
  }
  // Down-level is a gate: excluded unless the Level facet asks for it by name.
  if(multi.move.length){ if(multi.move.indexOf(o.move) < 0) return false; }
  else if(o.move === 'down') return false;
  if(state.paytier !== 'all'){
    var floor = {'600':600000,'450':450000,'400':400000}[state.paytier];
    if(!o.median || o.median < floor) return false;
  }
  if(toggles.traffic && !o.traffic) return false;
  if(toggles.customer && !o.warm) return false;
  if(toggles.open && !o.reqs.length) return false;
  return true;
}

function reqOk(r){
  if(!showHidden && hidden[r.id]) return false;
  if(showHidden && !hidden[r.id]) return false;
  if(!facetOk('tier', r.tier)) return false;
  if(!facetOk('place', r.place)) return false;
  if(multi.app.length){
    var appOk = multi.app.some(function(v){
      if(v === 'applied') return !!r.status;
      if(v === 'open') return !r.status;
      return r.status === v;
    });
    if(!appOk) return false;
  }
  if(toggles.sde && !r.sde) return false;
  if(toggles.banded && !r.pay) return false;
  if(state.comp !== 'all' && r.competency !== state.comp) return false;
  return true;
}

// When a req-level filter is on, an org with no board cannot satisfy it, so it
// is hidden rather than shown as a false match.
function reqFilterOn(){
  return showHidden || multi.tier.length > 0 || multi.place.length > 0 || multi.app.length > 0 ||
         state.comp !== 'all' || toggles.sde || toggles.banded;
}

function reqHtml(r){
  var g = TIER[r.tier];
  return '<div class="req">' +
    '<div>' +
      '<p class="title">' + esc(r.title) +
        (r.sde ? '<span class="sde">SDE signal</span>' : '') +
        (r.status ? '<span class="stat-badge ' + STATUS[r.status].cls + '">' + esc(STATUS[r.status].label) + '</span>' : '') + '</p>' +
      '<p class="terms"><span class="comp">' + esc(COMPS[r.competency]) + '</span>' +
        ' &middot; matched ' + esc(r.terms.join(', ')) + '</p>' +
    '</div>' +
    '<div class="gauge g-' + r.tier + '">' +
      '<span class="bar">' + g.bar + '</span>' +
      '<span class="lab">' + esc(g.label) + '</span>' +
    '</div>' +
    '<div>' +
      '<p class="loc" title="' + esc(r.location) + '">' + esc(shortLoc(r.location) || 'not stated') + '</p>' +
      (r.pay ? '<p class="pay"><b>' + money(r.pay[0]) + ' \u2013 ' + money(r.pay[1]) + '</b>' +
               '<span class="paynote">base only</span></p>' : '') +
      '<div class="acts">' +
        '<a class="act" href="' + esc(safeUrl(r.url)) + '" target="_blank" rel="noopener">Open req</a>' +
        '<a class="act alt" href="https://drive.google.com/file/d/' + RESUMES[r.resume].id +
          '/view" target="_blank" rel="noopener">' + esc(RESUMES[r.resume].label) + ' CV</a>' +
        (hidden[r.id]
          ? (hidden[r.id] === 'file'
              ? '<span class="act muted" title="Hidden in dismissed.json. Remove it there to restore.">Hidden in file</span>'
              : '<button class="act muted" data-restore="' + esc(r.id) + '">Restore</button>')
          : '<button class="act muted" data-hide="' + esc(r.id) + '" title="Hide this req. Stored in this browser.">Not for me</button>') +
      '</div>' +
      '<p class="since">tracked since ' + esc(r.since) + '</p>' +
    '</div>' +
  '</div>';
}

// A board polled with nothing matching is ground truth. A board never polled is
// simply unknown. Saying the same thing for both would hide the difference.
function emptyNote(o, reqs){
  if(reqs && reqs.length){
    return reqs.length + (reqs.length === 1 ? ' live req' : ' live reqs') +
           (typeof o.scanned === 'number' ? ' out of ' + o.scanned.toLocaleString() + ' scanned' : '') + '.';
  }
  if(!o.polled){
    return 'No board polled here, so this is a relationship rather than an application. ' +
           'Nothing about it can go stale, because the search link is live.';
  }
  if(o.board_status && o.board_status !== 'ok'){
    return 'Board failed on the last run, so its reqs are carried forward rather than trusted.';
  }
  if(typeof o.scanned === 'number' && o.scanned > 0){
    return 'Board polled: ' + o.scanned.toLocaleString() +
           ' open reqs scanned, none matched the filter. That is a checked answer, not a gap.';
  }
  if(o.scanned === 0){
    return 'Board polled and currently publishes nothing at all.';
  }
  return 'No live req matching the filter right now.';
}

function orgHtml(o, reqs){
  // Three columns, matching the Role Finder card: narrative, fit gauge, then
  // location, comp and the actions stacked so the eye lands on them together.
  var tags = '';
  if(o.arch_label) tags += '<span class="tag">' + esc(o.arch_label) + '</span>';
  tags += '<span class="tag">' + esc(o.industry_label) + '</span>';
  if(o.warm) tags += '<span class="tag t-cust">Warm channel</span>';
  if(o.relationship === 'customer') tags += '<span class="tag t-aws" title="' + esc(o.rel_note) + '">AWS customer</span>';
  else if(o.relationship === 'competitor') tags += '<span class="tag t-rival" title="' + esc(o.rel_note) + '">Shield competitor</span>';
  else if(o.relationship === 'both') tags += '<span class="tag t-rival" title="' + esc(o.rel_note) + '">Competitor, on AWS</span>';
  if(!o.traffic) tags += '<span class="tag t-pivot">Pivot</span>';
  if(o.move === 'down') tags += '<span class="tag t-gate">Down-level</span>';
  if(o.move === 'up') tags += '<span class="tag t-up">Up-level</span>';

  var g = o.gauge || FITG[o.fit];
  var gauge = g
    ? '<div class="gauge g-fit-' + (o.fit || 'adj') + '">' +
        '<span class="bar">' + g.bar + '</span>' +
        '<span class="lab">' + esc(g.label) + '</span>' +
      '</div>'
    : '<div class="gauge"></div>';

  var comp = '';
  if(o.median){
    comp += '<p class="pay"><b>' + money(o.median) + ' total median</b>' +
            '<span class="paynote">' + (o.median_conf === 'reported' ? 'levels.fyi reported' : 'estimate') +
            '</span></p>';
  }
  if(o.pay_note) comp += '<p class="paynote2">' + esc(o.pay_note) + '</p>';
  if(o.target_level){
    comp += '<p class="paynote2">L6 maps to ' + esc(o.target_level) +
            (o.level_conf === 'reported' ? '' : ' (estimate)') + '</p>';
  }
  var geo = (o.geo && o.geo.length) ? '<p class="tax">' + esc(o.geo.join(' \u00b7 ')) + '</p>' : '';

  var acts = '';
  if(o.careers) acts += '<a class="act" href="' + esc(safeUrl(o.careers)) + '" target="_blank" rel="noopener">Careers</a>';
  acts += '<a class="act alt" href="https://www.google.com/search?q=' +
          encodeURIComponent(o.name + ' security engineer job') +
          '" target="_blank" rel="noopener">Search jobs</a>';
  acts += '<a class="act alt" href="https://www.google.com/search?q=' +
          encodeURIComponent(o.name + ' security research blog') +
          '" target="_blank" rel="noopener">Research</a>';

  return '<section class="orgcard">' +
    '<div class="orgmain">' +
      '<div class="orghead">' +
        '<h3>' + esc(o.name) + '</h3>' +
        (reqs.length ? '<span class="opennow">Open now</span>' : '') +
      '</div>' +
      (o.team ? '<p class="team">' + esc(o.team) + ' <span class="tags">' + tags + '</span></p>'
              : '<p class="team"><span class="tags">' + tags + '</span></p>') +
      (o.why ? '<p class="why">' + esc(o.why) + '</p>' : '') +
      '<p class="seen">' + emptyNote(o, reqs) + '</p>' +
    '</div>' +
    gauge +
    '<div class="orgside">' +
      (o.locations ? '<p class="loc">' + esc(o.locations) + '</p>' : '') +
      comp + geo +
      '<div class="acts">' + acts + '</div>' +
    '</div>' +
    (reqs.length ? '<div class="reqs">' + reqs.map(reqHtml).join('') + '</div>' : '') +
  '</section>';
}

function render(){
  var reqOn = reqFilterOn();
  var shown = [];
  var reqCount = 0;
  ORGS.forEach(function(o){
    if(!orgOk(o)) return;
    var reqs = o.reqs.filter(reqOk);
    if(reqOn && !reqs.length) return;
    reqCount += reqs.length;
    shown.push([o, reqs]);
  });
  var nHidden = Object.keys(hidden).length;
  document.getElementById('count').textContent =
    shown.length + ' of ' + ORGS.length + ' orgs \u00b7 ' + reqCount + ' reqs' +
    (nHidden ? ' \u00b7 ' + nHidden + ' hidden' : '');
  hideChip.textContent = nHidden ? 'Hidden (' + nHidden + ')' : 'Hidden';
  var list = document.getElementById('list');
  if(!shown.length){
    var why = 'Nothing matches every filter. Widen one of them.';
    if(state.move === 'down') why = 'No organisation on the list would down-level you.';
    if(state.app === 'accepted') why = 'No application has been accepted yet. This fills in as replies land.';
    list.innerHTML = '<div class="empty">' + why + '</div>';
    return;
  }
  list.innerHTML = shown.map(function(p){ return orgHtml(p[0], p[1]); }).join('');
}

function syncRow(f){
  var sel = multi[f];
  document.querySelectorAll('button.chip[data-f="' + f + '"]').forEach(function(x){
    var v = x.dataset.v;
    x.setAttribute('aria-pressed', String(v === 'all' ? sel.length === 0 : sel.indexOf(v) >= 0));
  });
}

document.querySelectorAll('button.chip[data-f]').forEach(function(b){
  b.addEventListener('click', function(){
    var f = b.dataset.f, v = b.dataset.v;
    if(multi[f]){
      if(v === 'all'){ multi[f] = []; }
      else {
        var i = multi[f].indexOf(v);
        if(i >= 0) multi[f].splice(i, 1); else multi[f].push(v);
      }
      syncRow(f);
    } else {
      state[f] = v;
      document.querySelectorAll('button.chip[data-f="' + f + '"]').forEach(function(x){
        x.setAttribute('aria-pressed', String(x === b));
      });
    }
    render();
  });
});

document.querySelectorAll('button.chip[data-t]').forEach(function(b){
  b.addEventListener('click', function(){
    var t = b.dataset.t;
    toggles[t] = !toggles[t];
    b.setAttribute('aria-pressed', String(toggles[t]));
    render();
  });
});

document.getElementById('list').addEventListener('click', function(ev){
  var h = ev.target.closest('[data-hide]');
  if(h){ hideReq(h.dataset.hide); return; }
  var r = ev.target.closest('[data-restore]');
  if(r){ restoreReq(r.dataset.restore); }
});

var hideChip = document.getElementById('hidechip');
hideChip.addEventListener('click', function(){
  showHidden = !showHidden;
  hideChip.setAttribute('aria-pressed', String(showHidden));
  render();
});

var exportBtn = document.getElementById('hideexport');
exportBtn.addEventListener('click', function(){
  var ids = Object.keys(hidden).sort();
  var text = JSON.stringify({dismissed: ids}, null, 2);
  navigator.clipboard.writeText(text).then(function(){
    exportBtn.textContent = 'Copied, paste into dismissed.json';
    setTimeout(function(){ exportBtn.textContent = 'Copy hidden list'; }, 2500);
  }, function(){
    exportBtn.textContent = 'Copy failed';
    setTimeout(function(){ exportBtn.textContent = 'Copy hidden list'; }, 2500);
  });
});

['co','comp','ind'].forEach(function(id){
  var el = document.getElementById(id);
  if(!el) return;
  el.addEventListener('change', function(){ state[id] = el.value; render(); });
});

render();
"""


PAY_TIER_FLOOR = {"600": 600000, "450": 450000, "400": 400000, "sub": 0}


BAND_COLOR = {"lead_with": "var(--hot)", "table_stakes": "var(--ink-2)", "gap": "var(--gold)"}

ROW_H = 38
BAND_GAP = 52
BAR_X = 646
BAR_MAX = 163
LABEL_X = 360


def skills_chart(rows):
    """Build the demand mind-map from the job descriptions actually fetched.

    The bands are a fixed judgement about one profile. The percentages are
    counted live, so this cannot drift the way a hand-count does. Only reqs
    whose description was retrieved count toward the denominator, because a req
    we never read is not evidence of absence.
    """
    corpus = [r for r in rows if r.get("jd_seen")]
    total = len(corpus)
    if not total:
        return "", 0

    counted = []
    for band, band_label in SKILL_BANDS:
        entries = []
        for skill in SKILLS:
            if skill["band"] != band:
                continue
            n = sum(1 for r in corpus if skill["key"] in (r.get("skills") or []))
            entries.append((skill["label"], round(100.0 * n / total)))
        entries.sort(key=lambda e: -e[1])
        counted.append((band, band_label, entries))

    height = 90
    for _, _, entries in counted:
        height += BAND_GAP + len(entries) * ROW_H
    mid = height / 2

    parts = [
        '<svg viewBox="0 0 960 %d" role="img" style="max-width:100%%;height:auto" '
        'aria-label="Skills named across %d live job descriptions, grouped into lead with, '
        'table stakes and gaps, each bar showing the share of postings naming it.">' % (height, total),
        '<defs><marker id="mmA" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" '
        'markerHeight="6" orient="auto"><path d="M0 0 L8 4 L0 8 z" fill="currentColor"/></marker></defs>',
        # Two subtitle lines rather than one: the full string does not fit the box
        # at this font size, and shrinking the type would lose the anchor.
        '<rect x="14" y="%d" width="204" height="90" rx="3" fill="none" stroke="currentColor" '
        'stroke-width="1.5"/>' % (mid - 45),
        '<text x="116" y="%d" text-anchor="middle" font-size="13" font-weight="600" '
        'fill="currentColor">Your profile</text>' % (mid - 16),
        '<text x="116" y="%d" text-anchor="middle" font-size="11" fill="var(--ink-2)">'
        '12 yrs cyber security</text>' % (mid + 6),
        '<text x="116" y="%d" text-anchor="middle" font-size="11" fill="var(--ink-2)">'
        '6 yrs on an incident response team</text>' % (mid + 24),
    ]

    y = 60
    for band, band_label, entries in counted:
        colour = BAND_COLOR[band]
        band_top = y
        band_bottom = y + len(entries) * ROW_H
        anchor_y = (band_top + band_bottom) / 2
        parts.append(
            '<path d="M214 %.0f C 268 %.0f, 274 %.0f, 320 %.0f" fill="none" stroke="currentColor" '
            'stroke-width="1.2" opacity=".5" marker-end="url(#mmA)"/>' % (mid, mid, anchor_y, anchor_y))
        parts.append(
            '<text x="334" y="%d" font-size="10" letter-spacing="1.6" fill="%s">%s</text>'
            % (band_top - 14, colour, esc_html(band_label.upper())))
        parts.append(
            '<line x1="334" y1="%d" x2="334" y2="%d" stroke="%s" stroke-width="1.5" opacity=".45"/>'
            % (band_top - 6, band_bottom - 10, colour))
        for label, pct in entries:
            cy = y + 18
            width = max(2, round(BAR_MAX * pct / 100.0))
            parts.append('<line x1="334" y1="%d" x2="352" y2="%d" stroke="%s" stroke-width="1.2" '
                         'opacity=".45"/>' % (cy, cy, colour))
            parts.append('<text x="%d" y="%d" font-size="12.5" fill="currentColor">%s</text>'
                         % (LABEL_X, cy + 4, esc_html(label)))
            parts.append('<rect x="%d" y="%d" width="%d" height="12" rx="1.5" fill="%s" opacity=".8"/>'
                         % (BAR_X, cy - 7, width, colour))
            parts.append('<text x="%d" y="%d" font-size="11" fill="var(--ink-2)">%d%%</text>'
                         % (BAR_X + width + 9, cy + 4, pct))
            y += ROW_H
        y += BAND_GAP

    parts.append("</svg>")
    return "".join(parts), total


def build_orgs(orgs_data, rows, board_stats=None):
    """Group reqs under their organization card.

    An org is matched to reqs by its `board` slug. Orgs with no board keep a
    strategy card and a live-search link, which is how the Role Finder handled
    them and the reason nothing here expires.
    """
    board_stats = board_stats or {}
    by_board = {}
    for org in orgs_data:
        if org.get("board"):
            by_board.setdefault(org["board"], []).append(org)

    reqs_by_board = {}
    for row in rows:
        reqs_by_board.setdefault(row["board"], []).append(row)

    out = []
    claimed = set()
    for org in orgs_data:
        comp = org.get("comp") or {}
        board = org.get("board")
        reqs = reqs_by_board.get(board, []) if board else []
        if board:
            claimed.add(board)
        industry = org.get("industry")
        out.append({
            "name": org["name"],
            "industry": industry,
            "industry_label": INDUSTRY_LABELS.get(industry, industry or "unclassified"),
            "sector": org.get("sector") or SECTOR_OF_INDUSTRY.get(industry),
            "arch": org.get("arch"),
            "arch_label": ARCH_LABELS.get(org.get("arch"), org.get("arch") or ""),
            "fit": org.get("fit"),
            "fit_label": FIT_LABELS.get(org.get("fit"), org.get("fit") or ""),
            "traffic": bool(org.get("traffic")),
            "warm": bool(org.get("warm_channel")),
            "relationship": org.get("relationship") or "unknown",
            "rel_note": org.get("relationship_note") or "",
            "rel_url": org.get("relationship_url") or "",
            "team": org.get("team") or "",
            "why": org.get("why") or "",
            "locations": org.get("locations") or "",
            "careers": org.get("careers") or "",
            "polled": bool(board),
            "gauge": FIT_GAUGE.get(org.get("fit")),
            "geo": geo_note(org.get("locations") or ""),
            "scanned": (board_stats.get(board) or {}).get("live") if board else None,
            "board_status": (board_stats.get(board) or {}).get("status") if board else None,
            "median": comp.get("median_total"),
            "median_conf": comp.get("confidence") or "unknown",
            "pay_note": comp.get("note") or "",
            "pay_tier": comp.get("tier") or "sub",
            "target_level": comp.get("target_level"),
            "amazon_equiv": comp.get("amazon_equiv"),
            "level_conf": comp.get("level_confidence") or "unknown",
            "move": level_move(comp.get("amazon_equiv")),
            "reqs": reqs,
        })

    # Any board producing reqs with no org entry still has to appear, or reqs
    # would silently vanish from the page.
    for board, reqs in sorted(reqs_by_board.items()):
        if board in claimed:
            continue
        out.append({
            "name": reqs[0]["company"], "industry": None,
            "industry_label": "unclassified", "sector": None,
            "arch": None, "arch_label": "", "fit": None, "fit_label": "",
            "traffic": False, "warm": False, "relationship": "unknown",
            "rel_note": "", "rel_url": "", "team": "", "why": "",
            "locations": "", "careers": "", "polled": True,
            "gauge": None, "geo": [],
            "scanned": (board_stats.get(board) or {}).get("live"),
            "board_status": (board_stats.get(board) or {}).get("status"),
            "median": None, "median_conf": "unknown", "pay_note": "",
            "pay_tier": "sub", "target_level": None, "amazon_equiv": None,
            "level_conf": "unknown", "move": "unknown", "reqs": reqs,
        })

    order = {"core": 0, "strong": 1, "adj": 2}
    move_order = {"up": 0, "lateral": 1, "unknown": 2, "down": 3}
    out.sort(key=lambda o: (
        0 if o["reqs"] else 1,          # actionable before aspirational
        order.get(o["fit"], 3),
        move_order.get(o["move"], 4),
        -(o["median"] or 0),
        -len(o["reqs"]),
        o["name"],
    ))
    return out


def render(state, slug, apps=(), orgs_data=(), dismissed=()):
    # Every record that can reach the published page goes through the
    # sanitizer first. sanitize raises SanitizerBlocked and returns nothing
    # if a record is unsafe; this function then writes no files.
    state = sanitize(state)
    apps = sanitize_records(list(apps))
    orgs_data = sanitize_records(list(orgs_data))
    dismissed = sanitize({"dismissed": list(dismissed)})["dismissed"]
    rows = build_rows(state, apps)
    orgs = sanitize_records(build_orgs(orgs_data, rows, state.get("boards") or {}))
    skills_svg, skills_n = skills_chart(rows)
    boards = state.get("boards") or {}
    ok = [b for b in boards.values() if b.get("status") == "ok"]
    scanned = sum(b.get("live") or 0 for b in ok)
    failed = [b for b in boards.values() if b.get("status") != "ok"]
    last_run = (state.get("last_run") or "")[:16].replace("T", " ")
    companies = sorted({r["company"] for r in rows})

    board_rows = "".join(
        '<tr><td>{co}</td><td>{pl}</td><td class="n">{live}</td>'
        '<td class="n">{m}</td><td class="{cls}">{st}</td></tr>'.format(
            co=esc_html(b["company"]),
            pl=esc_html(b["platform"]),
            live="n/a" if b.get("live") is None else "{:,}".format(b["live"]),
            m="n/a" if b.get("matches") is None else b["matches"],
            cls="fail" if b.get("status") != "ok" else ("zero" if not b.get("matches") else "ok"),
            st="failed" if b.get("status") != "ok" else ("no match" if not b.get("matches") else "ok"),
        )
        for b in sorted(boards.values(), key=lambda x: (-(x.get("matches") or 0), x["company"]))
    )

    action = [a for a in apps if a.get("status") in ACTION_STATUSES]
    alert_html = ""
    if action:
        items = "".join(
            "<li><b>{co}</b>, {t}. {n}</li>".format(co=esc_html(a["company"]), t=esc_html(a["title"]), n=esc_html(a.get("note") or ""))
            for a in action
        )
        alert_html = (
            '<div class="alert"><h3>{n} application{p} need a look</h3><ul>{items}</ul></div>'
        ).format(n=len(action), p="" if len(action) == 1 else "s", items=items)

    app_rows = "".join(
        '<tr><td class="w">{co}</td><td>{t}</td>'
        '<td class="w"><span class="stat-badge {cls}">{lab}</span></td>'
        '<td class="note">{n}</td></tr>'.format(
            co=esc_html(a["company"]),
            t=esc_html(a["title"]),
            cls=STATUS_META[a["status"]]["cls"],
            lab=STATUS_META[a["status"]]["label"],
            n=esc_html(a.get("note") or ""),
        )
        for a in sorted(apps, key=lambda x: (x["status"] not in ACTION_STATUSES, x["company"]))
    )
    comp_labels = {c["key"]: c["label"] for c in COMPETENCIES}
    comp_labels[FALLBACK_COMPETENCY["key"]] = FALLBACK_COMPETENCY["label"]
    used = [c for c in list(COMPETENCIES) + [FALLBACK_COMPETENCY]
            if any(r["competency"] == c["key"] for r in rows)]
    def money(value):
        return "${:,.0f}K".format(value / 1000) if value else "no data"

    sector_rows = ""
    for key in ("big_tech", "ai_lab", "cyber", "other", "gov"):
        members = [o for o in orgs if o["sector"] == key]
        if not members:
            continue
        priced = [o["median"] for o in members if o["median"]]
        priced.sort()
        median = priced[len(priced) // 2] if priced else None
        sector_rows += (
            '<tr><td>{l}</td><td class="n">{n}</td><td class="n">{p}</td>'
            '<td class="n">{m}</td><td class="n">{r}</td></tr>'
        ).format(
            l=esc_html(SECTOR_LABELS.get(key, key)), n=len(members), p=len(priced),
            m=esc_html(money(median)),
            r=sum(len(o["reqs"]) for o in members),
        )

    level_rows = ""
    for o in sorted(orgs, key=lambda x: x["name"]):
        if not o["target_level"]:
            continue
        level_rows += (
            '<tr><td>{n}</td><td class="w">{t}</td><td class="w">{m}</td><td class="w">{c}</td></tr>'
        ).format(
            n=esc_html(o["name"]), t=esc_html(o["target_level"]),
            m=esc_html(LEVEL_MOVE_LABELS.get(o["move"], o["move"])),
            c=esc_html(o["level_conf"]),
        )
    unresolved_levels = sum(1 for o in orgs if not o["target_level"])

    used_ind = []
    for o in orgs:
        if o["industry"] and o["industry"] not in used_ind:
            used_ind.append(o["industry"])
    ind_options = "".join(
        '<option value="{k}">{l} ({n})</option>'.format(
            k=esc_html(k), l=esc_html(INDUSTRY_LABELS.get(k, k)),
            n=sum(1 for o in orgs if o["industry"] == k))
        for k in sorted(used_ind, key=lambda k: INDUSTRY_LABELS.get(k, k))
    )

    comp_options = "".join(
        '<option value="{k}">{l} ({n})</option>'.format(
            k=esc_html(c["key"]), l=esc_html(c["label"]), n=sum(1 for r in rows if r["competency"] == c["key"]))
        for c in used
    )
    comp_rows = "".join(
        '<tr><td>{l}</td><td class="w">{cv}</td><td class="n">{n}</td><td class="note">{t}</td></tr>'.format(
            l=esc_html(c["label"]), cv=esc_html(RESUMES[c["cv"]]["label"]),
            n=sum(1 for r in rows if r["competency"] == c["key"]),
            t=esc_html(", ".join(c["terms"]) or "anything the rules above did not claim"))
        for c in list(COMPETENCIES) + [FALLBACK_COMPETENCY]
    )
    applied_count = sum(1 for r in rows if r.get("status"))
    rejected_count = sum(1 for a in apps if a.get("status") == "rejected")
    banded_count = sum(1 for r in rows if r.get("pay"))

    options = "".join('<option value="{c}">{c}</option>'.format(c=esc_html(o["name"]))
                      for o in sorted(orgs, key=lambda x: x["name"]))

    js = JS % {
        "status": json.dumps(STATUS_META),
        "resumes": json.dumps(RESUMES),
        "comps": json.dumps(comp_labels),
        "tier": json.dumps(TIER_META),
        "orgs": json.dumps(orgs, ensure_ascii=False),
        "moves": json.dumps(LEVEL_MOVE_LABELS),
        "fitgauge": json.dumps(FIT_GAUGE),
        "dismissed": json.dumps(sorted(dismissed)),
    }

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>jobwatch</title>
<link rel="stylesheet" href="/assets/css/fonts-jobwatch.css">
<style>%(css)s</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="eyebrow">jobwatch / ground truth, polled daily at %(run_time)s %(city)s</div>
  <h1>Every live req that survived<br>the filter.</h1>
  <p class="thesis">Pulled straight from the ATS JSON behind each company's board, so nothing here is a cached
  listing that quietly expired. The gauge ranks <strong>which of my include terms fired on the title</strong>,
  which is a measure of how narrow the term is rather than a judgement of the role. Narrow terms name the
  discipline outright. Wide ones are shared with a much larger pool. <strong>US roles only</strong>: any req
  the board confirms is outside the US is dropped at poll time.</p>
  <ul class="stats">
    <li><b>%(matched)d</b><span>reqs matched</span></li>
    <li><b>%(scanned)s</b><span>reqs scanned</span></li>
    <li><b>%(nboards)d</b><span>boards polled</span></li>
    <li><b>%(applied)d</b><span>applied, still live</span></li>
    <li><b>%(rejected)d</b><span>rejected</span></li>
    <li><b>%(banded)d</b><span>publish a band</span></li>
    <li><b>%(sde)d</b><span>flagged SDE</span></li>
    <li><b>%(last)s</b><span>last run, UTC</span></li>
  </ul>
  %(alert)s
</header>

<section class="panel">
  <h2>What the market actually asks for</h2>
  <p class="sub">Every requirement counted across <strong>%(skills_n)d live job descriptions</strong>
  pulled from the reqs on this page. The bar is the share of those postings naming the skill, so it
  reads as demand rather than as my proficiency. The three bands are my judgement about my own
  profile; the percentages are counted at poll time and move as the market does.</p>
  <figure style="margin:0 0 10px">%(skills_svg)s</figure>
  <div class="box">
    <h3>Read the top of the map, not the bottom</h3>
    <p>The most-requested capabilities are the literal content of six years on the Shield Response
    Team, so they belong in the first line of an application. The table-stakes band is held but
    shared with everyone applying, which puts it in the body rather than the opening.</p>
  </div>
  <div class="box">
    <h3>One of the gaps is a routing signal rather than a shortfall</h3>
    <p>Compiled languages are not a skill to go and acquire. That requirement is what marks a
    posting as an SDE seat wearing a security label, which is the same thing the SDE signal flag
    catches on the title. Treat it as a filter that removes roles. EDR and endpoint is the one
    real gap, and it is exactly what separates a network-side career from the endpoint half of
    detection.</p>
  </div>
</section>

<div class="controls">
  <div class="ctl-row">
    <span class="ctl-label">Sector</span>
    <button class="chip" data-f="sector" data-v="all" aria-pressed="true">All</button>
    <button class="chip" data-f="sector" data-v="big_tech" aria-pressed="false">Big tech</button>
    <button class="chip" data-f="sector" data-v="ai_lab" aria-pressed="false">AI lab</button>
    <button class="chip" data-f="sector" data-v="cyber" aria-pressed="false">Cyber</button>
    <button class="chip" data-f="sector" data-v="other" aria-pressed="false">Other</button>
    <button class="chip" data-f="sector" data-v="gov" aria-pressed="false">Government</button>
  </div>
  <div class="ctl-row">
    <span class="ctl-label">Level</span>
    <button class="chip" data-f="move" data-v="all" aria-pressed="true">In scope, L6+</button>
    <button class="chip" data-f="move" data-v="up" aria-pressed="false">Up-level</button>
    <button class="chip" data-f="move" data-v="lateral" aria-pressed="false">Lateral</button>
    <button class="chip" data-f="move" data-v="unknown" aria-pressed="false">Unresolved</button>
    <button class="chip" data-f="move" data-v="down" aria-pressed="false">Down-level</button>
  </div>
  <div class="ctl-row">
    <span class="ctl-label">Comp</span>
    <button class="chip" data-f="paytier" data-v="all" aria-pressed="true">Any</button>
    <button class="chip" data-f="paytier" data-v="400" aria-pressed="false">$400K+</button>
    <button class="chip" data-f="paytier" data-v="450" aria-pressed="false">$450K+</button>
    <button class="chip" data-f="paytier" data-v="600" aria-pressed="false">$600K+</button>
    <button class="chip" data-t="banded" aria-pressed="false">Has posted band</button>
  </div>
  <div class="ctl-row">
    <span class="ctl-label">Fit</span>
    <button class="chip" data-f="fit" data-v="all" aria-pressed="true">All</button>
    <button class="chip" data-f="fit" data-v="core" aria-pressed="false">Core mandate</button>
    <button class="chip" data-f="fit" data-v="strong" aria-pressed="false">Strong</button>
    <button class="chip" data-f="fit" data-v="adj" aria-pressed="false">Adjacent</button>
    <button class="chip" data-t="traffic" aria-pressed="false">Hostile traffic at scale</button>
    <button class="chip" data-t="customer" aria-pressed="false">Warm channel</button>
    <button class="chip" data-f="rel" data-v="competitor" aria-pressed="false">Shield competitor</button>
    <button class="chip" data-f="rel" data-v="customer" aria-pressed="false">AWS customer</button>
    <button class="chip" data-t="open" aria-pressed="false">Has live reqs</button>
  </div>
  <div class="ctl-row">
    <span class="ctl-label">Mine</span>
    <button class="chip" data-f="app" data-v="all" aria-pressed="true">Everything</button>
    <button class="chip" data-f="app" data-v="applied" aria-pressed="false">Applied to</button>
    <button class="chip" data-f="app" data-v="open" aria-pressed="false">Not yet applied</button>
    <button class="chip" data-f="app" data-v="accepted" aria-pressed="false">Accepted</button>
    <button class="chip" data-f="app" data-v="rejected" aria-pressed="false">Rejected</button>
    <button class="chip" id="hidechip" aria-pressed="false">Hidden</button>
    <button class="chip" id="hideexport">Copy hidden list</button>
  </div>
  <div class="ctl-row">
    <span class="ctl-label">Where</span>
    <button class="chip" data-f="place" data-v="all" aria-pressed="true">Anywhere</button>
    <button class="chip" data-f="place" data-v="remote" aria-pressed="false">Remote</button>
    <button class="chip" data-f="place" data-v="us" aria-pressed="false">US site</button>
    <button class="chip" data-f="place" data-v="multi" aria-pressed="false">Multi site</button>
    <button class="chip" data-f="place" data-v="unclear" aria-pressed="false">Unstated</button>
  </div>
  <div class="ctl-row">
    <span class="ctl-label">Signal</span>
    <button class="chip" data-f="tier" data-v="all" aria-pressed="true">All</button>
    <button class="chip" data-f="tier" data-v="rare" aria-pressed="false">Names the discipline</button>
    <button class="chip" data-f="tier" data-v="direct" aria-pressed="false">Traffic adjacent</button>
    <button class="chip" data-f="tier" data-v="wide" aria-pressed="false">Wide term</button>
    <button class="chip" data-t="sde" aria-pressed="false">SDE signal</button>
  </div>
  <div class="ctl-row">
    <span class="ctl-label">Slice</span>
    <select class="chip" id="co"><option value="all">All organisations</option>%(options)s</select>
    <select class="chip" id="ind"><option value="all">All industries</option>%(ind_options)s</select>
    <select class="chip" id="comp"><option value="all">All competencies</option>%(comp_options)s</select>
    <span class="count" id="count"></span>
  </div>
  <div class="ctl-row">
    <span class="ctl-label"></span>
    <span class="hint2">Chips stack: any selection within a row, all rows together. Click a lit chip to clear it, or All to reset the row.</span>
  </div>
</div>

<div id="list"></div>

<section class="panel">
  <h2>Where my applications stand</h2>
  <p class="sub">Hand maintained from the confirmation mail. jobwatch itself never submits anything, so this
  is the one part of the page I have to keep honest by hand. A req I have applied to still shows in the list
  above with its badge, because it closing is exactly the thing I want to hear about.</p>
  <div class="scroll">
    <table class="apps">
      <thead><tr><th>Company</th><th>Role</th><th>Status</th><th>Note</th></tr></thead>
      <tbody>%(app_rows)s</tbody>
    </table>
  </div>
  <p class="hint">Scroll the table sideways for the full row.</p>
</section>

<section class="panel">
  <h2>Coverage on the last run</h2>
  <p class="sub">Every board is polled through its ATS JSON API. A board that errors is caught on its own and
  never causes its known reqs to be reported as closed, so a bad day at one company cannot corrupt the diff.</p>
  <div class="scroll">
    <table class="boards">
      <thead><tr><th>Company</th><th>Platform</th><th>Live reqs</th><th>Matched</th><th>Status</th></tr></thead>
      <tbody>%(board_rows)s</tbody>
    </table>
  </div>
</section>

<section class="panel">
  <h2>Comp by sector, and what it costs to stay in the lane</h2>
  <p class="sub">Sector predicts the band better than discipline does. This is the tension worth
  holding: the work is most on-target in cyber, and the money is in big tech and the AI labs.
  Median is across the organisations here that have market data, so a sector with few priced
  entries is a thin sample rather than a finding.</p>
  <div class="scroll">
    <table class="boards">
      <thead><tr><th>Sector</th><th>Orgs</th><th>Priced</th><th>Median total</th><th>Live reqs</th></tr></thead>
      <tbody>%(sector_rows)s</tbody>
    </table>
  </div>
  <p class="hint" style="display:block;margin-top:8px">Big tech is tech-native product companies
  at scale. AI lab covers the frontier labs and the AI infrastructure builders. Cyber is the
  security and threat-intel vendors, where the work is most on-target. Other is everything where
  technology is a cost centre rather than the product: carriers, registries, media and betting.
  Government includes the FFRDCs and the nonprofits.</p>
  <div class="box" style="margin-top:14px">
    <h3>Base band and market median answer different questions</h3>
    <p>The band on a req is what the employer published, and US pay-transparency law makes that
    <strong>base salary only</strong>. Equity and bonus sit outside it. The market median on an org
    card is <strong>total compensation</strong> at the level, which is base plus stock plus bonus.
    Comparing one against the other understates a role badly, often by most of the package at
    senior levels. Both are labelled here for that reason, and an org with no market data says so
    rather than showing a blank.</p>
    <p>Geography moves the same number by 5 to 15 percent after tax, because state income tax
    varies from zero to roughly 11 percent. A headline figure in a high-tax state can take home
    less than a smaller one in a state with no income tax. A remote role is taxed where you live
    rather than where the employer sits, which is the one lever that is yours to pull.</p>
  </div>
</section>

<section class="panel">
  <h2>Level equivalence, and the down-level gate</h2>
  <p class="sub">The target is Amazon L6 or above, so lateral or up. A role that would down-level
  is gated rather than scored: it is excluded from the default view and reachable only by
  selecting Down-level explicitly. Ladder names are not comparable across employers, so every
  mapping is normalised to the Amazon axis and carries how it was sourced.</p>
  <div class="scroll">
    <table class="apps">
      <thead><tr><th>Organisation</th><th>Their level</th><th>Move</th><th>Confidence</th></tr></thead>
      <tbody>%(level_rows)s</tbody>
    </table>
  </div>
  <p class="hint">%(unresolved_levels)d of %(org_total)d organisations have no level mapping yet.
  Those are shown as unresolved rather than assumed in scope.</p>
</section>

<section class="panel">
  <h2>Competency map, and which CV each one leads with</h2>
  <div class="box">
    <h3>One test: does the work involve hostile traffic at scale?</h3>
    <p>Include: <code>ddos</code> <code>denial of service</code> <code>detection</code>
    <code>incident response</code> <code>threat</code> <code>botnet</code> <code>abuse</code>
    <code>edge</code> <code>perimeter</code> <code>waf</code> <code>network security</code>
    <code>traffic</code> <code>sirt</code></p>
    <p>Exclude, and exclude always wins: <code>intern</code> <code>manager</code> <code>director</code>
    <code>recruiter</code> <code>sales</code> <code>workforce security</code> <code>endpoint</code>
    <code>grc</code> <code>compliance</code> <code>physical security</code> <code>studio security</code></p>
    <p>Matching is anchored on word boundaries, so <code>intern</code> catches Interns and Internship while
    leaving International alone, and <code>edge</code> never fires on Knowledge.</p>
  </div>
  <div class="scroll">
    <table class="apps">
      <thead><tr><th>Competency</th><th>Resume variant</th><th>Reqs</th><th>Title signals</th></tr></thead>
      <tbody>%(comp_rows)s</tbody>
    </table>
  </div>
  <p class="hint">Scroll the table sideways for the full row.</p>
  <div class="box" style="margin-top:14px">
    <h3>How a req gets classified</h3>
    <p>Every req lands in exactly one competency, and every competency names the resume variant that
    leads with it. The order in the table is the policy: the first competency whose signals appear in the
    title claims the req, so the narrow disciplines are checked before the broad ones. That is why a
    Threat Investigator goes to intelligence work rather than falling through to detection, and why a
    Detection and Mitigation Engineer is read as DDoS defence rather than generic detection.</p>
    <p>Two variants share a destination on purpose. Botnet research and traffic integrity both lead with
    the Edge and DDoS variant, because the botnet corpus and the volumetric work are the same scarce
    asset. Threat intelligence, detection and response, and anti-abuse all lead with the Detection and
    Response variant, because that is the one written to open on detection engineering.</p>
    <p>All five variants live in one Drive folder and anchor the same headline title. jobwatch reads
    nothing from them and never touches them.</p>
  </div>
  <div class="box">
    <h3>The band shown is base only</h3>
    <p>US pay-transparency law makes companies publish a range, and that range is <strong>base salary
    only</strong>. Equity and bonus sit outside it and are almost never stated. A posting will
    often give a band and then separately note that all full-time employees are also eligible for
    equity, so reading the posted number as total compensation understates the role badly, often by
    most of the package at senior levels. That is why every band here is labelled rather than shown
    bare.</p>
    <p>The number is pulled from the company's own job description at poll time, so it is whatever
    they published rather than an estimate. Reqs with no band publish none; there is no guessing and
    no third-party data. levels.fyi was considered for a market comparison and does not cover any of
    the companies on this board.</p>
  </div>
  <div class="box">
    <h3>US only, and how the board's vagueness is handled</h3>
    <p>A req is dropped when its location resolves to anywhere outside the US. Title and location are
    checked together, because boards put the country in either one, which catches a title reading
    Remote, GBR that would otherwise pass as an eligible remote role.</p>
    <p>The harder problem is a board that will not say where the job is. Workday returns "3 Locations"
    and Greenhouse returns "Hybrid", and either can hide a non-US site. Both are resolved rather than
    guessed: Workday postings are expanded through the posting detail endpoint, which names every site,
    and Greenhouse reads the real city out of the job's own location metadata. That is not cosmetic:
    a req reading "Hybrid" in the list can resolve to sites on the other side of the world, so it
    drops where it would previously have been kept.</p>
    <p>Nothing on this page is left as an unresolved location. If a req cannot be resolved and cannot be
    confirmed as US, it stays visible rather than being silently dropped, so the gap is never hidden.</p>
  </div>
  <div class="box">
    <h3>SDE signal means flagged, not hidden</h3>
    <p>A title carrying Software Engineer usually means an SDE seat wearing a security label. Those stay on the
    list and get marked, because a coding loop is worth the prep when the domain match is real. The filter above
    it is the one that decides whether the domain match is real.</p>
  </div>
</section>

<footer>
  Generated from jobwatch_state.json. Filters are session only, nothing is stored or sent anywhere.
  Every link goes to the live req on the company's own board, so a dead link here means the req closed,
  which is exactly the thing this was built to catch. Not indexed, and not linked from anywhere.
</footer>

</div>
<script src="/%(slug)s.js"></script>
</body>
</html>
""" % {
        "css": CSS,
        "matched": len(rows),
        "scanned": "{:,}".format(scanned),
        "nboards": len(boards),
        "sde": sum(1 for r in rows if r["sde"]),
        "last": last_run or "n/a",
        "options": options,
        "board_rows": board_rows,
        "slug": slug,
        "city": esc_html(SITE_CITY),
        "run_time": esc_html(SITE_RUN_TIME),
        "alert": alert_html,
        "app_rows": app_rows,
        "applied": applied_count,
        "comp_options": comp_options,
        "ind_options": ind_options,
        "sector_rows": sector_rows,
        "level_rows": level_rows,
        "unresolved_levels": unresolved_levels,
        "org_total": len(orgs),
        "skills_svg": skills_svg,
        "skills_n": skills_n,
        "comp_rows": comp_rows,
        "rejected": rejected_count,
        "banded": banded_count,
    }
    scan_public_text(html)
    scan_public_text(js)
    return html, js


def main():
    parser = argparse.ArgumentParser(description="Render jobwatch state into a static page.")
    parser.add_argument("--out", default="site", help="output directory")
    parser.add_argument("--slug", required=True, help="bare object key the page is served at")
    args = parser.parse_args()

    if not SLUG_RE.match(args.slug):
        parser.error("--slug must match [A-Za-z0-9_-]{1,64}; it becomes a file name and an object key")

    try:
        with open(STATE_PATH, "r", encoding="utf-8") as handle:
            state = sanitize(handle.read())

        apps = []
        if os.path.exists(APPS_PATH):
            with open(APPS_PATH, "r", encoding="utf-8") as handle:
                apps = sanitize(handle.read()).get("applications", [])

        orgs_data = []
        if os.path.exists(ORGS_PATH):
            with open(ORGS_PATH, "r", encoding="utf-8") as handle:
                orgs_data = sanitize(handle.read()).get("organizations", [])

        dismissed = []
        if os.path.exists(HIDDEN_PATH):
            with open(HIDDEN_PATH, "r", encoding="utf-8") as handle:
                dismissed = sanitize(handle.read()).get("dismissed", [])

        html, js = render(state, args.slug, apps, orgs_data, dismissed)
    except SanitizerBlocked as exc:
        # Fail closed: do not write HTML or JS, even leftovers from an older run.
        print("sanitizer blocked public page: {}".format(exc), file=sys.stderr)
        raise SystemExit(2)

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, args.slug), "w", encoding="utf-8") as handle:
        handle.write(html)
    with open(os.path.join(args.out, args.slug + ".js"), "w", encoding="utf-8") as handle:
        handle.write(js)
    print("wrote {}/{} and {}.js".format(args.out, args.slug, args.slug))


if __name__ == "__main__":
    main()
