"""Shared vocabulary for jobwatch.

Every term list, competency, resume variant and taxonomy lives here so the poller
and the renderer cannot drift apart. Before this existed, INCLUDE_TERMS was
defined three times: once in jobwatch.py, again as the TIER_* split in
render_site.py, and a third time hardcoded as <code> tags in the page.

Nothing here does IO. Both scripts import from it.
"""

import re

INCLUDE_TERMS = (   'ddos',
    'denial of service',
    'detection',
    'incident response',
    'threat',
    'botnet',
    'abuse',
    'edge',
    'perimeter',
    'waf',
    'network security',
    'traffic',
    'sirt')

EXCLUDE_TERMS = (   'intern',
    'manager',
    'director',
    'recruiter',
    'sales',
    'workforce security',
    'endpoint',
    'grc',
    'compliance',
    'physical security',
    'studio security')

FLAG_TERMS = ('software engineer',)

NON_US_MARKERS = (
    'united kingdom',
    'england',
    'scotland',
    'wales',
    'london',
    'manchester',
    'ireland',
    'dublin',
    'israel',
    'tel aviv',
    'india',
    'hyderabad',
    'mumbai',
    'new delhi',
    'bangalore',
    'bengaluru',
    'pune',
    'japan',
    'tokyo',
    'australia',
    'sydney',
    'melbourne',
    'singapore',
    'switzerland',
    'zurich',
    'geneva',
    'sweden',
    'stockholm',
    'germany',
    'berlin',
    'munich',
    'hamburg',
    'france',
    'paris',
    'netherlands',
    'amsterdam',
    'spain',
    'madrid',
    'barcelona',
    'portugal',
    'lisbon',
    'poland',
    'warsaw',
    'krakow',
    'romania',
    'bucharest',
    'czech',
    'prague',
    'italy',
    'milan',
    'rome',
    'belgium',
    'brussels',
    'denmark',
    'copenhagen',
    'norway',
    'oslo',
    'finland',
    'helsinki',
    'austria',
    'vienna',
    'canada',
    'toronto',
    'vancouver',
    'montreal',
    'ottawa',
    'mexico',
    'brazil',
    'sao paulo',
    'argentina',
    'buenos aires',
    'chile',
    'colombia',
    'costa rica',
    'china',
    'beijing',
    'shanghai',
    'shenzhen',
    'hong kong',
    'taiwan',
    'taipei',
    'hsinchu',
    'korea',
    'seoul',
    'vietnam',
    'hanoi',
    'thailand',
    'bangkok',
    'malaysia',
    'kuala lumpur',
    'indonesia',
    'jakarta',
    'philippines',
    'manila',
    'new zealand',
    'auckland',
    'south africa',
    'nigeria',
    'kenya',
    'egypt',
    'united arab emirates',
    'dubai',
    'abu dhabi',
    'saudi',
    'turkey',
    'istanbul',
    'emea',
    'apac',
    'latam',
    'anz',
)


NON_US_ABBREV = (   'uk',
    'gbr',
    'ire',
    'irl',
    'isr',
    'ind',
    'deu',
    'fra',
    'esp',
    'nld',
    'che',
    'swe',
    'pol',
    'rou',
    'cze',
    'aus',
    'nzl',
    'can',
    'bra',
    'mex',
    'jpn',
    'kor',
    'sgp',
    'hkg',
    'twn',
    'chn',
    'zaf')

GENERIC_LOCATIONS = frozenset({   'flexible',
              'hybrid',
              'in office',
              'in-office',
              'multiple',
              'office',
              'on-site',
              'onsite',
              'remote',
              'remote-friendly',
              'various'})

RESUMES = {   'ai_sec': {'id': 'REPLACE_WITH_YOUR_AISEC_CV_FILE_ID', 'label': 'AI Security'},
    'dr': {'id': 'REPLACE_WITH_YOUR_DR_CV_FILE_ID', 'label': 'Detection & Response'},
    'edge_ddos': {'id': 'REPLACE_WITH_YOUR_EDGE_CV_FILE_ID', 'label': 'Edge / DDoS'},
    'general': {'id': 'REPLACE_WITH_YOUR_GENERAL_CV_FILE_ID', 'label': 'General'},
    'waf_edge': {'id': 'REPLACE_WITH_YOUR_WAF_CV_FILE_ID', 'label': 'WAF / Edge'}}

COMPETENCIES = (   {   'cv': 'waf_edge',
        'key': 'waf',
        'label': 'WAF & application perimeter',
        'terms': (   'waf',
                     'web application firewall',
                     'perimeter',
                     'bot management',
                     'bot mitigation',
                     'application protection')},
    {   'cv': 'edge_ddos',
        'key': 'ddos',
        'label': 'DDoS & volumetric defence',
        'terms': ('ddos', 'denial of service', 'volumetric', 'scrubbing', 'mitigation')},
    {   'cv': 'edge_ddos',
        'key': 'botnet',
        'label': 'Botnet & malware research',
        'terms': ('botnet', 'malware', 'reverse engineer')},
    {   'cv': 'edge_ddos',
        'key': 'edge',
        'label': 'Edge, network & traffic integrity',
        'terms': (   'edge',
                     'network security',
                     'traffic',
                     'transit',
                     'backbone',
                     'peering',
                     'anycast',
                     'sirt')},
    {   'cv': 'ai_sec',
        'key': 'ai',
        'label': 'Agentic AI security',
        'terms': ('agentic', 'llm', 'genai', 'ai security', 'prompt injection')},
    {   'cv': 'dr',
        'key': 'intel',
        'label': 'Threat intelligence & investigation',
        'terms': (   'threat intelligence',
                     'threat intel',
                     'threat investigator',
                     'threat hunt',
                     'threat research',
                     'insider threat',
                     'threat analyst',
                     'adversary',
                     'threat')},
    {   'cv': 'dr',
        'key': 'dr',
        'label': 'Detection & incident response',
        'terms': ('detection', 'incident response', 'forensic', 'response')},
    {   'cv': 'dr',
        'key': 'abuse',
        'label': 'Anti-abuse & platform protection',
        'terms': ('abuse', 'fraud', 'account takeover', 'trust and safety', 'safety')})

FALLBACK_COMPETENCY = {'cv': 'general', 'key': 'general', 'label': 'Security engineering, unclassified', 'terms': ()}

TIER_RARE = ('ddos', 'denial of service', 'botnet', 'sirt', 'waf', 'perimeter')

TIER_DIRECT = ('network security', 'edge', 'traffic', 'incident response')

TIER_WIDE = ('detection', 'threat', 'abuse')

TIER_META = {   'direct': {'bar': '██████░░', 'label': 'Traffic adjacent', 'rank': 2},
    'rare': {'bar': '████████', 'label': 'Names the discipline', 'rank': 3},
    'wide': {'bar': '████░░░░', 'label': 'Wide term', 'rank': 1}}

# Application statuses. Local tracker only — never published.
# stage=verify is the "did it land?" bucket. submitted lives there.
# ACTION_STATUSES is the "needs a look" alert list; submitted is not on it.
STATUS_META = {
    "accepted": {"cls": "st-good", "label": "Accepted", "stage": "offer"},
    "applied": {"cls": "st-ok", "label": "Applied", "stage": "in_play"},
    "closed": {"cls": "st-no", "label": "Closed", "stage": "closed"},
    "closed_candidate_declined": {"cls": "st-no", "label": "Closed, declined", "stage": "closed"},
    "closed_duplicate_180d": {"cls": "st-no", "label": "Closed, 180-day duplicate", "stage": "closed"},
    "closed_fola_not_fit": {"cls": "st-no", "label": "Closed, not a fit", "stage": "closed"},
    "confirmed": {"cls": "st-ok", "label": "Applied", "stage": "in_play"},
    "not_submitted": {"cls": "st-no", "label": "Not submitted", "stage": "verify"},
    "parked_mulling": {"cls": "st-no", "label": "Parked", "stage": "parked"},
    "pending": {"cls": "st-warn", "label": "Needs confirming", "stage": "verify"},
    "rejected": {"cls": "st-no", "label": "Rejected", "stage": "closed"},
    "screen_done_awaiting": {"cls": "st-warn", "label": "Screen done, awaiting", "stage": "in_play"},
    "submitted": {"cls": "st-warn", "label": "Submitted, verify it sent", "stage": "verify"},
    "superseded_by_staff": {"cls": "st-no", "label": "Superseded", "stage": "closed"},
    "unconfirmed": {"cls": "st-warn", "label": "Verify it sent", "stage": "verify"},
    "warm_resume_sent": {"cls": "st-ok", "label": "Warm resume sent", "stage": "in_play"},
    "watch": {"cls": "st-no", "label": "Watching", "stage": "watch"},
}

ACTION_STATUSES = ("pending", "unconfirmed", "not_submitted")

# Safe bucket for a status the local tracker has not named yet.
UNKNOWN_STATUS = {"cls": "st-no", "label": "Unknown", "stage": "unknown"}


def status_meta(status):
    """Look up an application status. Unknown values map to a safe bucket.

    Local tracker only. The public page must not call this: application
    records are not public output.
    """
    return STATUS_META.get(status, UNKNOWN_STATUS)


# Internal only. Never published. Extra keys on an application must not
# fail a public render, because application records are not public output.
INTERVIEW_STYLES = (
    "ai_allowed_or_takehome",
    "design_scenario_ir_heavy",
    "live_no_ai_coding",
    "unknown",
)

INTL = (   'united kingdom',
    'london',
    'ireland',
    'dublin',
    'israel',
    'tel aviv',
    'india',
    'hyderabad',
    'mumbai',
    'new delhi',
    'japan',
    'tokyo',
    'australia',
    'sydney',
    'singapore',
    'switzerland',
    'zurich',
    'sweden',
    'stockholm',
    'germany',
    'hamburg',
    'berlin',
    'canada',
    'toronto',
    'romania',
    'china',
    'beijing',
    'taiwan',
    'vietnam',
    'korea',
    'france',
    'paris',
    'netherlands',
    'amsterdam',
    'spain',
    'poland',
    'brazil',
    'mexico',
    'gbr',
    'ire',
    'rou',
    'isr')

US = (   'united states',
    'usa',
    'us -',
    'us,',
    'remote us',
    'us remote',
    'seattle',
    'san francisco',
    'new york',
    'austin',
    'sunnyvale',
    'san mateo',
    'santa clara',
    'mountain view',
    'ann arbor',
    'san jose',
    'washington, d',
    'atlanta',
    'denver',
    'boston',
    'chicago',
    'los angeles',
    'san diego',
    'bellevue',
    'redmond',
    'silver spring',
    'reston',
    'arlington',
    'mclean',
    'herndon',
    'michigan',
    'california',
    'texas',
    'virginia',
    ', ca',
    ', wa',
    ', ny',
    ', tx',
    ', mi',
    ', ga')


# ---------------------------------------------------------------- organizations
# Real vertical per org. Closed set: an org that matches none of these is a bug
# rather than an "other", because a catch-all bucket is how taxonomies rot.
INDUSTRIES = (
    "security_vendor", "threat_intel_vendor", "security_services",
    "hyperscaler", "social_platform", "data_platform", "marketplace",
    "fintech", "gaming", "comms_platform", "semiconductor", "streaming_media",
    "ai_lab", "ai_infrastructure",
    "telecom_carrier", "telecom_equipment", "internet_registry", "betting",
    "government", "nonprofit",
)

# Coarse roll-up, because sector predicts the band better than discipline does.
# Derived from industry so the two can never disagree; an org may override it
# (Netflix pays like big tech, the other streaming orgs do not).
SECTOR_OF_INDUSTRY = {
    "hyperscaler": "big_tech", "social_platform": "big_tech", "data_platform": "big_tech",
    "marketplace": "big_tech", "fintech": "big_tech", "gaming": "big_tech",
    "comms_platform": "big_tech", "semiconductor": "big_tech",
    "ai_lab": "ai_lab", "ai_infrastructure": "ai_lab",
    "security_vendor": "cyber", "threat_intel_vendor": "cyber", "security_services": "cyber",
    "telecom_carrier": "other", "telecom_equipment": "other",
    "internet_registry": "other", "betting": "other", "streaming_media": "other",
    "government": "gov", "nonprofit": "gov",
}

SECTOR_LABELS = {
    "big_tech": "Big tech", "ai_lab": "AI lab", "cyber": "Cyber",
    "other": "Other", "gov": "Government",
}

INDUSTRY_LABELS = {
    "security_vendor": "Security vendor", "threat_intel_vendor": "Threat intel vendor",
    "security_services": "Security services", "hyperscaler": "Hyperscaler",
    "social_platform": "Social platform", "data_platform": "Data platform",
    "marketplace": "Marketplace", "fintech": "Fintech", "gaming": "Gaming",
    "comms_platform": "Comms platform", "semiconductor": "Semiconductor",
    "streaming_media": "Streaming and media", "ai_lab": "AI lab",
    "ai_infrastructure": "AI infrastructure", "telecom_carrier": "Telecom carrier",
    "telecom_equipment": "Telecom equipment", "internet_registry": "Internet registry",
    "betting": "Betting", "government": "Government", "nonprofit": "Nonprofit",
}

ARCH_LABELS = {
    "edge": "Edge / DDoS", "abuse": "Anti-abuse", "intel": "Threat intel",
    "netsec": "Network / infra", "dr": "Detection & response", "ent": "Enterprise",
}

FIT_LABELS = {"core": "Core mandate", "strong": "Strong", "adj": "Adjacent"}

# ---------------------------------------------------------------- levelling
# The target is Amazon L6 or higher. Lateral or up. A role that would down-level
# is a gate rather than a scoring penalty, so it is hidden unless asked for.
HOME_LEVEL = 6


AMAZON_LEVEL_RE = re.compile(r"^L(\d{1,2})$", re.IGNORECASE)


def level_move(amazon_equiv):
    """Return 'lateral', 'up', 'down' or 'unknown' for an Amazon-form level.

    Deliberately strict. It takes an Amazon level such as "L6", never a target's
    own ladder name, because those are not comparable: Meta E5, Roblox IC4 and
    Microsoft 64 are all L6 equivalents and digit-scraping them would silently
    report a down-level. Anything not matching ^L\d+$ is 'unknown' rather than a
    guess."""
    match = AMAZON_LEVEL_RE.match(str(amazon_equiv or "").strip())
    if not match:
        return "unknown"
    value = int(match.group(1))
    if value > HOME_LEVEL:
        return "up"
    if value == HOME_LEVEL:
        return "lateral"
    return "down"


LEVEL_MOVE_LABELS = {
    "up": "Up-level", "lateral": "Lateral", "down": "Down-level",
    "unknown": "Level unresolved",
}

# Down-level is gated: excluded from the default view, reachable only on request.
GATED_LEVEL_MOVES = ("down",)

# ---------------------------------------------------------------- skills demand
# What the market asks for, counted across live job descriptions.
#
# The BANDS are a judgement about one profile and are hand-set. The PERCENTAGES
# are generated from real JD text, so the chart stays current instead of being a
# hand-count frozen on the day it was made.
#
#   lead_with    - what to open an application with
#   table_stakes - held, but not a differentiator
#   gap          - not held; name it rather than phrase around it
SKILLS = (
    {"key": "threat_intel", "label": "Threat intelligence", "band": "lead_with",
     "terms": ("threat intelligence", "threat intel", "threat research", "threat actor",
               "adversary", "indicators of compromise", "ioc", "threat hunting")},
    {"key": "incident_response", "label": "Incident response", "band": "lead_with",
     "terms": ("incident response", "incident commander", "on-call", "on call", "oncall",
               "triage", "escalation", "incident management")},
    {"key": "ddos", "label": "DDoS & mitigation", "band": "lead_with",
     "terms": ("ddos", "denial of service", "volumetric", "scrubbing", "botnet",
               "mitigation", "traffic filtering")},
    {"key": "network_depth", "label": "Network & protocol depth", "band": "lead_with",
     "terms": ("tcp", "bgp", "anycast", "netflow", "pcap", "packet capture",
               "network protocol", "protocol analysis", "layer 3", "layer 7")},

    {"key": "automation", "label": "Automation & SOAR", "band": "table_stakes",
     "terms": ("automation", "automate", "soar", "orchestration", "playbook", "tooling")},
    {"key": "python", "label": "Python", "band": "table_stakes",
     "terms": ("python",)},
    {"key": "forensics", "label": "Forensics & evidence", "band": "table_stakes",
     "terms": ("forensic", "forensics", "evidence", "memory analysis", "malware analysis",
               "reverse engineering")},
    {"key": "detection_eng", "label": "Detection engineering", "band": "table_stakes",
     "terms": ("detection engineering", "detection logic", "detections", "alerting",
               "signature", "detection rule", "detection content")},
    {"key": "cloud", "label": "Cloud platforms", "band": "table_stakes",
     "terms": ("aws", "azure", "gcp", "google cloud", "kubernetes", "terraform")},

    {"key": "edr", "label": "EDR & endpoint", "band": "gap",
     "terms": ("edr", "endpoint detection", "endpoint security", "osquery", "sentinelone",
               "falcon sensor", "xdr")},
    {"key": "compiled", "label": "Compiled languages", "band": "gap",
     "terms": ("golang", "go programming", "c\\+\\+", "rust", "java")},
    {"key": "siem", "label": "SIEM & log pipelines", "band": "gap",
     "terms": ("siem", "splunk", "elasticsearch", "elastic stack", "log pipeline",
               "logging pipeline", "sumo logic")},
    {"key": "etl", "label": "ETL & streaming", "band": "gap",
     "terms": ("kafka", "spark", "flink", "airflow", "etl", "data pipeline", "streaming data")},
)

SKILL_BANDS = (
    ("lead_with", "Lead with"),
    ("table_stakes", "Proven, table stakes"),
    ("gap", "Gaps to name"),
)

SKILL_RE = {
    s["key"]: re.compile("|".join(r"\b" + t + r"\b" for t in s["terms"]), re.IGNORECASE)
    for s in SKILLS
}


def detect_skills(text):
    """Return the skill keys a job description names. Word-boundary anchored so
    'go' does not match inside 'algorithm' and 'ioc' does not match 'associate'."""
    if not text:
        return []
    return [key for key, rx in SKILL_RE.items() if rx.search(text)]


# Org-level fit gauge, drawn as a link-utilisation bar like the req signal gauge.
FIT_GAUGE = {
    "core": {"bar": "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588", "label": "Core mandate"},
    "strong": {"bar": "\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591", "label": "Strong"},
    "adj": {"bar": "\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591", "label": "Adjacent"},
}

# Generic, published tax and rent context by location. Nothing personal here:
# these are state rates and market rents, not his position.
GEO_NOTES = (
    ("remote", "Remote: taxed where you live"),
    ("wa", "WA 0% state, keep ~69%"),
    ("seattle", "WA 0% state, keep ~69%"),
    ("bellevue", "WA 0% state, keep ~69%"),
    ("redmond", "WA 0% state, keep ~69%"),
    ("dc", "DC/VA ~5.3-5.8% state, keep ~63%"),
    ("washington, d", "DC/VA ~5.3-5.8% state, keep ~63%"),
    ("virginia", "DC/VA ~5.3-5.8% state, keep ~63%"),
    ("reston", "DC/VA ~5.3-5.8% state, keep ~63%"),
    ("arlington", "DC/VA ~5.3-5.8% state, keep ~63%"),
    ("austin", "TX 0% state, keep ~69%"),
    ("texas", "TX 0% state, keep ~69%"),
    ("sf", "CA ~9-11% state, keep ~60%"),
    ("ca", "CA ~9-11% state, keep ~60%"),
    ("california", "CA ~9-11% state, keep ~60%"),
    ("san francisco", "CA ~9-11% state, keep ~60%"),
    ("sunnyvale", "CA ~9-11% state, keep ~60%"),
    ("san mateo", "CA ~9-11% state, keep ~60%"),
    ("santa clara", "CA ~9-11% state, keep ~60%"),
    ("san jose", "CA ~9-11% state, keep ~60%"),
    ("new york", "NY ~10% state and city, keep ~60%"),
    ("nyc", "NY ~10% state and city, keep ~60%"),
)


def geo_note(text):
    """Return the tax context lines a location string implies, deduped and ordered."""
    lowered = (text or "").lower()
    out = []
    for needle, note in GEO_NOTES:
        if needle in lowered and note not in out:
            out.append(note)
    return out[:2]


# --------------------------------------------------------------------------
# Applying: gates and settings used by apply.py
# --------------------------------------------------------------------------

ELIGIBILITY_BARS = ("u.s. citizen", "us citizen", "citizenship required",
                    "must be a citizen", "must be a u.s. citizen",
                    "security clearance", "active clearance", "ts/sci", "sci ")

ELIGIBILITY_FLAGS = (
    ("fedramp", "FedRAMP is not itself a citizenship rule. Most offerings require a US Person, "
                "which an LPR satisfies, but some agencies and DoD impact levels require a "
                "citizen. Ask before investing in the loop."),
    ("public trust", "Public Trust is usually a citizenship requirement in practice, though some "
                     "contractor positions accept an LPR. Treat as a real question."),
    ("itar", "An LPR is a US Person under ITAR. Not a bar."),
    ("export control", "An LPR is a US Person under the EAR. Not a bar."),
    ("us person", "An LPR is a US Person. Not a bar."),
    ("u.s. person", "An LPR is a US Person. Not a bar."),
    ("no sponsorship", "No sponsorship needed. Not a bar."),
    ("green card holder only", "Satisfied. Not a bar."),
)

# Your home metro, lower case. Used to tell an onsite role you can take from one
# that would need a move. Leave empty if you are location agnostic.
HOME_METRO = ()
# Matched against the location field. A bare "remote" anywhere in the body is not
# evidence: a Fastly req listing Denver, New York and San Francisco was classified
# remote because the word appears in its benefits copy.
REMOTE_TERMS = ("remote", "distributed", "work from anywhere")
# Matched against the body, where only an explicit statement counts.
REMOTE_PHRASES = ("fully remote", "us remote", "remote within the us", "u.s. remote",
                  "remote-first", "work from anywhere in the us")
ONSITE_TERMS = ("from the office full time", "onsite full time", "in office five days",
                "fully onsite", "on-site full time", "4 days a week in office",
                "5 days a week in office")
RELOCATION_BARS = ("relocate on their own", "relocation is not provided",
                   "no relocation assistance", "relocation not offered",
                   "at their own expense", "must be local to")

REMOTE_TERMS = ("remote", "distributed", "work from anywhere")
# Matched against the body, where only an explicit statement counts.
REMOTE_PHRASES = ("fully remote", "us remote", "remote within the us", "u.s. remote",
                  "remote-first", "work from anywhere in the us")
ONSITE_TERMS = ("from the office full time", "onsite full time", "in office five days",
                "fully onsite", "on-site full time", "4 days a week in office",
                "5 days a week in office")
RELOCATION_BARS = ("relocate on their own", "relocation is not provided",
                   "no relocation assistance", "relocation not offered",
                   "at their own expense", "must be local to")

REMOTE_PHRASES = ("fully remote", "us remote", "remote within the us", "u.s. remote",
                  "remote-first", "work from anywhere in the us")
ONSITE_TERMS = ("from the office full time", "onsite full time", "in office five days",
                "fully onsite", "on-site full time", "4 days a week in office",
                "5 days a week in office")
RELOCATION_BARS = ("relocate on their own", "relocation is not provided",
                   "no relocation assistance", "relocation not offered",
                   "at their own expense", "must be local to")

ONSITE_TERMS = ("from the office full time", "onsite full time", "in office five days",
                "fully onsite", "on-site full time", "4 days a week in office",
                "5 days a week in office")
RELOCATION_BARS = ("relocate on their own", "relocation is not provided",
                   "no relocation assistance", "relocation not offered",
                   "at their own expense", "must be local to")

RELOCATION_BARS = ("relocate on their own", "relocation is not provided",
                   "no relocation assistance", "relocation not offered",
                   "at their own expense", "must be local to")

URGENCY_TERMS = ("immediate", "immediately", "asap", "as soon as possible", "urgently",
                 "urgent need", "backfill", "start right away", "hit the ground running")

JUNIOR_TERMS = ("junior", "jr.", "associate", "new grad", "graduate", "entry level",
                "intern", "apprentice", "engineer i", "engineer ii", "level 1", "tier 1")

EQUITY_TERMS = ("equity", "rsu", "restricted stock", "stock option", "stock grant",
                "long-term incentive", "lti")
BASE_FLOOR = 250000

BASE_FLOOR = 250000

FIXED_GAPS = (
    ("reverse engineering", "ghidra", "ida pro", "ida ", "disassembl", "stripped binar",
     "malware analysis", "binary analysis of"),
    ("Binary reverse engineering is a real gap: no Ghidra, IDA, or stripped multi-arch "
     "binary work. The vantage point is network and C2 telemetry instead, which answers "
     "many of the same questions from a different angle."),
)
SDE_TELL = (
    ("golang", " go ", "c++", "rust", "java ", "kafka", "spark", "flink", "scala"),
    ("The posting demands a compiled language or a streaming stack with a year count, "
     "which usually means an SDE seat wearing security vocabulary. Read the day-to-day "
     "before investing."),
)

SDE_TELL = (
    ("golang", " go ", "c++", "rust", "java ", "kafka", "spark", "flink", "scala"),
    ("The posting demands a compiled language or a streaming stack with a year count, "
     "which usually means an SDE seat wearing security vocabulary. Read the day-to-day "
     "before investing."),
)

FIXED_TITLE = "Senior Security Engineer"

# Companies where a referral is worth more than a portal submission. A req here
# still gets a full packet; it is just marked as needing a warm introduction.
NEVER_AUTO = ()
