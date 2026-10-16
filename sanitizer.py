#!/usr/bin/env python3
"""Fail-closed sanitizer for JobWatch public and shared output.

`sanitize(record)` returns a new record, or raises SanitizerBlocked and
returns nothing. Any unexpected condition is a block: unknown keys, wrong
types, invalid JSON, leftover PII or secrets after redaction, a deny-pass
hit, or an internal exception.

Application records are not public output. Do not pass them to sanitize.
Extra keys on an application (interview_style, dated notes, recruiter
mail) must never reach this module, or they would fail closed and stall
the published board. render_site.py ignores applications.json entirely.

Allowlist
---------
Built from the records the public page is allowed to emit. Extra keys are
refused. Missing keys are allowed.

`name` is an exact match against the known company list (sample
corpus plus `jobwatch.BOARDS`). `label` is a closed enum from
taxonomy. `relationship`, `move`, and `pay_note` are enums.
Application fields are not here: status (as an application state),
note, last_contact, match, why, relationship_note, rel_note, resume.

State file (`jobwatch_state.json`):

    version                 int
    last_run                str | None
    boards                  map of board-slug -> board record
    jobs                    map of job-id -> job record

Job record:

    id, board, company, title, location, url    str
    terms, flags, skills                        list[str]
    pay_low, pay_high                           int | None
    jd_seen                                     bool
    first_seen, last_seen                       str

Board stats record:

    company, platform                           str
    status                                      board enum: ok | failed
    live, matches                               int | None
    dropped_non_us, locations_resolved          int
    with_posted_band, with_jd                   int

Organization record (public projection only):

    name                                        company name
    board, industry, sector, arch, fit          str | None
    team, locations, careers                    str
    relationship, relationship_url              str
    traffic, warm_channel, open_now             bool
    comp                                        nested compensation record

Compensation record:

    levels_company                              company name
    tier, confidence, level_confidence          str
    level_source                                str | None
    target_level, amazon_equiv                  str | None
    median_total                                int | None

Dismissed file:

    dismissed                                   list[str]  (job ids)

Rendered job row: job fields plus tier, sde, place, since, competency,
pay, and no application status or resume variant.

Rendered org card: public org fields plus industry_label, arch_label,
fit_label (enum labels), warm, rel_url, polled, gauge, geo, scanned,
board_status, median, median_conf, pay_note, pay_tier, level_conf,
move, reqs. No why, no rel_note.

Gauge: bar (str), label (enum), rank (int)
"""

from __future__ import annotations

import base64
import html as html_lib
import json
import os
import re
import unicodedata
from urllib.parse import unquote, urlparse, urlunparse

import taxonomy as tx
from taxonomy import (
    ARCH_LABELS,
    COMPETENCIES,
    FALLBACK_COMPETENCY,
    FIT_GAUGE,
    FIT_LABELS,
    INDUSTRY_LABELS,
    LEVEL_MOVE_LABELS,
    known_companies,
    MOVE_ENUM,
    PAY_NOTE_ENUM,
    RELATIONSHIP_ENUM,
    RESUMES,
    SECTOR_LABELS,
    SKILL_BANDS,
    SKILLS,
    STATUS_META,
    TIER_META,
)


class SanitizerBlocked(Exception):
    """Public output is refused. Callers must emit nothing."""


# --------------------------------------------------------------------------
# Allowlist. Keys and the types they may hold. See module docstring.
# --------------------------------------------------------------------------

_STR = "str"
_STR_OR_NONE = "str?"
_INT = "int"
_INT_OR_NONE = "int?"
_BOOL = "bool"
_STR_LIST = "str[]"
_PAY = "pay"
_RECORD = "record"
_RECORD_OR_NONE = "record?"
_RECORD_LIST = "record[]"
_RECORD_MAP = "record{}"
_COMPANY = "company"
_LABEL = "label"
_BOARD_STATUS = "board_status"
_RELATIONSHIP = "relationship"
_MOVE = "move"
_PAY_NOTE = "pay_note"
_URL = "url"

KEY_TYPES = {
    # state
    "version": _INT,
    "last_run": _STR_OR_NONE,
    "boards": _RECORD_MAP,
    "jobs": _RECORD_MAP,
    # job
    "id": _STR,
    "board": _STR,
    "company": _COMPANY,
    "title": _STR,
    "location": _STR,
    "url": _URL,
    "terms": _STR_LIST,
    "flags": _STR_LIST,
    "pay_low": _INT_OR_NONE,
    "pay_high": _INT_OR_NONE,
    "skills": _STR_LIST,
    "jd_seen": _BOOL,
    "first_seen": _STR,
    "last_seen": _STR,
    # board stats — status here is ok/failed, never an application state
    "platform": _STR,
    "live": _INT_OR_NONE,
    "matches": _INT_OR_NONE,
    "dropped_non_us": _INT,
    "locations_resolved": _INT,
    "with_posted_band": _INT,
    "with_jd": _INT,
    "status": _BOARD_STATUS,
    # organizations (public projection)
    "updated": _STR,
    "organizations": _RECORD_LIST,
    "name": _COMPANY,
    "industry": _STR_OR_NONE,
    "sector": _STR_OR_NONE,
    "arch": _STR_OR_NONE,
    "fit": _STR_OR_NONE,
    "traffic": _BOOL,
    "warm_channel": _BOOL,
    "open_now": _BOOL,
    "team": _STR,
    "locations": _STR,
    "careers": _URL,
    "comp": _RECORD,
    "relationship": _RELATIONSHIP,
    "relationship_url": _URL,
    # compensation
    "levels_company": _COMPANY,
    "median_total": _INT_OR_NONE,
    "target_level": _STR_OR_NONE,
    "amazon_equiv": _STR_OR_NONE,
    "level_source": _STR_OR_NONE,
    "level_confidence": _STR,
    "tier": _STR,
    "confidence": _STR,
    # dismissed
    "dismissed": _STR_LIST,
    # rendered job row
    "sde": _BOOL,
    "place": _STR,
    "since": _STR,
    "competency": _STR,
    "pay": _PAY,
    # rendered org
    "industry_label": _LABEL,
    "arch_label": _LABEL,
    "fit_label": _LABEL,
    "warm": _BOOL,
    "rel_url": _URL,
    "polled": _BOOL,
    "gauge": _RECORD_OR_NONE,
    "geo": _STR_LIST,
    "scanned": _INT_OR_NONE,
    "board_status": _BOARD_STATUS,
    "median": _INT_OR_NONE,
    "median_conf": _STR,
    "pay_note": _PAY_NOTE,
    "pay_tier": _STR,
    "level_conf": _STR,
    "move": _MOVE,
    "reqs": _RECORD_LIST,
    # gauge / enum label
    "bar": _STR,
    "label": _LABEL,
    "rank": _INT,
}

ALLOWED_KEYS = frozenset(KEY_TYPES)

# Keys that used to be published and must never appear on a public record.
PRIVATE_KEYS = frozenset({
    "note", "last_contact", "match", "why", "relationship_note", "rel_note",
    "resume", "applications", "interview_style",
})

BOARD_STATUS_ENUM = frozenset({"ok", "failed", None})


def _build_label_enum():
    labels = {
        "",
        "unclassified",
        "Lead with",
        "Proven, table stakes",
        "Gaps to name",
        "Unknown",
    }
    for meta in (TIER_META, STATUS_META, FIT_GAUGE):
        for row in meta.values():
            if isinstance(row, dict) and row.get("label"):
                labels.add(row["label"])
    for mapping in (SECTOR_LABELS, INDUSTRY_LABELS, ARCH_LABELS, FIT_LABELS,
                    LEVEL_MOVE_LABELS):
        labels.update(mapping.values())
    for competency in list(COMPETENCIES) + [FALLBACK_COMPETENCY]:
        labels.add(competency["label"])
    for resume in RESUMES.values():
        labels.add(resume["label"])
    for skill in SKILLS:
        labels.add(skill["label"])
    for _key, band_label in SKILL_BANDS:
        labels.add(band_label)
    return frozenset(labels)


LABEL_ENUM = _build_label_enum()

APPLICANT_NAMES = []
APPLICANT_ADDRESSES = []
APPLICANT_PROFILE_URLS = []

REDACTED = "[REDACTED]"

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_PATH = os.path.join(HERE, "applicant_profile.json")


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\b"
)

PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]*)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[\s.-]\d{3}[\s.-]\d{4}(?!\d)"
)

LINKEDIN_RE = re.compile(
    r"https?://(?:[\w-]+\.)?linkedin\.com/(?:in|pub|mwlite/in)/[A-Za-z0-9_\-%/]+",
    re.IGNORECASE,
)

PROFILE_URL_RE = re.compile(
    r"https?://(?:www\.)?(?:"
    r"linkedin\.com/(?:in|pub|mwlite/in)/[A-Za-z0-9_\-%/]+"
    r"|github\.com/[A-Za-z0-9\-]+/?"
    r"|gitlab\.com/[A-Za-z0-9\-]+/?"
    r"|twitter\.com/[A-Za-z0-9_]+/?"
    r"|x\.com/[A-Za-z0-9_]+/?"
    r"|facebook\.com/[A-Za-z0-9.]+/?"
    r"|about\.me/[A-Za-z0-9.\-]+/?"
    r")(?![A-Za-z0-9._\-/])",
    re.IGNORECASE,
)

ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+"
    r"[A-Z][A-Za-z0-9.'\-]+(?:\s+[A-Z][A-Za-z0-9.'\-]+){0,4}\s+"
    r"(?:Street|Avenue|Road|Drive|Lane|Boulevard|Court|Circle|Place|"
    r"St\.|Ave\.|Rd\.|Dr\.|Ln\.|Blvd\.|Ct\.|Pl\.|"
    r"(?:St|Ave|Rd|Dr|Ln|Blvd|Ct|Pl)(?=\s*,|\s*$))"
    r"(?:\s+(?:Apt|Apartment|Suite|Unit|#)\s*[A-Za-z0-9\-]+)?"
    r"(?:\s*,\s*[A-Z][A-Za-z .\-]+(?:\s*,\s*[A-Z]{2}(?:\s+\d{5}(?:-\d{4})?)?)?)?"
)

LABELED_NAME_RE = re.compile(
    r"\b(?:name|applicant|candidate|recruiter)\s*[:\-\u2013\u2014]\s*"
    r"([^\s].{0,80})",
    re.IGNORECASE,
)

# Jane—Doe / Ada–Lovelace: em/en dash used to hide a person name.
EMDASH_NAME_RE = re.compile(
    r"\b[A-Za-z][A-Za-z]{1,20}[\u2013\u2014][A-Za-z][A-Za-z]{1,20}\b"
)

MAILTO_RE = re.compile(r"mailto\s*:", re.IGNORECASE)

# Stage / outcome words. A title prefix is not a stage (Offer Management,
# Interviewing Platform, Applied Scientist). Onsite / On-site is a work-mode
# label when it stands alone after a dash or parens, or leads a location
# ("Software Engineer - Onsite", "Software Engineer (Onsite)",
# "Onsite - Austin, TX"). It is a stage when it comes with a date, weekday,
# person, 'w/', another stage word, or a non-work-mode separator
# (pipe, brackets, middot, emoji): "onsite Tue", "onsite w/ Jane",
# "SWE 📅 onsite".
_STATUS_WORDS = frozenset({
    "applied", "interview", "interviewing", "offer", "screen", "screening",
    "rejected", "ghosted", "declined", "waitlisted", "withdrew", "withdrawn",
})
_ONSITE_WORDS = frozenset({"onsite", "on-site", "on site"})
_DAY_WORDS = frozenset({
    "mon", "tue", "tues", "wed", "thu", "thur", "thurs", "fri", "sat", "sun",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
})
_WHEN_WORDS = frozenset({"tmrw", "tomorrow", "today", "next"})
_STATUS_ABBREV = frozenset({"oa", "hm"})
_OFFICE_EMOJI = "\U0001F3E2"
_STATUS_EMOJI_RE = re.compile("[\u2705\u274C\U0001F389\U0001F4C5]")
_GIVEN_NAMES = frozenset({
    "ada", "alex", "anna", "daniel", "david", "emily", "james", "jane",
    "john", "laura", "mary", "michael", "rachel", "robert", "sarah",
})
_WORKMODE_SEPS = frozenset({"-", "\u2013", "\u2014", "(", ")"})
_STATUS_SEPS = frozenset({"(", ")", "[", "]", "|", "·", "•", "/"})
_DATE_RE = re.compile(r"^\d{1,2}/\d{1,2}(?:/\d{2,4})?$")
_PHRASE_ALWAYS_RE = re.compile(
    r"(?i)(?:"
    r"\bapplication\s+stage\b"
    r"|\bgot\s+offer\b"
    r"|\boffer!"
    r"|\b(?:oa|hm)\b"
    r"|\b(?:applied|interview|interviewing|offer|screen(?:ing)?)\s*:"
    r"|\b(?:rejected|ghosted|declined|waitlisted|withdrew|withdrawn)\b"
    r"|\b(?:ref'd|referred)\s+by\b"
    r"|\bphone\s+screen\b(?:\s+(?:mon|tue|tues|wed|thu|thur|thurs|fri|sat|sun|"
    r"monday|tuesday|wednesday|thursday|friday|saturday|sunday|"
    r"\d{1,2}/\d{1,2}(?:/\d{2,4})?|done|with|scheduled|w/))"
    r"|\(\s*phone\s+screen\b"
    r")"
)
_WALK_RE = re.compile(
    r"(?i)(final\s+round|take-?home|phone\s+screen|on-site|on\s+site|got\s+offer|w/|"
    r"[A-Za-z][A-Za-z']*|\d{1,2}/\d{1,2}(?:/\d{2,4})?|"
    r"[\U0001F300-\U0001FAFF\u2300-\u27BF\u2600-\u26FF]|"
    r"[()\[\]|·•:!\-\u2013\u2014])"
)

# Mine/Kanban only in a board context, not "Mine Safety" / "Kanban Tools Engineer".
BOARD_NAME_RE = re.compile(
    r"(?i)(?:\b(?:the|open|sync|view|check)\s+(?:the\s+)?(?:mine|kanban)\b"
    r"|\b(?:mine|kanban)\s+board\b)"
)

PERSON_TWO_WORD_RE = re.compile(
    r"\b([A-Z][a-z]{2,})\s+([A-Z][a-z]{2,})\b"
)

WITH_PERSON_RE = re.compile(
    r"(?i)(?:\bw/\s+[A-Za-z]{3,}\b|\bwith\s+(?:ada|alex|anna|daniel|david|emily|james|jane|john|laura|mary|michael|rachel|robert|sarah)\b)"
)

PATH_NAME_RE = re.compile(
    r"(?i)/([a-z]{3,})-([a-z]{3,})(?:-([a-z]+))?"
)

# Role / org / place words. A two-word phrase using one of these is not a person.
_ROLE_OR_ORG_WORDS = frozenset({
    "abuse", "adjacent", "ai", "analyst", "applied", "cloud", "core",
    "detection", "ddos", "edge", "engineer", "engineering", "enterprise",
    "filter", "hunting", "incident", "industries", "infra", "integrity",
    "intel", "investigator", "kanban", "lab", "labs", "lead", "mandate",
    "media", "mine", "mitigation", "network", "networks", "officer",
    "operations", "perimeter", "platform", "principal", "protection",
    "reliability", "remote", "research", "researcher", "response", "safety",
    "science", "scientist", "screening", "security", "senior", "sirt",
    "software", "staff", "support", "systems", "team", "threat", "tools",
    "traffic", "waf",
})

BLOCKED_SCHEMES_RE = re.compile(
    r"(?i)(?:^|[\s\"'=])(?:javascript|data|vbscript|file|blob|ftp|mailto):"
)

HTTP_SCHEME_RE = re.compile(r"(?i)(?:^|[\s\"'=])http://")

PUNYCODE_HOST_RE = re.compile(r"(?i)(?:https://|//)[^/\s\"']*xn--")

NON_ASCII_HOST_RE = re.compile(r"https://[^/\s\"']*[^\x00-\x7F]")

B64_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{12,}={0,2})(?![A-Za-z0-9_=-])"
)

UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

UUID_SHAPE_RE = re.compile(
    r"(?i)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
)

HEX_ID_RE = re.compile(r"(?i)^[0-9a-f]+$")

HEX_RUN_RE = re.compile(r"(?i)[0-9a-f]{16,}")

CAMEL_RE = re.compile(
    r"^(?:"
    r"[a-z]+(?:[A-Z][a-z]+)+[A-Z]?"
    r"|[a-z]+(?:[A-Z]{2,}(?=[A-Z][a-z]|$)|[A-Z][a-z]+)+"
    r"|[A-Z][a-z]+(?:[A-Z][a-z]+)+"
    r")$"
)

SLUG_RE = re.compile(r"^[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)+$")

ATS_HOST_SUFFIXES = (
    ".greenhouse.io",
    ".ashbyhq.com",
    ".lever.co",
    ".myworkdayjobs.com",
    ".workday.com",
)

URL_KEYS = frozenset({"url", "careers", "relationship_url", "rel_url"})

RESUME_FILE_RE = re.compile(
    r"(?i)(?:"
    r"\b[a-z][a-z0-9]*[_-][a-z][a-z0-9]*[_-]resume(?:[_-]v?\d+)?"
    r"|\b[\w.-]*(?:resume|cv)[\w.-]*\.(?:txt|pdf|docx|doc)"
    r")"
)

SPLIT_EMAIL_RE = re.compile(
    r"""['"]\s*\+\s*['"]\s*@\s*['"]\s*\+\s*['"]"""
)

AT_DOT_RE = re.compile(
    r"(?i)\b[a-z0-9._%+\-]+\s*(?:\[at\]|\(at\))\s*[a-z0-9.\-]+\s*(?:\[dot\]|\(dot\))\s*[a-z]{2,}\b"
)

COMMENT_SPLIT_RE = re.compile(
    r"[A-Za-z0-9](?:/\*.*?\*/|<!--.*?-->)[A-Za-z0-9]",
    re.DOTALL,
)

UNCLOSED_BLOCK_COMMENT_RE = re.compile(r"/\*(?:(?!\*/).)*$", re.DOTALL)

UNCLOSED_SCRIPT_RE = re.compile(
    r"(?is)<script\b[^>]*>(?:(?!</script>).)*$"
)

JS_BRACKET_KEY_RE = re.compile(
    r"""\[\s*['"](notes?|email|phone|name|profile|applied|resume)['"]\s*\]""",
    re.IGNORECASE,
)

DATASET_RE = re.compile(
    r"""dataset(?:\.[A-Za-z_]\w*|\[\s*['"][^'"]+['"]\s*\])""",
    re.IGNORECASE,
)

DATA_ATTR_RE = re.compile(
    r"""\bdata-[a-z0-9_-]+\b""",
    re.IGNORECASE,
)

SENSITIVE_ATTRS = frozenset({
    "note", "notes", "email", "phone", "name", "profile", "applied", "resume",
    "last_contact", "match", "why", "relationship_note", "rel_note",
    "applications", "interview_style",
})

SECRET_RES = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(
        r"(?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)"
        r"\s*[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/\+_\-]{16,}",
        re.IGNORECASE,
    ),
)

_DETECTORS = (
    ("email", EMAIL_RE),
    ("phone", PHONE_RE),
    ("linkedin", LINKEDIN_RE),
    ("profile_url", PROFILE_URL_RE),
    ("address", ADDRESS_RE),
    ("labeled_name", LABELED_NAME_RE),
    ("emdash_name", EMDASH_NAME_RE),
    ("mailto", MAILTO_RE),
)

# Cyrillic / Greek / fullwidth lookalikes that survive a naive regex.
_HOMOGLYPHS = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u04bb": "h", "\u0501": "d", "\u0391": "A", "\u0395": "E",
    "\u039f": "O", "\u03bf": "o", "\u03b1": "a", "\u03b5": "e",
    "\u043c": "m", "\u041c": "M", "\u043a": "k", "\u043d": "n",
    "\u0432": "b", "\u044c": "b",
    "\uff20": "@", "\uff0e": ".", "\u2024": ".",
    "\u00a0": " ",
})

ORGS_PATH = os.path.join(HERE, "organizations.json")
STATE_PATH = os.path.join(HERE, "jobwatch_state.json")


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _profile_literals():
    names = [n for n in APPLICANT_NAMES if n]
    addresses = [a for a in APPLICANT_ADDRESSES if a]
    urls = [u for u in APPLICANT_PROFILE_URLS if u]
    env = os.environ.get("JOBWATCH_APPLICANT_NAMES", "").strip()
    if env:
        names.extend(part.strip() for part in env.split(",") if part.strip())
    if os.path.exists(PROFILE_PATH):
        with open(PROFILE_PATH, encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise SanitizerBlocked("applicant profile is not a dict")
        names.extend(data.get("names") or [])
        addresses.extend(data.get("addresses") or [])
        urls.extend(data.get("profile_urls") or [])
    out = []
    for item in names + addresses + urls:
        if not isinstance(item, str) or not item.strip():
            raise SanitizerBlocked("applicant profile values must be strings")
        out.append(item.strip())
    out.sort(key=len, reverse=True)
    return out


def _known_companies():
    """Sample corpus plus live board companies from jobwatch.BOARDS.

    organizations.json cannot add a name. Adding a board (e.g. Stripe)
    publishes that company without a second hardcoded list.
    """
    return known_companies()


def _strip_format_chars(text):
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def _strip_comments(text):
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"/\*.*$", "", text, flags=re.DOTALL)
    text = re.sub(r"(?m)//.*?$", "", text)
    return text


def _decode_entities(text):
    prev = None
    for _ in range(8):
        if text == prev:
            break
        prev = text
        text = html_lib.unescape(text)
    return text


def _decode_js_escapes(text):
    def uni(match):
        return chr(int(match.group(1), 16))
    def hx(match):
        return chr(int(match.group(1), 16))
    prev = None
    for _ in range(6):
        if text == prev:
            break
        prev = text
        if "\\\\" in text:
            text = text.replace("\\\\", "\\")
        text = re.sub(r"\\u([0-9a-fA-F]{4})", uni, text)
        text = re.sub(r"\\x([0-9a-fA-F]{2})", hx, text)
    return text


def _decode_percent(text):
    prev = None
    for _ in range(4):
        if text == prev:
            break
        prev = text
        text = unquote(text)
    return text


def _collapse_js_concat(text):
    return re.sub(r"""['"]\s*\+\s*['"]""", "", text)


def _deny_normalize(text):
    """Case-fold, NFKC, strip Cf, map homoglyphs, decode, strip comments."""
    if not text:
        return ""
    folded = unicodedata.normalize("NFKC", text)
    folded = _strip_format_chars(folded)
    folded = _decode_js_escapes(folded)
    folded = _decode_percent(folded)
    folded = _decode_entities(folded)
    folded = _collapse_js_concat(folded)
    folded = folded.translate(_HOMOGLYPHS)
    folded = _strip_comments(folded)
    folded = unicodedata.normalize("NFKC", folded).casefold()
    folded = _strip_format_chars(folded)
    folded = folded.translate(_HOMOGLYPHS)
    return folded


def _script_bodies(text):
    bodies = []
    for match in re.finditer(
        r"<script\b[^>]*>(.*?)</script>", text, flags=re.DOTALL | re.IGNORECASE
    ):
        body = match.group(1).strip()
        if body:
            bodies.append(body)
    trailing = re.search(
        r"(?is)<script\b[^>]*>(?![\s\S]*</script>)([\s\S]*)$", text
    )
    if trailing and trailing.group(1).strip():
        bodies.append(trailing.group(1).strip())
    return bodies


def _json_values(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key
            yield from _json_values(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _json_values(item)
    elif isinstance(obj, str):
        yield obj


def _script_json_blocked(body):
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if isinstance(parsed, dict):
        unknown = set(parsed) - ALLOWED_KEYS
        leaked = set(parsed) & PRIVATE_KEYS
        extra = unknown | leaked
        if extra:
            return "json_key"
        walk = [parsed]
        while walk:
            item = walk.pop()
            if isinstance(item, dict):
                extra = (set(item) - ALLOWED_KEYS) | (set(item) & PRIVATE_KEYS)
                if extra:
                    return "json_key"
                walk.extend(item.values())
            elif isinstance(item, list):
                walk.extend(item)
    return None


def _looks_like_person_name(text):
    if WITH_PERSON_RE.search(text):
        return True
    known_fold = {name.casefold() for name in _known_companies()}
    for match in PERSON_TWO_WORD_RE.finditer(text):
        full = match.group(0)
        if full.casefold() in known_fold:
            continue
        left, right = match.group(1).casefold(), match.group(2).casefold()
        if left not in _GIVEN_NAMES:
            continue
        if right in _ROLE_OR_ORG_WORDS:
            continue
        return True
    return False


def _path_has_person(path):
    """Hyphenated path tokens are a person only when a given name is present.

    `/jobs/1/jane-roe-referral` is blocked. `/fonts-jobwatch` and
    `/ddos-mitigation` are not.
    """
    for match in PATH_NAME_RE.finditer(path or ""):
        tokens = [part.casefold() for part in match.groups() if part]
        if any(token in _GIVEN_NAMES for token in tokens):
            return True
    return False


def _is_emoji(ch):
    if not ch or len(ch) != 1:
        return False
    code = ord(ch)
    return (
        0x1F300 <= code <= 0x1FAFF
        or 0x2300 <= code <= 0x27BF
        or 0x2600 <= code <= 0x26FF
    )


def _is_status_follower(token):
    folded = (token or "").casefold()
    if not folded:
        return False
    if _DATE_RE.match(folded) or folded in _DAY_WORDS:
        return True
    if folded in {"w/", "with"} or folded in _GIVEN_NAMES:
        return True
    if folded in _STATUS_WORDS or folded in _ONSITE_WORDS:
        return True
    if folded in _STATUS_ABBREV:
        return True
    if folded in {"final", "take-home", "takehome"}:
        return True
    return False


def _onsite_in(text):
    folded = (text or "").casefold()
    return bool(re.search(r"(?i)\bon[\s-]?site\b", folded))


def _application_status_hit(text):
    """True when a stage/outcome word appears in a status context."""
    if not text:
        return False
    if _PHRASE_ALWAYS_RE.search(text):
        return True
    if _onsite_in(text) and _OFFICE_EMOJI in text:
        return True
    tokens = _WALK_RE.findall(text)
    for index, raw in enumerate(tokens):
        folded = raw.casefold()
        nxt = tokens[index + 1].casefold() if index + 1 < len(tokens) else ""
        nxt_raw = tokens[index + 1] if index + 1 < len(tokens) else ""
        prev = tokens[index - 1] if index else ""
        prev_fold = prev.casefold()
        is_onsite = folded in _ONSITE_WORDS
        is_status = folded in _STATUS_WORDS or folded in _STATUS_ABBREV or folded in {
            "final round", "take-home", "take home", "phone screen", "got offer",
        }
        if not is_onsite and not is_status:
            continue
        if _is_status_follower(nxt) or nxt == "w/":
            return True
        if prev_fold == "w/":
            return True
        if nxt in {":", "!"}:
            return True
        if prev and _is_emoji(prev):
            return True
        if nxt_raw and _is_emoji(nxt_raw):
            return True
        if prev in _STATUS_SEPS and not (is_onsite and prev in _WORKMODE_SEPS):
            return True
        if is_status and prev in _WORKMODE_SEPS:
            return True
        if is_onsite:
            if nxt in _WHEN_WORDS or prev_fold in _WHEN_WORDS:
                return True
            if nxt in _DAY_WORDS or prev_fold in _DAY_WORDS:
                return True
            if nxt == _OFFICE_EMOJI or prev == _OFFICE_EMOJI:
                return True
            if nxt in {"(", "["}:
                after = tokens[index + 2].casefold() if index + 2 < len(tokens) else ""
                if after in _DAY_WORDS or after in _WHEN_WORDS:
                    return True
        if is_status and folded == raw.casefold() and index == 0 and len(tokens) == 1:
            return True
    return False


def _path_has_stage(path):
    if _application_status_hit(path or ""):
        return True
    for segment in (path or "").split("/"):
        folded = segment.casefold().strip()
        if folded in _STATUS_WORDS or folded in {
            "final-round", "take-home", "takehome", "waitlisted",
        }:
            return True
    return False


def _field_tokens(text):
    return [tok.casefold() for tok in re.findall(r"[A-Za-z][A-Za-z0-9'./-]*", text or "")]


# USPS abbreviations and a few sample-corpus cities that taxonomy.US names
# only via longer phrases (Portland is in the sample orgs; CO/OR/MA/IL are
# the state tags next to Denver/Portland/Boston/Chicago).
_USPS_STATES = frozenset({
    "al", "ak", "az", "ar", "ca", "co", "ct", "dc", "de", "fl", "ga",
    "hi", "ia", "id", "il", "in", "ks", "ky", "la", "ma", "md", "me",
    "mi", "mn", "mo", "ms", "mt", "nc", "nd", "ne", "nh", "nj", "nm",
    "nv", "ny", "oh", "ok", "or", "pa", "ri", "sc", "sd", "tn", "tx",
    "ut", "va", "vt", "wa", "wi", "wv", "wy", "usa", "us",
})
_FIELD_CONNECTORS = frozenset({
    "and", "or", "of", "the", "a", "an", "for", "to", "in", "at",
})
_FIELD_VOCAB_EXTRAS = frozenset({
    "portland", "defense", "reporting", "sinkholing",
})


def _add_vocab_tokens(bucket, text):
    if not isinstance(text, str) or not text:
        return
    for tok in re.findall(r"[A-Za-z][A-Za-z0-9'./-]*", text):
        folded = tok.casefold()
        if not folded:
            continue
        bucket.add(folded)
        if "-" in folded:
            for part in folded.split("-"):
                if part:
                    bucket.add(part)
        if folded == "defence":
            bucket.add("defense")


def _walk_vocab(obj, bucket, depth=0):
    if depth > 8:
        return
    if isinstance(obj, str):
        _add_vocab_tokens(bucket, obj)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                _add_vocab_tokens(bucket, key)
            _walk_vocab(value, bucket, depth + 1)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            _walk_vocab(item, bucket, depth + 1)


def _field_allowlist():
    """Team/locations tokens: BOARDS + taxonomy + city names. Anything else blocks."""
    bucket = set(_USPS_STATES)
    bucket.update(_FIELD_CONNECTORS)
    bucket.update(_FIELD_VOCAB_EXTRAS)
    import jobwatch
    _walk_vocab(jobwatch.BOARDS, bucket)
    for name in dir(tx):
        if name.startswith("_"):
            continue
        value = getattr(tx, name)
        if callable(value):
            continue
        _walk_vocab(value, bucket)
    return frozenset(bucket)


def _normalize_onsite_spacing(text):
    return re.sub(r"(?i)\bon\s+site\b", "onsite", text or "")


def _field_vocab_blocked(key, value):
    """Team/locations is an allowlist. Tokens must come from boards/taxonomy/cities."""
    if not isinstance(value, str) or not value:
        return False
    tokens = _field_tokens(_normalize_onsite_spacing(value))
    if key == "team" and tokens == ["kanban"]:
        return True
    if key == "team" and tokens == ["mine"]:
        return True
    allowed = _field_allowlist()
    for token in tokens:
        if key in {"location", "locations"} and token in _ONSITE_WORDS:
            continue
        if key in {"location", "locations"} and token in {"location", "locations"}:
            continue
        if token not in allowed:
            return True
    return False


def _is_exempt_job_id(token):
    raw = (token or "").rstrip("=")
    if not raw:
        return True
    if raw.isdigit():
        return True
    if UUID_RE.match(raw):
        return True
    if HEX_ID_RE.match(raw) and len(raw) >= 8:
        return True
    return False


def _ats_hosts():
    hosts = {
        "boards.greenhouse.io",
        "job-boards.greenhouse.io",
        "jobs.ashbyhq.com",
        "jobs.lever.co",
    }
    import jobwatch
    for row in jobwatch.BOARDS:
        host = (row.get("host") or "").lower()
        domain = (row.get("domain") or "").lower()
        if host:
            hosts.add(host)
        if domain:
            hosts.add(domain)
    return hosts


def _is_ats_host(host):
    host = (host or "").lower()
    if host in _ats_hosts():
        return True
    return any(host.endswith(suffix) for suffix in ATS_HOST_SUFFIXES)


def _hex_decodes_printable(raw):
    if len(raw) < 16 or len(raw) % 2:
        return False
    try:
        decoded = bytes.fromhex(raw)
    except ValueError:
        return False
    return bool(decoded) and all(32 <= byte <= 126 for byte in decoded)


def _printable_hex_leak(text):
    if not text:
        return False
    compact = UUID_SHAPE_RE.sub(lambda match: match.group(0).replace("-", ""), text)
    for source in (text, compact):
        for match in HEX_RUN_RE.finditer(source):
            raw = match.group(0)
            if len(raw) % 2:
                raw = raw[:-1]
            for start in range(0, len(raw) - 15, 2):
                for end in range(start + 16, len(raw) + 1, 2):
                    if _hex_decodes_printable(raw[start:end]):
                        return True
    return False


def _b64_payload(token):
    raw = (token or "").strip()
    if len(raw) < 8:
        return ""
    try:
        alphabet = raw + "=" * (-len(raw) % 4)
        decoded = base64.b64decode(alphabet, altchars=b"-_", validate=False)
        return decoded.decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return ""


def _looks_like_b64(token, allow_id=False):
    if not token or len(token) < 12:
        return False
    if allow_id and _is_exempt_job_id(token):
        return False
    body = token.rstrip("=")
    if CAMEL_RE.match(body) or SLUG_RE.match(body):
        return False
    if re.fullmatch(r"[A-Za-z]+(?:-[A-Za-z]+)+", body):
        return False
    if token.isalpha() and (token.islower() or token.isupper() or token.istitle()):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_=-]+", token):
        return False
    payload = _b64_payload(token)
    interesting = bool(
        payload
        and (
            EMAIL_RE.search(payload)
            or ("@" in payload and payload.isprintable())
            or (
                len(payload) >= 6
                and payload.isprintable()
                and not payload.isidentifier()
            )
        )
    )
    if interesting:
        return True
    pad = len(token) - len(body)
    if pad:
        rem = len(body) % 4
        valid_pad = (rem == 2 and pad == 2) or (rem == 3 and pad == 1)
        if valid_pad and "-" not in body:
            return True
        return False
    if "+" in token:
        return True
    return False


def _b64_in_text(text, allow_id=False):
    if not text:
        return False
    for token in re.split(r"[/\s?#&=]+", text):
        cleaned = token.strip(".,;:()[]{}\"'")
        if _looks_like_b64(cleaned, allow_id=allow_id):
            return True
    for match in B64_TOKEN_RE.finditer(text):
        if _looks_like_b64(match.group(1), allow_id=allow_id):
            return True
    return False


def _host_is_blocked(host):
    host = (host or "").strip().lower()
    if not host:
        return True
    if "xn--" in host:
        return True
    if not host.isascii():
        return True
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return True
    return False


def _obfuscated_board_token(text):
    """Cyrillic / lookalike Mine or Kanban. Latin 'Mine Safety' is not this."""
    if not text:
        return False
    for token in re.findall(r"[^\s,;:/\\|]+", text):
        cleaned = token.strip("()[]{}<>.\"'")
        if not cleaned or cleaned.isascii():
            continue
        folded = _deny_normalize(cleaned)
        if folded in {"mine", "kanban"} or "mine" in folded or "kanban" in folded:
            return True
    return False


def _b64_email(value):
    raw = (value or "").strip()
    if len(raw) < 8:
        return False
    try:
        pad = "=" * (-len(raw) % 4)
        decoded = base64.b64decode(raw + pad, validate=False)
        text = decoded.decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return False
    return bool(EMAIL_RE.search(text))


def _query_has_blocked(query):
    if not query:
        return False
    decoded = _deny_normalize(query)
    if EMAIL_RE.search(query) or EMAIL_RE.search(decoded):
        return True
    if AT_DOT_RE.search(query) or AT_DOT_RE.search(decoded):
        return True
    for part in query.split("&"):
        _key, sep, val = part.partition("=")
        if not sep:
            val = part
        val = _decode_percent(val)
        if EMAIL_RE.search(val) or _b64_email(val) or _b64_in_text(val):
            return True
    if _b64_in_text(query) or _b64_in_text(decoded):
        return True
    return False


def _sanitize_url(value):
    if not isinstance(value, str) or not value:
        raise SanitizerBlocked("wrong type for url")
    decoded = _decode_percent(_decode_js_escapes(value.strip()))
    parsed = urlparse(decoded)
    scheme = (parsed.scheme or "").lower()
    if scheme != "https":
        raise SanitizerBlocked("url scheme is not https")
    if not parsed.netloc:
        raise SanitizerBlocked("url host is missing")
    host = parsed.hostname or parsed.netloc.split("@")[-1].split(":")[0]
    if _host_is_blocked(host) or _host_is_blocked(parsed.netloc.split("@")[-1].split(":")[0]):
        raise SanitizerBlocked("url host is not ascii")
    if _query_has_blocked(parsed.query) or _query_has_blocked(parsed.fragment):
        raise SanitizerBlocked("url query is blocked")
    if _path_has_person(parsed.path):
        raise SanitizerBlocked("url path has a person name")
    if _path_has_stage(parsed.path):
        raise SanitizerBlocked("url path has a stage word")
    if _printable_hex_leak(parsed.path):
        raise SanitizerBlocked("url path has encoded text")
    if _b64_in_text(parsed.path, allow_id=_is_ats_host(host)):
        raise SanitizerBlocked("url path has a base64 token")
    cleaned = urlunparse(("https", parsed.netloc, parsed.path, "", "", ""))
    leftover = _find_blocked(cleaned)
    if leftover:
        raise SanitizerBlocked("blocked url")
    return cleaned


def _find_blocked_plain(text):
    if not text:
        return None
    if _STATUS_EMOJI_RE.search(text):
        return "application"
    if EMAIL_RE.search(text):
        return "email"
    if PHONE_RE.search(text):
        return "phone"
    if LINKEDIN_RE.search(text):
        return "linkedin"
    if PROFILE_URL_RE.search(text):
        return "profile_url"
    if ADDRESS_RE.search(text):
        return "address"
    if LABELED_NAME_RE.search(text):
        return "name"
    if EMDASH_NAME_RE.search(text):
        return "name"
    if MAILTO_RE.search(text):
        return "mailto"
    if _application_status_hit(text):
        return "application"
    if _printable_hex_leak(text):
        return "hex"
    if RESUME_FILE_RE.search(text):
        return "resume_file"
    if SPLIT_EMAIL_RE.search(text):
        return "email"
    if AT_DOT_RE.search(text):
        return "email"
    if BOARD_NAME_RE.search(text):
        return "board_name"
    if COMMENT_SPLIT_RE.search(text):
        return "comment_split"
    if UNCLOSED_BLOCK_COMMENT_RE.search(text):
        return "unclosed_comment"
    if UNCLOSED_SCRIPT_RE.search(text):
        return "unclosed_script"
    if JS_BRACKET_KEY_RE.search(text):
        return "js_key"
    if DATASET_RE.search(text):
        return "dataset"
    if DATA_ATTR_RE.search(text):
        return "data_attr"
    if BLOCKED_SCHEMES_RE.search(text):
        return "scheme"
    if HTTP_SCHEME_RE.search(text):
        return "scheme"
    if PUNYCODE_HOST_RE.search(text) or NON_ASCII_HOST_RE.search(text):
        return "host"
    if _b64_in_text(text):
        return "base64"
    if _looks_like_person_name(text):
        return "name"
    if _path_has_person(text):
        return "name"
    for secret_re in SECRET_RES:
        if secret_re.search(text):
            return "secret"
    lowered = text.casefold()
    for literal in _profile_literals():
        if literal.casefold() in lowered:
            return "applicant_profile"
    return None


def _find_blocked(text):
    """Return a short reason if text still contains a blocked pattern."""
    if not text:
        return None
    if not isinstance(text, str):
        return "public text is not a string"
    if _obfuscated_board_token(text):
        return "board_name"
    hit = _find_blocked_plain(text)
    if hit:
        return hit
    normalized = _deny_normalize(text)
    hit = _find_blocked_plain(normalized)
    if hit:
        return hit
    if UNCLOSED_SCRIPT_RE.search(text):
        return "unclosed_script"
    for body in _script_bodies(text):
        if body == text:
            continue
        hit = _script_json_blocked(body)
        if hit:
            return hit
        stripped = body.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed = None
            if parsed is not None:
                hit = _script_json_blocked(stripped)
                if hit:
                    return hit
        hit = _find_blocked(body)
        if hit:
            return hit
    return None


def _redact_text(text):
    if not isinstance(text, str):
        raise SanitizerBlocked("free text is not a string")
    if not text:
        return text
    out = text
    for _name, detector in _DETECTORS:
        out = detector.sub(REDACTED, out)
    for secret_re in SECRET_RES:
        out = secret_re.sub(REDACTED, out)
    for literal in _profile_literals():
        out = re.sub(re.escape(literal), REDACTED, out, flags=re.IGNORECASE)
    leftover = _find_blocked(out)
    if leftover:
        raise SanitizerBlocked("residual {} after redaction".format(leftover))
    return out


def scan_public_text(text):
    """Refuse a finished public string (HTML, JS, report) if anything remains."""
    if not isinstance(text, str):
        raise SanitizerBlocked("public text is not a string")
    leftover = _find_blocked(text)
    if leftover:
        raise SanitizerBlocked("public text still contains {}".format(leftover))
    return text


def _check_type(key, value, expected):
    if expected == _STR:
        return isinstance(value, str)
    if expected == _STR_OR_NONE:
        return value is None or isinstance(value, str)
    if expected == _INT:
        return _is_int(value)
    if expected == _INT_OR_NONE:
        return value is None or _is_int(value)
    if expected == _BOOL:
        return isinstance(value, bool)
    if expected == _STR_LIST:
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if expected == _PAY:
        if value is None:
            return True
        return (
            isinstance(value, list)
            and len(value) == 2
            and all(_is_int(item) or item is None for item in value)
        )
    if expected == _RECORD:
        return isinstance(value, dict)
    if expected == _RECORD_OR_NONE:
        return value is None or isinstance(value, dict)
    if expected == _RECORD_LIST:
        return isinstance(value, list) and all(isinstance(item, dict) for item in value)
    if expected == _RECORD_MAP:
        return (
            isinstance(value, dict)
            and all(isinstance(item, str) for item in value)
            and all(isinstance(item, dict) for item in value.values())
        )
    if expected == _COMPANY:
        return (
            isinstance(value, str)
            and value != ""
            and "|" not in value
            and value in _known_companies()
        )
    if expected == _LABEL:
        return isinstance(value, str) and value in LABEL_ENUM
    if expected == _BOARD_STATUS:
        return value in BOARD_STATUS_ENUM or value in ("ok", "failed")
    if expected == _RELATIONSHIP:
        return value in RELATIONSHIP_ENUM
    if expected == _MOVE:
        return value in MOVE_ENUM
    if expected == _PAY_NOTE:
        return isinstance(value, str) and value in PAY_NOTE_ENUM
    if expected == _URL:
        return isinstance(value, str) and value != ""
    return False


def _sanitize_value(key, value, expected):
    if not _check_type(key, value, expected):
        raise SanitizerBlocked("wrong type for {}".format(key))
    if expected == _STR:
        if key in {"team", "locations", "location"} and _field_vocab_blocked(key, value):
            raise SanitizerBlocked("blocked {} token".format(key))
        return _redact_text(value)
    if expected == _COMPANY:
        leftover = _find_blocked(value)
        if leftover:
            raise SanitizerBlocked("blocked company name")
        return value
    if expected == _STR_OR_NONE:
        return None if value is None else _redact_text(value)
    if expected == _STR_LIST:
        return [_redact_text(item) for item in value]
    if expected in (_LABEL, _BOARD_STATUS, _RELATIONSHIP, _MOVE, _PAY_NOTE):
        return value
    if expected == _URL:
        return _sanitize_url(value)
    if expected == _RECORD:
        return _sanitize_dict(value)
    if expected == _RECORD_OR_NONE:
        return None if value is None else _sanitize_dict(value)
    if expected == _RECORD_LIST:
        return [_sanitize_dict(item) for item in value]
    if expected == _RECORD_MAP:
        cleaned = {}
        for map_key, map_value in value.items():
            if _find_blocked(map_key):
                raise SanitizerBlocked("blocked map key")
            cleaned[map_key] = _sanitize_dict(map_value)
        return cleaned
    return value


def _sanitize_dict(record):
    if not isinstance(record, dict):
        raise SanitizerBlocked("record is not a dict")
    leaked = set(record) & PRIVATE_KEYS
    if leaked:
        raise SanitizerBlocked("private keys: {}".format(", ".join(sorted(leaked))))
    unknown = set(record) - ALLOWED_KEYS
    if unknown:
        raise SanitizerBlocked("unknown keys: {}".format(", ".join(sorted(unknown))))
    out = {}
    for key, value in record.items():
        out[key] = _sanitize_value(key, value, KEY_TYPES[key])
    leftover = _find_blocked(_public_dump(out))
    if leftover:
        raise SanitizerBlocked("residual {} after redaction".format(leftover))
    return out


def _public_dump(record):
    return json.dumps(record, ensure_ascii=False, sort_keys=True)


def _parse_record(record):
    if isinstance(record, (bytes, bytearray)):
        try:
            record = record.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SanitizerBlocked("invalid JSON") from exc
    if isinstance(record, str):
        try:
            record = json.loads(record)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SanitizerBlocked("invalid JSON") from exc
    if not isinstance(record, dict):
        raise SanitizerBlocked("record is not a dict")
    return record


def _sanitize(record):
    return _sanitize_dict(_parse_record(record))


def sanitize(record):
    """Sanitize one public record.

    Accepts a dict or a JSON string/bytes of a dict. Returns a new dict.
    Raises SanitizerBlocked — and returns nothing — on any failure.
    Application records are not public records; do not call this on them.
    """
    try:
        return _sanitize(record)
    except SanitizerBlocked:
        raise
    except Exception as exc:
        raise SanitizerBlocked("internal sanitizer failure") from exc


def sanitize_records(records):
    """Sanitize a list of public records. Any failure blocks the whole batch."""
    try:
        if not isinstance(records, list):
            raise SanitizerBlocked("records is not a list")
        return [sanitize(record) for record in records]
    except SanitizerBlocked:
        raise
    except Exception as exc:
        raise SanitizerBlocked("internal sanitizer failure") from exc
