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

`name` is the company name only. `label` is a closed enum from taxonomy.
Application fields are not here: status (as an application state), note,
last_contact, match, why, relationship_note, rel_note, resume.

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

import html as html_lib
import json
import os
import re
import unicodedata

from taxonomy import (
    ARCH_LABELS,
    COMPETENCIES,
    FALLBACK_COMPETENCY,
    FIT_GAUGE,
    FIT_LABELS,
    INDUSTRY_LABELS,
    LEVEL_MOVE_LABELS,
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
    "url": _STR,
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
    "careers": _STR,
    "comp": _RECORD,
    "relationship": _STR,
    "relationship_url": _STR,
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
    "rel_url": _STR,
    "polled": _BOOL,
    "gauge": _RECORD_OR_NONE,
    "geo": _STR_LIST,
    "scanned": _INT_OR_NONE,
    "board_status": _BOARD_STATUS,
    "median": _INT_OR_NONE,
    "median_conf": _STR,
    "pay_note": _STR,
    "pay_tier": _STR,
    "level_conf": _STR,
    "move": _STR,
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
    r"\b(?:[Nn]ame|[Aa]pplicant|[Cc]andidate|[Rr]ecruiter)\s*[:\-\u2013\u2014]\s*"
    r"([A-Z][a-z]+(?:[\s\u2013\u2014\-][A-Z][a-z]+)+)\b"
)

# Jane—Doe / Ada–Lovelace: em/en dash used to hide a person name.
EMDASH_NAME_RE = re.compile(
    r"\b[A-Z][a-z]{1,20}[\u2013\u2014][A-Z][a-z]{1,20}\b"
)

MAILTO_RE = re.compile(r"mailto\s*:", re.IGNORECASE)

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
    "\uff20": "@", "\uff0e": ".", "\u2024": ".",
    "\u00a0": " ", "\u200b": "", "\u200c": "", "\u200d": "",
    "\ufeff": "",
})


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


def _strip_comments(text):
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"(?m)//.*?$", "", text)
    return text


def _decode_entities(text):
    # Twice: &amp;#109;ailto: and &#109;ailto: both have to land as mailto:
    once = html_lib.unescape(text)
    return html_lib.unescape(once)


def _deny_normalize(text):
    """Case-fold, NFKC, map homoglyphs, strip comments, decode entities."""
    if not text:
        return ""
    folded = unicodedata.normalize("NFKC", text).casefold()
    folded = folded.translate(_HOMOGLYPHS)
    folded = _decode_entities(folded)
    folded = _strip_comments(folded)
    folded = unicodedata.normalize("NFKC", folded).translate(_HOMOGLYPHS)
    return folded


def _script_json_payloads(text):
    payloads = []
    for match in re.finditer(r"<script\b[^>]*>(.*?)</script>", text, flags=re.DOTALL | re.IGNORECASE):
        body = match.group(1).strip()
        if not body:
            continue
        payloads.append(body)
        try:
            payloads.append(json.dumps(json.loads(body), ensure_ascii=False))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    return payloads


def _data_attr_payloads(text):
    return [
        match.group(2)
        for match in re.finditer(
            r"""data-(?:notes?|email|phone|name|profile)\s*=\s*(['"])(.*?)\1""",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
    ]


def _find_blocked_plain(text):
    if not text:
        return None
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
    hit = _find_blocked_plain(text)
    if hit:
        return hit
    normalized = _deny_normalize(text)
    hit = _find_blocked_plain(normalized)
    if hit:
        return hit
    for payload in _script_json_payloads(text) + _data_attr_payloads(text):
        hit = _find_blocked(payload) if payload != text else _find_blocked_plain(payload)
        if hit:
            return hit
        hit = _find_blocked_plain(_deny_normalize(payload))
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
        return isinstance(value, str) and value != ""
    if expected == _LABEL:
        return isinstance(value, str) and value in LABEL_ENUM
    if expected == _BOARD_STATUS:
        return value in BOARD_STATUS_ENUM or value in ("ok", "failed")
    return False


def _sanitize_value(key, value, expected):
    if not _check_type(key, value, expected):
        raise SanitizerBlocked("wrong type for {}".format(key))
    if expected in (_STR, _COMPANY):
        return _redact_text(value)
    if expected == _STR_OR_NONE:
        return None if value is None else _redact_text(value)
    if expected == _STR_LIST:
        return [_redact_text(item) for item in value]
    if expected == _LABEL:
        return value
    if expected == _BOARD_STATUS:
        return value
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
