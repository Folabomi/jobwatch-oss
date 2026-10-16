#!/usr/bin/env python3
"""Fail-closed sanitizer for JobWatch public and shared output.

`sanitize(record)` returns a new record, or raises SanitizerBlocked and
returns nothing. Any unexpected condition is a block: unknown keys, wrong
types, invalid JSON, leftover PII or secrets after redaction, or an
internal exception.

Allowlist
---------
Built from the records JobWatch already persists and publishes. A key that
is not in this table is refused, even if its value looks harmless. Missing
keys are allowed; extra keys are not.

State file (`jobwatch_state.json`), written by jobwatch.py:

    version                 int
    last_run                str | None
    boards                  map of board-slug -> board record
    jobs                    map of job-id -> job record

Job record (poller + state):

    id, board, company, title, location, url    str
    terms, flags, skills                        list[str]
    pay_low, pay_high                           int | None
    jd_seen                                     bool
    first_seen, last_seen                       str

Board stats record:

    company, platform, status                   str
    live, matches                               int | None
    dropped_non_us, locations_resolved          int
    with_posted_band, with_jd                   int

Applications file (`applications.json`):

    updated, note                               str
    applications                                list[application record]

Application record:

    company, title, status, note                str
    match                                       str | None
    last_contact                                str

Organizations file (`organizations.json`):

    updated, note                               str
    organizations                               list[organization record]

Organization record (hand-maintained):

    name, board, industry, sector, arch, fit    str
    team, why, locations, careers               str
    relationship, relationship_note             str
    relationship_url                            str
    traffic, warm_channel, open_now             bool
    comp                                        nested compensation record

Compensation record:

    levels_company, tier, note, confidence      str
    level_source, level_confidence              str
    target_level, amazon_equiv                  str | None
    median_total                                int | None

Dismissed file (`dismissed.json`):

    dismissed                                   list[str]  (job ids)

Rendered job row (render_site.build_rows):

    id, company, title, location, url, board    str
    terms, skills                               list[str]
    tier, place, since, competency, resume      str
    status                                      str | None
    sde, jd_seen                                bool
    pay                                         [int, int] | None

Rendered organization card (render_site.build_orgs):

    name, team, why, locations, careers         str
    industry_label, arch_label, fit_label       str
    relationship, rel_note, rel_url             str
    median_conf, pay_note, pay_tier             str
    level_conf, move                            str
    industry, sector, arch, fit                 str | None
    target_level, amazon_equiv                  str | None
    board_status                                str | None
    traffic, warm, polled                       bool
    scanned, median                             int | None
    geo                                         list[str]
    gauge                                       nested gauge record | None
    reqs                                        list[rendered job row]

Gauge record:

    bar, label                                  str
    rank                                        int

Callers must not emit a record that did not come back from sanitize.
"""

from __future__ import annotations

import json
import os
import re


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

KEY_TYPES = {
    # state
    "version": _INT,
    "last_run": _STR_OR_NONE,
    "boards": _RECORD_MAP,
    "jobs": _RECORD_MAP,
    # job
    "id": _STR,
    "board": _STR,
    "company": _STR,
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
    # board stats
    "platform": _STR,
    "live": _INT_OR_NONE,
    "matches": _INT_OR_NONE,
    "dropped_non_us": _INT,
    "locations_resolved": _INT,
    "with_posted_band": _INT,
    "with_jd": _INT,
    "status": _STR_OR_NONE,
    # applications file / record
    "updated": _STR,
    "note": _STR,
    "applications": _RECORD_LIST,
    "match": _STR_OR_NONE,
    "last_contact": _STR,
    # organizations file / record
    "organizations": _RECORD_LIST,
    "name": _STR,
    "industry": _STR_OR_NONE,
    "sector": _STR_OR_NONE,
    "arch": _STR_OR_NONE,
    "fit": _STR_OR_NONE,
    "traffic": _BOOL,
    "warm_channel": _BOOL,
    "open_now": _BOOL,
    "team": _STR,
    "why": _STR,
    "locations": _STR,
    "careers": _STR,
    "comp": _RECORD,
    "relationship": _STR,
    "relationship_note": _STR,
    "relationship_url": _STR,
    # compensation
    "levels_company": _STR,
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
    "resume": _STR,
    "pay": _PAY,
    # rendered org
    "industry_label": _STR,
    "arch_label": _STR,
    "fit_label": _STR,
    "warm": _BOOL,
    "rel_note": _STR,
    "rel_url": _STR,
    "polled": _BOOL,
    "gauge": _RECORD_OR_NONE,
    "geo": _STR_LIST,
    "scanned": _INT_OR_NONE,
    "board_status": _STR_OR_NONE,
    "median": _INT_OR_NONE,
    "median_conf": _STR,
    "pay_note": _STR,
    "pay_tier": _STR,
    "level_conf": _STR,
    "move": _STR,
    "reqs": _RECORD_LIST,
    # gauge
    "bar": _STR,
    "label": _STR,
    "rank": _INT,
}

ALLOWED_KEYS = frozenset(KEY_TYPES)

# Applicant-profile values. Operators add real ones via applicant_profile.json
# (gitignored) or JOBWATCH_APPLICANT_NAMES. Tests append here.
APPLICANT_NAMES = []
APPLICANT_ADDRESSES = []
APPLICANT_PROFILE_URLS = []

REDACTED = "[REDACTED]"

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_PATH = os.path.join(HERE, "applicant_profile.json")


# --------------------------------------------------------------------------
# Detection. The same patterns redact and then re-scan.
# --------------------------------------------------------------------------

# Local-part @ domain.tld. Requires a dot in the domain so CSS @media and
# JS identifiers cannot trip it.
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\b"
)

# North-American and +country grouped numbers. ISO dates (2026-04-02) and
# bare pay integers (250000) do not match.
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]*)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[\s.-]\d{3}[\s.-]\d{4}(?!\d)"
)

LINKEDIN_RE = re.compile(
    r"https?://(?:[\w-]+\.)?linkedin\.com/(?:in|pub|mwlite/in)/[A-Za-z0-9_\-%/]+",
    re.IGNORECASE,
)

# Personal profile URLs, not org/repo paths (github.com/org/repo is two
# segments and is left alone).
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

# House number + capitalised street name + a real suffix. Abbreviations
# without a period only count when they end the phrase or meet a comma, so
# "11 percent ... high-tax state" cannot match on the letters "st".
ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+"
    r"[A-Z][A-Za-z0-9.'\-]+(?:\s+[A-Z][A-Za-z0-9.'\-]+){0,4}\s+"
    r"(?:Street|Avenue|Road|Drive|Lane|Boulevard|Court|Circle|Place|"
    r"St\.|Ave\.|Rd\.|Dr\.|Ln\.|Blvd\.|Ct\.|Pl\.|"
    r"(?:St|Ave|Rd|Dr|Ln|Blvd|Ct|Pl)(?=\s*,|\s*$))"
    r"(?:\s+(?:Apt|Apartment|Suite|Unit|#)\s*[A-Za-z0-9\-]+)?"
    r"(?:\s*,\s*[A-Z][A-Za-z .\-]+(?:\s*,\s*[A-Z]{2}(?:\s+\d{5}(?:-\d{4})?)?)?)?"
)

# Labeled applicant name in free text ("Name: Jane Doe").
LABELED_NAME_RE = re.compile(
    r"\b(?:[Nn]ame|[Aa]pplicant|[Cc]andidate)\s*[:\-]\s*"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b"
)

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
)


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


def _find_blocked(text):
    """Return a short reason if text still contains a blocked pattern."""
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
    for secret_re in SECRET_RES:
        if secret_re.search(text):
            return "secret"
    lowered = text.lower()
    for literal in _profile_literals():
        if literal.lower() in lowered:
            return "applicant_profile"
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
    return False


def _sanitize_value(key, value, expected):
    if not _check_type(key, value, expected):
        raise SanitizerBlocked("wrong type for {}".format(key))
    if expected == _STR:
        return _redact_text(value)
    if expected == _STR_OR_NONE:
        return None if value is None else _redact_text(value)
    if expected == _STR_LIST:
        return [_redact_text(item) for item in value]
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
    """Sanitize one record for public output.

    Accepts a dict or a JSON string/bytes of a dict. Returns a new dict.
    Raises SanitizerBlocked — and returns nothing — on any failure.
    """
    try:
        return _sanitize(record)
    except SanitizerBlocked:
        raise
    except Exception as exc:
        raise SanitizerBlocked("internal sanitizer failure") from exc


def sanitize_records(records):
    """Sanitize a list of records. Any failure blocks the whole batch."""
    try:
        if not isinstance(records, list):
            raise SanitizerBlocked("records is not a list")
        return [sanitize(record) for record in records]
    except SanitizerBlocked:
        raise
    except Exception as exc:
        raise SanitizerBlocked("internal sanitizer failure") from exc
