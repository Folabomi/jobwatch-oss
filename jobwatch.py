#!/usr/bin/env python3
"""jobwatch: poll company job boards through their ATS JSON APIs and diff the results.

Read only. Queries public job board endpoints, filters titles, and records what is
live in jobwatch_state.json so the next run can report what opened and what closed.
"""

import argparse
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests

# --------------------------------------------------------------------------
# Filters. Tune these two lists; everything else keys off them.
# Matching is case insensitive and anchored on word boundaries, with common
# plural and "-ship" suffixes allowed, so "intern" catches "Interns" and
# "Internship" but never "International", and "edge" never catches "Knowledge".
# --------------------------------------------------------------------------

from taxonomy import (  # noqa: E402 - constants live in one place now
    EXCLUDE_TERMS,
    detect_skills,
    FLAG_TERMS,
    GENERIC_LOCATIONS,
    INCLUDE_TERMS,
    NON_US_ABBREV,
    NON_US_MARKERS,
)

# Drop reqs that are confirmably outside the US. Set False to see everything.
# Only confirmed non-US reqs are dropped; a board that will not say where the job
# is keeps its req, because dropping unknowns would lose real US roles.
US_ONLY = True

# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
TIMEOUT = 25
PAGE_PAUSE = 0.35
STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jobwatch_state.json")

# --------------------------------------------------------------------------
# Boards. Add one by appending a dict here; the platform key picks the parser.
# --------------------------------------------------------------------------

# Example boards, one per platform family. Replace with your own.
BOARDS = (
    {"slug": "cloudflare", "company": "Cloudflare", "platform": "greenhouse", "board": "cloudflare"},
    # Ashby ships the description in the list payload, so skill detection is free here.
    {"slug": "openai", "company": "OpenAI", "platform": "ashby", "board": "openai"},
    # Eightfold caps page size at 10 whatever you ask for.
    {"slug": "netflix", "company": "Netflix", "platform": "eightfold",
     "host": "explore.jobs.netflix.net", "domain": "netflix.com"},
    # Workday: the tenant is NOT always the hostname label. Read window.workday
    # in the page source. `search` for tenants that cap the catalogue at 2000.
    {"slug": "crowdstrike", "company": "CrowdStrike", "platform": "workday",
     "host": "crowdstrike.wd5.myworkdayjobs.com", "tenant": "crowdstrike",
     "site": "crowdstrikecareers", "search": True},
)


def build_matcher(terms):
    """Compile one case insensitive alternation with word boundary anchoring."""
    parts = [r"\s+".join(re.escape(word) for word in term.split()) for term in terms]
    pattern = r"\b(?:" + "|".join(parts) + r")(?:s|es|ship|ships)?\b"
    return re.compile(pattern, re.IGNORECASE)


NON_US_RE = re.compile(
    "|".join([r"\b" + r"\s+".join(re.escape(w) for w in m.split()) + r"\b" for m in NON_US_MARKERS]
             + [r"\b" + re.escape(a) + r"\b" for a in NON_US_ABBREV]),
    re.IGNORECASE,
)

INCLUDE_RE = build_matcher(INCLUDE_TERMS)
EXCLUDE_RE = build_matcher(EXCLUDE_TERMS)
FLAG_RE = build_matcher(FLAG_TERMS)


# Posted pay ranges. US pay-transparency law requires the BASE range, so anything
# parsed here is base only and must be labelled as such. Equity and bonus are
# separate and almost never stated.
PAY_RE = re.compile(r"\$\s?([\d]{2,3}(?:,\d{3})+)")
PAY_MIN = 60000
PAY_MAX = 1200000


def parse_pay(text):
    """Return (low, high) from a job description, or None. Conservative on purpose:
    it wants two plausible annual salary figures and takes the widest sane pair."""
    if not text:
        return None
    values = []
    for raw in PAY_RE.findall(text):
        try:
            value = int(raw.replace(",", ""))
        except ValueError:
            continue
        if PAY_MIN <= value <= PAY_MAX:
            values.append(value)
    if len(values) < 2:
        return None
    low, high = min(values), max(values)
    if low == high or high > low * 6:
        return None
    return (low, high)


def strip_html(markup):
    return html.unescape(re.sub(r"<[^>]+>", " ", markup or ""))


OPAQUE_LOCATION_RE = re.compile(r"^\s*\d+\s+locations?\s*$", re.IGNORECASE)


def is_opaque(location):
    """True when the board hides the real place behind a count such as "3 Locations"."""
    return bool(OPAQUE_LOCATION_RE.match(location or ""))


def enrich_greenhouse(session, board, record):
    """Greenhouse list payloads omit the description, so the posted band needs one
    extra call. Only ever called for reqs that already passed the title filter."""
    url = "https://boards-api.greenhouse.io/v1/boards/{}/jobs/{}".format(board["board"], record["id"])
    try:
        response = session.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        text = strip_html(response.json().get("content"))
        return {"pay": parse_pay(text), "skills": detect_skills(text), "jd": bool(text)}
    except Exception:  # noqa: BLE001 - enrichment must never break the poll
        return {}


def enrich_workday(session, board, record):
    """One detail call gives both the full site list and the posted band."""
    path = record.get("path")
    if not path:
        return {}
    url = "https://{}/wday/cxs/{}/{}{}".format(board["host"], board["tenant"], board["site"], path)
    try:
        response = session.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        info = response.json().get("jobPostingInfo") or {}
    except Exception:  # noqa: BLE001
        return {}
    places = [info.get("location")] + list(info.get("additionalLocations") or [])
    text = strip_html(info.get("jobDescription"))
    return {
        "location": flatten_location([x for x in places if x]) or None,
        "pay": parse_pay(text),
        "skills": detect_skills(text),
        "jd": bool(text),
    }


def safe_url(url):
    """Boards are third parties. Only ever keep an http(s) URL, so a hostile or
    compromised board cannot land a javascript: URL in the rendered page."""
    url = (url or "").strip()
    return url if url.lower().startswith(("http://", "https://")) else ""


def is_non_us(title, location):
    """True only when the board states a location we can confirm is outside the US."""
    return bool(NON_US_RE.search("{} {}".format(title or "", location or "")))


def classify(title):
    """Return (keep, matched_terms, flags). Exclude always wins over include."""
    if EXCLUDE_RE.search(title):
        return False, [], []
    hits = INCLUDE_RE.findall(title)
    if not hits:
        return False, [], []
    flags = ["sde-signal"] if FLAG_RE.search(title) else []
    return True, sorted(set(h.lower() for h in hits)), flags


def flatten_location(value):
    """Boards return location as a string, a dict, or a list of either."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("name", "location", "locationName", "text"):
            if value.get(key):
                return flatten_location(value[key])
        return ""
    if isinstance(value, (list, tuple)):
        seen = []
        for item in value:
            text = flatten_location(item)
            if text and text not in seen:
                seen.append(text)
        return "; ".join(seen)
    return str(value).strip()


def session_with_headers():
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return session


# --------------------------------------------------------------------------
# Per platform fetchers. Each returns a list of raw records:
# {"id", "title", "location", "url"}
# --------------------------------------------------------------------------


# Work styles some boards put in the location field instead of a place.
GENERIC_LOCATIONS = frozenset((
    "hybrid", "in-office", "in office", "on-site", "onsite", "remote",
    "flexible", "various", "multiple", "office", "remote-friendly",
))


def greenhouse_location(job):
    """Greenhouse boards sometimes set location.name to a work style such as
    "Hybrid" and put the real city in a metadata field. Fall back to metadata
    only when the location field says nothing about where the job is, and ignore
    metadata fields that describe the work style rather than the place."""
    stated = flatten_location(job.get("location"))
    if stated and stated.strip().lower() not in GENERIC_LOCATIONS:
        return stated
    for field in job.get("metadata") or []:
        name = (field.get("name") or "").lower()
        if "location" not in name or "type" in name:
            continue
        resolved = flatten_location(field.get("value"))
        if resolved and resolved.strip().lower() not in GENERIC_LOCATIONS:
            return resolved
    return stated


def fetch_greenhouse(session, board):
    url = "https://boards-api.greenhouse.io/v1/boards/{}/jobs".format(board["board"])
    response = session.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    return [
        {
            "id": str(job.get("id")),
            "title": (job.get("title") or "").strip(),
            "location": greenhouse_location(job),
            "url": job.get("absolute_url") or "",
        }
        for job in response.json().get("jobs", [])
    ]


def fetch_ashby(session, board):
    url = "https://api.ashbyhq.com/posting-api/job-board/{}".format(board["board"])
    response = session.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    records = []
    for job in response.json().get("jobs", []):
        if job.get("isListed") is False:
            continue
        locations = [job.get("location")] + list(job.get("secondaryLocations") or [])
        records.append(
            {
                "id": str(job.get("id")),
                "title": (job.get("title") or "").strip(),
                "location": flatten_location(locations),
                "url": job.get("jobUrl") or job.get("applyUrl") or "",
                "jd_text": job.get("descriptionPlain") or "",
            }
        )
    return records


def fetch_eightfold(session, board):
    """Eightfold caps num at 10 per page and reports the true total in `count`."""
    url = "https://{}/api/apply/v2/jobs".format(board["host"])
    page_size = 10
    start = 0
    total = None
    records = []
    while True:
        params = {
            "domain": board["domain"],
            "start": start,
            "num": page_size,
            "sort_by": "relevance",
        }
        response = session.get(url, params=params, timeout=TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        if total is None:
            total = int(payload.get("count") or 0)
        positions = payload.get("positions") or []
        if not positions:
            break
        for position in positions:
            native_id = position.get("display_job_id") or position.get("ats_job_id") or position.get("id")
            records.append(
                {
                    "id": str(native_id),
                    "title": (position.get("name") or position.get("posting_name") or "").strip(),
                    "location": flatten_location(position.get("locations") or position.get("location")),
                    "url": position.get("canonicalPositionUrl") or "",
                }
            )
        start += page_size
        if total is not None and start >= total:
            break
        if start > 5000:
            break
        time.sleep(PAGE_PAUSE)
    return records


def fetch_workday_page(session, board, search_text, offset):
    url = "https://{}/wday/cxs/{}/{}/jobs".format(board["host"], board["tenant"], board["site"])
    body = {"appliedFacets": {}, "limit": 20, "offset": offset, "searchText": search_text}
    headers = {
        "Content-Type": "application/json",
        "Referer": "https://{}/en-US/{}".format(board["host"], board["site"]),
    }
    response = session.post(url, json=body, headers=headers, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def fetch_workday(session, board):
    """Workday caps limit at 20. Big tenants also cap the unfiltered total, so for
    those we run one server side search per include term and dedupe."""
    queries = list(INCLUDE_TERMS) if board.get("search") else [""]
    records = {}
    for query in queries:
        offset = 0
        while True:
            payload = fetch_workday_page(session, board, query, offset)
            postings = payload.get("jobPostings") or []
            if not postings:
                break
            for posting in postings:
                external_path = posting.get("externalPath") or ""
                bullets = posting.get("bulletFields") or []
                native_id = bullets[0] if bullets else external_path
                records[str(native_id)] = {
                    "id": str(native_id),
                    "title": (posting.get("title") or "").strip(),
                    "location": flatten_location(posting.get("locationsText")),
                    "url": "https://{}/en-US/{}{}".format(board["host"], board["site"], external_path),
                    "path": external_path,
                }
            offset += 20
            total = payload.get("total")
            if total is None or offset >= int(total) or offset >= 2000:
                break
            time.sleep(PAGE_PAUSE)
        time.sleep(PAGE_PAUSE)
    return list(records.values())


FETCHERS = {
    "greenhouse": fetch_greenhouse,
    "ashby": fetch_ashby,
    "eightfold": fetch_eightfold,
    "workday": fetch_workday,
}


# --------------------------------------------------------------------------
# Polling
# --------------------------------------------------------------------------


def poll(boards, verbose=True):
    """Return (matches_by_id, ok_slugs, failures, stats). One dead board never kills the run."""
    session = session_with_headers()
    matches = {}
    ok_slugs = []
    failures = []
    stats = {}
    for board in boards:
        slug = board["slug"]
        try:
            raw = FETCHERS[board["platform"]](session, board)
        except Exception as error:  # noqa: BLE001 - any board failure is survivable
            failures.append((slug, "{}: {}".format(type(error).__name__, error)))
            stats[slug] = {
                "company": board["company"],
                "platform": board["platform"],
                "live": None,
                "matches": None,
                "status": "failed",
            }
            if verbose:
                print("  warn  {:<12} FAILED {}".format(slug, type(error).__name__), file=sys.stderr)
            continue
        kept = 0
        dropped_non_us = 0
        resolved = 0
        priced = 0
        jds = 0
        for record in raw:
            keep, terms, flags = classify(record["title"])
            if not keep:
                continue
            # Enrich every match with the posted band, and for Workday the full
            # site list at the same time. One extra call per match, never per req.
            extra = {}
            if board["platform"] == "workday":
                extra = enrich_workday(session, board, record)
                if extra.get("location"):
                    if is_opaque(record["location"]):
                        resolved += 1
                    record["location"] = extra["location"]
                time.sleep(PAGE_PAUSE)
            elif board["platform"] == "greenhouse":
                extra = enrich_greenhouse(session, board, record)
                time.sleep(PAGE_PAUSE)
            elif board["platform"] == "ashby":
                text = record.get("jd_text") or ""
                extra = {"skills": detect_skills(text), "jd": bool(text)}
            pay = extra.get("pay")
            if pay:
                priced += 1
            skills = extra.get("skills") or []
            jd_seen = bool(extra.get("jd"))
            if jd_seen:
                jds += 1

            if US_ONLY and is_non_us(record["title"], record["location"]):
                dropped_non_us += 1
                continue
            key = "{}:{}:{}".format(board["platform"], slug, record["id"])
            matches[key] = {
                "id": key,
                "board": slug,
                "company": board["company"],
                "title": record["title"],
                "location": record["location"],
                "url": safe_url(record["url"]),
                "terms": terms,
                "flags": flags,
                "pay_low": pay[0] if pay else None,
                "pay_high": pay[1] if pay else None,
                "skills": sorted(skills),
                "jd_seen": jd_seen,
            }
            kept += 1
        ok_slugs.append(slug)
        stats[slug] = {
            "company": board["company"],
            "platform": board["platform"],
            "live": len(raw),
            "matches": kept,
            "dropped_non_us": dropped_non_us,
            "locations_resolved": resolved,
            "with_posted_band": priced,
            "with_jd": jds,
            "status": "ok",
        }
        if verbose:
            print("  ok    {:<12} {:>5} live  {:>3} match  {:>3} non-US  {:>3} loc  {:>3} band  {:>3} jd".format(
                slug, len(raw), kept, dropped_non_us, resolved, priced, jds), file=sys.stderr)
    return matches, ok_slugs, failures, stats


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------


def load_state():
    if not os.path.exists(STATE_PATH):
        return {"version": 1, "last_run": None, "jobs": {}}
    with open(STATE_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_state(previous, matches, ok_slugs, stats=None):
    """Carry forward reqs belonging to boards that failed this run, so a transient
    board outage never reports its whole catalogue as closed."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    old_jobs = previous.get("jobs", {})
    jobs = {
        key: value
        for key, value in old_jobs.items()
        if value.get("board") not in ok_slugs
    }
    for key, match in matches.items():
        first_seen = old_jobs.get(key, {}).get("first_seen") or now
        jobs[key] = dict(match, first_seen=first_seen, last_seen=now)
    boards = dict(previous.get("boards") or {})
    boards.update(stats or {})
    state = {"version": 1, "last_run": now, "boards": boards, "jobs": jobs}
    with open(STATE_PATH, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return state


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def render_job(match):
    flag = "  [SDE SIGNAL]" if "sde-signal" in match.get("flags", []) else ""
    return "\n".join(
        [
            "- {} | {}{}".format(match["company"], match["title"], flag),
            "  {}".format(match.get("location") or "location not stated"),
            "  {}".format(match["url"]),
            "  id {} | matched {}".format(match["id"], ", ".join(match.get("terms", [])) or "n/a"),
        ]
    )


def render_report(matches, previous, ok_slugs, failures, diff_mode, first_run):
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append("# jobwatch {}".format(now))
    lines.append("")

    opened = []
    closed = []
    if diff_mode:
        old_jobs = previous.get("jobs", {})
        opened = [m for key, m in sorted(matches.items()) if key not in old_jobs]
        closed = [
            v
            for key, v in sorted(old_jobs.items())
            if key not in matches and v.get("board") in ok_slugs
        ]
        if first_run:
            lines.append("First run. No previous state, so everything below is reported as new.")
            lines.append("")
        lines.append("## Opened ({})".format(len(opened)))
        lines.append("")
        lines.extend([render_job(m) for m in opened] or ["Nothing new."])
        lines.append("")
        lines.append("## Closed ({})".format(len(closed)))
        lines.append("")
        lines.extend([render_job(m) for m in closed] or ["Nothing closed."])
        lines.append("")

    lines.append("## Live matches ({})".format(len(matches)))
    lines.append("")
    lines.extend([render_job(m) for m in sorted(matches.values(), key=lambda m: (m["company"], m["title"]))] or ["None."])
    lines.append("")
    lines.append("## Boards")
    lines.append("")
    lines.append("Polled cleanly: {}".format(", ".join(ok_slugs) or "none"))
    for slug, reason in failures:
        lines.append("FAILED {}: {}".format(slug, reason))
    lines.append("")
    lines.append("SUMMARY new={} closed={} live={} boards_ok={} boards_failed={}".format(
        len(opened), len(closed), len(matches), len(ok_slugs), len(failures)))
    return "\n".join(lines)


def run_probe(boards):
    """Print the raw shape of one response per board. Use this when an ATS changes."""
    session = session_with_headers()
    for board in boards:
        print("=== {} ({})".format(board["slug"], board["platform"]))
        try:
            raw = FETCHERS[board["platform"]](session, board)
            print("  records: {}".format(len(raw)))
            if raw:
                print("  sample: {}".format(json.dumps(raw[0], indent=2)[:600]))
        except Exception as error:  # noqa: BLE001
            print("  FAILED {}: {}".format(type(error).__name__, error))


def main():
    parser = argparse.ArgumentParser(description="Poll job boards through their ATS JSON APIs.")
    parser.add_argument("--diff", action="store_true", help="report what opened and closed since the last run")
    parser.add_argument("--board", help="poll a single board by slug")
    parser.add_argument("--probe", action="store_true", help="print raw shapes, do not touch state")
    parser.add_argument("--list-boards", action="store_true", help="list board slugs and exit")
    args = parser.parse_args()

    if args.list_boards:
        for board in BOARDS:
            print("{:<12} {:<10} {}".format(board["slug"], board["platform"], board["company"]))
        return 0

    boards = BOARDS
    if args.board:
        boards = tuple(b for b in BOARDS if b["slug"] == args.board)
        if not boards:
            print("unknown board '{}'. Try --list-boards.".format(args.board), file=sys.stderr)
            return 2

    if args.probe:
        run_probe(boards)
        return 0

    print("polling {} board(s)...".format(len(boards)), file=sys.stderr)
    matches, ok_slugs, failures, stats = poll(boards)

    if not ok_slugs:
        print("every board failed; leaving state untouched", file=sys.stderr)
        for slug, reason in failures:
            print("  {}: {}".format(slug, reason), file=sys.stderr)
        return 1

    previous = load_state()
    first_run = not previous.get("jobs")
    report = render_report(matches, previous, ok_slugs, failures, args.diff, first_run)
    print(report)
    save_state(previous, matches, ok_slugs, stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
