#!/usr/bin/env python3
"""Score a req against a CV and emit a tailored draft.

Read only. Never applies, never creates an account, never logs in, holds no
credentials. Operates on saved poller state plus a CV file (and an optional JD
file). Comp and location are gated with the same functions the poller and the
page already use, and that gate runs before any scoring or tailoring.

The draft is a reordering of the CV. Every number, date, title and skill in the
output has to already be in the source CV. Gaps are named, never phrased around.
"""

import argparse
import json
import os
import re
import sys

from taxonomy import (
    RESUMES,
    competency_for,
    detect_skill_hits,
    detect_skills,
    gate_req,
)

ROOT = os.path.dirname(os.path.abspath(__file__))

HEADING_RE = re.compile(r"^(#{1,3})\s+(.*)$")
BULLET_RE = re.compile(r"^(\s*[-*•]\s+)(.*)$")
NUMBER_RE = re.compile(r"\d+(?:,\d{3})*(?:\.\d+)?")
YEARS_RE = re.compile(r"(\d+)\s*\+?\s*(?:years?|yrs)\b", re.IGNORECASE)

# Phrases that would hide a miss. The gap line must never use these.
WEASEL = (
    "familiar with",
    "exposure to",
    "working knowledge",
    "transferable",
    "equivalent experience",
    "similar technologies",
)


def claimed_numbers(text):
    """Every numeral the text states, including years, counts and comma groups."""
    return set(NUMBER_RE.findall(text or ""))


def years_stated(text):
    """Largest explicit 'N years' claim, or None if the text never says one."""
    values = [int(match) for match in YEARS_RE.findall(text or "")]
    return max(values) if values else None


def invented_claims(cv_text, draft):
    """Numbers and skill keys that appear in the draft but not in the CV.

    An empty result is the invent-nothing postcondition. Callers treat a
    non-empty result as a bug, not as something to paper over.
    """
    extra_numbers = sorted(claimed_numbers(draft) - claimed_numbers(cv_text))
    extra_skills = sorted(set(detect_skills(draft)) - set(detect_skills(cv_text)))
    return {"numbers": extra_numbers, "skills": extra_skills}


def parse_cv(text):
    """Split a markdown-ish CV into header, sections, jobs and bullets.

    Lossless on purpose: tailoring only reorders existing lines. Reconstruction
    has to emit the same sentences, just in a different sequence.
    """
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    header = []
    sections = []
    current = None
    job = None
    for line in lines:
        heading = HEADING_RE.match(line)
        if heading and heading.group(1) == "#":
            if current is None and not header:
                header.append(line)
                continue
        if heading and heading.group(1) == "##":
            if current is not None:
                if job is not None:
                    current["jobs"].append(job)
                    job = None
                sections.append(current)
            current = {"heading": line, "lines": [], "jobs": []}
            continue
        if heading and heading.group(1) == "###" and current is not None:
            if job is not None:
                current["jobs"].append(job)
            job = {"heading": line, "lines": []}
            continue
        if current is None:
            header.append(line)
        elif job is not None:
            job["lines"].append(line)
        else:
            current["lines"].append(line)
    if current is not None:
        if job is not None:
            current["jobs"].append(job)
        sections.append(current)
    return {"text": text or "", "header": header, "sections": sections}


def _iter_bullets(lines):
    for index, line in enumerate(lines):
        match = BULLET_RE.match(line)
        if match:
            yield index, line, match.group(2)


def _skill_keys(text):
    return {hit["key"] for hit in detect_skill_hits(text)}


def _line_score(text, jd_keys, jd_lower):
    """Rank a CV line against the posting. Skills that the JD names weigh most."""
    if not text or not text.strip():
        return 0
    overlap = sum(10 for hit in detect_skill_hits(text) if hit["key"] in jd_keys)
    words = re.findall(r"[a-z][a-z0-9+]{3,}", text.lower())
    wording = sum(1 for word in words if word in jd_lower)
    return overlap + min(wording, 8)


def _reorder_bullets(lines, jd_keys, jd_lower):
    bullets = list(_iter_bullets(lines))
    if len(bullets) < 2:
        return list(lines)
    ranked = sorted(
        bullets,
        key=lambda item: -_line_score(item[2], jd_keys, jd_lower),
    )
    out = list(lines)
    for (index, _, _), (_, new_line, _) in zip(bullets, ranked):
        out[index] = new_line
    return out


def _reorder_jobs(jobs, jd_keys, jd_lower):
    scored = []
    for job in jobs:
        reordered = _reorder_bullets(job["lines"], jd_keys, jd_lower)
        best = max(
            (_line_score(line, jd_keys, jd_lower) for _, line, _ in _iter_bullets(reordered)),
            default=_line_score(job["heading"], jd_keys, jd_lower),
        )
        scored.append((best, {"heading": job["heading"], "lines": reordered}))
    scored.sort(key=lambda item: -item[0])
    return [job for _, job in scored]


def _reorder_prose(lines, jd_keys, jd_lower):
    """Reorder sentences or comma lists; leave one-liners that are not lists alone."""
    out = []
    for line in lines:
        stripped = line.strip()
        if "," in stripped and not BULLET_RE.match(line) and len(stripped.split(",")) >= 3:
            parts = [part.strip() for part in stripped.split(",")]
            parts.sort(key=lambda part: -_line_score(part, jd_keys, jd_lower))
            indent = line[: len(line) - len(line.lstrip())]
            out.append(indent + ", ".join(parts))
            continue
        if stripped and not stripped.startswith("#") and "." in stripped:
            sentences = _split_sentences(stripped)
            if len(sentences) >= 2:
                sentences.sort(key=lambda sent: -_line_score(sent, jd_keys, jd_lower))
                indent = line[: len(line) - len(line.lstrip())]
                joined = " ".join(sentences)
                out.append(indent + joined)
                continue
        out.append(line)
    return _reorder_bullets(out, jd_keys, jd_lower)


def _split_sentences(text):
    parts = re.split(r"(?<=\.)\s+", text.strip())
    return [part for part in parts if part]


def tailor_cv(cv, jd_text):
    """Reorder the CV so the top third tracks the posting's own language.

    Jobs, bullets, summary sentences and skill lists move. Words do not. The
    function refuses to return a draft that introduces a number or skill the
    source CV did not already state.
    """
    jd_text = jd_text or ""
    jd_keys = _skill_keys(jd_text)
    jd_lower = jd_text.lower()
    parsed = cv if isinstance(cv, dict) else parse_cv(cv)
    source = parsed["text"]
    chunks = list(parsed["header"])
    for section in parsed["sections"]:
        chunks.append(section["heading"])
        if section["jobs"]:
            chunks.extend(_reorder_prose(section["lines"], jd_keys, jd_lower))
            for job in _reorder_jobs(section["jobs"], jd_keys, jd_lower):
                chunks.append(job["heading"])
                chunks.extend(job["lines"])
        else:
            chunks.extend(_reorder_prose(section["lines"], jd_keys, jd_lower))
    draft = "\n".join(chunks).strip() + "\n"
    invented = invented_claims(source, draft)
    if invented["numbers"] or invented["skills"]:
        raise ValueError(
            "tailor invented claims that are not in the CV: {}".format(invented)
        )
    return draft


def score_fit(jd_text, cv):
    """Compare the posting to the CV. Gaps are named; nothing is paraphrased."""
    source = cv["text"] if isinstance(cv, dict) else (cv or "")
    jd_hits = detect_skill_hits(jd_text)
    cv_keys = _skill_keys(source)
    held = []
    gaps = []
    for hit in jd_hits:
        item = {
            "key": hit["key"],
            "label": hit["label"],
            "evidence": hit["evidence"],
        }
        if hit["key"] in cv_keys:
            held.append(item)
        else:
            item["detail"] = "not in CV"
            gaps.append(item)

    jd_years = years_stated(jd_text)
    cv_years = years_stated(source)
    years = None
    if jd_years and cv_years is not None and cv_years < jd_years:
        years = {
            "key": "years",
            "label": "Years of experience",
            "evidence": "posting asks for {} years; CV states {}".format(
                jd_years, cv_years
            ),
            "detail": "not in CV",
        }
        gaps.append(years)

    asked = len(jd_hits)
    matched = len(held)
    return {
        "asked": asked,
        "matched": matched,
        "ratio": (float(matched) / asked) if asked else None,
        "held": held,
        "gaps": gaps,
        "years": years,
    }


def evaluate(req, cv_text, jd_text, org=None, variant=None, force=False):
    """Gate, then score, then tailor. Non-viable reqs skip the later work."""
    req = req or {}
    gate = gate_req(req, org=org)
    title = req.get("title") or ""
    competency = competency_for(title) if title else competency_for(jd_text or "")
    resume_key = variant or competency["cv"]
    resume_meta = RESUMES.get(resume_key) or {"label": resume_key}
    result = {
        "req": {
            "id": req.get("id") or "",
            "company": req.get("company") or "",
            "title": title,
            "location": req.get("location") or "",
            "pay_low": req.get("pay_low"),
            "pay_high": req.get("pay_high"),
            "url": req.get("url") or "",
        },
        "viable": gate["viable"],
        "gate": gate,
        "competency": {
            "key": competency["key"],
            "label": competency["label"],
            "cv": competency["cv"],
        },
        "resume_variant": {
            "key": resume_key,
            "label": resume_meta.get("label") or resume_key,
        },
        "score": None,
        "draft": None,
        "skipped": None,
    }
    if not gate["viable"] and not force:
        result["skipped"] = "not viable"
        return result
    if not (jd_text or "").strip():
        result["skipped"] = "no job description"
        return result
    if not (cv_text or "").strip():
        result["skipped"] = "no CV"
        return result
    parsed = parse_cv(cv_text)
    result["score"] = score_fit(jd_text, parsed)
    result["draft"] = tailor_cv(parsed, jd_text)
    return result


def _load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_text(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _orgs_from(path):
    if not path or not os.path.exists(path):
        return []
    payload = _load_json(path)
    if isinstance(payload, list):
        return payload
    return payload.get("organizations") or []


def org_for(req, orgs):
    board = (req or {}).get("board")
    company = (req or {}).get("company")
    for org in orgs:
        if board and org.get("board") == board:
            return org
    for org in orgs:
        if company and org.get("name") == company:
            return org
    return None


def find_req(state, req_id):
    jobs = (state or {}).get("jobs") or {}
    if req_id in jobs:
        return jobs[req_id]
    suffix = []
    for key, job in jobs.items():
        if key.endswith(":" + req_id) or job.get("id") == req_id:
            suffix.append(job)
    if len(suffix) == 1:
        return suffix[0]
    if len(suffix) > 1:
        raise ValueError("req id '{}' is ambiguous".format(req_id))
    return None


def new_reqs(state):
    """Reqs first seen on the last run. First run reports everything as new."""
    last = (state or {}).get("last_run")
    jobs = list(((state or {}).get("jobs") or {}).values())
    if not last:
        return jobs
    return [
        job
        for job in jobs
        if job.get("first_seen") == last or job.get("first_seen") == job.get("last_seen")
    ]


def resolve_jd(req, jd_path, jd_dir):
    if jd_path:
        return _load_text(jd_path)
    if req and (req.get("jd_text") or "").strip():
        return req["jd_text"]
    if req and jd_dir:
        key = req.get("id") or ""
        candidates = [
            key,
            key.replace(":", "_"),
            key.split(":")[-1] if key else "",
        ]
        for name in candidates:
            if not name:
                continue
            path = os.path.join(jd_dir, name + ".md")
            if os.path.isfile(path):
                return _load_text(path)
    return ""


def resolve_cv(resume_key, cv_path, cv_dir):
    if cv_path:
        return _load_text(cv_path)
    if cv_dir and resume_key:
        path = os.path.join(cv_dir, resume_key + ".md")
        if os.path.isfile(path):
            return _load_text(path)
        raise SystemExit(
            "no CV file for variant '{}' (looked for {})".format(resume_key, path)
        )
    raise SystemExit("pass --cv or --cv-dir so there is a resume to tailor")


def _money(value):
    if not value:
        return ""
    return "${:,.0f}K".format(value / 1000)


def render_result(result):
    """Human report. Organisation first, gaps named, posted band labelled base only."""
    req = result["req"]
    lines = []
    heading = " · ".join(part for part in (req.get("company"), req.get("title")) if part)
    lines.append("=== {}".format(heading or req.get("id") or "req"))
    loc = req.get("location") or "location not stated"
    pay = ""
    if req.get("pay_low") and req.get("pay_high"):
        pay = " · {}–{} base only".format(_money(req["pay_low"]), _money(req["pay_high"]))
    elif req.get("pay_high"):
        pay = " · {} posted high, base only".format(_money(req["pay_high"]))
    lines.append("    {}{}".format(loc, pay))
    if req.get("id"):
        lines.append("    {}".format(req["id"]))
    lines.append("")

    gate = result["gate"]
    lines.append("GATE    {}".format("viable" if gate["viable"] else "not viable"))
    for check in gate["checks"]:
        mark = "ok" if check["ok"] else "FAIL"
        lines.append("        {:<8} {}  {}".format(check["gate"], mark, check["detail"]))
    lines.append("")

    variant = result["resume_variant"]
    competency = result["competency"]
    lines.append("CV      {}".format(variant["label"]))
    lines.append("        competency: {}".format(competency["label"]))
    lines.append("        variant: {}".format(variant["key"]))
    lines.append("")

    if result.get("skipped"):
        lines.append("SKIP    {}".format(result["skipped"]))
        if result["skipped"] == "not viable":
            lines.append("        tailoring skipped; the req was never viable")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    score = result["score"] or {}
    asked = score.get("asked") or 0
    matched = score.get("matched") or 0
    if asked:
        lines.append("FIT     {} of {} skills the posting names".format(matched, asked))
    else:
        lines.append("FIT     posting named none of the tracked skills")
    for item in score.get("held") or []:
        lines.append("        held  {} ({})".format(item["label"], item["evidence"]))
    for item in score.get("gaps") or []:
        lines.append(
            "        gap   {} ({}) — {}".format(
                item["label"], item["evidence"], item.get("detail") or "not in CV"
            )
        )
    if not (score.get("gaps") or []):
        lines.append("        gaps  none")
    lines.append("")
    lines.append("DRAFT")
    lines.append("-----")
    lines.append((result.get("draft") or "").rstrip())
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Score a req against a CV and emit a tailored draft. "
            "Invents nothing. Never applies."
        )
    )
    parser.add_argument("--req", help="req id from state, e.g. greenhouse:acme:100")
    parser.add_argument(
        "--new",
        action="store_true",
        help="every req first seen on the last run",
    )
    parser.add_argument("--list-reqs", action="store_true", help="print req ids and exit")
    parser.add_argument(
        "--state",
        default=os.path.join(ROOT, "jobwatch_state.json"),
        help="poller state file",
    )
    parser.add_argument(
        "--orgs",
        default=os.path.join(ROOT, "organizations.json"),
        help="organizations.json, for the level gate",
    )
    parser.add_argument("--jd", help="job description file (full text, not the title)")
    parser.add_argument(
        "--jd-dir",
        help="JD files named {req_id with colons as underscores}.md",
    )
    parser.add_argument("--cv", help="CV file to tailor (overrides --cv-dir)")
    parser.add_argument(
        "--cv-dir",
        help="variant files named {variant}.md, e.g. edge_ddos.md",
    )
    parser.add_argument(
        "--variant",
        help="force a CV variant key instead of the competency map",
    )
    parser.add_argument("--title", help="when scoring a JD file with no state")
    parser.add_argument("--location")
    parser.add_argument("--company")
    parser.add_argument("--pay-low", type=int)
    parser.add_argument("--pay-high", type=int)
    parser.add_argument("--amazon-equiv", help="Amazon-form level, e.g. L6")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="machine-readable output",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="score and tailor even if the gate fails",
    )
    parser.add_argument("--out", help="write the draft to this file (single req)")
    args = parser.parse_args(argv)

    state = None
    needs_state = args.req or args.new or args.list_reqs
    if needs_state:
        if not os.path.exists(args.state):
            print("no state file at {}".format(args.state), file=sys.stderr)
            return 2
        state = _load_json(args.state)

    if args.list_reqs:
        jobs = list((state.get("jobs") or {}).values())
        jobs.sort(key=lambda job: (job.get("company") or "", job.get("title") or ""))
        for job in jobs:
            print("{}\t{}\t{}".format(job.get("id"), job.get("company"), job.get("title")))
        return 0

    orgs = _orgs_from(args.orgs)
    targets = []
    if args.req:
        job = find_req(state, args.req)
        if job is None:
            print("unknown req '{}'".format(args.req), file=sys.stderr)
            return 2
        targets.append(job)
    elif args.new:
        targets = new_reqs(state)
        if not targets:
            print("no new reqs in {}".format(args.state), file=sys.stderr)
            return 0
    elif args.jd or args.title:
        targets.append({
            "id": "",
            "company": args.company or "",
            "title": args.title or "",
            "location": args.location or "",
            "pay_low": args.pay_low,
            "pay_high": args.pay_high,
            "amazon_equiv": args.amazon_equiv,
            "url": "",
        })
    else:
        parser.error("pass --req, --new, or --jd")

    reports = []
    for job in targets:
        if args.title:
            job = dict(job, title=args.title)
        if args.location:
            job = dict(job, location=args.location)
        if args.company:
            job = dict(job, company=args.company)
        if args.pay_low is not None:
            job = dict(job, pay_low=args.pay_low)
        if args.pay_high is not None:
            job = dict(job, pay_high=args.pay_high)
        if args.amazon_equiv:
            job = dict(job, amazon_equiv=args.amazon_equiv)

        org = org_for(job, orgs)
        title = job.get("title") or ""
        jd_text = resolve_jd(job, args.jd, args.jd_dir)
        competency = competency_for(title) if title else competency_for(jd_text)
        resume_key = args.variant or competency["cv"]
        try:
            cv_text = resolve_cv(resume_key, args.cv, args.cv_dir)
        except SystemExit as error:
            print(error, file=sys.stderr)
            return 2

        result = evaluate(
            job,
            cv_text,
            jd_text,
            org=org,
            variant=args.variant,
            force=args.force,
        )
        reports.append(result)

    if args.as_json:
        payload = reports[0] if len(reports) == 1 else reports
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        sys.stdout.write("\n".join(render_result(item) for item in reports))

    if args.out:
        if len(reports) != 1:
            print("--out is for a single req; omit --new or pass --req", file=sys.stderr)
            return 2
        if not reports[0].get("draft"):
            print("no draft to write ({})".format(reports[0].get("skipped")), file=sys.stderr)
            return 2
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(reports[0]["draft"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
