#!/usr/bin/env python3
"""Take a req, decide whether it is worth my time, tailor a CV, verify, and stop.

Nothing here submits an application, creates an account, fills a form, or logs
into anything. It reads public postings, writes files to resumes/tailored, and
stops. Submission is a click I make, every time, because the cost of a wrong
listing is three seconds of scrolling and the cost of a wrong submission is a
first impression I cannot take back.

The rule that overrides everything: never invent a fact. That is enforced by
construction rather than by intent. Tailoring moves and drops whole paragraphs
lifted byte for byte out of a source variant, so a claim can only appear in the
output if it was already in the input. Two lines are exempt and are rebuilt from
terms that already appear in my own CVs.

    python3 apply.py <req-id-or-url>
    python3 apply.py <id> --variant edge_ddos
    python3 apply.py <id> --dry
    python3 apply.py --log <id> --outcome rejected --reason "..."
"""

import argparse
import io
import json
import os
import re
import sys
from datetime import date

import docx_edit as dx
import jobwatch as jw
import render_site as rs
from taxonomy import (
    BASE_FLOOR,
    ELIGIBILITY_BARS, ELIGIBILITY_FLAGS, HOME_METRO, REMOTE_TERMS,
    ONSITE_TERMS, RELOCATION_BARS, REMOTE_PHRASES,
    EQUITY_TERMS,
    FIXED_GAPS,
    FIXED_TITLE,
    JUNIOR_TERMS,
    NEVER_AUTO,
    RESUMES,
    SDE_TELL,
    URGENCY_TERMS,
    level_move,
)

HERE = os.path.dirname(os.path.abspath(__file__))
RESUME_DIR = os.path.join(HERE, "resumes")
OUT_ROOT = os.path.join(RESUME_DIR, "tailored")
APPS_PATH = os.path.join(HERE, "applications.json")
ORGS_PATH = os.path.join(HERE, "organizations.json")

CANDIDATE_NAME = "Candidate Name"      # goes on the tailored filename
MIN_ATS_WORDS = 900
MAX_PARAGRAPHS = 52          # about two pages in these templates
# Word records the page count it computed in docProps/app.xml, which is the only
# real measurement available without a renderer. Across the variants: 1,195 words
# renders as two pages and 1,308 renders as three. Paragraph count alone was the
# proxy before, and it let a three-page document go out to a live application.
MAX_WORDS = 1220
DASHES = ("—", "–")


# --------------------------------------------------------------------------
# Loading the posting
# --------------------------------------------------------------------------


def load_json(path, key):
    with io.open(path, encoding="utf-8") as handle:
        return json.load(handle)[key]


def find_req(needle):
    """Match a req by id or by URL against what the poller already has."""
    state = jw.load_state()
    jobs = state.get("jobs", {})
    if needle in jobs:
        return jobs[needle]
    for job in jobs.values():
        if needle == job.get("url") or needle in (job.get("id") or ""):
            return job
    return None


def posting_text(req):
    """The full description. Ashby and Lever carry it inline; the rest need a
    fetch. Treated as untrusted input throughout: it is scanned and quoted,
    never followed."""
    session = jw.session_with_headers()
    board = next((b for b in jw.BOARDS if b["slug"] == req["board"]), None)
    if not board:
        return ""
    try:
        records = jw.FETCHERS[board["platform"]](session, board)
    except Exception:  # noqa: BLE001
        return ""
    native = req["id"].rsplit(":", 1)[-1]
    for record in records:
        if str(record.get("id")) == native:
            if record.get("jd_text"):
                return record["jd_text"]
            if board["platform"] == "greenhouse":
                return jw.strip_html(_greenhouse_body(session, board, record))
            if board["platform"] == "workday":
                # enrich_workday returns the band and locations, not the body, so
                # the description comes from the posting endpoint directly.
                return _workday_body(session, board, record)
    return ""


def _workday_body(session, board, record):
    path = record.get("path") or ""
    url = "https://{}/wday/cxs/{}/{}{}".format(
        board["host"], board["tenant"], board["site"], path)
    try:
        response = session.get(url, headers={"Accept": "application/json"}, timeout=jw.TIMEOUT)
        response.raise_for_status()
        info = response.json().get("jobPostingInfo") or {}
        return jw.strip_html(info.get("jobDescription") or "")
    except Exception:  # noqa: BLE001
        return ""


def _greenhouse_body(session, board, record):
    url = "https://boards-api.greenhouse.io/v1/boards/{}/jobs/{}".format(
        board["board"], record["id"])
    try:
        response = session.get(url, timeout=jw.TIMEOUT)
        response.raise_for_status()
        return response.json().get("content") or ""
    except Exception:  # noqa: BLE001
        return ""


# --------------------------------------------------------------------------
# Gates
# --------------------------------------------------------------------------


def hits(text, terms):
    """Which of these terms appear, matched on word boundaries.

    Substring matching found 'rust' inside 'customer trust' and 'scala' inside
    'escalations', and reported an incident response role as a disguised SDE
    seat on that basis. A term list is only as good as the boundary around it.
    """
    low = text.lower()
    found = []
    for term in terms:
        pattern = re.escape(term.strip())
        if term.strip()[:1].isalnum():
            pattern = r"\b" + pattern
        if term.strip()[-1:].isalnum():
            pattern = pattern + r"\b"
        if re.search(pattern, low):
            found.append(term)
    return found


def run_gates(req, text, org):
    """Return (stopped_by, notes). Every gate reports, including the ones that
    passed, because a gate that silently never fires looks exactly like a gate
    that works."""
    notes = []
    stopped = None

    urgent = hits(text, URGENCY_TERMS)
    notes.append(("start date", "urgency language: " + ", ".join(urgent) if urgent
                  else "no urgency language", bool(urgent)))
    if urgent and not stopped:
        stopped = "start date"

    bars = hits(text, ELIGIBILITY_BARS)
    non_us = jw.is_non_us(req["title"], req.get("location"))
    fail = bool(bars) or non_us
    flagged = [(term, note) for term, note in ELIGIBILITY_FLAGS if hits(text, (term,))]
    if fail:
        detail = ", ".join(bars) if bars else "location is outside the US"
    elif flagged:
        detail = "; ".join("{}: {}".format(t, n) for t, n in flagged)
    else:
        detail = "no citizenship or clearance bar"
    notes.append(("eligibility", detail, fail))

    where = (req.get("location") or "").lower()
    remote = bool(hits(where, REMOTE_TERMS) or hits(text, REMOTE_PHRASES))
    home = bool(hits(where, HOME_METRO))
    onsite = hits(text, ONSITE_TERMS)
    self_move = hits(text, RELOCATION_BARS)
    away = not remote and not home and bool(where)
    move_fail = away and bool(self_move)
    if move_fail:
        detail = "{}, and the posting says {}".format(req.get("location"), self_move[0])
    elif away and onsite:
        detail = "{}, and the posting says {}".format(req.get("location"), onsite[0])
    elif remote:
        detail = "remote"
    elif home:
        detail = "home metro"
    else:
        detail = req.get("location") or "not stated"
    notes.append(("location", detail, move_fail))
    if move_fail and not stopped:
        stopped = "location"
    if fail and not stopped:
        stopped = "eligibility"

    junior = hits(req["title"], JUNIOR_TERMS)
    down = org is not None and level_move((org.get("comp") or {}).get("amazon_equiv")) == "down"
    fail = bool(junior) or down
    notes.append(("level",
                  ", ".join(junior) if junior else ("org maps below L6" if down
                                                    else "senior or above"),
                  fail))
    if fail and not stopped:
        stopped = "level"

    # The poller only sees a band where the board exposes one. Some boards put two
    # level bands in the description itself, so read the page before concluding
    # there is nothing to judge.
    band = req.get("pay_low") and (req["pay_low"], req["pay_high"])
    if not band:
        band = jw.parse_pay(text)
    equity = hits(text, EQUITY_TERMS)
    if not band:
        detail, fail = "no published band", False
    elif band[1] >= BASE_FLOOR:
        detail, fail = "top of band ${:,} base clears the floor".format(band[1]), False
    elif equity:
        detail = ("top of band ${:,} base is under the floor, but the page names {}, "
                  "so the total is not the band".format(band[1], ", ".join(equity)))
        fail = False
    else:
        detail = "top of band ${:,} base is under the floor and no equity is mentioned".format(band[1])
        fail = True
    notes.append(("comp", detail, fail))
    if fail and not stopped:
        stopped = "comp"

    warm = req["company"].lower().split()[0] in NEVER_AUTO
    notes.append(("never auto",
                  "warm intro preferred, do not treat as ready to send" if warm
                  else "portal submission is fine", False))
    return stopped, notes, warm


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

REQ_LINE = re.compile(r"^\s*[-•*]\s*(.+)$", re.M)
YEARS = re.compile(r"(\d+)\+?\s*years?", re.I)


TAG_RE = re.compile(r"<[^>]{1,200}>")
ENTITY = (("&amp;", "&"), ("&nbsp;", " "), ("&#39;", "'"), ("&quot;", '"'),
          ("&lt;", "<"), ("&gt;", ">"), ("&rsquo;", "'"), ("&mdash;", " "))


def strip_markup(text):
    """Greenhouse ships the description as HTML, so <li> and </li> were arriving
    inside requirement lines and being scored as words. Boards differ in what they
    hand back and the extractor should not have to know which is which."""
    out = TAG_RE.sub(" ", text)
    for entity, char in ENTITY:
        out = out.replace(entity, char)
    return re.sub(r"[ \t]{3,}", "  ", out)


def requirement_lines(text):
    """The posting's own requirement bullets, taken from the section that names
    them so the whole description is not treated as a checklist."""
    text = strip_markup(text)
    low = text.lower()
    # Take the first anchor that exists, in priority order, rather than the
    # earliest or latest position. "The ideal candidate" sits near the top of an
    # flat Workday posting and swept the benefits links in as unmet asks; switching to the
    # latest match then landed on "GDPR requirements preferred" deep in the prose
    # and swept almost everything out. A named section beats a common noun.
    body = text
    for anchor in ("qualifications", "you will have", "what you", "requirements:",
                   "looking for", "the ideal candidate"):
        found = low.find(anchor)
        if found >= 0:
            body = text[found:]
            break
    # Nothing after the legal tail is ever an ask.
    for stop in ("the annual base pay", "the job description is intended",
                 "f5 reserves the right", "equal employment", "reasonable accommodation"):
        end = body.lower().find(stop)
        if end > 0:
            body = body[:end]
    lines = [re.sub(r"\s+", " ", m.group(1)).strip() for m in REQ_LINE.finditer(body)]
    if lines:
        return lines[:20]
    # Some boards flatten their bullets. Workday ships the description as one
    # paragraph with the list markers replaced by runs of spaces, and the run is
    # TWO spaces between bullets, four between sections. Splitting on three or
    # more never split a single bullet, which is why an 8,848 character posting
    # with seven qualification bullets yielded one line.
    parts = [re.sub(r"\s+", " ", p).strip() for p in re.split(r"[ \t]{2,}|\n", body)]
    return [p for p in parts if 40 < len(p) < 800 or is_short_requirement(p)][:20]


# A length floor drops headings, and it also dropped "FedRAMP eligible", which is
# sixteen characters and the most consequential line in one posting. Short
# fragments are kept when they carry a term that decides whether I can hold the
# job at all.
SHORT_SIGNAL = tuple(t for t in ELIGIBILITY_BARS) + tuple(t for t, _ in ELIGIBILITY_FLAGS) + (
    "clearance", "citizen", "degree", "bachelor", "certification", "on-site", "onsite")


def is_short_requirement(part):
    return 8 <= len(part) <= 40 and bool(hits(part, SHORT_SIGNAL))


def terms(text):
    """Distinctive words, without the punctuation stuck to them.

    The bare regex kept "environments." and "investigations." as separate terms
    from the words themselves, so a gap list read as though the full stop were a
    missing skill.
    """
    found = re.findall(r"[a-z][a-z+#./-]{2,}", text.lower())
    return {w.strip("./-") for w in found if len(w.strip("./-")) >= 4} - STOP


def evidence_for(line, cv_texts):
    """The source bullet that proves a requirement, or None.

    Scoring is coverage of the REQUIREMENT, not raw count of shared words. A raw
    count let the 150 word summary paragraph stand as proof for seven different
    requirements at once, including CrowdStrike and DLP telemetry and PCI
    familiarity, none of which he has. A long paragraph shares three ordinary
    words with almost any sentence, so length was winning instead of relevance.
    """
    words = terms(line)
    if len(words) < 3:
        return None
    best, best_score = None, 0.0
    for cv_line in cv_texts:
        cv_words = terms(cv_line)
        shared = words & cv_words
        if len(shared) < 3:
            continue
        coverage = len(shared) / float(len(words))
        # Precision breaks ties toward the focused bullet rather than the summary.
        precision = len(shared) / float(len(cv_words) or 1)
        score = coverage + 0.25 * precision
        if coverage >= MIN_COVERAGE and score > best_score:
            best, best_score = cv_line, score
    return best


# A requirement is only met if the evidence covers this share of its distinctive
# terms. Calibrated on a flat Workday posting: it keeps the incident response and attack
# technique asks, and it drops CrowdStrike, the compliance frameworks and the
# time zone availability line, which is the honest outcome.
MIN_COVERAGE = 0.30


STOP = {"experience", "strong", "with", "that", "have", "years", "ability", "work",
        "working", "skills", "including", "such", "this", "role", "team", "teams",
        "will", "your", "into", "from", "across", "well", "good", "plus", "using",
        "about", "more", "than", "over", "them", "their", "both", "like", "also"}


def score_requirements(text, cv_texts):
    """Grade each requirement by how much of it the CV actually covers.

    Met or unmet is the wrong shape for these. A posting asks for "load
    balancing, reverse proxy, WAF, API security, DDoS protection, bot defense,
    Kubernetes ingress and public cloud security" in one breath, and the honest
    answer is that he owns four of those eight and not the others. A binary
    verdict either inflates that to met or throws the whole line away.

    So each line comes back with the terms covered, the terms missing, and a
    band. The missing list is the part worth reading, since it is the interview.
    """
    graded = []
    for line in requirement_lines(text):
        words = terms(line)
        if len(words) < 3:
            continue
        proof = evidence_for(line, cv_texts)
        everything = set().union(*[terms(c) for c in cv_texts]) if cv_texts else set()
        covered = sorted(words & everything)
        missing = sorted(words - everything)
        share = len(covered) / float(len(words))
        band = "strong" if share >= 0.5 else "partial" if share >= 0.25 else "gap"
        graded.append({"line": line, "proof": proof, "covered": covered,
                       "missing": missing, "share": share, "band": band})
    return graded


def fixed_gap_notes(text):
    out = []
    for terms, statement in (FIXED_GAPS, SDE_TELL):
        if hits(text, terms):
            out.append(statement)
    return out


# --------------------------------------------------------------------------
# Tailoring, by selection and ordering only
# --------------------------------------------------------------------------


def posting_terms(text):
    """The posting's own vocabulary, most frequent first."""
    counts = {}
    for word in re.findall(r"[a-zA-Z][a-zA-Z+#.\-]{3,}", text.lower()):
        if word not in STOP:
            counts[word] = counts.get(word, 0) + 1
    return counts


def overlap(line, counts):
    words = set(re.findall(r"[a-zA-Z][a-zA-Z+#.\-]{3,}", line.lower()))
    return sum(counts.get(w, 0) for w in words)


def tailor(doc, text):
    """Reorder the experience sub-sections by relevance and drop the weakest
    bullets until the page estimate fits. Returns the index order plus a log of
    what moved and what was cut."""
    counts = posting_terms(text)
    sections = doc.sections()
    labels = [dx.para_text(doc.blocks[h]) for h, _ in sections]

    try:
        exp_at = labels.index("PROFESSIONAL EXPERIENCE")
        end_at = next(i for i in range(exp_at + 1, len(labels))
                      if labels[i] in ("THOUGHT LEADERSHIP", "EARLIER EXPERIENCE"))
    except (ValueError, StopIteration):
        return list(range(len(doc.blocks))), ["structure not recognised, left as is"], []

    movable = sections[exp_at + 1:end_at]
    # Score per bullet, not in total. On one req the six-bullet detection
    # section scored 71 and the one-bullet ownership section scored 15, so the
    # long section ranked higher while the short one was stronger line for line,
    # and the single best-matched bullet on the CV ended up last.
    scored = []
    for head, members in movable:
        total = sum(overlap(dx.para_text(doc.blocks[i]), counts) for i in members)
        weight = total / float(len(members) or 1)
        scored.append((weight, head, members))
    ranked = sorted(scored, key=lambda s: -s[0])

    log = ["experience sub-sections reordered by overlap with the posting:"]
    for rank, (weight, head, _) in enumerate(ranked, start=1):
        was = [s[1] for s in scored].index(head) + 1
        log.append("  {}. {}  (score {}, was {})".format(
            rank, dx.para_text(doc.blocks[head])[:56], weight, was))

    order = []
    for index, (head, members) in enumerate(sections):
        if exp_at + 1 <= index < end_at:
            continue
        if index == exp_at:
            order.append(head)
            order.extend(members)
            for _, rhead, rmembers in ranked:
                order.append(rhead)
                order.extend(rmembers)
            continue
        order.append(head)
        order.extend(members)
    order = [i for i in range(len(doc.blocks)) if i not in set(order)] + order
    order = sorted(set(order), key=order.index) if False else order

    def words_in(indexes):
        return sum(len(dx.para_text(doc.blocks[i]).split()) for i in indexes)

    cut = []
    while len(order) > MAX_PARAGRAPHS or words_in(order) > MAX_WORDS:
        bullets = [i for i in order if dx.is_bullet(doc.blocks[i])]
        if len(bullets) <= 12:
            break
        weakest = min(bullets, key=lambda i: overlap(dx.para_text(doc.blocks[i]), counts))
        order.remove(weakest)
        cut.append(dx.para_text(doc.blocks[weakest]))
    if cut:
        log.append("dropped {} bullet(s) to hold two pages:".format(len(cut)))
        log.extend("  - " + c[:88] for c in cut)
    log.append("{} paragraphs, {} words (budget {} / {})".format(
        len(order), words_in(order), MAX_PARAGRAPHS, MAX_WORDS))
    return order, log, cut


def competencies_line(doc, text):
    """Rebuild the keyword line from terms that already appear on my own CVs,
    ordered by how much the posting uses them. No term is introduced."""
    index = doc.find("Core competencies")
    if index is None:
        return None, None
    current = dx.para_text(doc.blocks[index])
    prefix, _, rest = current.partition(":")
    mine = [t.strip() for t in re.split(r"[•|]", rest) if t.strip()]
    counts = posting_terms(text)
    ranked = sorted(mine, key=lambda t: -overlap(t, counts))
    return index, "{}: {}".format(prefix.strip(), " • ".join(ranked))


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def fact_diff(source_path, out_path, allowed):
    """Every paragraph in the output must be byte-identical to one in the source
    unless it is a whitelisted line. Anything else is an invented claim."""
    source = {b for b in dx.Document(source_path).blocks}
    problems = []
    for block in dx.Document(out_path).blocks:
        if block in source:
            continue
        if dx.para_text(block) in allowed:
            continue
        problems.append(dx.para_text(block))
    return problems


def extract_any(path):
    """What a parser reads, from either format. A .docx is read as XML, which is
    what a resume parser does. A .pdf goes through pdftotext, which is what an
    ATS text-layer check means."""
    if path.lower().endswith(".pdf"):
        import subprocess
        try:
            out = subprocess.run(["pdftotext", "-layout", path, "-"],
                                 capture_output=True, timeout=30)
            return [l.strip() for l in out.stdout.decode("utf-8", "ignore").splitlines()
                    if l.strip()]
        except Exception:  # noqa: BLE001
            return []
    return dx.extract_text(path)


def ats_check(path, text):
    lines = extract_any(path)
    words = sum(len(l.split()) for l in lines)
    counts = posting_terms(text)
    key = [t for t, n in sorted(counts.items(), key=lambda kv: -kv[1])[:40] if n > 1]
    blob = " ".join(lines).lower()
    present = [t for t in key if t in blob]
    return {
        "lines": lines,
        "words": words,
        "ok": words >= MIN_ATS_WORDS,
        "terms_total": len(key),
        "terms_present": len(present),
        "missing": [t for t in key if t not in present][:15],
    }


def house_style(text):
    problems = []
    for dash in DASHES:
        if dash in text:
            problems.append("contains {}".format("em dash" if dash == DASHES[0] else "en dash"))
    for match in re.finditer(r"\b(\w[\w ]{2,30}), not \w", text):
        problems.append('contrastive "X, not Y": ' + match.group(0)[:60])
    return problems


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def slugify(value):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")[:48]


def write_packet(req, org, variant_key, source_path, out_dir, text,
                 gate_notes, warm, graded, fixed, tailor_log, ats, diff):
    os.makedirs(out_dir, exist_ok=True)
    resume = RESUMES[variant_key]
    verdict = "apply via warm intro" if warm else "apply"

    with io.open(os.path.join(out_dir, "fit-report.md"), "w", encoding="utf-8") as h:
        h.write("# {}\n\n{}\n\n".format(req["title"], req["company"]))
        h.write("- Req: {}\n- Location: {}\n- Variant: {}\n".format(
            req["url"], req.get("location") or "not stated", resume["label"]))
        if req.get("pay_low"):
            h.write("- Posted band: ${:,} to ${:,}, base only\n".format(
                req["pay_low"], req["pay_high"]))
        h.write("\n## Verdict\n\n**{}**\n\n".format(verdict))
        if warm:
            h.write("This company is on the never-auto list. The packet is ready, but a "
                    "referral is worth more than a portal submission here.\n\n")
        h.write("## Gates\n\n")
        for name, detail, failed in gate_notes:
            h.write("- {} **{}**: {}\n".format("FAIL" if failed else "pass", name, detail))
        h.write("\n## Requirement vocabulary coverage\n\n")
        h.write("The percentage is how many of a requirement's distinctive words appear anywhere\n"
                "on the CV. It measures vocabulary, not capability, and it will rate a time zone\n"
                "availability line as highly as a technical one. **The missing lists are the part\n"
                "worth reading.** They are the interview.\n")
        for band, heading in (("strong", "Most vocabulary present"),
                              ("partial", "Some vocabulary present"),
                              ("gap", "Little vocabulary present")):
            rows = [g for g in graded if g["band"] == band]
            if not rows:
                continue
            h.write("\n## {}\n\n".format(heading))
            for g in rows:
                h.write("- **{:.0%}** {}\n".format(g["share"], g["line"][:220]))
                if g["proof"]:
                    h.write("  - evidence: {}\n".format(g["proof"][:200]))
                if g["missing"]:
                    h.write("  - not on my CV: {}\n".format(", ".join(g["missing"][:14])))
        if fixed:
            h.write("\n## Fixed gap notes\n\n")
            for statement in fixed:
                h.write("- {}\n".format(statement))


    with io.open(os.path.join(out_dir, "fact-diff.txt"), "w", encoding="utf-8") as h:
        h.write("Every paragraph in the tailored CV must be byte-identical to one in\n")
        h.write("{}\nexcept the two whitelisted lines.\n\n".format(os.path.basename(source_path)))
        if diff:
            h.write("PROBLEMS, these do not trace to the source:\n")
            for p in diff:
                h.write("  - {}\n".format(p[:160]))
        else:
            h.write("Clean. No claim in the output that was not in the source.\n")
        h.write("\n" + "\n".join(tailor_log) + "\n")

    with io.open(os.path.join(out_dir, "ats-check.txt"), "w", encoding="utf-8") as h:
        h.write("words extractable: {}  (floor {})  {}\n".format(
            ats["words"], MIN_ATS_WORDS, "OK" if ats["ok"] else "FAIL"))
        h.write("posting terms present: {} of {}\n".format(
            ats["terms_present"], ats["terms_total"]))
        if ats["missing"]:
            h.write("not present: {}\n".format(", ".join(ats["missing"])))
        h.write("\n--- what a parser reads ---\n")
        for line in ats["lines"]:
            h.write(line + "\n")

    with io.open(os.path.join(out_dir, "answers.md"), "w", encoding="utf-8") as h:
        h.write("# Draft answers, edit before sending\n\n")
        h.write("Grounded only in the source CV. Where a question needs a number I do not\n"
                "have, it says so rather than inventing one.\n\n")
        for question in ANSWER_PROMPTS:
            h.write("## {}\n\n_Draft._ {}\n\n".format(question[0], question[1]))
        h.write("## Dropdowns and self-assessments\n\n")
        h.write("Pick the lowest option that is true. Overclaiming on a screening question is\n"
                "the fastest way to lose credibility in the interview that follows.\n")

    with io.open(os.path.join(out_dir, "checklist.md"), "w", encoding="utf-8") as h:
        h.write("# Before I submit\n\n")
        for item in (
            "Read fit-report.md, especially the requirements I do not meet.",
            "Read fact-diff.txt. If it is not clean, do not send the CV.",
            "Read ats-check.txt and confirm the employer name and key terms are there.",
            "Open the docx in Word and confirm it is two pages and looks right.",
            "Edit answers.md into my own words.",
            "Submit it myself. Nothing here has been sent.",
        ):
            h.write("- [ ] {}\n".format(item))
        if warm:
            h.write("- [ ] Never-auto company: find a referral before using the portal.\n")


ANSWER_PROMPTS = (
    ("Why this company",
     "Name the specific team and the specific problem, from the org note and the posting. "
     "Not enthusiasm."),
    ("Something you built that you think is genuinely cool",
     "The attack-to-rule compilation pipeline: 71 compiled rules for DNS vectors, each "
     "validated to zero false positives against clean baseline traffic before deploy, each "
     "traceable to the packet evidence that produced it."),
    ("Detection logic in cloud-native environments",
     "Multi-signal suspicion scoring across ASN reputation, volume anomalies, protocol "
     "violations, 5-tuple behaviour and temporal characteristics."),
    ("Automated security response workflows in Python",
     "The multi-agent triage system in daily production use, and the context routing that "
     "cut orchestration consumption from 42% to 18%."),
    ("Leading incident response in complex infrastructure",
     "First responder for DDoS events against AWS global infrastructure and thousands of "
     "Shield Advanced customers, plus the Sev2 reduction working group across six teams."),
    ("Judging whether a DNS request to an unknown domain is suspicious",
     "Answer from production: honeypot correlation, C2 directive patterns, registration and "
     "resolution behaviour, and why header values are the wrong thing to key on."),
)


# --------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Prepare an application. Never submits.")
    parser.add_argument("req", nargs="?", help="req id or URL")
    parser.add_argument("--variant", choices=sorted(RESUMES), help="override the routing")
    parser.add_argument("--dry", action="store_true", help="gates and score only, write nothing")
    parser.add_argument("--log", metavar="ID", help="record an outcome")
    parser.add_argument("--outcome", help="with --log")
    parser.add_argument("--reason", default="", help="with --log")
    args = parser.parse_args()

    if args.log:
        return record_outcome(args.log, args.outcome, args.reason)
    if not args.req:
        parser.print_help()
        return 2

    req = find_req(args.req)
    if not req:
        print("no live req matching {}".format(args.req), file=sys.stderr)
        return 2

    orgs = load_json(ORGS_PATH, "organizations")
    org = next((o for o in orgs if o.get("board") == req["board"]), None)

    print("{}  |  {}".format(req["company"], req["title"]), file=sys.stderr)
    text = posting_text(req)
    if not text:
        print("could not read the posting body, so nothing can be gated honestly",
              file=sys.stderr)
        return 2
    print("posting: {:,} characters".format(len(text)), file=sys.stderr)

    stopped, notes, warm = run_gates(req, text, org)
    for name, detail, failed in notes:
        print("  {} {:<12} {}".format("FAIL" if failed else "pass", name, detail),
              file=sys.stderr)
    if stopped:
        print("\nstopped by the {} gate. Nothing written.".format(stopped), file=sys.stderr)
        return 1

    variant_key = args.variant or rs.competency_for(req["title"])["cv"]
    source_path = os.path.join(RESUME_DIR, variant_key + ".docx")
    if not os.path.exists(source_path):
        print("no source variant at {}".format(source_path), file=sys.stderr)
        return 2

    doc = dx.Document(source_path)
    cv_texts = [t for t in doc.texts() if len(t.split()) > 6]
    graded = score_requirements(text, cv_texts)
    fixed = fixed_gap_notes(text)
    bands = {b: len([g for g in graded if g["band"] == b]) for b in ("strong", "partial", "gap")}
    print("\nrequirements: {} covered well, {} partial, {} gaps, {} fixed note(s)".format(
        bands["strong"], bands["partial"], bands["gap"], len(fixed)), file=sys.stderr)
    for g in graded:
        if g["band"] == "gap":
            print("  gap  {}".format(g["line"][:96]), file=sys.stderr)

    if args.dry:
        print("dry run, nothing written", file=sys.stderr)
        return 0

    order, tailor_log, _cut = tailor(doc, text)
    comp_index, comp_line = competencies_line(doc, text)
    allowed = set()
    if comp_index is not None and comp_index in order:
        doc.set_text(comp_index, comp_line)
        allowed.add(comp_line)
    doc.keep(order)

    out_dir = os.path.join(OUT_ROOT, "{}-{}".format(
        slugify(req["company"]), slugify(req["title"])))
    os.makedirs(out_dir, exist_ok=True)
    # Recruiters download a lot of files called resume.docx. Lead with your name.
    out_name = "{} - {} {}.docx".format(CANDIDATE_NAME, req["company"], req["title"])[:120]
    out_path = doc.save(os.path.join(out_dir, out_name))

    diff = fact_diff(source_path, out_path, allowed)
    ats = ats_check(out_path, text)
    write_packet(req, org, variant_key, source_path, out_dir, text,
                 notes, warm, graded, fixed, tailor_log, ats, diff)

    print("\nvariant     {}".format(RESUMES[variant_key]["label"]), file=sys.stderr)
    print("fact diff   {}".format("clean" if not diff else
                                  "{} PROBLEM(S)".format(len(diff))), file=sys.stderr)
    print("ats         {} words, {} of {} posting terms present  {}".format(
        ats["words"], ats["terms_present"], ats["terms_total"],
        "OK" if ats["ok"] else "FAIL"), file=sys.stderr)
    print("packet      {}".format(out_dir), file=sys.stderr)
    print("\nNothing submitted. Read checklist.md, then submit it yourself.", file=sys.stderr)
    return 0


def record_outcome(req_id, outcome, reason):
    with io.open(APPS_PATH, encoding="utf-8") as handle:
        doc = json.load(handle)
    req = find_req(req_id)
    if not req:
        print("no req matching {}".format(req_id), file=sys.stderr)
        return 2
    app = next((a for a in doc["applications"]
                if a["company"] == req["company"] and a.get("match") == req["title"]), None)
    if not app:
        print("no application logged for that req", file=sys.stderr)
        return 2
    app["status"] = outcome or app["status"]
    app["last_contact"] = date.today().isoformat()
    if reason:
        app["note"] = (app.get("note") or "") + " " + reason
    doc["updated"] = date.today().isoformat()
    with io.open(APPS_PATH, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print("{}: {}".format(req["company"], outcome))
    print("If the reason names something checkable before applying, it belongs in a gate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
