#!/usr/bin/env python3
"""Measure a CV instead of estimating it: real pages, real extractable text.

Two failures made this necessary. A PDF went to an employer that an applicant
tracking system read as 105 words, with the employer's own name absent, because the
export path broke the text layer and nothing checked. And a tailored document
went out at three pages, because the only length check was a paragraph
count standing in for a page count.

Word is the only thing on this machine that can paginate a .docx, so it is driven
through AppleScript to export a PDF, and the PDF is read back with pdftotext.
That is the same path a recruiter's parser takes, which is the point.

    python3 verify.py resumes/dr.docx [more.docx ...]
"""

import os
import subprocess
import sys
import tempfile

MAX_PAGES = 2
MIN_WORDS = 900
# Strings that must survive the round trip into the PDF. Set these to your current
# employer, team and title. If any of them fails to extract, the text layer is
# broken even when the page looks correct on screen.
MUST_APPEAR = ()

# Word leaves documents open if anything throws mid-script, and a stale open copy
# is what a later run then repaginates. Close in a try block, and never quit an
# instance the user already had running.
SCRIPT = '''
tell application "Microsoft Word"
  set wasRunning to running
  try
    open POSIX file "{src}"
    set d to active document
    repaginate d
    save as d file name "{out}" file format format PDF
  end try
  try
    repeat while (count of documents) > 0
      close active document saving no
    end repeat
  end try
  if not wasRunning then quit
end tell
'''


def to_pdf(docx_path):
    out = os.path.join(tempfile.mkdtemp(), "check.pdf")
    # Word can sit for a long time on a first launch or a repair prompt, so cap it
    # rather than letting a hung dialog block the whole run.
    try:
        subprocess.run(["osascript", "-e", SCRIPT.format(src=os.path.abspath(docx_path), out=out)],
                       check=False, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Word did not respond within 90 seconds. It is sitting on a dialog. "
                           "Bring Word to the front, dismiss it, close any open documents, "
                           "then run this again.")
    if not os.path.exists(out):
        raise RuntimeError(
            "Word produced no PDF for {}. It is usually wedged on a dialog; open Word, "
            "dismiss it, close any stray documents, then re-run.".format(
                os.path.basename(docx_path)))
    return out


def report(docx_path):
    pdf = to_pdf(docx_path)
    info = subprocess.run(["pdfinfo", pdf], capture_output=True, text=True).stdout
    pages = next((int(l.split()[1]) for l in info.splitlines() if l.startswith("Pages")), 0)
    text = subprocess.run(["pdftotext", "-layout", pdf, "-"],
                          capture_output=True, text=True).stdout
    words = len(text.split())
    missing = [t for t in MUST_APPEAR if t.lower() not in text.lower()]

    problems = []
    if pages > MAX_PAGES:
        problems.append("{} pages, over the {} page limit".format(pages, MAX_PAGES))
    if words < MIN_WORDS:
        problems.append("only {} extractable words, the text layer is broken".format(words))
    if missing:
        problems.append("does not extract: " + ", ".join(missing))

    print("{}\n  {} pages, {} extractable words".format(
        os.path.basename(docx_path), pages, words))
    for problem in problems:
        print("  FAIL  " + problem)
    if not problems:
        print("  OK    reads clean end to end")
    return not problems


if __name__ == "__main__":
    paths = sys.argv[1:] or ["resumes/general.docx"]
    results = []
    for path in paths:
        try:
            results.append(report(path))
        except RuntimeError as problem:
            print("{}\n  BLOCKED  {}".format(os.path.basename(path), problem))
            results.append(False)
    sys.exit(0 if all(results) else 1)
