#!/usr/bin/env python3
"""Tests for the parts of the apply module that have shipped wrong answers.

Every test here has a companion that MUST fail. A checker that only ever sees
input it handles has not been tested, it has just been watched not complaining.
That is how a substring match read 'rust' inside 'customer trust', how an
eligibility list without FedRAMP in it passed a posting that says FedRAMP, and
how a patch that changed no bytes printed "patched".
"""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import apply
import taxonomy as tx

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fixture(name):
    with io.open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return handle.read()


class TermMatching(unittest.TestCase):
    def test_whole_words_only(self):
        self.assertEqual(apply.hits("customer trust and escalations", ("rust", "scala")), [])
        self.assertEqual(apply.hits("governance and roadmap", (" go ",)), [])

    def test_still_matches_the_real_thing(self):
        """The failing companion. If boundaries broke matching outright this passes
        nothing, and the fix would be worse than the bug."""
        self.assertEqual(apply.hits("5 years of Rust and Scala", ("rust", "scala")),
                         ["rust", "scala"])
        self.assertIn("kafka", apply.hits("experience with Kafka streams", ("kafka",)))


class RequirementExtraction(unittest.TestCase):
    def setUp(self):
        self.text = fixture("workday_flat.txt")
        self.lines = apply.requirement_lines(self.text)

    def test_finds_the_qualification_bullets(self):
        """Workday separates flattened bullets with TWO spaces. Requiring three
        returned one line from a posting with seven bullets."""
        self.assertGreaterEqual(len(self.lines), 7)
        joined = " ".join(self.lines).lower()
        for expected in ("10+ years", "crowdstrike", "fedramp",
                         "load balancing", "nist"):
            self.assertIn(expected, joined, "lost a real requirement: " + expected)

    def test_excludes_the_legal_tail(self):
        """The failing companion. Anchoring on 'The ideal candidate' swept the
        benefits link and the EEO paragraph in as requirements."""
        joined = " ".join(self.lines).lower()
        for boilerplate in ("benefits can be found", "reserves the right",
                            "annual base pay", "reasonable accommodation",
                            "not be all-inclusive"):
            self.assertNotIn(boilerplate, joined, "boilerplate read as a requirement")


class EligibilityGate(unittest.TestCase):
    """Written for a lawful permanent resident, the WORK_STATUS default. An LPR is
    a US Person under ITAR and the EAR, needs no sponsorship, and is not a
    citizen, so citizenship and clearance bar and the rest do not."""

    def bars(self, text):
        return apply.hits(text, tx.ELIGIBILITY_BARS)

    def test_citizenship_and_clearance_are_bars(self):
        self.assertTrue(self.bars("Must be a U.S. citizen."))
        self.assertTrue(self.bars("Active security clearance required."))
        self.assertTrue(self.bars("TS/SCI required."))

    def test_us_person_language_is_not_a_bar(self):
        """The failing companion, and the one that cost real reqs. Export control
        wording appears across US infrastructure security postings."""
        for text in ("Subject to export control regulations.",
                     "Must be a US Person under ITAR.",
                     "We do not offer sponsorship for this role.",
                     "Green card holder only."):
            self.assertEqual(self.bars(text), [], "blocked a role an LPR can take: " + text)

    def test_fedramp_is_flagged_but_does_not_bar(self):
        text = fixture("workday_flat.txt")
        self.assertEqual(self.bars(text), [])
        flagged = [t for t, _ in tx.ELIGIBILITY_FLAGS if apply.hits(text, (t,))]
        self.assertIn("fedramp", flagged, "FedRAMP present in the posting and not reported")


class PageBudget(unittest.TestCase):
    def test_word_budget_is_calibrated_on_real_files(self):
        """1,195 words rendered as two pages and 1,308 as three, both measured
        from Word's own count. The budget has to sit between them."""
        self.assertLess(1195, apply.MAX_WORDS)
        self.assertLess(apply.MAX_WORDS, 1308)

class WarmJoin(unittest.TestCase):
    def test_matches_on_company_not_substring(self):
        """A short company key can appear inside an unrelated job id. Matching on
        the whole record rather than the company field reported the wrong company
        as a hit and made the result look richer than it was."""
        contacts = {"ac": {"company": "AC", "furthest_stage": "referral only", "people": []}}
        jobs = [{"company": "Northline", "title": "Senior Security Engineer",
                 "url": "https://jobs.example.com/northline/10ac51a3-17eb-4eed"},
                {"company": "AC", "title": "Principal Security Engineer - Incident Response",
                 "url": "https://ac.example.com/x"}]
        matched = [j for j in jobs if j.get("company", "").lower() in contacts]
        self.assertEqual([j["company"] for j in matched], ["AC"])


class LocationGate(unittest.TestCase):
    """Seattle, and not funding a move. Non-US was gated; a domestic onsite req
    that expects a self-funded relocation was not."""

    def test_self_funded_relocation_reads_as_a_bar(self):
        for phrase in ("Must be local to SF bay area or willing to relocate on their own.",
                       "Relocation is not provided for this role.",
                       "No relocation assistance available."):
            self.assertTrue(apply.hits(phrase, tx.RELOCATION_BARS), phrase)

    def test_remote_and_home_metro_are_not_bars(self):
        """The failing companion. Most of the live reqs are US remote or Seattle,
        and a gate that catches those catches nearly everything."""
        for where in ("US, Remote", "Remote - USA", "Seattle", "Bellevue, WA"):
            self.assertTrue(apply.hits(where.lower(), tx.REMOTE_TERMS)
                            or apply.hits(where.lower(), tx.HOME_METRO), where)


if __name__ == "__main__":
    # Appending a class below this block defines it after main() has already
    # run, so the test never executes and the count quietly stays the same.
    # Assert the count instead of trusting it.
    EXPECTED = 11
    found = sum(len(unittest.TestLoader().loadTestsFromTestCase(c)._tests)
                for c in (TermMatching, RequirementExtraction, EligibilityGate,
                          PageBudget, WarmJoin, LocationGate))
    assert found == EXPECTED, "expected {} tests, collected {}".format(EXPECTED, found)
    unittest.main(verbosity=2)
