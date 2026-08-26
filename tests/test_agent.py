#!/usr/bin/env python3
"""Honesty, gating, and invent-nothing tests for the tailor CLI."""

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from taxonomy import competency_for, detect_skills, gate_req, is_non_us  # noqa: E402
from tailor import (  # noqa: E402
    WEASEL,
    evaluate,
    invented_claims,
    render_result,
    score_fit,
    tailor_cv,
)

CV_DIR = os.path.join(ROOT, "examples", "cvs")
JD_DIR = os.path.join(ROOT, "examples", "jds")


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def cv(name):
    return _read(os.path.join(CV_DIR, name + ".md"))


def jd(name):
    return _read(os.path.join(JD_DIR, name + ".md"))


VIABLE = {
    "title": "DDoS Mitigation Engineer",
    "company": "Acme Cloud",
    "location": "Denver, CO",
    "pay_low": 250000,
    "pay_high": 310000,
    "id": "greenhouse:acme:100",
}

ORG_L6 = {"name": "Acme Cloud", "board": "acme", "comp": {"amazon_equiv": "L6"}}
ORG_DOWN = {"name": "Downco", "board": "downco", "comp": {"amazon_equiv": "L5"}}


class ScoringHonestyTests(unittest.TestCase):
    """Gaps the CV does not meet must surface. Never phrase around them."""

    def test_missing_skills_are_named_as_gaps(self):
        result = score_fit(jd("gaps"), cv("edge_ddos"))
        gap_keys = {item["key"] for item in result["gaps"]}
        for key in ("edr", "siem", "compiled", "etl", "cloud", "detection_eng", "years"):
            self.assertIn(key, gap_keys, "gap {} did not surface".format(key))
        for item in result["gaps"]:
            self.assertEqual(item.get("detail"), "not in CV")
        self.assertEqual(result["matched"], 0)

    def test_held_skills_are_the_ones_the_cv_actually_names(self):
        result = score_fit(jd("greenhouse_acme_100"), cv("edge_ddos"))
        held = {item["key"] for item in result["held"]}
        gaps = {item["key"] for item in result["gaps"]}
        self.assertIn("ddos", held)
        self.assertIn("python", held)
        self.assertIn("edr", gaps)
        self.assertIn("siem", gaps)
        self.assertIn("etl", gaps)
        self.assertIn("years", gaps)
        self.assertNotIn("edr", held)
        self.assertNotIn("siem", held)

    def test_gap_report_does_not_phrase_around_the_miss(self):
        result = evaluate(VIABLE, cv("edge_ddos"), jd("greenhouse_acme_100"), org=ORG_L6)
        report = render_result(result).lower()
        self.assertIn("not in cv", report)
        self.assertIn("edr", report)
        for phrase in WEASEL:
            self.assertNotIn(phrase, report)
            for item in result["score"]["gaps"]:
                blob = " ".join(
                    str(item.get(field) or "") for field in ("label", "evidence", "detail")
                ).lower()
                self.assertNotIn(phrase, blob)

    def test_score_uses_the_provided_cv_not_the_profile_band(self):
        """SKILLS band 'gap' is a judgement about one person. A CV that names
        EDR must count it as held, even though the published band calls it a gap."""
        cv_with_edr = cv("edge_ddos") + "\nEDR and Splunk experience.\n"
        result = score_fit(jd("greenhouse_acme_100"), cv_with_edr)
        held = {item["key"] for item in result["held"]}
        gaps = {item["key"] for item in result["gaps"]}
        self.assertIn("edr", held)
        self.assertIn("siem", held)
        self.assertNotIn("edr", gaps)
        self.assertNotIn("siem", gaps)

    def test_years_shortfall_is_a_named_gap(self):
        result = score_fit(jd("greenhouse_acme_100"), cv("edge_ddos"))
        years = result["years"]
        self.assertIsNotNone(years)
        self.assertIn("10", years["evidence"])
        self.assertIn("8", years["evidence"])
        self.assertEqual(years["detail"], "not in CV")


class GatingTests(unittest.TestCase):
    """Non-viable reqs are skipped before any tailoring work."""

    def test_non_us_location_is_not_viable(self):
        self.assertTrue(is_non_us("DDoS Engineer", "London, UK"))
        req = dict(VIABLE, location="London, UK")
        result = evaluate(req, cv("edge_ddos"), jd("greenhouse_acme_100"), org=ORG_L6)
        self.assertFalse(result["viable"])
        self.assertEqual(result["skipped"], "not viable")
        self.assertIsNone(result["score"])
        self.assertIsNone(result["draft"])
        location = [c for c in result["gate"]["checks"] if c["gate"] == "location"][0]
        self.assertFalse(location["ok"])

    def test_posted_band_below_floor_is_not_viable(self):
        req = dict(VIABLE, pay_low=80000, pay_high=90000)
        result = evaluate(req, cv("edge_ddos"), jd("greenhouse_acme_100"), org=ORG_L6)
        self.assertFalse(result["viable"])
        self.assertEqual(result["skipped"], "not viable")
        self.assertIsNone(result["draft"])
        self.assertIsNone(result["score"])
        comp = [c for c in result["gate"]["checks"] if c["gate"] == "comp"][0]
        self.assertFalse(comp["ok"])
        self.assertIn("base only", comp["detail"])

    def test_down_level_is_not_viable(self):
        result = evaluate(VIABLE, cv("edge_ddos"), jd("greenhouse_acme_100"), org=ORG_DOWN)
        self.assertFalse(result["viable"])
        self.assertEqual(result["skipped"], "not viable")
        self.assertIsNone(result["draft"])
        self.assertIsNone(result["score"])
        level = [c for c in result["gate"]["checks"] if c["gate"] == "level"][0]
        self.assertFalse(level["ok"])

    def test_gate_req_is_the_same_verdict_evaluate_uses(self):
        req = dict(VIABLE, location="Singapore")
        self.assertFalse(gate_req(req, org=ORG_L6)["viable"])
        self.assertTrue(gate_req(VIABLE, org=ORG_L6)["viable"])
        self.assertFalse(gate_req(VIABLE, org=ORG_DOWN)["viable"])

    def test_unknown_band_and_unresolved_level_stay_viable(self):
        req = {
            "title": "DDoS Mitigation Engineer",
            "location": "Remote, US",
            "pay_high": None,
        }
        gate = gate_req(req, org={"comp": {"amazon_equiv": None}})
        self.assertTrue(gate["viable"])
        result = evaluate(req, cv("edge_ddos"), jd("greenhouse_acme_100"))
        self.assertTrue(result["viable"])
        self.assertIsNotNone(result["draft"])

    def test_force_still_records_the_failed_gate(self):
        req = dict(VIABLE, location="London, UK")
        result = evaluate(
            req, cv("edge_ddos"), jd("greenhouse_acme_100"), org=ORG_L6, force=True
        )
        self.assertFalse(result["viable"])
        self.assertIsNotNone(result["draft"])
        self.assertIsNotNone(result["score"])


class InventNothingTests(unittest.TestCase):
    """Output claims must be traceable to the CV. The JD cannot donate facts."""

    def test_draft_numbers_and_skills_are_a_subset_of_the_cv(self):
        source = cv("dr")
        draft = tailor_cv(source, jd("greenhouse_acme_100"))
        invented = invented_claims(source, draft)
        self.assertEqual(invented["numbers"], [])
        self.assertEqual(invented["skills"], [])

    def test_draft_does_not_absorb_jd_requirements(self):
        source = cv("dr")
        draft = tailor_cv(source, jd("gaps"))
        lowered = draft.lower()
        for banned in (
            "edr",
            "splunk",
            "golang",
            "rust",
            "kafka",
            "kubernetes",
            "terraform",
            "sentinelone",
            "osquery",
        ):
            self.assertNotIn(banned, lowered)
        self.assertNotIn("12+", draft)
        invented = invented_claims(source, draft)
        self.assertEqual(invented["numbers"], [])
        self.assertEqual(invented["skills"], [])

    def test_evaluate_draft_is_traceable_for_every_variant(self):
        posting = jd("greenhouse_acme_100")
        for name in ("edge_ddos", "dr", "waf_edge", "general", "ai_sec"):
            result = evaluate(VIABLE, cv(name), posting, org=ORG_L6)
            self.assertTrue(result["viable"], name)
            invented = invented_claims(cv(name), result["draft"])
            self.assertEqual(invented["numbers"], [], name)
            self.assertEqual(invented["skills"], [], name)

    def test_top_third_moves_the_posting_language_up(self):
        source = cv("dr")
        self.assertIn("Northline Response", source.split("###")[1])
        draft = tailor_cv(source, jd("greenhouse_acme_100"))
        first_job = draft.split("###")[1]
        self.assertIn("Harbor Edge", first_job)
        self.assertIn("DDoS", first_job)

    def test_competency_map_picks_the_variant(self):
        result = evaluate(VIABLE, cv("edge_ddos"), jd("greenhouse_acme_100"), org=ORG_L6)
        self.assertEqual(result["competency"]["key"], "ddos")
        self.assertEqual(result["resume_variant"]["key"], "edge_ddos")
        waf = dict(VIABLE, title="WAF Platform Engineer")
        result = evaluate(waf, cv("waf_edge"), jd("greenhouse_acme_100"), org=ORG_L6)
        self.assertEqual(result["competency"]["cv"], "waf_edge")
        self.assertEqual(competency_for("Detection and Response Engineer")["cv"], "dr")


class CliTests(unittest.TestCase):
    def test_json_cli_emits_score_variant_and_draft(self):
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(ROOT, "tailor.py"),
                "--jd",
                os.path.join(JD_DIR, "greenhouse_acme_100.md"),
                "--cv-dir",
                CV_DIR,
                "--title",
                "DDoS Mitigation Engineer",
                "--company",
                "Acme Cloud",
                "--location",
                "Denver, CO",
                "--pay-low",
                "250000",
                "--pay-high",
                "310000",
                "--amazon-equiv",
                "L6",
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["viable"])
        self.assertEqual(payload["resume_variant"]["key"], "edge_ddos")
        self.assertTrue(payload["score"]["gaps"])
        self.assertIn("not in CV", payload["score"]["gaps"][0]["detail"])
        self.assertTrue(payload["draft"])
        invented = invented_claims(cv("edge_ddos"), payload["draft"])
        self.assertEqual(invented["numbers"], [])
        self.assertEqual(invented["skills"], [])

    def test_cli_skips_a_non_viable_req(self):
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(ROOT, "tailor.py"),
                "--jd",
                os.path.join(JD_DIR, "greenhouse_acme_100.md"),
                "--cv",
                os.path.join(CV_DIR, "edge_ddos.md"),
                "--title",
                "DDoS Mitigation Engineer",
                "--location",
                "London, UK",
                "--pay-high",
                "310000",
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["viable"])
        self.assertEqual(payload["skipped"], "not viable")
        self.assertIsNone(payload["draft"])

    def test_sample_state_req_with_jd_dir(self):
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(ROOT, "tailor.py"),
                "--state",
                os.path.join(ROOT, "examples", "jobwatch_state.sample.json"),
                "--orgs",
                os.path.join(ROOT, "examples", "organizations.sample.json"),
                "--req",
                "greenhouse:acme:100",
                "--jd-dir",
                JD_DIR,
                "--cv-dir",
                CV_DIR,
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["viable"])
        self.assertEqual(payload["req"]["company"], "Acme Cloud")
        self.assertEqual(payload["resume_variant"]["key"], "edge_ddos")
        self.assertIsNotNone(payload["draft"])


class SharedVocabularyTests(unittest.TestCase):
    def test_poller_and_tailor_share_is_non_us(self):
        import jobwatch

        self.assertIs(jobwatch.is_non_us, is_non_us)

    def test_renderer_and_tailor_share_competency_for(self):
        import render_site

        self.assertIs(render_site.competency_for, competency_for)
        self.assertEqual(competency_for("DDoS Mitigation Engineer")["cv"], "edge_ddos")
        self.assertEqual(competency_for("WAF Platform Engineer")["cv"], "waf_edge")

    def test_detect_skills_agrees_on_the_fixture_jd(self):
        keys = set(detect_skills(jd("gaps")))
        self.assertTrue({"edr", "siem", "compiled", "etl", "cloud", "detection_eng"} <= keys)


if __name__ == "__main__":
    unittest.main()
