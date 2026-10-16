#!/usr/bin/env python3
"""Fail-closed sanitizer: every public record either comes out clean or not at all.

Each PII and secret pattern has a companion that MUST raise when redaction is
skipped, so a detector that never fires cannot hide behind a passing suite.
"""

import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sanitizer
from sanitizer import SanitizerBlocked, sanitize, sanitize_records, scan_public_text

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def example(name):
    with io.open(os.path.join(EXAMPLES, name), encoding="utf-8") as handle:
        return json.load(handle)


def app(note):
    return {
        "company": "Acme Cloud",
        "title": "DDoS Mitigation Engineer",
        "status": "confirmed",
        "note": note,
    }


CLEAN_JOB = {
    "id": "greenhouse:acme:100",
    "board": "acme",
    "company": "Acme Cloud",
    "title": "DDoS Mitigation Engineer",
    "location": "Denver, CO",
    "url": "https://example.com/jobs/100",
    "terms": ["ddos"],
    "flags": [],
    "pay_low": 250000,
    "pay_high": 310000,
    "skills": ["ddos"],
    "jd_seen": True,
    "first_seen": "2026-04-02T09:00:00+00:00",
    "last_seen": "2026-04-02T09:00:00+00:00",
}


class MalformedInput(unittest.TestCase):
    def test_none_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(None)

    def test_list_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize([CLEAN_JOB])

    def test_int_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(1)

    def test_empty_string_is_invalid_json(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize("")

    def test_sanitize_records_rejects_a_bare_dict(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize_records(CLEAN_JOB)


class InvalidJSON(unittest.TestCase):
    def test_truncated_object_is_blocked(self):
        with self.assertRaises(SanitizerBlocked) as caught:
            sanitize("{")
        self.assertIn("invalid JSON", str(caught.exception))

    def test_json_null_is_not_a_record(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize("null")

    def test_json_array_is_not_a_record(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize("[]")

    def test_json_string_of_a_clean_record_passes(self):
        cleaned = sanitize(json.dumps(CLEAN_JOB))
        self.assertEqual(cleaned["id"], CLEAN_JOB["id"])
        self.assertEqual(cleaned["title"], CLEAN_JOB["title"])


class UnknownKeys(unittest.TestCase):
    def test_extra_top_level_key_is_blocked(self):
        dirty = dict(CLEAN_JOB, ssn="123-45-6789")
        with self.assertRaises(SanitizerBlocked) as caught:
            sanitize(dirty)
        self.assertIn("unknown keys", str(caught.exception))
        self.assertIn("ssn", str(caught.exception))

    def test_extra_nested_comp_key_is_blocked(self):
        org = {
            "name": "Acme Cloud",
            "board": "acme",
            "industry": "security_vendor",
            "sector": "cyber",
            "arch": "edge",
            "fit": "core",
            "traffic": True,
            "warm_channel": False,
            "open_now": True,
            "team": "Edge",
            "why": "Volumetric defence.",
            "locations": "Denver, CO",
            "careers": "https://example.com/acme/careers",
            "relationship": "competitor",
            "relationship_note": "synthetic",
            "relationship_url": "https://example.com/",
            "comp": {
                "levels_company": "Acme Cloud",
                "median_total": 415000,
                "target_level": "L5",
                "amazon_equiv": "L6",
                "level_source": "levels.fyi",
                "level_confidence": "reported",
                "tier": "400",
                "note": "senior median",
                "confidence": "reported",
                "personal_email": "ada@example.com",
            },
        }
        with self.assertRaises(SanitizerBlocked) as caught:
            sanitize(org)
        self.assertIn("unknown keys", str(caught.exception))
        self.assertIn("personal_email", str(caught.exception))


class WrongTypes(unittest.TestCase):
    def test_title_must_be_a_string(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_JOB, title=123))

    def test_terms_must_be_a_list_of_strings(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_JOB, terms="ddos"))

    def test_jd_seen_must_be_a_bool(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_JOB, jd_seen="true"))

    def test_pay_low_bool_is_not_an_int(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_JOB, pay_low=True))


class EmailPattern(unittest.TestCase):
    def test_email_in_free_text_is_redacted(self):
        cleaned = sanitize(app("Recruiter wrote back: ada@example.com yesterday."))
        self.assertNotIn("ada@example.com", cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_email_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(app("ada@example.com"))


class PhonePattern(unittest.TestCase):
    def test_phone_in_free_text_is_redacted(self):
        cleaned = sanitize(app("Call me on (206) 555-0100 after 5."))
        self.assertNotIn("555-0100", cleaned["note"])
        self.assertNotIn("206", json.dumps(cleaned))
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_phone_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(app("206-555-0100"))


class NamePattern(unittest.TestCase):
    def setUp(self):
        self._names = list(sanitizer.APPLICANT_NAMES)
        sanitizer.APPLICANT_NAMES.append("Jane Doe")

    def tearDown(self):
        sanitizer.APPLICANT_NAMES[:] = self._names

    def test_applicant_name_in_free_text_is_redacted(self):
        cleaned = sanitize(app("Please ask Jane Doe to confirm the slot."))
        self.assertNotIn("Jane Doe", cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_labeled_applicant_name_is_redacted(self):
        cleaned = sanitize(app("Name: Ada Lovelace applied last week."))
        self.assertNotIn("Ada Lovelace", cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_name_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(app("Jane Doe"))


class AddressPattern(unittest.TestCase):
    def test_home_address_in_free_text_is_redacted(self):
        cleaned = sanitize(app("I live at 123 Main Street, Seattle, WA 98101."))
        self.assertNotIn("123 Main Street", cleaned["note"])
        self.assertNotIn("98101", cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_address_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(app("123 Main Street"))


class LinkedInPattern(unittest.TestCase):
    def test_linkedin_url_in_free_text_is_redacted(self):
        cleaned = sanitize(app("Profile: https://www.linkedin.com/in/ada-lovelace"))
        self.assertNotIn("linkedin.com", cleaned["note"])
        self.assertNotIn("ada-lovelace", cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_linkedin_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(app("https://www.linkedin.com/in/ada-lovelace"))


class ProfileUrlPattern(unittest.TestCase):
    def test_github_profile_url_is_redacted(self):
        cleaned = sanitize(app("See https://github.com/adalovelace for older work."))
        self.assertNotIn("github.com/adalovelace", cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_repo_url_is_not_treated_as_a_profile(self):
        cleaned = sanitize(app("We use https://github.com/acme/edge-filter in production."))
        self.assertIn("github.com/acme/edge-filter", cleaned["note"])

    def test_profile_url_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(app("https://github.com/adalovelace"))


class TokenPattern(unittest.TestCase):
    def test_github_pat_is_redacted(self):
        token = "ghp_" + ("a" * 36)
        cleaned = sanitize(app("do not paste " + token + " into a note"))
        self.assertNotIn(token, cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_bearer_token_is_redacted(self):
        cleaned = sanitize(app("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"))
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_token_left_in_place_is_blocked(self):
        token = "ghp_" + ("b" * 36)
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(app(token))


class ApiKeyPattern(unittest.TestCase):
    def test_aws_access_key_is_redacted(self):
        key = "AKIA" + ("A" * 16)
        cleaned = sanitize(app("creds " + key))
        self.assertNotIn(key, cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_labeled_api_key_is_redacted(self):
        cleaned = sanitize(app("api_key=abcdefghijklmnopQR"))
        self.assertNotIn("abcdefghijklmnopQR", cleaned["note"])
        self.assertIn(sanitizer.REDACTED, cleaned["note"])

    def test_api_key_left_in_place_is_blocked(self):
        key = "AKIA" + ("B" * 16)
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(app(key))


class FailClosed(unittest.TestCase):
    def test_internal_exception_becomes_sanitizer_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=RuntimeError("boom")):
            with self.assertRaises(SanitizerBlocked) as caught:
                sanitize(app("clean note"))
        self.assertIn("internal sanitizer failure", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, RuntimeError)

    def test_failure_returns_nothing(self):
        try:
            result = sanitize({"ssn": "nope"})
        except SanitizerBlocked:
            return
        self.fail("sanitize returned {!r} instead of raising".format(result))

    def test_clean_job_is_unchanged(self):
        self.assertEqual(sanitize(CLEAN_JOB), CLEAN_JOB)

    def test_pay_integers_are_not_phones(self):
        cleaned = sanitize(CLEAN_JOB)
        self.assertEqual(cleaned["pay_low"], 250000)
        self.assertEqual(cleaned["pay_high"], 310000)


class SampleCorpus(unittest.TestCase):
    def test_sample_state_is_allowed(self):
        cleaned = sanitize(example("jobwatch_state.sample.json"))
        self.assertEqual(cleaned["version"], 1)
        self.assertEqual(len(cleaned["jobs"]), 15)

    def test_sample_organizations_are_allowed(self):
        cleaned = sanitize(example("organizations.sample.json"))
        self.assertEqual(len(cleaned["organizations"]), 8)

    def test_sample_applications_are_allowed(self):
        cleaned = sanitize(example("applications.sample.json"))
        self.assertEqual(len(cleaned["applications"]), 4)

    def test_rendered_sample_page_is_public_clean(self):
        import render_site as rs
        state = example("jobwatch_state.sample.json")
        apps = example("applications.sample.json")["applications"]
        orgs = example("organizations.sample.json")["organizations"]
        html, js = rs.render(state, "demo", apps, orgs, [])
        scan_public_text(html)
        scan_public_text(js)
        self.assertIn("Acme Cloud", html)
        self.assertIn("DDoS Mitigation Engineer", js)


if __name__ == "__main__":
    EXPECTED = 43
    found = sum(
        len(unittest.TestLoader().loadTestsFromTestCase(cls)._tests)
        for cls in (
            MalformedInput, InvalidJSON, UnknownKeys, WrongTypes,
            EmailPattern, PhonePattern, NamePattern, AddressPattern,
            LinkedInPattern, ProfileUrlPattern, TokenPattern, ApiKeyPattern,
            FailClosed, SampleCorpus,
        )
    )
    assert found == EXPECTED, "expected {} tests, collected {}".format(EXPECTED, found)
    unittest.main(verbosity=2)
