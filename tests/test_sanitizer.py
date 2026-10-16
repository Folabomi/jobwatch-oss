#!/usr/bin/env python3
"""Fail-closed sanitizer: every public record either comes out clean or not at all.

Each deny has a must-pass companion so a detector that never fires cannot hide
behind a passing suite. Application records are not public output and are not
sent through sanitize.
"""

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sanitizer
import taxonomy as tx
from sanitizer import SanitizerBlocked, sanitize, sanitize_records, scan_public_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def example(name):
    with io.open(os.path.join(EXAMPLES, name), encoding="utf-8") as handle:
        return json.load(handle)


def fixture_json(name):
    with io.open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return json.load(handle)


def job_with(**overrides):
    record = dict(CLEAN_JOB)
    record.update(overrides)
    return record


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

CLEAN_ORG = {
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
    "locations": "Denver, CO",
    "careers": "https://example.com/acme/careers",
    "relationship": "competitor",
    "relationship_url": "https://example.com/",
    "comp": {
        "levels_company": "Acme Cloud",
        "median_total": 415000,
        "target_level": "L5",
        "amazon_equiv": "L6",
        "level_source": "levels.fyi",
        "level_confidence": "reported",
        "tier": "400",
        "confidence": "reported",
    },
}

GH_PAT = "ghp_" + ("a" * 36)
AWS_KEY = "AKIA" + ("A" * 16)


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

    def test_clean_dict_passes(self):
        self.assertEqual(sanitize(CLEAN_JOB)["id"], CLEAN_JOB["id"])


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
        org = json.loads(json.dumps(CLEAN_ORG))
        org["comp"]["personal_email"] = "ada@example.com"
        with self.assertRaises(SanitizerBlocked) as caught:
            sanitize(org)
        self.assertIn("unknown keys", str(caught.exception))
        self.assertIn("personal_email", str(caught.exception))

    def test_allowlisted_org_projection_passes(self):
        cleaned = sanitize(CLEAN_ORG)
        self.assertEqual(cleaned["name"], "Acme Cloud")
        self.assertNotIn("why", cleaned)
        self.assertNotIn("relationship_note", cleaned)


class PrivateKeys(unittest.TestCase):
    def test_note_is_blocked(self):
        with self.assertRaises(SanitizerBlocked) as caught:
            sanitize(dict(CLEAN_JOB, note="recruiter pinged"))
        self.assertIn("private keys", str(caught.exception))

    def test_why_and_rel_note_are_blocked(self):
        dirty = dict(CLEAN_ORG, why="Volumetric defence.", relationship_note="synthetic")
        with self.assertRaises(SanitizerBlocked) as caught:
            sanitize(dirty)
        self.assertIn("private keys", str(caught.exception))

    def test_resume_and_interview_style_are_blocked(self):
        dirty = dict(CLEAN_JOB, resume="edge", interview_style="ai_allowed_or_takehome")
        with self.assertRaises(SanitizerBlocked) as caught:
            sanitize(dirty)
        self.assertIn("private keys", str(caught.exception))

    def test_applications_wrapper_is_blocked(self):
        with self.assertRaises(SanitizerBlocked) as caught:
            sanitize(example("applications.sample.json"))
        self.assertIn("private keys", str(caught.exception))

    def test_public_job_without_private_keys_passes(self):
        self.assertEqual(sanitize(CLEAN_JOB), CLEAN_JOB)


class WrongTypes(unittest.TestCase):
    def test_title_must_be_a_string(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title=123))

    def test_terms_must_be_a_list_of_strings(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(terms="ddos"))

    def test_jd_seen_must_be_a_bool(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(jd_seen="true"))

    def test_pay_low_bool_is_not_an_int(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(pay_low=True))

    def test_typed_fields_on_a_clean_job_pass(self):
        cleaned = sanitize(CLEAN_JOB)
        self.assertTrue(cleaned["jd_seen"])
        self.assertEqual(cleaned["terms"], ["ddos"])


class CompanyNameAndLabel(unittest.TestCase):
    def test_empty_company_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(company=""))

    def test_free_text_label_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize({"label": "Ada Lovelace applied last week"})

    def test_application_status_is_not_a_board_status(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize({"company": "Acme Cloud", "status": "submitted"})

    def test_company_name_and_enum_label_pass(self):
        cleaned = sanitize({"name": "Acme Cloud", "label": "Core mandate"})
        self.assertEqual(cleaned["name"], "Acme Cloud")
        self.assertEqual(cleaned["label"], "Core mandate")

    def test_person_name_is_not_a_known_company(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize({"name": "Jane Roe"})

    def test_company_pipe_person_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize({"name": "Acme | Jane Roe"})

    def test_board_status_ok_passes(self):
        cleaned = sanitize({"company": "Acme Cloud", "status": "ok"})
        self.assertEqual(cleaned["status"], "ok")


class EmailPattern(unittest.TestCase):
    def test_email_in_free_text_is_redacted(self):
        cleaned = sanitize(job_with(title="Recruiter wrote back: ada@example.com yesterday."))
        self.assertNotIn("ada@example.com", cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_email_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(job_with(title="ada@example.com"))


class PhonePattern(unittest.TestCase):
    def test_phone_in_free_text_is_redacted(self):
        cleaned = sanitize(job_with(title="Call me on (206) 555-0100 after 5."))
        self.assertNotIn("555-0100", cleaned["title"])
        self.assertNotIn("206", json.dumps(cleaned))
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_phone_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(job_with(title="206-555-0100"))


class NamePattern(unittest.TestCase):
    def setUp(self):
        self._names = list(sanitizer.APPLICANT_NAMES)
        sanitizer.APPLICANT_NAMES.append("Jane Doe")

    def tearDown(self):
        sanitizer.APPLICANT_NAMES[:] = self._names

    def test_applicant_name_in_free_text_is_redacted(self):
        cleaned = sanitize(job_with(title="Please ask Jane Doe to confirm the slot."))
        self.assertNotIn("Jane Doe", cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_labeled_applicant_name_is_redacted(self):
        cleaned = sanitize(job_with(title="Name: Ada Lovelace on the hiring loop."))
        self.assertNotIn("Ada Lovelace", cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_name_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(job_with(title="Jane Doe"))

    def test_company_name_without_a_person_passes(self):
        cleaned = sanitize(job_with(title="DDoS Mitigation Engineer"))
        self.assertEqual(cleaned["title"], "DDoS Mitigation Engineer")


class AddressPattern(unittest.TestCase):
    def test_home_address_in_free_text_is_redacted(self):
        cleaned = sanitize(job_with(title="I live at 123 Main Street, Seattle, WA 98101."))
        self.assertNotIn("123 Main Street", cleaned["title"])
        self.assertNotIn("98101", cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_address_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(job_with(title="123 Main Street"))


class LinkedInPattern(unittest.TestCase):
    def test_linkedin_url_in_free_text_is_redacted(self):
        cleaned = sanitize(job_with(title="Profile: https://www.linkedin.com/in/ada-lovelace"))
        self.assertNotIn("linkedin.com", cleaned["title"])
        self.assertNotIn("ada-lovelace", cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_linkedin_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(job_with(title="https://www.linkedin.com/in/ada-lovelace"))


class ProfileUrlPattern(unittest.TestCase):
    def test_github_profile_url_is_redacted(self):
        cleaned = sanitize(job_with(title="See https://github.com/adalovelace for older work."))
        self.assertNotIn("github.com/adalovelace", cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_repo_url_is_not_treated_as_a_profile(self):
        cleaned = sanitize(job_with(title="We use https://github.com/acme/edge-filter in production."))
        self.assertIn("github.com/acme/edge-filter", cleaned["title"])

    def test_profile_url_left_in_place_is_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(job_with(title="https://github.com/adalovelace"))


class TokenPattern(unittest.TestCase):
    def test_github_pat_is_redacted(self):
        cleaned = sanitize(job_with(title="do not paste " + GH_PAT + " into a note"))
        self.assertNotIn(GH_PAT, cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_bearer_token_is_redacted(self):
        cleaned = sanitize(job_with(title="Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"))
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_token_left_in_place_is_blocked(self):
        token = "ghp_" + ("b" * 36)
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(job_with(title=token))


class ApiKeyPattern(unittest.TestCase):
    def test_aws_access_key_is_redacted(self):
        cleaned = sanitize(job_with(title="creds " + AWS_KEY))
        self.assertNotIn(AWS_KEY, cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_labeled_api_key_is_redacted(self):
        cleaned = sanitize(job_with(title="api_key=abcdefghijklmnopQR"))
        self.assertNotIn("abcdefghijklmnopQR", cleaned["title"])
        self.assertIn(sanitizer.REDACTED, cleaned["title"])

    def test_api_key_left_in_place_is_blocked(self):
        key = "AKIA" + ("B" * 16)
        with mock.patch.object(sanitizer, "_redact_text", side_effect=lambda text: text):
            with self.assertRaises(SanitizerBlocked):
                sanitize(job_with(title=key))


class DenyPassHomoglyph(unittest.TestCase):
    def test_cyrillic_a_in_email_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("contact ad\u0430@example.com for a screen")

    def test_company_domain_without_an_address_passes(self):
        scan_public_text("contact the example.com recruiter desk for a screen")


class DenyPassMailtoEntity(unittest.TestCase):
    def test_mailto_html_entity_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("write me &#109;ailto:ada@example.com")

    def test_mail_to_the_hiring_desk_passes(self):
        scan_public_text("write me by mail to the hiring desk")


class DenyPassCommentSplit(unittest.TestCase):
    def test_html_comment_split_email_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("ada@exam<!-- -->ple.com")

    def test_js_comment_split_email_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("ada@exam/*skip*/ple.com")

    def test_unrelated_html_comment_passes(self):
        scan_public_text("<!-- layout note --> Acme Cloud hiring")


class DenyPassEmDashName(unittest.TestCase):
    def test_emdash_person_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("Jane\u2014Doe confirmed the loop")

    def test_recruiter_emdash_label_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("Recruiter \u2014 Ada Lovelace")

    def test_company_emdash_team_passes(self):
        scan_public_text("Acme Cloud \u2014 Edge Platform")


class DenyPassScriptJson(unittest.TestCase):
    def test_email_inside_script_json_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('<script>{"note":"ada@example.com"}</script>')

    def test_clean_script_json_passes(self):
        scan_public_text('<script>{"company":"Acme Cloud","tier":"rare"}</script>')


class DenyPassDataAttr(unittest.TestCase):
    def test_data_notes_email_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('<div data-notes="ada@example.com">Acme Cloud</div>')

    def test_unrelated_data_attr_passes(self):
        scan_public_text('<div data-tier="rare">Acme Cloud</div>')


class FailClosed(unittest.TestCase):
    def test_internal_exception_becomes_sanitizer_blocked(self):
        with mock.patch.object(sanitizer, "_redact_text", side_effect=RuntimeError("boom")):
            with self.assertRaises(SanitizerBlocked) as caught:
                sanitize(job_with(title="clean title"))
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


class ApplicationsAreNotPublic(unittest.TestCase):
    def test_uneven_fixture_carries_interview_style_and_every_status(self):
        data = fixture_json("applications_uneven.json")
        apps = data["applications"]
        styles = {a.get("interview_style") for a in apps if "interview_style" in a}
        self.assertTrue(styles <= set(tx.INTERVIEW_STYLES))
        self.assertIn("ai_allowed_or_takehome", styles)
        seen = {a["status"] for a in apps}
        self.assertTrue(set(tx.STATUS_META) <= seen)

    def test_sanitizing_an_application_record_is_the_wrong_path(self):
        app = fixture_json("applications_uneven.json")["applications"][0]
        with self.assertRaises(SanitizerBlocked):
            sanitize(app)

    def test_render_ignores_application_records(self):
        import render_site as rs
        state = example("jobwatch_state.sample.json")
        orgs = example("organizations.sample.json")["organizations"]
        html, js = rs.render(state, "demo", orgs, [])
        scan_public_text(html)
        scan_public_text(js)
        self.assertIn("Acme Cloud", html)
        self.assertIn("DDoS Mitigation Engineer", js)
        self.assertNotIn("Where my applications stand", html)
        self.assertNotIn("need a look", html)
        self.assertNotIn("var STATUS", js)
        self.assertNotIn("RESUMES", js)
        self.assertNotIn("Moved to a screening call", html)
        self.assertNotIn("ai_allowed_or_takehome", html + js)
        self.assertNotIn("drive.google.com", js)

    def test_interview_style_on_disk_does_not_block_publish(self):
        import render_site as rs
        with io.open(os.path.join(ROOT, "render_site.py"), encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn("APPS_PATH", source)
        self.assertNotIn('"applications.json"', source)
        self.assertNotIn("'applications.json'", source)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        state_path = os.path.join(tmp, "jobwatch_state.json")
        orgs_path = os.path.join(tmp, "organizations.json")
        apps_path = os.path.join(tmp, "applications.json")
        out = os.path.join(tmp, "site")
        with open(state_path, "w", encoding="utf-8") as handle:
            json.dump(example("jobwatch_state.sample.json"), handle)
        with open(orgs_path, "w", encoding="utf-8") as handle:
            json.dump(example("organizations.sample.json"), handle)
        with open(apps_path, "w", encoding="utf-8") as handle:
            json.dump(fixture_json("applications_uneven.json"), handle)
        with mock.patch.object(rs, "STATE_PATH", state_path), \
                mock.patch.object(rs, "ORGS_PATH", orgs_path), \
                mock.patch.object(rs, "HIDDEN_PATH", os.path.join(tmp, "dismissed.json")), \
                mock.patch.object(sys, "argv", ["render_site.py", "--out", out, "--slug", "demo"]):
            rs.main()
        with io.open(os.path.join(out, "demo"), encoding="utf-8") as handle:
            page = handle.read()
        self.assertNotIn("interview_style", page)
        self.assertNotIn("Submitted, verify it sent", page)


class SampleCorpus(unittest.TestCase):
    def test_sample_state_is_allowed(self):
        cleaned = sanitize(example("jobwatch_state.sample.json"))
        self.assertEqual(cleaned["version"], 1)
        self.assertEqual(len(cleaned["jobs"]), 15)

    def test_sample_organizations_raw_file_is_not_public(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(example("organizations.sample.json"))

    def test_rendered_sample_page_is_public_clean(self):
        import render_site as rs
        state = example("jobwatch_state.sample.json")
        orgs = example("organizations.sample.json")["organizations"]
        html, js = rs.render(state, "demo", orgs, [])
        scan_public_text(html)
        scan_public_text(js)
        self.assertIn("Acme Cloud", html)
        self.assertIn("DDoS Mitigation Engineer", js)


class StatusMetaLocal(unittest.TestCase):
    def test_known_status_keeps_its_label(self):
        meta = tx.status_meta("submitted")
        self.assertEqual(meta["label"], "Submitted, verify it sent")
        self.assertEqual(meta["stage"], "verify")
        self.assertNotIn("submitted", tx.ACTION_STATUSES)

    def test_unknown_status_maps_to_a_safe_bucket(self):
        meta = tx.status_meta("brand_new_status")
        self.assertEqual(meta, tx.UNKNOWN_STATUS)


class DeploySiteGated(unittest.TestCase):
    def test_deploy_exits_nonzero_before_any_upload_when_sanitizer_blocks(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        shutil.copy(os.path.join(ROOT, "deploy_site.sh"), os.path.join(root, "deploy_site.sh"))
        with open(os.path.join(root, "render_site.py"), "w", encoding="utf-8") as handle:
            handle.write(
                "import sys\n"
                "print('sanitizer blocked public page: unknown keys: ssn', file=sys.stderr)\n"
                "sys.exit(2)\n"
            )
        bindir = os.path.join(root, "bin")
        os.makedirs(bindir)
        marker = os.path.join(root, "aws_ran")
        aws = os.path.join(bindir, "aws")
        with open(aws, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\necho aws_called >> \"$MARKER\"\nexit 0\n")
        os.chmod(aws, os.stat(aws).st_mode | stat.S_IEXEC)
        env = os.environ.copy()
        env.update({
            "PATH": bindir + os.pathsep + env.get("PATH", ""),
            "JOBWATCH_BUCKET": "s3://test-bucket",
            "JOBWATCH_DISTRIBUTION": "E1234567890ABC",
            "JOBWATCH_SLUG": "demo",
            "MARKER": marker,
        })
        result = subprocess.run(
            ["bash", "./deploy_site.sh"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sanitizer blocked", result.stderr)
        self.assertFalse(os.path.exists(marker))


class PublishHold(unittest.TestCase):
    def test_hold_skips_deploy_and_monoclaw_but_still_polls(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        shutil.copy(os.path.join(ROOT, "run_local.sh"), os.path.join(root, "run_local.sh"))
        with open(os.path.join(root, "jobwatch.py"), "w", encoding="utf-8") as handle:
            handle.write(
                "import sys\n"
                "sys.stderr.write('polling 1 board(s)...\\n')\n"
                "sys.stdout.write('# jobwatch\\n\\nSUMMARY new=0 closed=0 live=3 boards_ok=1 boards_failed=0\\n')\n"
            )
        deploy_ran = os.path.join(root, "deploy_ran")
        claw_ran = os.path.join(root, "claw_ran")
        with open(os.path.join(root, "deploy_site.sh"), "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\ntouch deploy_ran\nexit 0\n")
        os.chmod(os.path.join(root, "deploy_site.sh"), 0o755)
        with open(os.path.join(root, ".publish_hold"), "w", encoding="utf-8") as handle:
            handle.write("hold\n")
        result = subprocess.run(
            ["bash", "./run_local.sh"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("publish hold", result.stdout)
        self.assertIn("SUMMARY new=0", result.stdout)
        self.assertTrue(os.path.exists(os.path.join(root, "jobwatch_report.md")))
        self.assertFalse(os.path.exists(deploy_ran))
        with io.open(os.path.join(ROOT, "run_local.sh"), encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn("monoclaw_push.sh", source)


class DenyPassCaseInsensitive(unittest.TestCase):
    def test_lowercase_recruiter_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("recruiter: jane roe")

    def test_recruiter_single_given_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("Recruiter: Jane")

    def test_application_stage_onsite_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("application stage: onsite")

    def test_recruiter_loop_without_a_name_passes(self):
        scan_public_text("recruiter loop completed for Acme Cloud")


class DenyPassEnumsAndAppPhrases(unittest.TestCase):
    def test_free_text_relationship_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, relationship="best friends"))

    def test_known_relationship_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, relationship="competitor"))
        self.assertEqual(cleaned["relationship"], "competitor")

    def test_free_text_move_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize({"name": "Acme Cloud", "move": "promo"})

    def test_known_move_passes(self):
        cleaned = sanitize({"name": "Acme Cloud", "move": "lateral"})
        self.assertEqual(cleaned["move"], "lateral")

    def test_free_text_pay_note_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize({"name": "Acme Cloud", "pay_note": "ask Jane Roe"})

    def test_enum_pay_note_passes(self):
        cleaned = sanitize({"name": "Acme Cloud", "pay_note": "Band posted per req"})
        self.assertEqual(cleaned["pay_note"], "Band posted per req")

    def test_title_applied_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="applied"))

    def test_title_onsite_date_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="onsite 10/20"))

    def test_title_applied_date_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="applied 10/1"))

    def test_clean_title_passes(self):
        cleaned = sanitize(job_with(title="DDoS Mitigation Engineer"))
        self.assertEqual(cleaned["title"], "DDoS Mitigation Engineer")


class DenyPassResumeAndEmailObfuscation(unittest.TestCase):
    def test_underscore_resume_filename_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("jane_roe_resume_v3")

    def test_camelcase_cv_filename_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("JaneRoe-CV.txt")

    def test_resume_variant_phrase_passes(self):
        scan_public_text("Competency map, and which CV each one leads with")

    def test_split_email_concat_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("""'a"+"@"+"b'""")

    def test_plus_without_an_at_passes(self):
        scan_public_text("a plus b in the title")

    def test_at_dot_spelling_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("ada [at] example [dot] com")

    def test_at_the_edge_passes(self):
        scan_public_text("on call at the edge")

    def test_recursively_encoded_at_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("ada&amp;amp;#64;example.com")

    def test_ampersand_without_an_entity_passes(self):
        scan_public_text("Edge & DDoS at Acme Cloud")


class DenyPassFormatAndBoardNames(unittest.TestCase):
    def test_soft_hyphen_in_email_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("ada\u00ad@example.com")

    def test_hyphenated_discipline_passes(self):
        scan_public_text("US-only DDoS-mitigation seat")

    def test_mine_board_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("open the Mine board")

    def test_kanban_board_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("sync the Kanban")

    def test_cyrillic_mine_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("M\u0456ne")

    def test_hidden_chip_label_passes(self):
        scan_public_text("Hidden")


class DenyPassCommentsAndScript(unittest.TestCase):
    def test_unclosed_block_comment_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("secret /* ada@example.com")

    def test_comment_split_token_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("CA/*x*/RDS")

    def test_standalone_block_comment_passes(self):
        scan_public_text("/* layout */ Acme Cloud hiring")

    def test_script_json_note_key_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('<script type="text/json">{"note":"ping"}</script>')

    def test_script_json_applied_key_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('<script>{"applied":true}</script>')

    def test_unclosed_script_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('<script>{"company":"Acme Cloud"}')

    def test_js_unicode_at_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("ada\\u0040example.com")

    def test_clean_closed_script_json_passes(self):
        scan_public_text('<script>{"company":"Acme Cloud","tier":"rare"}</script>')


class DenyPassDataAndDataset(unittest.TestCase):
    def test_arbitrary_data_attr_email_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('<div data-foo="ada@example.com">Acme Cloud</div>')

    def test_data_tier_passes(self):
        scan_public_text('<div data-tier="rare">Acme Cloud</div>')

    def test_dataset_notes_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("el.dataset.notes = 'ping'")

    def test_dataset_tier_passes(self):
        scan_public_text("el.dataset.tier = 'rare'")

    def test_obj_notes_access_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('obj["notes"]')

    def test_obj_tier_access_passes(self):
        scan_public_text('obj["tier"]')


class DeploySiteHold(unittest.TestCase):
    def test_deploy_site_honors_publish_hold(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        shutil.copy(os.path.join(ROOT, "deploy_site.sh"), os.path.join(root, "deploy_site.sh"))
        with open(os.path.join(root, ".publish_hold"), "w", encoding="utf-8") as handle:
            handle.write("hold\n")
        bindir = os.path.join(root, "bin")
        os.makedirs(bindir)
        marker = os.path.join(root, "aws_ran")
        aws = os.path.join(bindir, "aws")
        with open(aws, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\necho aws_called >> \"$MARKER\"\nexit 0\n")
        os.chmod(aws, os.stat(aws).st_mode | stat.S_IEXEC)
        env = os.environ.copy()
        env.update({
            "PATH": bindir + os.pathsep + env.get("PATH", ""),
            "MARKER": marker,
        })
        result = subprocess.run(
            ["bash", "./deploy_site.sh"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("publish hold", result.stdout)
        self.assertFalse(os.path.exists(marker))


TEST_CASES = (
    MalformedInput, InvalidJSON, UnknownKeys, PrivateKeys, WrongTypes,
    CompanyNameAndLabel, EmailPattern, PhonePattern, NamePattern,
    AddressPattern, LinkedInPattern, ProfileUrlPattern, TokenPattern,
    ApiKeyPattern, DenyPassHomoglyph, DenyPassMailtoEntity,
    DenyPassCommentSplit, DenyPassEmDashName, DenyPassScriptJson,
    DenyPassDataAttr, FailClosed, ApplicationsAreNotPublic, SampleCorpus,
    StatusMetaLocal, DeploySiteGated, PublishHold, DenyPassCaseInsensitive,
    DenyPassEnumsAndAppPhrases, DenyPassResumeAndEmailObfuscation,
    DenyPassFormatAndBoardNames, DenyPassCommentsAndScript,
    DenyPassDataAndDataset, DeploySiteHold,
)

EXPECTED_SANITIZER_TESTS = 124


def _discovered_count():
    return sum(
        len(unittest.TestLoader().loadTestsFromTestCase(cls)._tests)
        for cls in TEST_CASES
    )


def setUpModule():
    found = _discovered_count()
    if found != EXPECTED_SANITIZER_TESTS:
        raise AssertionError(
            "expected {} tests, collected {}".format(EXPECTED_SANITIZER_TESTS, found)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
