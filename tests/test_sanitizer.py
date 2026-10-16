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
from sanitizer import (
    SanitizerBlocked,
    VocabMiss,
    check_drop_budget,
    format_drop_counts,
    last_drop_counts,
    reset_drops,
    sanitize,
    sanitize_records,
    scan_public_text,
)

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
    def test_email_in_free_text_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Recruiter wrote back: ada@example.com yesterday."))

    def test_title_without_an_email_passes(self):
        cleaned = sanitize(job_with(title="Recruiter wrote back yesterday."))
        self.assertNotIn(sanitizer.REDACTED, cleaned["title"])


class PhonePattern(unittest.TestCase):
    def test_phone_in_free_text_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Call me on (206) 555-0100 after 5."))

    def test_e164_in_title_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Call me on +12065550142 after 5."))

    def test_title_without_a_phone_passes(self):
        cleaned = sanitize(job_with(title="Call the hiring desk after 5."))
        self.assertNotIn(sanitizer.REDACTED, json.dumps(cleaned))

    def test_bare_ten_digit_in_title_is_not_a_phone(self):
        cleaned = sanitize(job_with(title="Tracking req 1206555014 this week."))
        self.assertEqual(cleaned["title"], "Tracking req 1206555014 this week.")


class NamePattern(unittest.TestCase):
    def setUp(self):
        self._names = list(sanitizer.APPLICANT_NAMES)
        sanitizer.APPLICANT_NAMES.append("Jane Doe")

    def tearDown(self):
        sanitizer.APPLICANT_NAMES[:] = self._names

    def test_applicant_name_in_free_text_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Please ask Jane Doe to confirm the slot."))

    def test_labeled_applicant_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Name: Ada Lovelace on the hiring loop."))

    def test_name_left_in_place_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Jane Doe"))

    def test_company_name_without_a_person_passes(self):
        cleaned = sanitize(job_with(title="DDoS Mitigation Engineer"))
        self.assertEqual(cleaned["title"], "DDoS Mitigation Engineer")


class AddressPattern(unittest.TestCase):
    def test_home_address_in_free_text_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="I live at 123 Main Street, Seattle, WA 98101."))

    def test_address_left_in_place_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="123 Main Street"))


class LinkedInPattern(unittest.TestCase):
    def test_linkedin_url_in_free_text_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Profile: https://www.linkedin.com/in/ada-lovelace"))

    def test_linkedin_left_in_place_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="https://www.linkedin.com/in/ada-lovelace"))


class ProfileUrlPattern(unittest.TestCase):
    def test_github_profile_url_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="See https://github.com/adalovelace for older work."))

    def test_repo_url_is_not_treated_as_a_profile(self):
        cleaned = sanitize(job_with(title="We use https://github.com/acme/edge-filter in production."))
        self.assertIn("github.com/acme/edge-filter", cleaned["title"])

    def test_profile_url_left_in_place_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="https://github.com/adalovelace"))


class TokenPattern(unittest.TestCase):
    def test_github_pat_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="do not paste " + GH_PAT + " into a note"))

    def test_bearer_token_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"))

    def test_token_left_in_place_is_blocked(self):
        token = "ghp_" + ("b" * 36)
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title=token))


class ApiKeyPattern(unittest.TestCase):
    def test_aws_access_key_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="creds " + AWS_KEY))

    def test_labeled_api_key_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="api_key=abcdefghijklmnopQR"))

    def test_api_key_left_in_place_is_blocked(self):
        key = "AKIA" + ("B" * 16)
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

    def test_any_data_attr_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('<div data-tier="rare">Acme Cloud</div>')

    def test_markup_without_data_attr_passes(self):
        scan_public_text('<div class="tier">Acme Cloud</div>')


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

    def test_deploy_fails_when_run_summary_omits_drop_fields(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        shutil.copy(os.path.join(ROOT, "deploy_site.sh"), os.path.join(root, "deploy_site.sh"))
        with open(os.path.join(root, "render_site.py"), "w", encoding="utf-8") as handle:
            handle.write("print('wrote site/demo and demo.js')\n")
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
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("drops-by-field", result.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_deploy_requires_drops_by_field_then_uploads(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        shutil.copy(os.path.join(ROOT, "deploy_site.sh"), os.path.join(root, "deploy_site.sh"))
        with open(os.path.join(root, "render_site.py"), "w", encoding="utf-8") as handle:
            handle.write("import sys\nprint('drops_none=0', file=sys.stderr)\nprint('wrote site/demo')\n")
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
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("drops_none=0", result.stdout)
        self.assertTrue(os.path.exists(marker))

    def test_report_summary_always_includes_drops_by_field(self):
        import jobwatch
        reset_drops()
        matches = {"greenhouse:acme:100": job_with()}
        report = jobwatch.render_report(matches, {}, ["acme"], [], False, False)
        self.assertIn("drops_none=0", report)
        summary = [line for line in report.splitlines() if line.startswith("SUMMARY ")][0]
        self.assertIn("drops_none=0", summary)
        self.assertIn("drops=0", summary)

    def test_title_drops_token_is_refused_by_both_gates(self):
        decoy = "- Cloudflare | SWE drops_none=0"
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        shutil.copy(os.path.join(ROOT, "run_local.sh"), os.path.join(root, "run_local.sh"))
        shutil.copy(os.path.join(ROOT, "deploy_site.sh"), os.path.join(root, "deploy_site.sh"))
        with open(os.path.join(root, "jobwatch.py"), "w", encoding="utf-8") as handle:
            handle.write(
                "import sys\n"
                "sys.stderr.write('polling 1 board(s)...\\n')\n"
                "sys.stdout.write('# jobwatch\\n\\n"
                + decoy
                + "\\n\\nSUMMARY new=0 closed=0 live=1 boards_ok=1 boards_failed=0\\n')\n"
            )
        deploy_ran = os.path.join(root, "deploy_ran")
        with open(os.path.join(root, "deploy_site.sh"), "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\ntouch deploy_ran\nexit 0\n")
        os.chmod(os.path.join(root, "deploy_site.sh"), 0o755)
        local = subprocess.run(
            ["bash", "./run_local.sh"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(local.returncode, 0, local.stdout + local.stderr)
        self.assertIn("drops-by-field", local.stderr)
        self.assertFalse(os.path.exists(deploy_ran))

        shutil.copy(os.path.join(ROOT, "deploy_site.sh"), os.path.join(root, "deploy_site.sh"))
        with open(os.path.join(root, "render_site.py"), "w", encoding="utf-8") as handle:
            handle.write("print({!r})\nprint('wrote site/demo')\n".format(decoy))
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
        deploy = subprocess.run(
            ["bash", "./deploy_site.sh"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(deploy.returncode, 0, deploy.stdout + deploy.stderr)
        self.assertIn("drops-by-field", deploy.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_run_local_exits_nonzero_when_deploy_fails(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        shutil.copy(os.path.join(ROOT, "run_local.sh"), os.path.join(root, "run_local.sh"))
        with open(os.path.join(root, "jobwatch.py"), "w", encoding="utf-8") as handle:
            handle.write(
                "import sys\n"
                "sys.stderr.write('polling 1 board(s)...\\n')\n"
                "sys.stdout.write("
                "'# jobwatch\\n\\n"
                "SUMMARY new=0 closed=0 live=3 boards_ok=1 boards_failed=0 "
                "drops=0 drops_none=0\\n')\n"
            )
        with open(os.path.join(root, "deploy_site.sh"), "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\necho deploy boom >&2\nexit 1\n")
        os.chmod(os.path.join(root, "deploy_site.sh"), 0o755)
        result = subprocess.run(
            ["bash", "./run_local.sh"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.returncode, 1)
        self.assertIn("site publish failed", result.stdout)


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
        self.assertIn("held", result.stdout)
        self.assertNotIn("site published", result.stdout)
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

    def test_cyrillic_mine_board_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("open the M\u0456ne")

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

    def test_data_tier_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('<div data-tier="rare">Acme Cloud</div>')

    def test_dataset_notes_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("el.dataset.notes = 'ping'")

    def test_dataset_tier_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("el.dataset.tier = 'rare'")

    def test_dataset_foo_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("el.dataset.foo")

    def test_el_plain_tier_passes(self):
        scan_public_text("el.tier = 'rare'")

    def test_obj_notes_access_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text('obj["notes"]')

    def test_obj_tier_access_passes(self):
        scan_public_text('obj["tier"]')


class KnownCompaniesHardcoded(unittest.TestCase):
    def test_orgs_file_cannot_whitelist_a_person_name(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "organizations.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"organizations": [{"name": "Jane Roe"}]}, handle)
        with mock.patch.object(sanitizer, "ORGS_PATH", path):
            self.assertNotIn("Jane Roe", sanitizer._known_companies())
            with self.assertRaises(SanitizerBlocked):
                sanitize({"name": "Jane Roe"})

    def test_hardcoded_company_still_passes(self):
        self.assertIn("Acme Cloud", sanitizer._known_companies())
        cleaned = sanitize({"name": "Acme Cloud"})
        self.assertEqual(cleaned["name"], "Acme Cloud")

    def test_known_companies_matches_jobwatch_boards(self):
        import jobwatch
        boards = {row["company"] for row in jobwatch.BOARDS}
        known = set(sanitizer._known_companies())
        self.assertEqual(boards, known - set(tx.SAMPLE_COMPANIES))

    def test_new_board_company_is_publishable(self):
        import jobwatch
        extra = jobwatch.BOARDS + (
            {"slug": "stripe", "company": "Stripe", "platform": "greenhouse", "board": "stripe"},
        )
        with mock.patch.object(jobwatch, "BOARDS", extra):
            self.assertIn("Stripe", sanitizer._known_companies())
            cleaned = sanitize({"name": "Stripe"})
            self.assertEqual(cleaned["name"], "Stripe")


class DenyPassLeaksAndUrls(unittest.TestCase):
    def test_skill_person_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(skills=["Jane Roe"]))

    def test_skill_ddos_passes(self):
        cleaned = sanitize(job_with(skills=["ddos"]))
        self.assertEqual(cleaned["skills"], ["ddos"])

    def test_locations_person_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(location="Seattle; Jane Roe home"))

    def test_org_locations_person_name_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, locations="Seattle; Jane Roe home"))

    def test_locations_city_passes(self):
        cleaned = sanitize(job_with(location="Seattle; Remote US"))
        self.assertEqual(cleaned["location"], "Seattle; Remote US")

    def test_org_locations_city_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, locations="Seattle; Remote US"))
        self.assertEqual(cleaned["locations"], "Seattle; Remote US")

    def test_interviewing_with_jane_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE - interviewing w/ Jane"))

    def test_title_dash_onsite_passes(self):
        cleaned = sanitize(job_with(title="Software Engineer - Onsite"))
        self.assertEqual(cleaned["title"], "Software Engineer - Onsite")

    def test_title_paren_onsite_passes(self):
        cleaned = sanitize(job_with(title="Software Engineer (Onsite)"))
        self.assertEqual(cleaned["title"], "Software Engineer (Onsite)")

    def test_title_offer_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE - offer"))

    def test_title_screen_with_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE - screen with desk"))

    def test_title_offer_a_role_passes(self):
        cleaned = sanitize(job_with(title="We offer a mitigation seat"))
        self.assertEqual(cleaned["title"], "We offer a mitigation seat")

    def test_applied_scientist_passes(self):
        cleaned = sanitize(job_with(title="Applied Scientist"))
        self.assertEqual(cleaned["title"], "Applied Scientist")

    def test_applied_ai_engineer_passes(self):
        cleaned = sanitize(job_with(title="Applied AI Engineer"))
        self.assertEqual(cleaned["title"], "Applied AI Engineer")

    def test_mine_safety_passes(self):
        cleaned = sanitize(job_with(title="Mine Safety"))
        self.assertEqual(cleaned["title"], "Mine Safety")

    def test_kanban_tools_engineer_passes(self):
        cleaned = sanitize(job_with(title="Kanban Tools Engineer"))
        self.assertEqual(cleaned["title"], "Kanban Tools Engineer")

    def test_offer_management_engineer_passes(self):
        cleaned = sanitize(job_with(title="Offer Management Engineer"))
        self.assertEqual(cleaned["title"], "Offer Management Engineer")

    def test_onsite_it_support_passes(self):
        cleaned = sanitize(job_with(title="Onsite IT Support"))
        self.assertEqual(cleaned["title"], "Onsite IT Support")

    def test_interviewing_platform_engineer_passes(self):
        cleaned = sanitize(job_with(title="Interviewing Platform Engineer"))
        self.assertEqual(cleaned["title"], "Interviewing Platform Engineer")

    def test_senior_applied_researcher_passes(self):
        cleaned = sanitize(job_with(title="Senior Applied Researcher"))
        self.assertEqual(cleaned["title"], "Senior Applied Researcher")

    def test_applied_ml_ads_passes(self):
        cleaned = sanitize(job_with(title="Applied ML, Ads"))
        self.assertEqual(cleaned["title"], "Applied ML, Ads")

    def test_screening_infrastructure_engineer_passes(self):
        cleaned = sanitize(job_with(title="Screening Infrastructure Engineer"))
        self.assertEqual(cleaned["title"], "Screening Infrastructure Engineer")

    def test_location_onsite_austin_passes(self):
        cleaned = sanitize(job_with(location="Onsite - Austin, TX"))
        self.assertEqual(cleaned["location"], "Onsite - Austin, TX")

    def test_swe_rejected_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE rejected"))

    def test_ghosted_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("ghosted")

    def test_phone_screen_tue_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("(phone screen Tue)")

    def test_refd_by_jane_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("ref'd by Jane")

    def test_referred_by_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="referred by Jane"))

    def test_declined_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE declined"))

    def test_reference_architecture_passes(self):
        cleaned = sanitize(job_with(title="Reference architecture"))
        self.assertEqual(cleaned["title"], "Reference architecture")

    def test_b64_token_in_free_text_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("token amFuZUB4LmNvbQ== leftover")

    def test_b64_token_in_url_path_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="https://example.com/jobs/amFuZUB4LmNvbQ=="))

    def test_greenhouse_numeric_job_url_passes(self):
        url = "https://boards.greenhouse.io/cloudflare/jobs/5891234"
        cleaned = sanitize(job_with(url=url))
        self.assertEqual(cleaned["url"], url)

    def test_ashby_uuid_job_url_passes(self):
        url = "https://jobs.ashbyhq.com/openai/6f8c2e1a-4b3d-4c2a-9f1e-8a7b6c5d4e3f"
        cleaned = sanitize(job_with(url=url))
        self.assertEqual(cleaned["url"], url)

    def test_lever_uuid_job_url_passes(self):
        url = "https://jobs.lever.co/netflix/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        cleaned = sanitize(job_with(url=url))
        self.assertEqual(cleaned["url"], url)

    def test_hex_job_id_url_passes(self):
        url = "https://jobs.ashbyhq.com/openai/6f8c2e1a4b3d4c2a9f1e8a7b6c5d4e3f"
        cleaned = sanitize(job_with(url=url))
        self.assertEqual(cleaned["url"], url)

    def test_cyrillic_mine_in_team_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, team="M\u0456ne"))

    def test_cyrillic_kanban_in_team_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, team="K\u0430nban"))

    def test_latin_team_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="Edge Platform"))
        self.assertEqual(cleaned["team"], "Edge Platform")

    def test_double_escaped_at_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("jr\\\\x40x.com")

    def test_x40_literal_without_escape_passes(self):
        scan_public_text("jr x40 token in a title")

    def test_punycode_host_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="https://xn--nxasmq2b.example/jobs/1"))

    def test_non_ascii_host_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="https://m\u00fcnich.example.com/jobs/1"))

    def test_swe_pipe_applied_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE | applied"))

    def test_swe_bracket_applied_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE [applied]"))

    def test_payments_interview_fri_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Payments [interview Fri]"))

    def test_swe_emoji_onsite_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE \U0001F4C5 onsite"))

    def test_onsite_tuesday_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="onsite Tue"))

    def test_onsite_with_jane_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="onsite w/ Jane"))

    def test_final_round_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE - final round"))

    def test_take_home_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE | take-home"))

    def test_waitlisted_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("waitlisted")

    def test_withdrew_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("withdrew")

    def test_withdrawn_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE withdrawn"))

    def test_finals_club_title_passes(self):
        cleaned = sanitize(job_with(title="Reliability Engineer"))
        self.assertEqual(cleaned["title"], "Reliability Engineer")

    def test_hex_ascii_in_text_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("6a616e6540782e636f6d")

    def test_hex_ascii_in_url_path_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="https://example.com/jobs/6a616e6540782e636f6d"))

    def test_hex_ascii_inside_uuid_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://example.com/jobs/6a616e65-4078-2e63-6f6d-000000000001"
            ))

    def test_workday_job_url_passes(self):
        url = (
            "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
            "crowdstrikecareers/job/DDoS-Mitigation_R12345"
        )
        cleaned = sanitize(job_with(url=url))
        self.assertEqual(cleaned["url"], url)

    def test_unpadded_b64_path_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="https://example.com/r/amFuZUB4LmNvbQ"))

    def test_unpadded_b64_token_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("leak amFuZUB4LmNvbQ leftover")

    def test_real_word_twelve_plus_passes(self):
        cleaned = sanitize(job_with(title="Infrastructure Engineer"))
        self.assertEqual(cleaned["title"], "Infrastructure Engineer")

    def test_camelcase_identifier_passes(self):
        scan_public_text("document.querySelectorAll")

    def test_kanban_alone_in_team_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, team="Kanban"))

    def test_stage_word_in_team_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, team="applied"))

    def test_stage_word_in_locations_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, locations="interview"))

    def test_careers_path_applied_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, careers="https://example.com/jobs/applied"))

    def test_careers_clean_path_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, careers="https://example.com/acme/careers"))
        self.assertEqual(cleaned["careers"], "https://example.com/acme/careers")

    def test_hex_at_escape_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("ada\\x40example.com")

    def test_percent_at_in_url_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="https://example.com/jobs/1?e=ada%40example.com"))

    def test_person_name_in_url_path_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="https://example.com/jobs/1/jane-roe-referral"))

    def test_base64_email_in_query_is_blocked(self):
        token = __import__("base64").b64encode(b"ada@example.com").decode("ascii")
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="https://example.com/jobs/1?e=" + token))

    def test_javascript_url_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="javascript:alert(1)"))

    def test_ftp_url_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="ftp://example.com/jobs/1"))

    def test_data_url_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="data:text/html,hi"))

    def test_http_url_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="http://example.com/jobs/1"))

    def test_https_url_strips_query_and_passes(self):
        cleaned = sanitize(job_with(url="https://example.com/jobs/100?utm=1#top"))
        self.assertEqual(cleaned["url"], "https://example.com/jobs/100")
        self.assertNotIn("?", cleaned["url"])
        self.assertNotIn("#", cleaned["url"])


class DenyPassOnsiteWhenAndAllowlist(unittest.TestCase):
    def test_title_onsite_paren_day_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE Onsite (Fri)"))

    def test_title_on_site_thu_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="ON SITE THU"))

    def test_title_onsite_tmrw_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="onsite tmrw"))

    def test_title_onsite_tomorrow_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="onsite tomorrow"))

    def test_title_onsite_today_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="onsite today"))

    def test_title_onsite_next_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="onsite next"))

    def test_title_thu_onsite_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="Thu onsite"))

    def test_title_onsite_office_emoji_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE \U0001F3E2 Onsite"))

    def test_team_on_site_thu_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, team="ON SITE THU"))

    def test_team_onsite_paren_day_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, team="Onsite (Fri)"))

    def test_team_onsite_office_emoji_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, team="Onsite \U0001F3E2"))

    def test_got_offer_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="got offer"))

    def test_offer_bang_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="offer!"))

    def test_standalone_oa_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="OA"))

    def test_standalone_hm_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="HM"))

    def test_status_check_emoji_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE \u2705"))

    def test_status_cross_emoji_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, team="Edge \u274C"))

    def test_status_party_emoji_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            scan_public_text("hired \U0001F389")

    def test_status_calendar_emoji_in_locations_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(dict(CLEAN_ORG, locations="Denver \U0001F4C5"))

    def test_team_unknown_token_is_a_vocab_miss(self):
        with self.assertRaises(VocabMiss) as caught:
            sanitize(dict(CLEAN_ORG, team="Zebra Unit"))
        self.assertEqual(caught.exception.field, "team")

    def test_locations_unknown_city_is_a_vocab_miss(self):
        with self.assertRaises(VocabMiss) as caught:
            sanitize(dict(CLEAN_ORG, locations="Atlantis"))
        self.assertEqual(caught.exception.field, "locations")

    def test_team_applied_ai_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="Applied AI"))
        self.assertEqual(cleaned["team"], "Applied AI")

    def test_title_final_round_studios_passes(self):
        cleaned = sanitize(job_with(title="Final Round Studios Engineer"))
        self.assertEqual(cleaned["title"], "Final Round Studios Engineer")

    def test_title_takehome_assessments_platform_passes(self):
        cleaned = sanitize(job_with(title="Take-Home Assessments Platform"))
        self.assertEqual(cleaned["title"], "Take-Home Assessments Platform")

    def test_oauth_is_not_oa_status(self):
        cleaned = sanitize(job_with(title="OAuth Platform Engineer"))
        self.assertEqual(cleaned["title"], "OAuth Platform Engineer")

    def test_human_is_not_hm_status(self):
        cleaned = sanitize(job_with(title="Human Factors Engineer"))
        self.assertEqual(cleaned["title"], "Human Factors Engineer")

    def test_friday_without_onsite_passes(self):
        cleaned = sanitize(job_with(title="Friday Incident Response"))
        self.assertEqual(cleaned["title"], "Friday Incident Response")

    def test_locations_portland_or_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, locations="Portland, OR; US Remote"))
        self.assertEqual(cleaned["locations"], "Portland, OR; US Remote")


class DenyPassLiveBoardAndDrops(unittest.TestCase):
    def setUp(self):
        reset_drops()

    def test_netflix_city_state_country_no_spaces_passes(self):
        cleaned = sanitize(job_with(
            company="Netflix",
            location="Los Gatos,California,United States of America",
        ))
        self.assertEqual(cleaned["location"], "Los Gatos,California,United States of America")
        self.assertNotIn(sanitizer.REDACTED, cleaned["location"])

    def test_netflix_city_state_country_with_spaces_passes(self):
        cleaned = sanitize(job_with(
            company="Netflix",
            location="Los Gatos, California, United States of America",
        ))
        self.assertEqual(cleaned["location"], "Los Gatos, California, United States of America")

    def test_workday_applied_ai_ml_slug_passes(self):
        url = (
            "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
            "crowdstrikecareers/job/Applied-AI-ML_R12345"
        )
        cleaned = sanitize(job_with(company="CrowdStrike", url=url))
        self.assertEqual(cleaned["url"], url)

    def test_ashby_openai_uuid_url_still_passes(self):
        url = "https://jobs.ashbyhq.com/openai/6f8c2e1a-4b3d-4c2a-9f1e-8a7b6c5d4e3f"
        cleaned = sanitize(job_with(company="OpenAI", url=url))
        self.assertEqual(cleaned["url"], url)

    def test_emdash_applied_ai_is_not_a_status(self):
        cleaned = sanitize(job_with(title="Global Programs \u2014 Applied AI Engineering"))
        self.assertEqual(cleaned["title"], "Global Programs \u2014 Applied AI Engineering")

    def test_dash_applied_ai_is_not_a_status(self):
        cleaned = sanitize(job_with(title="Global Programs - Applied AI Engineering"))
        self.assertEqual(cleaned["title"], "Global Programs - Applied AI Engineering")

    def test_swe_dash_applied_still_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE - applied"))

    def test_swe_final_round_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE final round"))

    def test_swe_takehome_due_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="SWE take-home due"))

    def test_url_payments_onsite_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(url="https://example.com/jobs/Payments(onsite)"))

    def test_title_paren_onsite_still_passes(self):
        cleaned = sanitize(job_with(title="Software Engineer (Onsite)"))
        self.assertEqual(cleaned["title"], "Software Engineer (Onsite)")

    def test_redacted_marker_fails_the_page(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="leak " + sanitizer.REDACTED))

    def test_vocab_miss_is_not_sanitizer_blocked(self):
        with self.assertRaises(VocabMiss):
            sanitize(job_with(location="Atlantis"))
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(title="ada@example.com"))

    def test_sanitize_records_drops_unknown_city(self):
        reset_drops()
        records = [job_with(id="greenhouse:acme:{}".format(i)) for i in range(10)]
        records[0] = job_with(id="greenhouse:acme:0", location="Atlantis")
        kept = sanitize_records(records)
        self.assertEqual(len(kept), 9)
        self.assertNotIn(sanitizer.REDACTED, json.dumps(kept))
        self.assertEqual(last_drop_counts(), {"location": 1})
        self.assertIn("drops_location=1", format_drop_counts())
        self.assertNotIn("Atlantis", format_drop_counts())

    def test_pii_still_fails_the_whole_page(self):
        reset_drops()
        with self.assertRaises(SanitizerBlocked):
            sanitize_records([
                job_with(location="Denver, CO"),
                job_with(id="greenhouse:acme:101", title="write ada@example.com"),
            ])

    def test_drop_counts_are_per_field_name(self):
        reset_drops()
        records = [job_with(id="greenhouse:acme:{}".format(i)) for i in range(30)]
        records[0] = job_with(id="greenhouse:acme:0", location="Atlantis")
        records[1] = job_with(id="greenhouse:acme:1", location="El Dorado")
        records[2] = dict(CLEAN_ORG, team="Zebra Unit")
        sanitize_records(records)
        self.assertEqual(last_drop_counts(), {"location": 2, "team": 1})
        text = format_drop_counts()
        self.assertEqual(text, "drops_location=2 drops_team=1")
        self.assertNotIn("Atlantis", text)
        self.assertNotIn("Zebra", text)

    def test_drop_rate_over_ten_percent_fails_page(self):
        reset_drops()
        records = [job_with(id="greenhouse:acme:{}".format(i)) for i in range(10)]
        records[0] = job_with(id="greenhouse:acme:0", location="Atlantis")
        records[1] = job_with(id="greenhouse:acme:1", location="El Dorado")
        with self.assertRaises(SanitizerBlocked):
            sanitize_records(records)

    def test_one_drop_in_ten_keeps_the_page(self):
        reset_drops()
        records = [job_with(id="greenhouse:acme:{}".format(i)) for i in range(10)]
        records[0] = job_with(id="greenhouse:acme:0", location="Atlantis")
        kept = sanitize_records(records)
        self.assertEqual(len(kept), 9)
        self.assertEqual(last_drop_counts(), {"location": 1})

    def test_drop_count_over_25_fails_page(self):
        reset_drops()
        records = [
            job_with(id="greenhouse:acme:{}".format(i), location="Denver, CO")
            for i in range(260)
        ]
        for i in range(26):
            records[i] = job_with(
                id="greenhouse:acme:{}".format(i),
                location="Atlantis",
            )
        with self.assertRaises(SanitizerBlocked):
            sanitize_records(records)

    def test_live_fixture_zero_percent_blocked(self):
        data = fixture_json("live_postings.json")
        postings = data["postings"]
        self.assertEqual(len(postings), 17)
        for posting in postings:
            self.assertEqual(
                set(posting),
                {"id", "board", "company", "title", "location", "url"},
            )
        blocked = 0
        reset_drops()
        for index, posting in enumerate(postings):
            record = job_with(
                id=posting["id"] or "greenhouse:acme:{}".format(index),
                board=posting["board"],
                company=posting["company"],
                title=posting["title"],
                location=posting["location"],
                url=posting["url"],
            )
            try:
                cleaned = sanitize(record)
            except (SanitizerBlocked, VocabMiss):
                blocked += 1
                continue
            self.assertNotIn(sanitizer.REDACTED, json.dumps(cleaned))
        self.assertEqual(blocked, 0)
        self.assertEqual(blocked / float(len(postings)), 0.0)


class DenyPassQaRereview(unittest.TestCase):
    def setUp(self):
        reset_drops()

    def _ordered_job(self, first_key, first_value, second_key, second_value):
        record = {first_key: first_value, second_key: second_value}
        for key, value in CLEAN_JOB.items():
            if key not in record:
                record[key] = value
        return record

    def test_deny_runs_before_vocab_miss_location_first(self):
        record = self._ordered_job(
            "location", "Zzyzx, Atlantis",
            "title", "SWE got offer",
        )
        self.assertEqual(list(record)[:2], ["location", "title"])
        with self.assertRaises(SanitizerBlocked):
            sanitize(record)

    def test_deny_runs_before_vocab_miss_title_first(self):
        record = self._ordered_job(
            "title", "SWE got offer",
            "location", "Zzyzx, Atlantis",
        )
        self.assertEqual(list(record)[:2], ["title", "location"])
        with self.assertRaises(SanitizerBlocked):
            sanitize(record)

    def test_vocab_miss_alone_still_drops_both_key_orders(self):
        loc_first = self._ordered_job(
            "location", "Zzyzx, Atlantis",
            "title", "DDoS Mitigation Engineer",
        )
        title_first = self._ordered_job(
            "title", "DDoS Mitigation Engineer",
            "location", "Zzyzx, Atlantis",
        )
        with self.assertRaises(VocabMiss) as caught:
            sanitize(loc_first)
        self.assertEqual(caught.exception.field, "location")
        with self.assertRaises(VocabMiss) as caught:
            sanitize(title_first)
        self.assertEqual(caught.exception.field, "location")

    def test_workday_director_data_infra_url_passes(self):
        url = (
            "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
            "crowdstrikecareers/job/USA---New-York-NY/"
            "Director--Engineering---Data-Infrastructure---Reliability_R30161"
        )
        cleaned = sanitize(job_with(company="CrowdStrike", url=url))
        self.assertEqual(cleaned["url"], url)

    def test_workday_data_scientist_applied_ai_ml_url_passes(self):
        url = (
            "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
            "crowdstrikecareers/job/USA---New-York-NY/"
            "Data-Scientist--Applied-AI-ML_R29843"
        )
        cleaned = sanitize(job_with(company="CrowdStrike", url=url))
        self.assertEqual(cleaned["url"], url)

    def test_workday_triple_dash_location_and_req_suffix_pass(self):
        url = (
            "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
            "crowdstrikecareers/job/USA---Sunnyvale-CA/"
            "Sr-Engineer--AI---AI-Detection-and-Response--AIDR---Hybrid-_R26576-1"
        )
        cleaned = sanitize(job_with(company="CrowdStrike", url=url))
        self.assertEqual(cleaned["url"], url)

    def test_greenhouse_hex_email_path_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/6a616e6540782e636f6d",
            ))

    def test_ashby_hex_email_uuid_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/6a616e65-4078-2e63-6f6d-000000000001",
            ))

    def test_numeric_ats_id_still_exempt(self):
        url = "https://boards.greenhouse.io/cloudflare/jobs/7558153"
        cleaned = sanitize(job_with(company="Cloudflare", url=url))
        self.assertEqual(cleaned["url"], url)

    def test_real_uuid_without_printable_hex_still_passes(self):
        url = "https://jobs.ashbyhq.com/openai/3c67f712-697d-48d8-b05c-01be896e61da"
        cleaned = sanitize(job_with(company="OpenAI", url=url))
        self.assertEqual(cleaned["url"], url)

    def test_multi_city_semicolon_locations_pass(self):
        cleaned = sanitize(job_with(
            location="Austin, TX; Dallas, TX; New York, NY",
        ))
        self.assertEqual(cleaned["location"], "Austin, TX; Dallas, TX; New York, NY")

    def test_washington_dc_district_of_columbia_passes(self):
        loc = "Washington DC,District of Columbia,United States of America"
        cleaned = sanitize(job_with(location=loc))
        self.assertEqual(cleaned["location"], loc)

    def test_takehome_assessments_platform_still_passes(self):
        cleaned = sanitize(job_with(title="Take-Home Assessments Platform"))
        self.assertEqual(cleaned["title"], "Take-Home Assessments Platform")

    def test_team_developer_platform_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="Developer Platform"))
        self.assertEqual(cleaned["team"], "Developer Platform")

    def test_team_ads_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="Ads"))
        self.assertEqual(cleaned["team"], "Ads")

    def test_team_studio_technology_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="Studio Technology"))
        self.assertEqual(cleaned["team"], "Studio Technology")

    def test_drop_rate_exactly_ten_percent_keeps_page(self):
        records = [job_with(id="greenhouse:acme:{}".format(i)) for i in range(10)]
        records[0] = job_with(id="greenhouse:acme:0", location="Atlantis")
        kept = sanitize_records(records)
        self.assertEqual(len(kept), 9)
        self.assertEqual(last_drop_counts(), {"location": 1})

    def test_drop_count_exactly_25_keeps_page(self):
        records = [
            job_with(id="greenhouse:acme:{}".format(i), location="Denver, CO")
            for i in range(250)
        ]
        for i in range(25):
            records[i] = job_with(
                id="greenhouse:acme:{}".format(i),
                location="Atlantis",
            )
        kept = sanitize_records(records)
        self.assertEqual(len(kept), 225)
        self.assertEqual(last_drop_counts(), {"location": 25})

    def test_drop_count_exactly_three_percent_keeps_page(self):
        records = [
            job_with(id="greenhouse:acme:{}".format(i), location="Denver, CO")
            for i in range(1000)
        ]
        for i in range(30):
            records[i] = job_with(
                id="greenhouse:acme:{}".format(i),
                location="Atlantis",
            )
        kept = sanitize_records(records)
        self.assertEqual(len(kept), 970)
        self.assertEqual(last_drop_counts(), {"location": 30})

    def test_drop_count_over_three_percent_fails_page(self):
        records = [
            job_with(id="greenhouse:acme:{}".format(i), location="Denver, CO")
            for i in range(1000)
        ]
        for i in range(31):
            records[i] = job_with(
                id="greenhouse:acme:{}".format(i),
                location="Atlantis",
            )
        with self.assertRaises(SanitizerBlocked):
            sanitize_records(records)

    def test_dropped_value_never_appears_in_logs_or_output(self):
        buf = io.StringIO()
        records = [job_with(id="greenhouse:acme:{}".format(i)) for i in range(10)]
        records[0] = job_with(id="greenhouse:acme:0", location="Atlantis")
        with mock.patch("sys.stderr", buf):
            kept = sanitize_records(records)
            print(format_drop_counts(), file=sys.stderr)
        dumped = json.dumps(kept)
        logs = buf.getvalue()
        for sink in (dumped, logs, format_drop_counts(), json.dumps(last_drop_counts())):
            self.assertNotIn("Atlantis", sink)
            self.assertNotIn(sanitizer.REDACTED, sink)
        self.assertIn("drops_location=1", logs)

    def test_render_org_vocab_miss_uses_drop_budget(self):
        import render_site as rs
        state = example("jobwatch_state.sample.json")
        orgs = [dict(row) for row in example("organizations.sample.json")["organizations"]]
        orgs[0]["locations"] = "Atlantis"
        html, js = rs.render(state, "demo", orgs, [])
        self.assertNotIn("Atlantis", html)
        self.assertNotIn("Atlantis", js)
        self.assertEqual(last_drop_counts().get("locations"), 1)
        self.assertNotIn("Atlantis", format_drop_counts())

    def test_render_org_vocab_miss_over_budget_fails_page(self):
        import render_site as rs
        state = example("jobwatch_state.sample.json")
        template = example("organizations.sample.json")["organizations"][0]
        orgs = [dict(template, locations="Atlantis") for _ in range(26)]
        with self.assertRaises(SanitizerBlocked):
            rs.render(state, "demo", orgs, [])

    def test_main_catches_org_vocab_miss(self):
        import render_site as rs
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        out = os.path.join(tmp, "site")
        state_path = os.path.join(tmp, "state.json")
        orgs_path = os.path.join(tmp, "organizations.json")
        with open(state_path, "w", encoding="utf-8") as handle:
            json.dump(example("jobwatch_state.sample.json"), handle)
        raw_orgs = [dict(row) for row in example("organizations.sample.json")["organizations"]]
        raw_orgs[0]["locations"] = "Atlantis"
        raw_orgs[0]["why"] = "secret"
        with open(orgs_path, "w", encoding="utf-8") as handle:
            json.dump({"organizations": raw_orgs}, handle)
        buf = io.StringIO()
        with mock.patch.object(rs, "STATE_PATH", state_path), \
                mock.patch.object(rs, "ORGS_PATH", orgs_path), \
                mock.patch.object(rs, "HIDDEN_PATH", os.path.join(tmp, "dismissed.json")), \
                mock.patch.object(sys, "argv", ["render_site.py", "--out", out, "--slug", "demo"]), \
                mock.patch("sys.stderr", buf):
            rs.main()
        with io.open(os.path.join(out, "demo"), encoding="utf-8") as handle:
            page = handle.read()
        self.assertNotIn("Atlantis", page)
        self.assertNotIn("secret", page)
        self.assertNotIn("Atlantis", buf.getvalue())

    def test_record_live_writes_pending_not_committed(self):
        import jobwatch
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        pending = os.path.join(tmp, "live_postings.pending.json")
        committed = os.path.join(FIXTURES, "live_postings.json")
        vocab = os.path.join(FIXTURES, "live_field_vocab.json")
        with io.open(committed, encoding="utf-8") as handle:
            before_c = handle.read()
        with io.open(vocab, encoding="utf-8") as handle:
            before_v = handle.read()
        matches = {
            "x": {
                "id": "greenhouse:acme:1",
                "board": "acme",
                "company": "Acme Cloud",
                "title": "Zzyzxian Platform Engineer",
                "location": "Denver, CO",
                "url": "https://example.com/jobs/1",
            }
        }
        with mock.patch.object(sanitizer, "LIVE_PENDING_PATH", pending), \
                mock.patch.object(jobwatch, "poll", return_value=(matches, ["acme"], [], {})):
            payload = jobwatch.record_public_postings()
        self.assertTrue(os.path.exists(pending))
        with io.open(committed, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before_c)
        with io.open(vocab, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before_v)
        self.assertFalse(os.path.exists(os.path.join(tmp, "live_field_vocab.json")))
        with io.open(pending, encoding="utf-8") as handle:
            written = json.load(handle)
        self.assertEqual(written["postings"][0]["title"], "Zzyzxian Platform Engineer")
        self.assertNotIn("team", written)
        self.assertNotIn("Zzyzxian", before_v)
        with self.assertRaises(VocabMiss):
            sanitize(dict(CLEAN_ORG, team="Zzyzxian"))
        self.assertEqual(payload["match_count"], 1)

    def test_record_live_refuses_committed_dest(self):
        import jobwatch
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        pending = os.path.join(tmp, "live_postings.pending.json")
        committed = os.path.join(FIXTURES, "live_postings.json")
        vocab = os.path.join(FIXTURES, "live_field_vocab.json")
        with io.open(committed, encoding="utf-8") as handle:
            before_c = handle.read()
        with io.open(vocab, encoding="utf-8") as handle:
            before_v = handle.read()
        matches = {
            "x": {
                "id": "greenhouse:acme:1",
                "board": "acme",
                "company": "Acme Cloud",
                "title": "Zzyzxian Platform Engineer",
                "location": "Denver, CO",
                "url": "https://example.com/jobs/1",
            }
        }
        with mock.patch.object(sanitizer, "LIVE_PENDING_PATH", pending), \
                mock.patch.object(jobwatch, "poll", return_value=(matches, ["acme"], [], {})):
            jobwatch.record_public_postings(dest=sanitizer.LIVE_POSTINGS_PATH)
        with io.open(committed, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before_c)
        with io.open(vocab, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before_v)
        self.assertTrue(os.path.exists(pending))


class DenyPassCisoBar(unittest.TestCase):
    B64_PADDED = "amFuZUB4LmNvbQ=="
    B64_UNPADDED = "amFuZUB4LmNvbQ"
    B64URL = "amFuZUB4LmNvbT4-"
    B64_PCT = "amFuZUB4LmNvbQ%3D%3D"
    B64_OF_HEX = "NmE2MTZlNjU0MDc4MmU2MzZmNmQ="
    B64_OF_PCT = "amFuZSU0MHguY29t"
    B64_PHONE = "NTU1LTEyMy00NTY3"

    def test_greenhouse_slug_b64_padded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + self.B64_PADDED,
            ))

    def test_ashby_slug_b64_padded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + self.B64_PADDED,
            ))

    def test_workday_slug_b64_padded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + self.B64_PADDED
                ),
            ))

    def test_greenhouse_slug_b64_unpadded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + self.B64_UNPADDED,
            ))

    def test_ashby_slug_b64_unpadded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + self.B64_UNPADDED,
            ))

    def test_workday_slug_b64_unpadded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + self.B64_UNPADDED
                ),
            ))

    def test_greenhouse_slug_b64url_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + self.B64URL,
            ))

    def test_ashby_slug_b64url_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + self.B64URL,
            ))

    def test_workday_slug_b64url_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + self.B64URL
                ),
            ))

    def test_greenhouse_slug_percent_b64_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + self.B64_PCT,
            ))

    def test_ashby_slug_percent_b64_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + self.B64_PCT,
            ))

    def test_workday_slug_percent_b64_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + self.B64_PCT
                ),
            ))

    def test_greenhouse_slug_b64_of_hex_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + self.B64_OF_HEX,
            ))

    def test_ashby_slug_b64_of_hex_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + self.B64_OF_HEX,
            ))

    def test_workday_slug_b64_of_hex_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + self.B64_OF_HEX
                ),
            ))

    def test_greenhouse_slug_b64_of_percent_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + self.B64_OF_PCT,
            ))

    def test_ashby_slug_b64_of_percent_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + self.B64_OF_PCT,
            ))

    def test_workday_slug_b64_of_percent_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + self.B64_OF_PCT
                ),
            ))

    def test_greenhouse_slug_b64_phone_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + self.B64_PHONE,
            ))

    def test_ashby_slug_b64_phone_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + self.B64_PHONE,
            ))

    def test_workday_slug_b64_phone_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + self.B64_PHONE
                ),
            ))

    def test_query_b64_email_fails_page_not_stripped(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://example.com/jobs/100?e=" + self.B64_PADDED,
            ))

    def test_query_b64_of_hex_fails_page_not_stripped(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://example.com/jobs/100?e=" + self.B64_OF_HEX,
            ))

    def test_openai_rfc4122_uuid_must_pass(self):
        url = "https://jobs.ashbyhq.com/openai/5a647e2b-5d6c-4c71-aeea-b16e3fda4b3f"
        cleaned = sanitize(job_with(company="OpenAI", url=url))
        self.assertEqual(cleaned["url"], url)

    def test_uuid_shaped_invalid_variant_still_fails(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/6a616e65-4078-2e63-6f6d-000000000001",
            ))

    def test_title_comma_takehome_assessments_platform_passes(self):
        cleaned = sanitize(job_with(
            title="Software Engineer, Take-Home Assessments Platform",
        ))
        self.assertEqual(
            cleaned["title"],
            "Software Engineer, Take-Home Assessments Platform",
        )

    def test_team_payments_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="Payments"))
        self.assertEqual(cleaned["team"], "Payments")

    def test_team_ml_infra_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="ML Infra"))
        self.assertEqual(cleaned["team"], "ML Infra")

    def test_team_identity_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="Identity"))
        self.assertEqual(cleaned["team"], "Identity")

    def test_team_workers_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="Workers"))
        self.assertEqual(cleaned["team"], "Workers")

    def test_team_zero_trust_passes(self):
        cleaned = sanitize(dict(CLEAN_ORG, team="Zero Trust"))
        self.assertEqual(cleaned["team"], "Zero Trust")

    E164 = "+12065550142"
    E164_B64 = "KzEyMDY1NTUwMTQy"
    E164_B64_PADDED = "KzEyMDY1NTUwMTQ="

    def test_greenhouse_slug_b64_e164_unpadded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + self.E164_B64,
            ))

    def test_ashby_slug_b64_e164_unpadded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + self.E164_B64,
            ))

    def test_workday_slug_b64_e164_unpadded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + self.E164_B64
                ),
            ))

    def test_greenhouse_slug_b64_e164_padded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + self.E164_B64_PADDED,
            ))

    def test_ashby_slug_b64_e164_padded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + self.E164_B64_PADDED,
            ))

    def test_workday_slug_b64_e164_padded_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + self.E164_B64_PADDED
                ),
            ))

    def test_greenhouse_e164_slug_piece_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr_" + self.E164,
            ))

    def test_ashby_e164_slug_piece_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr_" + self.E164,
            ))

    def test_workday_e164_slug_piece_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr_"
                    + self.E164
                ),
            ))

    def test_greenhouse_e164_path_segment_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/" + self.E164,
            ))

    def test_ashby_e164_path_segment_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/" + self.E164,
            ))

    def test_workday_e164_path_segment_is_blocked(self):
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/"
                    + self.E164
                ),
            ))

    def test_bare_ten_digit_ats_id_still_passes(self):
        url = "https://boards.greenhouse.io/cloudflare/jobs/1206555014"
        cleaned = sanitize(job_with(company="Cloudflare", url=url))
        self.assertEqual(cleaned["url"], url)

    def _nested_b64(self, text, levels):
        raw = text.encode("ascii")
        for _ in range(levels):
            raw = __import__("base64").b64encode(raw)
        return raw.decode("ascii")

    def test_b64_nested_3_levels_is_blocked(self):
        token = self._nested_b64("jane@x.com", 3)
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://boards.greenhouse.io/acme/jobs/Sr-Engineer_" + token,
            ))

    def test_b64_nested_5_levels_is_blocked(self):
        token = self._nested_b64("jane@x.com", 5)
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                url="https://jobs.ashbyhq.com/openai/Sr-Engineer_" + token,
            ))

    def test_b64_nested_10_levels_is_blocked(self):
        token = self._nested_b64("jane@x.com", 10)
        with self.assertRaises(SanitizerBlocked):
            sanitize(job_with(
                company="CrowdStrike",
                url=(
                    "https://crowdstrike.wd5.myworkdayjobs.com/en-US/"
                    "crowdstrikecareers/job/USA---New-York-NY/Sr-Engineer_"
                    + token
                ),
            ))


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
    DenyPassDataAndDataset, DeploySiteHold, KnownCompaniesHardcoded,
    DenyPassLeaksAndUrls, DenyPassOnsiteWhenAndAllowlist,
    DenyPassLiveBoardAndDrops, DenyPassQaRereview, DenyPassCisoBar,
)

EXPECTED_SANITIZER_TESTS = 336


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
