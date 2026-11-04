#!/usr/bin/env python3
"""Tests for the pull-request reviewer in `tools/pr_review.py`."""

import io
import json
import os
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from email.message import Message

try:
    from tools import pr_review
except ModuleNotFoundError:
    import pr_review


def pull(**overrides):
    value = {
        "number": 31,
        "title": "tuic: bound pending stream tasks",
        "body": "",
        "draft": False,
        "changed_files": 3,
        "additions": 12,
        "deletions": 30,
        "head": {"sha": "a" * 40},
        "base": {"ref": "main"},
        "user": {"login": "int8-ptr"},
    }
    value.update(overrides)
    return value


CLEAN = {"summary": "Изменение ограничивает очередь потоков.", "verdict": "approve", "findings": []}


class FakeGitHub:
    def __init__(
        self,
        *,
        token="reviewer-token",
        login="murmur-reviewer",
        pull_value=None,
        diff="+hello\n-world\n",
        reviews=None,
        fail_submit=False,
    ):
        self.token = token
        self.login = login
        self.pull_value = pull_value or pull()
        self.diff_value = diff
        self.reviews_value = [] if reviews is None else reviews
        self.fail_submit = fail_submit
        self.submitted = []

    def pull(self, number):
        return self.pull_value

    def diff(self, number):
        return self.diff_value

    def reviews(self, number):
        return self.reviews_value

    def viewer_login(self):
        return self.login

    def submit_review(self, number, review):
        if self.fail_submit:
            raise pr_review.ReviewError("POST submit: HTTP 422")
        self.submitted.append(review)
        return {"id": 900 + len(self.submitted)}


def reviewer(github, answer=CLEAN, **kwargs):
    replies = answer if isinstance(answer, list) else [answer]
    replies = [json.dumps(item) if isinstance(item, dict) else item for item in replies]

    def complete(prompt):
        return replies.pop(0)

    return pr_review.Reviewer(
        github=github,
        complete=complete,
        repo="labi-le/murmur",
        number=31,
        model="gemini-4-argon",
        log=lambda message: None,
        **kwargs,
    )


class ParseTests(unittest.TestCase):
    def test_plain_and_fenced_json_are_accepted(self):
        payload = {"summary": "ok", "verdict": "approve", "findings": []}
        self.assertEqual(pr_review.parse_review(json.dumps(payload)), payload)
        fenced = "```json\n" + json.dumps(payload) + "\n```"
        self.assertEqual(pr_review.parse_review(fenced), payload)

    def test_findings_are_normalised(self):
        answer = json.dumps(
            {
                "summary": "s",
                "verdict": "request_changes",
                "findings": [
                    {
                        "severity": "p1",
                        "file": "crates/tuic/src/lib.rs",
                        "line": 12,
                        "claim": "c",
                        "evidence": "e",
                    }
                ],
            }
        )
        review = pr_review.parse_review(answer)
        self.assertEqual(review["findings"][0]["severity"], "P1")
        self.assertEqual(review["findings"][0]["line"], 12)

    def test_invalid_severity_missing_claim_and_bad_verdict_are_rejected(self):
        for payload in (
            {"summary": "s", "verdict": "approve", "findings": [{"severity": "P9", "file": "a", "claim": "c"}]},
            {"summary": "s", "verdict": "approve", "findings": [{"severity": "P1", "file": "a", "claim": ""}]},
            {"summary": "s", "verdict": "lgtm", "findings": []},
            {"summary": "s", "verdict": "approve", "findings": "none"},
        ):
            with self.assertRaises(pr_review.ReviewError):
                pr_review.parse_review(json.dumps(payload))

    def test_answer_without_json_object_is_rejected(self):
        with self.assertRaises(pr_review.ReviewError):
            pr_review.parse_review("I think this looks fine")

    def test_non_integer_line_is_dropped(self):
        answer = json.dumps(
            {
                "summary": "s",
                "verdict": "approve",
                "findings": [{"severity": "P3", "file": "a.rs", "line": "12", "claim": "c"}],
            }
        )
        self.assertIsNone(pr_review.parse_review(answer)["findings"][0]["line"])


class GitHubErrorTests(unittest.TestCase):
    def test_403_reports_the_permission_github_expects(self):
        headers = Message()
        headers["X-Accepted-GitHub-Permissions"] = "pull_requests=write"

        def failed(*args, **kwargs):
            return 403, '{"message":"Resource not accessible by personal access token"}', headers

        original = pr_review._request
        pr_review._request = failed
        try:
            with self.assertRaises(pr_review.ReviewError) as caught:
                pr_review.GitHub("token", "labi-le/murmur")._call("/pulls/31/reviews", method="POST", payload={})
        finally:
            pr_review._request = original
        self.assertIn("accepted: pull_requests=write", str(caught.exception))


class EventTests(unittest.TestCase):
    def review(self, *severities, verdict="approve"):
        return {
            "summary": "",
            "verdict": verdict,
            "findings": [
                {"severity": severity, "file": "a.rs", "line": 1, "claim": "c", "evidence": ""}
                for severity in severities
            ],
        }

    def test_blocking_findings_request_changes(self):
        self.assertEqual(pr_review.decide_event(self.review("P0")), "REQUEST_CHANGES")
        self.assertEqual(pr_review.decide_event(self.review("P2", "P1")), "REQUEST_CHANGES")

    def test_non_blocking_findings_approve(self):
        self.assertEqual(pr_review.decide_event(self.review("P2", "P3")), "APPROVE")

    def test_model_verdict_alone_can_request_changes(self):
        self.assertEqual(pr_review.decide_event(self.review(verdict="request_changes")), "REQUEST_CHANGES")


class BodyTests(unittest.TestCase):
    def test_body_lists_findings_with_locations(self):
        review = {
            "summary": "Кратко.",
            "verdict": "request_changes",
            "findings": [
                {"severity": "P1", "file": "crates/b.rs", "line": 7, "claim": "вторая", "evidence": "e2"},
                {"severity": "P0", "file": "crates/a.rs", "line": None, "claim": "первая", "evidence": "e1"},
            ],
        }
        body = pr_review.review_body(review, "REQUEST_CHANGES")
        self.assertIn("Кратко.", body)
        self.assertIn("crates/a.rs", body)
        self.assertIn("crates/b.rs:7", body)
        self.assertLess(body.index("P0 — `crates/a.rs`"), body.index("P1 — `crates/b.rs:7`"))
        for boilerplate in ("Автоматическое", "Ревьюер", "gemini-4-argon", "<!--"):
            self.assertNotIn(boilerplate, body)

    def test_approve_without_findings_carries_no_body(self):
        review = {"summary": "Кратко.", "verdict": "approve", "findings": []}
        self.assertEqual(pr_review.review_body(review, "APPROVE"), "")

    def test_verdict_only_request_changes_keeps_the_summary(self):
        review = {"summary": "Нужно поправить.", "verdict": "request_changes", "findings": []}
        self.assertEqual(pr_review.review_body(review, "REQUEST_CHANGES"), "Нужно поправить.")

    def test_body_is_capped(self):
        review = {
            "summary": "s" * 1000,
            "verdict": "approve",
            "findings": [
                {"severity": "P3", "file": "a.rs", "line": 1, "claim": "c" * 2000, "evidence": "e" * 2000}
                for _ in range(40)
            ],
        }
        body = pr_review.review_body(review, "APPROVE")
        self.assertLessEqual(len(body), pr_review.MAX_REVIEW_BODY_CHARS + 40)
        self.assertIn("[ревью обрезано", body)


class PromptTests(unittest.TestCase):
    def test_prompt_carries_agents_diff_and_truncation_marker(self):
        prompt = pr_review.build_prompt(pull(body="b" * 10), "+line\n" * 10, "# AGENTS\nrule", "gemini-4-argon")
        self.assertIn("Pull request #31", prompt)
        self.assertIn("# AGENTS.md", prompt)
        self.assertIn("+line", prompt)
        self.assertIn("gemini-4-argon", prompt)

    def test_oversized_diff_is_cut_with_a_marker(self):
        original = pr_review.MAX_DIFF_CHARS
        try:
            pr_review.MAX_DIFF_CHARS = 10
            prompt = pr_review.build_prompt(pull(), "x" * 100, "", "m")
        finally:
            pr_review.MAX_DIFF_CHARS = original
        self.assertIn("[diff обрезан: 90 символов отброшено]", prompt)

    def test_missing_agents_file_is_not_fatal(self):
        self.assertEqual(pr_review.read_text("/nonexistent/AGENTS.md", 10), "")

    def test_diff_paths_and_guide_selection_match_touched_domains(self):
        diff = (
            "diff --git a/crates/transport-vless/src/lib.rs b/crates/transport-vless/src/lib.rs\n"
            "--- a/crates/transport-vless/src/lib.rs\n"
            "+++ b/crates/transport-vless/src/lib.rs\n"
            "@@ -1 +1 @@\n"
            "+fn x() {}\n"
            "diff --git a/tools/pr_review.py b/tools/pr_review.py\n"
        )
        paths = pr_review.diff_paths(diff)
        self.assertEqual(paths, ["crates/transport-vless/src/lib.rs", "tools/pr_review.py"])
        guides = pr_review.select_guides(paths)
        self.assertIn("docs/architecture.md", guides)
        self.assertIn("docs/protocols.md", guides)
        self.assertIn("docs/verification.md", guides)
        self.assertNotIn("docs/benchmarks.md", guides)

    def test_prompt_renders_preloaded_guides(self):
        prompt = pr_review.build_prompt(
            pull(),
            "+line\n",
            "# AGENTS",
            "gemini-4-argon",
            guides=[("docs/architecture.md", "never hold parking_lot across await")],
        )
        self.assertIn(
            "# docs/architecture.md (доверенный контекст из базовой ревизии)\nnever hold parking_lot across await",
            prompt,
        )


class ReadRepoFileTests(unittest.TestCase):
    def test_reads_allowed_file_and_rejects_traversal_secrets_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "docs").mkdir(parents=True)
            (root / "docs" / "note.md").write_text("decision text", encoding="utf-8")
            (root / ".secrets").mkdir()
            (root / ".secrets" / "key.txt").write_text("secret", encoding="utf-8")
            (root / ".env").write_text("TOKEN=1", encoding="utf-8")
            self.assertEqual(pr_review.read_repo_file("docs/note.md", root=tmp), "decision text")
            self.assertIn("outside", pr_review.read_repo_file("../etc/passwd", root=tmp))
            self.assertIn("forbidden", pr_review.read_repo_file(".secrets/key.txt", root=tmp))
            self.assertIn("forbidden", pr_review.read_repo_file(".env", root=tmp))
            link_path = root / "docs" / "escape.md"
            os.symlink(root / "docs" / "note.md", link_path)
            self.assertIn("not accessible", pr_review.read_repo_file("docs/escape.md", root=tmp))


class GatewayToolLoopTests(unittest.TestCase):
    def test_gateway_executes_read_file_tool_and_returns_final_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "docs").mkdir()
            (root / "docs" / "note.md").write_text("guide rule 42", encoding="utf-8")
            seen_payloads = []
            responses = [
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "provider_specific_fields": {"thought_signature": "sig-1"},
                                "tool_calls": [
                                    {
                                        "id": "call_1",
                                        "type": "function",
                                        "function": {
                                            "name": "read_file",
                                            "arguments": json.dumps({"path": "docs/note.md"}),
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                },
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": "",
                            }
                        }
                    ]
                },
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": json.dumps(CLEAN),
                            }
                        }
                    ]
                },
            ]

            def fake_request(url, *, token, method="GET", payload=None, accept="", timeout=60):
                seen_payloads.append(payload)
                return 200, json.dumps(responses.pop(0)), {}

            original = pr_review._request
            pr_review._request = fake_request
            try:
                gateway = pr_review.Gateway(api_key="k", root=tmp)
                answer = gateway.complete("review this")
            finally:
                pr_review._request = original
            self.assertEqual(json.loads(answer), CLEAN)
            self.assertEqual(len(seen_payloads), 3)
            self.assertEqual(seen_payloads[0]["tool_choice"], "auto")
            assistant_msg = seen_payloads[1]["messages"][-2]
            self.assertEqual(assistant_msg["provider_specific_fields"], {"thought_signature": "sig-1"})
            tool_msg = seen_payloads[1]["messages"][-1]
            self.assertEqual(tool_msg["role"], "tool")
            self.assertEqual(tool_msg["tool_call_id"], "call_1")
            self.assertEqual(tool_msg["content"], "guide rule 42")
            self.assertNotIn("tools", seen_payloads[2])


class RunTests(unittest.TestCase):
    def test_clean_review_is_approved_and_submitted(self):
        github = FakeGitHub()
        result = reviewer(github).run()
        self.assertTrue(result["submitted"])
        self.assertEqual(github.submitted[0]["event"], "APPROVE")
        self.assertEqual(github.submitted[0]["commit_id"], "a" * 40)

    def test_blocking_finding_requests_changes(self):
        github = FakeGitHub()
        answer = json.dumps(
            {
                "summary": "s",
                "verdict": "approve",
                "findings": [
                    {
                        "severity": "P1",
                        "file": "crates/tuic/src/lib.rs",
                        "line": 3,
                        "claim": "c",
                        "evidence": "e",
                    }
                ],
            }
        )
        result = reviewer(github, answer=answer).run()
        self.assertEqual(result["event"], "REQUEST_CHANGES")
        self.assertEqual(github.submitted[0]["event"], "REQUEST_CHANGES")

    def test_missing_token_skips_without_any_api_call(self):
        github = FakeGitHub(token="")
        self.assertFalse(reviewer(github).run()["submitted"])
        self.assertEqual(github.submitted, [])

    def test_draft_and_dependabot_and_self_authored_and_already_reviewed_are_skipped(self):
        draft = reviewer(FakeGitHub(pull_value=pull(draft=True)))
        self.assertIn("draft", draft.run()["skipped"])
        dependabot = reviewer(FakeGitHub(pull_value=pull(user={"login": "dependabot[bot]"})))
        self.assertIn("dependabot", dependabot.run()["skipped"])
        own = reviewer(FakeGitHub(login="int8-ptr"))
        self.assertIn("author", own.run()["skipped"])
        seen = reviewer(FakeGitHub(reviews=[{"user": {"login": "Murmur-Reviewer"}, "commit_id": "a" * 40}]))
        self.assertIn("already reviewed", seen.run()["skipped"])

    def test_review_at_another_head_sha_does_not_skip(self):
        github = FakeGitHub(reviews=[{"user": {"login": "murmur-reviewer"}, "commit_id": "b" * 40}])
        self.assertTrue(reviewer(github).run()["submitted"])

    def test_empty_diff_is_skipped(self):
        self.assertIn("empty diff", reviewer(FakeGitHub(diff=" \n")).run()["skipped"])

    def test_invalid_model_answer_is_retried_once_then_fails(self):
        github = FakeGitHub()
        instance = reviewer(github, answer=["not json", "still not json"])
        with self.assertRaises(pr_review.ReviewError):
            instance.run()
        self.assertEqual(github.submitted, [])

    def test_retry_can_recover(self):
        github = FakeGitHub()
        answer = json.dumps({"summary": "s", "verdict": "approve", "findings": []})
        instance = reviewer(github, answer=["nope", answer])
        self.assertTrue(instance.run()["submitted"])

    def test_dry_run_does_not_submit(self):
        github = FakeGitHub()
        with redirect_stdout(io.StringIO()) as printed:
            result = reviewer(github, dry_run=True).run()
        self.assertTrue(result["dry_run"])
        self.assertEqual(github.submitted, [])
        self.assertIn('"event": "APPROVE"', printed.getvalue())


class MainTests(unittest.TestCase):
    def test_missing_repository_or_number_fails(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(pr_review.main({}), 1)
            self.assertEqual(pr_review.main({"GITHUB_REPOSITORY": "labi-le/murmur"}), 1)

    def test_missing_token_exits_zero_without_network(self):
        with redirect_stderr(io.StringIO()) as log:
            code = pr_review.main({"GITHUB_REPOSITORY": "labi-le/murmur", "PR_NUMBER": "31"})
        self.assertEqual(code, 0)
        self.assertIn("GH_TOKEN is empty", log.getvalue())

    def test_missing_api_key_fails(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(
                pr_review.main({"GITHUB_REPOSITORY": "labi-le/murmur", "PR_NUMBER": "31", "GH_TOKEN": "t"}),
                1,
            )


if __name__ == "__main__":
    unittest.main()
