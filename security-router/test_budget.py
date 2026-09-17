#!/usr/bin/env python3
"""Exercise the exact workflow cap validator and fail-closed completion step."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/pr-security-gate.yml").read_text())
STEPS = WORKFLOW["jobs"]["scan"]["steps"]
VALIDATOR = next(s for s in STEPS if s.get("id") == "budget")["run"]
COMPLETION = next(s for s in STEPS if s.get("name") == "Require bounded scan completion")["run"]


class SpendingCaps(unittest.TestCase):
    def run_validator(self, scan="", report=""):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "outputs"
            result = subprocess.run(["bash", "-e", "-c", VALIDATOR], env={
                **os.environ, "SCAN_BUDGET_USD": scan, "REPORT_BUDGET_USD": report,
                "GITHUB_OUTPUT": str(output),
            }, capture_output=True, text=True)
            return result, output.read_text() if output.exists() else ""

    def test_unconfigured_repositories_keep_existing_arguments(self):
        result, output = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "scan_args=\nreport_args=\n")

    def test_valid_caps_reach_both_invocations(self):
        result, output = self.run_validator("18.00", "0.50")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "scan_args=--max-budget-usd 18.00\nreport_args=--max-budget-usd 0.50\n")
        scan = next(s for s in STEPS if s.get("id") == "scan")
        self.assertIn("${{ steps.budget.outputs.scan_args }}", scan["with"]["claude_args"])
        self.assertEqual(WORKFLOW["jobs"]["scan"]["outputs"]["report_budget_args"], "${{ steps.budget.outputs.report_args }}")
        post = next(s for s in WORKFLOW["jobs"]["report"]["steps"] if s.get("id") == "postcomment")
        self.assertIn("${{ needs.scan.outputs.report_budget_args }}", post["with"]["claude_args"])

    def test_incomplete_or_unsafe_caps_fail_before_emitting_arguments(self):
        for scan, report in [("18", ""), ("", "0.5"), *[(bad, "0.5") for bad in
                ("0", "-1", "1000", "1e2", "nan", " 18", "1.001", "18\nother=argument", "18; echo injected", "$(touch injected)")]]:
            with self.subTest(scan=scan, report=report):
                result, output = self.run_validator(scan, report)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")
        self.assertNotEqual(self.run_validator("18", "0")[0].returncode, 0)

    def test_bounded_failures_do_not_pass_on_a_partial_report_or_timeout_warning(self):
        for outcome in ("failure", "cancelled", "skipped", ""):
            with self.subTest(outcome=outcome):
                result = subprocess.run(["bash", "-e", "-c", COMPLETION], env={**os.environ, "SCAN_OUTCOME": outcome}, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
        result = subprocess.run(["bash", "-e", "-c", COMPLETION], env={**os.environ, "SCAN_OUTCOME": "success"}, capture_output=True)
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
