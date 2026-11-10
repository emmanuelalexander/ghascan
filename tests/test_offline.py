#!/usr/bin/env python3
"""Tests offline de ghascan (sin red)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from ghascan_lib import patterns as P          # noqa: E402
from ghascan_lib.analyze import analyze_text   # noqa: E402
from ghascan_lib import report as R            # noqa: E402


PR_TITLE = """\
name: x
on:
  pull_request_target:
    types: [opened]
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""

SAFE = """\
name: x
on:
  issues:
    types: [opened]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          T: ${{ github.event.issue.title }}
        run: echo "$T"
"""

DISABLED = """\
name: x
on:
  issues:
    types: [opened]
jobs:
  a:
    if: false
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""

GATED = """\
name: x
on:
  issues:
    types: [opened]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - if: github.event.label.name == 'security'
        run: echo "${{ github.event.label.name }}"
"""

COMMENT = """\
name: x
on:
  issue_comment:
    types: [created]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.comment.body }}
"""

TOJSON = """\
name: x
on:
  issues:
    types: [opened]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(github.event.issue) }}'
"""

HEREDOC = """\
name: x
on:
  issues:
    types: [opened]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<'EOF'
          ${{ github.event.issue.title }}
          EOF
"""

ENV_INJECT = """\
name: x
on:
  issues:
    types: [opened]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "X=${{ github.event.issue.title }}" >> "$GITHUB_ENV"
"""

DISPATCH = """\
name: x
on:
  workflow_dispatch:
    inputs:
      tag:
        description: tag
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: git tag ${{ github.event.inputs.tag }}
"""

PUSH_ONLY = """\
name: x
on:
  push:
    branches: [main]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""


class TestAnalyzer(unittest.TestCase):
    def test_pr_title_critical(self):
        f = analyze_text(PR_TITLE, 'x.yml', 't')
        self.assertIn(f.verdict, ('CRITICAL', 'HIGH'))
        self.assertEqual(f.active[0].control, 'FULL_CONTROL')
        self.assertIn('GHA_POC', f.poc)

    def test_safe_env_fp(self):
        f = analyze_text(SAFE, 'x.yml', 't')
        self.assertEqual(f.verdict, 'FALSE_POSITIVE')

    def test_disabled_job_fp(self):
        f = analyze_text(DISABLED, 'x.yml', 't')
        self.assertEqual(f.verdict, 'FALSE_POSITIVE')
        self.assertTrue(any(v.rule == 'R2_JOB_DISABLED' for v in f.eliminated))

    def test_gate_fp(self):
        f = analyze_text(GATED, 'x.yml', 't')
        self.assertEqual(f.verdict, 'FALSE_POSITIVE')
        self.assertTrue(any(v.rule == 'R7B_EXACT_GATE' for v in f.eliminated))

    def test_comment_body(self):
        f = analyze_text(COMMENT, 'x.yml', 't')
        self.assertIn(f.verdict, ('CRITICAL', 'HIGH'))
        self.assertEqual(f.trigger_openness, 'OPEN')

    def test_tojson_full_control(self):
        f = analyze_text(TOJSON, 'x.yml', 't')
        self.assertIn(f.verdict, ('CRITICAL', 'HIGH'))

    def test_quoted_heredoc_eliminated(self):
        f = analyze_text(HEREDOC, 'x.yml', 't')
        self.assertEqual(f.verdict, 'FALSE_POSITIVE')
        self.assertTrue(any(v.rule == 'R8_HEREDOC' for v in f.eliminated))

    def test_github_env_injection(self):
        f = analyze_text(ENV_INJECT, 'x.yml', 't')
        self.assertTrue(f.env_injections)
        self.assertIn(f.verdict, ('CRITICAL', 'HIGH'))

    def test_dispatch_input(self):
        f = analyze_text(DISPATCH, 'x.yml', 't')
        self.assertEqual(f.active[0].control, 'DISPATCH_INPUT')
        self.assertIn(f.verdict, ('MEDIUM', 'LOW'))

    def test_wrong_trigger_fp(self):
        f = analyze_text(PUSH_ONLY, 'x.yml', 't')
        self.assertEqual(f.verdict, 'FALSE_POSITIVE')
        self.assertTrue(any(v.rule == 'R4_TRIGGER' for v in f.eliminated))


class TestPatterns(unittest.TestCase):
    def test_43_queries(self):
        self.assertEqual(len(P.QUERIES), 43)
        for i in range(1, 44):
            self.assertIn(i, P.QUERIES)
            name, q = P.QUERIES[i]
            self.assertTrue(name)
            self.assertIn('path:.github/workflows', q)


class TestReports(unittest.TestCase):
    def test_json_and_html(self):
        f = analyze_text(PR_TITLE, 'x.yml', 'acme/repo')
        with tempfile.TemporaryDirectory() as td:
            jp = os.path.join(td, 'r.json')
            hp = os.path.join(td, 'r.html')
            R.write_json([f], jp)
            R.write_html([f], hp)
            with open(jp, encoding='utf-8') as fh:
                data = json.load(fh)
            self.assertEqual(data['total_findings'], 1)
            self.assertEqual(data['findings'][0]['verdict'], f.verdict)
            with open(hp, encoding='utf-8') as fh:
                html_text = fh.read()
            self.assertIn('ghascan', html_text)
            self.assertIn('PoC', html_text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
