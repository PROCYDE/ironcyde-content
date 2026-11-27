#!/usr/bin/env python3
"""Applies this repository's quality bar to a content test report.

Reads the JSON report of IRONCYDE's `content test --format json --strict` and fails when
  - a Log Type or a case has a problem (did not normalize, a failed assertion, invalid OCSF);
  - a case has an OCSF warning other than a missing recommended attribute: a deprecated class or attribute, an
    enum caption that does not match its ID, and so on. Recommended attributes cannot all be filled (many do not
    exist in a source), so missing ones are tolerated; every other warning has a fix in the parser;
  - a case's event does not declare metadata.profiles as a list.

The report is data: it is only parsed as JSON, and nothing in it is executed. The script needs the standard
library only, so the content-test workflow can run the copy from main without installing anything.

Usage: check_content_report.py REPORT.json
Exit status: 0 when clean, 1 on findings, 2 when the report cannot be read.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass

# Warning codes a case may carry. Everything else fails.
TOLERATED_WARNINGS = frozenset({"validation_attribute_recommended_missing"})

CODE_RE = re.compile(r"\b(validation_[a-z0-9_]+)\b")
MAX_MESSAGE = 500


def gha_data(text: str) -> str:
    """Escapes a workflow command's message, so a value from a pull request cannot end the command and start
    another one."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def gha_property(text: str) -> str:
    """Escapes a workflow command's property value, such as the file name."""
    return gha_data(text).replace(":", "%3A").replace(",", "%2C")


@dataclass(frozen=True)
class Finding:
    path: str
    message: str

    def render(self, gha: bool) -> str:
        message = self.message if len(self.message) <= MAX_MESSAGE else self.message[:MAX_MESSAGE] + "..."
        if gha:
            where = f" file={gha_property(self.path)}," if self.path else " "
            return f"::error{where}title=Content quality::{gha_data(message)}"
        return f"{self.path or 'report'}: {message}"


def text_of(item: object) -> str:
    """A problem or warning as text: the report writes them as strings, or as objects with a message."""
    if isinstance(item, dict):
        return str(item.get("message", item))
    return str(item)


def warning_code(warning: str) -> str | None:
    match = CODE_RE.search(warning)
    return match.group(1) if match else None


def check_case(log_type: str, case: dict) -> list[Finding]:
    name = str(case.get("name", "?"))
    path = str(case.get("file") or f"log_types/{log_type}/tests/{name}.yaml")
    findings = [Finding(path, f"{name}: {text_of(p)}") for p in case.get("problems") or []]
    for warning in case.get("warnings") or []:
        text = text_of(warning)
        if warning_code(text) not in TOLERATED_WARNINGS:
            findings.append(Finding(path, f"{name}: {text}"))
    output = case.get("output")
    if isinstance(output, dict):
        metadata = output.get("metadata")
        profiles = metadata.get("profiles") if isinstance(metadata, dict) else None
        if not isinstance(profiles, list):
            findings.append(Finding(path, f"{name}: the event does not declare metadata.profiles; set it in every "
                                          "branch, to [] when the branch uses no profile"))
    return findings


def check_report(report: object) -> list[Finding]:
    if not isinstance(report, dict) or not isinstance(report.get("log_types"), list):
        raise ValueError("not a content test report: no log_types list")
    findings: list[Finding] = []
    for log_type in report["log_types"]:
        if not isinstance(log_type, dict):
            raise ValueError("not a content test report: a log type is not an object")
        key = str(log_type.get("key", "?"))
        for problem in log_type.get("problems") or []:
            path = problem.get("file", "") if isinstance(problem, dict) else ""
            findings.append(Finding(str(path) or f"log_types/{key}", f"{key}: {text_of(problem)}"))
        cases = log_type.get("cases") or []
        if not cases and not log_type.get("problems"):
            findings.append(Finding(f"log_types/{key}", f"{key}: the report has no cases for this Log Type"))
        for case in cases:
            if isinstance(case, dict):
                findings.extend(check_case(key, case))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    try:
        with open(args[0], encoding="utf-8") as fh:
            findings = check_report(json.load(fh))
    except (OSError, ValueError) as err:
        message = f"cannot read the content test report: {err}"
        print(f"::error title=Content quality::{gha_data(message)}" if gha else message, file=sys.stderr)
        return 2
    for finding in findings:
        print(finding.render(gha))
    if findings:
        print(f"{len(findings)} finding(s). Fix the parser or the case; only missing recommended attributes are "
              "tolerated. See CONTRIBUTING.md.", file=sys.stderr)
        return 1
    print("content quality: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
