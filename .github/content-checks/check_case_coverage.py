#!/usr/bin/env python3
"""Checks that every Log Type's regression cases cover what its parser can emit.

For each log_types/<key>/:
  - every OCSF class the parser can emit (the class_uid literals in parser.vrl) is asserted by at least one case;
  - every case asserts class_uid, type_uid and metadata.profiles, so the class, the activity and the declared
    profiles of each tested branch are pinned down;
  - a case's type_uid matches its class_uid and activity_id (type_uid = class_uid * 100 + activity_id).

The classes are read statically: a parser writes each class it emits as a literal (`class_uid = 4001`,
`"class_uid": 3002`, `.class_uid = 4003`, `class_uid = if x { 4001 } else { 4003 }`), or names the classes it
accepts from its input in `includes([2004, 3002], class_uid)`. Comparisons (`class_uid == 2001`) emit nothing.

Usage: check_case_coverage.py [--root DIR]
Exit status: 0 when clean, 1 on findings.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

REQUIRED_ASSERTIONS = ("class_uid", "type_uid", "metadata.profiles")

# class_uid = 4001 | "class_uid": 4001 | .class_uid = 4001, but not class_uid == 4001.
ASSIGNED_RE = re.compile(r"""\bclass_uid"?\s*(?::|=(?!=))\s*(\d{4,6})\b""")
# class_uid = if cond { 4001 } else if other { 4002 } else { 4003 }, on one line or several.
CONDITIONAL_RE = re.compile(r"""\bclass_uid"?\s*(?::|=(?!=))\s*if\b""")
BRANCH_VALUE_RE = re.compile(r"\{\s*(\d{4,6})\s*\}")
ELSE_RE = re.compile(r"\s*else\b")
# includes([2004, 3002, 4001], class_uid): the classes a parser accepts from its input.
ACCEPTED_RE = re.compile(r"\bincludes\(\s*\[([\d\s,]+)\]\s*,\s*class_uid\s*\)")


def gha_data(text: str) -> str:
    """Escapes a workflow command's message, so a file name or value from a pull request cannot end the command and
    start another one."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def gha_property(text: str) -> str:
    """Escapes a workflow command's property value, such as the file name."""
    return gha_data(text).replace(":", "%3A").replace(",", "%2C")


@dataclass(frozen=True)
class Finding:
    path: str
    message: str

    def render(self, gha: bool) -> str:
        if gha:
            return f"::error file={gha_property(self.path)},title=Case coverage::{gha_data(self.message)}"
        return f"{self.path}: {self.message}"


def strip_comments(vrl: str) -> str:
    """Drops full-line comments, so a class named in prose is not taken for one the parser emits."""
    return "\n".join(line for line in vrl.splitlines() if not line.lstrip().startswith("#"))


def conditional_expression(code: str, start: int) -> str:
    """The text of an if/else chain that starts at `start`: up to the closing brace that no `else` follows."""
    depth, i = 0, start
    while i < len(code):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0 and not ELSE_RE.match(code, i + 1):
                return code[start:i + 1]
        i += 1
    return code[start:]


def emitted_classes(vrl: str) -> set[int]:
    """The class_uid values a parser can emit, read from its source."""
    code = strip_comments(vrl)
    classes = {int(m.group(1)) for m in ASSIGNED_RE.finditer(code)}
    for m in CONDITIONAL_RE.finditer(code):
        classes.update(int(v) for v in BRANCH_VALUE_RE.findall(conditional_expression(code, m.end())))
    for m in ACCEPTED_RE.finditer(code):
        classes.update(int(v) for v in m.group(1).replace(",", " ").split())
    return classes


def is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def check_case(path: str, text: str) -> tuple[list[Finding], int | None]:
    """Checks one case file. Returns its findings and the class it asserts, if it asserts one."""
    try:
        case = yaml.safe_load(text)
    except yaml.YAMLError as err:
        return [Finding(path, f"not valid YAML: {str(err).splitlines()[0]}")], None
    expected = case.get("expected") if isinstance(case, dict) else None
    if not isinstance(expected, dict):
        return [Finding(path, "has no expected assertions; assert at least " + ", ".join(REQUIRED_ASSERTIONS))], None
    findings = [Finding(path, f"does not assert {name}") for name in REQUIRED_ASSERTIONS if name not in expected]
    class_uid = expected.get("class_uid")
    if "class_uid" in expected and not is_int(class_uid):
        findings.append(Finding(path, "class_uid must be an integer"))
        class_uid = None
    if "metadata.profiles" in expected and not isinstance(expected["metadata.profiles"], list):
        findings.append(Finding(path, "metadata.profiles must be a list; write [] when the branch declares none"))
    type_uid, activity_id = expected.get("type_uid"), expected.get("activity_id")
    if is_int(class_uid) and is_int(type_uid):
        if is_int(activity_id) and type_uid != class_uid * 100 + activity_id:
            findings.append(Finding(path, f"type_uid {type_uid} is not class_uid {class_uid} * 100 + activity_id {activity_id}"))
        elif type_uid // 100 != class_uid:
            findings.append(Finding(path, f"type_uid {type_uid} does not belong to class_uid {class_uid}"))
    return findings, class_uid if is_int(class_uid) else None


def check_log_type(root: Path, log_type: Path) -> list[Finding]:
    rel = log_type.relative_to(root).as_posix()
    parser = log_type / "parser.vrl"
    findings: list[Finding] = []
    emitted = emitted_classes(parser.read_text(encoding="utf-8"))
    if not emitted:
        findings.append(Finding(f"{rel}/parser.vrl", "names no class_uid literal; write each class the parser emits as a "
                                                    "literal so its cases can be checked"))
    asserted: set[int] = set()
    cases = sorted((log_type / "tests").glob("*.yaml")) if (log_type / "tests").is_dir() else []
    if not cases:
        findings.append(Finding(rel, "has no regression cases"))
    for case in cases:
        case_findings, class_uid = check_case(case.relative_to(root).as_posix(), case.read_text(encoding="utf-8"))
        findings.extend(case_findings)
        if class_uid is not None:
            asserted.add(class_uid)
    for class_uid in sorted(emitted - asserted):
        findings.append(Finding(f"{rel}/parser.vrl", f"can emit class_uid {class_uid}, but no case asserts it; add a "
                                                    "regression case for that branch"))
    return findings


def check(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for parser in sorted((root / "log_types").glob("*/parser.vrl")):
        findings.extend(check_log_type(root, parser.parent))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path.cwd())
    args = ap.parse_args(argv)
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    findings = check(args.root.resolve())
    for finding in findings:
        print(finding.render(gha))
    if findings:
        print(f"{len(findings)} finding(s). Every class a parser can emit needs a regression case, and every case "
              "asserts class_uid, type_uid and metadata.profiles; see CONTRIBUTING.md.", file=sys.stderr)
        return 1
    print("case coverage: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
