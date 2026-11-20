#!/usr/bin/env python3
"""Checks that content in this public repository uses only documentation-reserved identifiers.

Every IP address, email address and domain name in log_types/ must come from a range or name that is
reserved for documentation (RFC 5737, RFC 3849, RFC 2606, RFC 6761) or be listed as an exception with a
reason in test_data_policy.yaml. Optionally, a private denylist (customer names, internal hostnames) is
read from the CONTENT_DENYLIST environment variable; its terms are never printed.

Usage: check_test_data.py [--root DIR] [--policy FILE]
Exit status: 0 when clean, 1 on findings, 2 on a broken policy.
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent

# An IPv4 address not glued to a longer dotted number or word (version strings, OIDs, hostnames like
# 192.0.2.4.example.net are handled by the domain rule).
IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w]|\.\w)")
# IPv6 candidates: hex groups with at least two colons, optional zone. ipaddress decides what is real.
IPV6_RE = re.compile(r"(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3})(?:%[\w.-]+)?(?![\w:])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63})\b")
DOMAIN_RE = re.compile(r"(?<![\w.@-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63}))\b(?![.-]\w)")


@dataclass
class Finding:
    path: str
    line: int
    kind: str
    value: str
    secret: bool = False

    def render(self) -> str:
        shown = "a CONTENT_DENYLIST entry" if self.secret else repr(self.value)
        return f"{self.path}:{self.line}: {self.kind}: {shown}"

    def annotation(self) -> str:
        shown = "a CONTENT_DENYLIST entry" if self.secret else self.value
        return f"::error file={self.path},line={self.line},title=Test data policy::{self.kind}: {shown}"


@dataclass
class Exception_:
    value: str
    paths: list[str]
    reason: str
    used: bool = False

    def covers(self, path: str, value: str) -> bool:
        return self.value.lower() == value.lower() and any(fnmatch.fnmatch(path, p) for p in self.paths)


@dataclass
class Policy:
    scan: list[str]
    networks: list[ipaddress._BaseNetwork]
    domains: list[str]
    tlds: set[str]
    non_domain_suffixes: set[str]
    non_domains: set[str]
    denylist: list[re.Pattern]
    exceptions: list[Exception_] = field(default_factory=list)


class PolicyError(Exception):
    pass


def load_policy(path: Path) -> Policy:
    data = yaml.safe_load(path.read_text())
    try:
        networks = []
        for item in data["allowed_networks"]:
            if not item.get("reason"):
                raise PolicyError(f"allowed network {item.get('network')!r} has no reason")
            networks.append(ipaddress.ip_network(item["network"]))
        domains = []
        for item in data["allowed_domains"]:
            if not item.get("reason"):
                raise PolicyError(f"allowed domain {item.get('domain')!r} has no reason")
            domains.append(item["domain"].lower().lstrip("."))
        exceptions = []
        for item in data.get("exceptions") or []:
            if not str(item.get("reason", "")).strip():
                raise PolicyError(f"exception {item.get('value')!r} has no reason")
            if not item.get("paths"):
                raise PolicyError(f"exception {item.get('value')!r} names no paths")
            exceptions.append(Exception_(str(item["value"]), list(item["paths"]), item["reason"]))
        non_domain_suffixes = set()
        for item in data.get("non_domain_suffixes") or []:
            if not str(item.get("reason", "")).strip():
                raise PolicyError(f"non-domain suffix {item.get('suffix')!r} has no reason")
            non_domain_suffixes.add(str(item["suffix"]).lower().lstrip("."))
        non_domains = set()
        for item in data.get("non_domains") or []:
            if not str(item.get("reason", "")).strip():
                raise PolicyError(f"non-domain {item.get('value')!r} has no reason")
            non_domains.add(str(item["value"]).lower().rstrip("."))
        denylist = [re.compile(p, re.IGNORECASE) for p in data.get("denylist_patterns") or []]
        return Policy(
            scan=list(data["scan"]),
            networks=networks,
            domains=domains,
            tlds={t.lower() for t in data["checked_tlds"]},
            non_domain_suffixes=non_domain_suffixes,
            non_domains=non_domains,
            denylist=denylist,
            exceptions=exceptions,
        )
    except (KeyError, TypeError, ValueError) as err:
        raise PolicyError(f"{path}: {err}") from err


def ip_allowed(policy: Policy, text: str) -> bool | None:
    """True/False for an address, None if the text is not an IP address at all."""
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    return any(addr.version == n.version and addr in n for n in policy.networks)


def domain_allowed(policy: Policy, domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == a or d.endswith("." + a) for a in policy.domains)


def is_non_domain(policy: Policy, domain: str) -> bool:
    """True for file names and field paths that the domain rule would otherwise mistake for hosts."""
    d = domain.lower().rstrip(".")
    return d in policy.non_domains or d.rsplit(".", 1)[-1] in policy.non_domain_suffixes


def line_of(text: str, needle: str, start: int = 0) -> int:
    idx = text.find(needle, start)
    if idx < 0:
        idx = text.lower().find(needle.lower())
    return text.count("\n", 0, max(idx, 0)) + 1


def strings_in(node) -> list[str]:
    """All string values (not keys) of a decoded YAML or JSON document."""
    out: list[str] = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            out.extend(strings_in(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(strings_in(v))
    return out


def expand_json(value: str, depth: int = 0) -> list[str]:
    """Split a JSON object/array string into its string values, leaving other strings unchanged."""
    if depth > 5 or not value.lstrip().startswith(("{", "[")):
        return [value]
    try:
        parsed = json.loads(value)
    except ValueError:
        return [value]
    out: list[str] = []
    for item in strings_in(parsed):
        out.extend(expand_json(item, depth + 1))
    return out


def comment_lines(text: str) -> list[str]:
    return [ln.split("#", 1)[1] if "#" in ln else "" for ln in text.splitlines() if ln.lstrip().startswith("#")]


def scan_file(policy: Policy, rel: str, text: str, private_terms: list[str]) -> list[Finding]:
    found: list[Finding] = []

    # Addresses and emails are precise enough to check in the whole file, code and comments included.
    for m in IPV4_RE.finditer(text):
        ok = ip_allowed(policy, m.group(1))
        if ok is False:
            found.append(Finding(rel, line_of(text, m.group(1), m.start()), "IPv4 address outside documentation ranges", m.group(1)))
    for m in IPV6_RE.finditer(text):
        cand = m.group(1)
        if cand.count(":") < 2:
            continue
        ok = ip_allowed(policy, cand)
        if ok is False:
            found.append(Finding(rel, line_of(text, cand, m.start()), "IPv6 address outside documentation ranges", cand))
    email_domains = set()
    for m in EMAIL_RE.finditer(text):
        email_domains.add(m.group(1).lower())
        if not domain_allowed(policy, m.group(1)):
            found.append(Finding(rel, line_of(text, m.group(0), m.start()), "email address outside reserved domains", m.group(0)))

    # Domain names are only looked for in data and comments: VRL code and YAML keys are full of dotted paths.
    # A dotted name counts when its last label is a two-letter (country code) TLD or listed in checked_tlds.
    if rel.endswith((".yaml", ".yml")):
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as err:
            found.append(Finding(rel, 1, "file is not valid YAML", str(err).splitlines()[0]))
            texts = []
        else:
            texts = []
            for value in strings_in(data):
                texts.extend(expand_json(value))
            texts += comment_lines(text)
    else:
        texts = comment_lines(text)
    seen = set()
    for chunk in texts:
        for m in DOMAIN_RE.finditer(chunk):
            domain, tld = m.group(1), m.group(2).lower()
            if (tld not in policy.tlds and len(tld) != 2) or domain.lower() in seen:
                continue
            seen.add(domain.lower())
            if ip_allowed(policy, domain) is not None:
                continue
            if domain.lower() in email_domains or domain_allowed(policy, domain):
                continue
            if is_non_domain(policy, domain):
                continue
            found.append(Finding(rel, line_of(text, domain), "domain outside reserved names", domain))

    for pattern in policy.denylist:
        for m in pattern.finditer(text):
            found.append(Finding(rel, line_of(text, m.group(0), m.start()), f"matches denylist pattern {pattern.pattern!r}", m.group(0)))
    lowered = text.lower()
    for term in private_terms:
        idx = lowered.find(term)
        if idx >= 0:
            found.append(Finding(rel, text.count("\n", 0, idx) + 1, "private denylist", term, secret=True))
    return found


def tracked_files(root: Path, patterns: list[str]) -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
        files = [f for f in out.decode().split("\0") if f]
    except (OSError, subprocess.CalledProcessError):
        files = [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
    return sorted(f for f in files if any(fnmatch.fnmatch(f, p) for p in patterns))


def run(root: Path, policy: Policy, private_terms: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel in tracked_files(root, policy.scan):
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        for f in scan_file(policy, rel, text, private_terms):
            excused = False
            if not f.secret:
                for ex in policy.exceptions:
                    if ex.covers(rel, f.value):
                        ex.used = excused = True
            if not excused:
                findings.append(f)
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path.cwd())
    ap.add_argument("--policy", type=Path, default=HERE / "test_data_policy.yaml")
    args = ap.parse_args(argv)
    gha = os.environ.get("GITHUB_ACTIONS") == "true"

    try:
        policy = load_policy(args.policy)
    except PolicyError as err:
        print(f"policy error: {err}", file=sys.stderr)
        return 2

    raw_terms = os.environ.get("CONTENT_DENYLIST", "")
    private_terms = [t.strip().lower() for t in raw_terms.splitlines() if t.strip() and not t.startswith("#")]
    if gha:
        for t in private_terms:
            print(f"::add-mask::{t}")
    if not private_terms:
        print("note: CONTENT_DENYLIST is not set; the private denylist check is skipped "
              "(expected for pull requests from forks).")

    findings = run(args.root.resolve(), policy, private_terms)
    unused = [ex for ex in policy.exceptions if not ex.used]

    for f in findings:
        print(f.annotation() if gha else f.render())
    for ex in unused:
        msg = f"exception {ex.value!r} for {ex.paths} is no longer needed; remove it from the policy"
        print(f"::error title=Test data policy::{msg}" if gha else f"policy: {msg}")

    if findings or unused:
        print(f"\n{len(findings)} finding(s), {len(unused)} stale exception(s). Use documentation values "
              "(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, example.com/.net/.org, .test, "
              ".example, .invalid) or add an exception with a reason; see CONTRIBUTING.md.", file=sys.stderr)
        return 1
    print("test data policy: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
