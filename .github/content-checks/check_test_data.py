#!/usr/bin/env python3
"""Checks that content in this public repository uses only documentation-reserved identifiers.

Every IP address, email address and domain name in log_types/ must come from a range or name that is
reserved for documentation (RFC 5737, RFC 3849, RFC 2606, RFC 6761) or be listed as an exception with a
reason in test_data_policy.yaml. Optionally, a private denylist (customer names, internal hostnames) is
read from the CONTENT_DENYLIST environment variable; its terms are never printed.

Usage: check_test_data.py [--root DIR] [--policy FILE] [--private-only]
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
# An address may end in a colon that is no further group, as in a syslog line "from 2a00::1: Accepted".
_IPV6 = r"([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3})(?:%[\w.-]+)?(?!\w|:[0-9A-Fa-f:])"
IPV6_RE = re.compile(r"(?<![\w:.])" + _IPV6)
# The same after a key and a colon (addr:2a00::1), when the key is no hex group itself: a fingerprint such as
# SHA256:43:51:... never ends in time for the address to stop before the next colon.
IPV6_KEYED_RE = re.compile(r"(?<![\w:.-])[\w.-]*[G-Zg-z_-][\w.-]*:" + _IPV6)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63})\b")
# The host of a URL is checked whatever its top-level domain, because a URL leaves no doubt that it names a host.
URL_HOST_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://(?:[^/\s@\"']*@)?([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z][A-Za-z0-9-]*)")
# String literals in VRL and YAML: double-quoted with escapes, single-quoted (YAML), and VRL raw strings s'...'.
STRING_RE = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|s?'(?:[^'\\\n]|\\.)*'")
DOMAIN_RE = re.compile(r"(?<![\w.@-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63}))\b(?![.-]\w)")


def gha_data(text: str) -> str:
    """Escapes a workflow command's message, so a file name or value from a pull request cannot end the command and
    start another one."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def gha_property(text: str) -> str:
    """Escapes a workflow command's property value, such as the file name."""
    return gha_data(text).replace(":", "%3A").replace(",", "%2C")


@dataclass
class Finding:
    path: str
    line: int
    kind: str
    value: str
    secret: bool = False
    # The path itself contains a private term, so it is never printed either.
    secret_path: bool = False

    def render(self) -> str:
        shown = "a CONTENT_DENYLIST entry" if self.secret else repr(self.value)
        where = "a file whose path contains a CONTENT_DENYLIST entry" if self.secret_path else f"{self.path}:{self.line}"
        return f"{where}: {self.kind}: {shown}"

    def annotation(self) -> str:
        shown = "a CONTENT_DENYLIST entry" if self.secret else self.value
        if self.secret_path:
            return ("::error title=Test data policy::"
                    + gha_data(f"a file whose path contains a CONTENT_DENYLIST entry: {self.kind}: {shown}"))
        return (f"::error file={gha_property(self.path)},line={self.line},title=Test data policy::"
                + gha_data(f"{self.kind}: {shown}"))


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
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
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


class Pairs(list):
    """A JSON object as all of its key/value pairs, so a duplicate key cannot hide an earlier value."""


def keys_in(node) -> list[str]:
    """All mapping keys of a decoded YAML or JSON document, as strings."""
    out: list[str] = []
    if isinstance(node, Pairs):
        for k, v in node:
            out.append(str(k))
            out.extend(keys_in(v))
    elif isinstance(node, dict):
        for k, v in node.items():
            out.append(str(k))
            out.extend(keys_in(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(keys_in(v))
    return out


def strings_in(node) -> list[str]:
    """All string values (not keys) of a decoded YAML or JSON document."""
    out: list[str] = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, Pairs):
        for _, v in node:
            out.extend(strings_in(v))
    elif isinstance(node, dict):
        for v in node.values():
            out.extend(strings_in(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(strings_in(v))
    return out


def expand_json(value: str, depth: int = 0, keys: list[str] | None = None) -> list[str]:
    """Split a JSON object/array string into its string values, leaving other strings unchanged. The keys of every
    JSON level, nested JSON strings included, are added to keys when it is given."""
    # No depth limit: a document too deep to decode raises RecursionError, which the caller reports as a finding.
    if not value.lstrip().startswith(("{", "[")):
        return [value]
    try:
        parsed = json.loads(value, object_pairs_hook=Pairs)
    except ValueError:
        return [value]
    if keys is not None:
        keys.extend(keys_in(parsed))
    out: list[str] = []
    for item in strings_in(parsed):
        out.extend(expand_json(item, depth + 1, keys))
    return out


def comment_start(line: str, vrl: bool) -> int | None:
    """Where the comment of a line begins, after its #, or None. In VRL a # inside a string literal starts no comment.
    In YAML any # at the start or after whitespace counts, quotes or not: a quoted value is checked as data anyway,
    and this way neither quotes inside a comment nor a stray apostrophe before it can hide the comment's text."""
    if not vrl:
        m = re.search(r"(?:^|(?<=\s))#", line)
        return m.end() if m else None
    pos = 0
    while True:
        hash_ = line.find("#", pos)
        lit = STRING_RE.search(line, pos)
        if hash_ < 0:
            return None
        if lit is None or hash_ < lit.start():
            return hash_ + 1
        pos = lit.end()


def comments_and_strings(text: str, vrl: bool) -> list[str]:
    """The comments, inline ones included, and for VRL the string literals of a file: where hostnames can appear
    without being mistaken for the dotted paths of code and YAML keys. A comment is taken as written, quotes and all."""
    out: list[str] = []
    for line in text.splitlines():
        start = comment_start(line, vrl)
        code = line if start is None else line[:start - 1]
        if start is not None:
            out.append(line[start:])
        if vrl:
            out.extend(lit[2:-1] if lit.startswith("s'") else lit[1:-1] for lit in STRING_RE.findall(code))
    return out


class UniqueKeyLoader(yaml.SafeLoader):
    """A safe loader that refuses duplicate mapping keys, which would hide all but the last value."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


VRL_ESCAPE_RE = re.compile(r"\\(u\{[0-9A-Fa-f]{1,6}\}|x[0-9A-Fa-f]{2}|.)", re.DOTALL)
VRL_SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'", "{": "{", "}": "}"}


def vrl_unescape(literal: str) -> str:
    """The value of a VRL string literal's body, so an escape such as \\u{61} cannot hide a term."""
    def one(m: re.Match) -> str:
        esc = m.group(1)
        if esc.startswith("u{"):
            try:
                return chr(int(esc[2:-1], 16))
            except (ValueError, OverflowError):
                return m.group(0)
        if esc.startswith("x") and len(esc) == 3:
            return chr(int(esc[1:], 16))
        return VRL_SIMPLE_ESCAPES.get(esc, m.group(0))
    return VRL_ESCAPE_RE.sub(one, literal)


def decoded_strings(rel: str, text: str) -> tuple[list[str], list[str], str | None]:
    """The string values and the keys of a YAML file after decoding, JSON samples expanded, and the YAML error if it
    has one. Escapes such as \\u0038 only show their meaning here, so the checks also look at these. Keys are only
    checked against the denylists: as hostnames they would be mistaken for field paths."""
    if rel.endswith(".vrl"):
        # Raw strings s'...' have no escapes; only the others need decoding.
        return [vrl_unescape(lit[1:-1]) for lit in STRING_RE.findall(text) if lit.startswith('"')], [], None
    if not rel.endswith((".yaml", ".yml")):
        return [], [], None
    try:
        # Aliases could make a document recursive or expand it exponentially; content has no use for them.
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent):
                return [], [], "YAML aliases are not allowed in content"
        data = yaml.load(text, Loader=UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass
        values: list[str] = []
        keys = keys_in(data)
        for value in strings_in(data):
            values.extend(expand_json(value, keys=keys))
    except yaml.YAMLError as err:
        return [], [], str(err).splitlines()[0]
    except RecursionError:
        return [], [], "the document is nested too deeply"
    return values, keys, None


def scan_file(policy: Policy, rel: str, text: str, private_terms: list[str]) -> list[Finding]:
    found: list[Finding] = []

    decoded, keys, yaml_error = decoded_strings(rel, text)
    if yaml_error is not None:
        found.append(Finding(rel, 1, "file is not valid YAML", yaml_error))

    # Addresses and emails are precise enough to check in the whole file, code and comments included, and again in
    # the decoded string values, where an escape such as \\u0038 no longer hides them.
    reported: set[tuple[str, str]] = set()

    def report(kind: str, value: str, line: int) -> None:
        if (kind, value.lower()) not in reported:
            reported.add((kind, value.lower()))
            found.append(Finding(rel, line, kind, value))

    for i, chunk in enumerate([text] + decoded):
        raw = i == 0
        for m in IPV4_RE.finditer(chunk):
            if ip_allowed(policy, m.group(1)) is False:
                report("IPv4 address outside documentation ranges", m.group(1),
                       line_of(text, m.group(1), m.start() if raw else 0))
        for m in [*IPV6_RE.finditer(chunk), *IPV6_KEYED_RE.finditer(chunk)]:
            cand = m.group(1)
            if cand.endswith(":") and not cand.endswith("::") and chunk[m.end(1):m.end(1) + 1].isspace():
                cand = cand[:-1]  # the colon that ends a log prefix ("from 2a00::1: Accepted"), not an empty group
            if cand.count(":") >= 2 and ip_allowed(policy, cand) is False:
                report("IPv6 address outside documentation ranges", cand, line_of(text, cand, m.start() if raw else 0))
        for m in EMAIL_RE.finditer(chunk):
            if not domain_allowed(policy, m.group(1)):
                report("email address outside reserved domains", m.group(0),
                       line_of(text, m.group(0), m.start() if raw else 0))

    # Domain names are only looked for in data, comments and VRL strings: code and YAML keys are full of dotted
    # paths. A dotted name counts when its last label is a two-letter (country code) TLD or listed in checked_tlds;
    # a URL's host counts whatever its last label. Email addresses are removed first: they are checked above, and an
    # exception for one never allows its domain anywhere else.
    if rel.endswith((".yaml", ".yml")):
        texts = decoded + comments_and_strings(text, vrl=False)
    else:
        # The decoded literals too, so an escape such as \\u{2e} cannot hide a host.
        texts = comments_and_strings(text, vrl=True) + decoded
    seen = set()
    for chunk in texts:
        chunk = EMAIL_RE.sub(" ", chunk)
        # (name, from a URL): file name and field path exclusions apply only to bare names, never to a URL's host.
        candidates = [(m.group(1), True) for m in URL_HOST_RE.finditer(chunk)]
        candidates += [(m.group(1), False) for m in DOMAIN_RE.finditer(chunk)
                       if m.group(2).lower() in policy.tlds or len(m.group(2)) == 2]
        for domain, from_url in candidates:
            key = domain.lower()
            if key in seen or ip_allowed(policy, domain) is not None or domain_allowed(policy, domain):
                continue
            if not from_url and is_non_domain(policy, domain):
                continue
            # Only reported names count as seen, so an excluded bare name never hides the same name in a URL.
            seen.add(key)
            found.append(Finding(rel, line_of(text, domain), "domain outside reserved names", domain))

    for pattern in policy.denylist:
        for i, chunk in enumerate([text] + decoded + keys):
            for m in pattern.finditer(chunk):
                report(f"matches denylist pattern {pattern.pattern!r}", m.group(0),
                       line_of(text, m.group(0), m.start() if i == 0 else 0))
    found += scan_private(rel, text, private_terms, decoded + keys)
    # Any finding that shows a private term, in any spelling, must not print it.
    for f in found:
        f.secret = f.secret or any(t in f.value.lower() for t in private_terms)
        f.secret_path = any(t in rel.lower() for t in private_terms)
    return found


def scan_private(rel: str, text: str, private_terms: list[str], decoded: list[str] | None = None) -> list[Finding]:
    """Findings for the private denylist alone, in the file and its decoded strings and keys; they never carry the
    term."""
    found: list[Finding] = []
    lowered = text.lower()
    if decoded is None:
        values, keys, _ = decoded_strings(rel, text)
        decoded = values + keys
    lowered_decoded = [d.lower() for d in decoded]
    for term in private_terms:
        idx = lowered.find(term)
        if idx < 0 and any(term in d for d in lowered_decoded):
            idx = 0
        if idx >= 0:
            found.append(Finding(rel, text.count("\n", 0, idx) + 1, "private denylist", term, secret=True,
                                 secret_path=any(t in rel.lower() for t in private_terms)))
        elif term in rel.lower():
            found.append(Finding(rel, 1, "private denylist in the file path", term, secret=True, secret_path=True))
    return found


def tracked_files(root: Path, patterns: list[str]) -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
        files = [f for f in out.decode().split("\0") if f]
    except (OSError, subprocess.CalledProcessError):
        files = [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
    return sorted(f for f in files if any(fnmatch.fnmatch(f, p) for p in patterns))


def run(root: Path, policy: Policy, private_terms: list[str], private_only: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    for rel in tracked_files(root, policy.scan):
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError as err:
            # Reported as a finding, never as a traceback: the path may contain a private term.
            findings.append(Finding(rel, 1, "file cannot be read", err.strerror or type(err).__name__,
                                    secret_path=any(t in rel.lower() for t in private_terms)))
            continue
        if private_only:
            findings += scan_private(rel, text, private_terms)
            continue
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
    ap.add_argument("--private-only", action="store_true",
                    help="check only the CONTENT_DENYLIST terms, as the trusted private denylist workflow does")
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
        print("note: CONTENT_DENYLIST is not set here; the private denylist check runs in the trusted "
              "content-denylist workflow.")
        if args.private_only:
            return 0

    findings = run(args.root.resolve(), policy, private_terms, args.private_only)
    unused = [] if args.private_only else [ex for ex in policy.exceptions if not ex.used]

    for f in findings:
        print(f.annotation() if gha else f.render())
    for ex in unused:
        msg = f"exception {ex.value!r} for {ex.paths} is no longer needed; remove it from the policy"
        print(f"::error title=Test data policy::{gha_data(msg)}" if gha else f"policy: {msg}")

    if findings or unused:
        print(f"\n{len(findings)} finding(s), {len(unused)} stale exception(s). Use documentation values "
              "(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, example.com/.net/.org, .test, "
              ".example, .invalid) or add an exception with a reason; see CONTRIBUTING.md.", file=sys.stderr)
        return 1
    print("test data policy: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
