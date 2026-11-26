# Contributing content

## Prepare a change

1. Keep existing Log Type keys stable; they are referenced by installed configurations and events.
2. Make focused parser or metadata changes.
3. Add regression cases for changed behavior and important failure modes.
4. Use synthetic or sanitized logs that follow the test data rules below. Do not include real
   credentials, tokens, personal data, or confidential host/customer identifiers.
5. Record provenance for externally derived code or samples and retain applicable notices.

Use lowercase letters, digits, and underscores for Log Type keys and case filenames. Each case
contains a nonempty `raw_sample` and may contain dot-separated expected field assertions:

```yaml
raw_sample: 'Jun 14 15:16:01 host sshd[123]: Failed password for root from 192.0.2.10 port 51000 ssh2'
expected:
  class_uid: 3002
  status_id: 2
  actor.user.name: root
```

Assertions cover meaningful stable values, not generated execution timestamps. A parser receives
the original raw text in `.message`, including when that text is JSON; decode it explicitly.

## OCSF profiles

An OCSF profile adds optional attributes to a class. Which attributes belong to a profile depends on
the class: `device` is a core attribute of Process Activity (1007) but belongs to the `host` profile
in Authentication (3002), Network Activity (4001) and API Activity (6003); `actor` is core in
Authentication but belongs to `host` in Network Activity and Detection Finding (2004). An event that
sets a profile attribute must name that profile in `metadata.profiles`.

This matters for two reasons:

- **Observables**: IRONCYDE derives observables (host names, IP addresses, users, hashes, ...) from
  the event the way the OCSF schema defines them. Profile attributes yield observables only when the
  event declares their profile, so an undeclared `device` contributes no host name.
- **Validation**: OCSF validation reports a profile attribute whose profile is not declared as an
  error, and the content test fails that case.

To find the profiles a parser branch needs, take each attribute the branch sets, including nested
ones, and look it up in the class it emits, using the OCSF version in `metadata.version`:

1. On a class page of the [OCSF schema browser](https://schema.ocsf.io), profile attributes are marked
   with their profile; the class's own attribute list decides, not the object's general description.
2. For a nested attribute, check the object as well: `device.container` and `process.container`
   belong to the `container` profile, `process.euid` to `linux/linux_users` or `macos/macos_users`,
   and the `*_dt` time attributes to `datetime`, whichever class contains them.
3. Declare each such profile once. An attribute that lists several profiles needs only one of them.
   Core attributes need no declaration.

Declare the profiles per class and per branch, next to the code that sets the attributes, and keep
profiles a branch already declares (for example `security_control` on findings):

```vrl
if class_uid == 4001 {
  # device and actor belong to the host profile in Network Activity.
  .metadata.profiles = ["host"]
  .device = {"hostname": host, "type_id": 0}
  .actor = {"user": {"name": user}}
}
```

Do not move data to `unmapped` or drop it to avoid a declaration. Assert the profiles in the
regression case of every branch that sets them; list assertions compare the whole list:

```yaml
expected:
  class_uid: 4001
  device.hostname: web1
  metadata.profiles: [host]
```

The content test reports an undeclared profile attribute as an OCSF validation error
(`validation_attribute_requires_profile`) on the case that produces it, so each branch that sets
profile attributes needs a regression case.

## Test data rules

This repository is public, and everything in it, including its Git history and every pushed branch,
is published. Test cases, sample events, parser comments and metadata therefore use only identifiers
that are reserved for documentation:

| Kind | Use | Never |
| --- | --- | --- |
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) | public addresses, and also private ranges such as `10.0.0.0/8` or `192.168.0.0/16` |
| IPv6 | `2001:db8::/32` (RFC 3849); `fe80::/10` for zone tests | other addresses |
| Domains, hostnames, emails | `example.com`, `example.net`, `example.org`, `*.example`, `*.test`, `*.invalid` (RFC 2606) | real company, customer, vendor tenant or personal domains; internal names such as `*.local`, `*.corp`, `*.internal` that come from a real network |
| Users and hosts | clearly fictitious names: `alice`, `bob`, `deploy`, `web1`, `Jane Doe` | names copied from a real system, ticket or customer log |
| Secrets | no real value at all; if a format needs one, a vendor-documented example such as AWS's `AKIAIOSFODNN7EXAMPLE` | tokens, keys, passwords, session IDs, hashes or fingerprints copied from a real system |
| Account, tenant and object IDs | documented placeholders such as `123456789012`, or obviously fake values | IDs from a real tenant, subscription or deployment |

When a sample comes from a vendor's documentation or a public dataset, still replace its addresses,
names and IDs with the values above and record the source (rule 5). A deployment's stored test cases
and logs exported from a customer or internal system are never sanitized enough to copy: write a new
synthetic sample that has the same structure. When a parser's behavior depends on the exact length of
a line, keep the length when you replace values.

CI enforces this on every pull request (`content-checks` workflow):

- **Secret scan**: [gitleaks](https://github.com/gitleaks/gitleaks) with its default rules over the
  whole history and the working tree, configured in [`.gitleaks.toml`](.gitleaks.toml). Only
  vendor-documented example credentials are allowlisted.
- **Test data policy**: [`check_test_data.py`](.github/content-checks/check_test_data.py) checks every
  IP address, email address and domain name in `log_types/` against
  [`test_data_policy.yaml`](.github/content-checks/test_data_policy.yaml). Domains are looked for in
  sample data, comments, parser strings and URLs.
- **Private denylist**: the `content-denylist` workflow checks a maintainer-managed private list of
  customer names and internal hostnames (`CONTENT_DENYLIST`) with the checker from `main`, so the list
  never reaches code a pull request changes. Matches are reported without the term. Pull requests from
  forks are not checked, so reviewers still read every sample.

File names such as `README.md` and field paths such as `container.id` are not domains. The policy
ignores common file extensions and JSON object keys; a real host that ends in one of those extensions
is therefore not checked mechanically, unless it appears in a URL, so reviewers still read every sample.

Run the test data check locally with Python 3 and PyYAML:

```bash
python3 .github/content-checks/check_test_data.py
```

If a value that is not reserved for documentation is really needed (for example a vendor's fixed
service endpoint that the parser matches on), add an entry under `exceptions` in the policy with the
exact value, the files it may appear in, and a reason a reviewer can verify. Exceptions that no longer
match anything fail the check. Never add customer names or internal hostnames to the public policy.

If a secret was ever pushed, to any branch, treat it as compromised: rotate it first, then ask a
maintainer to clean up the history. Deleting the file or the branch alone does not unpublish it.

## Validate

The `content-test` workflow runs every Log Type through IRONCYDE's own content check, the same check a
content source applies before installation: the repository format, the parser safety checks, every
regression case through the pinned Vector, expected field assertions, and OCSF validation. Failing cases
and parsers are annotated on their files. The workflow pins the IRONCYDE release it checks against.

It runs for pull requests from branches of this repository and for every change on `main`. Pull requests
from forks are not tested automatically; a maintainer runs the check before merging.

With access to the IRONCYDE image registry, run the same check locally from the repository root, using the
release the workflow pins:

```bash
docker run --rm --network none -v "$PWD:/content:ro" \
  registry.procyde.online/ironcyde/ironcyde-api:<version> content test /content
```

`--log-type <key>` limits the run to one Log Type, `--strict` fails cases on OCSF recommendations too, and
`--format json` prints the complete report, including each case's normalized event.

## Publish a reviewed update

- Keep `format_version: 1` until a coordinated reader/format upgrade exists.
- Keep content within the documented repository format.
- Document parser retirement explicitly; do not use an empty parser as a retirement signal.
- Require review and passing validation before updating the branch used by deployments.
  Configure GitHub branch protections separately; this document does not enforce them.

By submitting a contribution, you confirm that you have the right to contribute it under the
repository's [Apache-2.0 license](LICENSE).
