# Agent notes

Guidance for coding agents that add or change Log Types here. [CONTRIBUTING.md](CONTRIBUTING.md) is the
source of truth; read it before you edit, and follow it where this file is shorter.

- **Layout**: one directory per Log Type under `log_types/<key>/` with `log_type.yaml`, `parser.vrl` and
  `tests/*.yaml`. Keep existing keys stable.
- **Public repository**: every sample, comment and branch is published. Use only the documentation-reserved
  addresses, domains, names and placeholder IDs from the
  [test data rules](CONTRIBUTING.md#test-data-rules); never copy values from a real system or log.
- **This repository is stricter than IRONCYDE**: the product accepts small parsers with one case. Official
  content follows the [quality rules](CONTRIBUTING.md#quality-rules-for-this-repository), and CI enforces
  them:
  - a regression case for every class and every branch a parser can emit, fallbacks and placeholders
    included; each case asserts `class_uid`, `type_uid` and `metadata.profiles`;
  - valid OCSF for the version in `metadata.version` with no warning except missing recommended attributes;
    fill those where the source has the data, and never invent a value;
  - hosts, addresses, users, processes, hashes and URLs at their OCSF paths, not in `unmapped`;
  - exactly the profiles whose attributes a branch sets ([OCSF profiles](CONTRIBUTING.md#ocsf-profiles)).
- **VRL pitfalls**: `to_int(null)` is `0`, `to_string(null)` is `""`, `get()` of a missing key is `null`; none
  is an error, so `??` does not fall through. An `if` expression cannot be a value inside an object literal.
  `duration` is a reserved word.
- **Validate** before you finish ([Validate](CONTRIBUTING.md#validate)):

  ```bash
  python3 .github/content-checks/check_test_data.py
  ```

  ```bash
  python3 .github/content-checks/check_case_coverage.py
  ```

  and the content test with `--format json --strict`, checked by `check_content_report.py`. Fix every
  finding in the parser; do not weaken an assertion or drop data to make a check pass.
- **Field paths are an interface**: detections and searches use them. When a change moves or removes a
  field, list it in the pull request under "Field path changes for consumers".
