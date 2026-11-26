# Agent notes

Guidance for coding agents that add or change Log Types here. [CONTRIBUTING.md](CONTRIBUTING.md) is the
source of truth; read it before you edit, and follow it where this file is shorter.

- **Layout**: one directory per Log Type under `log_types/<key>/` with `log_type.yaml`, `parser.vrl` and
  `tests/*.yaml`. Keep existing keys stable.
- **Public repository**: every sample, comment and branch is published. Use only the documentation-reserved
  addresses, domains, names and placeholder IDs from the
  [test data rules](CONTRIBUTING.md#test-data-rules); never copy values from a real system or log.
- **OCSF output**: emit the OCSF version the parser declares in `metadata.version`, with only attributes
  that exist in the emitted class. Declare every profile whose attributes a branch sets, per class, in
  `metadata.profiles` ([OCSF profiles](CONTRIBUTING.md#ocsf-profiles)).
- **Branches need cases**: every class or branch a parser can emit needs a regression case; validation only
  sees what the cases produce. Assert stable values, including `metadata.profiles` where a branch sets
  profile attributes.
- **Validate** before you finish ([Validate](CONTRIBUTING.md#validate)):

  ```bash
  python3 .github/content-checks/check_test_data.py
  ```

  and the content test with `--format json`, which shows each case's normalized event. Fix every failing
  case; do not weaken an assertion to make it pass.
