# Contributing content

## Prepare a change

1. Keep existing Log Type keys stable; they are referenced by installed configurations and events.
2. Make focused parser or metadata changes.
3. Add regression cases for changed behavior and important failure modes.
4. Use synthetic or sanitized logs. Do not include real credentials, tokens, personal data, or
   confidential host/customer identifiers.
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

## Validate

This repository does not yet have its own CI or pinned execution toolchain. Use the supported
IRONCYDE parser workspace/server runner to test the candidate with its regression cases.
The authoritative gate checks VRL restrictions, output shape, field assertions, and OCSF errors.
Browser-only preview is not a substitute.

## Publish a reviewed update

- Keep `format_version: 1` until a coordinated reader/format upgrade exists.
- Keep content within the documented repository format.
- Document parser retirement explicitly; do not use an empty parser as a retirement signal.
- Require review and passing validation before updating the branch used by deployments.
  Configure GitHub branch protections separately; this document does not enforce them.

By submitting a contribution, you confirm that you have the right to contribute it under the
repository's [Apache-2.0 license](LICENSE).
