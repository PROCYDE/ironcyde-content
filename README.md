# IRONCYDE Content

Official security content for IRONCYDE.

This repository contains Log Type definitions, VRL normalization parsers, and regression tests.

## Included content

| Log Type key | Content |
| --- | --- |
| `linux_auth` | Linux sshd, PAM, login, and sudo authentication outcomes, plus sudo command activity. |

The Linux parser produces OCSF Authentication or Process Activity events. It accepts raw syslog text
and supported JSON-wrapped messages. Nonmatching messages are intentionally rejected; see the
parser and its regression cases for supported inputs and expected outputs.

## Review a parser

The repository root is the content root:

```text
content.yaml
log_types/
  linux_auth/
    log_type.yaml
    parser.vrl
    tests/
      accepted_certificate.yaml
      ...
```

- [Manifest](content.yaml): repository format and official content version.
- [Metadata](log_types/linux_auth/log_type.yaml): description and OCSF/Vector requirements.
- [Parser](log_types/linux_auth/parser.vrl): VRL source.
- [Regression cases](log_types/linux_auth/tests/): exact sample input and expected field assertions.

The repository uses `format_version: 1` and `content_version: 1`. The included content targets
OCSF 1.9.0 and declares a minimum Vector version of 0.57.0.

## Contribute

Follow [CONTRIBUTING.md](CONTRIBUTING.md). Preserve existing keys, include representative sanitized
regression cases, and validate changes with IRONCYDE's authoritative server runner.

Report issues and propose changes through this repository's GitHub issues and pull requests.
Do not attach production logs containing credentials, personal data, or confidential identifiers.

## License

This repository is licensed under [Apache-2.0](LICENSE). Contributions must have compatible
provenance; retain any required third-party notices.
