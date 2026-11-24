# IRONCYDE Content

Official security content for IRONCYDE.

This repository contains Log Type definitions, VRL normalization parsers, and regression tests.

## Included content

| Log Type key | Content |
| --- | --- |
| `atomic` | Atomic Red Team simulated technique artifacts (ATT&CK-mapped). |
| `authentik` | Authentik authentication and application authorization events. |
| `aws_cloudtrail` | AWS CloudTrail API activity. |
| `caldera` | MITRE Caldera ability and step execution. |
| `crowdstrike_falcon` | CrowdStrike Falcon detection summaries. |
| `defender_edr` | Microsoft Defender for Endpoint alerts. |
| `exim` | Exim mainlog SMTP activity, including VRFY reconnaissance. |
| `falco` | Falco runtime-security alerts (file, process, network, detection). |
| `kubernetes_audit` | Kubernetes API audit events. |
| `linux_auth` | Linux sshd, PAM, login, and sudo authentication outcomes, plus sudo command activity. |
| `okta_system_log` | Okta System Log authentication, admin, and lifecycle events. |
| `palo_alto` | Palo Alto PAN-OS traffic and threat logs. |
| `scanner_finding` | IRONCYDE scanner/recon findings (nuclei, nmap, trivy, gitleaks, ...). |
| `snort` | Snort alert and flow events. |
| `suricata` | Suricata EVE alert, DNS, HTTP, and flow events. |
| `trex_emu` | TRex emu traffic records (DNS, HTTP, DHCP, ICMP, ARP, netflow). |
| `zeek` | Zeek conn.log network activity. |
| `windows_event` | Windows Security event log entries (classic key/value or Fluent Bit StringInserts form). |
| `windows_sysmon` | Windows Sysmon operational events (process, network, file, DNS, registry, module). |

Most parsers produce OCSF events from raw or JSON-wrapped messages. Nonmatching messages are
intentionally rejected; see each parser and its regression cases for supported inputs and
expected outputs.

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

- [Manifest](content.yaml): repository format.
- [Metadata](log_types/linux_auth/log_type.yaml): name, description, vendor, and product.
- [Parser](log_types/linux_auth/parser.vrl): VRL source.
- [Regression cases](log_types/linux_auth/tests/): exact sample input and expected field assertions.

## Contribute

Follow [CONTRIBUTING.md](CONTRIBUTING.md). Preserve existing keys, include representative sanitized
regression cases, and validate changes with IRONCYDE's authoritative server runner.

Report issues and propose changes through this repository's GitHub issues and pull requests.
Do not attach production logs containing credentials, personal data, or confidential identifiers.

## License

This repository is licensed under [Apache-2.0](LICENSE). Contributions must have compatible
provenance; retain any required third-party notices.
