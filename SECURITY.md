# Security Policy

## Scope & Defensive Intent

**OodaTap** is a strictly passive, defensive network-telemetry analysis tool. It operates on captured packet files (`.pcap`/`.pcapng`) and flow/event logs (Zeek, Suricata, JSONL), performs no active network probing or offensive actions, and never requires TLS private keys or plaintext payload decryption.

## Supported Versions

| Version | Supported |
| :--- | :---: |
| `0.1.x` | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in OodaTap—such as a malformed-packet parser crash, denial-of-service in `.pcap`/`.pcapng` framing, or HTML report XSS—please report it responsibly rather than opening a public issue with an exploit payload:

1. Use GitHub's **Private Vulnerability Reporting** ("Security" → "Advisories" → "Report a vulnerability") on [`ejames-dev/OodaTap`](https://github.com/ejames-dev/OodaTap/security/advisories), or
2. Contact the maintainer directly with reproduction details and minimal sanitized test input.

### Operational Guidance
- Never commit raw production `.pcap` files, customer logs, API keys, or `.env` files containing sensitive network captures.
- Review and customize [`policies/default_policy.yaml`](policies/default_policy.yaml) for your internal CIDRs and approved developer hosts before deploying alerts to a production SIEM.
