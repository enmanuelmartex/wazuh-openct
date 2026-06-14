# Data Sources Overview

The integration is **source‑agnostic**: it reacts to rule groups, not to a
specific product. The table below lists every source it understands, the IoC it
extracts, and what you must configure on the endpoint.

| Source | Triggering group(s) | IoC | Endpoint requirement |
|--------|---------------------|-----|----------------------|
| **File Integrity Monitoring** | `syscheck` (added/modified) | SHA‑256 of the file | Native — [configure directories](syscheck-fim.md) |
| **Sysmon — Process Create** | `sysmon_eid1_detections` | Process SHA‑256 **+** IPs/URLs in command line | [Sysmon](sysmon.md) + [command‑line IoCs](commandline-iocs.md) |
| **Sysmon — Network Connect** | `sysmon_eid3_detections` | Public destination IP | [Sysmon](sysmon.md) |
| **Sysmon — Driver Load** | `sysmon_eid6_detections` | Driver SHA‑256 | [Sysmon](sysmon.md) |
| **Sysmon — Image/DLL Load** | `sysmon_eid7_detections` | DLL SHA‑256 | [Sysmon](sysmon.md) |
| **Sysmon — Downloaded file (ADS)** | `sysmon_eid15_detections` | File SHA‑256 | [Sysmon](sysmon.md) |
| **Sysmon — DNS Query** | `sysmon_eid22_detections` | Query name + resolved IPs | [Sysmon](sysmon.md) |
| **Sysmon — File Delete** | `sysmon_eid23_detections` | File SHA‑256 | [Sysmon](sysmon.md) |
| **Sysmon — Clipboard** | `sysmon_eid24_detections` | SHA‑256 | [Sysmon](sysmon.md) |
| **Sysmon — Process Tampering** | `sysmon_eid25_detections` | Process SHA‑256 | [Sysmon](sysmon.md) |
| **Suricata / Packetbeat** | `ids` | DNS name + answers, or public src/dst IP | [Linux sources](linux-sources.md) |
| **osquery** | `osquery`, `osquery_file` | `columns.sha256` | osquery wodle |
| **auditd** | `audit_command` | URLs in `execve` args | [Linux sources](linux-sources.md) |

## The native baseline vs. the rest

The official Wazuh documentation describes this integration limited to
`syscheck_file`, because **FIM is the only source enabled natively** — Wazuh
calculates file hashes itself, so no endpoint agent beyond the Wazuh agent is
required.

Everything else (process execution, network traffic, DNS) requires you to add a
telemetry source on the endpoint and ship its logs to the Manager:

- **Windows** → Sysmon
- **Linux network/DNS** → Suricata or Packetbeat
- **Linux command auditing** → auditd

!!! warning "Event volume"
    Adding Sysmon, Suricata or auditd significantly increases the events the
    Manager must process. Size your Manager accordingly and use the noise filters
    in the [Sysmon config](sysmon.md) to keep volume sane.

## SHA‑256 is the common currency

Most sources resolve to a **SHA‑256 hash**, which the script extracts with a
64‑hex‑character regex and queries against `hashes.SHA-256`. Make sure your
endpoints compute SHA‑256 (the provided Sysmon config sets
`<HashAlgorithms>SHA256</HashAlgorithms>`, and Syscheck reports `sha256_after`).
