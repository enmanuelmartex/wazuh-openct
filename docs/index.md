# Wazuh + OpenCTI Threat Intelligence Integration

This project connects a **Wazuh Manager** to an **OpenCTI** threat‑intelligence
platform so that indicators of compromise (IoCs) seen on your endpoints are
checked, in real time, against your CTI database. When a hash, IP address,
domain, hostname or URL observed by Wazuh matches something stored in OpenCTI,
Wazuh raises an **enriched alert** that carries the indicator name, score,
confidence, labels, marking (TLP), the creating organization and direct links
back into the OpenCTI dashboard.

It is a **custom Wazuh integration**: a small wrapper script plus a Python
script that lives on the Manager, is triggered by rule groups, queries OpenCTI's
GraphQL API, and feeds the result back into Wazuh's analysis pipeline as a new
event.

!!! info "What this fork adds"
    The lineage is **juaromu → misje → this fork**. The original integration was
    created by **juaromu** (`juaromu/wazuh-opencti`); **misje** later rewrote it to
    add indicator logic; this fork is built on the original repository and adapted
    to run on **modern OpenCTI (6.x and 7.x)** with several new detection paths.
    See [What's New](whats-new.md) for the full comparison.

## Tested environment

| Component        | Version tested            | Notes                                         |
|------------------|---------------------------|-----------------------------------------------|
| Wazuh Manager    | **4.14.5**                | Also verified on earlier 4.x releases         |
| OpenCTI          | **7.2** (and 6.x)         | Upstream `misje` targeted 5.12.24 only        |
| Sysmon           | 4.90 schema               | Windows endpoints                             |
| Endpoint OS      | Windows 10/11, Linux      | Linux via auditd / packetbeat                 |

## How it fits together

```
┌─────────────┐   events    ┌──────────────┐   matched groups   ┌──────────────────┐
│   Endpoint  │ ──────────▶ │    Wazuh     │ ─────────────────▶ │ custom-opencti.py│
│ (Sysmon/FIM)│   (agent)   │   Manager    │   (integration)    │  (GraphQL query) │
└─────────────┘             └──────────────┘                    └────────┬─────────┘
                                   ▲                                      │
                                   │       enriched alert (new event)     │ HTTP / GraphQL
                                   └──────────────────────────────────────┤
                                                                          ▼
                                                                 ┌──────────────────┐
                                                                 │     OpenCTI      │
                                                                 │  (CTI database)  │
                                                                 └──────────────────┘
```

1. An agent forwards an event (a Sysmon detection, a file‑integrity change, a
   DNS query…) to the Manager.
2. A Wazuh rule tags the event with a **group** the integration listens for.
3. The integration extracts the IoC (SHA‑256, IP, domain, hostname or URL) and
   queries OpenCTI over **GraphQL**.
4. If OpenCTI knows the IoC, the script emits a new event that Wazuh turns into
   an **OpenCTI alert** with a severity that depends on the match type.

## Documentation map

- **[Requirements](requirements.md)** — what you need before you start.
- **[Compatibility](compatibility.md)** — OpenCTI/Wazuh versions and why this fork exists.
- **[How it works](how-it-works.md)** — the query logic, end to end.
- **[What's New](whats-new.md)** — feature‑by‑feature comparison against upstream.
- **Installation** — [files](integration-files.md), [manager config](manager-configuration.md), [detection rules](detection-rules.md).
- **Data sources** — [Syscheck/FIM](syscheck-fim.md), [Sysmon](sysmon.md), [command‑line IoCs](commandline-iocs.md), [Linux network/DNS](linux-sources.md).
- **[Event types](event-types.md)** — every alert type and its severity.
- **[Step‑by‑step guide](step-by-step.md)** — a full walkthrough from zero to a working alert.
- **[Testing & troubleshooting](testing-troubleshooting.md)**.
- **[Script internals](script-internals.md)** — for people who want to extend it.

!!! warning "Credentials"
    The OpenCTI API token is a sensitive secret. Throughout this documentation it
    is shown as a placeholder (`REPLACE-ME-WITH-A-VALID-TOKEN`). Never commit a
    real token to a public repository or paste it into a published site.
