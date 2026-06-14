# Wazuh + OpenCTI Threat Intelligence Integration

A custom [Wazuh](https://wazuh.com/) integration that enriches alerts with threat
intelligence from [OpenCTI](https://www.opencti.io/). When a SHA‑256 hash, IP
address, domain, hostname or URL observed on an endpoint matches an indicator or
observable in OpenCTI, Wazuh raises an **enriched alert** carrying the indicator
name, score, confidence, labels, marking (TLP) and direct links back into the
OpenCTI dashboard.

This fork adapts the integration to run on **modern OpenCTI (6.x / 7.x)** and adds
new detection paths (command‑line IoC extraction, expanded Sysmon coverage and a
new `observable_only` alert type).

> **Tested on:** Wazuh Manager **4.14.5** · OpenCTI **7.2** (also verified on 6.x)
> · Sysmon schema **4.90**.

---

## Credits & lineage

This project stands on the work of two upstream projects. Full credit to both:

```
juaromu/wazuh-opencti  ──▶  misje/wazuh-opencti  ──▶  this fork
   (original)                 (indicators + types)      (OpenCTI 6/7 + new sources)
```

- **[juaromu/wazuh-opencti](https://github.com/juaromu/wazuh-opencti)** — the
  **original** integration, which this repository was forked from. It established
  the basic idea: look up Wazuh alert metadata as observables in OpenCTI.
- **[misje/wazuh-opencti](https://github.com/misje/wazuh-opencti)** — a major
  rewrite that introduced indicator lookups, STIX pattern matching, event types,
  indicator sorting and related‑observable resolution, and modernised the GraphQL
  filter syntax (OpenCTI 5.12.24+).
- **This fork** — adapts the integration to OpenCTI **6.x / 7.x**, makes rule‑group
  matching robust across Wazuh naming schemes, and adds the new features listed
  below.

If you find this useful, please also star/credit the upstream repositories.

---

## What this fork adds

| Capability | juaromu | misje | This fork |
|------------|:------:|:-----:|:---------:|
| Observable lookup | ✅ | ✅ | ✅ |
| Indicator lookup & STIX patterns | ❌ | ✅ | ✅ |
| Event types | ❌ | ✅ (4) | ✅ (**6**) |
| OpenCTI version | pre‑5 syntax | 5.12.24 | **6.x / 7.x** |
| Group matching | by position | exact string | **regex (both schemes)** |
| Command‑line IoC extraction (EID 1) | ❌ | ❌ | ✅ **new** |
| Multi‑key queries (`filterGroups`) | ❌ | partial | ✅ **expanded** |
| `observable_only` alert type | ❌ | ❌ | ✅ **new** |

See [`docs/whats-new.md`](docs/whats-new.md) for the detailed comparison.

---

## Quick start

1. Copy `custom-opencti` and `custom-opencti.py` to `/var/ossec/integrations/` and
   set permissions:
   ```bash
   chmod 750 /var/ossec/integrations/custom-opencti{,.py}
   chown root:wazuh /var/ossec/integrations/custom-opencti{,.py}
   ```
2. Add the detection rules to `/var/ossec/etc/rules/local_rules.xml`
   (see [`docs/installation/detection-rules.md`](docs/installation/detection-rules.md)).
3. Add the integration block to `/var/ossec/etc/ossec.conf`:
   ```xml
   <integration>
     <name>custom-opencti</name>
     <group>syscheck,sysmon_eid1_detections,sysmon_eid3_detections,sysmon_eid22_detections,audit_command</group>
     <alert_format>json</alert_format>
     <api_key>REPLACE-ME-WITH-A-VALID-TOKEN</api_key>
     <hook_url>http://YOUR_OPENCTI_IP:8080/graphql</hook_url>
   </integration>
   ```
4. Restart the Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

Full walkthrough: [`docs/guide/step-by-step.md`](docs/guide/step-by-step.md).

---

## Documentation

The complete documentation lives in [`docs/`](docs/) and is built with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/):

```bash
pip install mkdocs-material
mkdocs serve        # preview locally at http://127.0.0.1:8000
mkdocs gh-deploy    # publish to GitHub Pages
```

Full table of contents:

- **[Home / Overview](docs/index.md)**
- **Getting started**
    - [Requirements](docs/getting-started/requirements.md)
    - [Compatibility & version history](docs/getting-started/compatibility.md)
    - [How it works](docs/getting-started/how-it-works.md)
- **[What's new](docs/whats-new.md)**
- **Installation**
    - [Integration files](docs/installation/integration-files.md)
    - [Manager configuration](docs/installation/manager-configuration.md)
    - [Detection rules](docs/installation/detection-rules.md)
- **Data sources**
    - [Overview](docs/data-sources/overview.md)
    - [Syscheck (FIM)](docs/data-sources/syscheck-fim.md)
    - [Sysmon (Windows)](docs/data-sources/sysmon.md)
    - [Command‑line IoCs](docs/data-sources/commandline-iocs.md)
    - [Linux sources](docs/data-sources/linux-sources.md)
- **[Event types](docs/event-types.md)**
- **[Step‑by‑step guide](docs/guide/step-by-step.md)**
- **[Testing & troubleshooting](docs/testing-troubleshooting.md)**
- **Reference**
    - [Script internals](docs/reference/script-internals.md)

---

## Security note

The OpenCTI API token is a sensitive secret. It is shown as
`REPLACE-ME-WITH-A-VALID-TOKEN` throughout this repository. **Never commit a real
token** to version control, and rotate any token that has been exposed.


