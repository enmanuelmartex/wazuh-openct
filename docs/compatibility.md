# Compatibility & Version History

The integration has gone through three generations. Understanding the lineage
explains **why this fork exists** and which OpenCTI versions it targets.

## The three generations

```
juaromu/wazuh-opencti  ──▶  misje/wazuh-opencti  ──▶  this fork
(original, basic)           (indicators + types)      (OpenCTI 6/7 + new sources)
```

### 1. juaromu (original)

The first script, from the **`juaromu/wazuh-opencti`** repository — the repo this
project was forked from. It queried only **observables**
(`stixCyberObservables`) using the *old* GraphQL filter syntax and returned the
first match with its labels. It had **no concept of indicators**, no event types,
no scoring or sorting, and no related‑observable logic. The OpenCTI URL and token
were hard‑coded inside the script, and it dispatched on the rule group **by
position** (`groups[0]` = OS, `groups[2]` = event type) against hard‑coded strings
such as `sysmon_event1`.

### 2. misje/wazuh-opencti

A substantial rewrite (**`misje/wazuh-opencti`**) that introduced the model this
fork still uses:

- Queries **both** observables and **indicators**.
- Introduces **event types**: `indicator_pattern_match`,
  `indicator_partial_pattern_match`, `observable_with_indicator`,
  `observable_with_related_indicator`.
- **Sorts** indicators by `!revoked`, detection, score, confidence and
  `valid_until`, and caps the number of alerts.
- Resolves **related observables** (e.g. a domain that resolves to a flagged IP).
- Reads the token and URL from the **integration configuration** instead of
  hard‑coding them.
- Adds Linux sources: **packetbeat DNS**, **osquery**, **auditd** (`audit_command`).
- Requires **OpenCTI 5.12.24+** because of the GraphQL filter syntax it uses.

### 3. This fork

Built on top of `misje` and adapted to run on the OpenCTI versions in use today,
plus new detection paths. See [What's New](whats-new.md) for the detail.

## OpenCTI version support

| Integration version | OpenCTI support |
|---------------------|-----------------|
| `juaromu` (original) | Old filter syntax (pre‑5.x era) |
| `misje`              | **5.12.24** (older versions need filter‑syntax reverts) |
| **This fork**        | **6.x and 7.x** (tested through **7.2**) |

!!! warning "Why upstream fails on OpenCTI 6+"
    OpenCTI changed its GraphQL **filtering API** after the 5.12 line: filters
    moved to a structure that uses `mode`, `filters` and `filterGroups`. A script
    written for the 5.12 syntax returns errors (or empty results) against a 6.x/7.x
    instance. This fork uses the newer filter structure throughout, which is why it
    works on 6.x and 7.x but the older scripts do not. This was the original reason
    for the fork: the `misje` script did **not** work on a 6.x instance until the
    query and filtering were updated.

## Wazuh version support

Wazuh ships on the **4.x** line (4.14.5 was used here). One important detail
carried over from upstream:

!!! note "`sysmon_eidX_detections`, not `sysmon_eventX`"
    Modern Wazuh does **not** emit generic `sysmon_eventX` groups out of the box —
    it emits specific **detection** groups like `sysmon_eid1_detections`. The base
    rules also do not cover Sysmon events 16–25 by default. This fork therefore
    matches groups with a **regex** that accepts *both* naming schemes
    (`sysmon_eventX`, `sysmon_event_XX` **and** `sysmon_eidXX_detections`), so it
    is robust regardless of which rules you have loaded. The
    [base Sysmon rules](../installation/detection-rules.md) provided here create
    the `sysmon_eidXX_detections` groups for events 1, 3, 6, 7, 15, 22, 23, 24 and 25.
