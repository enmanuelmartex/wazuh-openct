# What's New in This Fork

This page compares this fork against its two ancestors — the **juaromu**
original (`juaromu/wazuh-opencti`, the repo this project was forked from) and the
**misje/wazuh-opencti** rewrite — so you can see exactly what changed and why.

## Summary

| Capability | juaromu | misje | **This fork** |
|------------|:------:|:-----:|:-------------:|
| Observable lookup | ✅ | ✅ | ✅ |
| Indicator lookup & STIX patterns | ❌ | ✅ | ✅ |
| Event types (match classification) | ❌ | ✅ (4) | ✅ (**6**) |
| Indicator sorting (score/confidence/validity) | ❌ | ✅ | ✅ |
| Related‑observable resolution | ❌ | ✅ | ✅ |
| Token & URL from config (not hard‑coded) | ❌ | ✅ | ✅ |
| OpenCTI version | pre‑5 syntax | 5.12.24 | **6.x / 7.x** |
| Group matching | by position | exact string | **regex (both schemes)** |
| Command‑line IoC extraction (EID 1) | ❌ | ❌ | ✅ **new** |
| Multi‑key queries (`filterGroups`) | ❌ | partial | ✅ **expanded** |
| `observable_only` alert type | ❌ | ❌ | ✅ **new** |
| Sysmon EID 6/7/15/23/24/25 coverage | partial | ✅ | ✅ (+ regex robustness) |

## New in detail

### 1. Runs on modern OpenCTI (6.x / 7.x)

The headline change. OpenCTI altered its GraphQL **filtering** structure after
5.12; queries now use `mode`, `filters` and `filterGroups`. This fork uses that
structure throughout, so it works on 6.x and 7.x where the older scripts return
errors or nothing. This was the reason the fork was created: the upstream script
did not work on a 6.x instance until the query was updated.

### 2. Regex‑based group matching

Instead of reading the rule group by **position** (`groups[2]`) or matching exact
strings like `sysmon_event1`, the script matches groups with regular expressions
that accept **all** of the naming schemes Wazuh has used over time:

```python
# Matches sysmon_event1, sysmon_event_15, sysmon_eid1_detections, …
sha256_sysmon_event_regex = re.compile(
    'sysmon_(?:(?:event_?|eid)(?:1|6|7|15|23|24|25)|process-anomalies)')
sysmon_event3_regex  = re.compile('sysmon_(?:event|eid)3')
sysmon_event22_regex = re.compile('sysmon_(?:event_|eid)22')
```

This removes the dependency on a fixed group order and makes the integration work
whether your rules emit `sysmon_event1` or `sysmon_eid1_detections`.

### 3. Command‑line IoC extraction (Sysmon EID 1)

Sysmon Event 1 (Process Create) now does more than check the process hash. The
script scans `commandLine` and pulls out:

- **Public IPv4/IPv6 addresses** (validated, private/loopback discarded), e.g.
  `ping.exe 8.8.8.8`.
- **URLs** beginning with `http://` or `https://`, e.g.
  `curl.exe http://malicious.example/payload`.

It then builds STIX patterns for each and queries them **alongside** the SHA‑256
hash in a single request using `filterGroups`:

```python
# Hash OR command-line values, in one GraphQL request
obs_filter_groups = [
    {"mode": "or", "filterGroups": [], "filters": [{"key": "hashes.SHA-256", "values": filter_values}]},
    {"mode": "or", "filterGroups": [], "filters": [{"key": "value", "values": cmdline_values}]},
]
```

This catches LOLBin‑style downloaders (`certutil`, `bitsadmin`, `mshta`,
PowerShell `Invoke-WebRequest`, etc.) where the malicious indicator is the **URL
or IP in the arguments**, not the binary itself.

### 4. New `observable_only` event type

Upstream only alerted when an observable had an indicator tied to it. Many feeds
(AbuseIPDB, raw imports) create **observables without indicators**. This fork adds
an `observable_only` path that still raises a **medium‑severity** alert so you
learn the IoC is known to your CTI, even without a formal STIX indicator:

```python
if not indicators and not related_obs_w_ind:
    new_alert['opencti']['event_type'] = 'observable_only'
    # …emit a medium-severity alert instead of staying silent
```

### 5. Expanded, hardened Sysmon coverage

Sysmon events 6 (driver load), 7 (image/DLL load), 15 (downloaded file ADS),
23 (file delete), 24 (clipboard) and 25 (process tampering) are all routed
through the SHA‑256 lookup via the group regex, together with a tuned
[Sysmon configuration](data-sources/sysmon.md) that captures exactly these events
and suppresses high‑volume noise.

## Unchanged from upstream

The core query model — indicator sorting, related‑observable resolution, the
`max_ind_alerts` / `max_obs_alerts` caps, label/marking simplification for
OpenSearch, and the `source` context block — is inherited from `misje` and works
the same way.
