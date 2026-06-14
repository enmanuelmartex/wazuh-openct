# Event Types Reference

Every alert the integration produces carries an `opencti.event_type` field. It
describes **how** the IoC matched, which in turn drives the alert severity. This
fork defines six types (the original four from upstream plus the new
`observable_only`, and the always‑present `error`).

## The types

| `event_type` | Meaning | Confidence | Example rule / level |
|--------------|---------|:----------:|----------------------|
| `indicator_pattern_match` | The IoC matches a STIX indicator's pattern **exactly**. | Highest | 100212 / **14** |
| `observable_with_indicator` | The IoC is a known observable that has its **own** indicator. | Highest | 100213 / **14** |
| `observable_with_related_indicator` | The observable has no indicator, but a **related** observable does (e.g. domain → resolved IP). | High | 100214 / **12** |
| `indicator_partial_pattern_match` | The IoC appears **inside** a more complex pattern, not as the whole pattern. | High | 100215 / **12** |
| `observable_only` *(new)* | The IoC is a known observable with **no** indicator and **no** related indicator (raw feeds). | Medium | 100216 / **10** |
| `error` | The API could not be reached or returned an error. | — | 100211 / **5** |

## How each is decided

### Indicator matches

The script queries indicators directly. For each returned indicator:

```python
event_type = 'indicator_pattern_match' \
    if indicator['pattern'] in ind_filter \
    else 'indicator_partial_pattern_match'
```

If the exact STIX pattern the script built is present in the indicator, it is an
**exact** match; otherwise the IoC matched as part of a larger pattern and it is
**partial**.

### Observable matches

For each matching observable the script checks for indicators:

- Has its own indicator(s) → **`observable_with_indicator`**
- No own indicator, but a related observable has one → **`observable_with_related_indicator`**
- Neither → **`observable_only`** (this fork)

```python
if not indicators and not related_obs_w_ind:
    event_type = 'observable_only'          # NEW: still alert
else:
    event_type = 'observable_with_indicator' if indicators \
                 else 'observable_with_related_indicator'
```

## Why `observable_only` exists

Many threat‑intel feeds import **observables without attaching STIX indicators**
(AbuseIPDB IP lists are a common example). Upstream would find the observable but,
seeing no indicator, stay silent. That means a known‑bad IP could go unreported.

`observable_only` closes that gap with a **medium‑severity** alert: the IoC is
known to your CTI even though no formal indicator exists. Tune rule 100216's level
to taste — if your database is heavy on indicator‑less observables, this can be
chatty.

## Fields available in each alert

Depending on type, alerts expose (non‑exhaustive):

- `opencti.indicator.name`, `…x_opencti_score`, `…confidence`, `…pattern`,
  `…valid_until`, `…labels`, `…killChainPhases`
- `opencti.observable_value`, `opencti.x_opencti_score`, `opencti.entity_type`
- `opencti.indicator_link`, `opencti.observable_link` — direct dashboard URLs
- `opencti.related.*` — the related observable and its indicator
- `opencti.source.*` — the originating Wazuh event (alert id, rule id, file path,
  hashes, network 5‑tuple, query name, command line)
- `opencti.labels` — imported OpenCTI labels for analyst context
