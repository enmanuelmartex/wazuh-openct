# Script Internals

For people who want to read, debug or extend `custom-opencti.py`. This is a map of
the script, not a line‑by‑line listing.

## Entry point

```python
if __name__ == '__main__':
    # requires at least: alert_file, token, url
    debug_enabled = len(sys.argv) > 4 and sys.argv[4] == 'debug'
    main(sys.argv)
```

`main()` loads the alert JSON, calls `query_opencti(alert, url, token)`, and sends
each resulting alert with `send_event()`.

## Key globals and regexes

| Name | Purpose |
|------|---------|
| `max_ind_alerts`, `max_obs_alerts` | Caps (default 3) on alerts per query. |
| `regex_file_hash` | `[A-Fa-f0-9]{64}` — extracts SHA‑256 from `hashes`. |
| `sha256_sysmon_event_regex` | Matches EID 1/6/7/15/23/24/25 and `process-anomalies`, both `event` and `eid` naming. |
| `sysmon_event3_regex`, `sysmon_event22_regex` | Match EID 3 and 22 across naming schemes. |
| `cmdline_url_regex`, `cmdline_ipv4_regex`, `cmdline_ipv6_regex` | Pull IoCs out of command lines. |
| `dns_results_regex` | Splits Sysmon EID 22 `queryResults` into records. |

## Dispatch logic (`query_opencti`)

A single `try` block reads `alert['rule']['groups']` and picks the first branch
that matches:

1. **SHA‑256 Sysmon events** → hash lookup, **plus** command‑line IP/URL
   extraction (with `filterGroups` when both are present).
2. **Sysmon EID 3** → public destination IP.
3. **`ids`** → packetbeat DNS (name + A/AAAA) or public src/dst IP.
4. **Sysmon EID 22** → query name + resolved IPs.
5. **`syscheck_file`** (added/modified) → `sha256_after`.
6. **osquery** → `columns.sha256`.
7. **`audit_command`** → `http*` args from `execve`.
8. Otherwise → `sys.exit()`.

`IndexError` and `KeyError` are caught and treated as "nothing to look up" — the
script exits silently rather than erroring.

## The GraphQL query

One request asks for both `indicators` and `stixCyberObservables`. It uses
fragments (`Object`, `Labels`, `IndShort`, `IndLong`, `Indicators`,
`NameRelation`, `AddrRelation`, `PageInfo`) to keep the payload readable, and the
modern filter structure:

```python
'variables': {
  'obs': {
    "mode": "or",
    "filterGroups": obs_filter_groups,         # multi-key when needed
    "filters": [{"key": filter_key, "values": filter_values}] if not obs_filter_groups else []
  },
  'ind': {
    "mode": "and",
    "filterGroups": [],
    "filters": [
      {"key": "pattern_type", "values": ["stix"]},
      {"mode": "or", "key": "pattern", "values": ind_filter},
    ]
  }
}
```

## Post‑processing helpers

| Function | Role |
|----------|------|
| `remove_empties()` | Recursively strips nulls, empty strings/lists/dicts before sending (keeps booleans). |
| `simplify_objectlist()` | Flattens nested `edges/node` lists (labels, kill‑chain phases, external refs) into plain arrays for OpenSearch. |
| `indicator_sort_func()` / `sort_indicators()` | Rank by `!revoked`, detection, score, confidence, validity. |
| `modify_indicator()` / `modify_observable()` | Reshape objects and add dashboard links. |
| `relationship_with_indicators()` | Find a related observable that has an indicator. |
| `format_dns_results()` | Keep only global A/AAAA answers; unmap IPv4‑mapped IPv6. |
| `extract_commandline_iocs()` | Validate and return public IPs + URLs from a command line. |
| `ind_ip_pattern()` | Build an IPv4/IPv6 STIX pattern. |
| `add_context()` | Attach the `source` block (originating event metadata). |

## Output channel

Alerts are written to the Wazuh socket as a synthetic event:

```python
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
# message format:
# 1:[<agent_id>] (<name>) <ip>->opencti:<json>
```

Wazuh re‑ingests it; the `threat_intel` rules (matching `integration == opencti`)
turn it into the final alert.

## Extending it

To add a new source, add a branch in `query_opencti` that:

1. Detects your group in `alert['rule']['groups']`.
2. Sets `filter_key`, `filter_values`, and `ind_filter` (STIX patterns).
3. Lets the shared query and post‑processing handle the rest.

The upstream projects (`juaromu/wazuh-opencti` and `misje/wazuh-opencti`)
explicitly welcome pull requests that add new event types and groups.
