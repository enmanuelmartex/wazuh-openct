# Syscheck (File Integrity Monitoring)

FIM is the **native baseline** for this integration. Wazuh computes SHA‑256
hashes for files in the directories you monitor; when a file is added or
modified, the integration looks the hash up in OpenCTI. No endpoint tooling
beyond the Wazuh agent is required.

## How the script uses it

When an alert's groups contain `syscheck_file` together with
`syscheck_entry_added` or `syscheck_entry_modified`, the script reads:

```python
filter_key   = 'hashes.SHA-256'
filter_values = [alert['syscheck']['sha256_after']]
```

and queries OpenCTI for an observable/indicator matching that hash.

!!! note
    In the `ossec.conf` integration block you can list either `syscheck` or
    `syscheck_file` in `<group>` — both appear in FIM alert groups. The provided
    example uses `syscheck`.

## Configuring monitored directories

FIM directories are configured **per agent** (or per agent group). Edit the
agent configuration from **Agents management → Groups → `default`** (pencil
icon), or in the agent's `agent.conf`.

### Windows example

```xml
<agent_config>
  <syscheck>
    <directories realtime="yes" report_changes="yes" check_all="yes">C:\Users\user\OneDrive\Desktop</directories>
    <directories realtime="yes" report_changes="yes" check_all="yes">C:\Users\user\Downloads</directories>
    <directories realtime="yes" report_changes="yes" check_all="yes">C:\Users\user\AppData\Local\Temp</directories>
    <directories realtime="yes" report_changes="yes" check_all="yes">C:\Windows\System32\drivers</directories>

    <ignore>C:\Windows\System32\LogFiles</ignore>
    <ignore>C:\Windows\SoftwareDistribution</ignore>
    <ignore>C:\Windows\Prefetch</ignore>
    <ignore type="sregex">\.log$|\.etl$|\.evtx$</ignore>
  </syscheck>
</agent_config>
```

### Linux example

```xml
<agent_config>
  <syscheck>
    <directories realtime="yes" report_changes="yes" check_all="yes">/media/user/software</directories>
    <directories realtime="yes" report_changes="yes" check_all="yes">/tmp</directories>
  </syscheck>
</agent_config>
```

### Attribute reference

| Attribute | Effect |
|-----------|--------|
| `realtime="yes"` | Report changes immediately (inotify / Windows backend) instead of waiting for the scan cycle. Optional but recommended for fast detection. |
| `report_changes="yes"` | Include what changed in the alert. |
| `check_all="yes"` | Compute all checks, including hashes — **required** so `sha256_after` is present. |

!!! tip "Pick high‑risk directories"
    Download folders, the desktop, `Temp`, and driver paths are good candidates:
    they are where dropped payloads land. Avoid monitoring noisy log/cache
    directories, and use `<ignore>` to suppress churn.

## Why `check_all` matters

The integration keys on `syscheck.sha256_after`. If `check_all` (or at least the
hash checks) is disabled, the alert will not contain a SHA‑256 and the script has
nothing to query. Always include `check_all="yes"` on monitored directories you
want threat‑intel enrichment for.

## Testing FIM enrichment

1. Create an **Observable (File)** in OpenCTI with the SHA‑256 of a harmless test
   file, and attach an **Indicator** to it.
2. Compute the hash on the endpoint — on Windows:
   ```powershell
   Get-FileHash .\test.txt -Algorithm SHA256
   ```
3. Drop the file into a monitored directory.
4. Wazuh computes the hash → the integration queries OpenCTI → an enriched alert
   appears.

See the [step‑by‑step guide](step-by-step.md) for the full test
procedure.
