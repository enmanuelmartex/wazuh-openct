# Linux Sources (Network, DNS, Commands)

On Linux there is no Sysmon, so network, DNS and command telemetry come from
other tools. The integration understands three Linux‑oriented paths.

## Suricata / Packetbeat — the `ids` group

Events tagged with the `ids` group are inspected for network IoCs.

### DNS queries (packetbeat)

If the alert is a packetbeat DNS query (`data.method == "QUERY"` and a `dns`
object is present), the script looks up the **queried name** plus any resolved
**A/AAAA** addresses:

```python
filter_values = [alert['data']['dns']['question']['name']] + addrs
ind_filter = [
    f"[domain-name:value = '{name}']",
    f"[hostname:value = '{name}']",
] + [ind_ip_pattern(a) for a in addrs]
```

Only globally routable A/AAAA answers are kept; IPv4‑mapped IPv6 answers are
normalized to IPv4.

A minimal packetbeat DNS rule set:

```xml
<group name="packetbeat,ids">
  <rule id="101000" level="0">
    <decoded_as>json</decoded_as>
    <field name="@source">packetbeat</field>
    <options>no_full_log</options>
    <description>packetbeat messages grouped</description>
  </rule>

  <rule id="101001" level="3">
    <if_sid>101000</if_sid>
    <field name="method">QUERY</field>
    <mitre><id>T1071</id></mitre>
    <description>DNS query for $(dns.question.name)</description>
    <options>no_full_log</options>
  </rule>
</group>
```

### Generic IP lookups

For non‑DNS `ids` events, the script picks whichever of the source/destination IP
is **public** and looks it up:

```python
filter_values = [next(filter(
    lambda x: x and ipaddress.ip_address(x).is_global,
    [oneof('dest_ip', 'dstip', within=alert['data']),
     oneof('src_ip', 'srcip', within=alert['data'])]), None)]
```

This is convenient for Suricata alerts, which carry `src_ip` / `dest_ip`.

## auditd — the `audit_command` group

On Linux, URLs passed to commands are captured through auditd's `execve` records.
The script extracts any `execve` argument starting with `http`:

```python
filter_values = [v for v in alert['data']['audit']['execve'].values()
                 if v.startswith('http')]
ind_filter = [f"[url:value = '{v}']" for v in filter_values]
```

To produce these events you need an auditd rule that logs `execve` and a Wazuh
rule that tags it `audit_command`. A common audit rule:

```bash
# /etc/audit/rules.d/audit.rules
-a always,exit -F arch=b64 -S execve -k audit_command
-a always,exit -F arch=b32 -S execve -k audit_command
```

Ensure the agent forwards the audit log:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

## osquery — the `osquery` / `osquery_file` groups

If you run the osquery wodle and a query returns a `sha256` column, the script
looks that hash up:

```python
filter_key = 'hashes.SHA-256'
filter_values = [alert['data']['osquery']['columns']['sha256']]
```

Enable the osquery wodle in `ossec.conf` and write queries that surface file
hashes (for example FIM‑style queries over `hash` tables).

!!! note "Sysmon for Linux"
    Sysmon also exists for Linux. The script's Sysmon EID 3 handling reads
    `win.eventdata.destinationIp`; for Linux Sysmon deployments the field mapping
    differs, so the `ids` / Suricata path is generally the more reliable route for
    Linux network IoCs.
