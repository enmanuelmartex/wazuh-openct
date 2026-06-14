# Sysmon (Windows)

Sysmon is what unlocks the Windows detection paths beyond file integrity:
process creation, network connections, driver/DLL loads, downloaded files, DNS
queries, file deletion, clipboard capture and process tampering. This page covers
the three pieces you need: **install Sysmon**, **ship its events to Wazuh**, and
**tune the Sysmon config** so you capture exactly what the script consumes
without drowning the Manager.

## 1. Install Sysmon on the endpoint

Download Sysmon from Microsoft Sysinternals and install it with the provided
config (next section):

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml
# to update an existing install with a new config:
sysmon64.exe -c sysmonconfig.xml
```

## 2. Ship Sysmon events to Wazuh

Add the Sysmon channel to the agent configuration (Agents management → Groups →
`default`, or `agent.conf`):

```xml
<agent_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

Then make sure the [base Sysmon rules](../installation/detection-rules.md#part-1-base-sysmon-rules)
are loaded on the Manager so each event lands in its `sysmon_eidXX_detections`
group.

## 3. Which events the script consumes

The Sysmon config provided with this project deliberately captures **only** the
events the script reads, and disables the rest:

| EID | Sysmon event | IoC extracted | Script path |
|:---:|--------------|---------------|-------------|
| 1 | Process Create | SHA‑256 **+** IPs/URLs in `commandLine` | `sysmon_eid1_detections` |
| 3 | Network Connect | Public destination IP | `sysmon_eid3_detections` |
| 6 | Driver Load | Driver SHA‑256 | `sysmon_eid6_detections` |
| 7 | Image/DLL Load | DLL SHA‑256 | `sysmon_eid7_detections` |
| 15 | FileCreateStreamHash | Downloaded file SHA‑256 | `sysmon_eid15_detections` |
| 22 | DNS Query | Query name + resolved IPs | `sysmon_eid22_detections` |
| 23 | File Delete | File SHA‑256 | `sysmon_eid23_detections` |
| 24 | Clipboard Change | SHA‑256 | `sysmon_eid24_detections` |
| 25 | Process Tampering | Process SHA‑256 | `sysmon_eid25_detections` |

Events **2, 4, 5, 8–14, 16–21** are disabled — the script does not use them, and
they would only add volume.

!!! note "SHA‑256 only"
    The config sets `<HashAlgorithms>SHA256</HashAlgorithms>` because that is the
    hash the script's regex extracts. Capturing MD5/IMPHASH as well only bloats
    the events.

## 4. Filtering strategy per event

The config balances **coverage** against **disk/Manager load**. The approach
differs by event:

### Event 1 — Process Create → *exclude noise*

Captures everything **except** high‑volume, low‑value system processes
(`svchost.exe`, `RuntimeBroker.exe`, Defender/MRT, Windows Update, etc.). A
second include block specifically captures download/execution LOLBins and
`ping.exe`, whose command lines carry IPs and URLs — see
[command‑line IoCs](commandline-iocs.md).

### Event 3 — Network Connect → *exclude private & Microsoft*

Excludes RFC 1918 private ranges, loopback, link‑local and multicast (the script
discards those anyway), plus known high‑volume Microsoft destinations. Whatever
remains is a connection to a **public** IP worth checking.

### Events 6 & 7 — Driver / DLL Load → *include only suspicious*

These are the events most likely to flood the disk if captured wholesale. The
config **includes only** unsigned or invalidly‑signed modules, and DLLs loaded
from user‑writable paths (`C:\Users\`, `Temp`, `ProgramData`). Signed Microsoft
modules are pure noise here.

### Event 15 — Downloaded file (ADS) → *include executables/scripts*

Captures the SHA‑256 of files written with a Zone.Identifier ADS (i.e. downloaded
from the internet), limited to executable and script extensions plus archives and
macro‑capable documents.

### Event 22 — DNS Query → *exclude known‑good domains*

Uses **exclude** (never `include`) so unknown malicious domains are never missed.
It suppresses high‑volume known‑good domains (Microsoft, Google, CDNs, OCSP, etc.)
and captures everything else. The script also parses the `queryResults` to extract
resolved A/AAAA addresses and looks **those** up too.

### Events 23, 24, 25 — Delete / Clipboard / Tampering → *include all*

Low‑volume, high‑signal events. File Delete is restricted to executables/scripts
(to catch self‑deleting malware); clipboard and tampering are captured in full.

## 5. Minimal config skeleton

The full tuned config is large; this skeleton shows the shape. Use the complete
file shipped with the project for production.

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <EventFiltering>

    <!-- EID 1: capture all but system noise -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <!-- … more noise exclusions … -->
      </ProcessCreate>
    </RuleGroup>

    <!-- EID 3: exclude private/multicast/Microsoft -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <DestinationIp condition="begin with">10.</DestinationIp>
        <DestinationIp condition="begin with">192.168.</DestinationIp>
        <!-- … -->
      </NetworkConnect>
    </RuleGroup>

    <!-- EID 6/7: include only unsigned/suspicious -->
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include">
        <Signed condition="is">false</Signed>
      </DriverLoad>
    </RuleGroup>

    <!-- EID 22: exclude known-good domains, capture the rest -->
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.microsoft.com</QueryName>
        <!-- … -->
      </DnsQuery>
    </RuleGroup>

    <!-- EID 24/25: capture all (low volume) -->
    <RuleGroup name="" groupRelation="or">
      <ClipboardChange onmatch="include" />
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessTampering onmatch="include" />
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

!!! tip "Disabling unused events cleanly"
    To disable an event type, include a rule that can never match, e.g.:
    ```xml
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <RuleName condition="is">DISABLED</RuleName>
      </RegistryEvent>
    </RuleGroup>
    ```
    This is how the provided config switches off events 2, 4, 5, 8–14 and 16–21.
