# Step‑by‑Step Guide

A complete walkthrough, from a clean Wazuh + OpenCTI deployment to a working,
enriched threat‑intel alert. It generalizes the FIM‑only procedure to cover
Sysmon and the other sources.

!!! note "Assumptions"
    Wazuh Manager (tested on **4.14.5**) and OpenCTI (tested on **6.x / 7.2**) are
    already installed, running and reachable from each other. You have root on the
    Manager and admin on OpenCTI.

## Step 1 — Get an OpenCTI API token

1. In OpenCTI, open **Profile → API Access**.
2. Copy the **API key**. Keep it secret.

![OpenCTI API Token Generation](assets/images/3.png){.rounded-img}

The same page shows the required headers; the script sets them for you.

## Step 2 — Install the integration files

On the Manager:

```bash
cd /var/ossec/integrations

# Download the integration files from GitHub
wget https://raw.githubusercontent.com/enmanuelmartex/wazuh-opencti/main/custom-opencti
wget https://raw.githubusercontent.com/enmanuelmartex/wazuh-opencti/main/custom-opencti.py

chmod 750 custom-opencti custom-opencti.py
chown root:wazuh custom-opencti custom-opencti.py
```

See [Integration files](integration-files.md) for detail.

## Step 3 — Add the detection rules

Edit `/var/ossec/etc/rules/local_rules.xml` (or **Server management → Rules →
`local_rules.xml`**) and add:

- the **OpenCTI threat‑intel rules** (`100210`–`100216`), and
- if you use Sysmon, the **base Sysmon rules** (`100140`–`100149`).

Full XML in [Detection rules](detection-rules.md).

## Step 4 — Configure the integration in the Manager

Edit `/var/ossec/etc/ossec.conf` (or **Server management → Settings → Edit
configuration**) and add, below `<cluster>`:

![Wazuh Settings Configuration](assets/images/8.png){.rounded-img}

```xml
<integration>
  <name>custom-opencti</name>
  <group>sysmon_eid1_detections,sysmon_eid3_detections,sysmon_eid6_detections,sysmon_eid7_detections,sysmon_eid15_detections,sysmon_eid22_detections,sysmon_eid23_detections,sysmon_eid24_detections,sysmon_eid25_detections,sysmon_process-anomalies,syscheck,audit_command</group>
  <alert_format>json</alert_format>
  <api_key>REPLACE-ME-WITH-A-VALID-TOKEN</api_key>
  <hook_url>http://YOUR_OPENCTI_IP:8080/graphql</hook_url>
</integration>
```

Trim the `<group>` list to the sources you actually collect (see
[Manager configuration](manager-configuration.md)).

## Step 5 — Configure the data sources

=== "FIM (native, required minimum)"

    On the agent (Agents management → Groups → `default`):

    ![Wazuh Groups Configuration](assets/images/6.png){.rounded-img}

    ```xml
    <agent_config>
      <syscheck>
        <directories realtime="yes" check_all="yes">C:\Users\user\Downloads</directories>
        <directories realtime="yes" check_all="yes">/media/user/software</directories>
      </syscheck>
    </agent_config>
    ```

    **Why `check_all="yes"` is mandatory**

    Without `check_all="yes"`, Wazuh omits the `sha256_after` field from the FIM
    alert. The `custom-opencti.py` script reads `syscheck.sha256_after` to query
    OpenCTI — if the field is absent, no enrichment occurs and the event is
    silently skipped.

    !!! info "Default monitored paths may not have check_all"
        Directories Wazuh monitors out of the box — `System32`, `drivers\etc`,
        `Startup` on Windows; `/etc`, `/usr/bin` on Linux — are configured
        **without** `check_all="yes"`. They generate normal FIM alerts but are
        **not enriched by OpenCTI** unless you explicitly redefine them with that
        attribute.

    ---

    **Realtime monitoring — known limitations**

    !!! warning "Do not monitor root paths in realtime"
        Avoid `realtime="yes"` on `C:\` (Windows) or `/` (Linux) — always use
        specific subdirectories.

        - **Windows:** `syscheck.max_fd_win_rt` (`internal_options.conf`) caps
          realtime handles at **256** (max 1 024). A full-disk path exceeds this
          and the agent silently stops reporting changes.
        - **Linux:** `fs.inotify.max_user_watches` (typically 8 192–65 536)
          limits concurrent directory watches. Monitoring `/` exhausts it —
          look for `ERROR: Unable to add inotify watch` in `ossec.log`.
          With `check_all="yes"`, hashing the whole filesystem also causes heavy
          CPU/IO load. Check or raise the limit if you monitor many specific paths:
          ```bash
          cat /proc/sys/fs/inotify/max_user_watches
          sudo sysctl fs.inotify.max_user_watches=524288
          ```
        - **Linux:** `/proc`, `/sys`, and `/dev` are virtual pseudo-filesystems —
          do not add them explicitly. Wazuh skips them automatically even if they
          fall inside a monitored path (`skip_proc`, `skip_sys`, `skip_dev` are
          enabled by default).

    !!! note "Scheduled fallback"
        If you omit `realtime="yes"`, FIM falls back to **scheduled mode**
        (`<frequency>`, default **12 hours**). Changes are only detected on the
        next scan cycle, not immediately.

    ---

    **Recommended paths to monitor**

    The following paths are best-practice additions on top of Wazuh's built-in
    defaults. Add them to your agent/group config with `check_all="yes"` to enable
    OpenCTI enrichment.

    *Windows — Endpoints*

    | Path | Security reason |
    |------|-----------------|
    | `C:\Windows\System32\drivers\etc` | Hosts file tampering — DNS redirects, C2 persistence |
    | `C:\Windows\System32` | System binary replacement, DLL hijacking |
    | `C:\Windows\SysWOW64` | Same as above, 32-bit subsystem |
    | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` | System-wide startup persistence |
    | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` | Per-user startup persistence |
    | `C:\Windows\System32\Tasks` | Scheduled task persistence |
    | `C:\Windows\Tasks` | Legacy scheduled task persistence |
    | `C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1` | PowerShell profile hijacking |
    | `C:\Users\<user>\Documents\WindowsPowerShell` | Per-user PowerShell profiles |
    | `C:\Program Files` | Application binary tampering |
    | `C:\Program Files (x86)` | Same, 32-bit applications |
    | `C:\Users\<user>\Downloads` | Primary malware delivery path |
    | `C:\Users\<user>\Desktop` | High-exposure user path |
    | `C:\Users\<user>\Documents` | Data exfiltration, document-embedded macros |

    *Windows — Servers (AD / File Servers)*

    All endpoint paths above, plus:

    | Path | Security reason |
    |------|-----------------|
    | `C:\Windows\System32\config` | SAM, SYSTEM, SECURITY hive tampering |
    | `C:\Windows\NTDS` | Active Directory database (AD DS only) |
    | `C:\Windows\SYSVOL` | GPO and logon script persistence |
    | `C:\inetpub\wwwroot` | Web shell deployment (IIS servers) |

    *Linux*

    | Path | Security reason |
    |------|-----------------|
    | `/etc` | System-wide configuration — broad persistence vector |
    | `/etc/passwd` | User account manipulation, privilege escalation |
    | `/etc/shadow` | Credential harvesting |
    | `/etc/sudoers` | Privilege escalation via sudo rules |
    | `/etc/ssh/sshd_config` | SSH backdoor — PermitRoot, authorized keys path |
    | `/etc/cron.d`, `/etc/cron.daily`, `/etc/crontab` | Cron-based persistence |
    | `/usr/bin`, `/usr/sbin` | System binary replacement (rootkits) |
    | `/bin`, `/sbin` | Core binary replacement |
    | `/boot` | Bootloader / kernel tampering |
    | `/lib`, `/usr/lib` | Shared library hijacking |
    | `/root` | Root home — SSH keys, scripts, credential files |
    | `/home/<user>/.ssh` | SSH key tampering, `authorized_keys` backdoors |
    | `/var/www` | Web shell deployment (Apache, Nginx) |

    See [Syscheck (FIM)](syscheck-fim.md) for the full attribute reference and
    noise‑reduction tips (`<ignore>` rules, `report_changes`).

=== "Sysmon (Windows)"

    1. Install Sysmon with the project's tuned config:
       ```powershell
       sysmon64.exe -accepteula -i sysmonconfig.xml
       ```
    2. Ship the channel to Wazuh:
       ```xml
       <localfile>
         <location>Microsoft-Windows-Sysmon/Operational</location>
         <log_format>eventchannel</log_format>
       </localfile>
       ```
    3. Ensure the base Sysmon rules are loaded (Step 3).

    Detail in [Sysmon](sysmon.md).

=== "Linux (DNS / commands)"

    Add packetbeat/Suricata for the `ids` group and/or auditd for
    `audit_command`. See [Linux sources](linux-sources.md).

## Step 6 — Restart and verify the service

```bash
systemctl restart wazuh-manager
systemctl status wazuh-manager
```

## Step 7 — Enable debug logging (for the test)

```bash
nano /var/ossec/etc/local_internal_options.conf
# add:
integrator.debug=1

systemctl restart wazuh-manager
```

Watch the integration log in another terminal:

```bash
tail -f /var/ossec/logs/integrations.log
```

You will see queries sent to OpenCTI, the GraphQL responses, connection errors,
and indicators found.

## Step 8 — Create a test IoC in OpenCTI

1. Create an **Observable** of type **File** (or IPv4‑Addr, Domain‑Name…).
2. Add the **SHA‑256** of a harmless test file (or the test IP/domain).
3. Create an **Indicator** and **link it** to the observable.
4. Save.

!!! important "Indicator vs. observable"
    Wazuh raises a **high‑severity** alert (`observable_with_indicator` /
    `indicator_pattern_match`) only when the observable has an indicator attached.
    Without an indicator you will get the **medium** `observable_only` alert
    instead. Add the indicator to test the high‑severity path.

## Step 9 — Generate the event

=== "FIM"

    Get the hash and drop the file in a monitored directory:

    ```powershell
    Get-FileHash .\test.txt -Algorithm SHA256
    # copy the hash into OpenCTI, then move test.txt into e.g. Downloads
    ```

    Wazuh computes the SHA‑256 → the integration queries OpenCTI → an enriched
    alert appears.

=== "Sysmon command line"

    Run a benign command that contains a test IP/URL you registered in OpenCTI:

    ```powershell
    ping.exe <your-test-public-ip>
    ```

=== "DNS"

    Resolve a test domain you registered:

    ```powershell
    Resolve-DnsName <your-test-domain>
    ```

## Step 10 — Confirm the alert

In the Wazuh dashboard, go to **Threat Hunting** (or **Explore → Discover**) and
look for alerts like:

![Wazuh Threat Hunting Alerts](assets/images/5.png){.rounded-img}

```text
OpenCTI Critical: Malicious IoC [Score: 80] - Target: <indicator name>
```

The alert includes the indicator name, score, confidence, labels, the related
observable, the OpenCTI dashboard URL, and the detected hash / IP / domain.

![Wazuh Discover Events](assets/images/9.png){.rounded-img}

## Step 11 — Disable debug (production)

Once verified, set `integrator.debug=0` (or remove the line) and restart the
Manager to avoid filling `integrations.log`.

---

If nothing appears, work through
[Testing & troubleshooting](testing-troubleshooting.md).
