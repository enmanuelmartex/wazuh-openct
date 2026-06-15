# Requirements

Before installing the integration, make sure you have the following components
in place.

## Infrastructure

| Component        | Requirement                                  |
|------------------|----------------------------------------------|
| **Wazuh Manager** | 4.x (tested on **4.14.5**)                  |
| **OpenCTI**       | **6.x** or **7.x** (tested on **7.2**)      |
| **Network**       | Manager must be able to reach the OpenCTI GraphQL endpoint (`http(s)://<host>:<port>/graphql`) |

!!! warning "OpenCTI 5.x and earlier"
    This fork uses the modern GraphQL filter syntax (`mode` / `filters` /
    `filterGroups`) introduced after OpenCTI 5.12. It does **not** work on
    OpenCTI versions older than 6.0. See
    [Compatibility](compatibility.md) for details.

## OpenCTI API token

You need an API token with **read** permissions on knowledge and exploration:

1. Log in to OpenCTI → **Profile → API Access**.
2. Copy the token. Keep it secret — you will paste it into `ossec.conf`.
3. The token must have at least the *Access knowledge* and *Access exploration*
   capabilities.

!!! danger "Never commit your token"
    Use the placeholder `REPLACE-ME-WITH-A-VALID-TOKEN` in any file you publish
    or store in version control.

## Endpoint telemetry (optional, per source)

The integration works with **any** combination of sources. The minimum is
Wazuh's native FIM (Syscheck), which requires no extra tooling:

| Source | Endpoint requirement | Details |
|--------|---------------------|---------|
| **FIM (Syscheck)** | None — built into the Wazuh agent | [Syscheck (FIM)](syscheck-fim.md) |
| **Sysmon (Windows)** | [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) installed with the project's config | [Sysmon](sysmon.md) |
| **Suricata / Packetbeat** | Suricata or Packetbeat deployed and forwarding to Wazuh | [Linux sources](linux-sources.md) |
| **auditd** | `execve` audit rules enabled | [Linux sources](linux-sources.md) |
| **osquery** | osquery wodle enabled in Wazuh | [Linux sources](linux-sources.md) |

## Python dependencies

The script runs under the **Wazuh-bundled Python** interpreter
(`/var/ossec/framework/python/bin/python3`). Its only third-party dependency,
`requests`, is included with that interpreter — no `pip install` needed on the
Manager.

## Next steps

➡️ Continue to **[Compatibility & version history](compatibility.md)** to
understand the project's lineage and OpenCTI version support.
