# Requirements

Before configuring the integration, make sure the two platforms it bridges are
already installed and running. This project does **not** install Wazuh or
OpenCTI for you — it assumes a normal, working deployment of both.

## Mandatory

| Requirement | Detail |
|-------------|--------|
| **Wazuh Manager** | Installed and running. Tested on **4.14.5**. The integration runs entirely on the Manager; agents need no extra software for it. |
| **OpenCTI** | Installed and running, reachable from the Manager. Tested on **6.x** and **7.2**. |
| **OpenCTI API token** | A token with **read** permissions (*Access knowledge* + *Access exploration*). Used by the script to authenticate GraphQL queries. |
| **Network connectivity** | The Manager must reach the OpenCTI GraphQL endpoint (`http(s)://<opencti>/graphql`), typically on port 8080 or 443. |
| **Administrative access** | Root / sudo on the Wazuh Manager host to drop the integration files and edit `ossec.conf`. |
| **Python `requests`** | The script imports `requests`. It ships with the Wazuh framework Python, but confirm it is importable (see [Troubleshooting](testing-troubleshooting.md)). |

## Conditional (depending on what you want to detect)

The base integration only needs **Syscheck (FIM)**, which Wazuh provides
natively. Everything else expands coverage and requires extra telemetry on the
endpoints:

| To detect… | You need… |
|------------|-----------|
| File hashes from monitored directories | **Syscheck / FIM** — built in, nothing extra. |
| Process hashes, DLLs, drivers, downloaded files, DNS queries, clipboard, process tampering (Windows) | **Sysmon** installed on the endpoint + the [Sysmon config](sysmon.md) + base Sysmon rules on the Manager. |
| Public IPs and URLs inside process command lines (Windows) | Sysmon Event 1 with command‑line capture (covered by the Sysmon config). |
| Network connections to public IPs (Windows) | Sysmon Event 3. |
| DNS queries / network IoCs (Linux) | **Packetbeat** or **Suricata** feeding the `ids` group. |
| URLs in audited commands (Linux) | **auditd** with an `execve` rule producing the `audit_command` group. |

!!! note "Getting the OpenCTI token"
    In OpenCTI, open your **Profile → API Access** and copy the **API key**. The
    same screen shows the required headers (`Content-Type: application/json` and
    `Authorization: Bearer <token>`), which the script sets automatically.

## TLS / HTTPS note

If OpenCTI is served over HTTPS with a certificate signed by a private CA, place
the root CA on the Manager and reference it through the `verify` option of the
`requests` call inside the script. With plain HTTP (e.g. an internal lab on
`http://<ip>:8080/graphql`) no certificate handling is needed.
