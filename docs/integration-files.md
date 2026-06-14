# Installing the Integration Files

The integration is two files that live in the Manager's integrations directory:

| File | Purpose |
|------|---------|
| `custom-opencti` | Shell **wrapper**. Wazuh calls this; it locates the bundled Python and launches the `.py`. |
| `custom-opencti.py` | The **logic**: extracts IoCs, queries OpenCTI, builds enriched alerts. |

## 1. Place the files

On the Wazuh Manager:

```bash
cd /var/ossec/integrations
```

Copy both files into this directory. If you host them in your own repository you
can fetch them directly, for example:

```bash
wget -O custom-opencti    https://raw.githubusercontent.com/<your-org>/<your-repo>/main/custom-opencti
wget -O custom-opencti.py https://raw.githubusercontent.com/<your-org>/<your-repo>/main/custom-opencti.py
```

!!! note "Docker deployments"
    On the Wazuh Docker images, the integrations directory is the root of the
    `wazuh_integrations` volume, and the Manager config is
    `config/wazuh_cluster/wazuh_manager.conf`.

## 2. Set permissions and ownership

Both files must be executable by the `wazuh` group and owned by `root:wazuh`:

```bash
chmod 750 /var/ossec/integrations/custom-opencti
chmod 750 /var/ossec/integrations/custom-opencti.py
chown root:wazuh /var/ossec/integrations/custom-opencti
chown root:wazuh /var/ossec/integrations/custom-opencti.py
```

## 3. How the wrapper finds Python

You do not normally edit the wrapper, but it helps to know what it does. It
resolves its own directory, then runs the `.py` with the Manager's embedded
Python interpreter:

```sh
WPYTHON_BIN="framework/python/bin/python3"
...
${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
```

Because it uses the bundled interpreter, you do **not** need a system‑wide Python.
The script's only third‑party dependency, `requests`, is included with the Wazuh
framework Python.

## 4. Arguments passed by Wazuh

When a rule matches, Wazuh calls the wrapper with positional arguments. The script
reads them as:

| Position | Value | Source |
|----------|-------|--------|
| `args[1]` | path to the alert JSON file | Wazuh (temporary file) |
| `args[2]` | OpenCTI API token | `<api_key>` in `ossec.conf` |
| `args[3]` | OpenCTI GraphQL URL | `<hook_url>` in `ossec.conf` |
| `args[4]` | `debug` (optional) | enables verbose logging |

That is why the token and URL are **not** hard‑coded in the script — they come
from the integration block you configure next.

➡️ Continue to **[Manager configuration](manager-configuration.md)**.
