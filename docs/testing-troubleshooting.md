# Testing & Troubleshooting

## Enable debug output

```bash
nano /var/ossec/etc/local_internal_options.conf
# add:
integrator.debug=1

systemctl restart wazuh-manager
tail -f /var/ossec/logs/integrations.log
```

The log shows the API key in use, the alert being processed, the request sent to
OpenCTI, the GraphQL response, and any error events. Set it back to `0` in
production.

You can also run the script by hand against a saved alert file:

```bash
/var/ossec/framework/python/bin/python3 \
  /var/ossec/integrations/custom-opencti.py \
  /tmp/sample_alert.json "<TOKEN>" "http://YOUR_OPENCTI_IP:8080/graphql" debug
```

## Common problems

### No alerts at all

| Check | How |
|-------|-----|
| Is the integration firing? | `integrations.log` should show activity when a matching event occurs. If empty, the event's groups don't match `<group>`. |
| Do the event groups match? | Use **Ruleset Test** in the dashboard to see the actual `rule.groups` of your events. |
| Is `check_all="yes"` set for FIM? | Without it, `sha256_after` is missing and the script exits. |
| Does the IoC exist in OpenCTI? | Search for it manually in the OpenCTI dashboard. |

### `integrations.log` is empty

The integration is not being invoked. Confirm the `<integration>` block exists,
`name` is exactly `custom-opencti`, and the Manager was restarted. Check the main
Manager log for the integration returning exit code 1:

```bash
tail -f /var/ossec/logs/ossec.log | grep -i opencti
```

### `OpenCTI Error: API Connection Failed` (rule 100211)

The Manager cannot reach OpenCTI. Verify:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://YOUR_OPENCTI_IP:8080/graphql
```

Check the `hook_url` (must end in `/graphql`), network/firewall, and that OpenCTI
is up.

### GraphQL errors / empty results on OpenCTI 6.x or 7.x

If you ported an **older** script, its filter syntax is incompatible with 6.x/7.x.
Use **this fork**, which uses the `mode` / `filters` / `filterGroups` structure.
See [Compatibility](compatibility.md).

### `401 Unauthorized` / parse errors

The token is wrong or lacks read permissions. Regenerate it in **Profile → API
Access** and confirm *Access knowledge* + *Access exploration* permissions. The
script passes it as `Authorization: Bearer <token>`.

### `ModuleNotFoundError: requests`

Run the script with the **bundled** interpreter
(`/var/ossec/framework/python/bin/python3`), not the system Python. The wrapper
does this automatically; only manual runs hit this.

### Sysmon events not arriving

| Check | How |
|-------|-----|
| Is Sysmon installed and logging? | Event Viewer → Applications and Services Logs → Microsoft‑Windows‑Sysmon/Operational. |
| Is the channel shipped? | The agent must have the `Microsoft-Windows-Sysmon/Operational` `<localfile>`. |
| Are base Sysmon rules loaded? | Without them, modern Wazuh won't emit `sysmon_eidXX_detections`. |
| Is the event captured by Sysmon config? | If filtered out (e.g. a signed DLL on EID 7), no event is produced by design. |

## Performance notes

- Each matching event triggers an HTTP call to OpenCTI. High‑volume groups (DNS,
  DLL loads) can generate many calls — keep the Sysmon noise filters in place.
- Adjust `max_ind_alerts` and `max_obs_alerts` (default 3 each) at the top of the
  script to cap alerts per query.
- The integration is synchronous per event; a slow/unreachable OpenCTI will show
  up as connection‑error alerts rather than hangs.

!!! note "Reducing alert noise"
    If `observable_only` (100216) or `observable_with_related_indicator` (100214)
    are too chatty for your CTI database, lower their `level` so they index without
    paging anyone.
