# Custom Wazuh Detection Rules

This folder contains custom Wazuh detection rules created for the SOC Detection Lab. Each rule file corresponds to a specific use case and MITRE ATT&CK technique.

---

## Files

| File | Use Case | MITRE Technique |
|---|---|---|
| `uc1_nmap_recon.xml` | Network Reconnaissance Detection | [T1046](https://attack.mitre.org/techniques/T1046/) |
| `uc2_suspicious_commands.xml` | Suspicious Command Execution | [T1059](https://attack.mitre.org/techniques/T1059/) |
| `uc3_network_activity.xml` | Suspicious Network Activity | [T1049](https://attack.mitre.org/techniques/T1049/) |

---

## Rule ID Range

Custom rules use IDs in the range `100001 – 100023` to avoid conflicts with Wazuh's built-in rules (which go up to 99999).

| Rule IDs | Use Case |
|---|---|
| 100001 – 100003 | UC1 – Nmap Reconnaissance |
| 100010 – 100013 | UC2 – Suspicious Command Execution |
| 100020 – 100023 | UC3 – Suspicious Network Activity |

---

## How to Deploy

1. Copy the XML files to the Wazuh Manager rules directory:

```bash
cp uc1_nmap_recon.xml /var/ossec/etc/rules/
cp uc2_suspicious_commands.xml /var/ossec/etc/rules/
cp uc3_network_activity.xml /var/ossec/etc/rules/
```

2. Verify the rules have no syntax errors:

```bash
/var/ossec/bin/wazuh-logtest
```

3. Restart the Wazuh Manager to apply the changes:

```bash
systemctl restart wazuh-manager
```

4. Confirm rules are loaded:

```bash
/var/ossec/bin/wazuh-control status
```

---

## Requirements

| Component | Version |
|---|---|
| Wazuh Manager | 4.x or higher |
| Sysmon | 13.x or higher (for UC2 and UC3) |
| Windows Endpoint | Windows 10 / Server 2016+ |

---

## Notes

- UC2 and UC3 rules depend on **Sysmon** being installed and configured on the Windows endpoint with at minimum Event IDs 1 and 3 enabled.
- Rule `100023` is a **correlated rule** — it fires only when UC3 network activity follows UC2 command execution within a 5-minute window, indicating a chained attack sequence.
- Alert levels follow Wazuh's severity scale: `10-11` = medium, `12-13` = high, `14-15` = critical.
