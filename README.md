# SOC Detection Lab using Wazuh

## Project Overview

This project demonstrates the implementation of a Security Operations Center (SOC) detection lab using Wazuh to monitor endpoint activity, analyze logs, detect suspicious behavior, and map alerts to the MITRE ATT&CK framework.

The lab simulates three real-world attacker scenarios covering network reconnaissance, suspicious command execution, and abnormal network activity — all detected and alerted through custom Wazuh rules.

---

## Lab Architecture

![SOC Architecture Diagram](https://user-images.githubusercontent.com/229574965/559983858-e55f0bca-22b1-4ae7-a642-6cd8922018b2.png)

The SOC lab environment consists of:

- **Windows Endpoint** — target machine running Sysmon
- **Wazuh Agent** — installed on the Windows endpoint to collect logs
- **Wazuh Manager** — receives and analyzes logs, applies detection rules
- **Wazuh Indexer** — stores and indexes alert data
- **Wazuh Dashboard** — visualizes alerts and supports threat hunting

Logs from the Windows endpoint are forwarded to the Wazuh Manager for analysis and alert generation.

---

## Endpoint Monitoring

The Windows endpoint was configured with **Sysmon** to capture detailed system activity including:

- Process creation (Event ID 1)
- Network connections (Event ID 3)
- Command execution
- Windows Event Logs

These logs were forwarded to Wazuh for monitoring and detection.

---

## Attack Simulation

Three attack scenarios were simulated to test the detection capabilities of the SOC lab.

---

### 1. Network Reconnaissance – Port Scanning (UC1)

Network reconnaissance was simulated using Nmap from an attacker machine targeting the Windows endpoint.

**Command used:**
```bash
nmap -sS -p- <target-ip>
```

**Goal:** Discover open ports and running services on the target machine.

This activity generated a high volume of connection attempts captured in network and firewall logs, then analyzed by Wazuh.

---

### 2. Suspicious Command Execution (UC2)

After gaining access to the Windows endpoint, the following enumeration commands were manually executed via `cmd.exe`:

**Commands used:**
```cmd
whoami
net user
ipconfig /all
```

| Command | Purpose |
|---|---|
| `whoami` | Identify current user context and privileges |
| `net user` | Enumerate local user accounts on the machine |
| `ipconfig /all` | Gather full network configuration details |

These commands were captured by **Sysmon (Event ID 1 – Process Creation)** and forwarded to Wazuh for analysis.

---

### 3. Suspicious Network Activity (UC3)

Abnormal outbound network connections were simulated to replicate post-compromise behavior such as C2 communication or lateral movement attempts.

**Activity simulated:**
- Outbound connections initiated from `cmd.exe` and `powershell.exe`
- Connections targeting uncommon ports (4444, 1337, 8888)
- High-frequency connection attempts from a single process

These were captured by **Sysmon (Event ID 3 – Network Connection)** and correlated with UC2 command execution activity inside Wazuh to identify the full attack sequence.

---

## Use Cases

---

### Use Case 1 – Network Reconnaissance Detection

**MITRE ATT&CK:** [T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

**Description:**
An attacker performs network reconnaissance to discover open ports and running services on the target Windows endpoint using Nmap. This is typically one of the first steps in an attack chain.

**Attack Simulation:**
```bash
nmap -sS -p- <target-ip>
```

**Log Sample (Wazuh Alert):**
```json
{
  "rule": {
    "id": "100003",
    "level": 14,
    "description": "Multiple connection rejections from same source – Possible full port scan (nmap -p-)"
  },
  "data": {
    "srcip": "192.168.1.100",
    "action": "DROP",
    "frequency": "50+ in 60 seconds"
  },
  "mitre": {
    "technique": "Network Service Discovery",
    "id": "T1046"
  }
}
```

**Detection Logic:**
- Custom Wazuh rule `100003` fires when 50+ connection rejections occur from the same source IP within 60 seconds
- Alert level set to **14 (high)**

---

### Use Case 2 – Suspicious Command Execution

**MITRE ATT&CK:** [T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

**Description:**
An attacker who has gained access to the Windows endpoint manually executes system enumeration commands to gather information about the environment.

**Attack Simulation:**
```cmd
whoami
net user
ipconfig /all
```

**Log Sample (Sysmon Event ID 1 → Wazuh Alert):**
```json
{
  "rule": {
    "id": "100011",
    "level": 11,
    "description": "Sysmon: net user executed – Local user account enumeration detected (T1059)"
  },
  "data": {
    "win.eventdata.image": "C:\\Windows\\System32\\net.exe",
    "win.eventdata.commandLine": "net user",
    "win.system.eventID": "1",
    "win.eventdata.user": "DESKTOP-XXX\\attacker"
  },
  "mitre": {
    "technique": "Command and Scripting Interpreter",
    "id": "T1059"
  }
}
```

**Detection Logic:**
- Rule `100010` detects `whoami.exe` via Sysmon Event ID 1
- Rule `100011` detects `net user` by matching process image and command-line arguments
- Rule `100012` detects `ipconfig /all` by matching process image and `/all` flag
- Composite rule `100013` fires at **level 14** if 2+ of these commands execute within 120 seconds

---

### Use Case 3 – Suspicious Network Activity

**MITRE ATT&CK:** [T1049 – System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)

**Description:**
After initial enumeration, abnormal outbound network connections are observed originating from shell processes on the Windows endpoint. Wazuh correlates process activity with network logs to identify suspicious behavior.

**Log Sample (Sysmon Event ID 3 → Wazuh Alert):**
```json
{
  "rule": {
    "id": "100021",
    "level": 11,
    "description": "Sysmon: Shell process initiated outbound network connection – Suspicious activity (T1049)"
  },
  "data": {
    "win.eventdata.image": "C:\\Windows\\System32\\cmd.exe",
    "win.eventdata.destinationIp": "203.0.113.45",
    "win.eventdata.destinationPort": "4444",
    "win.eventdata.initiated": "true",
    "win.system.eventID": "3"
  },
  "mitre": {
    "technique": "System Network Connections Discovery",
    "id": "T1049"
  }
}
```

**Detection Logic:**
- Rule `100020` flags outbound connections to known suspicious ports
- Rule `100021` flags any shell process making outbound connections
- Rule `100022` fires when a single process makes 20+ outbound connections within 60 seconds
- **Correlated rule `100023`** (level 15 – critical) fires when network activity is detected within 5 minutes of the recon commands from UC2, identifying the full attack chain

---

## Detection Engineering

Custom detection rules were created in Wazuh to detect all three use cases. Rule files are located in the [`rules/`](./rules/) folder.

| Rule File | Use Case | Rule IDs |
|---|---|---|
| `uc1_nmap_recon.xml` | Network Reconnaissance | 100001 – 100003 |
| `uc2_suspicious_commands.xml` | Suspicious Command Execution | 100010 – 100013 |
| `uc3_network_activity.xml` | Suspicious Network Activity | 100020 – 100023 |

---

## Alert Tuning

Alert tuning was performed to reduce false positives and improve detection accuracy by:

- Adjusting rule frequency thresholds
- Setting appropriate timeframe windows per rule
- Using composite rules to correlate related events before alerting

---

## MITRE ATT&CK Mapping

| Technique | ID | Use Case | Detection Method |
|---|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | UC1 – Network Reconnaissance Detection | Custom Wazuh rule triggered on Nmap scan patterns in network logs |
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | UC2 – Suspicious Command Execution | Sysmon Event ID 1 (Process Creation) forwarded to Wazuh; alert on `whoami`, `net user`, `ipconfig` |
| System Network Connections Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | UC3 – Suspicious Network Activity | Wazuh correlation of Sysmon network events and process logs for abnormal outbound connections |

---

## Technologies Used

| Tool | Role |
|---|---|
| Wazuh 4.x | SIEM / Detection Engine |
| Sysmon 13.x | Endpoint Telemetry |
| Nmap | Attack Simulation (Reconnaissance) |
| Windows Event Logs | Log Source |
| MITRE ATT&CK Framework | Threat Mapping |

---

## Results

### Wazuh Manager – Successful Startup

![Wazuh v4.14.2 startup confirmation showing all services running](https://user-images.githubusercontent.com/229574965/559984513-97febfb9-b001-4f95-af9e-2d443c07f05e.jpeg)

Wazuh v4.14.2 was successfully deployed and started on the Ubuntu server. All core services confirmed running including `wazuh-apid`, `wazuh-analysisd`, `wazuh-remoted`, `wazuh-logcollector`, and `wazuh-modulesd`. The manager is fully operational and ready to receive logs from the Windows endpoint agent.

---

### Wazuh Dashboard – Live Alert Feed (Threat Hunting View)

![Wazuh Dashboard showing 494 alerts from endpoint DESKTOP-6B015RT](https://user-images.githubusercontent.com/229574965/559984500-f4b19768-b215-4d26-a491-85bfb86aa2b5.jpeg)

The Wazuh Dashboard captured **494 alerts** from the monitored Windows endpoint (`DESKTOP-6B015RT`) over a 24-hour window. The alert feed shows a range of rule severities (levels 3–9) including:

- **User account changes** (Rule 60110) — triggered during the `net user` command simulation
- **Users Group Changed** (Rule 60170) — flagged during enumeration activity
- **Service startup type changes** (Rule 61104) — detected during post-exploitation behavior
- **CIS Benchmark violations** (Rules 19005–19009) — SCA policy compliance alerts

This demonstrates that Wazuh was actively monitoring endpoint activity and generating alerts mapped to real security events throughout the attack simulation.

---

## Skills Demonstrated

- Log analysis and threat detection
- Custom Wazuh rule creation and tuning
- Endpoint monitoring with Sysmon
- MITRE ATT&CK mapping
- Detection engineering and alert correlation
- SOC lab environment setup and configuration