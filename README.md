# SOC Detection Lab using Wazuh

## Project Overview
This project demonstrates the implementation of a Security Operations Center (SOC) detection lab using Wazuh to monitor endpoint activity, analyze logs, detect suspicious behavior, and map alerts to the MITRE ATT&CK framework.

The lab simulates attacker activities such as network reconnaissance and suspicious command execution.

---

## Lab Architecture

<img width="3200" height="2400" alt="SOC Architecture Diagram" src="https://github.com/user-attachments/assets/e55f0bca-22b1-4ae7-a642-6cd8922018b2" />


The SOC lab environment consists of:

- Windows Endpoint
- Wazuh Agent
- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard
- Sysmon for endpoint monitoring

Logs from the Windows endpoint are forwarded to Wazuh for analysis and alert generation.

---

## Endpoint Monitoring

The Windows endpoint was configured with Sysmon to capture detailed system activity including:

- Process creation
- Network connections
- Command execution
- Windows Event Logs

These logs were forwarded to Wazuh for monitoring and detection.

---

## Attack Simulation

Three attack scenarios were simulated to test the detection capabilities of the SOC lab environment.

---

### 1. Network Reconnaissance – Port Scanning (UC1)

Network reconnaissance was simulated using Nmap from a Kali Linux attacker machine targeting the Windows endpoint.

**Command used:**
```bash
nmap -sS -p- <target-ip>
```

**Goal:** Discover open ports and running services on the target machine.

This activity generated a high volume of connection attempts that were captured in firewall and network logs, then analyzed by Wazuh.

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

These were captured by **Sysmon (Event ID 3 – Network Connection)** and correlated with the command execution activity from UC2 inside Wazuh to identify the full attack sequence.

---

---
## Endpoint Monitoring
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

**What Happens:**
- Nmap sends SYN packets across all 65,535 ports
- The Windows endpoint receives a high volume of connection attempts in a short timeframe
- Wazuh picks up the abnormal traffic pattern from network and firewall logs

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
- Alert level set to **14 (high)** to trigger immediate SOC attention

---

### Use Case 2 – Suspicious Command Execution

**MITRE ATT&CK:** [T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

**Description:**
An attacker who has gained access to the Windows endpoint manually executes system enumeration commands to gather information about the environment — current user, local accounts, and network configuration.

**Attack Simulation:**

```cmd
whoami
net user
ipconfig /all
```

**What Happens:**
- Sysmon (Event ID 1 – Process Creation) captures each command execution
- Logs are forwarded to the Wazuh Manager
- Custom rules match on process name and command-line arguments

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
- Composite rule `100013` fires at **level 14** if 2+ of these commands are executed within 120 seconds — indicating an active enumeration session

---

### Use Case 3 – Suspicious Network Activity

**MITRE ATT&CK:** [T1049 – System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)

**Description:**
After initial enumeration, abnormal outbound network connections are observed originating from shell processes on the Windows endpoint. Wazuh correlates process activity with network logs to identify suspicious behavior.

**What Was Monitored:**
- Outbound connections to uncommon/suspicious ports (4444, 1337, 8888, etc.)
- Shell processes (`cmd.exe`, `powershell.exe`) initiating network connections
- High-frequency outbound connections from a single process

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
- Rule `100021` flags any shell process (`cmd.exe`, `powershell.exe`, `wscript.exe`) making outbound connections
- Rule `100022` fires when a single process makes 20+ outbound connections within 60 seconds
- **Correlated rule `100023`** (level 15 – critical) fires when network activity is detected within 5 minutes of the recon commands from UC2 — identifying the full attack chain: **Enumeration → Lateral Movement**

---
---
## Detection Engineering

Custom detection rules were created in Wazuh to detect:

- Port scanning attempts
- Suspicious command execution
- Unusual network connections

---

## Alert Tuning

Alert tuning was performed to reduce false positives and improve detection accuracy by adjusting rule thresholds and conditions.

---

## MITRE ATT&CK Mapping

| Technique | ID | Use Case | Detection Method |
|---|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | UC1 – Network Reconnaissance Detection | Custom Wazuh rule triggered on Nmap scan patterns in network logs |
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | UC2 – Suspicious Command Execution | Sysmon Event ID 1 (Process Creation) forwarded to Wazuh; alert on `whoami`, `net user`, `ipconfig` |
| System Network Connections Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | UC3 – Suspicious Network Activity | Wazuh correlation of Sysmon network events and process logs for abnormal outbound connections |

---

## Technologies Used

- Wazuh
- Sysmon
- Nmap
- Windows Event Logs
- MITRE ATT&CK Framework

---

## Results

### Wazuh Manager – Successful Startup

![Screenshot 2026-01-25 214945](https://github.com/user-attachments/assets/92bab6ed-48a1-4534-a683-6610c7c934f0)

Wazuh v4.14.2 was successfully deployed and started on the Ubuntu server. All core services confirmed running including `wazuh-apid`, `wazuh-analysisd`, `wazuh-remoted`, `wazuh-logcollector`, and `wazuh-modulesd`. The manager is fully operational and ready to receive logs from the Windows endpoint agent.

---

### Wazuh Dashboard – Live Alert Feed (Threat Hunting View)

![Screenshot 2026-01-25 214944](https://github.com/user-attachments/assets/44e895f0-0f95-4bc6-b79a-5eeb2f5e590a)

The Wazuh Dashboard captured **494 alerts** from the monitored Windows endpoint (`DESKTOP-6B015RT`) over a 24-hour window. The alert feed shows a range of rule severities (levels 3–9) including:

- **User account changes** (Rule 60110) — triggered during the `net user` command simulation
- **Users Group Changed** (Rule 60170) — flagged during enumeration activity
- **Service startup type changes** (Rule 61104) — detected during post-exploitation behavior
- **CIS Benchmark violations** (Rules 19005–19009) — SCA policy compliance alerts

This demonstrates that the Wazuh SIEM was actively monitoring endpoint activity and generating alerts mapped to real security events throughout the attack simulation.

---
