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

### Port Scanning

Network reconnaissance was simulated using Nmap.

Example command:

nmap -sS -p- <target-ip>

This activity generated logs which were analyzed by Wazuh.

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

Detected activities were mapped to the MITRE ATT&CK framework.

Examples:

Port Scanning  
T1046 – Network Service Discovery

Suspicious Command Execution  
T1059 – Command and Scripting Interpreter

Network Enumeration  
T1049 – System Network Connections Discovery

---

## Technologies Used

- Wazuh
- Sysmon
- Nmap
- Windows Event Logs
- MITRE ATT&CK Framework

---

## Results

This SOC lab demonstrates practical security monitoring and detection engineering skills including:

- Log analysis
- Threat detection
- Custom rule creation
- Security monitoring
- MITRE ATT&CK mapping
