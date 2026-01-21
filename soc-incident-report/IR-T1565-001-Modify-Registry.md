# 🚨 Incident Report  
## Stored Data Manipulation – Modify Registry

---

## 1. Incident Summary

| Item | Value |
|---|---|
| MITRE Technique | Stored Data Manipulation – Modify Registry |
| MITRE ID | T1565.001 |
| Rule ID | Y1112 |
| Severity Level | 5 |
| Detection Time | __________________ |
| Detected By | Wazuh SIEM |

**Description:**  
A security alert was generated after detecting a Windows Registry modification that may indicate malicious activity such as persistence, defense evasion, or system configuration tampering.

---

## 2. Detection Rule Information

```yaml
rule.id: Y1112
rule.level: 5
rule.mitre.technique: Stored Data Manipulation – Modify Registry
rule.mitre.id: T1565.001
```
## 3. Affected Asset Information

- **Hostname:** window10
  - Wazuh field: `agent.name`

- **Agent ID:** 001  
  - Wazuh field: `agent.id`

- **Operating System:** window10  
  - Wazuh field: `agent.os.name`

- **IP Address:** 192.168.100.20  
  - Wazuh field: `agent.ip`

---

## 4. Registry Modification Details

- **Registry Key Path:** __________________  
  - Wazuh field: `syscheck.path`

- **Registry Action:** modified  
  - Wazuh field: `syscheck.event`

- **Registry Value (if available):** __________________  
  - Wazuh field: `syscheck.value_name`

- **Windows Event Channel:** __________________  
  - Wazuh field: `win.system.channel`


> Common Event IDs related to registry modification:
> - `4657` – Registry value modification  
> - `4663` – Registry object access  

---

## 5. Process & Execution Context

> Note: This alert was generated from registry monitoring (FIM).  
> Process execution details were not available in the current telemetry.

- **Process Information:** Not available  
- **Reason:** Registry modification detected via Wazuh FIM (syscheck), which does not include process execution context by default.

- **Relevant Decoder:** __________________  
  - Wazuh field: `decoder.name`

- **Raw Log Reference:**  
  - Wazuh field: `full_log`


---

## 6. Analysis

**Observed Behavior:**  
______________________________________

**Why This Is Suspicious:**
- Registry modification detected without clear legitimate reason
- Registry path commonly abused for persistence or system manipulation
- Activity aligns with MITRE ATT&CK technique T1565.001

**Analyst Confidence Level:**  
- ☐ Low  
- ☐ Medium  
- ☐ High  

---

## 7. Response Actions

- ☐ Alert triage performed  
- ☐ Registry change validated  
- ☐ Endpoint isolated  
- ☐ Malicious process terminated  
- ☐ Registry value restored  

---

## 8. Recommendations

- Enable registry integrity monitoring
- Limit registry modification privileges
- Correlate registry events with process creation logs
- Review and tune detection rules for high-risk registry paths

---

## 9. Evidence

- Screenshot of Wazuh alert  
- Screenshot of raw Windows event log  

<!-- INSERT EVIDENCE IMAGES HERE -->
