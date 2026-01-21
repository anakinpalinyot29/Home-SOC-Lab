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

- **Hostname:** __________________  
  - Wazuh field: `agent.name`

- **Agent ID:** __________________  
  - Wazuh field: `agent.id`

- **Operating System:** __________________  
  - Wazuh field: `agent.os.name`

- **IP Address:** __________________  
  - Wazuh field: `agent.ip`

- **Logged-on User:** __________________  
  - Wazuh field: `data.win.eventdata.SubjectUserName`

---

## 4. Registry Modification Details

- **Registry Key Path:** __________________  
  - Wazuh field: `data.win.eventdata.TargetObject`

- **Registry Value Name:** __________________  
  - Wazuh field: `data.win.eventdata.ValueName`

- **Modified Value Data:** __________________  
  - Wazuh field: `data.win.eventdata.Details`

- **Windows Event ID:** __________________  
  - Wazuh field: `data.win.system.eventID`

> Common Event IDs related to registry modification:
> - `4657` – Registry value modification  
> - `4663` – Registry object access  

---

## 5. Process & Execution Context

- **Process Name:** __________________  
  - Wazuh field: `data.win.eventdata.ProcessName`

- **Process ID:** __________________  
  - Wazuh field: `data.win.eventdata.ProcessId`

- **Parent Process Name:** __________________  
  - Wazuh field: `data.win.eventdata.ParentProcessName`

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
