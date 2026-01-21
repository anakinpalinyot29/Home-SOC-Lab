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
3. Affected Asset Information
| Item             | Value      | Wazuh Field                          |
| ---------------- | ---------- | ------------------------------------ |
| Hostname         | __________ | `agent.name`                         |
| Agent ID         | __________ | `agent.id`                           |
| Operating System | __________ | `agent.os.name`                      |
| IP Address       | __________ | `agent.ip`                           |
| Logged-on User   | __________ | `data.win.eventdata.SubjectUserName` |

