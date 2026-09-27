# Threat Hunt: MySQL Database Compromise and Destructive Activity

**Investigated asset:** `corp-wdds-f332a`  
**Investigation type:** MySQL service compromise, unauthorized database access, and destructive activity  
**Status:** MySQL compromise confirmed; underlying Windows host compromise not established by available telemetry.

**Evidence note:** The KQL below reflects the queries used for the portfolio evidence screenshots. The MySQL audit table stores event details in `RawData`; the Windows endpoint queries use Microsoft Defender telemetry. Interpret results alongside the screenshots and original logs.

---

## Threat Event

The investigation identified unauthorized access to a MySQL service associated with `corp-wdds-f332a`. Activity attributed to source IP `64.89.163.139` included suspicious root authentication, access to database contents, creation of a ransom-related database, destructive SQL commands, privilege changes, and a MySQL shutdown. The available evidence confirmed compromise of the **database service**; it did **not** independently establish that the attacker obtained control of the underlying Windows operating system.

## Investigation Timeframe

- **Date:** August 23, 2026
- **UTC window:** 18:00:00–18:40:00 (40 minutes)
- **Affected asset:** `corp-wdds-f332a`
- **Query scope:** The KQL below explicitly filters to this UTC window.

## Investigation Objectives

1. Establish the sequence of suspicious MySQL authentication and query activity.
2. Identify the source IPs, accounts, database operations, and destructive actions involved.
3. Correlate database evidence with Windows logon, process, and network telemetry.
4. Determine what was confirmed, what remained unverified, and the resulting confidentiality, integrity, and availability concerns.

---

## Observed Attacker Activity and Investigation Timeline

The following is a **sequence of observed activity**, not a timestamped reconstruction. Insert exact UTC timestamps from the original logs when adding evidence.

| Sequence | Observed activity | Investigative significance |
| --- | --- | --- |
| 1 | Suspicious MySQL root authentication associated with `64.89.163.139` | Establishes the database access path under investigation. |
| 2 | Queries accessing database contents | Supports unauthorized access to data; the exact data accessed must be established from query logs. |
| 3 | Creation of a ransom-related database | Indicates an extortion-related action in the database service. |
| 4 | `DROP DATABASE` | Confirms destructive database activity. |
| 5 | `RESET MASTER` and/or `PURGE` log operations | Indicates attempts to alter or remove MySQL log history. |
| 6 | Privilege modifications | Shows changes to database access or authorization. |
| 7 | MySQL shutdown | Establishes an availability-impacting action against the service. |

### Evidence 1 — MySQL authentication and initial access

**Evidence:** MySQL authentication query and results, including the source IP, account, and timestamps.

<img width="1030" height="710" alt="image" src="https://github.com/user-attachments/assets/73fb9a99-c2ef-4690-9640-e87c259b0e57" />


**Finding:** Suspicious database authentication was associated with `64.89.163.139`. Preserve the original event timestamp and log fields in the screenshot.

### Evidence 2 — Database access and query activity

**Evidence:** Database read and enumeration query results.

<img width="1149" height="661" alt="image" src="https://github.com/user-attachments/assets/81588eb4-db2a-4b9c-8e85-2dfc3dc4c5fe" />


**Finding:** Database contents were queried. Do not claim confirmed exfiltration unless separate transfer evidence supports it.

### Evidence 3 — Ransom-related and destructive SQL activity

**Evidence:** Ransom-related database creation and destructive SQL query results.

<img width="982" height="723" alt="image" src="https://github.com/user-attachments/assets/2c56ae28-b9e2-40f8-9679-fa8f6bd1f278" />


**Finding:** The database service was used to perform destructive operations.

### Evidence 4 — Log manipulation, privileges, and shutdown

**Evidence:** MySQL log operations, privilege changes, and shutdown query results.

<img width="1038" height="666" alt="image" src="https://github.com/user-attachments/assets/de1c7190-69be-4409-9ce0-7cb75917c27b" />


**Finding:** These events document changes to logging, access permissions, and service availability.

---

## Tables Used to Investigate Indicators of Compromise

| Data source | Purpose |
| --- | --- |
| `MySQLAudit_CL` (`TimeGenerated`, `RawData`) | Review authentication, database reads, destructive statements, log operations, privilege changes, and shutdown. |
| `DeviceLogonEvents` | Check Windows authentication activity on the investigated host. |
| `DeviceProcessEvents` | Look for suspicious process execution and possible host-level follow-on activity. |
| `DeviceNetworkEvents` | Look for relevant network connections and correlate them with the database investigation. |

*The verified `MySQLAudit_CL` schema includes `TimeGenerated`, `RawData`, `TenantId`, `Type`, and `_ResourceId`. SQL and connection details appear within `RawData`.*

---

## Related KQL Queries and Evidence

The following queries use the verified MySQL audit schema and Microsoft Defender endpoint tables. All are scoped to August 23, 2026, 18:00–18:40 UTC. The screenshots below are preserved from the supplied README.

### Query 1 — MySQL authentication: suspicious source and root account

```kql
// Evidence 01: MySQL Authentication and Initial Access
// Investigation Window: August 23, 2026 | 18:00–18:40 UTC

MySQLAudit_CL
| where TimeGenerated between (
    datetime(2026-08-23 18:00:00) ..
    datetime(2026-08-23 18:40:00)
)
| where (RawData contains "Connect" or RawData contains "Access denied")
    and (RawData contains "64.89.163.139" or RawData contains "root")
| project TimeGenerated, RawData
| order by TimeGenerated asc
```

**Screenshot:** <img width="604" height="267" alt="image" src="https://github.com/user-attachments/assets/9ef00d5a-03fb-4ab2-aaac-2040146d9798" />

**What to show:** Query, timestamp, source IP `64.89.163.139`, account, and authentication result.

### Query 2 — MySQL query history: access to database contents

```kql
// Evidence 02: Database Enumeration and Query Activity

MySQLAudit_CL
| where TimeGenerated between (
    datetime(2026-08-23 18:00:00) ..
    datetime(2026-08-23 18:40:00)
)
| where RawData matches regex @"(?i)\b(SELECT|SHOW|DESCRIBE|USE)\b"
| project TimeGenerated, RawData
| order by TimeGenerated asc
```

**Screenshot:** <img width="610" height="198" alt="image" src="https://github.com/user-attachments/assets/46d62bfb-c766-4425-a1fd-0b2a6cfff4ae" />

**What to show:** The actual SQL operations and their timestamps.

### Query 3 — Destructive SQL and ransom-related activity

```kql
// Evidence 03: Ransom-Related and Destructive SQL
// August 23, 2026 | 18:00–18:40 UTC

MySQLAudit_CL
| where TimeGenerated between (
    datetime(2026-08-23 18:00:00) ..
    datetime(2026-08-23 18:40:00)
)
| where RawData matches regex @"(?i)\b(CREATE\s+DATABASE|DROP\s+DATABASE|DROP\s+TABLE|TRUNCATE\s+TABLE)\b"
| project TimeGenerated, RawData
| order by TimeGenerated asc
```

**Screenshot:** <img width="883" height="213" alt="image" src="https://github.com/user-attachments/assets/0f7501d5-f7c0-4881-ad1b-71b44ca465cd" />

**What to show:** SQL statement, database target (if visible), source/account context, and timestamp.

### Query 4 — MySQL log operations, privileges, and shutdown

```kql
// Evidence 04: Log Manipulation, Privilege Changes, and Shutdown
// August 23, 2026 | 18:00–18:40 UTC

MySQLAudit_CL
| where TimeGenerated between (
    datetime(2026-08-23 18:00:00) ..
    datetime(2026-08-23 18:40:00)
)
| where RawData matches regex @"(?i)\b(RESET\s+MASTER|PURGE\s+BINARY\s+LOGS|GRANT|REVOKE|ALTER\s+USER|SHUTDOWN)\b"
| project TimeGenerated, RawData
| order by TimeGenerated asc
```

**Screenshot:** <img width="1039" height="237" alt="image" src="https://github.com/user-attachments/assets/207ffc65-404c-4eda-bcf4-18f3f33972b4" />
 
**What to show:** Individual operations and chronological order.

### Query 5 — Windows logon correlation

```kql
// Evidence 05: Windows Authentication Correlation
// August 23, 2026 | 18:00–18:40 UTC

DeviceLogonEvents
| where Timestamp between (
    datetime(2026-08-23 18:00:00) ..
    datetime(2026-08-23 18:40:00)
)
| where DeviceName =~ "corp-wdds-f332a"
| where RemoteIP in ("64.89.163.139", "201.187.98.150")
| project
    Timestamp,
    DeviceName,
    ActionType,
    AccountName,
    LogonType,
    RemoteIP,
    FailureReason,
    IsLocalAdmin
| order by Timestamp asc
```

**Screenshot:** <img width="1214" height="731" alt="image" src="https://github.com/user-attachments/assets/bc8cfa02-974a-4d7f-8d2d-6d913fe5d355" />

**What to show:** Host `corp-wdds-f332a`, relevant source IPs, success/failure results, and timestamps.

**Separate finding:** `201.187.98.150` appeared in suspicious Windows authentication telemetry with failures and one success, but the evidence reviewed did not establish that it was connected to the MySQL attack.


### Query 6A — Windows Process Activity
```kql
// Evidence 06A: Windows Process Activity
// August 23, 2026 | 18:00–18:40 UTC

DeviceProcessEvents
| where Timestamp between (
    datetime(2026-08-23 18:00:00) ..
    datetime(2026-08-23 18:40:00)
)
| where DeviceName =~ "corp-wdds-f332a"
| where FileName in~ (
    "mysqld.exe",
    "mysql.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

**Purpose:** Investigate MySQL-related processes and command-shell execution on `corp-wdds-f332a` during the incident window.

**Screenshot:** <img width="1156" height="442" alt="image" src="https://github.com/user-attachments/assets/d93f742d-9ae6-4181-9a7d-fba9492e79fe" />

**Finding:** Review process execution and parent-child relationships for evidence of suspicious activity on the underlying Windows host. The available telemetry did not establish Windows host compromise.

### Query 6B — Windows Network Activity

```kql
// Evidence 06B: Windows Network Activity
// August 23, 2026 | 18:00–18:40 UTC

DeviceNetworkEvents
| where Timestamp between (
    datetime(2026-08-23 18:00:00) ..
    datetime(2026-08-23 18:40:00)
)
| where DeviceName =~ "corp-wdds-f332a"
| where RemoteIP in ("64.89.163.139", "201.187.98.150")
    or LocalPort == 3306
    or RemotePort == 3306
| project
    Timestamp,
    DeviceName,
    ActionType,
    LocalIP,
    LocalPort,
    RemoteIP,
    RemotePort
| order by Timestamp asc
```

**Screenshot:** <img width="1181" height="717" alt="image" src="https://github.com/user-attachments/assets/2640c92d-0379-4864-b3d1-825f19f038ff" />

**Additional network evidence:** <img width="1181" height="717" alt="Additional network evidence" src="https://github.com/user-attachments/assets/f342f967-0bbb-437a-a5ba-ac33f5f198b1" />


**Finding:** Network activity was investigated separately from the MySQL audit logs. The available evidence did not establish that the separate Windows authentication activity involving `201.187.98.150` was connected to the confirmed MySQL compromise.


---

## Indicators and Investigative Leads

| Indicator | Type | Interpretation |
| --- | --- | --- |
| `corp-wdds-f332a` | Investigated host | Windows system associated with the affected MySQL service. |
| `64.89.163.139` | Source IP | Associated with the suspicious MySQL activity investigated. |
| `201.187.98.150` | Source IP | Separate suspicious Windows authentication activity; not established as part of the MySQL incident. |
| `root` | MySQL account | Account involved in suspicious database authentication. |
| `DROP DATABASE` | SQL operation | Destructive database action. |
| `RESET MASTER` / `PURGE` | SQL operations | MySQL log-history alteration/removal operations. |

---

## Scope, Impact, and Assessment

| Security objective | Evidence-based assessment |
| --- | --- |
| **Confidentiality** | Unauthorized queries accessed database contents. The available summary does not establish a confirmed external data transfer. |
| **Integrity** | Destructive SQL and privilege changes affected database integrity and access controls. |
| **Availability** | Database deletion and MySQL shutdown affected service/data availability. |
| **Windows host compromise** | Not established by the available Defender evidence. |

**Conclusion:** The investigation confirmed compromise and misuse of the MySQL service associated with `corp-wdds-f332a`. The observed sequence included unauthorized database access, destructive commands, log-related operations, privilege changes, and service shutdown. The evidence does not justify describing the underlying Windows host as confirmed compromised, nor does it establish that the MySQL service was directly Internet-facing without separate firewall or network-configuration evidence.

## Recommended Response and Follow-Up

- Preserve MySQL authentication, query/audit, Windows logon, process, and network evidence.
- Review and rotate exposed database credentials and investigate how the root account was accessed.
- Restore affected data from verified backups where appropriate and validate database integrity.
- Review MySQL access controls, least privilege, remote access restrictions, and logging configuration.
- Investigate the separate Windows authentication activity without assuming it belongs to the same attack.
- Continue correlation with additional telemetry if host compromise or data exfiltration must be determined.

*These are recommended actions, not a claim that they were all performed during the lab.*

---

## Created By

- **Author Name:** Jacob Mutua
- **Author Contact:** www.linkedin.com/in/jacob-mutua-62w06a281
- **Incident Date:** August 23, 2026
- **Documentation Date:** August 23, 2026

## Validated By

- **Reviewer Name:** [If applicable]
- **Reviewer Contact:** [If applicable]
- **Validation Date:** [If applicable]

## Additional Notes

- This portfolio entry distinguishes confirmed database-service activity from unconfirmed host-level activity.
- Screenshot evidence is embedded alongside the corresponding KQL queries; avoid publishing credentials or other secrets.

## Revision History

| Version | Changes | Date | Modified By |
| --- | --- | --- | --- |
| 1.0 | Revised case study with verified schema, UTC-scoped KQL, and embedded evidence | September 26, 2026 | Jacob Mutua |

