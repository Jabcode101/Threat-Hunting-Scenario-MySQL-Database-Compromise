# Threat Hunting Scenario — MySQL Database Compromise

# Threat Hunt Report: Unauthorized MySQL Access and Destructive Activity

**Investigated asset:** `corp-wdds-f332a`  
**Incident window:** August 23, 2026, 18:00:00–18:40:00 UTC  
**Assessment:** MySQL service compromise confirmed; compromise of the underlying Windows host was not established by the available telemetry.

[View the detailed investigation, KQL queries, and evidence screenshots](https://github.com/Jabcode101/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged

- Microsoft Azure Log Analytics / custom MySQL audit logs (`MySQLAudit_CL`)
- Microsoft Defender for Endpoint telemetry
- Kusto Query Language (KQL)
- MySQL audit and query activity
- Windows endpoint authentication, process, and network events

## Scenario

A MySQL service associated with `corp-wdds-f332a` showed suspicious authentication and SQL activity. The investigation examined whether unauthorized database access led to data access, destructive operations, log-related changes, privilege modifications, and service disruption. It also checked Windows endpoint telemetry to assess whether the activity extended beyond the database service.

The investigation focused on source IP `64.89.163.139`. Separate Windows authentication activity involving `201.187.98.150` was reviewed, but a connection to the MySQL incident was not established.

### High-Level Investigation Plan

1. Examine `MySQLAudit_CL` for MySQL connection attempts and authentication outcomes.
2. Review SQL query activity for database enumeration and reads.
3. Identify ransom-related database creation and destructive SQL statements.
4. Review MySQL log operations, privilege changes, and shutdown activity.
5. Correlate Windows logons using `DeviceLogonEvents`.
6. Examine host process and network telemetry using `DeviceProcessEvents` and `DeviceNetworkEvents`.

All queries were scoped to **August 23, 2026, 18:00–18:40 UTC**. The custom MySQL table stores audit-event details in `RawData` rather than separate `DeviceName`, `ActionType`, and `Query` columns.

---

## Steps Taken

### 1. Investigated MySQL Authentication

Reviewed connection and authentication events in `MySQLAudit_CL`. The results included root authentication activity associated with `64.89.163.139`, including an access-denied event. MySQL connection IDs were also visible for correlating subsequent SQL activity.

<img width="1030" height="710" alt="MySQL authentication query and results" src="https://github.com/user-attachments/assets/4efcf3b0-86b3-4457-996b-9c817376a714" />

### 2. Investigated Database Access

Searched the audit records for `SELECT`, `SHOW`, `DESCRIBE`, and `USE` statements to examine database access and enumeration. These records support database-query activity, but do not by themselves establish external data exfiltration.

<img width="1149" height="661" alt="MySQL database access query and results" src="https://github.com/user-attachments/assets/8b99d341-80de-4114-b861-97dd79ca976b" />

### 3. Investigated Destructive SQL and Ransom-Related Activity

Searched for `CREATE DATABASE`, `DROP DATABASE`, `DROP TABLE`, and `TRUNCATE TABLE`. The investigation identified ransom-related database creation and destructive database operations.

<img width="982" height="723" alt="Destructive and ransom-related SQL query results" src="https://github.com/user-attachments/assets/a0d79116-c37a-4cf7-ab6c-3885d3bd69f2" />

### 4. Investigated Log Operations, Privileges, and Shutdown

Reviewed audit events for commands including `RESET MASTER`, `PURGE BINARY LOGS`, `GRANT`, and `SHUTDOWN`. These operations were relevant to changes in MySQL log history, permissions, and service availability.

<img width="1038" height="666" alt="MySQL log operations, privileges, and shutdown results" src="https://github.com/user-attachments/assets/e9aa37e1-805c-4071-b2d6-39bbb9935ec0" />

### 5. Correlated Windows Authentication

Used `DeviceLogonEvents` to review the investigated host and both suspicious IP addresses. Authentication activity involving `201.187.98.150` was treated as a separate investigative lead, not attributed to the MySQL attacker without supporting correlation.

<img width="1214" height="731" alt="Windows authentication correlation results" src="https://github.com/user-attachments/assets/d75f1cd5-8bc8-4741-b938-02afc817ef71" />

### 6A. Examined Windows Process Activity

Used `DeviceProcessEvents` to inspect MySQL executables and command-shell processes during the incident window. The reviewed evidence did not establish that the attacker gained control of the Windows host.

<img width="1156" height="442" alt="Windows process activity results" src="https://github.com/user-attachments/assets/bb15c034-acd3-45b4-8421-24b2ff34195a" />

### 6B. Examined Windows Network Activity

Used `DeviceNetworkEvents` to look for connections involving `64.89.163.139`, `201.187.98.150`, or MySQL port `3306`. The output was limited to relevant timestamps, device, action, local and remote IPs, and ports.

<img width="1181" height="717" alt="Windows network activity results" src="https://github.com/user-attachments/assets/08ddda64-5c1d-4b31-b714-2e4eaacd5c7f" />

---

## Observed Activity Sequence

The table summarizes the activity documented in the investigation; it is not a minute-by-minute event timeline. Confirm exact event times and ordering against the original audit records.

| Sequence | Observed activity | Significance |
| --- | --- | --- |
| 1 | Suspicious MySQL root authentication associated with `64.89.163.139` | Initial database access under investigation |
| 2 | Database enumeration and read queries | Database contents accessed; exfiltration not independently confirmed |
| 3 | Ransom-related database creation | Extortion-related database activity |
| 4 | `DROP DATABASE` and other destructive SQL | Database integrity and availability impact |
| 5 | `RESET MASTER` / `PURGE` operations | Changes to MySQL log history |
| 6 | Privilege-related operations | Database authorization changes |
| 7 | MySQL shutdown | Service availability impact |
| 8 | Windows logon, process, and network correlation | Host compromise not established by the available telemetry |

## Indicators and Investigative Leads

| Indicator | Interpretation |
| --- | --- |
| `corp-wdds-f332a` | Investigated Windows asset associated with the MySQL service |
| `64.89.163.139` | IP associated with suspicious MySQL activity |
| `root` | MySQL account involved in suspicious authentication |
| `201.187.98.150` | Separate suspicious Windows authentication lead; relationship to the MySQL incident unconfirmed |
| `DROP DATABASE` | Destructive SQL operation |
| `RESET MASTER` / `PURGE` | MySQL log-related operations |

## Summary

The investigation confirmed unauthorized activity against the MySQL service associated with `corp-wdds-f332a`, including database access, destructive SQL, log-related operations, privilege changes, and shutdown. These findings raise confidentiality concerns and establish integrity and availability impacts. The available evidence did **not** establish confirmed data exfiltration or compromise of the underlying Windows operating system.

## Response and Follow-Up Recommendations

- Preserve the MySQL audit and relevant Windows endpoint records.
- Investigate the root-account access path and rotate potentially exposed database credentials.
- Validate database integrity and recover affected data from verified backups where appropriate.
- Review least-privilege permissions, MySQL remote access controls, and audit logging.
- Continue investigating the separate Windows authentication lead without assuming a connection to the database attack.

*These are recommendations, not a claim that each action was performed during the investigation.*

## Detailed Technical Report

The companion report contains the complete KQL for **Evidence 1–5, 6A, and 6B**, alongside the original embedded GitHub screenshot references:

**[Open the detailed MySQL threat hunt report](https://github.com/Jabcode101/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)**

## Author

- **Name:** Jacob Mutua
- **Professional profile:** www.linkedin.com/in/jacob-mutua-62w06a281

