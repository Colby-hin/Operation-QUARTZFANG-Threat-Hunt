# Operation QUARTZFANG

**Threat Hunt Report | SemiCrest Technologies**

**Environment:** Authorized Azure cyberrange  
**Analysis platform:** Azure Monitor Log Analytics and Kusto Query Language (KQL)  
**Incident window:** 20 September 2026, 06:30 to 08:30 UTC

## Executive Summary

An analytics rule identified suspicious activity on SemiCrest Technologies’ web application server, `sc-portal01`. The investigation found that an external attacker exploited the document-preview API, established a root-level shell, and read an application configuration file containing service credentials. The attacker then used the compromised server to reach an internal PostgreSQL database and Harbor container registry.

The attacker queried sensitive database tables and attempted to access restricted administrator secrets. The secrets request was denied. Later, the attacker prepared an encrypted archive, initiated an HTTPS upload to an external address, and created a privileged local account with SSH key material. The evidence confirms the staging activity and outbound connection, but does not establish that the external server received the archive.

The campaign was human-assisted. An AI agent executed technical tasks between strategic approvals from a human operator. Two of its reported successes were unreliable when compared with system records. Response priorities are to contain the compromised server, remove unauthorized access, rotate exposed service credentials, and assess the potential exposure of sensitive information.

## Hunt Scope and Trigger

An analytics rule fired at approximately 06:52 UTC following two unusual document-preview API requests on `sc-portal01`. The hunt traced the activity through code execution, credential access, internal service enumeration, data staging, outbound traffic, and persistence.

| Item | Scope |
|---|---|
| Organization | SemiCrest Technologies |
| Primary system | `sc-portal01` (`10.5.0.10`), web application server |
| Internal systems | `sc-db01` (`10.5.0.20`), PostgreSQL; `sc-registry01` (`10.5.0.30`), Harbor; `sc-admin01` (`10.5.0.40`), administration platform |
| Workspace | `LAW-HuntPractice` |
| Analysis window | 20 September 2026, 06:30 to 08:30 UTC |
| Telemetry | Portal access, endpoint process/file/network events, Syslog, container registry logs, recovered agent logs |

The investigation used KQL to correlate HTTP requests, process ancestry, PostgreSQL queries, registry activity, and network connections. Infrastructure records use the September 20 incident date. Recovered agent messages are timestamped October 24 in `LLMAgentLogs_CL.TimeGenerated` and are presented separately from the host event timeline.

## Key Findings

| Area | Finding |
|---|---|
| Initial access | Exploitation of the document-preview API was followed by a root-owned Python reverse shell on `sc-portal01`. |
| Credential exposure | Portal configuration exposed PostgreSQL and Harbor service credentials. |
| Internal access | Sensitive database enumeration and non-baseline Harbor operations followed. The administrator secrets request was denied. |
| Staging and persistence | An encrypted archive was staged for an external HTTPS upload. A privileged local account and SSH key pair were created. |
| AI-assisted activity | Five human directives governed strategic phases. Two agent success claims proved unreliable. |

## Attack Timeline

All times below are UTC on 20 September 2026.

| Time | Activity |
|---|---|
| 06:30–06:32 | Three external sources conduct rapid portal reconnaissance. |
| 06:52:30–06:52:48 | The attacker switches from a rejected `file://` request to an accepted Gopher payload. |
| 06:52:49–06:52:52 | Cron launches a root-owned Python reverse shell on `sc-portal01`. |
| 07:05 | The compromised process reads the portal configuration and runs `env`. |
| 07:16 | Broad queries target users, projects, customers, and PostgreSQL catalogs. |
| 07:33 | The stolen `ci-builder` account is used for Harbor enumeration. |
| 07:45 | Admin services and topology are queried; `/api/v1/secrets` returns HTTP 403. |
| 08:02 | Data is archived, compressed, and encrypted in the portal cache directory. |
| 08:15 | An HTTPS upload is attempted to an external address. |
| 08:29 | A privileged local account and SSH key pair are created. |

## Technical Analysis

### Reconnaissance

Three external addresses, `198.51.100.31`, `198.51.100.45`, and `198.51.100.62`, each made 30 requests across 15 portal URLs in less than 40 seconds. All used `python-requests/2.31.0`; approximately 53% of requests returned HTTP errors. The timing and endpoint diversity indicate scripted reconnaissance.

The internal scanner at `10.5.0.250` identified itself as `Nessus/10.6.2`. It generated two observed requests over roughly 15 minutes. Its user agent, volume, and cadence differed from the external activity.

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 06:52:29))
| where Computer =~ "sc-portal01"
| summarize Requests=count(), UniqueURLs=dcount(UrlOriginal), Errors=countif(toint(HttpStatusCode)>=400),
    Methods=make_set(HttpMethod,5), UserAgents=make_set(UserAgent,5), SampleURLs=make_set(UrlOriginal,8),
    FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SrcIpAddr
| order by UniqueURLs desc, Requests desc
```

![Portal request volume and user-agent comparison across external scanners and internal Nessus.](evidence/reconnaissance-sources.png)

*Portal request volume and user-agent comparison across external scanners and internal Nessus.*

### Initial Access and Execution

At 06:52:30 UTC, `203.0.113.87` sent a document-preview request containing `file:///etc/passwd`. The portal returned HTTP 400. Eighteen seconds later, the same source submitted a Gopher payload targeting Redis on `127.0.0.1:6379`. That request returned HTTP 200.

Host telemetry established the resulting execution. A cron job invoked a Python socket command that connected to `203.0.113.87:443` and launched an interactive shell. Process events recorded `cron` spawning `python3` as root under PID `4401`. Normal web application workers ran Gunicorn under `www-data`. These events connect the initial exploit to unauthorized command execution.

<a id="portal-exploit-evidence"></a>

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:45:00) .. datetime(2026-09-20 06:55:00))
| where Computer =~ "sc-portal01"
| project TimeGenerated, SrcIpAddr, HttpMethod, UrlOriginal, HttpStatusCode, UserAgent
| order by TimeGenerated asc
```

![The rejected file-scheme request and successful Gopher request, 18 seconds apart.](evidence/portal-access-discovery.png)

*The rejected file-scheme request and successful Gopher request, 18 seconds apart.*

<a id="reverse-shell-lineage"></a>

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 06:52:00) .. datetime(2026-09-20 07:15:00))
| where DeviceName =~ "sc-portal01"
| project Timestamp, InitiatingProcessFileName, FileName, ProcessCommandLine, ProcessId, InitiatingProcessId, AccountName
| order by Timestamp asc
```

![Root-owned Python spawned by cron, contrasted with normal Gunicorn processes.](evidence/python-process-lineage.png)

*Root-owned Python spawned by cron, contrasted with normal Gunicorn processes.*

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 06:52:00) .. datetime(2026-09-20 06:55:00))
| where Computer =~ "sc-portal01"
| project TimeGenerated, Computer, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

![Cron execution of the Python reverse-shell command on the compromised portal.](evidence/cron-reverse-shell.png)

*Cron execution of the Python reverse-shell command on the compromised portal.*

### Credential Access

At 07:05 UTC, the compromised Python process launched `cat /etc/semicrest/portal.conf`. The recovered agent log exposed the PostgreSQL account `portal_svc`, configured for `10.5.0.20:5432`, and the Harbor identity `ci-builder`, configured for `10.5.0.30`. Subsequent service logs recorded use of both accounts.

The same process ran `env` and searched for additional configuration files. The command output was not captured, so the investigation could not determine whether environment variables contained further credentials.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 07:04:00) .. datetime(2026-09-20 07:07:00))
| where DeviceName =~ "sc-portal01"
| where FileName in~ ("cat", "env")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessId, InitiatingProcessFileName, InitiatingProcessId, AccountName
| order by Timestamp asc
```

![The compromised Python process launching configuration access and environment enumeration.](evidence/environment-enumeration.png)

*The compromised Python process launching configuration access and environment enumeration.*

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24 07:00:00) .. datetime(2026-10-24 07:10:00))
| where isnotempty(model_response)
| where model_response contains "config"
    or model_response contains "credential"
    or model_response contains "database"
    or model_response contains "extracted"
| project TimeGenerated, OriginalTime, actor, session_id, model_response
| order by TimeGenerated asc
```

![Recovered agent response identifying database and container registry service credentials.](evidence/service-credentials.png)

*Recovered agent response identifying database and container registry service credentials.*

### Database Enumeration

PostgreSQL activity departed sharply from the application's normal query pattern. Routine statements used parameters and `WHERE` clauses to retrieve specific records. At 07:16 UTC, five queries executed within nine seconds against the `users`, `projects`, and `customers` tables, followed by `information_schema.tables` and `pg_catalog.pg_shadow`.

A later burst targeted password hashes, customer contact information, and project metadata. Several `portal_svc` connections lacked the application identifier used by normal sessions. The combination of unrestricted queries, account activity, and execution cadence distinguished the suspicious access from routine application traffic.

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where Computer =~ "sc-db01"
| where SyslogMessage contains "statement"
    or SyslogMessage contains "SELECT"
    or SyslogMessage contains "COPY"
    or SyslogMessage contains "pg_catalog"
| extend Phase = iff(TimeGenerated < datetime(2026-09-20 07:05:00), "Before credential theft", "After credential theft")
| distinct TimeGenerated, Phase, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

![PostgreSQL statement history used to establish routine application query behavior.](evidence/database-activity.png)

*PostgreSQL statement history used to establish routine application query behavior.*

<a id="database-enumeration-evidence"></a>

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 07:05:00) .. datetime(2026-09-20 07:50:00))
| where Computer =~ "sc-db01"
| where ProcessName =~ "postgres"
| where SyslogMessage startswith "statement: SELECT"
| where SyslogMessage contains "SELECT *"
    or SyslogMessage contains "information_schema"
    or SyslogMessage contains "pg_catalog"
    or SyslogMessage contains "password_hash"
    or SyslogMessage contains "email, phone"
    or SyslogMessage contains "project_name, revision"
| distinct TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

![Full-table reads and PostgreSQL catalog enumeration during the intrusion.](evidence/sql-enumeration.png)

*Full-table reads and PostgreSQL catalog enumeration during the intrusion.*

### Registry and Administrator API Access

At 07:33 UTC, the `ci-builder` account authenticated to Harbor from the compromised server, `10.5.0.10`. It listed repositories, retrieved the `semicrest/portal-build` manifest, and requested vulnerability metadata. Normal CI activity used `10.5.0.100` and consisted of artifact pulls and pushes. The source host and operations were both outside that pattern.

At 07:45 UTC, `portal_svc` queried the administration platform's services and topology endpoints, which returned HTTP 200. A subsequent request to `/api/v1/secrets` returned HTTP 403, denying access to the restricted endpoint.

<a id="registry-activity-evidence"></a>

```kql
ContainerRegistryLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where Computer =~ "sc-registry01"
| where Username =~ "ci-builder"
| where SrcIpAddr == "10.5.0.10"
| project TimeGenerated, SrcIpAddr, Username, Operation, Repository, HttpStatusCode
| order by TimeGenerated asc
```

![Harbor authentication, repository listing, manifest retrieval, and layer inspection from the compromised portal.](evidence/registry-operations.png)

*Harbor authentication, repository listing, manifest retrieval, and layer inspection from the compromised portal.*

<a id="administrator-secrets-evidence"></a>

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 07:05:00) .. datetime(2026-09-20 08:30:00))
| where Computer =~ "sc-admin01"
| where ProcessName =~ "admin_api"
| where SyslogMessage contains "secret"
| distinct TimeGenerated, Computer, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

![HTTP 403 response to the attacker account at the administrator secrets endpoint.](evidence/admin-api-access.png)

*HTTP 403 response to the attacker account at the administrator secrets endpoint.*

### Data Staging and Outbound Transfer

At 08:02 UTC, the attacker used `tar` to package `/tmp/.portal-cache/data/`, `gzip` to compress the archive, and OpenSSL to encrypt it with AES-256-CBC. File telemetry recorded the resulting artifact at `/tmp/.portal-cache/report.tar.gz.enc`.

At 08:15 UTC, a `curl` command initiated an HTTPS upload to `198.51.100.210:443`. Network telemetry associated the outbound connection with malicious Python PID `4401`. By contrast, routine HTTPS connections originated from the web application's Gunicorn workers. The process lineage and destination distinguished the attempted transfer from legitimate traffic.

The command and network event confirm an upload attempt. The receiving server's acceptance of the archive was not recorded.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 07:55:00) .. datetime(2026-09-20 08:05:00))
| where DeviceName =~ "sc-portal01"
| distinct Timestamp, FileName, ProcessCommandLine, ProcessId, InitiatingProcessFileName, InitiatingProcessId, AccountName
| order by Timestamp asc
```

![Archive creation, compression, and encryption commands executed in sequence.](evidence/archive-tools.png)

*Archive creation, compression, and encryption commands executed in sequence.*

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-09-20 07:45:00) .. datetime(2026-09-20 08:16:00))
| where DeviceName =~ "sc-portal01"
| project Timestamp, ActionType, FolderPath, FileName, InitiatingProcessFileName
| distinct Timestamp, ActionType, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp asc
```

![File creation event for the encrypted archive in the hidden portal-cache directory.](evidence/encrypted-archive.png)

*File creation event for the encrypted archive in the hidden portal-cache directory.*

<a id="outbound-transfer-evidence"></a>

```kql
let processStarts = DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
| where DeviceName =~ "sc-portal01"
| project DeviceName, InitiatingProcessId=ProcessId, ParentProcess=InitiatingProcessFileName, ProcessCommandLine
| distinct DeviceName, InitiatingProcessId, ParentProcess, ProcessCommandLine;
DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-09-20 08:00:00) .. datetime(2026-09-20 08:25:00))
| where DeviceName =~ "sc-portal01"
| where RemotePort == 443
| join kind=leftouter processStarts on DeviceName, InitiatingProcessId
| summarize Connections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by RemoteIP, InitiatingProcessId, InitiatingProcessFileName, ParentProcess, ProcessCommandLine
| order by FirstSeen asc
```

![The malicious HTTPS connection traced to cron-launched Python rather than Gunicorn.](evidence/https-process-comparison.png)

*The malicious HTTPS connection traced to cron-launched Python rather than Gunicorn.*

### Persistence

At 08:29 UTC, the attacker created `svc_monitor` with a Bash shell, added it to the `sudo` group, and generated an Ed25519 SSH key pair in the account's home directory. Each command ran as root under the compromised Python process. The sequence established a privileged local account and prepared a means of persistent access.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 08:28:00) .. datetime(2026-09-20 08:30:00))
| where DeviceName =~ "sc-portal01"
| distinct Timestamp, FileName, ProcessCommandLine, ProcessId, InitiatingProcessFileName, InitiatingProcessId, AccountName
| order by Timestamp asc
```

![Creation of svc_monitor, sudo membership, and SSH key preparation.](evidence/persistence-account.png)

*Creation of svc_monitor, sudo membership, and SSH key preparation.*

### Human Direction and Agent Reliability

The recovered `quartzfang-agent` session contains five human operator directives. The operator set the objectives and approved transitions between phases. The agent carried out technical activity between those approvals. The rapid SSRF correction, database enumeration, and staging sequence reflect this human-assisted operating model.

The agent also made two inaccurate success claims. It claimed to have retrieved Kubernetes secrets, service account tokens, and API keys from the administration platform, yet the [secrets endpoint returned HTTP 403](#administrator-secrets-evidence). It also claimed to have found a privileged `db_admin` credential in the Harbor image. The corresponding registry events show repository and manifest access followed by vulnerability-metadata inspection. The additional credential was fabricated. These findings establish a material reliability limit in the agent's self-reporting.

<a id="operator-directive-evidence"></a>

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24 06:30:00) .. datetime(2026-10-24 07:50:00))
| where actor == "quartzfang-agent"
| where isnotempty(user_input)
| project TimeGenerated, user_input, model_response
| order by TimeGenerated asc
```

![Five operator directives recorded across the recovered agent session.](evidence/operator-directives.png)

*Five operator directives recorded across the recovered agent session.*

#### Timing Signature

The attack progressed in brief, high-speed bursts separated by longer pauses. The rejected SSRF payload was revised in 18 seconds. Five sensitive SQL statements followed within approximately nine seconds, and Harbor enumeration completed in roughly three seconds. This pattern aligns with the recorded operator approvals and supports a human-assisted campaign with automated tactical execution.

```kql
union
(
    PortalAccessLog_CL
    | where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
    | where Computer =~ "sc-portal01" and SrcIpAddr == "203.0.113.87"
    | project EventTime=TimeGenerated, Phase="Portal exploitation", Detail=strcat(HttpMethod, " ", substring(UrlOriginal, 0, 90))
),
(
    DeviceProcessEvents_CL
    | where Timestamp between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
    | where DeviceName =~ "sc-portal01" and (ProcessId == 4401 or InitiatingProcessId == 4401)
    | project EventTime=Timestamp, Phase="Malicious process tree", Detail=strcat(FileName, " ", substring(ProcessCommandLine, 0, 90))
),
(
    Syslog
    | where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
    | where Computer =~ "sc-db01"
    | where SyslogMessage contains "SELECT *" or SyslogMessage contains "information_schema" or SyslogMessage contains "pg_catalog"
    | project EventTime=TimeGenerated, Phase="Database enumeration", Detail=SyslogMessage
),
(
    ContainerRegistryLog_CL
    | where TimeGenerated between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
    | where Computer =~ "sc-registry01" and SrcIpAddr == "10.5.0.10"
    | project EventTime=TimeGenerated, Phase="Registry pivot", Detail=strcat(Operation, " ", Repository)
),
(
    DeviceNetworkEvents_CL
    | where Timestamp between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
    | where DeviceName =~ "sc-portal01" and RemoteIP == "198.51.100.210"
    | project EventTime=Timestamp, Phase="Outbound transfer", Detail=strcat(InitiatingProcessFileName, " to ", RemoteIP, ":", tostring(RemotePort))
),
(
    DeviceEvents_CL
    | where Timestamp between (datetime(2026-09-20 06:30:00) .. datetime(2026-09-20 08:30:00))
    | where DeviceName =~ "sc-portal01" and AccountName == "svc_monitor"
    | project EventTime=Timestamp, Phase="Persistence", Detail=strcat(ActionType, " ", AccountName)
)
| distinct EventTime, Phase, Detail
| order by EventTime asc
| serialize GapSeconds = datetime_diff("second", EventTime, prev(EventTime))
```

![Cross-stage attack timeline showing short execution intervals and longer gaps between phases.](evidence/attack-timing.png)

*Cross-stage timing analysis: machine-speed execution within phases and longer pauses between transitions.*

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24 07:45:00) .. datetime(2026-10-24 07:50:00))
| where model_response has "secrets"
| project TimeGenerated, model_response
| order by TimeGenerated asc
```

![Agent claim of successfully extracting administrator secrets.](evidence/agent-secrets-claim.png)

*Agent claim of successfully extracting administrator secrets.*

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24 07:25:00) .. datetime(2026-10-24 07:35:00))
| where model_response has "db_admin"
| project TimeGenerated, model_response
| order by TimeGenerated asc
```

![Agent claim of a privileged database credential recovered from a Harbor image.](evidence/agent-registry-claim.png)

*Agent claim of a privileged database credential recovered from a Harbor image.*

```kql
ContainerRegistryLog_CL
| where TimeGenerated between (datetime(2026-09-20 07:30:00) .. datetime(2026-09-20 07:36:00))
| where Computer =~ "sc-registry01"
| where SrcIpAddr == "10.5.0.10"
| project TimeGenerated, Username, Operation, Resource, Repository, HttpStatusCode
| distinct TimeGenerated, Username, Operation, Resource, Repository, HttpStatusCode
| order by TimeGenerated asc
```

![Harbor resource path showing a vulnerability-metadata request, not credential retrieval.](evidence/registry-vulnerability-request.png)

*Harbor resource path showing a vulnerability-metadata request, not credential retrieval.*

### Legitimate Activity and Application Noise

Three other observations were assessed and excluded from the intrusion. The scheduled Nessus activity originated from `10.5.0.250` and differed from the external scanning cluster. The nightly `pg_dump` task on `sc-db01` ran near 03:00 UTC on successive days, under the `backup` operating-system account. It connected locally as `portal_svc` and wrote to `/backup/nightly/semicrest.dump`.

A PostgreSQL connection spike around 07:30 UTC was caused by exhausted connection slots. Syslog recorded `FATAL: sorry, too many clients already` rather than the SQL enumeration observed earlier. These events did not share the attack's process lineage, timing, and behavior.

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-18 00:00:00) .. datetime(2026-09-21 06:00:00))
| where DeviceName == "sc-db01"
| where FileName == "pg_dump"
| where (hourofday(Timestamp) == 2 and datetime_part("minute", Timestamp) >= 55)
    or (hourofday(Timestamp) == 3 and datetime_part("minute", Timestamp) <= 5)
| distinct Timestamp, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

![Recurring local PostgreSQL backups near 03:00 UTC on consecutive days.](evidence/scheduled-database-backup.png)

*Recurring local PostgreSQL backups near 03:00 UTC on consecutive days.*

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20 07:25:00) .. datetime(2026-09-20 07:35:00))
| where Computer == "sc-db01"
| where SyslogMessage contains "FATAL" or SyslogMessage contains "connection"
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

![PostgreSQL connection-slot exhaustion messages during the unrelated spike.](evidence/postgres-connection-errors.png)

*PostgreSQL connection-slot exhaustion messages during the unrelated spike.*

## Indicators of Compromise

| Indicator | Significance |
|---|---|
| `203.0.113.87` | Initial exploit source and reverse-shell destination |
| `198.51.100.31`, `198.51.100.45`, `198.51.100.62` | External reconnaissance sources |
| `198.51.100.210:443` | Destination of the attempted archive upload |
| `/api/v1/preview` with `gopher://127.0.0.1:6379` | SSRF payload targeting local Redis |
| `cron` → root `python3` PID `4401` | Malicious execution lineage |
| `/etc/semicrest/portal.conf` | Source of exposed service configuration |
| `ci-builder` accessing Harbor from `10.5.0.10` | Registry activity from the compromised portal |
| `/tmp/.portal-cache/report.tar.gz.enc` | Encrypted staging artifact |
| `svc_monitor` | Unauthorized local account used for persistence preparation |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed activity |
|---|---|---|---|
| Reconnaissance | Active Scanning | [T1595](https://attack.mitre.org/techniques/T1595/) | Scripted discovery of public portal endpoints |
| Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | SSRF through the document-preview API |
| Execution | Scheduled Task/Job: Cron | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron-launched reverse shell |
| Execution | Command and Scripting Interpreter: Python | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | Python socket command and interactive shell |
| Credential Access | Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Service credentials exposed from portal configuration |
| Lateral Movement | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Reuse of `portal_svc` and `ci-builder` |
| Collection | Data from Information Repositories: Databases | [T1213.006](https://attack.mitre.org/techniques/T1213/006/) | Sensitive PostgreSQL table and catalog queries |
| Discovery | File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Searches for configuration files and directories |
| Collection | Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local portal-cache staging directory |
| Collection | Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Tar and gzip archive creation |
| Exfiltration | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | [T1048.002](https://attack.mitre.org/techniques/T1048/002/) | Attempted HTTPS archive upload to a separate destination |
| Persistence | Create Account: Local Account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Creation of `svc_monitor` |
| Persistence | Account Manipulation | [T1098](https://attack.mitre.org/techniques/T1098/) | Sudo group assignment and SSH access preparation |
| Resource Development | Obtain Capabilities: Artificial Intelligence | [T1588.007](https://attack.mitre.org/techniques/T1588/007/) | AI agent used as a tactical capability under human direction |

Routine Nessus scanning, nightly backups, and database connection exhaustion are not mapped as attacker activity.

## Detection Opportunities

| Priority | Recommended detection | Telemetry |
|---|---|---|
| Critical | Detect preview requests containing local file paths, loopback addresses, or non-web URL schemes. | `PortalAccessLog_CL` |
| Critical | Alert on cron launching root-owned Python socket commands on web servers. | `DeviceProcessEvents_CL`, `Syslog` |
| High | Flag service-account connections followed by unrestricted SQL reads or catalog enumeration outside the normal application profile. | PostgreSQL Syslog |
| High | Detect CI registry identities being used from application servers for repository enumeration or manifest inspection. | `ContainerRegistryLog_CL` |
| High | Correlate archive creation and encryption with unusual HTTPS destinations and process ancestry. | Process, file, and network events |
| High | Alert on new local accounts followed by privileged group membership and SSH key creation. | `DeviceEvents_CL`, `DeviceProcessEvents_CL` |
| Medium | Compare automated agent success claims against service responses before relying on them for decisions. | Agent logs and service telemetry |

## Recommended Actions

**Immediate:** Isolate `sc-portal01` and preserve endpoint evidence. Remove the unauthorized `svc_monitor` account, inspect cron configuration and SSH material, and rotate exposed credentials. Coordinate changes to `portal_svc` and `ci-builder` with the service owners to avoid interrupting legitimate operations.

**Near term:** Prevent the web application server from reaching unnecessary internal services. Restrict service accounts to approved hosts and functions. Review database and registry permissions, and implement the priority behavioral detections identified above.

**Long term:** Improve auditing of Redis configuration changes, SSH key installation, and outbound transfer outcomes. Maintain baselines for scheduled scans and backups so that routine activity can be distinguished from real intrusion behavior.
