# TEMP.Hex Threat Hunting Lab

## Overview

Campaign-inspired threat hunting project based on TEMP.Hex/SOGU tradecraft.

## ATT&CK Coverage

T1091
T1059.003
T1059.001
T1082
T1033
T1074.001
T1071.001

# Appendix A — Lab Setup

## Environment

For this simulation, Windows 11 was used as the test environment.

---

## Step 1 — Download Sysmon

Download Sysmon from Microsoft Sysinternals:

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Step 2 — Download Sysmon Configuration

Download the SwiftOnSecurity Sysmon configuration:

https://github.com/SwiftOnSecurity/sysmon-config

---

## Step 3 — Install Sysmon

Open **Command Prompt as Administrator** and execute:

```cmd
/path/to/sysmon/folder/Sysmon64.exe -accepteula -i /path/to/sysmon-config-master/folder/sysmonconfig-export.xml
```

Example:

```cmd
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

---

## Step 4 — Verify Sysmon Service

Run:

```cmd
sc query Sysmon
```

Expected Output:

```text
STATE : 4 RUNNING
```

This confirms the Sysmon service is installed and actively collecting telemetry.

---

## Step 5 — Verify Sysmon Log Availability

Open **PowerShell as Administrator** and run:

```powershell
Get-WinEvent -ListLog *sysmon*
```

Expected Output:

```text
Microsoft-Windows-Sysmon/Operational
```

This confirms that Sysmon logging is available through Windows Event Logs.

---

## Step 6 — Verify Events Are Being Generated

Open:

```text
Event Viewer
│
└── Applications and Services Logs
    └── Microsoft
        └── Windows
            └── Sysmon
                └── Operational
```

This log contains all Sysmon-generated events.

Examples include:

| Event ID | Description        |
| -------- | ------------------ |
| 1        | Process Create     |
| 3        | Network Connection |
| 11       | File Create        |
| 13       | Registry Value Set |
| 22       | DNS Query          |

These events form the primary telemetry source used throughout this threat hunting project.

---

## Validation Screenshot

The following screenshot demonstrates:

* Sysmon installation
* Sysmon service running
* Sysmon log availability
* Event ID 1 Process Create telemetry
* Execution from the simulated removable-media staging directory


## Lab Stages

Stage 1
USB Execution

Stage 2
Discovery, Staging and Network Activity

Stage 3
Beaconing and Command & Control

Stage 4
Persistence (Coming Soon)
