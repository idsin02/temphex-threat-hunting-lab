# TEMP.Hex Threat Hunting Lab — Stage 3: Beaconing and Command & Control Simulation

> ATT&CK: T1071.001, T1059.001, T1036, T1074.001, T1105
>
> Platform: Windows 11
>
> Telemetry Source: Sysmon
>
> Status: Completed ✅

---

# Executive Summary

Following successful simulation of execution, discovery, staging, and outbound communication in Stage 2, the hunt was expanded to emulate beaconing behavior commonly observed in malware and command-and-control (C2) frameworks.

A secondary PowerShell script was launched from the RECYCLER.BIN directory and configured to generate recurring outbound web requests at fixed intervals.

The objective of this hunt was to validate visibility into beacon-like communications, DNS activity, process lineage, and recurring network behavior frequently associated with post-compromise command-and-control activity.

---

# Attack Flow

```text
USB Execution
│
└── Removable Disk (57GB).bat
      │
      └── powershell.exe
            │
            └── beacon.ps1
                  │
                  ├── DNS Query
                  │
                  ├── HTTPS Connection
                  │
                  ├── Beacon Check-In #1
                  ├── Beacon Check-In #2
                  ├── Beacon Check-In #3
                  ├── Beacon Check-In #4
                  └── Beacon Check-In #5
```

---

# ATT&CK Mapping

| Technique | Name                                      |
| --------- | ----------------------------------------- |
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1059.001 | PowerShell                                |
| T1036     | Masquerading                              |
| T1074.001 | Local Data Staging                        |
| T1105     | Ingress Tool Transfer (Simulated)         |

---

# Hunt Objective

Detect recurring outbound communications and establish visibility into beacon-like behavior following suspicious execution.

---

# Hunt Hypothesis

An adversary may establish recurring communications with external infrastructure shortly after successful execution.

Beaconing activity may generate repeated DNS queries and outbound HTTPS traffic at predictable intervals.

---

# Lab Environment

| Component            | Value           |
| -------------------- | --------------- |
| Operating System     | Windows 11      |
| Telemetry            | Sysmon          |
| Investigation Tool   | Event Viewer    |
| Campaign Inspiration | TEMP.Hex / SOGU |

---

# Beacon Simulation

## File Structure

```text
C:\USB_Test\RECYCLER.BIN\

├── Removable Disk (57GB).bat
└── beacon.ps1
```

---

## Beacon Script

```powershell
$Log = "$env:TEMP\beacon_log.txt"

1..5 | ForEach-Object {

    "Beacon Check-In: $(Get-Date)" |
    Out-File $Log -Append

    Invoke-WebRequest `
        -Uri "https://example.com" `
        -UseBasicParsing |
        Out-Null

    Start-Sleep -Seconds 30
}
```

---

## Process Chain

```text
Removable Disk (57GB).bat
│
└── powershell.exe
      │
      └── beacon.ps1
            │
            ├── DNS Activity
            ├── HTTPS Traffic
            └── beacon_log.txt
```

---

# Investigation Questions

### Question 5

Did execution result in recurring network activity?

### Question 6

Was network activity tied to USB execution?

### Question 7

Did the process exhibit beaconing behavior?

---

# Investigation Findings

The original USB-based execution chain launched a secondary PowerShell process responsible for recurring outbound communications.

PowerShell executed:

```text
C:\USB_Test\RECYCLER.BIN\beacon.ps1
```

The script generated:

* Repeated HTTPS Requests
* DNS Queries
* Local Beacon Log Entries

Network activity occurred at predictable intervals and closely resembled beacon-like communications commonly associated with command-and-control frameworks.

---

# Evidence Collected

| Evidence         | Observation               |
| ---------------- | ------------------------- |
| Parent Process   | Removable Disk (57GB).bat |
| Child Process    | powershell.exe            |
| Script           | beacon.ps1                |
| DNS Activity     | example.com               |
| Network Activity | HTTPS                     |
| Destination Port | 443                       |
| Local Artifact   | beacon_log.txt            |
| ATT&CK Technique | T1071.001                 |

---

# Timeline

```text
USB Execution
│
├── Discovery Completed
│
├── powershell.exe Launched
│
├── beacon.ps1 Executed
│
├── DNS Query Observed
│
├── HTTPS Connection Established
│
├── Beacon Check-In #1
├── Beacon Check-In #2
├── Beacon Check-In #3
├── Beacon Check-In #4
└── Beacon Check-In #5
```

---

# Detection Opportunities

## Detection 1

PowerShell launched from RECYCLER.BIN

Severity: 🔴 High

---

## Detection 2

ExecutionPolicy Bypass observed

Severity: 🟡 Medium

---

## Detection 3

DNS query immediately followed by HTTPS communication

Severity: 🟡 Medium

---

## Detection 4

Repeated outbound communications from the same process

Severity: 🔴 High

---

## Detection 5

PowerShell script execution from removable-media-like staging directory

Severity: 🔴 High

---

# Hunt Result

The hunt successfully identified recurring outbound communications associated with a PowerShell-based beacon simulation.

Telemetry demonstrated visibility into:

* Process Creation
* DNS Queries
* HTTPS Communications
* Recurring Check-In Behavior

The resulting evidence supports detection opportunities focused on beaconing and command-and-control activity.

---

# Analyst Assessment

The observed behavior demonstrates a realistic transition from initial execution to command-and-control simulation.

PowerShell-generated beaconing produced recurring outbound communications and created telemetry consistent with activity frequently investigated during malware incidents.

While the simulation remained completely benign, the resulting artifacts and process lineage closely resemble behaviors associated with post-compromise beaconing frameworks.

This stage establishes the foundation for the final phase of the campaign simulation: persistence.

---

# Screenshots

## PowerShell Beacon Execution

PowerShell launched from RECYCLER.BIN and executed beacon.ps1.

<img width="803" height="328" alt="3 1" src="https://github.com/user-attachments/assets/93456f2d-b893-4980-8afb-67b35ec16b1a" />


---

## Network Connection Evidence

Sysmon Event ID 3 showing outbound HTTPS communication generated by the beacon process.

<img width="683" height="325" alt="3 2" src="https://github.com/user-attachments/assets/684a3fcf-7b8b-45b8-85d9-087375ae9985" />


## Curl on 30 sec delay


https://github.com/user-attachments/assets/b606d371-375b-4c51-af74-ab2cb06eb67d


## Beacon Logs

<img width="290" height="179" alt="beacon_logs" src="https://github.com/user-attachments/assets/b36de643-bf61-44f2-9045-0a8e985218e9" />


---

# Next Stage

➡️ Stage 4 — Persistence Simulation
