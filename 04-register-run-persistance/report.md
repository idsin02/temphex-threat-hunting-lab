# TEMP.Hex Threat Hunting Lab — Stage 4: Registry Run Key Persistence

> ATT&CK: T1547.001 - Registry Run Keys / Startup Folder
>
> Platform: Windows 11
>
> Telemetry Source: Sysmon
>
> Status: Completed ✅

---

# Executive Summary

Following successful simulation of USB execution, discovery activity, staging, beaconing, and outbound communications, the final stage of the campaign focused on persistence.

A PowerShell script was used to create a Registry Run Key designed to automatically launch a previously established beaconing script upon user logon.

The objective of this hunt was to validate visibility into Registry-based persistence mechanisms and confirm telemetry coverage for ATT&CK technique **T1547.001 – Registry Run Keys / Startup Folder**.

Sysmon successfully captured registry modification activity through Event ID 13, and registry inspection confirmed successful persistence creation.

---

# Attack Flow

```text
USB Execution
│
├── Discovery
│
├── Staging
│
├── Beaconing
│
└── Persistence
      │
      └── Registry Run Key
            │
            └── WindowsUpdateService
                  │
                  └── beacon.ps1
```

---

# ATT&CK Mapping

| Technique | Name                                      |
| --------- | ----------------------------------------- |
| T1547.001 | Registry Run Keys / Startup Folder        |
| T1059.001 | PowerShell                                |
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1036     | Masquerading                              |

---

# Hunt Objective

Detect Registry-based persistence established following execution of a suspicious payload.

---

# Hunt Hypothesis

An adversary may create Registry Run Keys to ensure malicious code executes automatically when a user logs on.

Successful creation of Registry-based persistence should generate registry modification telemetry and create artifacts that can be verified through registry inspection.

---

# Lab Environment

| Component            | Value           |
| -------------------- | --------------- |
| Operating System     | Windows 11      |
| Telemetry            | Sysmon          |
| Investigation Tool   | Event Viewer    |
| Campaign Inspiration | TEMP.Hex / SOGU |

---

# Persistence Simulation

## Persistence Script

```powershell
$RunPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

New-ItemProperty `
    -Path $RunPath `
    -Name "WindowsUpdateService" `
    -Value "powershell.exe -ExecutionPolicy Bypass -File C:\USB_Test\RECYCLER.BIN\beacon.ps1" `
    -PropertyType String `
    -Force
```

---

## Persistence Logic

```text
Registry Path:

HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Created Value:

```text
WindowsUpdateService
```

Configured Command:

```text
powershell.exe -ExecutionPolicy Bypass -File C:\USB_Test\RECYCLER.BIN\beacon.ps1
```

---

# Investigation Questions

### Question 1

Was persistence successfully established?

### Question 2

Was the Registry Run Key captured by Sysmon?

### Question 3

What process created the persistence mechanism?

### Question 4

What would occur during the next user logon?

---

# Investigation Findings

Sysmon Event ID 13 captured a Registry Value Set operation performed by PowerShell.

The registry modification created a Run Key named:

```text
WindowsUpdateService
```

under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

The Run Key was configured to automatically launch:

```text
powershell.exe -ExecutionPolicy Bypass -File C:\USB_Test\RECYCLER.BIN\beacon.ps1
```

Registry inspection confirmed successful persistence creation.

---

# Evidence Collected

| Evidence           | Observation                                        |
| ------------------ | -------------------------------------------------- |
| Event ID           | 13                                                 |
| Log Source         | Sysmon                                             |
| Technique          | T1547.001                                          |
| Process            | powershell.exe                                     |
| Registry Path      | HKCU\Software\Microsoft\Windows\CurrentVersion\Run |
| Registry Value     | WindowsUpdateService                               |
| Payload            | beacon.ps1                                         |
| Persistence Status | Verified                                           |

---

# Event ID 13 Evidence

## Registry Value Set

```text
Image:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

TargetObject:

HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateService

Details:

powershell.exe -ExecutionPolicy Bypass -File C:\USB_Test\RECYCLER.BIN\beacon.ps1
```

This event confirms successful creation of Registry-based persistence.

---

# Registry Verification

Registry contents were manually verified using:

```cmd
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Observed Result:

```text
WindowsUpdateService

REG_SZ

powershell.exe -ExecutionPolicy Bypass -File C:\USB_Test\RECYCLER.BIN\beacon.ps1
```

This confirms persistence was successfully established.

---

# Expected Post-Logon Behavior

A reboot was not required for this simulation.

The objective of the hunt was to validate persistence creation rather than observe execution after restart.

Based on the Registry Run Key configuration, the expected behavior during the next user logon would be:

```text
User Logon
│
├── Windows reads:
│   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
│
├── WindowsUpdateService detected
│
├── powershell.exe launched
│
└── beacon.ps1 executed automatically
```

The registry configuration itself provides sufficient evidence that the persistence mechanism would execute during a future logon event.

---

# Timeline

```text
Beacon Simulation Completed
│
├── persist.ps1 executed
│
├── Registry Run Key created
│
├── Sysmon Event ID 13 generated
│
├── Registry contents verified
│
└── Persistence confirmed
```

---

# Detection Opportunities

## Detection 1

Registry Run Key Creation

Severity: 🔴 High

Monitor:

```text
CurrentVersion\Run
CurrentVersion\RunOnce
```

---

## Detection 2

PowerShell Creating Registry Persistence

Severity: 🔴 High

Monitor:

```text
powershell.exe
```

creating Registry Run Keys.

---

## Detection 3

ExecutionPolicy Bypass Used During Persistence Creation

Severity: 🟡 Medium

Monitor PowerShell command lines containing:

```text
-ExecutionPolicy Bypass
```

---

## Detection 4

Persistence Following Beaconing Activity

Severity: 🔴 High

Correlate:

```text
PowerShell Execution
↓
Beaconing Activity
↓
Registry Persistence
```

---

# Hunt Result

The hunt successfully identified Registry-based persistence through creation of a Run Key under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Sysmon Event ID 13 provided visibility into the Registry modification, while registry inspection independently confirmed successful persistence creation.

The resulting telemetry closely resembles behavior commonly observed during post-compromise persistence establishment.

---

# Analyst Assessment

This stage represents the final phase of the simulated intrusion chain.

The persistence mechanism was successfully established and verified without requiring a system reboot.

While execution after reboot was not observed directly, both Sysmon telemetry and registry inspection confirm that Windows would automatically launch the configured PowerShell command during a future user logon.

This completes the simulated campaign lifecycle:

* Initial Access (USB Execution)
* Discovery
* Staging
* Beaconing / Command & Control
* Persistence

The resulting telemetry provides a realistic dataset for threat hunting, detection engineering, and ATT&CK-aligned investigation workflows.

---

# Screenshots

## Registry Run Key Creation (Event ID 13)

<img width="682" height="200" alt="Registry-run-key-creation" src="https://github.com/user-attachments/assets/6c7725b0-fa73-41f9-a3c1-f507d3fa0421" />


---

## Registry Verification

<img width="578" height="329" alt="Registry-Verification" src="https://github.com/user-attachments/assets/93618d7c-0655-47a2-a543-5f3ce98335df" />

---



---

# Campaign Complete

✅ Stage 1 — USB Execution

✅ Stage 2 — Discovery, Staging and Network Activity

✅ Stage 3 — Beaconing and Command & Control

✅ Stage 4 — Registry Run Key Persistence
