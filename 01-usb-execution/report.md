# TEMP.Hex Threat Hunting Lab — Stage 1: USB Execution Simulation

> ATT&CK: T1091 - Replication Through Removable Media
> Platform: Windows 11
> Telemetry Source: Sysmon
> Status: Completed ✅


---

# Executive Summary

This hunt simulates a USB-delivered malware execution scenario inspired by the TEMP.Hex campaign.

A benign executable was staged inside a `RECYCLER.BIN` directory to emulate malware delivery through removable media. The objective was to validate visibility into suspicious execution originating from removable-media-like locations and confirm telemetry coverage for ATT&CK technique **T1091 – Replication Through Removable Media**.

The simulation successfully generated Sysmon telemetry and established a foundation for subsequent stages involving discovery, staging, beaconing, and persistence.

---

# Attack Flow

```text
USB
│
└── RECYCLER.BIN
      │
      └── Removable Disk (57GB).exe
               │
               └── Execution
```

---

# ATT&CK Mapping

| Technique | Name                                |
| --------- | ----------------------------------- |
| T1091     | Replication Through Removable Media |

---

# Hunt Objective

Detect suspicious process execution originating from removable-media-like staging locations.

---

# Hunt Hypothesis

An adversary may stage a malicious payload on removable media and rely on a user to manually execute the file.

Execution originating from suspicious removable-media-like locations may indicate malware delivery, lateral movement, or initial access activity.

---

# Lab Environment

| Component            | Value           |
| -------------------- | --------------- |
| Operating System     | Windows 11      |
| Telemetry            | Sysmon          |
| Investigation Tool   | Event Viewer    |
| Campaign Inspiration | TEMP.Hex / SOGU |

---

# Attack Simulation

## Directory Structure

```text
C:\USB_Test\
└── RECYCLER.BIN\
    └── notepad.exe
```

Optional:

```text
notepad.exe
↓
Removable Disk (57GB).exe
```

## Execution Steps

1. Create:

```text
C:\USB_Test
```



2. Create:

```text
C:\USB_Test\RECYCLER.BIN
```



3. Copy:

```text
C:\Windows\System32\notepad.exe
```



4. Execute:

```text
C:\USB_Test\RECYCLER.BIN\notepad.exe
```


5. Observe generated Sysmon telemetry.

---

# Investigation Question

### Question

Which executable originated from a suspicious removable-media-like location?

### Answer

```text
notepad.exe

Path:
C:\USB_Test\RECYCLER.BIN\notepad.exe
```

---

# Investigation Findings

Sysmon Event ID 1 captured execution of a process originating from:

```text
C:\USB_Test\RECYCLER.BIN\
```

The executable successfully launched and generated Process Create telemetry, validating visibility into removable-media-like execution activity.

---

# Evidence Collected

| Evidence         | Observation               |
| ---------------- | ------------------------- |
| Process          | notepad.exe               |
| Path             | C:\USB_Test\RECYCLER.BIN\ |
| Event ID         | 1                         |
| Log Source       | Sysmon                    |
| User             | admin                     |
| ATT&CK Technique | T1091                     |

---

# Expected Telemetry

## Sysmon Event ID 1

### Process Create

Expected Image:

```text
C:\USB_Test\RECYCLER.BIN\notepad.exe
```

or

```text
C:\USB_Test\RECYCLER.BIN\Removable Disk (57GB).exe
```

---

# Timeline

```text
03:02:35
│
├── notepad.exe executed
│
├── Sysmon Event ID 1 generated
│
├── Process execution confirmed
│
└── Threat hunting investigation initiated
```

---

# Detection Opportunity

## Detection Logic

Alert when:

* Event ID 1 (Process Create)

AND

* Image Path contains:

```text
RECYCLER.BIN
$Recycle.Bin
System Volume Information
USB
```

### Severity

🟡 Medium

### Rationale

Legitimate applications rarely execute directly from removable-media staging directories.

Execution from these locations may indicate malware delivery or user-assisted execution activity.

---

# Hunt Result

The hunt successfully identified execution originating from a suspicious removable-media-like location.

Sysmon Event ID 1 provided visibility into executable execution from `RECYCLER.BIN` and validated telemetry coverage for removable-media execution scenarios.

No malicious activity was performed.

---

# Analyst Assessment

Execution from `RECYCLER.BIN` was successfully detected through Sysmon Process Create telemetry.

While the executable used in this simulation was benign (`notepad.exe`), the same methodology could identify malware delivered through removable media.

The hunt validated visibility into execution originating from suspicious directories and established a foundation for subsequent stages involving:

* Discovery
* Staging
* Command & Control
* Persistence

---

# Screenshots

## Event ID 1 — Process Create
<img width="866" height="431" alt="stage1-process-create-evidence png" src="https://github.com/user-attachments/assets/dc226033-b54e-4b5f-a7c8-7e52c5ba7372" />


---

# Next Stage

➡️ Stage 2 — Discovery, Staging and Network Activity Simulation
