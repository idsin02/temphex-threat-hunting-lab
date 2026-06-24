# TEMP.Hex Threat Hunting Lab — Stage 5: Payload Obfuscation and Decode Execution

> ATT&CK: T1027 - Obfuscated Files or Information
>
> ATT&CK: T1140 - Deobfuscate / Decode Files or Information
>
> Platform: Windows 11
>
> Telemetry Source: Sysmon
>
> Status: Completed ✅

---

# Executive Summary

Following successful simulation of USB execution, discovery activity, beaconing, command-and-control communications, and persistence establishment, the final stage of the campaign focused on payload obfuscation and runtime decoding.

A PowerShell payload was encoded using Base64 and stored within a seemingly harmless configuration file (`config.dat`). A decoder script (`decoder.ps1`) subsequently reconstructed the original payload and executed it.

The objective of this hunt was to validate visibility into adversary techniques involving payload concealment, runtime decoding, and execution of reconstructed code.

Sysmon successfully captured both decoder execution and payload reconstruction activity, providing telemetry that closely resembles malware behavior observed in real-world campaigns.

---

# Attack Flow

```text
USB
│
└── RECYCLER.BIN
      │
      ├── config.dat
      │      (Base64 Encoded Payload)
      │
      ├── decoder.ps1
      │
      └── payload.ps1
               │
               ▼
       decoded-output.txt
```

---

# ATT&CK Mapping

| Technique | Name                                      |
| --------- | ----------------------------------------- |
| T1027     | Obfuscated Files or Information           |
| T1140     | Deobfuscate / Decode Files or Information |
| T1059.001 | PowerShell                                |
| T1091     | Replication Through Removable Media       |

---

# Hunt Objective

Detect payloads stored in encoded form and identify the decoding activity responsible for reconstructing executable content.

---

# Hunt Hypothesis

An adversary may attempt to evade detection by storing malicious payloads in encoded form and decoding them immediately prior to execution.

Successful payload reconstruction should generate telemetry indicating:

* Decoder execution
* File reconstruction activity
* PowerShell execution
* Creation of newly decoded payloads

---

# Lab Environment

| Component            | Value           |
| -------------------- | --------------- |
| Operating System     | Windows 11      |
| Telemetry            | Sysmon          |
| Investigation Tool   | Event Viewer    |
| Campaign Inspiration | TEMP.Hex / SOGU |

---

# Obfuscation Simulation

## Original Payload

A simple PowerShell payload was created:

```powershell
Get-Date | Out-File "$env:TEMP\decoded-output.txt"
```

---

## Encoding Process

The payload was converted into Base64 and stored as:

```text
config.dat
```

This simulated an attacker hiding executable content within a seemingly benign file.

---

## Decoder Script

```powershell
$Encoded = Get-Content ".\config.dat" -Raw

$Decoded = [System.Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String($Encoded)
)

$Decoded | Out-File ".\payload.ps1"

powershell.exe -ExecutionPolicy Bypass -File ".\payload.ps1"
```

---

# Investigation Questions

### Question 1

Was an encoded payload stored on disk?

### Question 2

Was a decoder responsible for reconstructing the payload?

### Question 3

Was the reconstructed payload executed?

### Question 4

What telemetry proves the payload originally existed in encoded form?

---

# Investigation Findings

An encoded PowerShell payload was successfully stored within:

```text
config.dat
```

Execution of:

```text
decoder.ps1
```

resulted in reconstruction of:

```text
payload.ps1
```

The decoded payload executed successfully and generated:

```text
decoded-output.txt
```

Sysmon captured both PowerShell execution and file creation events associated with payload reconstruction.

---

# Evidence Collected

| Evidence              | Observation        |
| --------------------- | ------------------ |
| Encoded Payload       | config.dat         |
| Decoder Script        | decoder.ps1        |
| Reconstructed Payload | payload.ps1        |
| Output Artifact       | decoded-output.txt |
| Process               | powershell.exe     |
| Event ID              | 1                  |
| Event ID              | 11                 |
| Technique             | T1027              |
| Technique             | T1140              |

---

# Event ID 1 Evidence

## Decoder Execution

```text
Image:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:

powershell.exe -ExecutionPolicy Bypass -File .\decoder.ps1
```

This confirms execution of the decoder responsible for reconstructing the payload.

---

# Event ID 11 Evidence

## Payload Reconstruction

```text
TargetFilename:

C:\USB_Test\RECYCLER.BIN\stage5\payload.ps1
```

This confirms the payload was written to disk following decoding.

---

# Execution Validation

The reconstructed payload successfully executed and generated:

```text
decoded-output.txt
```

Contents:

```text
Monday, June 8, 2026
```

This confirms successful decode-and-execute behavior.

---

# Architecture Diagram

```text
config.dat
(Base64 Payload)
        │
        ▼
decoder.ps1
        │
        ▼
payload.ps1
        │
        ▼
decoded-output.txt
```

---

# Timeline

```text
config.dat created
│
├── Payload encoded
│
├── decoder.ps1 executed
│
├── Sysmon Event ID 1 generated
│
├── payload.ps1 reconstructed
│
├── Sysmon Event ID 11 generated
│
├── payload.ps1 executed
│
└── decoded-output.txt created
```

---

# KQL Detection Opportunities

## Detection 1 — Decoder Execution

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "decoder.ps1"
| project Timestamp,
          DeviceName,
          ProcessCommandLine
```

---

## Detection 2 — Payload Reconstruction

```kusto
DeviceFileEvents
| where FileName =~ "payload.ps1"
| project Timestamp,
          DeviceName,
          FileName,
          FolderPath,
          InitiatingProcessFileName
```

---

## Detection 3 — PowerShell Execution From USB Path

```kusto
DeviceProcessEvents
| where FolderPath contains "RECYCLER.BIN"
| where FileName =~ "powershell.exe"
```

---

# Sigma Rule

```yaml
title: PowerShell Decoder Executed From USB Path
id: stage5-decoder-execution
status: experimental

logsource:
  product: windows
  category: process_creation

detection:
  selection:
    Image|endswith:
      - '\powershell.exe'

    CommandLine|contains:
      - 'decoder.ps1'

  condition: selection

level: high

tags:
  - attack.t1027
  - attack.t1140
```

---

# Detection Opportunities

## Detection 1

PowerShell decoding Base64 content.

Severity: 🔴 High

---

## Detection 2

PowerShell creating executable script files.

Severity: 🔴 High

---

## Detection 3

Encoded content immediately followed by script reconstruction.

Severity: 🔴 Critical

---

## Detection 4

Execution of newly reconstructed PowerShell scripts.

Severity: 🔴 Critical

---

# ATT&CK Navigator Coverage

```text
T1091  Replication Through Removable Media

T1059.001  PowerShell

T1071.001  Application Layer Protocol

T1547.001  Registry Run Keys

T1027  Obfuscated Files or Information

T1140  Deobfuscate / Decode Files
```

---

# Hunt Result

The hunt successfully demonstrated a common malware evasion technique in which executable content is stored in encoded form and reconstructed immediately before execution.

Sysmon captured decoder execution and payload creation activity, enabling reconstruction of the complete execution chain from encoded artifact to decoded payload execution.

No malicious payloads were used during this simulation.

---

# Analyst Assessment

Unlike previous stages focused on execution, discovery, beaconing, and persistence, this stage demonstrates adversary efforts to conceal executable content through encoding.

Although the payload used in this simulation was benign, the resulting telemetry closely resembles malware families that store PowerShell payloads as encoded blobs before reconstructing them at runtime.

The combination of Sysmon Event ID 1 (Process Create) and Event ID 11 (File Create) provides defenders with sufficient evidence to identify and investigate similar techniques in production environments.

This stage completes the full simulated intrusion lifecycle.

---

# Screenshots

<img width="521" height="230" alt="5 2" src="https://github.com/user-attachments/assets/d603615f-bcd3-4d87-a82d-3384947622b6" />
<img width="572" height="249" alt="5 1" src="https://github.com/user-attachments/assets/d54267b5-3815-4772-be54-a4f425315735" />
<img width="668" height="292" alt="5 7" src="https://github.com/user-attachments/assets/c08197b1-0f7d-4261-9639-3eb6b6cdfc94" />
<img width="686" height="322" alt="5 6" src="https://github.com/user-attachments/assets/d5a91555-da32-4f34-b4da-8d519b9ca124" />
<img width="440" height="175" alt="5 5" src="https://github.com/user-attachments/assets/5f86b9f0-8670-4489-9f25-711139ca6155" />
<img width="291" height="134" alt="5 4" src="https://github.com/user-attachments/assets/12e6ddc3-ce0b-47df-9729-c646b94d4304" />
<img width="365" height="168" alt="5 3" src="https://github.com/user-attachments/assets/7aabc608-1c7a-470f-9af6-0061de9fae4c" />

# Campaign Lifecycle Completed

✅ Stage 1 — USB Execution

✅ Stage 2 — Discovery & Staging

✅ Stage 3 — Beaconing & Command & Control

✅ Stage 4 — Registry Persistence

✅ Stage 5 — Payload Obfuscation & Decode Execution

---

# Future Improvements

Potential future enhancements include:

* Data Collection Simulation (T1005)
* Archive Creation (T1560)
* Simulated Exfiltration (T1041)
* ATT&CK Navigator Layer Export
* Sigma-to-KQL Conversion Pipeline
* Elastic Detection Rules

The current campaign already provides sufficient telemetry coverage for a complete threat hunting and detection engineering portfolio project.
