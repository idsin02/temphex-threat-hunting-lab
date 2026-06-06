# TEMP.Hex Threat Hunting Lab — Stage 2: Discovery, Staging and Network Activity

> ATT&CK: T1059.003, T1059.001, T1082, T1033, T1074.001, T1071.001, T1036
> Platform: Windows 11
> Telemetry Source: Sysmon
> Status: Completed ✅

---

# Executive Summary

Following successful validation of USB-based execution in Stage 1, the simulation was expanded to emulate post-exploitation behavior commonly observed after initial access.

A batch file masquerading as removable media was executed from a RECYCLER.BIN directory. The payload spawned command interpreters, performed host discovery activities, staged data locally, and generated outbound web traffic.

The objective of this hunt was to validate visibility into attacker behavior occurring immediately after execution and establish detection opportunities around discovery, staging, PowerShell abuse, and outbound communications.

---

# Attack Flow

```text
USB Execution
│
└── Removable Disk (57GB).bat
      │
      ├── cmd.exe
      │    ├── whoami
      │    ├── hostname
      │    └── ipconfig /all
      │
      ├── powershell.exe
      │    └── usb_stage.txt
      │
      └── curl.exe
           └── example.com
```

---

# ATT&CK Mapping

| Technique | Name                                      |
| --------- | ----------------------------------------- |
| T1059.003 | Windows Command Shell                     |
| T1059.001 | PowerShell                                |
| T1082     | System Information Discovery              |
| T1033     | System Owner/User Discovery               |
| T1074.001 | Local Data Staging                        |
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1036     | Masquerading                              |

---

# Hunt Objective

Detect post-exploitation activity following execution from a suspicious removable-media-like location.

---

# Hunt Hypothesis

An adversary may execute a payload from removable media and immediately begin discovery activities to understand the compromised host.

The payload may stage collected information locally before establishing outbound communications with external infrastructure.

---

# Lab Environment

| Component            | Value           |
| -------------------- | --------------- |
| Operating System     | Windows 11      |
| Telemetry            | Sysmon          |
| Investigation Tool   | Event Viewer    |
| Campaign Inspiration | TEMP.Hex / SOGU |

---

# Simulated Payload

```bat
@echo off
title Removable Disk
echo Simulating USB execution...

cmd.exe /c whoami > %TEMP%\usb_user.txt
cmd.exe /c hostname >> %TEMP%\usb_user.txt
cmd.exe /c ipconfig /all >> %TEMP%\usb_network.txt

powershell.exe -ExecutionPolicy Bypass -Command "Get-Date | Out-File $env:TEMP\usb_stage.txt"

curl.exe https://example.com

pause
```

---

# Investigation Questions

### Question 1

Which process executed from RECYCLER.BIN?

### Question 2

What child processes were spawned?

### Question 3

Did execution result in local staging?

### Question 4

Did execution result in outbound communication?

---

# Investigation Findings

The executed batch file originated from:

```text
C:\USB_Test\RECYCLER.BIN\
```

The process spawned multiple child processes including:

* cmd.exe
* powershell.exe
* curl.exe

Discovery commands collected:

* Username
* Hostname
* Network Configuration

Local staging files were created within the TEMP directory and outbound HTTP traffic was generated.

The resulting activity chain resembles common post-compromise behavior frequently observed after successful execution.

---

# Evidence Collected

| Evidence         | Observation               |
| ---------------- | ------------------------- |
| Parent Process   | Removable Disk (57GB).bat |
| Child Process    | cmd.exe                   |
| Child Process    | powershell.exe            |
| Child Process    | curl.exe                  |
| Discovery        | whoami                    |
| Discovery        | hostname                  |
| Discovery        | ipconfig                  |
| Staging File     | usb_user.txt              |
| Staging File     | usb_network.txt           |
| Staging File     | usb_stage.txt             |
| Network Activity | example.com               |

---

# Process Tree

```text
Removable Disk (57GB).bat
│
├── cmd.exe
│   ├── whoami
│   ├── hostname
│   └── ipconfig /all
│
├── powershell.exe
│   └── usb_stage.txt
│
└── curl.exe
    └── https://example.com
```

---

# Timeline

```text
Execution of Removable Disk (57GB).bat
│
├── cmd.exe launched
│
├── Discovery commands executed
│
├── usb_user.txt created
│
├── usb_network.txt created
│
├── powershell.exe launched
│
├── usb_stage.txt created
│
├── curl.exe executed
│
└── Outbound HTTP connection established
```

---

# Detection Opportunities

## Detection 1

Execution from RECYCLER.BIN

Severity: 🟡 Medium

---

## Detection 2

PowerShell launched with ExecutionPolicy Bypass

Severity: 🟡 Medium

---

## Detection 3

Discovery commands executed immediately after suspicious execution

Severity: 🟡 Medium

---

## Detection 4

Execution followed by outbound network communication

Severity: 🔴 High

---

# Hunt Result

The hunt successfully identified discovery, staging, and outbound communication activity following execution from a removable-media-like location.

Telemetry demonstrated visibility into:

* Command Execution
* Discovery Activity
* PowerShell Execution
* File Creation
* Network Communication

The simulation validates detection opportunities commonly associated with early-stage malware execution and operator reconnaissance.

---

# Analyst Assessment

The observed activity demonstrates a realistic post-exploitation sequence extending beyond simple process execution.

The payload performed host discovery, staged information locally, and generated outbound communications shortly after launch.

While all activity in this simulation remained benign, the resulting telemetry closely resembles behavior commonly investigated during malware execution and hands-on-keyboard intrusions.

This stage establishes the foundation for Stage 3, where recurring outbound communications and beaconing behavior are introduced.

---

# Screenshots

## File Create Process

<img width="725" height="302" alt="file create process" src="https://github.com/user-attachments/assets/f3df3be6-bb20-45d8-9da2-020a8d686948" />


## Discovery Activity

<img width="824" height="383" alt="discovery-commands" src="https://github.com/user-attachments/assets/d791c774-71b6-483b-b51c-eee864900a6d" />


## PowerShell Execution

<img width="851" height="383" alt="powershell-stage" src="https://github.com/user-attachments/assets/94aed725-6ee6-42cb-8c75-2265758f232d" />


## Network Activity

<img width="677" height="302" alt="network-activity" src="https://github.com/user-attachments/assets/90a31972-1dff-4b7a-8ca2-8ebdc1917055" />


---

# Next Stage

➡️ Stage 3 — Beaconing and Command & Control Simulation
