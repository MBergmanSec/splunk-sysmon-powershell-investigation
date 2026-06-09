# PowerShell Recon and Web Request Investigation

## Lab Overview

In this lab I used Splunk and Sysmon logs to investigate a suspicious PowerShell command that was designed to look similar to activity an attacker might perform after gaining access to a system.

The goal was to practice identifying suspicious command lines, following process execution, and correlating DNS and network activity to build a complete investigation timeline.

---

## Scenario

A user executed PowerShell using several suspicious command-line arguments:

* ExecutionPolicy Bypass
* WindowStyle Hidden

The PowerShell session then performed basic reconnaissance commands and made an outbound web request.

My objective was to determine:

* What the user executed
* Whether reconnaissance activity occurred
* Whether external communication took place
* What evidence was available in Sysmon logs

---

## Tools Used

* Splunk Enterprise
* Sysmon
* Windows 11
* PowerShell

---

## Investigation Process

### Step 1 - Identify Suspicious PowerShell Activity

I first searched for PowerShell process creation events and reviewed the command-line arguments.

I found a PowerShell process launched with:

```text
ExecutionPolicy Bypass
WindowStyle Hidden
```

These arguments immediately stood out because attackers commonly use them to avoid restrictions and reduce visibility to the user.

The command also contained:

```text
whoami
ipconfig
Invoke-WebRequest https://example.com
```

At this point I considered the activity suspicious and began investigating what happened next.

---

### Step 2 - Review Reconnaissance Activity

The PowerShell process spawned:

```text
whoami.exe
ipconfig.exe
```

These commands are commonly used to gather information about a host and the current user context.

While these commands are not malicious on their own, they become more interesting when combined with hidden PowerShell execution and outbound network activity.

---

### Step 3 - Investigate DNS Activity

Next I reviewed Sysmon Event ID 22 (DNS Query events).

I found a DNS lookup for:

```text
example.com
```

The timing matched the PowerShell execution and confirmed that the web request generated DNS activity.

---

### Step 4 - Investigate Network Activity

I then reviewed Sysmon Event ID 3 (Network Connections).

The logs showed PowerShell establishing an outbound HTTPS connection to:

```text
172.66.147.243
```

using port:

```text
443
```

This correlated directly with the previous DNS lookup and web request.

---

## Timeline

### 20:58:23

PowerShell launched

### 20:58:29

PowerShell executed with:

```text
ExecutionPolicy Bypass
WindowStyle Hidden
```

### 20:58:29

Reconnaissance commands executed:

```text
whoami.exe
ipconfig.exe
```

### 20:58:30

DNS query for:

```text
example.com
```

### 20:58:30

Outbound HTTPS connection established to:

```text
172.66.147.243
```

---

## Findings

During this investigation I was able to correlate multiple Sysmon event types to reconstruct the full sequence of activity.

The activity included:

* Suspicious PowerShell execution
* Hidden execution
* Execution policy bypass
* Host reconnaissance
* DNS resolution
* External network communication

Although this activity was generated in a lab environment, the same chain of events would justify further investigation in a production environment.

---

## What I Learned

This lab helped me become more comfortable with:

* Investigating Sysmon Event ID 1 (Process Creation)
* Investigating Sysmon Event ID 3 (Network Connections)
* Investigating Sysmon Event ID 22 (DNS Queries)
* Building investigation timelines
* Correlating multiple event types in Splunk
* Following parent-child process relationships

One of the biggest lessons from this lab was that a single event rarely tells the full story. The real value comes from correlating process creation, DNS activity, and network connections to understand what actually happened on the host.

---

## MITRE ATT&CK Techniques

* T1059.001 - PowerShell
* T1033 - System Owner/User Discovery
* T1016 - System Network Configuration Discovery
* T1071 - Application Layer Protocol
* T1059 - Command and Scripting Interpreter
