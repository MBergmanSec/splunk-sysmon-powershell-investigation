# Investigation Notes

## Initial Detection

The investigation began by reviewing Sysmon process creation events in Splunk.

A PowerShell command was identified containing several command-line arguments commonly associated with suspicious activity:

```text
ExecutionPolicy Bypass
WindowStyle Hidden
whoami
ipconfig
Invoke-WebRequest
```

At this stage I considered the activity suspicious due to the use of hidden PowerShell execution combined with reconnaissance commands.

---

## Process Investigation

Reviewing the process tree showed that PowerShell was launched by explorer.exe under the logged-in user account.

The command line indicated that multiple actions were being executed within a single PowerShell session.

Reconnaissance commands observed:

```text
whoami.exe
ipconfig.exe
```

These commands are often used to gather information about the current user and host configuration.

---

## DNS Investigation

I reviewed Sysmon Event ID 22 to determine whether the web request generated DNS activity.

A DNS query was identified for:

```text
example.com
```

The DNS event occurred immediately after the PowerShell command execution.

The timing strongly suggested that the query originated from the observed Invoke-WebRequest command.

---

## Network Investigation

Next I reviewed Sysmon Event ID 3 network connection events.

A PowerShell process established an outbound connection to:

```text
172.66.147.243
```

over:

```text
TCP 443
```

The timing correlated directly with both the PowerShell execution and the DNS query.

Because the connection used HTTPS, the contents of the communication could not be determined from Sysmon logs alone.

---

## Timeline Reconstruction

### 20:58:23

PowerShell launched.

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

Outbound HTTPS connection established.

---

## Analyst Assessment

If this activity had been observed in a real environment, I would have considered it high priority for further investigation due to:

* Hidden PowerShell execution
* Execution policy bypass
* Host reconnaissance
* External communication

Additional investigation would focus on:

* User legitimacy
* Endpoint history
* Network communication patterns
* Additional affected hosts
* Potential persistence mechanisms

Based on the available evidence, the activity is consistent with a potential early-stage compromise or attacker reconnaissance workflow.
