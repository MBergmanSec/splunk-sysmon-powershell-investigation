# PowerShell Recon and Web Request Investigation

--------------------------------------------------
1. PowerShell Process Creation Hunt
--------------------------------------------------

index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)"
| search Image="*powershell.exe*"
| table _time Image CommandLine ParentImage User
| sort _time

Purpose:
Identify PowerShell execution and suspicious command-line arguments.

--------------------------------------------------
2. DNS Query Investigation
--------------------------------------------------

index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=22
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='QueryName'>(?<QueryName>[^<]+)"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)"
| table _time Image QueryName User
| sort _time

Purpose:
Identify DNS lookups performed by the process.

--------------------------------------------------
3. Network Connection Investigation
--------------------------------------------------

index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=3
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)"
| table _time Image DestinationIp DestinationPort User
| sort _time

Purpose:
Identify outbound network connections.

--------------------------------------------------
4. Correlated Investigation Timeline
--------------------------------------------------

index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
"example.com" OR "Invoke-WebRequest" OR "powershell.exe" OR "whoami.exe" OR "ipconfig.exe"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)"
| rex field=_raw "<Data Name='QueryName'>(?<QueryName>[^<]+)"
| table _time EventCode Image CommandLine QueryName DestinationIp
| sort _time

Purpose:
Build a complete timeline of PowerShell execution, reconnaissance, DNS activity, and network communication.