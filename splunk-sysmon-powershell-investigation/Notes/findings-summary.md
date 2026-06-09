# Findings Summary

## Investigation Result

The activity investigated in this lab was intentionally generated in a controlled environment to simulate suspicious PowerShell behavior.

The investigation identified the following sequence of events:

1. PowerShell was launched by the logged-in user.
2. PowerShell executed with `ExecutionPolicy Bypass`.
3. PowerShell executed with `WindowStyle Hidden`.
4. Reconnaissance commands were executed:

   * whoami.exe
   * ipconfig.exe
5. PowerShell performed an Invoke-WebRequest to example.com.
6. A DNS lookup for example.com was observed.
7. An outbound HTTPS connection was established to the resolved IP address.

## Key Indicators

### Suspicious Indicators

* ExecutionPolicy Bypass
* WindowStyle Hidden
* PowerShell launching reconnaissance commands
* External web request
* DNS resolution followed by outbound network communication

### Contextual Indicators

The activity was executed from a normal user account rather than a privileged administrative account.

The combination of hidden PowerShell execution, reconnaissance commands, and external communication would warrant further investigation in a production environment.

## Conclusion

While the activity was generated as part of a lab exercise, the observed behavior is consistent with techniques frequently seen during the early stages of attacker activity.

The investigation successfully correlated process creation, DNS activity, and network connections to reconstruct the complete sequence of events.
