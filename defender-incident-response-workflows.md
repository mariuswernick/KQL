# Example Incident Response Workflows for Microsoft Defender

These workflows are designed for incident response engineers using Microsoft Defender (for Endpoint, Sentinel, or Cloud). They provide step-by-step guidance for common security incidents, leveraging KQL, Defender features, and best practices.

---

## 1. Malware Detected on Endpoint
1. **Alert Triage**
   - Review Defender alert details (file, user, device, detection method).
   - Check alert severity and scope (single or multiple endpoints).
2. **Initial Containment**
   - Isolate the device from the network (Defender for Endpoint > Device page > Isolate device).
   - Block the malicious file hash (Defender > Indicators > Add indicator).
3. **Investigation**
   - Run KQL to find all executions of the file:
     ```kql
     DeviceProcessEvents | where FileName == "<malware_name>"
     ```
   - Check for lateral movement (RDP, PsExec, SMB):
     ```kql
     DeviceNetworkEvents | where InitiatingProcessFileName in~ ("psexec.exe", "wmic.exe")
     ```
   - Review persistence mechanisms (registry, scheduled tasks).
4. **Remediation**
   - Remove/quarantine the file.
   - Revoke compromised credentials.
   - Patch vulnerabilities.
5. **Recovery & Lessons Learned**
   - Restore from backup if needed.
   - Document findings and update detection rules.

---

## 2. Suspicious PowerShell Activity
1. **Alert Triage**
   - Review alert for suspicious PowerShell command line.
   - Identify user and device involved.
2. **Scope Investigation**
   - Find all suspicious PowerShell executions:
     ```kql
     DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has_any ("IEX", "DownloadString", "-enc")
     ```
   - Check for encoded or obfuscated commands.
3. **Containment**
   - Isolate device if malicious activity is confirmed.
   - Block related file hashes or URLs.
4. **Remediation**
   - Remove persistence (scheduled tasks, registry keys).
   - Reset credentials if needed.
5. **Reporting**
   - Document the incident and update detection logic.

---

## 3. Lateral Movement Detected (e.g., PsExec, RDP)
1. **Alert Triage**
   - Review alert for lateral movement tools/processes.
2. **Scope Investigation**
   - Identify all affected endpoints:
     ```kql
     DeviceProcessEvents | where InitiatingProcessFileName in~ ("psexec.exe", "wmic.exe", "mstsc.exe")
     ```
   - Map connections:
     ```kql
     DeviceNetworkEvents | where RemotePort == 3389 or InitiatingProcessFileName == "psexec.exe"
     ```
3. **Containment**
   - Isolate affected endpoints.
   - Disable compromised accounts.
4. **Remediation**
   - Remove malicious tools.
   - Patch vulnerabilities.
5. **Recovery**
   - Monitor for further movement.
   - Document and update detection rules.

---

## 4. Credential Dumping Attempt
1. **Alert Triage**
   - Review alert for credential dumping (e.g., Mimikatz, lsass access).
2. **Scope Investigation**
   - Find all processes accessing lsass.exe:
     ```kql
     DeviceProcessEvents | where TargetProcessName == "lsass.exe" and InitiatingProcessAccountName != "SYSTEM"
     ```
   - Check for known tools (mimikatz, procdump):
     ```kql
     DeviceProcessEvents | where ProcessCommandLine has_any ("mimikatz", "procdump")
     ```
3. **Containment**
   - Isolate device.
   - Reset credentials for affected users.
4. **Remediation**
   - Remove malicious files.
   - Patch and harden systems.
5. **Reporting**
   - Document incident and update detection logic.

---

## 5. Suspicious External Connection (C2, Exfiltration)
1. **Alert Triage**
   - Review alert for unusual outbound connections (C2, data exfiltration).
2. **Scope Investigation**
   - Identify all devices connecting to suspicious IP/domain:
     ```kql
     DeviceNetworkEvents | where RemoteUrl == "<suspicious_domain>" or RemoteIP == "<suspicious_ip>"
     ```
   - Check for data transfer volume:
     ```kql
     DeviceNetworkEvents | where RemoteIP == "<suspicious_ip>" | summarize TotalBytes = sum(SentBytes + ReceivedBytes) by DeviceName
     ```
3. **Containment**
   - Block IP/domain at firewall and Defender.
   - Isolate affected devices.
4. **Remediation**
   - Remove malware or tools enabling exfiltration.
   - Reset credentials if needed.
5. **Reporting**
   - Document incident and update detection logic.

---

For more, see the [Microsoft Incident Response documentation](https://learn.microsoft.com/en-us/security/incident-response/overview) and [Defender Advanced Hunting docs](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview).
