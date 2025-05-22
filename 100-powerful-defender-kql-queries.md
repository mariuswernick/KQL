# 100 Powerful KQL Queries for Microsoft Defender

This document contains 100 powerful KQL (Kusto Query Language) queries for Microsoft Defender (Defender for Endpoint, Defender for Cloud, Defender for Identity, etc.). These queries cover threat hunting, incident investigation, lateral movement, persistence, privilege escalation, suspicious behaviors, and more. You can use them in Microsoft Defender Advanced Hunting, Microsoft Sentinel, or other KQL-compatible security tools.

---

1. **Find all processes spawned from Office applications:**
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
```

2. **Detect PowerShell execution with suspicious command line:**
```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "IEX", "DownloadString", "EncodedCommand")
```

3. **List all RDP connections:**
```kql
DeviceNetworkEvents
| where RemotePort == 3389
```

4. **Find credential dumping tools:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("mimikatz", "procdump", "lsass")
```

5. **Detect lateral movement via PsExec:**
```kql
DeviceProcessEvents
| where FileName in~ ("psexec.exe", "psexec64.exe")
```

6. **Suspicious scheduled tasks creation:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "schtasks" and ProcessCommandLine has_any ("create", "/create")
```

7. **Find new local admin accounts:**
```kql
DeviceEvents
| where ActionType == "UserAccountAddedToLocalGroup"
| where AdditionalFields has "Administrators"
```

8. **Detect encoded PowerShell commands:**
```kql
DeviceProcessEvents
| where FileName == "powershell.exe" and ProcessCommandLine has "-enc"
```

9. **Find unsigned drivers loaded:**
```kql
DeviceDriverEvents
| where SignatureStatus != "Signed"
```

10. **Detect LSASS access by non-system processes:**
```kql
DeviceProcessEvents
| where TargetProcessName == "lsass.exe" and InitiatingProcessAccountName != "SYSTEM"
```

11. **Suspicious WMI execution:**
```kql
DeviceProcessEvents
| where FileName in~ ("wmic.exe", "wmiapsrv.exe")
```

12. **Find rare parent-child process relationships:**
```kql
DeviceProcessEvents
| summarize count() by InitiatingProcessFileName, FileName
| where count_ < 5
```

13. **Detect use of net.exe for user enumeration:**
```kql
DeviceProcessEvents
| where FileName == "net.exe" and ProcessCommandLine has_any ("user", "group", "localgroup")
```

14. **Find processes running from temp folders:**
```kql
DeviceProcessEvents
| where FolderPath has_any ("\\AppData\\Local\\Temp", "\\Temp\\")
```

15. **Detect suspicious DLL sideloading:**
```kql
DeviceImageLoadEvents
| where FolderPath has_any ("\\AppData\\", "\\Temp\\")
```

16. **Find suspicious persistence via registry:**
```kql
DeviceRegistryEvents
| where RegistryKey has_any ("Run", "RunOnce", "RunServices")
```

17. **Detect use of certutil for file download:**
```kql
DeviceProcessEvents
| where FileName == "certutil.exe" and ProcessCommandLine has "urlcache"
```

18. **Find suspicious use of mshta.exe:**
```kql
DeviceProcessEvents
| where FileName == "mshta.exe"
```

19. **Detect suspicious use of rundll32:**
```kql
DeviceProcessEvents
| where FileName == "rundll32.exe" and ProcessCommandLine has_any (".js", ".vbs", "javascript")
```

20. **Find suspicious use of regsvr32:**
```kql
DeviceProcessEvents
| where FileName == "regsvr32.exe" and ProcessCommandLine has_any ("http", "https")
```

21. **Detect use of bitsadmin for file download:**
```kql
DeviceProcessEvents
| where FileName == "bitsadmin.exe" and ProcessCommandLine has "transfer"
```

22. **Find suspicious use of wscript/cscript:**
```kql
DeviceProcessEvents
| where FileName in~ ("wscript.exe", "cscript.exe")
```

23. **Detect suspicious use of msiexec:**
```kql
DeviceProcessEvents
| where FileName == "msiexec.exe" and ProcessCommandLine has_any ("http", "https")
```

24. **Find suspicious use of at.exe:**
```kql
DeviceProcessEvents
| where FileName == "at.exe"
```

25. **Detect suspicious use of sc.exe:**
```kql
DeviceProcessEvents
| where FileName == "sc.exe" and ProcessCommandLine has_any ("create", "config", "start")
```

26. **Find suspicious use of bcdedit:**
```kql
DeviceProcessEvents
| where FileName == "bcdedit.exe"
```

27. **Detect suspicious use of wevtutil:**
```kql
DeviceProcessEvents
| where FileName == "wevtutil.exe"
```

28. **Find suspicious use of vssadmin:**
```kql
DeviceProcessEvents
| where FileName == "vssadmin.exe" and ProcessCommandLine has_any ("delete", "shadow")
```

29. **Detect suspicious use of netsh:**
```kql
DeviceProcessEvents
| where FileName == "netsh.exe" and ProcessCommandLine has_any ("firewall", "advfirewall")
```

30. **Find suspicious use of nltest:**
```kql
DeviceProcessEvents
| where FileName == "nltest.exe"
```

31. **Detect suspicious use of dsquery:**
```kql
DeviceProcessEvents
| where FileName == "dsquery.exe"
```

32. **Find suspicious use of ntdsutil:**
```kql
DeviceProcessEvents
| where FileName == "ntdsutil.exe"
```

33. **Detect suspicious use of wmic for process creation:**
```kql
DeviceProcessEvents
| where FileName == "wmic.exe" and ProcessCommandLine has "process call create"
```

34. **Find suspicious use of explorer.exe:**
```kql
DeviceProcessEvents
| where FileName == "explorer.exe" and InitiatingProcessFileName != "explorer.exe"
```

35. **Detect suspicious use of svchost.exe:**
```kql
DeviceProcessEvents
| where FileName == "svchost.exe" and InitiatingProcessFileName != "services.exe"
```

36. **Find suspicious use of taskkill:**
```kql
DeviceProcessEvents
| where FileName == "taskkill.exe"
```

37. **Detect suspicious use of tasklist:**
```kql
DeviceProcessEvents
| where FileName == "tasklist.exe"
```

38. **Find suspicious use of whoami:**
```kql
DeviceProcessEvents
| where FileName == "whoami.exe"
```

39. **Detect suspicious use of systeminfo:**
```kql
DeviceProcessEvents
| where FileName == "systeminfo.exe"
```

40. **Find suspicious use of ipconfig:**
```kql
DeviceProcessEvents
| where FileName == "ipconfig.exe"
```

41. **Detect suspicious use of netstat:**
```kql
DeviceProcessEvents
| where FileName == "netstat.exe"
```

42. **Find suspicious use of arp:**
```kql
DeviceProcessEvents
| where FileName == "arp.exe"
```

43. **Detect suspicious use of route:**
```kql
DeviceProcessEvents
| where FileName == "route.exe"
```

44. **Find suspicious use of nslookup:**
```kql
DeviceProcessEvents
| where FileName == "nslookup.exe"
```

45. **Detect suspicious use of ping:**
```kql
DeviceProcessEvents
| where FileName == "ping.exe"
```

46. **Find suspicious use of tracert:**
```kql
DeviceProcessEvents
| where FileName == "tracert.exe"
```

47. **Detect suspicious use of ftp:**
```kql
DeviceProcessEvents
| where FileName == "ftp.exe"
```

48. **Find suspicious use of telnet:**
```kql
DeviceProcessEvents
| where FileName == "telnet.exe"
```

49. **Detect suspicious use of sftp:**
```kql
DeviceProcessEvents
| where FileName == "sftp.exe"
```

50. **Find suspicious use of plink:**
```kql
DeviceProcessEvents
| where FileName == "plink.exe"
```

51. **Detect suspicious use of putty:**
```kql
DeviceProcessEvents
| where FileName == "putty.exe"
```

52. **Find suspicious use of winscp:**
```kql
DeviceProcessEvents
| where FileName == "winscp.exe"
```

53. **Detect suspicious use of TeamViewer:**
```kql
DeviceProcessEvents
| where FileName == "TeamViewer.exe"
```

54. **Find suspicious use of AnyDesk:**
```kql
DeviceProcessEvents
| where FileName == "AnyDesk.exe"
```

55. **Detect suspicious use of remote utilities:**
```kql
DeviceProcessEvents
| where FileName has_any ("radmin", "remoteutilities")
```

56. **Find suspicious use of Ammyy Admin:**
```kql
DeviceProcessEvents
| where FileName == "AA_v3.exe"
```

57. **Detect suspicious use of VNC:**
```kql
DeviceProcessEvents
| where FileName has_any ("vnc", "tightvnc", "ultravnc")
```

58. **Find suspicious use of TeamViewerQS:**
```kql
DeviceProcessEvents
| where FileName == "TeamViewerQS.exe"
```

59. **Detect suspicious use of LogMeIn:**
```kql
DeviceProcessEvents
| where FileName has_any ("LogMeIn", "LMIRun")
```

60. **Find suspicious use of Splashtop:**
```kql
DeviceProcessEvents
| where FileName has_any ("Splashtop", "SRManager")
```

61. **Detect suspicious use of Chrome Remote Desktop:**
```kql
DeviceProcessEvents
| where FileName == "remoting_host.exe"
```

62. **Find suspicious use of Dameware:**
```kql
DeviceProcessEvents
| where FileName has_any ("DWRCC", "Dameware")
```

63. **Detect suspicious use of GoToAssist:**
```kql
DeviceProcessEvents
| where FileName has_any ("GoToAssist", "g2ax_host")
```

64. **Find suspicious use of ConnectWise:**
```kql
DeviceProcessEvents
| where FileName has_any ("ScreenConnect", "ConnectWise")
```

65. **Detect suspicious use of Kaseya:**
```kql
DeviceProcessEvents
| where FileName has_any ("Kaseya", "AgentMon")
```

66. **Find suspicious use of SolarWinds:**
```kql
DeviceProcessEvents
| where FileName has_any ("SolarWinds", "Dameware")
```

67. **Detect suspicious use of RDPWrap:**
```kql
DeviceProcessEvents
| where FileName == "RDPConf.exe"
```

68. **Find suspicious use of ngrok:**
```kql
DeviceProcessEvents
| where FileName == "ngrok.exe"
```

69. **Detect suspicious use of Serveo:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "serveo.net"
```

70. **Find suspicious use of SSH tunnels:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "-L" and ProcessCommandLine has "ssh"
```

71. **Detect suspicious use of port forwarding:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("-L", "-R", "-D")
```

72. **Find suspicious use of socat:**
```kql
DeviceProcessEvents
| where FileName == "socat.exe"
```

73. **Detect suspicious use of netcat:**
```kql
DeviceProcessEvents
| where FileName has_any ("nc.exe", "netcat.exe")
```

74. **Find suspicious use of PowerShell Empire:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "empire"
```

75. **Detect suspicious use of Cobalt Strike:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("beacon", "cobaltstrike")
```

76. **Find suspicious use of Metasploit:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "meterpreter"
```

77. **Detect suspicious use of Nishang:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "nishang"
```

78. **Find suspicious use of PowerSploit:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "powersploit"
```

79. **Detect suspicious use of SharpHound:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "sharphound"
```

80. **Find suspicious use of BloodHound:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "bloodhound"
```

81. **Detect suspicious use of Seatbelt:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "seatbelt"
```

82. **Find suspicious use of Rubeus:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "rubeus"
```

83. **Detect suspicious use of Mimikatz:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "mimikatz"
```

84. **Find suspicious use of LaZagne:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "lazagne"
```

85. **Detect suspicious use of CrackMapExec:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "crackmapexec"
```

86. **Find suspicious use of Responder:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "responder"
```

87. **Detect suspicious use of Inveigh:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "inveigh"
```

88. **Find suspicious use of Kerberoasting:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "kerberoast"
```

89. **Detect suspicious use of DCSync:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "dcsync"
```

90. **Find suspicious use of Golden Ticket:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "golden"
```

91. **Detect suspicious use of Silver Ticket:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "silver"
```

92. **Find suspicious use of Pass-the-Hash:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "pth"
```

93. **Detect suspicious use of Pass-the-Ticket:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "ptt"
```

94. **Find suspicious use of Overpass-the-Hash:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "opth"
```

95. **Detect suspicious use of Skeleton Key:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "skeleton"
```

96. **Find suspicious use of DCShadow:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "dcshadow"
```

97. **Detect suspicious use of PrintNightmare exploit:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "printnightmare"
```

98. **Find suspicious use of PetitPotam exploit:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "petitpotam"
```

99. **Detect suspicious use of ProxyShell exploit:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "proxyshell"
```

100. **Find suspicious use of ProxyLogon exploit:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "proxylogon"
```

---

Feel free to use, modify, and share these queries. For more details or advanced hunting, visit the [Microsoft Defender Advanced Hunting documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview).
