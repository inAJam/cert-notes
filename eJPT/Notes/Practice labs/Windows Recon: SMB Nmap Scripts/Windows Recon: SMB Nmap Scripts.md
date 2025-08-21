## Windows Recon: SMB Nmap Scripts

### Target
`demo.ine.local`

### Objectives: 
fingerprint the service using the tools available on the Kali machine and run Nmap scripts to enumerate the Windows target machine's SMB service


## Task 1: Identify SMB Protocol Dialects
We first run a simple scan to find the ports open on the target system.
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 21:30 IST
Nmap scan report for demo.ine.local (10.5.16.46)
Host is up (0.0026s latency).
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
49165/tcp open  unknown
49176/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.31 seconds
```
We know **SMB** runs on port **445**, so we run a targeted script scan for that port, highlighting any scripts starting with the words **smb**

```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p445 --script smb* demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 21:30 IST
Nmap scan report for demo.ine.local (10.5.16.46)
Host is up (0.0031s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-mbenum: 
|_  ERROR: Call to Browser Service failed with status = 2184
| smb-enum-shares: 
|   account_used: guest
|   \\10.5.16.46\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.5.16.46\C: 
|     Type: STYPE_DISKTREE                                                                                                                                                                                                                 
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.5.16.46\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.5.16.46\D$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.5.16.46\Documents: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.5.16.46\Downloads: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.5.16.46\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.5.16.46\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Anonymous access: <none>
|_    Current user access: READ
|_smb-print-text: false
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|     2:1:0
|     3:0:0
|_    3:0:2
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: WIN-OMCNBKR66MN
|   NetBIOS computer name: WIN-OMCNBKR66MN\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-08-07T16:01:51+00:00
| smb2-time: 
|   date: 2025-08-07T16:00:55
|_  start_date: 2025-08-07T15:58:23
|_smb-system-info: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb2-capabilities: 
|   2:0:2: 
|     Distributed File System
|   2:1:0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:0:0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3:0:2: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
| smb-brute: 
|_  guest:<blank> => Valid credentials
| smb-enum-sessions: 
|   Users logged in
|_    WIN-OMCNBKR66MN\bob since <unknown>
|_smb-flood: ERROR: Script execution failed (use -d to debug)
| smb-ls: Volume \\10.5.16.46\print$
|   maxfiles limit reached (10)
| SIZE   TIME                 FILENAME
| <DIR>  2013-08-22T15:39:31  .
| <DIR>  2013-08-22T15:39:31  ..
| <DIR>  2013-08-22T15:39:31  color
| <DIR>  2013-08-22T14:50:22  IA64
| <DIR>  2013-08-22T14:50:22  W32X86
| <DIR>  2013-08-22T14:50:24  W32X86\3
| <DIR>  2013-08-22T14:50:24  W32X86\PCC
| <DIR>  2013-08-22T15:39:31  x64
| <DIR>  2013-08-22T15:39:31  x64\3
| <DIR>  2013-08-22T14:50:22  x64\PCC
|_
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 174.23 seconds
```
We find the information regarding **smb** protocol dialects in there.  

```bash
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|     2:1:0
|     3:0:0
|_    3:0:2
```

## Task 2: Find SMB security level information
Similar to above, the **SMB** security level information is also present in there.
```bash
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

## Task 3: Enumerate active sessions, shares, Windows users, domains, services, etc.

To enumerate active sessions we run the script **smb-enum-sessions**
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p445 --script smb-enum-sessions demo.ine.local                                                                                                                               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 21:42 IST
Nmap scan report for demo.ine.local (10.5.16.46)
Host is up (0.0032s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-sessions: 
|   Users logged in
|_    WIN-OMCNBKR66MN\bob since <unknown>

Nmap done: 1 IP address (1 host up) scanned in 3.37 seconds
```
Since we already have the username and password, we can try to log in into the target system.

```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local                                                             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 21:45 IST
Nmap scan report for demo.ine.local (10.5.16.46)
Host is up (0.0030s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-sessions: 
|   Users logged in
|     WIN-OMCNBKR66MN\bob since 2025-08-07T15:58:30
|   Active SMB sessions
|_    ADMINISTRATOR is connected from \\10.10.36.2 for [just logged in, it's probably you], idle for [not idle]

Nmap done: 1 IP address (1 host up) scanned in 3.40 seconds
```
This lists all the active sessions.  
Next we try to enumerate all active shares. We use the script **smb-enum-shares**.
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p445 --script smb-enum-shares demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 21:49 IST
Nmap scan report for demo.ine.local (10.5.16.46)
Host is up (0.0030s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.5.16.46\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.5.16.46\C: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.5.16.46\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.5.16.46\D$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.5.16.46\Documents: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.5.16.46\Downloads: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.5.16.46\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.5.16.46\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Anonymous access: <none>
|_    Current user access: READ

Nmap done: 1 IP address (1 host up) scanned in 44.39 seconds

```
We notice that the admin has **read/write** access to the whole C drive.  
Now we try to enumerate the windows user on the target machine.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p445 --script smb-enum-users demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 22:07 IST
Nmap scan report for demo.ine.local (10.5.16.46)
Host is up (0.0033s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 4.22 seconds
```
It doesn't give anything, lets try using the username and password.  
```bash
└─# nmap -Pn -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771  demo.ine.local                                                               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 22:13 IST
Nmap scan report for demo.ine.local (10.5.16.46)
Host is up (0.0028s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-users: 
|   WIN-OMCNBKR66MN\Administrator (RID: 500)
|     Description: Built-in account for administering the computer/domain
|     Flags:       Normal user account, Password does not expire
|   WIN-OMCNBKR66MN\bob (RID: 1010)
|     Flags:       Normal user account, Password does not expire
|   WIN-OMCNBKR66MN\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|_    Flags:       Normal user account, Password does not expire, Password not required

Nmap done: 1 IP address (1 host up) scanned in 4.22 seconds
```
We find three accounts, with the guest account requiring no password.  
Next we try to enumerate the domains available.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p445 --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771  demo.ine.local                                                             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 22:20 IST
Nmap scan report for demo.ine.local (10.5.16.46)
Host is up (0.0027s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-domains: 
|   Builtin
|     Groups: Access Control Assistance Operators, Administrators, Backup Operators, Certificate Service DCOM Access, Cryptographic Operators, Distributed COM Users, Event Log Readers, Guests, Hyper-V Administrators, IIS_IUSRS, Network Configuration Operators, Performance Log Users, Performance Monitor Users, Power Users, Print Operators, RDS Endpoint Servers, RDS Management Servers, RDS Remote Access Servers, Remote Desktop Users, Remote Management Users, Replicator, Users
|     Users: n/a
|     Creation time: 2013-08-22T14:47:57
|     Passwords: min length: n/a; min age: n/a days; max age: 42 days; history: n/a passwords
|     Account lockout disabled
|   WIN-OMCNBKR66MN
|     Groups: WinRMRemoteWMIUsers__
|     Users: Administrator, bob, Guest
|     Creation time: 2013-08-22T14:47:57
|     Passwords: min length: n/a; min age: n/a days; max age: 42 days; history: n/a passwords
|     Properties: Complexity requirements exist
|_    Account lockout disabled

Nmap done: 1 IP address (1 host up) scanned in 3.34 seconds
```
We now try to enumerate server-stats.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 22:36 IST
Nmap scan report for demo.ine.local (10.5.21.103)
Host is up (0.0032s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-server-stats: 
|   Server statistics collected since 2025-08-07T17:02:07 (3m55s):
|     1042 bytes (4.43 b/s) sent, 1013 bytes (4.31 b/s) received
|_    0 failed logins, 0 permission errors, 0 system errors, 0 print jobs, 1 files opened

Nmap done: 1 IP address (1 host up) scanned in 1.21 seconds
```
Next we try to enumerate services.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 22:37 IST
Nmap scan report for demo.ine.local (10.5.21.103)
Host is up (0.0030s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-enum-services: 
|   AmazonSSMAgent: 
|     display_name: Amazon SSM Agent
|     state: 
|       SERVICE_PAUSED
|       SERVICE_PAUSE_PENDING
|       SERVICE_CONTINUE_PENDING
|       SERVICE_RUNNING
|     type: 
|       SERVICE_TYPE_WIN32
|       SERVICE_TYPE_WIN32_OWN_PROCESS
|     controls_accepted: 
|       SERVICE_CONTROL_CONTINUE
|       SERVICE_CONTROL_INTERROGATE
|       SERVICE_CONTROL_NETBINDADD
|       SERVICE_CONTROL_NETBINDENABLE                                                                  
|       SERVICE_CONTROL_STOP
|       SERVICE_CONTROL_PARAMCHANGE
|   DiagTrack: 
|     display_name: Diagnostics Tracking Service
|     state: 
|       SERVICE_PAUSED
|       SERVICE_PAUSE_PENDING
|       SERVICE_CONTINUE_PENDING
|       SERVICE_RUNNING
|     type: 
|       SERVICE_TYPE_WIN32
|       SERVICE_TYPE_WIN32_OWN_PROCESS
|     controls_accepted: 
|       SERVICE_CONTROL_CONTINUE
|       SERVICE_CONTROL_INTERROGATE
|       SERVICE_CONTROL_NETBINDADD
|       SERVICE_CONTROL_NETBINDENABLE
|       SERVICE_CONTROL_STOP
|       SERVICE_CONTROL_PARAMCHANGE
|   Ec2Config: 
|     display_name: Ec2Config
|     state: 
|       SERVICE_PAUSED
|       SERVICE_PAUSE_PENDING
|       SERVICE_CONTINUE_PENDING
|       SERVICE_RUNNING
|     type: 
|       SERVICE_TYPE_WIN32
|       SERVICE_TYPE_WIN32_OWN_PROCESS
|     controls_accepted: 
|       SERVICE_CONTROL_CONTINUE
|       SERVICE_CONTROL_INTERROGATE
|       SERVICE_CONTROL_NETBINDADD
|       SERVICE_CONTROL_NETBINDENABLE
|       SERVICE_CONTROL_STOP
|       SERVICE_CONTROL_PARAMCHANGE
|   MSDTC: 
|     display_name: Distributed Transaction Coordinator
|     state: 
|       SERVICE_PAUSED
|       SERVICE_PAUSE_PENDING
|       SERVICE_CONTINUE_PENDING
|       SERVICE_RUNNING
|     type: 
|       SERVICE_TYPE_WIN32
|       SERVICE_TYPE_WIN32_OWN_PROCESS
|     controls_accepted: 
|       SERVICE_CONTROL_CONTINUE
|       SERVICE_CONTROL_INTERROGATE
|       SERVICE_CONTROL_NETBINDADD
|       SERVICE_CONTROL_NETBINDENABLE
|       SERVICE_CONTROL_STOP
|       SERVICE_CONTROL_PARAMCHANGE
|   Spooler: 
|     display_name: Print Spooler
|     state: 
|       SERVICE_PAUSED
|       SERVICE_PAUSE_PENDING
|       SERVICE_CONTINUE_PENDING
|       SERVICE_RUNNING
|     type: 
|       SERVICE_TYPE_WIN32
|       SERVICE_TYPE_WIN32_OWN_PROCESS
|     controls_accepted: 
|       SERVICE_CONTROL_CONTINUE
|       SERVICE_CONTROL_NETBINDADD
|       SERVICE_CONTROL_NETBINDENABLE
|       SERVICE_CONTROL_STOP
|   vds: 
|     display_name: Virtual Disk
|     state: 
|       SERVICE_PAUSED
|       SERVICE_PAUSE_PENDING
|       SERVICE_CONTINUE_PENDING
|       SERVICE_RUNNING
|     type: 
|       SERVICE_TYPE_WIN32
|       SERVICE_TYPE_WIN32_OWN_PROCESS
|     controls_accepted: 
|       SERVICE_CONTROL_CONTINUE
|       SERVICE_CONTROL_NETBINDADD
|       SERVICE_CONTROL_NETBINDENABLE
|_      SERVICE_CONTROL_STOP

Nmap done: 1 IP address (1 host up) scanned in 1.20 seconds
```
We next enumerate all groups.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local                                                                   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 22:40 IST
Nmap scan report for demo.ine.local (10.5.21.103)
Host is up (0.0029s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-groups: 
|   Builtin\Administrators (RID: 544): Administrator, bob
|   Builtin\Users (RID: 545): bob
|   Builtin\Guests (RID: 546): Guest
|   Builtin\Power Users (RID: 547): <empty>
|   Builtin\Print Operators (RID: 550): <empty>
|   Builtin\Backup Operators (RID: 551): <empty>
|   Builtin\Replicator (RID: 552): <empty>
|   Builtin\Remote Desktop Users (RID: 555): bob
|   Builtin\Network Configuration Operators (RID: 556): <empty>
|   Builtin\Performance Monitor Users (RID: 558): <empty>
|   Builtin\Performance Log Users (RID: 559): <empty>
|   Builtin\Distributed COM Users (RID: 562): <empty>
|   Builtin\IIS_IUSRS (RID: 568): <empty>
|   Builtin\Cryptographic Operators (RID: 569): <empty>
|   Builtin\Event Log Readers (RID: 573): <empty>
|   Builtin\Certificate Service DCOM Access (RID: 574): <empty>
|   Builtin\RDS Remote Access Servers (RID: 575): <empty>
|   Builtin\RDS Endpoint Servers (RID: 576): <empty>
|   Builtin\RDS Management Servers (RID: 577): <empty>
|   Builtin\Hyper-V Administrators (RID: 578): <empty>
|   Builtin\Access Control Assistance Operators (RID: 579): <empty>
|   Builtin\Remote Management Users (RID: 580): <empty>
|_  WIN-OMCNBKR66MN\WinRMRemoteWMIUsers__ (RID: 1000): <empty>

Nmap done: 1 IP address (1 host up) scanned in 2.89 seconds
```
Finally we enumerate all shared folders on the machine, we first need to mention the shares and then use the **smb-ls** script to enumerate it. If we use **smb-ls** together with **smb-enum-shares**, **smb-ls** will enumerate all the shares enumerated.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local                                                            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-07 22:48 IST
Nmap scan report for demo.ine.local (10.5.21.103)
Host is up (0.0027s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: administrator
|   \\10.5.21.103\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\Windows
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.5.21.103\C: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.5.21.103\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.5.21.103\D$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Users: 0
|     Max Users: <unlimited>
|     Path: D:\
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.5.21.103\Documents: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\Users\Administrator\Documents
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.5.21.103\Downloads: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\Users\Administrator\Downloads
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.5.21.103\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Users: 1
|     Max Users: <unlimited>
|     Path: 
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.5.21.103\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\Windows\system32\spool\drivers
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
| smb-ls: Volume \\10.5.21.103\ADMIN$
|   maxfiles limit reached (10)
| SIZE   TIME                 FILENAME
| <DIR>  2013-08-22T13:36:16  .
| <DIR>  2013-08-22T13:36:16  ..
| <DIR>  2013-08-22T15:39:31  ADFS
| <DIR>  2013-08-22T15:39:31  ADFS\ar
| <DIR>  2013-08-22T15:39:31  ADFS\bg
| <DIR>  2013-08-22T15:39:31  ADFS\cs
| <DIR>  2013-08-22T15:39:31  ADFS\da
| <DIR>  2013-08-22T15:39:31  ADFS\de
| <DIR>  2013-08-22T15:39:31  ADFS\el
| <DIR>  2013-08-22T15:39:31  ADFS\en
| 
| 
| Volume \\10.5.21.103\C
|   maxfiles limit reached (10)
| SIZE   TIME                 FILENAME
| <DIR>  2013-08-22T15:39:30  PerfLogs
| <DIR>  2013-08-22T13:36:16  Program Files
| <DIR>  2014-05-17T10:36:57  Program Files\Amazon
| <DIR>  2013-08-22T13:36:16  Program Files\Common Files
| <DIR>  2014-10-15T05:58:49  Program Files\DIFX
| <DIR>  2013-08-22T15:39:31  Program Files\Internet Explorer
| <DIR>  2014-07-10T18:40:15  Program Files\Update Services
| <DIR>  2020-08-12T04:13:47  Program Files\Windows Mail
| <DIR>  2013-08-22T15:39:31  Program Files\Windows NT
| <DIR>  2013-08-22T15:39:31  Program Files\WindowsPowerShell
| 
| 
| Volume \\10.5.21.103\C$
|   maxfiles limit reached (10)
| SIZE   TIME                 FILENAME
| <DIR>  2013-08-22T15:39:30  PerfLogs
| <DIR>  2013-08-22T13:36:16  Program Files
| <DIR>  2014-05-17T10:36:57  Program Files\Amazon
| <DIR>  2013-08-22T13:36:16  Program Files\Common Files
| <DIR>  2014-10-15T05:58:49  Program Files\DIFX
| <DIR>  2013-08-22T15:39:31  Program Files\Internet Explorer
| <DIR>  2014-07-10T18:40:15  Program Files\Update Services
| <DIR>  2020-08-12T04:13:47  Program Files\Windows Mail
| <DIR>  2013-08-22T15:39:31  Program Files\Windows NT
| <DIR>  2013-08-22T15:39:31  Program Files\WindowsPowerShell
| 
| 
| Volume \\10.5.21.103\Documents
| SIZE   TIME                 FILENAME
| <DIR>  2020-09-10T09:50:27  .
| <DIR>  2020-09-10T09:50:27  ..
| 
| 
| Volume \\10.5.21.103\Downloads
| SIZE   TIME                 FILENAME
| <DIR>  2020-09-10T09:50:27  .
| <DIR>  2020-09-10T09:50:27  ..
| 
| 
| Volume \\10.5.21.103\print$
|   maxfiles limit reached (10)
| SIZE    TIME                 FILENAME
| <DIR>   2013-08-22T15:39:31  .
| <DIR>   2013-08-22T15:39:31  ..
| <DIR>   2013-08-22T15:39:31  color
| 1058    2013-08-22T06:54:44  color\D50.camp
| 1079    2013-08-22T06:54:44  color\D65.camp
| 797     2013-08-22T06:54:44  color\Graphics.gmmp
| 838     2013-08-22T06:54:44  color\MediaSim.gmmp
| 786     2013-08-22T06:54:44  color\Photo.gmmp
| 822     2013-08-22T06:54:44  color\Proofing.gmmp
| 218103  2013-08-22T06:54:44  color\RSWOP.icm
|_

Nmap done: 1 IP address (1 host up) scanned in 55.71 seconds
```