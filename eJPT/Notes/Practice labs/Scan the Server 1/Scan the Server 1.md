## Scan the Server 1

### Target
`demo.ine.local`

### Tools used:
* `nmap`

### Objective
Perform port scanning and service detection with Nmap.

---
We first do a normal `nmap` scan.  
```bash
┌──(root㉿INE)-[~]
└─# nmap demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-06 23:41 IST
Nmap scan report for demo.ine.local (192.182.132.3)
Host is up (0.000024s latency).
All 1000 scanned ports on demo.ine.local (192.182.132.3) are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 02:42:C0:B6:84:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
```
Since no open ports are found amongst the 1000 common ports we do a scan for all the ports.
```bash
┌──(root㉿INE)-[~]
└─# nmap -p- -v demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-06 23:41 IST
Initiating ARP Ping Scan at 23:41
Scanning demo.ine.local (192.182.132.3) [1 port]
Completed ARP Ping Scan at 23:41, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 23:41
Scanning demo.ine.local (192.182.132.3) [65535 ports]
Discovered open port 6421/tcp on 192.182.132.3
Discovered open port 41288/tcp on 192.182.132.3
Discovered open port 55413/tcp on 192.182.132.3
Completed SYN Stealth Scan at 23:41, 2.14s elapsed (65535 total ports)
Nmap scan report for demo.ine.local (192.182.132.3)
Host is up (0.000023s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
6421/tcp  open  nim-wan
41288/tcp open  unknown
55413/tcp open  unknown
MAC Address: 02:42:C0:B6:84:03 (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.30 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```
Since we know the open ports, let's run a service version scan using the **-sV** flag.
```bash
┌──(root㉿INE)-[~]
└─# nmap -p6421,41288,55413 -sV -v demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-06 23:44 IST
NSE: Loaded 46 scripts for scanning.
Initiating ARP Ping Scan at 23:44                                                                                                                                                          
Scanning demo.ine.local (192.182.132.3) [1 port]
Completed ARP Ping Scan at 23:44, 0.03s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 23:44
Scanning demo.ine.local (192.182.132.3) [3 ports]
Discovered open port 41288/tcp on 192.182.132.3
Discovered open port 6421/tcp on 192.182.132.3
Discovered open port 55413/tcp on 192.182.132.3
Completed SYN Stealth Scan at 23:44, 0.01s elapsed (3 total ports)
Initiating Service scan at 23:44
Scanning 3 services on demo.ine.local (192.182.132.3)
Completed Service scan at 23:44, 11.03s elapsed (3 services on 1 host)
NSE: Script scanning 192.182.132.3.
Initiating NSE at 23:44
Completed NSE at 23:44, 0.00s elapsed
Initiating NSE at 23:44
Completed NSE at 23:44, 0.00s elapsed
Nmap scan report for demo.ine.local (192.182.132.3)
Host is up (0.000029s latency).

PORT      STATE SERVICE   VERSION
6421/tcp  open  mongodb   MongoDB 2.6.10
41288/tcp open  memcached Memcached
55413/tcp open  ftp       vsftpd 3.0.3
MAC Address: 02:42:C0:B6:84:03 (Unknown)
Service Info: OS: Unix

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.33 seconds
           Raw packets sent: 4 (160B) | Rcvd: 4 (160B)
```