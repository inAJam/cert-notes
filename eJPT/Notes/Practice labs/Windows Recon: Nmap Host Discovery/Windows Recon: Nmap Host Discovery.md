### Target
`demo.ine.local`

### Objective:
Discover available live hosts and their open ports using Nmap and identify the running services and applications.

### Tools used:
* `nmap`

---
Since we are already given the target, we skip the host discovery phase and try to find the open ports.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -v  -T4 demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-06 23:32 IST
Initiating SYN Stealth Scan at 23:32
Scanning demo.ine.local (10.5.21.50) [1000 ports]
Discovered open port 139/tcp on 10.5.21.50
Discovered open port 445/tcp on 10.5.21.50
Discovered open port 135/tcp on 10.5.21.50
Discovered open port 3389/tcp on 10.5.21.50
Discovered open port 80/tcp on 10.5.21.50
Discovered open port 49154/tcp on 10.5.21.50
Discovered open port 49155/tcp on 10.5.21.50
Completed SYN Stealth Scan at 23:32, 4.30s elapsed (1000 total ports)
Nmap scan report for demo.ine.local (10.5.21.50)                                                                                                                                           
Host is up (0.0035s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49154/tcp open  unknown
49155/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 4.34 seconds
           Raw packets sent: 1995 (87.780KB) | Rcvd: 9 (396B)

```
Now to identify the running services and applications we use the **-sV** flag on the given ports.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -sV -T4 -v demo.ine.local                                                                                                                                                     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-06 23:35 IST
NSE: Loaded 46 scripts for scanning.
Initiating SYN Stealth Scan at 23:35
Scanning demo.ine.local (10.5.21.50) [1000 ports]
Discovered open port 139/tcp on 10.5.21.50
Discovered open port 445/tcp on 10.5.21.50
Discovered open port 135/tcp on 10.5.21.50
Discovered open port 3389/tcp on 10.5.21.50
Discovered open port 80/tcp on 10.5.21.50
Discovered open port 49154/tcp on 10.5.21.50
Discovered open port 49155/tcp on 10.5.21.50
Completed SYN Stealth Scan at 23:35, 4.48s elapsed (1000 total ports)
Initiating Service scan at 23:35
Scanning 7 services on demo.ine.local (10.5.21.50)
Completed Service scan at 23:36, 65.09s elapsed (7 services on 1 host)
NSE: Script scanning 10.5.21.50.
Initiating NSE at 23:36
Completed NSE at 23:36, 0.05s elapsed
Initiating NSE at 23:36
Completed NSE at 23:36, 0.03s elapsed
Nmap scan report for demo.ine.local (10.5.21.50)
Host is up (0.0036s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT      STATE SERVICE            VERSION
80/tcp    open  http               HttpFileServer httpd 2.3
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.86 seconds
           Raw packets sent: 1993 (87.692KB) | Rcvd: 7 (308B)
```