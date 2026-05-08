## Scan the Server 2

### Target
`demo.ine.local`

### Tools used:
* `nmap`

### Objective 1:  Identify the port running a Bind DNS server.

---
We skip the host discovery and start with a basic scan to find the open ports.
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 11:53 IST
Nmap scan report for demo.ine.local (192.249.197.3)
Host is up (0.000026s latency).
All 1000 scanned ports on demo.ine.local (192.249.197.3) are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 02:42:C0:F9:C5:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds
```
Since none of the ports in the top 1000 are visible, we switch to a scan of all the possible ports
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p- demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 11:54 IST
Nmap scan report for demo.ine.local (192.249.197.3)
Host is up (0.000025s latency).
Not shown: 65534 closed tcp ports (reset)
PORT    STATE SERVICE
177/tcp open  xdmcp
MAC Address: 02:42:C0:F9:C5:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.31 seconds
```
It looks like `port 177` is open. We focus on this port and try to find the service running on it.
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p177 -sV demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 11:54 IST
Nmap scan report for demo.ine.local (192.249.197.3)
Host is up (0.000049s latency).

PORT    STATE SERVICE VERSION
177/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
MAC Address: 02:42:C0:F9:C5:03 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.32 seconds

┌──(root㉿INE)-[~]                                                                                                                                                                         
└─# nmap -Pn -p177 -sV -A demo.ine.local                                                                                                                                                   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 11:58 IST
Nmap scan report for demo.ine.local (192.249.197.3)
Host is up (0.000075s latency).

PORT    STATE SERVICE VERSION
177/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
MAC Address: 02:42:C0:F9:C5:03 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.08 ms demo.ine.local (192.249.197.3)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.71 seconds
```
The port running `BIND DNS` is `port 177`
---
### Objective 2: Identify the port running the SNMP server

---
Since we couldn't find anything via a `TCP scan`, we then switch to a `UDP scan`. Since the TFTP is usually present at `port 69`, we try to scan the first 250 ports only.
```bash
┌──(root㉿INE)-[~]
└─# nmap demo.ine.local -p 1-250 -sU -v                                                                                                                                                                                                    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 12:10 IST
Initiating ARP Ping Scan at 12:10
Scanning demo.ine.local (192.249.197.3) [1 port]
Completed ARP Ping Scan at 12:10, 0.04s elapsed (1 total hosts)
Initiating UDP Scan at 12:10
Scanning demo.ine.local (192.249.197.3) [250 ports]
Increasing send delay for 192.249.197.3 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 192.249.197.3 from 50 to 100 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.249.197.3 from 100 to 200 due to 11 out of 12 dropped probes since last increase.
UDP Scan Timing: About 38.27% done; ETC: 12:11 (0:00:50 remaining)
Increasing send delay for 192.249.197.3 from 200 to 400 due to 11 out of 12 dropped probes since last increase.
Increasing send delay for 192.249.197.3 from 400 to 800 due to 11 out of 15 dropped probes since last increase.
UDP Scan Timing: About 61.13% done; ETC: 12:12 (0:00:52 remaining)
UDP Scan Timing: About 77.47% done; ETC: 12:13 (0:00:36 remaining)
Completed UDP Scan at 12:13, 211.82s elapsed (250 total ports)
Nmap scan report for demo.ine.local (192.249.197.3)
Host is up (0.000088s latency).
Not shown: 201 closed udp ports (port-unreach)
PORT    STATE         SERVICE
2/udp   open|filtered compressnet
9/udp   open|filtered discard
16/udp  open|filtered unknown
21/udp  open|filtered ftp
23/udp  open|filtered telnet
29/udp  open|filtered msg-icp
30/udp  open|filtered unknown
32/udp  open|filtered unknown
45/udp  open|filtered mpm
46/udp  open|filtered mpm-snd
55/udp  open|filtered isi-gl
56/udp  open|filtered xns-auth
57/udp  open|filtered priv-term
73/udp  open|filtered netrjs-3
81/udp  open|filtered hosts2-ns
91/udp  open|filtered mit-dov
97/udp  open|filtered swift-rvf
108/udp open|filtered snagas
111/udp open|filtered rpcbind
113/udp open|filtered auth
117/udp open|filtered uucp-path
121/udp open|filtered erpc
124/udp open|filtered ansatrader
126/udp open|filtered unitary
128/udp open|filtered gss-xlicen
130/udp open|filtered cisco-fna
133/udp open|filtered statsrv
134/udp open|filtered ingres-net
135/udp open|filtered msrpc
138/udp open|filtered netbios-dgm
141/udp open|filtered emfis-cntl
148/udp open|filtered cronus
150/udp open|filtered sql-net
151/udp open|filtered hems
154/udp open|filtered netsc-prod
156/udp open|filtered sqlsrv
168/udp open|filtered rsvd
170/udp open|filtered print-srv
171/udp open|filtered multiplex
173/udp open|filtered xyplex-mux
177/udp open|filtered xdmcp
182/udp open|filtered audit
194/udp open|filtered irc
212/udp open|filtered anet
216/udp open|filtered atls
219/udp open|filtered uarps
223/udp open|filtered cdc
234/udp open|filtered unknown
246/udp open|filtered dsp3270
MAC Address: 02:42:C0:F9:C5:03 (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 211.92 seconds
           Raw packets sent: 708 (22.352KB) | Rcvd: 216 (12.571KB)
```
There seems to be a lot of services running on the UDP ports. We switch next to the types of services running on these ports. For the sake of this lab, we focus only on the ports: `134,177,234`. Running a version scan gives us the following result.
```bash
┌──(root㉿INE)-[~]
└─# nmap demo.ine.local -p177,234,134 -sUV                                                                                                                                                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 12:21 IST
Nmap scan report for demo.ine.local (192.249.197.3)
Host is up (0.000042s latency).

PORT    STATE         SERVICE    VERSION
134/udp open|filtered ingres-net
177/udp open          domain     ISC BIND 9.10.3-P4 (Ubuntu Linux)
234/udp open          snmp       SNMPv1 server; net-snmp SNMPv3 server (public)
MAC Address: 02:42:C0:F9:C5:03 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.22 seconds
```
We can see that `SNMP` service is running on `port 234`

---
### Objective 3: Identify the port running a TFTP server.

---
For the final service, we just directly try to connect to `port 134`.
```bash
┌──(root㉿INE)-[~]
└─# tftp demo.ine.local 134                                                                                                                                                                
tftp> q
```
Therefore the `tftp` service is running on `port 134`