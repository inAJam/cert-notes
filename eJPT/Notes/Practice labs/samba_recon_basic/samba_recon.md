# Samba Recon: Basics

### Target:
`demo.ine.local`

### Tools:
* `nmap`
* `Metasploit`
* `smbclient`
* `rpcclient`

---

### Flag 1: Find the default tcp ports used by smbd
For this one we just run the `nmap` for a **TCP** scan.
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -sV demo.ine.local -oX samba_recon.XML
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-10 00:30 IST
Nmap scan report for demo.ine.local (192.14.127.3)
Host is up (0.000027s latency).
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
MAC Address: 02:42:C0:0E:7F:03 (Unknown)
Service Info: Host: SAMBA-RECON

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.44 seconds
```
From the above scan we discover lot's of interesting stuff like:
* Host Name: **SAMBA-RECON**
* WorkGroup: **RECONLABS**
* The ports used for the SAMBA services
Answer: **139**,**445**

### Flag 2: Find the default udp ports used by nmbd
`nmbd` is one of the two main daemons in Samba (the other is `smbd`). It handles NetBIOS over UDP/IP functions for SMB/CIFS networking and has two services **NetBIOS Name Service** and **NetBIOS Datagram Service**. To find these service we do a **UDP** port scan of the most common ports.
```bash
msf6 > db_nmap -Pn -sU 192.14.127.3 --top-ports 25
[*] Nmap: Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-10 00:36 IST
[*] Nmap: Nmap scan report for demo.ine.local (192.14.127.3)
[*] Nmap: Host is up (0.000092s latency).
[*] Nmap: PORT      STATE         SERVICE
[*] Nmap: 53/udp    closed        domain
[*] Nmap: 67/udp    closed        dhcps
[*] Nmap: 68/udp    closed        dhcpc
[*] Nmap: 69/udp    closed        tftp
[*] Nmap: 111/udp   closed        rpcbind
[*] Nmap: 123/udp   closed        ntp
[*] Nmap: 135/udp   closed        msrpc
[*] Nmap: 137/udp   open          netbios-ns
[*] Nmap: 138/udp   open|filtered netbios-dgm
[*] Nmap: 139/udp   closed        netbios-ssn
[*] Nmap: 161/udp   closed        snmp
[*] Nmap: 162/udp   closed        snmptrap
[*] Nmap: 445/udp   closed        microsoft-ds
[*] Nmap: 500/udp   closed        isakmp
[*] Nmap: 514/udp   closed        syslog
[*] Nmap: 520/udp   closed        route
[*] Nmap: 631/udp   closed        ipp
[*] Nmap: 998/udp   closed        puparp
[*] Nmap: 1434/udp  closed        ms-sql-m
[*] Nmap: 1701/udp  closed        L2TP
[*] Nmap: 1900/udp  closed        upnp
[*] Nmap: 4500/udp  closed        nat-t-ike
[*] Nmap: 5353/udp  closed        zeroconf
[*] Nmap: 49152/udp closed        unknown
[*] Nmap: 49154/udp closed        unknown
[*] Nmap: MAC Address: 02:42:C0:0E:7F:03 (Unknown)
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 22.50 seconds
```
We see that the ports **137** and **138** are running the name service and the datagram service respectively.
Answer: **137**,**138**

###  Flag 3: What is the workgroup name of samba server?
From Flag 1
Answer: **RECONLABS**

### Flag 4: Find the exact version of samba server by using appropriate nmap script
To find the specific version, we run the script **smb-os-discovery** over `nmap`
```bash
msf6 > db_nmap -Pn -p 139,445 192.14.127.3 --script smb-os-discovery
[*] Nmap: Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-10 00:42 IST
[*] Nmap: Nmap scan report for demo.ine.local (192.14.127.3)
[*] Nmap: Host is up (0.000045s latency).
[*] Nmap: PORT    STATE SERVICE
[*] Nmap: 139/tcp open  netbios-ssn
[*] Nmap: 445/tcp open  microsoft-ds
[*] Nmap: MAC Address: 02:42:C0:0E:7F:03 (Unknown)
[*] Nmap: Host script results:
[*] Nmap: | smb-os-discovery:
[*] Nmap: |   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
[*] Nmap: |   Computer name: demo
[*] Nmap: |   NetBIOS computer name: SAMBA-RECON\x00
[*] Nmap: |   Domain name: ine.local
[*] Nmap: |   FQDN: demo.ine.local
[*] Nmap: |_  System time: 2025-08-09T19:12:50+00:00
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
msf6 > 
```
Answer: **Samba 4.3.11-Ubuntu**

### Flag 5: Find the exact version of samba server by using smb_version metasploit module.
For this flag, we set up the **MSF** and then load up the **smb_version** module. Then we set up the proper options and run the module.
```bash
msf6 auxiliary(scanner/smb/smb_version) > setg RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 auxiliary(scanner/smb/smb_version) > set RPORT 445
RPORT => 445
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 192.14.127.3:445      - SMB Detected (versions:1, 2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:) (encryption capabilities:AES-128-CCM) (signatures:optional) (guid:{626d6173-2d61-6572-636f-6e0000000000}) (authentication domain:SAMBA-RECON)
[*] 192.14.127.3:445      -   Host could not be identified: Windows 6.1 (Samba 4.3.11-Ubuntu)
[*] demo.ine.local:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/smb_version) > 
```
Answer: **Samba 4.3.11-Ubuntu**

### Flag 6: What is the NetBIOS computer name of samba server? Use appropriate nmap scripts
From Flag 1
Answer: **SAMBA-RECON**

### Flag 7: Find the NetBIOS computer name of samba server using nmblookup
We just run `nmblookup` to get the result.
```bash
┌──(root㉿INE)-[~]                                                                                                                                                                                                                         
└─# nmblookup -A demo.ine.local
Looking up status of 192.14.127.3                                                                                                                                                                                                          
        SAMBA-RECON     <00> -         H <ACTIVE>                                                                                                                                                                                          
        SAMBA-RECON     <03> -         H <ACTIVE>                                                                                                                                                                                          
        SAMBA-RECON     <20> -         H <ACTIVE>                                                                                                                                                                                          
        ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE>                                                                                                                                                                                          
        RECONLABS       <00> - <GROUP> H <ACTIVE> 
        RECONLABS       <1d> -         H <ACTIVE> 
        RECONLABS       <1e> - <GROUP> H <ACTIVE> 

        MAC Address = 00-00-00-00-00-00
```
Answer: **SAMBA-RECON**

### Flag 8: Using smbclient determine whether anonymous connection (null session) is allowed on the samba server or not
Starting a **null session** means keeping the username and password empty. We don't supply the username and password and run the command.
```bash
┌──(root㉿INE)-[~]
└─# smbclient -L demo.ine.local -N                                                                                                                                                                                                        

        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      
        john            Disk      
        aisha           Disk      
        emma            Disk      
        everyone        Disk      
        IPC$            IPC       IPC Service (samba.recon.lab)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        RECONLABS            SAMBA-RECON

┌──(root㉿INE)-[~]
```
We quickly notice that we can easily see the sahres available. This shows that a null session is allowed.
Answer: **Anonymous connection is allowed**

### Flag 9: Using rpcclient determine whether anonymous connection (null session) is allowed on the samba server or not
Same as Flag 8, we set the proper parameters and run it.
```bash
┌──(root㉿INE)-[~]
└─# rpcclient -U "" -N demo.ine.local                                                                                                                                                                                                     
rpcclient $> 
```
Since the `rpcclient` shows no error, that means that a null session is allowed.
Answer: **Allowed**