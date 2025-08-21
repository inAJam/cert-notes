# Postfix Recon: Basics

### Target:
`demo.ine.local`

### What is the SMTP server name and banner?
```bash
┌──(root㉿INE)-[~]
└─# nmap -p 25 --script banner demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-10 23:41 IST
Nmap scan report for demo.ine.local (192.2.140.3)
Host is up (0.000050s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_banner: 220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.
MAC Address: 02:42:C0:02:8C:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds
```
Banner: **openmailbox.xyz ESMTP Postfix: Welcome to our mail server**
Server name: **openmailbox.xyz**

### Connect to SMTP service using netcat and retrieve the hostname of the server (domain name)
```bash
┌──(root㉿INE)-[~]                                                                      
└─# nc demo.ine.local 25                       
220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server. 
```
Hostname: **openmailbox.xyz**

###  Does user "admin" exist on the server machine? Connect to SMTP service using netcat and check manually
```bash
┌──(root㉿INE)-[~]                                                                                                                                                                                                                         
└─# nc demo.ine.local 25                                                             
220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.                                      
VRFY admin
252 2.0.0 admin
```
Answer: **Yes**

### Does user "commander" exist on the server machine? Connect to SMTP service using netcat and check manually
```bash
┌──(root㉿INE)-[~]                                                                                                                                                                                                                         
└─# nc demo.ine.local 25                                                                                                                                                                                                                   
220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.                                                                                                                                                                             
VRFY admin
252 2.0.0 admin
VRFY commander
550 5.1.1 <commander>: Recipient address rejected: User unknown in local recipient table
```
Answer: **No**

### What commands can be used to check the supported commands/capabilities? Connect to SMTP service using telnet and check.
The commands `ehlo` and `helo` can be used to check for supported commands/capabilities.
```bash
┌──(root㉿INE)-[~]
└─# telnet demo.ine.local 25                                                                                                                                                                                                               
Trying 192.2.140.3...
Connected to demo.ine.local.
Escape character is '^]'.
220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.
helo abc.xyz
250 openmailbox.xyz
ehlo abc.abc
250-openmailbox.xyz
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250 SMTPUTF8
```

Answer: **ehlo**, **helo**

### How many of the common usernames present in the dictionary /usr/share/commix/src/txt/usernames.txt exist on the server. Use smtp-user-enum tool for this task.
We just directly use `smtp-user-enum` via the command lin to get the answer.
```bash
┌──(root㉿INE)-[~]
└─# smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t demo.ine.local                                                                                                                                                            
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... /usr/share/commix/src/txt/usernames.txt
Target count ............. 1
Username count ........... 125
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Sun Aug 10 23:59:38 2025 #########
 existse.local: admin
 existse.local: administrator
 existse.local: mail
 existse.local: postmaster
 existse.local: root
 existse.local: sales
 existse.local: support
demo.ine.local: www-data exists
######## Scan completed at Sun Aug 10 23:59:38 2025 #########
8 results.

125 queries in 1 seconds (125.0 queries / sec)
```
Answer: 8


###  How many common usernames present in the dictionary /usr/share/metasploit-framework/data/wordlists/unix_users.txt exist on the server. Use suitable metasploit module for this task
We boot up **msf** and use the smtp_enum module with the proper flags.
```bash
msf6 auxiliary(scanner/smtp/smtp_enum) > setg RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 auxiliary(scanner/smtp/smtp_enum) > set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt 
USER_FILE => /usr/share/metasploit-framework/data/wordlists/unix_users.txt
msf6 auxiliary(scanner/smtp/smtp_enum) > run

[*] 192.2.140.3:25        - 192.2.140.3:25 Banner: 220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.
[+] 192.2.140.3:25        - 192.2.140.3:25 Users found: , _apt, admin, administrator, backup, bin, daemon, games, gnats, irc, list, lp, mail, man, news, nobody, postfix, postmaster, proxy, sync, sys, uucp, www-data
[*] demo.ine.local:25     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smtp/smtp_enum) > 
```
Answer: **22**

### Connect to SMTP service using telnet and send a fake mail to root user
```bash
┌──(root㉿INE)-[~]
└─# telnet demo.ine.local 25      
Trying 192.2.140.3...
Connected to demo.ine.local.
Escape character is '^]'.
220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.
helo dupe.abc
250 openmailbox.xyz
mail from abc@dup
501 5.5.4 Syntax: MAIL FROM:<address>
mail from: abc@duped.abc
250 2.1.0 Ok
rcpt to: root@openmailbox.xyz
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
Subject: hi root,
long time no see.
hope to never se you again.
bye
.                 
250 2.0.0 Ok: queued as 892257034AF
```

### Send a fake mail to root user using sendemail command
We use the inbuilt `sendemail` tool to do this task.
```bash
┌──(root㉿INE)-[~]
└─# sendemail -f dupe@duped.abc -t root@openmailbox.xyz -u "hello again root!" -m "no contact pls" -s demo.ine.local  
Aug 11 00:20:29 ine sendemail[10821]: ERROR => TLS setup failed: SSL connect attempt failed error:0A000086:SSL routines::certificate verify failed
┌──(root㉿INE)-[~]
└─# sendemail -f dupe@duped.abc -t root@openmailbox.xyz -u "hello again root!" -m "no contact pls" -s demo.ine.local            
Aug 11 00:20:29 ine sendemail[10821]: ERROR => TLS setup failed: SSL connect attempt failed error:0A000086:SSL routines::certificate verify failed
```
We set the **tls** to no since the original server does not use it.