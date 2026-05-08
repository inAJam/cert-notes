## Scan the Server 3

### Target
`demo.ine.local`

### Tools used:
* `nmap`

### Objective 1: 
This lab covers the process of performing port scanning and service detection with Nmap.

---
We first try to scan the common TCP ports
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 12:30 IST
Nmap scan report for demo.ine.local (192.115.201.3)
Host is up (0.000025s latency).
All 1000 scanned ports on demo.ine.local (192.115.201.3) are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 02:42:C0:73:C9:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.14 seconds
```
Since we didn't get any open ports, wwe do a full scan of all ports.
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p- -T4 demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 12:31 IST
Nmap scan report for demo.ine.local (192.115.201.3)
Host is up (0.000025s latency).
All 65535 scanned ports on demo.ine.local (192.115.201.3) are in ignored states.
Not shown: 65535 closed tcp ports (reset)
MAC Address: 02:42:C0:73:C9:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.31 seconds
```
From this we can conclude that the TCP ports are all closed. We then switch to UDP ports.
```bash
┌──(root㉿INE)-[~]
└─# nmap -sU -Pn -p1-250 -T4 demo.ine.local -v
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 12:33 IST
Initiating ARP Ping Scan at 12:33
Scanning demo.ine.local (192.115.201.3) [1 port]
Completed ARP Ping Scan at 12:33, 0.03s elapsed (1 total hosts)
Initiating UDP Scan at 12:33
Scanning demo.ine.local (192.115.201.3) [250 ports]
Discovered open port 161/udp on 192.115.201.3
Increasing send delay for 192.115.201.3 from 0 to 50 due to 11 out of 16 dropped probes since last increase.
Increasing send delay for 192.115.201.3 from 50 to 100 due to 11 out of 11 dropped probes since last increase.
UDP Scan Timing: About 42.53% done; ETC: 12:35 (0:00:42 remaining)
Increasing send delay for 192.115.201.3 from 100 to 200 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.115.201.3 from 200 to 400 due to 11 out of 11 dropped probes since last increase.                                                                            
Increasing send delay for 192.115.201.3 from 400 to 800 due to 11 out of 11 dropped probes since last increase.
UDP Scan Timing: About 64.47% done; ETC: 12:35 (0:00:40 remaining)
Completed UDP Scan at 12:37, 199.30s elapsed (250 total ports)
Nmap scan report for demo.ine.local (192.115.201.3)
Host is up (0.00011s latency).
Not shown: 190 closed udp ports (port-unreach), 59 open|filtered udp ports (no-response)
PORT    STATE SERVICE
161/udp open  snmp
MAC Address: 02:42:C0:73:C9:03 (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 199.39 seconds
           Raw packets sent: 777 (25.408KB) | Rcvd: 206 (11.834KB)
```
Looks like port 161 is running the `SNMP` service, running a service version scan on this port leads us to the following
```bash
┌──(root㉿INE)-[~]
└─# nmap -sUV -Pn -p161 -T4 demo.ine.local -v -A                                                                                                                                                                                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-01 12:38 IST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Initiating ARP Ping Scan at 12:38
Scanning demo.ine.local (192.115.201.3) [1 port]
Completed ARP Ping Scan at 12:38, 0.04s elapsed (1 total hosts)
Initiating UDP Scan at 12:38
Scanning demo.ine.local (192.115.201.3) [1 port]
Discovered open port 161/udp on 192.115.201.3
Completed UDP Scan at 12:38, 0.11s elapsed (1 total ports)
Initiating Service scan at 12:38
Initiating OS detection (try #1) against demo.ine.local (192.115.201.3)
Retrying OS detection (try #2) against demo.ine.local (192.115.201.3)
NSE: Script scanning 192.115.201.3.
Initiating NSE at 12:38
Completed NSE at 12:38, 1.90s elapsed
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Nmap scan report for demo.ine.local (192.115.201.3)
Host is up (0.000052s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-netstat: 
|   TCP  127.0.0.1:22         0.0.0.0:0
|   TCP  127.0.0.1:22         127.0.0.1:41612
|   TCP  127.0.0.1:1313       0.0.0.0:0
|   TCP  127.0.0.1:41612      127.0.0.1:22
|   TCP  127.0.0.11:36009     0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:55557        *:*
|_  UDP  127.0.0.11:60648     *:*
| snmp-sysdescr: Linux demo.ine.local 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul  5 10:34:03 UTC 2024 x86_64
|_  System uptime: 9m1.60s (54160 timeticks)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 0b3e7b2c441b566900000000
|   snmpEngineBoots: 1
|_  snmpEngineTime: 9m02s
| snmp-win32-software: 
|   adduser-3.113+nmu3ubuntu4; 0-01-01T00:00:00
|   apt-1.2.29ubuntu0.1; 0-01-01T00:00:00
|   autotools-dev-20150820.1; 0-01-01T00:00:00
|   base-files-9.4ubuntu4.8; 0-01-01T00:00:00
|   base-passwd-3.5.39; 0-01-01T00:00:00
|   bash-4.3-14ubuntu1.2; 0-01-01T00:00:00
|   binutils-2.26.1-1ubuntu1~16.04.8; 0-01-01T00:00:00
|   bsdutils-1:2.27.1-6ubuntu3.6; 0-01-01T00:00:00
|   build-essential-12.1ubuntu2; 0-01-01T00:00:00
|   bzip2-1.0.6-8ubuntu0.1; 0-01-01T00:00:00
|   ca-certificates-20170717~16.04.2; 0-01-01T00:00:00
|   coreutils-8.25-2ubuntu3~16.04; 0-01-01T00:00:00
|   cpp-4:5.3.1-1ubuntu1; 0-01-01T00:00:00
|   cpp-5-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   dash-0.5.8-2.1ubuntu2; 0-01-01T00:00:00
|   debconf-1.5.58ubuntu1; 0-01-01T00:00:00
|   debianutils-4.7; 0-01-01T00:00:00
|   dh-python-2.20151103ubuntu1.1; 0-01-01T00:00:00
|   diffutils-1:3.3-3; 0-01-01T00:00:00
|   dpkg-1.18.4ubuntu1.5; 0-01-01T00:00:00
|   dpkg-dev-1.18.4ubuntu1.5; 0-01-01T00:00:00
|   e2fslibs-1.42.13-1ubuntu1; 0-01-01T00:00:00
|   e2fsprogs-1.42.13-1ubuntu1; 0-01-01T00:00:00
|   fakeroot-1.20.2-1ubuntu1; 0-01-01T00:00:00
|   file-1:5.25-2ubuntu1.2; 0-01-01T00:00:00
|   findutils-4.6.0+git+20160126-2; 0-01-01T00:00:00
|   g++-4:5.3.1-1ubuntu1; 0-01-01T00:00:00
|   g++-5-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   gcc-4:5.3.1-1ubuntu1; 0-01-01T00:00:00
|   gcc-5-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   gcc-5-base-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   gcc-6-base-6.0.1-0ubuntu1; 0-01-01T00:00:00
|   gnupg-1.4.20-1ubuntu3.3; 0-01-01T00:00:00
|   gpgv-1.4.20-1ubuntu3.3; 0-01-01T00:00:00
|   grep-2.25-1~16.04.1; 0-01-01T00:00:00
|   gzip-1.6-4ubuntu1; 0-01-01T00:00:00
|   hostname-3.16ubuntu2; 0-01-01T00:00:00
|   ifupdown-0.8.10ubuntu1.4; 0-01-01T00:00:00
|   init-1.29ubuntu4; 0-01-01T00:00:00
|   init-system-helpers-1.29ubuntu4; 0-01-01T00:00:00
|   initscripts-2.88dsf-59.3ubuntu2; 0-01-01T00:00:00
|   insserv-1.14.0-5ubuntu3; 0-01-01T00:00:00
|   iproute2-4.3.0-1ubuntu3.16.04.5; 0-01-01T00:00:00
|   isc-dhcp-client-4.3.3-5ubuntu12.10; 0-01-01T00:00:00
|   isc-dhcp-common-4.3.3-5ubuntu12.10; 0-01-01T00:00:00
|   krb5-locales-1.13.2+dfsg-5ubuntu2.1; 0-01-01T00:00:00
|   libacl1-2.2.52-3; 0-01-01T00:00:00
|   libalgorithm-diff-perl-1.19.03-1; 0-01-01T00:00:00
|   libalgorithm-diff-xs-perl-0.04-4build1; 0-01-01T00:00:00
|   libalgorithm-merge-perl-0.08-3; 0-01-01T00:00:00
|   libapparmor1-2.10.95-0ubuntu2.10; 0-01-01T00:00:00
|   libapt-pkg5.0-1.2.29ubuntu0.1; 0-01-01T00:00:00
|   libasan2-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libatm1-1:2.5.1-1.5; 0-01-01T00:00:00
|   libatomic1-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libattr1-1:2.4.47-2; 0-01-01T00:00:00
|   libaudit-common-1:2.4.5-1ubuntu2.1; 0-01-01T00:00:00
|   libaudit1-1:2.4.5-1ubuntu2.1; 0-01-01T00:00:00
|   libblkid1-2.27.1-6ubuntu3.6; 0-01-01T00:00:00
|   libbsd0-0.8.2-1; 0-01-01T00:00:00
|   libbz2-1.0-1.0.6-8ubuntu0.1; 0-01-01T00:00:00
|   libc-bin-2.23-0ubuntu11; 0-01-01T00:00:00
|   libc-dev-bin-2.23-0ubuntu11; 0-01-01T00:00:00
|   libc6-2.23-0ubuntu11; 0-01-01T00:00:00
|   libc6-dev-2.23-0ubuntu11; 0-01-01T00:00:00
|   libcap2-1:2.24-12; 0-01-01T00:00:00
|   libcap2-bin-1:2.24-12; 0-01-01T00:00:00
|   libcc1-0-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libcilkrts5-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libcomerr2-1.42.13-1ubuntu1; 0-01-01T00:00:00
|   libcryptsetup4-2:1.6.6-5ubuntu2.1; 0-01-01T00:00:00
|   libdb5.3-5.3.28-11ubuntu0.1; 0-01-01T00:00:00
|   libdebconfclient0-0.198ubuntu1; 0-01-01T00:00:00
|   libdevmapper1.02.1-2:1.02.110-1ubuntu10; 0-01-01T00:00:00
|   libdns-export162-1:9.10.3.dfsg.P4-8ubuntu1.14; 0-01-01T00:00:00
|   libdpkg-perl-1.18.4ubuntu1.5; 0-01-01T00:00:00
|   libedit2-3.1-20150325-1ubuntu2; 0-01-01T00:00:00
|   libexpat1-2.1.0-7ubuntu0.16.04.4; 0-01-01T00:00:00
|   libfakeroot-1.20.2-1ubuntu1; 0-01-01T00:00:00
|   libfdisk1-2.27.1-6ubuntu3.6; 0-01-01T00:00:00
|   libffi6-3.2.1-4; 0-01-01T00:00:00
|   libfile-fcntllock-perl-0.22-3; 0-01-01T00:00:00
|   libgcc-5-dev-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libgcc1-1:6.0.1-0ubuntu1; 0-01-01T00:00:00
|   libgcrypt20-1.6.5-2ubuntu0.5; 0-01-01T00:00:00
|   libgdbm3-1.8.3-13.1; 0-01-01T00:00:00
|   libgmp10-2:6.1.0+dfsg-2; 0-01-01T00:00:00
|   libgomp1-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libgpg-error0-1.21-2ubuntu1; 0-01-01T00:00:00
|   libgpm2-1.20.4-6.1; 0-01-01T00:00:00
|   libgssapi-krb5-2-1.13.2+dfsg-5ubuntu2.1; 0-01-01T00:00:00
|   libidn11-1.32-3ubuntu1.2; 0-01-01T00:00:00
|   libisc-export160-1:9.10.3.dfsg.P4-8ubuntu1.14; 0-01-01T00:00:00
|   libisl15-0.16.1-1; 0-01-01T00:00:00
|   libitm1-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libk5crypto3-1.13.2+dfsg-5ubuntu2.1; 0-01-01T00:00:00
|   libkeyutils1-1.5.9-8ubuntu1; 0-01-01T00:00:00
|   libkmod2-22-1ubuntu5.2; 0-01-01T00:00:00
|   libkrb5-3-1.13.2+dfsg-5ubuntu2.1; 0-01-01T00:00:00
|   libkrb5support0-1.13.2+dfsg-5ubuntu2.1; 0-01-01T00:00:00
|   liblsan0-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libltdl-dev-2.4.6-0.1; 0-01-01T00:00:00
|   libltdl7-2.4.6-0.1; 0-01-01T00:00:00
|   liblz4-1-0.0~r131-2ubuntu2; 0-01-01T00:00:00
|   liblzma5-5.1.1alpha+20120614-2ubuntu2; 0-01-01T00:00:00
|   libmagic1-1:5.25-2ubuntu1.2; 0-01-01T00:00:00
|   libmnl0-1.0.3-5; 0-01-01T00:00:00
|   libmount1-2.27.1-6ubuntu3.6; 0-01-01T00:00:00
|   libmpc3-1.0.3-1; 0-01-01T00:00:00
|   libmpdec2-2.4.2-1; 0-01-01T00:00:00
|   libmpfr4-3.1.4-1; 0-01-01T00:00:00
|   libmpx0-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libncurses5-6.0+20160213-1ubuntu1; 0-01-01T00:00:00
|   libncursesw5-6.0+20160213-1ubuntu1; 0-01-01T00:00:00
|   libpam-modules-1.1.8-3.2ubuntu2.1; 0-01-01T00:00:00
|   libpam-modules-bin-1.1.8-3.2ubuntu2.1; 0-01-01T00:00:00
|   libpam-runtime-1.1.8-3.2ubuntu2.1; 0-01-01T00:00:00
|   libpam0g-1.1.8-3.2ubuntu2.1; 0-01-01T00:00:00
|   libpcre3-2:8.38-3.1; 0-01-01T00:00:00
|   libperl-dev-5.22.1-9ubuntu0.6; 0-01-01T00:00:00
|   libperl5.22-5.22.1-9ubuntu0.6; 0-01-01T00:00:00
|   libprocps4-2:3.3.10-4ubuntu2.4; 0-01-01T00:00:00
|   libpython-stdlib-2.7.12-1~16.04; 0-01-01T00:00:00
|   libpython2.7-minimal-2.7.12-1ubuntu0~16.04.4; 0-01-01T00:00:00
|   libpython2.7-stdlib-2.7.12-1ubuntu0~16.04.4; 0-01-01T00:00:00
|   libpython3-stdlib-3.5.1-3; 0-01-01T00:00:00
|   libpython3.5-3.5.2-2ubuntu0~16.04.5; 0-01-01T00:00:00
|   libpython3.5-minimal-3.5.2-2ubuntu0~16.04.5; 0-01-01T00:00:00
|   libpython3.5-stdlib-3.5.2-2ubuntu0~16.04.5; 0-01-01T00:00:00
|   libquadmath0-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libreadline6-6.3-8ubuntu2; 0-01-01T00:00:00
|   libseccomp2-2.3.1-2.1ubuntu2~16.04.1; 0-01-01T00:00:00
|   libselinux1-2.4-3build2; 0-01-01T00:00:00
|   libsemanage-common-2.3-1build3; 0-01-01T00:00:00
|   libsemanage1-2.3-1build3; 0-01-01T00:00:00
|   libsepol1-2.4-2; 0-01-01T00:00:00
|   libsmartcols1-2.27.1-6ubuntu3.6; 0-01-01T00:00:00
|   libsqlite3-0-3.11.0-1ubuntu1.2; 0-01-01T00:00:00
|   libss2-1.42.13-1ubuntu1; 0-01-01T00:00:00
|   libssl1.0.0-1.0.2g-1ubuntu4.15; 0-01-01T00:00:00
|   libstdc++-5-dev-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libstdc++6-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libsystemd0-229-4ubuntu21.16; 0-01-01T00:00:00
|   libtinfo5-6.0+20160213-1ubuntu1; 0-01-01T00:00:00
|   libtool-2.4.6-0.1; 0-01-01T00:00:00
|   libtsan0-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libubsan0-5.4.0-6ubuntu1~16.04.11; 0-01-01T00:00:00
|   libudev1-229-4ubuntu21.16; 0-01-01T00:00:00
|   libusb-0.1-4-2:0.1.12-28; 0-01-01T00:00:00
|   libustr-1.0-1-1.0.4-5; 0-01-01T00:00:00
|   libuuid1-2.27.1-6ubuntu3.6; 0-01-01T00:00:00
|   libwrap0-7.6.q-25; 0-01-01T00:00:00
|   libx11-6-2:1.6.3-1ubuntu2.1; 0-01-01T00:00:00
|   libx11-data-2:1.6.3-1ubuntu2.1; 0-01-01T00:00:00
|   libxau6-1:1.0.8-1; 0-01-01T00:00:00
|   libxcb1-1.11.1-1ubuntu1; 0-01-01T00:00:00
|   libxdmcp6-1:1.1.2-1.1; 0-01-01T00:00:00
|   libxext6-2:1.3.3-1; 0-01-01T00:00:00
|   libxmuu1-2:1.1.2-2; 0-01-01T00:00:00
|   libxtables11-1.6.0-2ubuntu3; 0-01-01T00:00:00
|   linux-libc-dev-4.4.0-154.181; 0-01-01T00:00:00
|   login-1:4.2-3.1ubuntu5.3; 0-01-01T00:00:00
|   lsb-base-9.20160110ubuntu0.2; 0-01-01T00:00:00
|   make-4.1-6; 0-01-01T00:00:00
|   makedev-2.3.1-93ubuntu2~ubuntu16.04.1; 0-01-01T00:00:00
|   manpages-4.04-2; 0-01-01T00:00:00
|   manpages-dev-4.04-2; 0-01-01T00:00:00
|   mawk-1.3.3-17ubuntu2; 0-01-01T00:00:00
|   mime-support-3.59ubuntu1; 0-01-01T00:00:00
|   mount-2.27.1-6ubuntu3.6; 0-01-01T00:00:00
|   multiarch-support-2.23-0ubuntu11; 0-01-01T00:00:00
|   ncurses-base-6.0+20160213-1ubuntu1; 0-01-01T00:00:00
|   ncurses-bin-6.0+20160213-1ubuntu1; 0-01-01T00:00:00
|   ncurses-term-6.0+20160213-1ubuntu1; 0-01-01T00:00:00
|   net-tools-1.60-26ubuntu1; 0-01-01T00:00:00
|   netbase-5.3; 0-01-01T00:00:00
|   netcat-1.10-41; 0-01-01T00:00:00
|   netcat-traditional-1.10-41; 0-01-01T00:00:00
|   openssh-client-1:7.2p2-4ubuntu2.8; 0-01-01T00:00:00
|   openssh-server-1:7.2p2-4ubuntu2.8; 0-01-01T00:00:00
|   openssh-sftp-server-1:7.2p2-4ubuntu2.8; 0-01-01T00:00:00
|   openssl-1.0.2g-1ubuntu4.15; 0-01-01T00:00:00
|   passwd-1:4.2-3.1ubuntu5.3; 0-01-01T00:00:00
|   patch-2.7.5-1ubuntu0.16.04.1; 0-01-01T00:00:00
|   perl-5.22.1-9ubuntu0.6; 0-01-01T00:00:00
|   perl-base-5.22.1-9ubuntu0.6; 0-01-01T00:00:00
|   perl-modules-5.22-5.22.1-9ubuntu0.6; 0-01-01T00:00:00
|   procps-2:3.3.10-4ubuntu2.4; 0-01-01T00:00:00
|   python-2.7.12-1~16.04; 0-01-01T00:00:00
|   python-meld3-1.0.2-2; 0-01-01T00:00:00
|   python-minimal-2.7.12-1~16.04; 0-01-01T00:00:00
|   python-pkg-resources-20.7.0-1; 0-01-01T00:00:00
|   python2.7-2.7.12-1ubuntu0~16.04.4; 0-01-01T00:00:00
|   python2.7-minimal-2.7.12-1ubuntu0~16.04.4; 0-01-01T00:00:00
|   python3-3.5.1-3; 0-01-01T00:00:00
|   python3-chardet-2.3.0-2; 0-01-01T00:00:00
|   python3-minimal-3.5.1-3; 0-01-01T00:00:00
|   python3-pkg-resources-20.7.0-1; 0-01-01T00:00:00
|   python3-requests-2.9.1-3ubuntu0.1; 0-01-01T00:00:00
|   python3-six-1.10.0-3; 0-01-01T00:00:00
|   python3-urllib3-1.13.1-2ubuntu0.16.04.3; 0-01-01T00:00:00
|   python3.5-3.5.2-2ubuntu0~16.04.5; 0-01-01T00:00:00
|   python3.5-minimal-3.5.2-2ubuntu0~16.04.5; 0-01-01T00:00:00
|   readline-common-6.3-8ubuntu2; 0-01-01T00:00:00
|   rename-0.20-4; 0-01-01T00:00:00
|   sed-4.2.2-7; 0-01-01T00:00:00
|   sensible-utils-0.0.9ubuntu0.16.04.1; 0-01-01T00:00:00
|   ssh-import-id-5.5-0ubuntu1; 0-01-01T00:00:00
|   supervisor-3.2.0-2ubuntu0.2; 0-01-01T00:00:00
|   systemd-229-4ubuntu21.16; 0-01-01T00:00:00
|   systemd-sysv-229-4ubuntu21.16; 0-01-01T00:00:00
|   sysv-rc-2.88dsf-59.3ubuntu2; 0-01-01T00:00:00
|   sysvinit-utils-2.88dsf-59.3ubuntu2; 0-01-01T00:00:00
|   tar-1.28-2.1ubuntu0.1; 0-01-01T00:00:00
|   tcpd-7.6.q-25; 0-01-01T00:00:00
|   ubuntu-keyring-2012.05.19; 0-01-01T00:00:00
|   util-linux-2.27.1-6ubuntu3.6; 0-01-01T00:00:00
|   vim-2:7.4.1689-3ubuntu1.3; 0-01-01T00:00:00
|   vim-common-2:7.4.1689-3ubuntu1.3; 0-01-01T00:00:00
|   vim-runtime-2:7.4.1689-3ubuntu1.3; 0-01-01T00:00:00
|   wget-1.17.1-1ubuntu1.5; 0-01-01T00:00:00
|   xauth-1:1.0.9-1ubuntu2; 0-01-01T00:00:00
|   xz-utils-5.1.1alpha+20120614-2ubuntu2; 0-01-01T00:00:00
|_  zlib1g-1:1.2.8.dfsg-2ubuntu4.1; 0-01-01T00:00:00
| snmp-processes: 
|   1: 
|     Name: supervisord
|     Path: /usr/bin/python
|     Params: /usr/bin/supervisord -n
|   16: 
|     Name: snmpd
|     Path: snmpd
|     Params: -c /etc/snmp/snmpd.conf
|   30: 
|     Name: sshd
|     Path: /usr/sbin/sshd
|   33: 
|     Name: listener
|     Path: /listener
|   34: 
|     Name: ssh
|     Path: ssh
|     Params: -i /opt/david_key -o StrictHostKeyChecking=no david@127.0.0.1
|   35: 
|     Name: sshd
|     Path: sshd: david [priv]
|   44: 
|     Name: sshd
|     Path: sshd: david@notty
|   45: 
|     Name: bash
|_    Path: -bash
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Status: up
|     Traffic stats: 10.58 Kb sent, 10.58 Kb received
|   ip_vti0
|     Type: tunnel  Speed: 0 Kbps
|     Status: down
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   eth0
|     MAC address: 02:42:c0:73:c9:03 (Unknown)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|     Status: up
|_    Traffic stats: 3.62 Mb sent, 3.93 Mb received
MAC Address: 02:42:C0:73:C9:03 (Unknown)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.05 ms demo.ine.local (192.115.201.3)

NSE: Script Post-scanning.
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3.76 seconds
           Raw packets sent: 15 (1.863KB) | Rcvd: 14 (1.717KB)
```