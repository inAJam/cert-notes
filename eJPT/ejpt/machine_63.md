## 192.168.100.63
```bash
Nmap scan report for ip-192-168-100-63.us-west-1.compute.internal (192.168.100.63)
Host is up (0.00041s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-01-29T01:10:02+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: EC2AMAZ-IK4QFED
|   NetBIOS_Domain_Name: EC2AMAZ-IK4QFED
|   NetBIOS_Computer_Name: EC2AMAZ-IK4QFED
|   DNS_Domain_Name: EC2AMAZ-IK4QFED
|   DNS_Computer_Name: EC2AMAZ-IK4QFED
|   Product_Version: 10.0.14393
|_  System_Time: 2026-01-29T01:09:58+00:00
| ssl-cert: Subject: commonName=EC2AMAZ-IK4QFED
| Not valid before: 2026-01-27T20:58:48
|_Not valid after:  2026-07-29T20:58:48
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
MAC Address: 02:DC:05:CE:26:A1 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE
HOP RTT     ADDRESS
1   0.41 ms ip-192-168-100-63.us-west-1.compute.internal (192.168.100.63)
```