## 192.168.100.5
```bash
Nmap scan report for ip-192-168-100-5.us-west-1.compute.internal (192.168.100.5)
Host is up (0.000019s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 8.7p1 Debian 2 (protocol 2.0)
| ssh-hostkey: 
|   3072 b7:6b:7b:a3:17:ab:c9:e6:fa:27:0a:c7:13:d7:d9:f9 (RSA)
|   256 d0:1a:6d:ed:6d:dc:d9:8f:bd:6a:b3:3e:59:46:4f:82 (ECDSA)
|_  256 a1:ed:dc:9c:37:0b:26:fe:61:89:e0:0f:50:10:bc:c9 (ED25519)
3389/tcp  open  ms-wbt-server xrdp
5910/tcp  open  vnc           VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     VeNCrypt (19)
|     VNC Authentication (2)
|   VeNCrypt auth subtypes: 
|     VNC auth, Anonymous TLS (258)
|_    Unknown security type (2)
45656/tcp open  http          Werkzeug httpd 2.0.2 (Python 3.9.8)
|_http-server-header: Werkzeug/2.0.2 Python/3.9.8
|_http-title: 404 Not Found
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32
OS details: Linux 2.6.32
Network Distance: 0 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Post-scan script results:
| clock-skew: 
|   0s: 
|     192.168.100.55 (ip-192-168-100-55.us-west-1.compute.internal)
|_    192.168.100.63 (ip-192-168-100-63.us-west-1.compute.internal)
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```