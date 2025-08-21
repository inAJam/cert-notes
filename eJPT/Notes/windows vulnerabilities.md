# Windows Vulnerabilities

Why windows?
* Massive market share
* Threat surface is fragmented due to the various versions of windows
* Built in C so vulnerable to buffer overflows, arbitrary code execution, etc.
* Require a proavtive implmentation of security practices to run securely
* Given the fragmented nature, patches are slow
* Comapred to publishing new versions, companies migrate slower to newer versions making them vulnerable
* Vulnerable to cross platform attacks like SQL injection and also physical like theft

Types of vulnerabilities:
* Information disclosure - allows attacker to access confidential data
* Buffer overflows
* Remote code execution
* Privilege Escalation
* Denial of Service 

## Frequently exploited services

### 1. File and Printer Sharing Services

| Service | Port(s) | Purpose | Common Issues | Notable Exploits |
|---------|---------|---------|--------------|------------------|
| SMB (Server Message Block) | 445, 139 | File/printer sharing and remote management | SMBv1 enabled, weak/null share permissions | EternalBlue (MS17-010), SMBGhost (CVE-2020-0796) |

---

### 2. Remote Administration Services

| Service | Port(s) | Purpose | Common Issues | Notable Exploits |
|---------|---------|---------|--------------|------------------|
| RDP (Remote Desktop Protocol) | 3389 | Remote graphical desktop access | Weak passwords, no NLA (Network Level Authentication), exposed to internet | BlueKeep (CVE-2019-0708) |
| WinRM (Windows Remote Management) | 5985 (HTTP), 5986 (HTTPS) | Remote PowerShell and system administration | Weak creds, improper role delegation | Credential reuse, lateral movement |

---

### 3. Web & Application Services

| Service | Port(s) | Purpose | Common Issues | Notable Exploits |
|---------|---------|---------|--------------|------------------|
| IIS (Internet Information Services) | 80, 443 | Hosting web applications and APIs | Outdated modules, weak app code | Directory traversal (CVE-2000-0884), ASP.NET deserialization |
| MS-SQL Server | 1433 | Database storage and management | Weak SA password, xp_cmdshell enabled | SQL injection, privilege escalation via stored procedures |
| WebDAV (IIS/Apache module) | 80, 443 | Remote file management over HTTP/HTTPS | Weak auth, arbitrary file upload, RCE | CVE-2017-7269, MS09-020 |

---

### 4. Mail & Collaboration Services

| Service | Port(s) | Purpose | Common Issues | Notable Exploits |
|---------|---------|---------|--------------|------------------|
| Exchange Server | 443 (OWA/ECP) | Email and collaboration platform | Unpatched, internet-exposed | ProxyLogon (CVE-2021-26855), ProxyShell (CVE-2021-34473), CVE-2023-21709 |

---

### 5. Background & Support Services

| Service | Port(s) | Purpose | Common Issues | Notable Exploits |
|---------|---------|---------|--------------|------------------|
| Spooler Service | N/A (RPC) | Manages print jobs and printer sharing | Runs by default, excessive permissions | PrintNightmare (CVE-2021-34527) |
| Windows RPC | 135 | Remote procedure calls between Windows components | NTLM (NT LAN Manager) relay, exposed to LAN/WAN | PetitPotam, DCOM abuse |
| WMI | N/A (RPC/DCOM) | Remote system management and monitoring | Misused for persistence | Remote code execution, lateral movement |

---

### 6. Legacy / Dangerous Services

| Service | Port(s) | Purpose | Common Issues | Notable Exploits |
|---------|---------|---------|--------------|------------------|
| Telnet | 23 | Remote terminal access | Cleartext creds, obsolete | Credential sniffing |
| FTP (IIS FTP) | 21 | File transfer service | Anonymous access, weak creds | FTP bounce attacks |
| NetBIOS | 137-139 | Legacy file/printer sharing and name resolution | Information leakage | SMBv1 exploitation, enum4linux attacks |

---

### Searching for exploits
* Enumerate all services running on the system
* use `searchsploit` and then pipe for **msf** ones
* Some exploit modules also come with scanner modules to see if the target is vulnerable to the given module
* Also, need to set the post screen from linux to windows
* `metasploit-autopwn`: this plugin can be used to automatically find the list of exploits but will need further pruning
* `analyze` command can also do this and then store the results which can be fetched with `vulns`
* `hydra` can be used to bruteforce passwords ans usernames
* `davtest` is a WebDAV testing tool used to check whether a WebDAV-enabled web server allows us to upload and execute files
* `cadaver` is a command-line WebDAV client for Unix. It supports file upload, download, on-screen display, namespace operations (move/copy), collection creation and deletion, and locking operations.


### EternalBlue exploit
* Was used in the WannaCry ransomware attacks to spread to other computers