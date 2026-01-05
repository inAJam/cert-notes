# Windows Vulnerabilities

Why windows?
* Massive market share
* Threat surface is fragmented due to the various versions of windows
* Built in C so vulnerable to buffer overflows, arbitrary code execution, etc.
* Requires a proactive implmentation of security practices to run securely
* Given the fragmented nature, patches are slow
* Compared to publishing new versions, companies migrate slower to newer versions making them vulnerable
* Vulnerable to cross platform attacks like SQL injection and also physical attacks like theft

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
* Enumerate all services running on the system, then target a particular service and search for an exploit.
* `searchsploit` can be used to find exploits. It returns all possible exploits including ones not found in `msf`.
  * Will need to be filtered for `msf` exploits.
* Some exploit modules also come with scanner modules to see if the target is vulnerable to the given module
  * Need to be careful about the different options while setting up, since the preset ones might even be for linux systems. 
* Can alo use external plugins like `metasploit-autopwn`
* `metasploit-autopwn`: this plugin can be used to automatically find the list of exploits but will need further pruning like finding the target operating system, the specific version of the application, etc.
* `analyze` command can also do this and then store the results which can be fetched with `vulns`
* `hydra` can be used to bruteforce passwords and usernames
* `davtest` is a WebDAV testing tool used to check whether a WebDAV-enabled web server allows us to upload and execute files
* `cadaver` is a command-line WebDAV client for Unix. It supports file upload, download, on-screen display, namespace operations (move/copy), collection creation and deletion, and locking operations.


### EternalBlue exploit: SMBv1 Vulnerability
This is the name given to a collection of windows vulnerabilities and exploits that allow attackers to remotely execute arbitrary code and gain access to a windows system. This exploit is feasible against multiple versions of windows running SMBv1.
* Developed by NSA and was later leaked to the public in 2017
* It allows attackers to send specially crafted packets that results in execution of arbitrary code which can spawn reverse shells
* Was used in the WannaCry ransomware attacks to spread to other computers
* It even has **metasploit** modules and **nmap** scripts to check if a system is exploitable and even a **metasploit** module for the exploit itself.

For manual exploitation the tool **AutoBlue-MS17-010** 


### BlueKeep exploit: Windows RDP vulnerability
This exploit takes advantage of a vulnerability of the windows RDP protocol, allowing attackers to gain access to a chunk of kernel memory consequently allowing them to remotely execute arbitrary code at the system level without authentication.  
* Was made public by microsoft
* It affects multiple version of windows


### Pass-The-Hash attack
It's an exploitation technique that involves capturing or harvesting **NTLM hashes** or clear-text passwords and utilizing them to authenticate with the target legitimately. 
**NTLM stands for NT LAN Manager.**
It is a Windows authentication protocol used to verify a user’s identity on a network. NTLM is a challenge–response authentication protocol used by Windows that allows a user to authenticate without sending their password over the network.  

How NTLM works: 
* Client → Server
  * **“I want to authenticate as USER”**
* Server → Client
  * **Sends a random challenge**
* Client
  * **Encrypts the challenge using the NTLM hash of the password**
* Client → Server 
  * **Sends the encrypted response**
* Server
  * **Verifies the response using its stored hash**

Some of the features of this exploit:   
* Multiple tools can be used to facilitate this attack.
  * Metasploit modules: PsExec
  * Crackmapexec
* It allows us to obtain access via legitimate credentials