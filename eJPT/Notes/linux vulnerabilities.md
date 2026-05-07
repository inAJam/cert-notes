# Linux Vulnerabilities

## Frequently Exploited Linux Services

| Service | Port(s) | Protocol | Purpose | Why It’s Often Exploited |
|-------|--------|----------|---------|---------------------------|
| Apache (HTTP/HTTPS) | 80 / 443 | TCP | Hosts websites and web applications | File upload, RCE, misconfig, outdated modules |
| SSH | 22 | TCP | Secure remote shell access | Weak passwords, key reuse, brute force |
| FTP | 21 | TCP | File transfer service | Anonymous login, cleartext credentials |
| Samba (SMB) | 445 | TCP | File and printer sharing (Windows/Linux) | Misconfig, weak creds, Samba RCE |


## Shellshock vulnerability
Shellshock is a family of bash vulnerabilitys where attackers inject commands into environment variables that Bash executes unintentionally.
In the context of remote exploitation, Apache webservers configured to run CGI (Common Gateway Interface) scripts, scripts used by apache to execute arbitrary commands on the linux system and then share the output with the client, or .sh scripts are also vulnerable to this attack. eg. getting the time from the webserver and diplaying it on the webpage.
* Need to locate a script that allows us to communicate with bash. Like a script asking for time, date,etc.

One of the most common fields to modify for this vulnerability is **User-Agent**, an HTTP header that tells the server what client (browser, OS, device) is making the request. Example:  

***User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0***

It usually contains:
* Browser name & version
* Operating system
* Device type
Servers use it to:
* Serve mobile vs desktop pages
* Track analytics
* Apply compatibility rules
**Important:** It is completely controlled by the client.

## Nessus Vulnerability Scanner
It is an automated system developed by **Tenable** that checks hosts, services, and configurations against a huge database of known weaknesses.  
We can use this to perform a vulnerability scan on the target system and then import the results back to **msf**

## wmap: Web vulnerability scanner
`wmap` is Metasploit’s built-in web application vulnerability scanner. It's a metasploit module and can be added with the **load** command.

## Misconfigured cronjobs
`cronjobs` can be setup by any user on the system and runs on the user's privileges. So a root user running a cronjob will have the cronjob running as root.

## SUID binary exploitation
* We can exploit these binaries to execute commands as the root user
  * We need executable permissions on these binaries

## Password hashes
* All info on all account s is stored on /etc/passwd
* All the encrypted passwords are stored in the /etc/shadow, which can only be accessed by the root user. The hashing algorithm used can be seen by the number after the username encapsulated by the `$` symbol
  * $1 -> MD5
  * $2 -> Blowfish
  * $5 -> SHA-265
  * $6 -> SHA-512 