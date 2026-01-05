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
* Need to locate a script that allows us to communicate with bash.