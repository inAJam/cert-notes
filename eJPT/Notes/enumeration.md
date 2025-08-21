# Enumeration

To gather additional, more specific details/information about the services running on the network.
* service enumaration
* user enumeration
* share enumeration

## MSF: metasploit framework

### Auxiliary modules
Used to perform functionality like scanning, discovery and fuzzing. 
* perform port scanning
* enumerate services

This modules can be used during information gathering phase as well as post exploitation phase. It also allows us for pivoting to other systems.

* `search` can be used to find the required modules needed
  * can use suboptions like **type**, **name**
* For FTP, using too many login attempts might cause the server to stop responding
  * Uses port 21
* SMB - Server Message Block, a network file sahring protocol used to share files over LAN.
  * Uses port 445
  * Originally ran over port 139 on top of NetBIOS
  * SAMBA is the linux implementation
* `g` can be used to set global variables
  * `setg RHOSTS`
* `info` can give more information on the module
* `unset` to remove any og the settings of the module
* `loot`, `creds` to find the data we have found via **msf**
* `sessions` are created for all successful exploitation