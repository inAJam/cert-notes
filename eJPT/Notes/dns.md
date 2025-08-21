# DNS
DNS is like the **phonebook of the internet**.  
It helps turn **human-readable names** (like `example.com`) into **IP addresses** (like `93.184.216.34`) so computers can connect to each other.  

### How DNS Works (Step-by-Step)

1. We type `example.com` into a browser.
2. The computer asks a **DNS resolver** for the IP address.
3. The resolver checks:
   - Is it cached?
   - Else → ask the **root server** → then **TLD server** → then **authoritative DNS server**
4. The final answer (like `93.184.216.34`) is returned.
5. The browser connects to that IP and loads the website. 

---
### Common DNS Record Types

| Type     | What It Does                          | Example                              |
|----------|----------------------------------------|--------------------------------------|
| `A`      | Maps domain to IPv4 address            | `example.com → 93.184.216.34`       |
| `AAAA`   | Maps domain to IPv6 address            | `example.com → 2606:2800::1234`     |
| `CNAME`  | Alias to another domain                | `www.example.com → example.com`     |
| `MX`     | Mail exchange for email servers        | `example.com → mail.example.com`    |
| `TXT`    | Stores text (e.g., SPF, verification)  | `v=spf1 include:_spf.google.com`    |
| `NS`     | Points to nameservers                  | `ns1.exampledns.com`                |
| `PTR`    | Reverse lookup: IP → domain            | `93.184.216.34 → example.com`       |
| `SOA`    | Start of Authority (domain info)       | Zone config, refresh timers, etc.   |
| `SRV`    | Defines specific services (VoIP, etc.) | `_sip._tcp.example.com`             |


### DNS Zone File

A **zone file** is a text file that defines mappings between **domain names** and **IP addresses** or other resources. It contains **DNS records** used by authoritative DNS servers. It includes:

- **SOA (Start of Authority)** record – admin + config info
- **NS (Name Server)** records – which servers answer for this zone
- **A** records – map domain to IPv4
- **AAAA** records – map domain to IPv6
- **CNAME** records – aliases
- **MX** records – mail server info
- **TXT** records – arbitrary metadata (e.g., SPF, verification)

host file -> /etc/hosts  

### DNS Interrogation

**DNS Interrogation** is the process of **querying DNS servers** to gather information about a domain and its infrastructure.

It helps us discover:
- IP addresses of subdomains
- Mail servers
- Nameservers
- Publicly exposed records
- Hidden or forgotten services

### DNS Zone Transfer

A **Zone Transfer** is a process used by DNS servers to **share entire DNS zones** (i.e., all domain records) with backup or secondary servers.  
If not properly restricted, **anyone can request a full dump** of a domain’s DNS records — a major misconfiguration!

---