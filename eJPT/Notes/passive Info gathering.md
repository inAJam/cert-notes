# Passive Information Gathering
Learn more about the target
* Passive - Gather info without actively engaging with the target like via linkendin
  * Ip & DNS info
  * domain names
  * emails, social media profiles
  * web technologies
* Active - Actively engage with the target like via nmap
  * Open ports
  * internal infrastructure

## Website recon and Footprinting
Commands like **host**
```
┌─[user@parrot]─[~]
└──╼ $host hackersploit.org
hackersploit.org has address 104.21.32.1
hackersploit.org has address 104.21.48.1
hackersploit.org has address 104.21.96.1
hackersploit.org has address 104.21.80.1
hackersploit.org has address 104.21.112.1
hackersploit.org has address 104.21.16.1
hackersploit.org has address 104.21.64.1
hackersploit.org has IPv6 address 2606:4700:3030::6815:1001
hackersploit.org has IPv6 address 2606:4700:3030::6815:5001
hackersploit.org has IPv6 address 2606:4700:3030::6815:6001
hackersploit.org has IPv6 address 2606:4700:3030::6815:2001
hackersploit.org has IPv6 address 2606:4700:3030::6815:3001
hackersploit.org has IPv6 address 2606:4700:3030::6815:4001
hackersploit.org has IPv6 address 2606:4700:3030::6815:7001
hackersploit.org mail is handled by 0 _dc-mx.2c2a3526b376.hackersploit.org.
┌─[user@parrot]─[~]
└──╼ $
```
## host 
Resolves domain names to IPs (A, AAAA, MX records). Useful for:
* Finding entry points for enumeration
* Discovering multiple IPs → potential load balancers, CDNs
* Identifying mail servers → phishing/social engineering angle

### Key Record Types

| Type  | Purpose                              |
|-------|--------------------------------------|
| A     | Maps domain to IPv4 address          |
| AAAA  | Maps domain to IPv6 address          |
| MX    | Mail exchange server for domain      |
| NS    | Name server records                  |
| TXT   | Text data (often for SPF/DMARC info) |
| CNAME | Canonical name (alias for domain)    |
| SOA   | Start of authority (zone data)       |

---

| Record Type | Points To      | Description                                  |
| ----------- | -------------- | -------------------------------------------- |
| **A**       | IPv4 address   | Maps domain to IPv4                          |
| **AAAA**    | IPv6 address   | Maps domain to IPv6                          |
| **TXT**     | Text string(s) | Carries metadata (SPF, DKIM, ownership, etc) |
---
`www.example.com → CNAME → example.com -> A → 93.184.216.34`  

**robots.txt**: to find list of allowed and disallowed webpages for a website.  
**sitemap_index.xml**: An XML index listing multiple sitemap files, each pointing to URLs used by the site. Used by search engines to properly index the site.
**builtwith**: what technologies a website is using, **whatweb** is a similar commandline tool.  
### WHOIS – Domain and IP Lookup Tool

`whois` is a command-line tool and protocol used to query databases that store the **registration details** of domain names and IP addresses. It’s commonly used in **reconnaissance**, **OSINT**, **network troubleshooting**, and **domain research**.

---

#### What Can You Learn from `whois`?

| Information Type      | Description                                          |
|-----------------------|------------------------------------------------------|
| **Registrar**         | The company through which the domain is registered   |
| **Registrant Info**   | Owner name, organization, email (if not redacted)    |
| **Creation/Expiry**   | Domain creation and expiration dates                 |
| **Name Servers**      | DNS servers associated with the domain               |
| **Domain Status**     | Active, clientHold, pendingDelete, etc.              |
| **IP/ASN Info**       | (For IP lookups) Network range, ASN, org, etc.       |

---

### Basic Usage

### Query a domain:
```bash
whois example.com 
``` 

## Netcraft – Internet Security and Reconnaissance Tool

**Netcraft** is an internet security services company that offers tools for analyzing **web infrastructure**, **hosting history**, **SSL certificates**, and **phishing threats**. It's especially useful for **passive reconnaissance** in penetration testing and OSINT.

---

### What You Can Discover with Netcraft

| Data Type               | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| **Hosting Info**        | Current web host, IP address, server location                               |
| **Historical Data**     | Changes in IP, hosting provider, DNS, technologies                          |
| **SSL Certificate Info**| Certificate authority, validity dates, common names                         |
| **Site Technology**     | Detected technologies (CMS, web server, frameworks)                         |
| **Risk Indicators**     | Reports of phishing, malicious content, or impersonation                    |
| **DNS Records**         | Subdomains, nameservers, MX records, etc.                                   |

---
| Term        | Meaning                              | Example              |
|-------------|---------------------------------------|----------------------|
| Domain      | Main website address                  | `example.com`        |
| Subdomain   | A part of the main site               | `blog.example.com`   |


## dnsrecon

`dnsrecon` is a Python-based command-line tool that performs **enumeration of DNS records** and supports brute-forcing subdomains, performing zone transfers, and reverse lookups.

### Features:
- Standard record enumeration (A, AAAA, MX, NS, TXT, etc.)
- Zone transfer testing (`AXFR`)
- Subdomain brute-forcing (dictionary-based)
- Reverse lookup of IP ranges
- Cache snooping and DNSSEC support

## DNSDumpster 
It is a free online passive DNS recon tool that maps a domain's DNS records, subdomains, hosts, and network information using publicly available sources.  

### What It Finds:
- Subdomains (via certificate transparency logs & DNS)
- A, MX, TXT, NS records
- Hosting provider and IP mapping
- Autonomous System Number (ASN)
- Reverse DNS
- Visual network map
  

## WAFWOOF
It is an open-source tool that identifies and fingerprints **Web Application Firewalls (WAFs)** protecting a target website. It's useful during the **reconnaissance and vulnerability scanning** phases of penetration testing.  

### What Does It Do?
- Detects if a **WAF is present**
- Identifies the **vendor/technology** (e.g., Cloudflare, AWS WAF, ModSecurity, etc.)
- Uses **HTTP response behavior analysis**, headers, cookies, and subtle differences to make determinations


## Sublist3r

**Sublist3r** is a Python-based OSINT tool used to **enumerate subdomains** of websites using **public sources** like search engines and certificate transparency logs. It's lightweight, fast, and often used during the **information gathering phase** of penetration testing.

---

### What Does Sublist3r Do?
- Finds **subdomains** for a target domain
- Uses **passive data sources**, avoiding detection
- Supports **multi-threading** for speed
- Outputs to file (plain text)


## Google search

| Operator      | Description                                     | Example |
|---------------|--------------------------------------------------|---------|
| `site:`       | Search within a specific site or domain          | `site:example.com` |
| `inurl:`      | Find URLs containing a specific word or path     | `inurl:admin` |
| `intitle:`    | Search page titles for keywords                  | `intitle:"index of"` |
| `filetype:`   | Search for specific file extensions              | `filetype:pdf` |
| `ext:`        | Same as `filetype:`                              | `ext:sql` |
| `intext:`     | Search for keywords within the page body         | `intext:"confidential"` |
| `allinurl:`   | Match multiple words in URL                      | `allinurl:login admin` |
| `allintitle:` | Match multiple words in the page title           | `allintitle:login panel` |
| `cache:`      | View Google’s cached version of a site           | `cache:example.com` |
| `link:`       | Find pages linking to a domain                   | `link:example.com` |
| `related:`    | Find sites related to a domain                   | `related:github.com` |
---

## theHarvester
**theHarvester** is an open-source tool used in **passive reconnaissance** to collect:
- Emails
- Subdomains
- Hostnames
- IP addresses

It gathers this data from **public sources** like search engines and online databases.

---

###  What Can It Find?

| Type         | Description                                  |
|--------------|----------------------------------------------|
| **Emails**   | Public email addresses related to a domain   |
| **Subdomains**| Other names under the main domain            |
| **Hosts**    | Hostnames pointing to IPs                    |
| **IP Info**  | IP addresses linked to subdomains            |
| **Metadata** | DNS, Netcraft, Shodan info (optional)        | 

## dig
`dig` (Domain Information Groper) is a command-line tool to **query DNS servers** and fetch DNS records like:

- A, AAAA
- MX, NS, TXT
- CNAME
- SOA
- AXFR (Zone Transfers)

## fierce

**Fierce** is an **automated DNS reconnaissance** tool used to:

- Find subdomains
- Detect misconfigured DNS
- Attempt zone transfers
- Identify internal IP ranges

It’s often used in the **early recon phase** of penetration testing.

---

### Features

- Brute-force subdomains using a wordlist
- Attempts DNS zone transfers (AXFR)
- Checks for wildcard DNS entries
- Maps discovered hosts to IPs
- Optional scan for RFC 1918 (private) ranges
