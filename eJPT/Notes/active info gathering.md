# Active info Gathering

## network mapping
Refers to the process of discovering and identifying  devices, hists and network infrastructure.

## nmap
`nmap` (Network Mapper) is a powerful **open-source scanner** used to discover:

- Live hosts on a network
- Open ports
- Running services
- Operating systems
- Vulnerabilities (with scripts)

## Host discovery techniques

| Method         | Packet Type        | OSI Layer | Pros                                     | Cons                                      |
|----------------|--------------------|-----------|------------------------------------------|-------------------------------------------|
| ICMP Echo      | ICMP Echo Request  | Layer 3   | Simple, fast, standard tool support      | Often blocked by firewalls                |
| ARP Request     | ARP Request         | Layer 2   | Accurate on local networks               | Works only within LAN                     |
| TCP SYN        | TCP SYN Packet     | Layer 4   | Bypasses ICMP filters                    | May trigger IDS/IPS, shows in logs        |
| TCP ACK        | TCP ACK Packet     | Layer 4   | Can bypass some stateful firewalls       | Less reliable for confirming live hosts   |
| UDP Ping       | UDP to common ports| Layer 4   | Can find hosts behind ICMP/TCP filters   | High false negatives, no reply = unknown  |
| Combined Scan  | Multiple           | L3 + L4   | Best coverage, increases detection rate  | Noisy, higher chance of detection         |

---

### 1. ICMP Echo Request (Ping Sweep)

- **Packet Type**: ICMP Echo Request (Type 8)
- **Layer**: Network (L3)
- **Tools**: `ping`, `nmap -sn`

Pros:
- Lightweight and fast
- Supported on almost all OSes

Cons:
- Commonly blocked on firewalls/routers
- Doesn't work across all networks
- Windows OS doesn't reply to ping sweeps

Ping sweep is used to discover live hosts. 

---
### 2. ARP Requests (Local Network Only)
- **Packet Type**: ARP Request
- **Layer**: Data Link (L2)
- **Tools**: `arp-scan`, `nmap -sn -PR`

Pros:
- Very accurate for LANs
- Bypasses firewall filtering

Cons:
- Only works on local subnet
- Not useful for remote networks

---
### 3. TCP SYN Ping
- **Packet Type**: TCP SYN
- **Layer**: Transport (L4)
- **Tools**: `nmap -PS`

Pros:
- Can detect hosts even when ICMP is blocked
- Stealthy (half-open)

Cons:
- Can trigger IDS/IPS
- May not work if TCP port is filtered or closed

---

### 4. TCP ACK Ping
- **Packet Type**: TCP ACK
- **Layer**: Transport (L4)
- **Tools**: `nmap -PA`

Pros:
- Useful for bypassing stateless firewalls
- Often sneaks through when SYN is blocked

Cons:
- Doesn’t confirm host is truly live
- Relies on RST replies (less definitive)

---

### 5. UDP Ping
- **Packet Type**: UDP packets to ports like 53 (DNS), 161 (SNMP)
- **Layer**: Transport (L4)
- **Tools**: `nmap -PU`

Pros:
- Works when ICMP and TCP are filtered
- Less likely to be blocked on uncommon ports

Cons:
- No response doesn’t mean host is down (UDP is connectionless)
- High false negative rate

---
### 6. Combined Scan
- **Packet Type**: ICMP + TCP + UDP
- **Layer**: Network + Transport (L3 + L4)
- **Tools**: nmap with multiple flags

Pros:
- Best chance to discover all live hosts
- Covers multiple evasion paths

Cons:
- Very noisy
- Likely to trigger detection systems

**Note:** If the host is already up, `nmap -Pn` will ignore host discovery. this will make the `nmap` scan faster.

## Firewall detection and IDS evasion

* Fragment packets
  * Flag: `nmap -f`
  * Also allows for setting up of the **MTU** for the packets
* IP spoofing
  * Flag: `nmap -D`
  * Can also mask the port via **-g** flag
* Can also change packet frequency or delay between packets
* The T0-T5 also use pascket delays to hide the traffic
  
**Optimizing nmap Scan**: host timeout for faster host discovery
