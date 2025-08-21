# Network protocols - OSI model

The **OSI (Open Systems Interconnection)** model consists of **7 layers**, each responsible for different aspects of network communication.

### OSI Layers (Top to Bottom)
| Layer | Name                   | Function                                    | Example Protocols               |
|-------|------------------------|---------------------------------------------|----------------------------------|
| 7     | Application            | User interface, APIs                        | HTTP, HTTPS, FTP, DNS, SSH       |
| 6     | Presentation           | Data encoding, compression, encryption      | SSL/TLS, JPEG, GIF, ASCII        |
| 5     | Session                | Sessions between applications               | NetBIOS, RPC, SMB, SQL           |
| 4     | Transport              | Reliable delivery, error checking           | TCP, UDP                         |
| 3     | Network                | Routing and logical addressing              | IP, ICMP, IPSec                  |
| 2     | Data Link              | Physical addressing and MAC access          | Ethernet, ARP, PPP, VLAN         |
| 1     | Physical               | Bit transmission over physical medium       | Cables, Wi-Fi, Hubs, Modulation  |

---

### Addresses at Each Layer

| OSI Layer | Type of Address Used         | Example                    |
|-----------|------------------------------|----------------------------|
| 7–5       | Application-Level Identifiers | URLs, Domain Names (`www.google.com`) |
| 4         | **Port Numbers**              | TCP/UDP ports (`80`, `443`, `22`) |
| 3         | **IP Address** (Logical)      | `192.168.1.10`, `10.0.0.5`, `2001:db8::1` |
| 2         | **MAC Address** (Physical)    | `00:1A:2B:3C:4D:5E`         |
| 1         | No address, just raw bits     | 1s and 0s                   |


When we send a large image (e.g., 10 MB) over the internet — such as uploading to a website — the data is broken down into smaller pieces and travels through the 7 layers of the OSI model.

---

### OSI Model Breakdown (Sender Side)

* **Application Layer**
   - We choose an image and click "Upload" in our browser or app.
   - Protocols: **HTTP**, **HTTPS**, **FTP**
   - Raw image data is handed off to the lower layers.

* **Presentation Layer**
   - Handles **compression** (e.g., JPEG) and **encryption** (e.g., SSL/TLS).
   - If using HTTPS, the image data is encrypted here.

* **Session Layer**
   - Maintains the **session** (e.g., cookies, tokens, secure connection).
   - Manages connection start/end between us and the server.

* **Transport Layer**
   - Protocol: **TCP** (reliable)
   - Splits the image into smaller pieces called **segments**.
   - Each segment typically carries up to **1460 bytes** of data.
   - Adds:
     - **Source/destination ports**
     - **Sequence numbers**
     - **Error detection**

   **10 MB image ≈ ~7,000 TCP segments**

* **Network Layer**
   - Adds an **IP header** to each segment → becomes a **packet**.
   - Contains:
     - **Source IP**
     - **Destination IP**
     - **TTL (Time to Live)**
   - Packets are routed across networks to the destination.

* **Data Link Layer**
   - Wraps each packet into a **frame**.
   - Adds:
     - **MAC addresses** (source and destination)
     - **Error checking (CRC)**
   - Sent to the local network (e.g., router).

* **Physical Layer**
   - Converts the frames into **electrical signals, light, or radio waves**.
   - Transmits bits (0s and 1s) over cables, Wi-Fi, etc.


### Receiver Side (Server)

The server:
1. **Receives bits**, reconstructs frames → packets → segments.
2. **Reassembles** the image using TCP sequence numbers.
3. Hands over the complete image to the application.

### Key points

| Concept            | Explanation |
|--------------------|-------------|
| **Segmentation**   | Large files are broken into smaller pieces. |
| **Reassembly**     | Pieces are ordered and recombined at the destination. |
| **TCP Reliability**| Ensures delivery is complete and ordered. |
| **MTU**            | Max size of a frame (usually ~1500 bytes for Ethernet). |

---

## Subnets, CIDR, and Netmask

### What is a Subnet?

A **subnet** (short for *sub-network*) is a smaller, logical segment of a larger network. Subnetting allows networks to be divided into smaller, more manageable sections. They help to:
- Organize IP addresses into groups
- Improve routing efficiency
- Isolate parts of the network for security
Example:
* Network: 192.168.1.0/24
  * Subnet 1: 192.168.1.0 – 192.168.1.127
  * Subnet 2: 192.168.1.128 – 192.168.1.255

### What is a Netmask?

A **subnet mask** is a 32-bit number that defines the network and host portions of an IP address.
Example:
* IP Address: 192.168.1.10
* Netmask: 255.255.255.0
* Binary Mask: 11111111.11111111.11111111.00000000


In the above network: 
  - First 24 bits (1s) = **network part** → `192.168.1`
  - Last 8 bits (0s) = **host part** → `.10`

The netmask tells the system which part of the IP is used to identify the network.


### What is CIDR?

**CIDR** stands for **Classless Inter-Domain Routing**. It’s a way to represent IP addresses and their associated subnet masks using a suffix notation (slash notation).

Example:
 - 192.168.1.0/24 → Netmask: 255.255.255.0
 - 10.0.0.0/8 → Netmask: 255.0.0.0
 - 172.16.0.0/12 → Netmask: 255.240.0.0

In the above example 
- The `/24` means **24 bits** are reserved for the **network part**.
- Remaining **8 bits** are for **host addresses**.  

### ICMP – Internet Control Message Protocol

It is a **Layer 3 (Network layer)** protocol used to send **error messages** and **diagnostic information** about IP packet delivery. ICMP is **not used to send data**, but to report on the delivery of IP packets.

Common Uses:

| Command        | Description                          |
|----------------|--------------------------------------|
| `ping`         | Uses ICMP Echo Request/Reply         |
| `traceroute`   | Uses ICMP (or UDP) to trace hops     |

ICMP Message Types:

| Type | Name                  | Description                         |
|------|-----------------------|-------------------------------------|
| 0    | Echo Reply            | `ping` reply                        |
| 3    | Destination Unreachable | Host or port is unreachable         |
| 8    | Echo Request          | `ping` request                      |
| 11   | Time Exceeded         | TTL (Time to Live) expired          |


**Note**: ICMP Can Be Blocked
- Firewalls often **block ICMP** to prevent:
  - Ping sweeps
  - Network mapping by attackers

---

### DHCP – Dynamic Host Configuration Protocol

It is a **Layer 7 (Application layer)** protocol that automatically **assigns IP addresses** and other network settings to devices on a network.

DHCP Workflow (DORA):

| Step  | Message        | Description                          |
|-------|----------------|--------------------------------------|
| 1     | **Discover**   | Client broadcasts to find DHCP server |
| 2     | **Offer**      | Server offers an IP address           |
| 3     | **Request**    | Client requests the offered IP        |
| 4     | **Acknowledge**| Server confirms and finalizes         |

DHCP Assigns:

- IP Address
- Subnet Mask
- Default Gateway
- DNS Server(s)
- Lease Time

DHCP Protocol Details:

- **Ports**:
  - **Client → Server**: UDP **67**
  - **Server → Client**: UDP **68**


ICMP vs DHCP – Quick Comparison

| Feature         | ICMP                          | DHCP                          |
|-----------------|-------------------------------|-------------------------------|
| Layer           | Network (Layer 3)             | Application (Layer 7)         |
| Purpose         | Diagnostic/Error reporting    | IP address assignment         |
| Common Tools    | `ping`, `traceroute`          | IP auto-assignment            |
| Transport       | Uses **IP** directly (no port)| Uses **UDP** (Ports 67/68)    |
| Example Message | "Destination unreachable"     | "Here’s your IP address"      |

Summary

- **ICMP** helps **troubleshoot** and **report** on IP communication problems.
- **DHCP** helps **automatically configure** IP settings for devices on a network.


## TCP vs UDP – Transport Layer Protocols

Both **TCP (Transmission Control Protocol)** and **UDP (User Datagram Protocol)** operate at **Layer 4** of the OSI model (Transport Layer), but they work very differently.


### TCP
- **Connection-oriented** protocol
- Establishes a **reliable** connection using a **3-way handshake**
- Ensures **ordered delivery** of data
- Performs **error checking** and **retransmission** if needed
- Slower but **more reliable**

TCP 3-Way Handshake:
* Client → SYN → Server
* Server → SYN-ACK → Client
* Client → ACK → Server
* Connection Established

Use Cases:
- Web browsing (HTTP/HTTPS)
- Email (SMTP, IMAP, POP3)
- File transfer (FTP)
- Secure Shell (SSH)

TCP Header Contains:
- Source and Destination Ports
- Sequence and Acknowledgment Numbers
- Flags (SYN, ACK, FIN, RST, etc.)
- Window size, checksum, etc.

TCP uses **port numbers** to identify specific services and applications on a host. These ports range from **0 to 65535** and are divided into 3 categories:

---
Well-Known Ports (0–1023)

- Assigned and controlled by **IANA** (Internet Assigned Numbers Authority)
- Used by **core services** and protocols

| Port | Service        | Description              |
|------|----------------|--------------------------|
| 20   | FTP (Data)     | File Transfer Protocol   |
| 21   | FTP (Control)  | Login, commands          |
| 22   | SSH            | Secure Shell             |
| 23   | Telnet         | Remote login (insecure)  |
| 25   | SMTP           | Email sending            |
| 53   | DNS            | Domain name system       |
| 80   | HTTP           | Web traffic              |
| 110  | POP3           | Email receiving          |
| 143  | IMAP           | Email reading/sync       |
| 443  | HTTPS          | Secure web               |

---
Registered Ports (1024–49151)

- Used by **user applications** and third-party software
- Still assigned by IANA, but less strict
- Examples:
  - 3306 → MySQL
  - 3389 → RDP (Remote Desktop)
  - 5432 → PostgreSQL

---

### UDP
- **Connectionless** protocol
- No handshakes, no connection setup
- **Unreliable** – no guaranteed delivery
- **Faster and lightweight**
- Suitable for time-sensitive applications

Use Cases:
- DNS
- Streaming video/audio (e.g., YouTube, Netflix)
- VoIP (Voice over IP)
- Online gaming
- DHCP

UDP Header Contains:
- Source Port
- Destination Port
- Length
- Checksum

---

### TCP vs UDP – Quick Comparison

| Feature             | TCP                             | UDP                         |
|---------------------|----------------------------------|-----------------------------|
| Type                | Connection-oriented              | Connectionless              |
| Reliability         | Reliable, ordered, error-checked | Unreliable, no ordering     |
| Speed               | Slower                           | Faster                      |
| Overhead            | More (due to handshakes, checks) | Less                        |
| Packet Delivery     | Guaranteed                       | Not guaranteed              |
| Common Use Cases    | HTTP, FTP, SSH, Email            | DNS, Streaming, VoIP, Games |
| Header Size         | 20–60 bytes                      | 8 bytes                     |
| Protocol Number (IP)| 6                                | 17                          |

---

**Summary**

| Protocol | Reliable | Fast | Ordered | Connection |
|----------|----------|------|---------|-------------|
| TCP      | Yes   |  No|  Yes  |  Yes      |
| UDP      | No    |  Yes|  No  |  No       |

