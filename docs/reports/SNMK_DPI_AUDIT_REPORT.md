# SNMK Deep Packet Inspection (DPI) & PCAP Forensics Report

**Audit Area:** Deep Packet Inspection, Protocol Dissection, PCAP/PCAPNG Forensics  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Core Dissection Modules:** `core/network/packet_engine.py`, `core/network/pcap_forensics.py`  
**Status:** **ENTERPRISE VERIFIED**

---

## 1. Executive Summary

SNMK features a native, Wireshark-grade Deep Packet Inspection (DPI) and forensic dissection subsystem capable of analyzing live traffic and captured PCAP/PCAPNG files. The engine performs layer-by-layer dissection across the OSI model, decodes protocol headers, reconstructs TCP flows, and renders interactive hex byte views.

---

## 2. PCAP and PCAPNG Validation & Cryptographic Integrity

`core/network/pcap_forensics.py` enforces cryptographic verification and header validation before parsing user-uploaded capture files:
- **Magic Number Verification:**
  - Standard PCAP (Little Endian): `0xd4 0xc3 0xb2 0xa1`
  - Standard PCAP (Big Endian): `0xa1 0xb2 0xc3 0xd4`
  - PCAPNG Next-Generation: `0x0a 0x0d 0x0d 0x0a`
- **Integrity Fingerprinting:** Computes SHA-256 hash immediately upon file receipt to establish forensic chain of custody.
- **Resource Limits:** Caps in-memory dissection at a configurable limit (default: 1,500 frames) to prevent memory exhaustion from multi-gigabyte capture dumps.

---

## 3. Supported Protocol Dissection Hierarchy

The `PacketDissector` class dissects frames across multiple network layers:
1. **Layer 2 (Data Link):** Ethernet II (`dst`, `src`, `type`), ARP requests and replies.
2. **Layer 3 (Network):** IPv4 (`src`, `dst`, `ttl`, `proto`, fragmentation flags) and IPv6 (`hop_limit`, `traffic_class`).
3. **Layer 4 (Transport):**
   - TCP: Source/destination ports, sequence numbers, acknowledgment numbers, window size, and decoded flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
   - UDP: Datagram lengths and port multiplexing.
   - ICMP: Echo requests, replies, unreachable messages, and TTL exceeded notices.
4. **Layer 7 (Application):**
   - DNS: Query identification, query names, response record types (A, AAAA, MX, TXT, CNAME).
   - TLS: Client Hello handshake inspection, SNI (Server Name Indication) domain extraction, cipher suite negotiation metadata.

---

## 4. Privacy & Data Minimization Controls

1. **Zero Decryption of Encrypted Traffic:** In compliance with ethical cybersecurity and privacy standards, TLS application data payloads are treated as opaque encrypted octets unless authorized keys are provided in a lab test environment.
2. **Hex Dump Sanitization:** The hex formatter (`format_hex_dump`) masks non-printable binary bytes and normalizes ASCII displays.
