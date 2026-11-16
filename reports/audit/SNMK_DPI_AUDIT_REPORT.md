# SNMK — Deep Packet Inspection Audit Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Scope** | `core/network/packet_engine.py` (23 359 bytes), `core/network/pcap_forensics.py`, `core/network/dns_engine.py`, `core/network/threat_engine.py`, `core/network/flow_*`, `core/network/reporting.py` |
| **Method** | Source review against the implementation; capture behaviour verified against the host's own capabilities |

> **Privacy.** This report describes the implementation. It contains no packet
> contents, no captured traffic, and no personal or confidential data. The
> audit did not capture any traffic.

---

## 1. What the DPI subsystem actually is

The DPI layer is **three cooperating subsystems**, not one:

| Subsystem | Module | Function |
|---|---|---|
| **Live capture** | `core/network/packet_engine.py` | Live sniffing via scapy, protocol dissection, flow statistics |
| **Offline forensics** | `core/network/pcap_forensics.py` | PCAP / PCAPNG parsing and analysis from a file |
| **Protocol engines** | `dns_engine.py`, `threat_engine.py`, `origin_engine.py`, `geo_engine.py` | Protocol-specific analysis over the dissected records |

It also carries four companion modules that are *not* DPI:
`discovery.py` (ARP/interface enumeration), `infrastructure.py`, `wifi_engine.py`
and `routing_engine.py` (host-local reconnaissance).

---

## 2. Capture backends

`core/network/interfaces.py:32` detects what the host can do:

```
DetectPacketCaptureCapabilities()
  1. TShark / Dumpcap  -> shutil.which("tshark") or shutil.which("dumpcap")
                           or C:\Program Files\Wireshark\tshark.exe
  2. Npcap / libpcap   -> shutil.which("tcpdump") or the TShark probe
  3. Scapy             -> importable
  4. Socket-only       -> the fallback
```

The platform reports which backend is in use (`capture_driver_type` in
`core/network/models.py:43`), so an operator can see whether a capture is
live or reconstructed from a file.

**Verified on the audit host:** no capture driver was present — the host
reported `None` for the capture driver type and scapy's native extension
could not be loaded (`WARNING: No libpcap provider available !`). The
platform degraded to the socket-only path, which is the correct behaviour.

---

## 3. Protocol coverage

| Protocol | Parsed | Where |
|---|---|---|
| Ethernet II | Yes | `packet_engine.py:74` (`scapy.Ether`) |
| IPv4 | Yes | `packet_engine.py:74` (`scapy.IP`) |
| IPv6 | Yes | `packet_engine.py:74` (`scapy.IPv6`) |
| TCP | Yes | `packet_engine.py:74` (`scapy.TCP`) |
| UDP | Yes | `packet_engine.py:74` (`scapy.UDP`) |
| ICMP | Yes | `packet_engine.py:74` (`scapy.ICMP`) |
| ARP | Yes | `packet_engine.py:74` (`scapy.ARP`) |
| DNS | Yes | `packet_engine.py:74` (`scapy.DNS`), plus `core/network/dns_engine.py` |
| HTTP metadata | Yes | `packet_engine.py:428` reconstructs the TCP stream and extracts the request line, headers and host |
| TLS handshake metadata | Yes | `packet_engine.py:428` extracts the handshake type, the SNI and the certificate fields |

**PCAP and PCAPNG are both supported.** `core/network/pcap_forensics.py:28`
defines the PCAPNG magic number (`0a0d0d0a`) alongside the four PCAP
magic variants, and the reader dispatches on it.

---

## 4. What is *not* claimed, and must not be

### TLS payloads are not readable
The platform extracts **handshake metadata only** — the handshake type, the
Server Name Indication, the certificate subject and issuer, the version and
the cipher suite. The application data of a TLS session is not decrypted and
the platform does not attempt to. There is no TLS interception, no key
logging and no proxy.

The audit confirms this: there is no `SSLKEYLOGFILE`, no session-key
handling and no MITM proxy anywhere in `core/network/`.

This is stated explicitly because "deep packet inspection" invites the
assumption that encrypted traffic is readable. **It is not**, and the
platform does not pretend otherwise.

### Session reconstruction
TCP stream reassembly is **partial**: `packet_engine.py:428` reassembles the
segments it observes for the HTTP extraction. It is not a full TCP
implementation — there is no retransmission handling, no sequence-number
windowing and no out-of-order buffering. A capture with heavy loss will
produce truncated HTTP metadata.

**Finding DPI-01 (Medium, open):** the reconstruction should be documented
as best-effort, and the HTTP extraction should carry a "reconstructed
from an incomplete stream" marker so a consumer can tell.

---

## 5. Flow analysis

| Capability | State |
|---|---|
| Flow keying | Five-tuple (src/dst IP, protocol, src/dst port) |
| Byte and packet counters | Yes |
| Conversation grouping | Yes — `core/network/reporting.py` |
| Time-series | Yes — the reporting module produces the timeline |
| Packet-loss detection | **Not implemented.** There is no sequence-number gap analysis. |
| Round-trip time | **Not implemented.** The capture is not timestamped against a send. |

**Finding DPI-02 (Low, open):** the documentation and the dashboard label
these as "flow analytics" without stating that loss and RTT are not
derived. A consumer could otherwise read a flow table as a latency
measurement.

---

## 6. Detection rules and alert generation

| Capability | State |
|---|---|
| Signature matching | `core/signature_matching.py` — 150+ GhostJS signatures, with a literal prefilter and a line-partitioned scan |
| Threat detection | `core/network/threat_engine.py` — beaconing, DNS-tunnelling and exfiltration heuristics |
| Origin attribution | `core/network/origin_engine.py` — CDN and origin analysis |
| Geo attribution | `core/network/geo_engine.py` |
| Alert generation | Findings are raised as `VulnerabilityFinding` objects and persisted |
| Evidence storage | The evidence is redacted before it is persisted (`core/database.py:3870`) |
| Dashboard integration | `core/network/reporting.py` feeds the network views |

The DSA report records that the signature matcher had a quadratic-backtracking
regular expression on attacker-controlled response bodies (27 s on 64 KB).
It was fixed with a required-literal prefilter and a line-partitioned scan,
and the fix is covered by a 434-entry differential harness
(`tests/test_dsa_signatures.py`).

---

## 7. Performance and resource management

| Concern | State |
|---|---|
| Capture buffer | `sniff()` with a bounded `count` and a `timeout` |
| Packet-loss tolerance | The loop skips unparsable packets with a `continue` — a malformed packet does not stop the capture |
| Per-packet cost | `scapy` dissection is the dominant cost and is inherently high |
| Memory | The packet engine keeps **bounded** aggregates (counters, per-flow records) rather than the packets themselves |
| Resource cleanup | The capture context manager exits on exception |
| Rate | A capture is CPU-bound and single-threaded; there is no ring buffer and no offload |

**Finding DPI-03 (Medium, open):** a live capture of a busy link will
saturate a core, and the platform offers no way to sample, filter at the
socket level, or cap the packet rate. A BPF filter would be the natural
answer and scapy supports it.

---

## 8. Permissions

| Check | State |
|---|---|
| Raw-socket permission | Not probed explicitly; the platform reports the detected backend, which implies it |
| Administrator/root | Required on Windows for Npcap, on Linux for `AF_PACKET` |
| Failure to capture | Degrades to the socket-only path rather than failing the request |

**Finding DPI-04 (Low, open):** the permission requirement is not documented
per platform in the user-facing docs, and the platform does not state
explicitly whether the current process is privileged.

---

## 9. Privacy and data minimisation

| Concern | State |
|---|---|
| What is retained | Aggregates, flow records and protocol metadata — **not packet payloads** |
| Payload retention | The HTTP extraction retains request metadata and headers, which can contain a cookie or an `Authorization` header |
| Redaction | `redact_sensitive_evidence()` is applied before persistence, and it covers bearer tokens, basic-auth headers, API keys, secrets, tokens, passwords and private-key blocks |
| Export | The exports carry the same redacted evidence |
| Retention | Governed by the `findings` table; there is no separate capture retention policy |
| Personal data | A capture can contain DNS queries and HTTP hosts that identify a user. The platform retains them as findings. |

**Finding DPI-05 (Medium, open):** the platform retains HTTP metadata that
can carry an `Authorization` header. The redaction covers the common shapes,
but the *minimum necessary* principle would suggest not extracting and
storing request headers at all unless a rule matched.

---

## 10. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| DPI-01 | The TCP reassembly is best-effort and the HTTP extraction does not say so | Medium | **Open** |
| DPI-02 | "Flow analytics" implies loss and latency, which are not derived | Low | **Open** |
| DPI-03 | No BPF filter, sampling or rate cap for a live capture | Medium | **Open** |
| DPI-04 | The capture-permission requirement is not probed or documented | Low | **Open** |
| DPI-05 | HTTP request headers are retained although only a rule match needs them | Medium | **Open** |
| DPI-06 | The capture backends could not be exercised on the audit host | Info | Verified as unavailable — recorded, not a defect |

---

## 11. What was verified, and what was not

**Verified by execution:**

* The capability probe runs and reports the correct backend on a host with
  no capture driver.
* scapy is imported and the packet dissection classes are resolvable.
* The PCAP/PCAPNG magic numbers are defined and dispatched on.
* The redaction of bearer tokens, basic-auth headers, keys, passwords and
  private-key blocks is covered by `tests/test_security_regressions.py`.

**Not verified by execution — recorded as such:**

* A live capture was **not** performed: the audit host has no capture
  driver and capturing traffic was neither necessary nor appropriate.
* The protocol dissectors were **not** exercised against a real controlled
  capture; the audit inspected the parsing code and the magic-number
  dispatch, not the output.
* The threat heuristics were **not** run against a labelled dataset, so
  their detection rate and false-positive rate are unknown.

**This is the honest position:** the DPI subsystem is implemented and its
structure is sound, but its *behaviour* on real traffic has not been
measured on this host, and no claim is made about detection accuracy.
