# SNMK — Network Security Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Scope** | `core/network/` (15 modules), the network-facing integrations, the scanner adapters, the scope policy |
| **Method** | Source review of every outbound request path, plus verification of the scope policy's behaviour |

---

## 1. The network surface

SNMK makes outbound requests in four distinct roles, and the security
requirement is different for each:

| Role | Examples | Requirement |
|---|---|---|
| **Auditing a target** | `core/cyber_tools.py` DNS/SSL/whois probes, `agents/recon_agent.py`, `agents/amass_engine.py`, `plugins/owasp_plugins.py` | The target is the *subject*; it must be inside the authorised scope |
| **Reaching an integration** | `core/integrations/*` | The host is operator-configured; it must be public and must be one the provider is expected to use |
| **Reaching a webhook** | `core/notifier.py` | The host is operator-configured; the same rules apply |
| **Reaching a tool binary** | `core/tool_dependency_manager.py` | The host is the tool's distribution point; it must be on the source allowlist |

The audit's central finding was that **the integration and webhook roles
had no host validation at all**, while the auditing role did.

---

## 2. The scope policy — the choke point

`core/scope_policy.py` is the single place that decides whether a hostname
may be contacted. It performs:

1. **Scheme validation** — only `http` and `https`.
2. **Hostname normalisation** — `urlparse` + `hostname`, so a userinfo
   prefix or a port cannot be used to smuggle a different host.
3. **Syntax validation** — the hostname must match the domain regex.
4. **DNS resolution** — and **every** returned address is checked.
5. **Address classification** — loopback, private, link-local, multicast,
   reserved and unspecified ranges are refused; so is `169.254.169.254`.
6. **Allowlist enforcement** — the host must be in the configured allowlist,
   or explicitly authorised for this session.
7. **Lab-mode handling** — a pre-authorised lab target may use a restricted
   address, but only with an explicit grant.

### Findings fixed in this pass

| ID | Finding | Fix |
|---|---|---|
| NET-01 | `_restricted_reason()` inspected only the **first** address a name resolved to. A DNS answer that mixed a public address with a private one passed the guard depending on the resolver's ordering. | Every resolved address is now inspected. |
| NET-02 | A hostname was resolved **twice** per validation — once by the SSRF guard and once by `validate_target()`. The second resolution could return a different answer, so the address that was checked was not necessarily the address that was used. | The addresses the guard resolved are handed to `validate_target()`; a hostname is resolved once. |
| NET-03 | The session-scoped allowlist grew without limit and was swept in O(n) on every validation. | The session set is separate from the persisted allowlist, capped at 256 entries, and evicted oldest-first. |
| NET-04 | Loopback is auto-classified as a lab target, so a request to `127.0.0.1` on the server is authorised without the caller enabling lab mode. | **Open** — the fix requires a signed lab grant rather than a string comparison. |
| NET-05 | `SWA_ENFORCE_ALLOWLIST` defaults to off, so a host that is not in `targets.json` is auto-added to a session allowlist and passes. | **Open** — the default should be on. |
| NET-06 | The resolution result is not pinned to the connection, so a short-TTL DNS name can be rebound between the check and the request. | **Open** — needs a transport that connects to the validated address. |

### Verified behaviour

| Check | Result |
|---|---|
| `http://169.254.169.254/latest/meta-data/` | Refused — cloud metadata |
| `http://127.0.0.1:8000/` | Refused unless lab mode is granted |
| `http://10.0.0.1/` | Refused — RFC 1918 |
| `http://[::1]/` | Refused — loopback |
| `file:///etc/passwd` | Refused — scheme |
| `http://evil.com@127.0.0.1/` | Refused — the hostname is parsed, not the prefix |
| A name resolving to both a public and a private address | Refused — every address is checked |

---

## 3. The integration adapters — the gap that was closed

Before this pass, `core/integrations/*.py` contained **no reference at all**
to `validate_tool_target`, `ipaddress` or `169.254`. An operator-supplied
`endpoint_url` was checked for its scheme and its host's presence, and then
the request was made — carrying the provider's own credential:

| Adapter | Credential sent | Host |
|---|---|---|
| `OpenAIAdapter` | `Authorization: Bearer <api_key>` | operator-supplied |
| `WazuhAdapter` | HTTP Basic `username:password` | operator-supplied |
| `SplunkAdapter` | `Authorization: Splunk <hec_token>` | operator-supplied |
| `ElasticSecurityAdapter` | `Authorization: ApiKey <api_key>` | operator-supplied |
| `DefectDojoAdapter` | `Authorization: Token <api_key>` | operator-supplied |
| `CrowdStrikeAdapter` | `client_secret` in the body | operator-supplied |
| `CISAKEVAdapter`, `FirstEPSSAdapter` | none | operator-supplied |

**Now:** `core/integrations/endpoint_policy.py` is the single decision point.
It rejects a non-HTTP scheme, an embedded credential, a host that resolves
to a restricted address, and — for the providers that are only ever a SaaS
offering — a host that is not one of theirs.

Self-hosted products (Splunk, Elasticsearch, Wazuh, DefectDojo) and
OpenAI-compatible gateways (LiteLLM, vLLM) accept any **public** host,
because that is what they are for. The address guard still applies, so they
cannot be used to reach the platform's own network. An operator who needs a
specific host for a SaaS provider can allow it with
`SWA_INTEGRATION_ALLOWED_HOSTS`.

---

## 4. DNS resolution behaviour

| Concern | State |
|---|---|
| IPv4 | Supported and used throughout |
| IPv6 | `socket.getaddrinfo` resolves AAAA and the address guard classifies `::1` and the IPv6 private ranges. **The application does not globally disable IPv6.** |
| Timeout | `getaddrinfo` has no timeout of its own; it relies on the OS resolver configuration. **Open** — a slow resolver blocks the calling thread. |
| Caching | **None.** Every validation performs a fresh resolution. That is the safe default (it defeats stale-cache rebinding) but it costs a lookup per request. |
| Reverse DNS | `socket.gethostbyname_ex` is used in `core/network/discovery.py` for the canonical name. |
| Resolution failure | `validate_target` returns `DNS_RESOLUTION_FAILURE` and refuses. The `_resolve_addresses` helper returns an empty list, and the guard then refuses rather than assuming the host is safe. |

---

## 5. The scanner adapters

`core/scanner_integrations.py` runs nmap, nuclei, sqlmap, nikto, bandit,
semgrep, trivy and gitleaks.

| Property | State |
|---|---|
| Target validation | `run_nmap_safe` and `run_nuclei_safe` call `validate_tool_target` before spawning. |
| Argument injection | Explicitly defended: `scanner_integrations.py:930` rejects a target that starts with `-`; `:963` validates the port specification against `^\d{1,5}([,\-]\d{1,5})*$`; `:1137` validates the sqlmap URL. |
| Shell usage | **None.** Every subprocess uses an argument list. |
| Timeout | Present on every adapter (40–60 s). |
| Process cleanup | `asyncio.create_subprocess_exec` with `wait_for` — a timeout kills the wait, and the process is reaped by the event loop's child watcher. |
| Rate limiting | Not per-scan; the platform-wide limiter applies to the HTTP surface, not to the spawned processes. |
| Evidence capture | The nmap XML is parsed and the ports are returned; nuclei and sqlmap produce structured findings that are persisted. |
| Audit log | The scan is recorded in the `scans` table with its target. |

**Finding NET-07 (Medium, open):** the external binaries are resolved
through `PATH` rather than by absolute path (bandit B607, 11 sites). A
poisoned `PATH` would substitute the binary. The fix is to resolve the
binary once, at installation time, and record its absolute path.

---

## 6. IPv4 and IPv6

The requirement was to prefer IPv4 only where the environment demands it,
and **not** to disable IPv6 globally. The audit confirms:

* `socket.getaddrinfo` is used, so both families are resolved and both are
  classified by the address guard.
* There is no `AF_INET` hard-coding that would silently drop IPv6-only
  hosts.
* `core/network/interfaces.py` and `discovery.py` enumerate IPv6 addresses
  alongside IPv4.

**No IPv6 workaround was introduced by this audit.**

---

## 7. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| NET-01 | Only the first resolved address was checked | High | **FIXED** |
| NET-02 | The hostname was resolved twice per validation | Medium | **FIXED** |
| NET-03 | The session allowlist grew without limit | Medium | **FIXED** |
| NET-04 | Loopback is auto-classified as a lab target | Medium | **Open** |
| NET-05 | `SWA_ENFORCE_ALLOWLIST` defaults off | Medium | **Open** |
| NET-06 | The resolved address is not pinned to the connection | Medium | **Open** |
| NET-07 | External binaries are resolved through `PATH` | Medium | **Open** |
| NET-08 | `getaddrinfo` has no timeout of its own | Low | **Open** |
| NET-09 | No DNS cache, so every validation costs a lookup | Low | **Open** — deliberate; a cache needs a rebinding review |
| NET-10 | The integration adapters had no host validation at all | High | **FIXED** |

---

## 8. Recommendations

| # | Action | Effort |
|---|---|---|
| 1 | Default `SWA_ENFORCE_ALLOWLIST=1` | Low |
| 2 | Require an explicit lab grant rather than inferring it from the target string | Medium |
| 3 | Pin the validated IP to the connection so rebinding cannot bypass the guard | Medium |
| 4 | Resolve the external binaries once and record their absolute path | Low |
| 5 | Give the resolver a bounded timeout | Medium |
| 6 | Add the timeout to the 35 HTTP calls without one | Low |
