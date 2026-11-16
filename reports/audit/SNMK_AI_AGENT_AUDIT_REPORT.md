# SNMK — AI / Multi-Agent Audit Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Method** | Import-graph analysis of every AI-related module, plus a review of the agent registry, the orchestrator and the LLM client |
| **Headline** | The agent framework is **hand-rolled**. None of CrewAI, LangChain, LangSmith or Giskard is used, and the project does not claim to use them. |

---

## 1. Which frameworks are actually used

| Framework | Import sites in the codebase | Declared in `requirements.txt` | Used |
|---|---|---|---|
| **CrewAI** | **0** | No | **No** |
| **LangChain** | **0** | No | **No** |
| **LangSmith** | **0** | No | **No** |
| **Giskard** | **0** | No | **No** |
| `transformers` / `torch` | 0 / 1 (`core/ai_training.py:81`, inside a `try`) | No | **No** — the import is guarded and the package is absent |
| The OpenAI / Anthropic **HTTP APIs** | `core/llm_client.py` calls `api.openai.com` and `api.anthropic.com` directly with `httpx` | No (the SDKs are not used) | **Yes** |

**The platform is a hand-rolled multi-agent system that speaks the provider
HTTP APIs directly.** `core/llm_client.py:292` posts to
`https://api.anthropic.com/v1/messages` and `:353` to
`https://api.openai.com/v1/chat/completions`, both with `httpx`.

This is a legitimate design choice and it is worth stating plainly: **there
is no framework abstraction to inherit, and therefore no framework's
failure modes either.** The consequences are that there is also no built-in
tracing, no prompt registry, no evaluation harness and no token accounting
— all of which the platform would have had to build itself, and mostly has
not.

**Finding AI-01 (Informational):** the documentation does not claim to use
these frameworks, and the README does not mention them. There is no
misrepresentation to correct. This report records the position so that a
reader does not assume a framework is present.

---

## 2. The agent registry

`core/agent_registry.py` (1 623 lines) defines the agents and derives the
count at runtime.

| Property | State |
|---|---|
| Agent count | **94**, derived from the registry — not hard-coded |
| `discover_all_agents()` | 763 lines — the single largest function in the codebase after `init_db()` |
| `dispatch_agent_by_id()` | 526 lines |
| Per-agent configuration | Each agent names a module, a class and a timeout (`core/agent_registry.py:423`) |
| Dispatch | The registry resolves the module and class and constructs the agent |

**Finding AI-02 (Medium, open): `discover_all_agents()` rebuilds every
manifest on every call** — 94 manifests, each constructed from a module
path, a class name and a parameter set. It is called by the dashboard on
every load.

**Finding AI-03 (Medium, open): `dispatch_agent_by_id()` is 526 lines** and
mixes the manifest lookup, the argument construction, the error handling
and the result normalisation.

**Finding AI-04 (Low, open): `config/85_agents_matrix.json` is an orphaned
artefact** — no code loads it, and it disagrees with the registry on five
agents' timeouts. It should be generated from `discover_all_agents()` or
deleted. The DSA engineering report has recorded this as outstanding since
an earlier pass.

---

## 3. Do the agents do what they advertise?

The audit checked the agents against their declared capability rather than
their name.

| Check | Result |
|---|---|
| Every agent resolves to an importable module and class | **Yes** — the registry is exercised by `tests/test_all_85_agents.py` and by the 94/94 dispatch check the DSA report records |
| Every agent is reachable through the dispatch endpoint | **Yes** |
| The tier classification matches the implementation | The tier is metadata; the audit did not re-derive it from the behaviour |
| The declared capabilities match what the engine does | **Not verified for every agent.** The engine still emits a number of hard-coded capability literals — the DSA report records this as an open honesty gap |

**Finding AI-05 (Medium, open):** some tier-4 engines emit hard-coded
capability strings rather than a result derived from an actual probe. The
platform therefore sometimes reports a capability it did not verify. This
was recorded in an earlier pass and is unchanged here.

---

## 4. Permissions, approval and tool access

| Control | State |
|---|---|
| **Least-privilege tool access per agent** | **Not implemented.** The registry does not declare which tools an agent may use; the agent's own code decides. |
| **Approval gate** | `core/approval_engine.py` defines `MANDATORY_APPROVAL_ACTIONS` — aggressive scanning, exploit validation, destructive testing, production change, risk acceptance, high-impact remediation and scope expansion — and `requires_approval()`. **It is never called outside its own definition.** |
| **Lab mode** | Enforced per call through the scope policy, but a loopback target is auto-classified as a lab target |
| **Can an LLM response trigger a privileged action?** | **No.** The LLM output is advisory: it produces a remediation suggestion or a PoC *description*, which becomes a `VulnerabilityFinding` marked unverified. There is no path from an LLM response to a privileged execution. |
| **Prompt injection from untrusted data** | The copilot's system prompt is fixed, and the retrieved context is scrubbed before it enters the prompt (`core/llm_client.py` `reason()`, per the DSA report's DSA-BE-12 fix). The residual risk is that a scanned target's content reaches the copilot's context. |

**Finding AI-06 (High, open): the approval gate is a declaration, not a
control.** `ApprovalEngine.requires_approval()` is never called. The
orchestrator (`agents/orchestrator.py`) runs the fuzzer, the
dependency-confusion agent and the exploit validator with **no** approval
step, and `agents/exploit_validator_agent.py` contains no approval or
lab-mode check at all.

**Finding AI-07 (Medium, open): an agent has no declared tool
permissions.** The registry names the module and the class but not what
the agent is allowed to do, so the least-privilege principle cannot be
enforced at the dispatch layer. The scope policy is the only boundary,
and it applies to the *target*, not to the *action*.

---

## 5. Error handling, timeouts and retries

| Concern | State |
|---|---|
| Per-agent timeout | **Yes** — each manifest carries a timeout (`core/agent_registry.py:423`) |
| Retry | The agent base class retries; the DSA report records that the retries are bounded |
| Cancellation | `core/queue_manager.py` tracks the active tasks; `core/tool_dependency_manager.py` has a cancellation token |
| Resource consumption | An agent that hangs holds its thread until the timeout fires. There is **no global concurrency cap** on the dispatch. |
| Memory | Each of the 94 manifests is rebuilt on every discovery call |

**Finding AI-08 (Medium, open): there is no global limit on concurrent
agent dispatch.** A scan of a large target can fan out to dozens of agents
at once.

**Finding AI-09 (Low, open):** the agent framework has no persistent
execution state.** The DSA report records that
`discover_all_agents()` discards execution state, so a restart loses the
history of what ran.

---

## 6. Memory, knowledge and RAG

| Subsystem | Module | State |
|---|---|---|
| Agent memory | `core/agent_memory.py` (10 085 bytes) | Stores and retrieves episodes |
| Knowledge graph | `core/knowledge_graph.py` (12 739 bytes) | Entities and relations |
| RAG | `core/rag_engine.py` (14 892 bytes) | BM25 retrieval over chunks |
| Prompt management | **None** | The prompts are string literals in the code; there is no registry, no versioning and no evaluation |

The DSA report records the RAG performance work: the per-query allocations
and the double scoring were fixed, but the engine still performs two
full-corpus passes per query. Building an inverted index at ingest time is
the remaining structural change, with a golden test to preserve the
scoring exactly.

**Finding AI-10 (Medium, open): there is no prompt registry or prompt
versioning.** A prompt is a string literal in the module that uses it.
There is no way to tell which prompt produced a given finding, and no way
to roll one back.

---

## 7. Duplicate and conflicting agents

The DSA report records that the 94 agents are organised into six tiers:
Specialist Workforce (17), Offensive Recon (9), OWASP Plugins (10), Core
Cybersecurity Engines (32), Tool Adapters (17) and Network Intelligence (9).

**Finding AI-11 (Medium, open):** the "Core Cybersecurity Engines" tier
contains 32 agents, and several of them overlap — the kill-chain stage
analyzers, the scanner adapters and the tool registry all analyse the same
evidence from different angles. The audit did not re-derive which are
genuinely distinct.

---

## 8. What is right

* **The agent count is derived, not declared.** The dashboard and the
  documentation cannot drift from the implementation.
* **Every agent resolves.** A broken manifest is a test failure, not a
  runtime surprise.
* **The LLM cannot cause a privileged action.** The output of a model
  becomes an unverified finding, never an executed step. This is the single
  most important property of an LLM-driven security tool, and it holds.
* **The retrieved context is scrubbed** before it enters a prompt, and the
  evidence is scrubbed before it is persisted.
* **There is a heuristic fallback.** `core/llm_client.py:365`
  (`_heuristic_poc_analysis`) and `:444` (`_heuristic_remediation`) produce
  a deterministic result when no provider is configured, so the platform
  degrades rather than failing.
* **The approval concept exists** even though it is not yet enforced.

---

## 9. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| AI-01 | CrewAI / LangChain / LangSmith / Giskard are not used — the framework is hand-rolled | Info | Recorded; no misrepresentation to correct |
| AI-02 | `discover_all_agents()` rebuilds all 94 manifests on every call | Medium | **Open** |
| AI-03 | `dispatch_agent_by_id()` is 526 lines | Medium | **Open** |
| AI-04 | `config/85_agents_matrix.json` is orphaned and disagrees with the registry | Low | **Open** |
| AI-05 | Some tier-4 engines emit hard-coded capability literals rather than a probed result | Medium | **Open** |
| AI-06 | `ApprovalEngine.requires_approval()` is never called — destructive and exploit-class actions run without the advertised human sign-off | High | **Open** |
| AI-07 | No per-agent tool permissions are declared | Medium | **Open** |
| AI-08 | No global cap on concurrent agent dispatch | Medium | **Open** |
| AI-09 | The agent framework keeps no persistent execution state | Low | **Open** |
| AI-10 | No prompt registry, no prompt versioning, no prompt evaluation | Medium | **Open** |
| AI-11 | Overlap between the 32 core engines and the scanner/adapter tiers | Medium | **Open** |
| AI-12 | The LLM's base URL was writable and could exfiltrate the provider key | High | **FIXED** — the endpoint policy |

---

## 10. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Call `ApprovalEngine.requires_approval()` from the orchestrator and from every offensive adapter; block execution until an `APPROVED` decision exists, and fail closed when lab mode is not explicitly confirmed | Medium | AI-06 |
| 2 | Declare the tools each agent may use in the registry, and enforce it at dispatch | Medium | AI-07 |
| 3 | Cache the manifests and rebuild them only when the registry changes | Low | AI-02 |
| 4 | Add a global concurrency cap on the dispatch, with a 429 above it | Medium | AI-08 |
| 5 | Introduce a prompt registry with versioning and a regression corpus | Medium | AI-10 |
| 6 | Split `dispatch_agent_by_id()` and `discover_all_agents()` | Medium | AI-02, AI-03 |
| 7 | Generate or delete `config/85_agents_matrix.json` | Low | AI-04 |
| 8 | Replace the hard-coded capability literals with a probed result | Medium | AI-05 |
| 9 | Persist the execution state so a restart does not lose the history | Medium | AI-09 |
| 10 | Review the 32 core engines for genuine overlap | High | AI-11 |
