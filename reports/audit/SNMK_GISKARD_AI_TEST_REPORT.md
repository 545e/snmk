# SNMK — Giskard AI Testing Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Method** | Import-graph analysis of the whole codebase, plus a review of every module that could host an AI-evaluation suite |

---

## 1. The finding

**Giskard is not used by SNMK. It is not installed, not imported, not
declared as a dependency, and not referenced in any configuration, workflow
or document.**

| Evidence | Result |
|---|---|
| Import sites for `giskard` across all 174 Python modules | **0** |
| `giskard` in `requirements.txt` / `requirements-dev.txt` | **No** |
| `giskard` in any GitHub Actions workflow | **No** |
| `giskard` in the documentation | **No** |
| A LLM evaluation corpus, dataset or test harness in the repository | **No** |

**The platform does not claim to use Giskard.** There is no
misrepresentation to correct — this report records the position so that a
reader does not assume an AI-evaluation suite is present.

---

## 2. What the platform does instead

SNMK has its own, much smaller, evaluation and safety machinery:

| Capability | Module | What it does |
|---|---|---|
| **Heuristic fallback** | `core/llm_client.py:365`, `:444` | A deterministic PoC analysis and remediation suggestion when no provider is configured. The platform never fabricates an LLM result. |
| **LLM red-team harness** | `core/llm_security_testing.py` (17 876 bytes) | 12 OWASP LLM Top 10 categories — prompt injection, jailbreak, system-prompt extraction, sensitive-data disclosure, insecure output, excessive agency, RAG poisoning — with a safe canary. |
| **Model evaluation** | `core/ai_evaluation.py` (17 892 bytes) | Precision, recall, F1, a confusion matrix, latency, throughput, token usage and a cost estimate for a classifier. |
| **Training** | `core/ai_training.py` (10 847 bytes) | A simulated training loop with a reproducible loss decay. |
| **Grounding** | `core/rag_engine.py` | BM25 retrieval with a scrubbed context. |
| **Prompt-injection defence** | `core/llm_client.py` | The prompt, the history and the grounding are scrubbed before the call. |
| **Evidence redaction** | `core/app_security.py` | Credentials are stripped from anything persisted. |

`tests/test_llm_security_testing.py` (3 tests) exercises the red-team
harness, and `tests/test_ai_training_and_evaluation.py` exercises the
evaluation engine.

---

## 3. What each Giskard capability would map onto

The prompt asks how Giskard's capabilities are covered. The honest answer
is: **three of them partially, four of them not at all.**

| Giskard capability | Covered by SNMK? | Assessment |
|---|---|---|
| **LLM testing** | **Partially.** `core/llm_security_testing.py` runs 12 threat categories against the copilot with a canary. | Real coverage of the *attack* side. It is not a general-purpose LLM test suite. |
| **RAG evaluation** | **No.** `core/rag_engine.py` has no ground-truth dataset and no relevance metric. | A gap. There is no way to say whether the retrieval returns the right chunks. |
| **Hallucination detection** | **Partially.** The heuristic fallback is deterministic, and the LLM output is marked unverified — so a hallucination does not become a verified finding. But nothing *measures* the hallucination rate. | The consequence is contained; the rate is unknown. |
| **Prompt-injection tests** | **Partially.** The red-team harness includes injection categories. | There is no adversarial *corpus* and no regression assertion. |
| **Sensitive-information leakage** | **Yes.** `redact_sensitive_evidence()` and the prompt scrubbing, with regression tests in `tests/test_security_regressions.py`. | The strongest of the seven. |
| **Robustness testing** | **No.** | A gap. |
| **Bias and reliability** | **No.** | A gap, and arguably out of scope for a security tool. |

---

## 4. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| GISK-01 | **There is no RAG evaluation.** The retrieval engine has no ground-truth dataset and no relevance metric, so "did it retrieve the right chunk?" cannot be answered. | Medium | **Open** |
| GISK-02 | **There is no hallucination measurement.** A hallucination cannot become a verified finding, but the rate is unknown. | Medium | **Open** |
| GISK-03 | **There is no adversarial prompt corpus and no regression assertion.** The red-team harness exists; a corpus does not. | Medium | **Open** |
| GISK-04 | **There is no robustness testing.** The platform's behaviour under a malformed or adversarial provider response is not asserted. | Medium | **Open** |
| GISK-05 | **There is no evaluation in CI.** `core/ai_evaluation.py` exists and is unit-tested, but nothing runs an evaluation against the model in the pipeline. | Medium | **Open** |
| GISK-06 | **The "training" is a simulation.** `core/ai_training.py` implements a reproducible loss-decay loop, not model training. The documentation and the module both describe it as a simulation; the API surface and the dashboard labels are what an operator reads. | Medium | **Open** — the simulation is honest in the code, but the operator-facing label should say so |
| GISK-07 | Giskard is not used | Info | Recorded; no misrepresentation to correct |

---

## 5. Recommendations

**Should SNMK adopt Giskard?** The prompt asks for an evaluation of the
integration where applicable. The honest position is that **it is not
applicable as-is**: Giskard is a library for testing an LLM application, and
SNMK's "LLM application" is a copilot over a security corpus rather than a
user-facing chatbot. That said, three of Giskard's ideas map cleanly onto
what SNMK is missing.

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Build a small ground-truth RAG corpus — 30 to 50 question/chunk pairs over the platform's own documentation — and assert retrieval relevance in CI | Medium | GISK-01 |
| 2 | Build an adversarial prompt corpus with expected invariants, and run it as a regression test | Medium | GISK-03 |
| 3 | Measure the hallucination rate on the copilot: ask questions whose answer is known to be absent from the corpus, and assert the copilot says so | Medium | GISK-02 |
| 4 | Add a robustness test: a malformed provider response, a truncated response, an empty response, and a provider timeout | Low | GISK-04 |
| 5 | Run `core/ai_evaluation.py` against the configured model in CI, and publish the metrics | Medium | GISK-05 |
| 6 | Label the AI training surface as a simulation in the dashboard, as the code already does | Low | GISK-06 |
| 7 | Consider Giskard (or an equivalent) for the copilot's own prompt-injection and leakage suites once the corpus exists | Medium | GISK-03 |

**If Giskard is adopted**, the concrete case is the LLM red-team harness:
`core/llm_security_testing.py` already has the right shape — a set of
attack categories, a safe canary, a verdict — and Giskard would supply the
dataset management, the reproducibility and the reporting around it. The
trade-off is a dependency surface in a security tool, which is the same
trade-off that applies to LangChain.
