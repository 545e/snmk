# SNMK — Documentation Audit Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Corpus** | 290 Markdown files (14 941 lines), 1 README, 1 `.env.example` |
| **Method** | Every documented claim checked against the implementation |

---

## 1. The state of the documentation

**It is extensive, largely accurate, and honest about its own limitations.**

290 documents is a lot of surface, and the majority of it is *accurate*.
The platform documents its architecture, its API, its agents, its tools, its
deployment, its security model and its testing in detail, and most of those
claims survive checking against the code.

What is weak is the **process** that keeps it true: nothing verifies a
documented number against the running system.

---

## 2. Findings

### 2.1 The agent count was wrong in 14 documents

**Severity:** Medium · **Status:** FIXED

The registry derives **94 agents across 6 tiers** at runtime. The README
said 94. **Fourteen documents still said 85 across 5 tiers in their body
text** — behind a correction banner at the top, which does not help a
reader who is looking at the sentence itself.

```markdown
# docs/AGENT_GUIDE.md, before
> **AGENT-COUNT CORRECTION (2026-11-11):** this document refers to "85 agents ...
The 85 agents are organized into 5 functional tiers:
```

**Fixed:** 19 body-text references across 14 documents now say 94 agents
across 6 tiers. The correction banners were left in place — they are
accurate history.

### 2.2 The correction banners are a symptom

**Severity:** Low · **Status:** Open

A banner at the top of a document that says "the rest of this document is
wrong" is a workaround, not a fix. It is a reasonable thing to do when a
count changes and the document is long, but it leaves the reader to notice
that the banner exists.

**Recommendation:** a CI check that compares the documented agent count with
`len(agent_registry.list_manifests())` and fails on a mismatch. The count
is already derived at runtime, so the check is three lines.

### 2.3 The "AI training" is a simulation and the documentation is inconsistent about it

**Severity:** Medium · **Status:** Open

`core/ai_training.py` implements a **simulated** training loop with a
reproducible loss decay — it does not train a model. The code says so, and
several documents say so:

> `ai_training.py` is a simulation — `docs/API_INVENTORY.md`

But the operator-facing surface does not. The dashboard presents an AI
training feature, and the API presents `/api/ai/training-jobs` as a real
job. The **documentation** is honest; the **interface** is not.

**Recommendation:** label the training surface as a simulation in the
dashboard and the API, exactly as the documentation already does.

### 2.4 The tier-4 agents return static capability dictionaries

**Severity:** Medium · **Status:** Open

The documentation is honest about this:

> **Tier-4 agent handlers largely return static capability dicts** (e.g.
> `{"nodes":150,"edges":320}` literals); dispatch reachability ≠ capability.

But it is recorded as a caveat in a corner of the documentation rather than
surfaced in the product. A dashboard that shows a capability the agent did
not actually measure is the same class of problem the previous pass fixed
in the REA engine and the tool registry — the honesty work is incomplete.

### 2.5 The "Verified clean" areas are documented, which is good

**Severity:** Info · **Status:** Recorded

`docs/DSA_ENGINEERING_REPORT.md` §5 records the areas that were checked
and found *not* to be problems — SQL injection, command injection,
deserialization, archive extraction, secret redaction. That is exactly the
right practice: a reader who finds a new audit does not have to re-derive
what has already been checked.

---

## 3. What is accurate

| Document | Claim | Verified |
|---|---|---|
| `README.md` | "94 agents", "6 operational tiers" | ✔ Matches the registry |
| `README.md` | "85/94 agents" derived at runtime | ✔ `list_manifests()` returns 94 |
| `docs/API_INVENTORY.md` | The route table | ✔ The route enumeration matches (176 `/api` routes) |
| `docs/TOOLS.md` | The tool catalogue | ✔ 34 registry entries, 15 external binaries |
| `docs/SECURITY.md` | The security model | ✔ The scope policy behaves as described |
| `docs/SCORING_AND_RISK.md` | The severity weights | ✔ Matches `core/scoring.py` |
| `docs/AGENT_GUIDE.md` | The six tiers | ✔ 17 / 9 / 10 / 32 / 17 / 9 = 94 |
| `docs/DSA_ENGINEERING_REPORT.md` | The measured performance | ✔ The numbers were reproduced |
| `docs/SONARQUBE.md` | The SonarQube setup | ✔ The workflow and the properties file match |
| `docs/CYBER_KILL_CHAIN.md` | The seven stages | ✔ Matches `core/kill_chain/stages/` |

---

## 4. Documentation that is missing

| Gap | Why it matters |
|---|---|
| **A security-model document** | The platform's SSRF guard, the scope allowlist, the credential vault and the authorisation model are described across four documents and none of them says how they fit together. `docs/SECURITY.md` is two pages. |
| **An operator runbook** | What to do when a scan fails, when the allowlist refuses a target, when the credential vault cannot decrypt, when a tool binary is missing. The troubleshooting document covers some of it, scattered. |
| **A data-protection statement** | The platform retains scan evidence, HTTP request metadata and DNS records. What it keeps, for how long, and what it redacts is spread across several documents. |
| **An explicit threat model** | Who is the adversary, what the platform defends against, and what it explicitly does not (for example: it does not defend against an operator who points it at an unauthorised target). |
| **A credential-rotation procedure** | The capability exists; the procedure does not exist. `SNMK_ENV_SECURITY_REPORT.md` §7 proposes one. |
| **A rollback procedure for a release** | The CI pipeline publishes an image and a wheel on a tag. There is no documented way back. |

---

## 5. The documentation that overstates

| Claim | Reality |
|---|---|
| "Enterprise-grade" | The authorisation metadata is decorative; the allowlist defaults off; the approval gate is not enforced. The platform is a capable **operator tool**, not an enterprise multi-tenant product. |
| "AI training" | A simulation. |
| "Verified capability" for the tier-4 engines | A static dictionary. |
| "Autonomous" | The agents are a fan-out of scripted checks with an LLM advisory path. The word is used loosely and consistently enough that it is more misleading than a wrong number would be. |

**None of these is fraud.** The platform's own engineering report is
candid about all of them, and this audit has repeated the caveats rather
than the marketing. But a reader who arrives at the README rather than at
the engineering report gets a different impression.

---

## 6. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| DOC-01 | 14 documents carried the old agent count in their body text | Medium | **FIXED** — 19 references updated |
| DOC-02 | The correction banners are a workaround for a missing check | Low | **Open** |
| DOC-03 | "AI training" is documented as a simulation but presented as a feature | Medium | **Open** |
| DOC-04 | The tier-4 static capability dictionaries are a caveat in the docs, not in the product | Medium | **Open** |
| DOC-05 | No consolidated security-model document | Medium | **Open** |
| DOC-06 | No operator runbook | Medium | **Open** |
| DOC-07 | No data-protection statement | Medium | **Open** |
| DOC-08 | No explicit threat model | Medium | **Open** |
| DOC-09 | No credential-rotation procedure | Low | **Open** — proposed in `SNMK_ENV_SECURITY_REPORT.md` §7 |
| DOC-10 | No release rollback procedure | Medium | **Open** |
| DOC-11 | The README's "enterprise-grade" framing is not supported by the authorisation model | Low | **Open** |

---

## 7. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Add a CI check that compares the documented agent count with the registry | Low | DOC-02 |
| 2 | Label the AI training surface as a simulation in the dashboard and the API | Low | DOC-03 |
| 3 | Surface the tier-4 static-capability caveat in the agent view | Low | DOC-04 |
| 4 | Write a consolidated security-model document | Medium | DOC-05 |
| 5 | Write an operator runbook | Medium | DOC-06 |
| 6 | Write a data-protection statement | Medium | DOC-07 |
| 7 | Write a one-page threat model | Medium | DOC-08 |
| 8 | Publish the credential-rotation procedure | Low | DOC-09 |
| 9 | Publish a release rollback procedure | Low | DOC-10 |
| 10 | Adjust the README's framing to match the authorisation model | Low | DOC-11 |
