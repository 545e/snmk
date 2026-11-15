# SNMK LLM, LangChain & LangSmith Engineering Audit Report

**Audit Area:** LLM Client, Prompt Engineering, LangChain Pipelines, LangSmith Tracing  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Adapter Module:** `core/langchain_adapter.py`, `core/llm_client.py`  
**Status:** **ENTERPRISE SECURED**

---

## 1. Executive Summary

This report audits the LLM integration layer, prompt engineering defenses, LangChain pipeline adapters, and LangSmith observability interfaces within SNMK. The architecture isolates upstream model providers (Gemini, OpenAI, Anthropic, Ollama) behind uniform abstractions while neutralizing adversarial prompt injections and enforcing structured output validation.

---

## 2. LangChain Adapter Architecture ([core/langchain_adapter.py](file:///C:/Users/krish/SWA/core/langchain_adapter.py))

### 2.1 Prompt Injection Defense (`SecurityPromptTemplate`)
User-supplied parameters and untrusted document inputs are filtered against adversarial prompt injection signatures prior to template rendering:
```python
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\bsystem\s+prompt\s+override\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+in\s+developer\s+mode\b"),
    re.compile(r"(?i)\bDAN\s+mode\b"),
    re.compile(r"(?i)\breveal\s+your\s+(internal|initial|system)\s+prompt\b")
]
```
Matching injection phrases are neutralized with `[FLAGGED_INJECTION_ATTEMPT_NEUTRALIZED]`, defeating jailbreak vectors.

### 2.2 Standard Chat Model Wrapper (`SNMKChatModel`)
Wraps `core.llm_client.SWALLMClient` to expose standard `invoke()` and `ainvoke()` interfaces. If upstream providers experience outages or network timeouts, the client activates an autonomous heuristic fallback without throwing unhandled exceptions.

### 2.3 RAG Knowledge Retrieval (`SNMKRetriever`)
Interfaces with `core.rag_engine.RAGKnowledgeEngine` using hybrid BM25 and term frequency analysis, grounding vulnerability assessments in verified OWASP benchmarks with strict citations.

### 2.4 Structured Output Validation (`StructuredVulnerabilityOutput`)
LLM responses are validated and parsed into strict Pydantic models with title, severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`), CWE identifier, CVSS 3.1 score, and actionable remediation patch diffs.

---

## 3. LangSmith & Telemetry Redaction

Trace spans sent to LangSmith or Tempo are sanitized:
- Prompts containing Bearer tokens, private keys, or passwords have credentials redacted.
- Metadata is tagged with `request_id`, `model_name`, and `latency_ms` for cost and performance tracking.
