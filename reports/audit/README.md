# SNMK — Audit Report Index

The 27 reports produced by the enterprise audit of 2026-11-15.

**Start here:** [`SNMK_FINAL_AUDIT_SUMMARY.md`](SNMK_FINAL_AUDIT_SUMMARY.md)

---

## The summary

| Report | Covers |
|---|---|
| [SNMK_FINAL_AUDIT_SUMMARY.md](SNMK_FINAL_AUDIT_SUMMARY.md) | The consolidated findings, the production-readiness assessment and the recommendations |
| [SNMK_ENGINEERING_AUDIT_REPORT.md](SNMK_ENGINEERING_AUDIT_REPORT.md) | The overall engineering posture: discovery, the baseline, what was fixed and what remains |

## Security

| Report | Covers |
|---|---|
| [SNMK_SECURITY_AUDIT_REPORT.md](SNMK_SECURITY_AUDIT_REPORT.md) | The application security findings: authentication, SSRF, file access, injection |
| [SNMK_API_SECURITY_REPORT.md](SNMK_API_SECURITY_REPORT.md) | The 197-route API surface against the OWASP API Security Top 10 |
| [SNMK_NETWORK_SECURITY_REPORT.md](SNMK_NETWORK_SECURITY_REPORT.md) | The scope policy, the SSRF guard and the outbound request paths |
| [SNMK_ENV_SECURITY_REPORT.md](SNMK_ENV_SECURITY_REPORT.md) | The configuration surface, the credential vault and the secret handling |
| [SNMK_SAST_SCA_SECRET_SCAN_REPORT.md](SNMK_SAST_SCA_SECRET_SCAN_REPORT.md) | SonarQube, Bandit, pip-audit and gitleaks — what ran and what it found |
| [SNMK_PENETRATION_TESTING_REPORT.md](SNMK_PENETRATION_TESTING_REPORT.md) | The platform's own penetration-testing machinery and its safety controls |
| [SNMK_DAST_OWASP_ZAP_REPORT.md](SNMK_DAST_OWASP_ZAP_REPORT.md) | The DAST gap and the concrete plan to close it |
| [SNMK_IAC_SECURITY_REPORT.md](SNMK_IAC_SECURITY_REPORT.md) | The Dockerfile, the Compose files and the workflows |
| [SNMK_CONTAINER_SECURITY_REPORT.md](SNMK_CONTAINER_SECURITY_REPORT.md) | The image: the user, the base, the layers, the build context |

## Quality and engineering

| Report | Covers |
|---|---|
| [SNMK_QA_TEST_REPORT.md](SNMK_QA_TEST_REPORT.md) | 454 tests, the measured coverage, the gaps and the missing cases |
| [SNMK_DSA_CODE_QUALITY_REPORT.md](SNMK_DSA_CODE_QUALITY_REPORT.md) | The data structures, the algorithms and the complexity profile |
| [SNMK_ARCHITECTURE_REPORT.md](SNMK_ARCHITECTURE_REPORT.md) | The layering, the concentration risks and the import cycles |
| [SNMK_PERFORMANCE_REPORT.md](SNMK_PERFORMANCE_REPORT.md) | The measured startup time, latency and resource usage |
| [SNMK_DEPENDENCY_AUDIT_REPORT.md](SNMK_DEPENDENCY_AUDIT_REPORT.md) | The 19 direct and 46 resolved dependencies, the licences and the missing lockfile |
| [SNMK_SONARQUBE_REPORT.md](SNMK_SONARQUBE_REPORT.md) | The static-analysis setup, the gate and the findings |
| [SNMK_DOCUMENTATION_AUDIT_REPORT.md](SNMK_DOCUMENTATION_AUDIT_REPORT.md) | Every documented claim checked against the implementation |

## The platform's subsystems

| Report | Covers |
|---|---|
| [SNMK_AI_AGENT_AUDIT_REPORT.md](SNMK_AI_AGENT_AUDIT_REPORT.md) | The 94 agents, their permissions and the approval gate |
| [SNMK_LLM_LANGCHAIN_LANGSMITH_REPORT.md](SNMK_LLM_LANGCHAIN_LANGSMITH_REPORT.md) | The LLM client, the prompt-injection posture and the observability gap |
| [SNMK_GISKARD_AI_TEST_REPORT.md](SNMK_GISKARD_AI_TEST_REPORT.md) | The AI-evaluation gap and what the platform covers instead |
| [SNMK_AUTOMATION_ENGINE_REPORT.md](SNMK_AUTOMATION_ENGINE_REPORT.md) | The workflow engine, the job lifecycle and the recovery paths |
| [SNMK_TOOL_INTEGRATION_REPORT.md](SNMK_TOOL_INTEGRATION_REPORT.md) | The three views of a tool and the provider adapters |
| [SNMK_DPI_AUDIT_REPORT.md](SNMK_DPI_AUDIT_REPORT.md) | The packet capture and protocol-analysis subsystems |
| [SNMK_DATABASE_AUDIT_REPORT.md](SNMK_DATABASE_AUDIT_REPORT.md) | The 43 tables, the indexing and the query patterns |
| [SNMK_CICD_AUDIT_REPORT.md](SNMK_CICD_AUDIT_REPORT.md) | The six workflows and what each one does and does not check |
| [SNMK_FRONTEND_BUILD_AUDIT_REPORT.md](SNMK_FRONTEND_BUILD_AUDIT_REPORT.md) | The frontend, the absence of a build system and the accessibility work |

---

## Reading order

| If you want | Read |
|---|---|
| The state of the project in five minutes | The summary, then §1 and §7 of the engineering report |
| The security posture | The security report, then the API and network reports |
| What to do next | §8 of the summary — the recommendations are ordered and effort-rated |
| The reasoning behind a specific fix | The `### I.0` and `### I.0.1` sections of `docs/DSA_ENGINEERING_REPORT.md` |
