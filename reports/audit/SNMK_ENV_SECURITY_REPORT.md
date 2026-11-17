# SNMK — Environment and Secret-Security Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Method** | Review of the configuration surface, the secret store, the git ignore rules, the build context and the documentation |
| **Rule** | No secret value appears in this report. Locations and shapes only. |

---

## 1. The configuration surface

| Variable | Purpose | Default | Assessment |
|---|---|---|---|
| `SWA_HOST` | The bind address | `127.0.0.1` | Good default — loopback. The container overrides it to `0.0.0.0`, which is correct inside a container. |
| `SWA_PORT` | The listen port | `8000` | |
| `SWA_LOG_LEVEL` | The log level | `info` | |
| `SWA_ALLOWED_ORIGINS` | The CORS allowlist | `http://127.0.0.1:8000,http://localhost:8000` | Good default — no wildcard. |
| `SWA_FORCE_HSTS` | HSTS | `0` | Off by default; a deployment behind TLS should set it to `1`. |
| `SWA_AUTH_ENABLED` | The authentication gate | **`false`** | **See §3.** |
| `SWA_API_KEY` | The master API key | `change_me_to_a_secure_random_api_key_for_production` | A placeholder the middleware recognises and refuses to treat as a real key. Good. |
| `SWA_SECRET_KEY` | The application secret | `change_this_to_a_secure_random_string_in_production` | A placeholder. |
| `SWA_API_TOKEN` | A bearer token for remote access | empty | |
| `SWA_RATE_LIMIT_ENABLED` | The rate limiter | `true` | On by default. Good. |
| `SWA_ENCRYPTION_KEY` | The credential-vault master key | empty | Empty means a local keyfile is generated. |
| `SWA_DB_PATH` | The database location | `swa_data.db` | |
| `SWA_LAB_MODE` | The lab-mode grant | `false` | |
| `SWA_ALLOWED_TARGETS_FILE` | The scope allowlist | `config/targets.json` | |
| `SWA_DEFAULT_CONCURRENCY` | The scan concurrency | `5` | |
| `SWA_DEFAULT_MAX_DEPTH` | The crawl depth | `2` | |
| `SWA_SCAN_TIMEOUT_SEC` | The scan timeout | `60` | |
| `SWA_AI_PROVIDER` | The LLM provider | `auto` | |
| `SWA_AI_MODEL` | The LLM model | `minimax/minimax-m3.1-flash:free` | A free tier model as the default. Sensible for a first run. |
| `SWA_AI_API_KEY` | The LLM key | `your_api_key_here` | A placeholder. |
| `SWA_AI_BASE_URL` | The LLM base URL | `https://openrouter.ai/api/v1` | |
| `SWA_REA_ALLOWED_ROOTS` | **New.** The roots the REA analyser may read | the platform's `data/` | |
| `SWA_EVIDENCE_ROOT` | **New.** The root the forensics tools work in | the platform's `data/` | |
| `SWA_INTEGRATION_ALLOWED_HOSTS` | **New.** Extra hosts an integration may use | empty | |
| `SWA_ENFORCE_ALLOWLIST` | Whether the scope allowlist is enforced | **`0`** | **See §4.** |

---

## 2. `.env.example`

**Every value is an obvious placeholder.** No key-shaped value, no token, no
real hostname, no account name.

The three placeholders the platform recognises by name are
`change_me_to_a_secure_random_api_key_for_production`,
`change_this_to_a_secure_random_string_in_production` and
`your_api_key_here`. The middleware's placeholder detection
(`web/server.py:263`) looks for `change_me`, `your_api_key`, `your_key`,
`placeholder`, `dummy`, `example`, `none` and `null` — so a deployment that
forgets to replace the key is treated as having **no** key, which is the
safe outcome.

**Finding ENV-01 (Low, open):** the `.env.example` header contains a
mojibake character (`SWA AI �? Environment Configuration Template`) — an
encoding artefact from an em-dash that was written in the wrong encoding.
Cosmetic, but it is the file every operator copies.

---

## 3. Authentication defaults

`SWA_AUTH_ENABLED` defaults to **`false`**, and in that mode
`core/app_security.py:231` returns `role="admin"` for every caller.

**Finding ENV-02 (High, open):** a fresh installation is fully
administrative to anyone who can reach the port.

The reason it is not simply switched on is the product's core use case: a
single operator running the platform locally on their own machine, where a
login prompt adds friction to no threat. The risk is the *deployment*, not
the development flow.

**What was done in this pass:**

* The container now sets `SWA_AUTH_ENABLED=true` by default and publishes
  on loopback only.
* The authentication bypass that made the setting meaningless is closed.
* The OpenAI-compatible endpoints are inside the gate.

**Finding ENV-03 (Medium, open):** the platform does not warn on start-up
that authentication is disabled. A single prominent log line — and a
`/api/auth/status` field that says so — would make the state visible
without changing the behaviour.

**Finding ENV-04 (Medium, open):** `SWA_API_KEY` empty plus
`SWA_AUTH_ENABLED=true` is a configuration in which *every* request is
refused. That is fail-closed and correct, but the failure message does not
say "no master key is configured". The entrypoint should refuse to start
instead.

---

## 4. The scope allowlist

`SWA_ENFORCE_ALLOWLIST` defaults to **`0`**, which means
`core/scope_policy.py:370` auto-authorises any host that is not in
`targets.json` for the duration of the session.

**Finding ENV-05 (High, open):** the configured allowlist provides no real
containment in the default configuration. The platform will scan any
internet host the operator names.

The default was chosen because a single-operator tool that refuses every
target until the allowlist is edited is unusable on first run. But the
behaviour should be the other way round for an intrusive tool.

**What was done in this pass:** the session allowlist that receives the
auto-authorised hosts is now **bounded** (256 entries, oldest evicted) and
is kept separate from the persisted allowlist, so it cannot grow without
limit and cannot be mistaken for a configured target.

**Finding ENV-06 (Medium, open):** `POST /api/scope/targets` writes an
arbitrary domain into the persisted allowlist. With authentication off
this is an unauthenticated write to the scope configuration.

---

## 5. The credential vault

`core/credentials.py` stores the integration secrets encrypted.

| Property | State |
|---|---|
| Algorithm | Fernet (AES-128-CBC + HMAC-SHA256) via `cryptography` |
| Key source | `SWA_ENCRYPTION_KEY`, or an auto-generated keyfile at `.swa_master.key` |
| Keyfile location | The repository root — **inside the source tree** |
| Keyfile mode | Written with the process umask; not explicitly chmod'ed (bandit B103) |
| Keyfile in git | **No** — git-ignored and untracked (verified with `git ls-files`) |
| Keyfile in the image | **Was yes, now no** — `.swa_master.key` was added to `.dockerignore` in this pass |
| Fallback when `cryptography` is missing | A hand-rolled XOR keystream (`credentials.py:116`) |
| Plaintext exposure | The list and get endpoints return `masked_value` only |

**Finding ENV-07 (Medium, open):** the fallback cipher is not
cryptography. It has no authenticated encryption, no key separation and no
nonce discipline, and it activates *silently* when a dependency is missing.

**Finding ENV-08 (Medium, open):** the master keyfile lives in the
repository root. It is git-ignored and now excluded from the Docker build
context, but it is still inside the source tree — a backup, an archive or a
`tar` of the working directory would carry it.

**Recommendation:** move the key to a path outside the tree (or to an OS
keyring), make `cryptography` a hard dependency that fails the start-up
rather than downgrading, and write the keyfile with an explicit `0600`.

---

## 6. Secret handling in the code

| Check | Result |
|---|---|
| Secrets logged | The `redact_sensitive_evidence()` function covers bearer tokens, basic-auth headers, API keys, secrets, tokens, passwords, private-key blocks and cookies. It is applied to `poc_curl`, `request_evidence` and `response_evidence` before a finding is persisted (`core/database.py:3870`). |
| Secrets in API responses | The integration endpoints return `masked_value` only. |
| Secrets in the frontend bundle | No key material was found in `web/static/app.js`, `index.html` or the stylesheets. The frontend reads its configuration from the API. |
| Secrets in the command line | The scanner adapters pass credentials through the environment or a config file, not the command line. |
| Secrets in the git history | gitleaks scanned all 155 commits: **one** real key-shaped value, in `docs/API_AUTHENTICATION.md`, now fixed. |

---

## 7. Rotation guidance

There is no documented rotation procedure. This is the procedure the code
supports:

| Secret | How to rotate | Effect |
|---|---|---|
| `SWA_API_KEY` | Change the environment variable and restart | Every existing bearer token stops working; sessions in the in-memory store are lost with the process |
| `SWA_ENCRYPTION_KEY` | Change it and **re-enter every stored integration secret** | The stored ciphertexts cannot be decrypted with the new key. `core/credentials.py` will fail to decrypt them rather than return garbage. |
| `SWA_SECRET_KEY` | Change it and restart | The session store is in-memory, so every session is invalidated by the restart |
| `SWA_OPERATOR_PASSWORD` | Change it and restart | Takes effect at the next login |
| An integration's own key | Re-enter it through `PUT /api/integrations/{id}` | The stored value is re-encrypted with the current master key |
| `.swa_master.key` | Delete it and let the platform regenerate, then re-enter every integration secret | Same as `SWA_ENCRYPTION_KEY` |

**Finding ENV-09 (Low, open):** rotating `SWA_ENCRYPTION_KEY` silently
invalidates every stored integration secret, and nothing warns the operator
before or after. The rotation procedure should be documented and the
credential list endpoint should report how many stored secrets would be
affected.

---

## 8. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| ENV-01 | A mojibake character in the `.env.example` header | Low | **Withdrawn** — re-checking the bytes showed valid UTF-8 (an em dash). The apparent mojibake was a PowerShell console rendering artifact, not a file defect. No change was made. |
| ENV-02 | Authentication is off by default | High | **Open** — the container default was changed and the bypass closed |
| ENV-03 | The platform does not warn at start-up that authentication is disabled | Medium | **Open** |
| ENV-04 | No start-up check for "authentication enabled but no key configured" | Medium | **Open** |
| ENV-05 | `SWA_ENFORCE_ALLOWLIST` defaults off, so the scope allowlist does not contain | High | **Open** |
| ENV-06 | `POST /api/scope/targets` writes to the persisted allowlist unauthenticated | Medium | **Open** |
| ENV-07 | The credential store silently downgrades to a hand-rolled XOR cipher | Medium | **Open** |
| ENV-08 | The master keyfile lives inside the source tree | Medium | **Open** |
| ENV-09 | Rotating the encryption key silently invalidates every stored secret | Low | **Open** |
| ENV-10 | The keyfile is written without an explicit restrictive mode (bandit B103) | Medium | **FIXED** — the keyfile is now created with `os.open(..., 0o600)`, so it is never briefly readable under the process umask. |
| ENV-11 | The build context included `.env` | High | **FIXED** — `.dockerignore` |
| ENV-12 | A key-shaped value was committed in the documentation | Medium | **FIXED** — `docs/API_AUTHENTICATION.md` |

---

## 9. Recommendations

| # | Action | Effort |
|---|---|---|
| 1 | Default `SWA_ENFORCE_ALLOWLIST=1` and make the first-run experience explicit | Low |
| 2 | Log a prominent warning at start-up when authentication is disabled | Low |
| 3 | Refuse to start when authentication is enabled and no key is configured | Low |
| 4 | Make `cryptography` a hard dependency; never downgrade the cipher | Low |
| 5 | Write the keyfile with an explicit `0600` and move it outside the source tree | Low |
| 6 | Require an admin role and an audit record for a scope-allowlist change | Medium |
| 7 | Publish a rotation procedure and report the blast radius of an encryption-key change | Low |
| 8 | Fix the `.env.example` header encoding | Low |
| 9 | Add a gitleaks allowlist for the known false positives so the scanner stays actionable | Low |
