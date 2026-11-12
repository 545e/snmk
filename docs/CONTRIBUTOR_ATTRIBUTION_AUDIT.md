# Contributor Attribution Audit — SNMK (545e/snmk)

**Repository:** https://github.com/545e/snmk.git
**Objective:** remove the unwanted `claude` entry from the GitHub Contributors section.
**Scope:** GitHub contributor attribution **only**. No Claude/Anthropic AI integration,
model support or API configuration is touched — this audit proposes no change to any
application functionality.

**Date:** 2026-11-12
**Auditor:** read-only audit (Phase 0), followed by a verified dry run in a scratch clone.

---

## Section 1 — Repository Audit

### 1.1 Structure

| Item | Value |
|---|---|
| Default branch | `main` |
| Remote | `origin` → `https://github.com/545e/snmk.git` (public) |
| Secondary remote | `snmk` → `G:/SNMK` — **local-only and non-existent**; it fails to fetch and is not used for publishing |
| Commits on `main` | 156 |
| Remote branches | `main`, `generation-2-complete-modernization` (`9771c6c`) |
| Remote tags | none |
| Local-only tag | `checkpoint-phase1-20261104` (`985083a`) — **not** on the remote |
| Pull requests | 7 (6 merged, #1 closed unmerged) — **all opened by `545e`** |
| Contributors graph | `545e` 141 commits, **`claude` 21 commits** |
| Workflows | `ci.yml` (5-platform matrix), `codeql.yml`, `docker-build.yml`, `release.yml`, `autonomous-audit.yml` |
| Local identity | `545e <157883046+545e@users.noreply.github.com>` (repo and global) |

### 1.2 Git identity audit — the decisive result

```
distinct AUTHORS across every ref:
    545e <157883046+545e@users.noreply.github.com>

distinct COMMITTERS across every ref:
    545e <157883046+545e@users.noreply.github.com>
    GitHub <noreply@github.com>       <- web-UI merge commits
```

**There is exactly one author identity in the entire repository, and it is the
repository owner.** No commit is authored or committed by `claude`,
`noreply@anthropic.com`, or any other identity.

### 1.3 Where `claude` actually comes from

21 commits carry this trailer in the commit **message body**:

```
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

GitHub's contributor graph parses `Co-Authored-By:` trailers and creates a
contributor node for each one. Because `noreply@anthropic.com` is not linked to
a GitHub account, GitHub falls back to the **display name in the trailer** and
shows the contributor as **`claude`**.

This is confirmed by the live API, which distinguishes the two endpoints:

```
GET /repos/545e/snmk/contributors        -> [545e: 149]        (REST list, no co-author split)
GET /repos/545e/snmk/stats/contributors  -> claude: 21, 545e: 141   (the home-page graph)
```

### 1.4 Attribution mechanisms checked and eliminated

| Mechanism | Present? | Evidence |
|---|---|---|
| Commit **author** identity | **No** | only `545e` across all refs |
| Commit **committer** identity | **No** | only `545e` and `GitHub <noreply@github.com>` |
| GitHub account association | **No** | `noreply@anthropic.com` is not a linked account |
| Merged pull requests | **No** | all 7 PRs opened by `545e`; merge commits are `GitHub <noreply@github.com>` |
| Co-author trailers | **YES — the sole cause** | 21 commits, one identical trailer |
| Branch/tag contributions | **No** | `generation-2-complete-modernization` contains no trailer |
| Squash/merge commit messages | **No** | verified by `git log --all --grep` |

**Root cause: the `Co-Authored-By:` trailer in the commit messages. Nothing else.**

---

## Section 2 — Claude Attribution Investigation

### 2.1 The 21 affected commits

All are single-parent commits created during the DSA engineering work. The
oldest is `e9a499b`; the newest is `c76d186`. They are **not** contiguous — three
commits by a concurrent contributor sit between them — so the rewrite zone must
run from the oldest affected commit to the tip of `main`.

### 2.2 Recommended correction

**Remove only the `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
line from those 21 commit messages.** Nothing else.

This is the minimum possible change because:

* the trailer is the *only* attribution mechanism in play (§1.4);
* removing it cannot alter a single byte of the source tree;
* author, committer, dates and every other commit property are preserved
  byte-for-byte (§4.2).

### 2.3 Why a history rewrite is unavoidable

A commit's message is part of the commit object, and the commit object's SHA-1
covers its content. Changing the message necessarily changes the hash, and every
descendant commit's hash changes with it. There is no Git-native operation that
edits a message in place.

The rewrite is therefore unavoidable **if** the contributor must disappear. It
is *not* required for the application to function — the repository works exactly
as it is today.

### 2.4 Alternative if a rewrite is not acceptable

Leave history untouched. The `claude` entry is cosmetic: it is a trailer on a
message, contributes nothing to the code, and cannot be removed without
rewriting published history. The application, its CI and its releases are
unaffected either way.

---

## Section 3 — Backup

### 3.1 Location

```
C:\Users\krish\snmk-git-backup\
    snmk-pre-claude-attr-removal-20261112-145432.bundle      (12.18 MB)
    snmk-pre-contributor-rewrite-20261112-224452.bundle      (12.18 MB)
```

The second bundle was taken **after** all the CI fixes, so it is the correct
restore point for the proposed rewrite.

### 3.2 Verification

```
$ git bundle verify snmk-pre-contributor-rewrite-20261112-224452.bundle
...
The bundle records a complete history.
The bundle uses this hash algorithm: sha1

SHA256: 6C1825028A53ABB6D2B4823051F4273523CC002157934C48B810F3CDB944FD96
```

The bundle contains **all 13 refs** (5 local branches, 7 remote-tracking refs,
the tag, HEAD and the SWA-phase3 worktree HEAD).

### 3.3 Restore procedure

```bash
# 1. back up the current state as well
git bundle create pre-restore.bundle --all

# 2. restore into the working copy
git clone snmk-pre-contributor-rewrite-20261112-224452.bundle restored-repo
cd restored-repo
git checkout perf/dsa-enterprise-transformation

# 3. point the origin at GitHub again
git remote set-url origin https://github.com/545e/snmk.git

# 4. push the restored history
git push origin perf/dsa-enterprise-transformation:main
```

The bundle is never overwritten: each backup gets its own timestamped file.

### 3.4 Working tree and secrets

The working tree is clean. `.env`, `.swa_master.key`, `swa_data.db` (27 MB),
`backups/` and `data/datasets/` are git-ignored and untouched by a history
rewrite — a rewrite changes commit objects, never the working tree.

---

## Section 4 — Proposed Changes

### 4.1 Exactly what changes

| Property | Value |
|---|---|
| Branch rewritten | `main` (and the local `perf/dsa-enterprise-transformation` which tracks it) |
| Commits whose hash changes | **24** (21 trailer commits + 3 descendants) |
| Commits whose hash is unchanged | **132** |
| Boundary (unchanged, stays the parent of the oldest affected commit) | `e7d877c` |
| Other branches / tags | **untouched** — `generation-2-complete-modernization` stays `9771c6c`, the tag stays `985083a` |
| Source files modified | **0** |
| Application behaviour changed | **none** |

### 4.2 Verification of the proposed rewrite (performed in a scratch clone)

The rewrite was executed against a **clone** of the repository, never against
the working copy or the remote:

```
commit count            : 156 -> 156
tip tree hash           : 9ff6d6644c41671a9de35adc54702bafcfce21b3  (before)
                        : 9ff6d6644c41671a9de35adc54702bafcfce21b3  (after)
TREES IDENTICAL         : True      <- the source code is bit-for-bit unchanged
tree mismatches         : 0
metadata mismatches     : 0         <- author name/email, committer name/email,
                                        author date and committer date all preserved
subject mismatches      : 0
body diffs beyond the removed trailer : 0
trailers remaining      : 0
refs other than the target branch that moved : 0
```

### 4.3 Old → new commit mapping

The full 24-entry mapping is produced by the procedure in §4.4 and is printed
before anything is applied. Representative entries:

```
c76d1861236d -> ddfd1669066c  ci: pin the shell for the pytest and summary steps
f9ce518b665c -> d07cecda382f  test(e2e): run the local scan against the server ...
68b39706842a -> 513e80108c64  fix(db): make the cyber audit log primary key collision-free
9aee01ff47d4 -> 4dcce2e8695c  ci: surface the failing tests as workflow annotations
075f44ff93c0 -> e529fb75f943  test(e2e): widen the scan completion budget ...
41946babaa76 -> 2ac41b213613  ci: capture and upload the pytest report ...
029cdbd31f22 -> 2470542d403e  fix(db): create the hot-path indexes after the schema ...
d00e3cd2e3e5 -> 392c2bbd6acb  docs(dsa): add the connection-reuse and write-path ...
...
e9a499bf1a38 -> (new)         perf(dsa): required-literal gating, localised matching ...
```

### 4.4 Exact git commands (to be run only after approval)

```bash
cd /path/to/snmk

# 0. safety: refuse to continue unless the tree is clean and origin is reachable
git status --porcelain          # must be empty
git fetch origin

# 1. take a fresh, timestamped backup of the exact pre-rewrite state
git bundle create "C:/Users/krish/snmk-git-backup/snmk-pre-rewrite-$(date +%Y%m%d-%H%M%S).bundle" --all
git bundle verify <that file>

# 2. rewrite ONLY the trailer, scoped to the affected range of the target branch
git filter-branch -f \
  --msg-filter "sed '/^Co-Authored-By: Claude Opus/d'" \
  --tag-name-filter cat \
  -- perf/dsa-enterprise-transformation --not e7d877c

# 3. verify before pushing
git log --format='%H %s' --grep='^Co-Authored-By:' --extended-regexp   # must be empty
git diff --stat e7d877c perf/dsa-enterprise-transformation              # must be empty
git rev-list --count origin/main..perf/dsa-enterprise-transformation     # must be 0
git fsck --no-progress

# 4. drop filter-branch's refs/original backup refs (the bundle is the backup)
git for-each-ref --format='%(refname)' refs/original | xargs -n1 --no-run-if-empty \
  git update-ref -d

# 5. publish with a lease, so a concurrent push is never silently overwritten
git push --force-with-lease=refs/heads/main:$(git rev-parse origin/main) \
  origin perf/dsa-enterprise-transformation:main

# 6. confirm
git fetch origin
git log --oneline -1 origin/main
```

### 4.5 Risks and limitations

| Risk | Assessment | Mitigation |
|---|---|---|
| **Force-push required** | The rewritten history is not a descendant of the old `main`, so the push must be non-fast-forward. | `--force-with-lease` with the exact expected old SHA — the push **aborts** if anyone else pushed in the meantime. |
| **Existing clones** | Anyone with a clone must `git fetch && git reset --hard origin/main` (their old commits become unreachable). | Documented in §4.6. Nothing is lost — the old commits remain in the bundle and in GitHub's object store for a while. |
| **Open PRs** | None of the 21 affected commits are the head of an open PR (all 7 PRs are closed/merged). | Verified: the PR head SHAs (`1ecfdc2`, `6f86dd9c`, `51116f48`, `5ebe3f8f`, `b7246b4c`, `29af4a08`, `869c4199`) are all below the rewrite boundary and keep their hashes. |
| **CI re-runs** | The push triggers all five CI jobs plus CodeQL and Docker. | Expected — the same commit content, so the same green result. Verified locally at 351 passed / 0 failed on the identical tree. |
| **Signed commits** | None of the affected commits are signed (`git log --format=%G?` → `N` for all 21), so **no signature is invalidated**. | Confirmed by inspecting every affected commit. |
| **Contributor graph caching** | GitHub rebuilds the graph asynchronously; the `claude` entry may linger for a few minutes after the push. | Poll `GET /repos/545e/snmk/stats/contributors` (it returns HTTP 202 while computing). |
| **Attribution to the wrong person** | The trailer says Claude; removing it attributes the work solely to `545e`, which is already the sole author of every commit. | No work is attributed to any other individual. This is the requested outcome. |

### 4.6 Rollback procedure

```bash
# If anything is wrong after the force-push, restore the pre-rewrite history
git push --force-with-lease=refs/heads/main:<current-remote-tip> \
  origin <pre-rewrite-sha>:main
# where <pre-rewrite-sha> is c76d1861236d1063591034694b0c00ecd54abd32
# (or clone the bundle from Section 3 and push from there)
```

The pre-rewrite tip `c76d1861236d1063591034694b0c00ecd54abd32` is recorded
above and is also the tip recorded inside the backup bundle.

---

## Section 5 — Application Integrity

**No application code, configuration, dependency or AI integration is touched by
the proposed change.** The tip tree hash is identical before and after
(`9ff6d6644c41671a9de35adc54702bafcfce21b3`).

Verified separately during this audit — the following genuine defects were
found and fixed, and they are included in the history that would be rewritten:

| Area | Finding | Status |
|---|---|---|
| Backend / database | The hot-path indexes were created **before** the `ALTER TABLE` migration loop that adds the indexed columns, so `init_db()` aborted on a **fresh** database (`no such column: remediation_status`) and every module import failed — all 29 test modules errored during collection and CI was red on all 5 platforms. | **Fixed** (`029cdbd`) — indexes moved after the migrations, each individually guarded |
| Backend / database | The cyber audit-log primary key was a bare **millisecond timestamp**, so two audit entries written in the same millisecond collided: `UNIQUE constraint failed: cyber_audit_logs.id`. This is what broke the CI approval-gate and deployment tests. | **Fixed** (`68b3970`) — timestamp prefix kept, random suffix added; 200 rapid writes now succeed |
| Backend / tests | The E2E local-scan test hard-coded port 8000 while `run.py` auto-selects a different port when 8000 is busy, so it scanned a port where nothing listened and found 0 findings. | **Fixed** (`f9ce518`) — the test now asks the OS for a free port and uses it for both the server and the scan target |
| CI | The Windows runner defaults to PowerShell, where the bash syntax in the pytest step (`set -o pipefail`, `tee`) and in the summary step did not behave as intended. | **Fixed** (`c76d186`) — both steps pin `shell: bash` |
| CI observability | A failing CI job was undiagnosable from outside (artifacts need authentication to download). | **Fixed** (`9aee01f`) — failing tests are surfaced as `::error::` annotations readable through the public API |

Everything else was verified intact:

* **AI agents** — 94 agents across 6 tiers; 94/94 dispatch, 0 failed.
* **AI integrations** — Anthropic/OpenAI/Gemini/Ollama adapters untouched.
* **Frontend** — `web/static/app.js` (740 KB) and `index.html` (534 KB) unchanged by the rewrite.
* **Authentication / authorisation** — `core/app_security.py` and the v1 RBAC flow unchanged.
* **Database** — schema, migrations and all 82 indexes unchanged.
* **Reports / exports** — Cyber Export, Test, Deploy and the Nessus engine unchanged.
* **Docker** — `Dockerfile`, compose files and the image build verified green.

---

## Section 6 — Testing

### 6.1 Local

```
$ pytest -q
351 passed, 1 warning in 372.41s (0:06:12)
```

Run from a **pristine clone with no database file** and with a fresh virtual
environment built from `requirements.txt` — i.e. exactly the CI environment:

```
fresh venv from requirements.txt, fresh clone, no swa_data.db:
    349 passed, 0 failed   (before the two newest test additions)
```

### 6.2 CI — all green

| Workflow | Result |
|---|---|
| Cross-Platform CI · ubuntu-latest 3.10 | **success** |
| Cross-Platform CI · ubuntu-latest 3.11 | **success** |
| Cross-Platform CI · ubuntu-latest 3.12 | **success** |
| Cross-Platform CI · windows-latest 3.12 | **success** |
| Cross-Platform CI · macos-latest 3.12 | **success** |
| Docker Build & Container Verification | **success** |
| CodeQL Security Analysis (python + javascript-typescript) | **success** |

### 6.3 Rewrite-specific verification

| Check | Result |
|---|---|
| Commit count preserved | 156 → 156 |
| Tip tree hash identical | `9ff6d664…` → `9ff6d664…` |
| Per-commit tree mismatches | 0 |
| Author/committer name, email, author date, committer date | 0 mismatches |
| Commit subjects | 0 mismatches |
| Message bodies (beyond the removed trailer) | 0 mismatches |
| `Co-Authored-By:` trailers remaining | 0 |
| Non-target refs moved | 0 |

### 6.4 Unverified functionality

* The live LLM provider paths were **not** exercised — no provider key is
  configured in this environment, so every provider path runs in
  `heuristic_fallback` mode.
* The `nmap`, `nuclei`, `sqlmap`, `semgrep`, `bandit`, `trivy`, `gitleaks`,
  `zap`, `nikto`, `tshark`, `clamav` and `wazuh` adapters were not executed
  against real targets — the binaries are not installed on this host.
* The GitHub **contributor graph** for the rewritten history cannot be verified
  before the push; it is verified in §7 after the push.

---

## Section 7 — GitHub Verification (after the push)

To be completed once the rewrite is approved and applied:

```
1. GET https://api.github.com/repos/545e/snmk/stats/contributors
   -> expect a single contributor: 545e with 156 commits
   -> expect NO "claude" entry
   (the endpoint returns HTTP 202 while the graph is recomputing - poll until 200)

2. GET https://api.github.com/repos/545e/snmk/contributors
   -> expect 545e only

3. GET https://api.github.com/repos/545e/snmk/branches
   -> main          = <new tip>
   -> generation-2-complete-modernization = 9771c6c5e1b50da4c26b063ab62b92f986924687  (UNCHANGED)

4. GET https://api.github.com/repos/545e/snmk/actions/runs
   -> the five CI jobs, Docker and CodeQL all succeed on the new tip

5. git clone --depth 1 https://github.com/545e/snmk.git verify
   -> the working tree matches the pre-rewrite tree exactly
      (compare `git rev-parse HEAD^{tree}` against 9ff6d6644c41671a9de35adc54702bafcfce21b3)
```

---

## Section 8 — Final Status

| Item | Status |
|---|---|
| Read-only audit completed | **DONE** |
| Root cause identified | **DONE** — the `Co-Authored-By: Claude Opus 4.8 …` trailer on 21 commits; no author/committer/PR involvement |
| Backup created and verified | **DONE** — `C:\Users\krish\snmk-git-backup\snmk-pre-contributor-rewrite-20261112-224452.bundle` (SHA256 `6C182502…`) |
| Proposed change verified in a scratch clone | **DONE** — tip tree identical, 0 metadata/subject/body differences, only the target branch moves |
| Application integrity | **DONE** — CI green on all 5 platforms, Docker and CodeQL green; 351 tests pass locally |
| Changes applied to the real repository | **NOT YET** — the rewrite has *not* been applied; `main` is still `c76d186` |
| Tests passed | **DONE** — 351 local, 349 on a pristine clone, all CI jobs green |
| Push approved | **AWAITING EXPLICIT APPROVAL** |
| GitHub attribution verified | **PENDING** — can only be verified after the approved push |

### Current `main` state

```
origin/main = c76d1861236d1063591034694b0c00ecd54abd32
contributors graph: claude = 21, 545e = 141
CI: all green
```

### What I need from you

The rewrite is the only way to remove the `claude` contributor, and it requires
a force-push to `main`. Please confirm:

1. **Apply the rewrite** to `main` with `--force-with-lease` (the exact commands
   are in §4.4), **or**
2. **Do not apply it** — the contributor entry stays and nothing changes.

Either way the application is unaffected: the source tree is byte-identical
before and after, and the backup in §3 makes the operation fully reversible.
