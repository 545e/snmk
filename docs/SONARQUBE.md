# SonarQube Static Analysis

SNMK is analysed with **SonarQube Community Build** (24.12 or newer) and
**sonar-scanner-cli** 6.x / 7.x.  The analysis runs on every push and pull
request, and on a weekly schedule.

The repository ships:

| File | Purpose |
|---|---|
| `sonar-project.properties` | Project key, source layout, exclusions, coverage wiring |
| `.github/workflows/sonarqube.yml` | CI pipeline: tests with coverage, then the scan, then the quality gate |

---

## 1. Running it locally

### 1.1 Start a SonarQube server

The Community Build is a self-contained server; it bundles a JRE, so no Java
installation is required.

```bash
# 1. Download and unpack
curl -fsSLO https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-24.12.0.100206.zip
unzip -q sonarqube-24.12.0.100206.zip

# 2. Start it
cd sonarqube-24.12.0.100206/bin/linux-x86-64
./sonar.sh start
```

On Windows use `bin\windows-x86-64\SonarService.bat install` followed by
`StartSonar.bat`.  The server listens on <http://localhost:9000>; the default
credentials are `admin` / `admin`.

> The first start creates the embedded database and takes a few minutes.
> Wait until `GET /api/system/status` reports `"status":"UP"`.

### 1.2 Rotate the default password

The Community Build requires the default password to be changed before the
API can be used:

```bash
curl -u admin:admin -X POST \
  "http://localhost:9000/api/users/change_password" \
  -d login=admin -d previousPassword=admin -d password='<new-password>'
```

### 1.3 Run the scanner

```bash
cd <repository root>

# Generate the coverage report the scan will import
python -m pip install -r requirements.txt -r requirements-dev.txt
pytest tests/ --ignore=tests/e2e_map_browser_test.py \
  --cov=core --cov=agents --cov=plugins --cov=reports --cov=web \
  --cov-report=xml:coverage.xml --cov-report=html:htmlcov

# Scan
sonar-scanner \
  -Dsonar.projectKey=snmk \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=admin \
  -Dsonar.password='<new-password>'
```

`sonar-scanner` picks up `sonar-project.properties` from the repository root
automatically.

---

## 2. What is measured

| Metric | Current value |
|---|---|
| Lines of code (ncloc) | ~74 000 |
| Test coverage | ~64 % |
| Duplicated lines | ~2.8 % |
| Cognitive complexity | ~12 000 |

The Python, JavaScript, HTML, CSS and YAML analysers are all active.

### Exclusions

`sonar-project.properties` excludes the virtual environment, runtime data
directories, downloaded tool binaries, coverage artefacts and vendored
assets.  Everything under `core/`, `agents/`, `plugins/`, `reports/`,
`web/`, `tools/` and `tests/` is analysed.

---

## 3. The quality gate

The project uses the **"Sonar way"** gate:

| Condition | Meaning |
|---|---|
| New violations `> 0` | No new issues may be introduced |
| New coverage `< 80 %` | New code must be covered |
| New duplicated lines `> 3 %` | New code must not duplicate |
| New security hotspots reviewed `< 100 %` | Hotspots must be triaged |

The gate deliberately evaluates **new code only**.  The repository carries a
large pre-existing backlog (more than a thousand findings, mostly cognitive
complexity in the report generators and duplicated blocks in the 700 kB
single-file frontend), and a gate on the whole codebase could never be
satisfied.  The new-code period is configured with
`sonar.newCode.referencePeriod`, so the gate blocks the backlog from growing
rather than pretending it does not exist.

### Configuration

```properties
# 30-day rolling window for "new code"
sonar.newCode.referencePeriod=30
```

---

## 4. Findings that were fixed

The first full analysis produced **1 132 open issues**:

| | Before | After |
|---|---|---|
| Bugs | 119 | 0 |
| Vulnerabilities | 40 | 0 |
| Code smells | 973 | 719 |
| Open issues | 1 132 | 720 |
| Security hotspots | 119 | 118 (each needs a human decision) |

See `docs/DSA_ENGINEERING_REPORT.md` §I.0 for the write-up.

### 4.1 Real defects

| Rule | Finding | Fix |
|---|---|---|
| `python:S1763` | Unreachable statement after `return` in `core/tool_dependency_manager.py` | Removed the dead assignment left over from a refactor |
| `python:S5850` | Ambiguous operator precedence in a regex in `core/js_intelligence.py` | Grouped the alternation explicitly |
| `javascript:S1534` | Duplicate `'api_keys'` key in a view map in `web/static/app.js` | Removed the duplicate |
| `python:S5527` / `python:S4830` | TLS certificate verification disabled in 40 places with no recorded rationale | Centralised in `core/tls_policy.py` (see below) |
| — | `SSLCertificateTool` reported `"valid": true` for every certificate it inspected, including expired and self-signed ones | The tool now performs a strictly verifying handshake and reports the real outcome |

### 4.2 The TLS policy

`core/tls_policy.py` is now the single source of truth for how SNMK handles
certificate verification:

* **Outbound requests** are made through `tls_policy.client_kwargs()`, which
  carries the platform's decision.  SNMK is a scanner: it must be able to
  reach hosts whose certificates are broken, because that condition is
  itself a finding.  Unverified peers are *reached*, never *trusted*.
* **Certificate inspection** uses `tls_policy.inspection_context()`, which
  permits reading a certificate that would fail validation.
* Setting `SWA_TLS_VERIFY=1` switches the whole platform to strict
  verification for deployments that need it.

Before this change the same decision was made independently in 40 call
sites, none of which recorded why.  An auditor had to re-derive the intent
at every site.

### 4.3 Accessibility

| Rule | Finding | Fix |
|---|---|---|
| `Web:MouseEventWithoutKeyboardEquivalentCheck` (100) | `<div>` / `<span>` elements reacted to `onclick` but could not be reached or activated from the keyboard | Converted to native `<button type="button">` elements |
| `Web:S6819` | `role="button"` on a non-native element | Avoided entirely by using native buttons |
| `Web:S6845` | `tabindex` on a non-interactive element | Avoided entirely by using native buttons |
| `Web:S6853` (71) | `<label>` elements were not associated with their control | Added the missing `for` attributes; one label that captions a value rather than a control was rewritten as a `<span>` |
| `Web:S6844` (6) | Anchors with `href="javascript:void(0)"` were used as buttons | Converted to real `<button type="button" class="link-btn">` elements, with a CSS rule that preserves their appearance |
| `Web:S5255` (9) | `<nav>` / `<aside>` landmarks had no accessible name | Added `aria-label` |
| `Web:TableHeaderHasIdOrScopeCheck` (5) | `<th>` elements had no `scope` | Added `scope="col"` / `scope="row"` |
| `css:S4649` (22) | `font-family` declarations named no generic fallback | Added the generic family |
| `css:S4670` (1) | A stray `sv-C{}` selector in `ui-concepts.html` | Removed the dead rule |

#### Why native buttons

The first attempt made the non-interactive elements *behave* like buttons by
adding `role="button"`, `tabindex="0"` and an Enter/Space `onkeydown`
handler.  That fixed the keyboard access, but SonarQube's `Web:S6819` is
right that a native `<button>` is better: it is focusable and activated
without any script, it participates in forms, and assistive technology
announces it correctly without help.

The appearance is preserved by the `swa-plain` class.  Its rules are wrapped
in `:where()`, which keeps their specificity at zero, so the element's own
class and its inline styles always win and only the browser's default button
chrome -- the background, the border, the padding and the font that buttons
do not inherit -- is removed:

```css
:where(button.swa-plain) {
    appearance: none;
    background: none;
    border: none;
    padding: 0;
    font: inherit;      /* buttons do not inherit the font */
    color: inherit;
    text-align: inherit; /* buttons default to centred text */
}
```


### 4.4 Code smells

| Rule | Finding | Fix |
|---|---|---|
| `python:S3457` | 121 f-strings without a single replacement field | Removed the pointless `f` prefix (verified: every string literal in the tree is unchanged) |
| `python:S1481` | 47 unused local variables | Removed the dead stores, or renamed the unused element of a tuple unpacking to `_` |
| `python:S1763` | Unreachable code | See above |

---

## 5. What is deliberately **not** fixed

| Rule | Why |
|---|---|
| `python:S3776` (135) | Cognitive complexity in the report generators and the enterprise API. Splitting these functions is a refactor with real regression risk and is tracked separately. |
| `javascript:S3358` (85) | Duplicated blocks in `web/static/app.js`, a 700 kB single-file frontend. The fix is to split the frontend into modules. |
| `python:S1192` (100) | Duplicated string literals. Mostly severity names and SQL fragments; extracting them would add indirection without much benefit. |
| `python:S4830` on the `httpx` clients | Reaching a target whose certificate is broken is the point of a scanner. See `core/tls_policy.py`. |
| `python:S5332` / `S1313` / `S4790` (92) | Security *hotspots*, not issues: they need a human decision about whether the hardcoded IP, the `http://` URL or the hash is safe in context. Each one has to be triaged individually. |

---

## 6. Reviewing a hotspot

Hotspots are questions, not defects.  To triage one:

```bash
# list the hotspots of the project
curl -u admin:<password> \
  "http://localhost:9000/api/hotspots/search?projectKey=snmk&ps=500&status=TO_REVIEW"

# mark one as safe (or as "to be fixed")
curl -u admin:<password> -X POST \
  "http://localhost:9000/api/hotspots/review" \
  -d hotspot=<hotspot-id> -d status=REVIEWED \
  -d resolution=SAFE -d comment="Read by the security owner: <reason>"
```

The quality gate requires every *new* hotspot to be reviewed, so a new
finding cannot be introduced without somebody looking at it.
