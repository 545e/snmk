# SNMK — Frontend and Build Audit Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Method** | Static analysis of the frontend assets, plus a comparison against the backend API surface |

---

## 1. The build system: there is none, and that is a decision

| Question | Answer |
|---|---|
| Is Vite used? | **No** — no `vite.config.*` |
| Is Webpack used? | **No** — no `webpack.config.*` |
| Is there a `package.json`? | **No** |
| Is there a lockfile? | **No** |
| Are there npm dependencies? | **Zero** |
| Is there a build step? | **No** — the files are served as-is |

**Both build systems are absent, and only one of them was ever needed.**
The frontend is six hand-written static files served directly by FastAPI.

### What that buys

* **No npm supply-chain surface.** Nothing from the npm registry enters the
  build or the image.
* **No build step.** The container builds a Python image and nothing else.
* **No bundler to configure or to break.**
* **No dependency updates to manage.**
* **The frontend cannot break because a transitive dependency changed.**

### What it costs

| Cost | Evidence |
|---|---|
| One 16 468-line JavaScript file | `web/static/app.js` — 85 duplicated blocks (SonarQube `javascript:S3358`), 51 cognitive-complexity findings, 350 `innerHTML` assignments |
| One 7 497-line HTML file | `web/static/index.html` — 1 757 `<div>` elements, 5 inline `<script>` blocks |
| No module boundary | Everything shares one global scope; there is no `import`/`export` |
| No minification | The 792 kB `app.js` is served as-is |
| No cache busting by content hash | The static files are served with a fixed name |

**Neither build system is necessary and neither should be added.** The
correct response to the single-file problem is ES modules — which the
platform already loads the rest of its UI with — not a bundler. A bundler
would add a dependency surface, a build step and a configuration burden to
solve a problem that the module system solves natively.

---

## 2. The frontend assets

| File | Lines | Purpose |
|---|---|---|
| `web/static/index.html` | 7 497 | The single-page application shell |
| `web/static/app.js` | 16 468 | The application logic |
| `web/static/styles.css` | 7 002 | The design system |
| `web/static/map.css` | 813 | The network map |
| `web/static/map.js` | 813 | The network map |
| `web/static/digital_forensics.js` | 501 | The forensics workspace |
| `web/static/snmk-enhance.css` | — | An enhancement layer |
| `ui-concepts.html` | 576 | A standalone design-concept page |
| `tests/e2e/rt_harness.mjs` | 514 | The browser E2E harness |

**Total: ~34 000 lines of front-end code in eight files.**

---

## 3. HTML

### Structure

| Check | State |
|---|---|
| Semantic elements | ✔ `<aside>`, `<nav>`, `<header>`, `<main>`, `<section>`, `<table>`, `<form>` are used |
| `<h1>`–`<h6>` hierarchy | ✔ Used |
| Landmarks | ✔ `aside`, `nav` present — **and they now have `aria-label`s** (the audit added four) |
| Form labels | ✔ Every input has a label — **and 71 labels now carry a `for`** (the audit added them) |
| Table headers | ✔ **and now carry `scope`** (the audit added `scope="col"` / `scope="row"` to five) |
| `lang` attribute | ✔ Present |
| Inline `<script>` blocks | 5 — a CSP with `'unsafe-inline'` has to permit them |
| Inline event handlers | Many (`onclick="..."`) — the direct cause of the CSP's `'unsafe-inline'` requirement |

### Accessibility

| Finding | Severity | Status |
|---|---|---|
| 100 `<div>`/`<span>` elements reacted to `onclick` and could not be reached from the keyboard | High | **FIXED** — native `<button>` elements |
| 71 `<label>` elements were not associated with their control | High | **FIXED** — `for` attributes added |
| 6 anchors with `href="javascript:void(0)"` were used as buttons | Medium | **FIXED** — real buttons |
| 9 landmarks had no accessible name | Medium | **FIXED** — `aria-label` added |
| 5 `<th>` elements had no `scope` | Low | **FIXED** |
| A `<label>` that captions a value was marked as a label | Low | **FIXED** — rewritten as a `<span>` |
| The "select all" checkbox used `onclick`, which made it look mouse-only | Low | **FIXED** — `onchange` |
| The sortable column headers were not real buttons | Medium | **FIXED** — a `<button>` inside the `<th>` |
| The `aria-label` on 9 elements | — | **FIXED** |

---

## 4. CSS

| Check | State |
|---|---|
| Custom properties | ✔ A design-token system (`--brand`, `--bg-card`, `--text-title`, …) is used throughout |
| Layout | Flexbox and Grid |
| Media queries | **20** in `styles.css` |
| Responsive | ✔ Mobile, tablet and desktop breakpoints are present |
| Dark theme | ✔ The palette is token-driven |
| Print styles | **None** — a report platform that generates printable output with no print stylesheet is a gap |
| Duplicated selectors | **32** (SonarQube `css:S4666`) — e.g. `.swa-view-title` is defined twice, at lines 2 193 and 6 389 |
| Unused selectors | Not measured |
| `!important` | Used in the transition block and elsewhere |

**Finding FE-01 (Medium, open): 32 duplicate CSS selectors.** The second
definition silently wins. Most are in the 6 300–6 500 region, which reads
like an appended override block. They should be merged into the original
rules.

**Finding FE-02 (Low, open): there is no print stylesheet.** The platform
generates PDF and HTML reports for an operator to print or to attach; the
on-screen UI does not need a print path, but the report templates do.

---

## 5. JavaScript

### Size and structure

| Metric | Value |
|---|---|
| `app.js` | 16 468 lines, 792 kB |
| Functions over 100 lines | 51 (SonarQube `javascript:S3776`) |
| `innerHTML` assignments | 350 |
| `escapeHtml()` call sites | 368 |
| Unescaped `innerHTML` interpolations | **81** |
| Duplicated blocks | 85 |
| Useless assignments | 21 |

### Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| FE-03 | **81 `innerHTML` template literals interpolate API data without `escapeHtml()`.** The values include `data.poc_curl` (which embeds the user-supplied target URL), `data.target_url`, `data.download_url` (an attribute context), `data.message` (integration error strings that embed user-supplied endpoints) and `data.output`. | Medium | **Open** |
| FE-04 | The CSP permits `'unsafe-inline'` and `'unsafe-eval'` in `default-src`, which neutralises the mitigation for FE-03. | Medium | **Open** |
| FE-05 | 85 duplicated blocks in one file. | Medium | **Open** |
| FE-06 | 51 functions over 100 lines. | Medium | **Open** |
| FE-07 | 21 useless assignments. | Low | **Open** |
| FE-08 | No `package.json`, so the front-end dependencies are not declared — there are none, which is the point. | Info | **Open** — a `package.json` with `"private": true` and no dependencies would make the intent explicit |

### The escapeHtml gap in detail

`escapeHtml()` exists at `web/static/app.js:3782` and is used in most
rendering paths. The 81 sites that do not use it are the ones that render
**data returned by the API** rather than static labels. The pattern is:

```js
out.innerHTML = `<div ...>[!] Vulnerability Confirmed: ${data.vuln_type}</div>
    <div ...>${data.evidence || data.summary}</div>
    ${data.poc_curl ? `<div ...><pre ...>${data.poc_curl}</pre></div>` : ''}`;
```

`data.poc_curl` embeds the operator-supplied target URL. If a target URL
contains `<img src=x onerror=...>`, the value reaches the DOM unescaped.

**The exploit path was not demonstrated.** The target URL is operator-supplied
rather than attacker-supplied in most flows, which lowers the severity. But
`data.message` — an integration or tool error string — can embed a URL that
*was* supplied by an attacker in an earlier request. That path is plausible
and was not ruled out.

**Fix:** route every interpolated value through `escapeHtml()`, and remove
`'unsafe-inline'`/`'unsafe-eval'` from the CSP.

---

## 6. Frontend-to-backend communication

| Check | State |
|---|---|
| The transport | `fetch()` with JSON |
| Error handling | Present in most call sites — a failed request shows an error state |
| Authentication | The session token is sent as a bearer header |
| The API base URL | Relative — the frontend is served by the same application |
| Polling | The live view polls the REST endpoints; the real-time channel is the WebSocket |
| The WebSocket | Now authenticated (the audit fixed it) |
| Loading and empty states | Present on the main views |
| Input validation | Client-side only, as expected; the server validates independently |

**Finding FE-09 (Low, open): there is no request cancellation.** A search
that is superseded by a newer one leaves the older request running and can
render a stale result. `AbortController` is the fix.

---

## 7. Responsiveness

| Breakpoint | Covered |
|---|---|
| Mobile | ✔ 20 media queries, a collapsible sidebar, a drawer-based copilot |
| Tablet | ✔ |
| Desktop | ✔ |

**Finding FE-10 (Low, open): the mobile sidebar is closed with a click on
the backdrop.** The audit added keyboard access to the backdrop, but a
focus-trap would be the correct treatment for a modal overlay.

---

## 8. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Split `app.js` into ES modules by domain — the platform already loads ES modules | Medium | FE-05, FE-06, FE-08 |
| 2 | Route every interpolated value through `escapeHtml()` | Medium | FE-03 |
| 3 | Remove `'unsafe-inline'` and `'unsafe-eval'` from the CSP and use a nonce | Medium | FE-04 |
| 4 | Merge the 32 duplicate CSS selectors | Low | FE-01 |
| 5 | Add a print stylesheet for the report views | Low | FE-02 |
| 6 | Remove the 21 useless assignments | Low | FE-07 |
| 7 | Use `AbortController` for the superseding requests | Low | FE-09 |
| 8 | Add a focus trap to the modal overlays | Low | FE-10 |
| 9 | Add a `package.json` with `"private": true` and no dependencies, so the absence of a build is explicit and the E2E harness has a home | Low | FE-08 |
| 10 | **Do not add Vite or Webpack.** | — | — |

---

## 9. Assessment

The frontend is **functional and complete but monolithic**. The audit
confirmed that every advertised view exists, that the API is reachable from
the UI, that the accessibility gaps have been closed, and that there is no
hidden build dependency.

The single-file frontend is the one structural problem worth solving, and
the solution is the module system the platform already uses — not a
bundler.
