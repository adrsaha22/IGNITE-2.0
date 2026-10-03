# IGNITE 2.0 — AI Detection Engineering Platform

Describe attacker behaviour in plain English. IGNITE turns it into a complete,
**quality-gated, reviewable and deployable** Splunk detection:

- Splunk SPL query **and** an equivalent Sigma rule
- ATT&CK mapping, independently verified against the official MITRE dataset
- Known false positives, severity and ordered response actions
- A 0–100 quality score from 14 weighted checks, with automatic repair
- Human review (draft → approved / rejected), version history and an
  append-only audit log
- Splunk parser validation, test searches and deployment (disabled / shadow / live)
- An ATT&CK coverage matrix showing where your detections are and where the gaps are
- Exports: contentctl YAML, savedsearches.conf, Sigma, Markdown report, JSON

```
describe ──► retrieve similar ──► generate ──► 14 quality ──► repair ──► save as ──► review ──► deploy
behaviour    known detections     (LLM)        checks        (≤2x)      draft        & approve   shadow ► live
                    ▲                                                                   │
                    └──────────── approved rules become references ◄────────────────────┘
```

| Front end | Stack | Status |
| --- | --- | --- |
| `frontend/` + `api/` | React 19 · TypeScript · Vite · Tailwind 4 · FastAPI | Primary |
| `app.py` | Streamlit | Fallback for the legacy template pipeline |

---

## Contents

1. [Quick start](#quick-start)
2. [Configuration](#configuration)
3. [Using the application](#using-the-application)
4. [Quality checks and score](#quality-checks-and-score)
5. [Rule library and review workflow](#rule-library-and-review-workflow)
6. [Splunk integration](#splunk-integration)
7. [Knowledge base, retrieval and evaluation](#knowledge-base-retrieval-and-evaluation)
8. [AI providers](#ai-providers)
9. [What is and is not validated](#what-is-and-is-not-validated)
10. [Other features](#other-features)
11. [Tests](#tests)
12. [Project layout](#project-layout)
13. [Security notes](#security-notes)
14. [Limitations and next steps](#limitations-and-next-steps)

---

## Quick start

**Prerequisites:** Python 3.12+, Node.js 20+ (developed against v24). Git is
needed only to build the full knowledge base.

```bash
# Backend
python -m venv venv
./venv/bin/pip install -r requirements.txt        # Windows: venv\Scripts\pip install -r requirements.txt
cp .env.example .env                               # then add one provider key (see below)

# Frontend
cd frontend && npm install && cd ..
```

Run in two terminals:

```bash
./venv/bin/uvicorn api.main:app --reload --port 8000     # API — docs at http://localhost:8000/docs
cd frontend && npm run dev                               # Web app — http://localhost:5173
```

It works immediately with a small bundled knowledge base. For better results,
[build the full one](#knowledge-base-retrieval-and-evaluation).

> No provider key? Set `DETECTION_GENERATION_MODE=demo` to try the workflow with
> clearly labelled offline templates (three scenarios only, see [Demo mode](#demo-mode)).

---

## Configuration

Everything is configured in `.env` on the backend (see `.env.example` for every
option). Secrets are read by the API only and never sent to the browser.

| Variable | Default | Purpose |
| --- | --- | --- |
| `IGNITE_LLM_PROVIDER` | `gemini` | `gemini`, `anthropic`, `openai`, `ollama` or `ellm` |
| `GEMINI_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | — | Key for the chosen provider |
| `GEMINI_MODEL` / `ANTHROPIC_MODEL` / `OPENAI_MODEL` / `OLLAMA_MODEL` | `gemini-flash-latest` / `claude-opus-5-5` / `gpt-4o` / `llama3.1` | Model per provider |
| `DETECTION_GENERATION_MODE` | `gemini` (LLM) | `demo` for offline templates (`llm` is accepted as an alias for the LLM path) |
| `IGNITE_MAX_REPAIR_ATTEMPTS` | `2` | Times failing checks are sent back for repair |
| `SPLUNK_URL`, `SPLUNK_TOKEN` | — | Enables parser validation, test searches and deployment |
| `SPLUNK_VERIFY_SSL` | `true` | Set `false` only for a local test instance |
| `IGNITE_OPERATOR` | OS user | Name recorded in the audit log |
| `IGNITE_DB_PATH` | `data/investigations.db` | SQLite file for rules, audit log and investigations |
| `IGNITE_CORS_ORIGINS` | local dev origins | Origins allowed to call the API |

---

## Using the application

The sidebar has five areas:

1. **Generate** — describe a scenario and press *Generate detection rules*
   (`Ctrl`/`Cmd`+`Enter`). Results appear across tabs: Overview, Detection
   Rules (quality checks, Sigma, response actions, grounding references,
   provenance), Testing Lab, Attack Intelligence, Validation, Library
   (saved investigations) and Export. Choose **Save to rule library** on a
   candidate to put it under governance.
2. **Rule Library** — every saved rule with status, quality grade and deployment
   state. Each rule has *Overview*, *Edit*, *Review & deploy*, *Export* and
   *History* views.
3. **ATT&CK Coverage** — the Enterprise matrix coloured by your strongest
   coverage per technique (deployed, approved, draft, knowledge-base references
   only, none), with coverage % per tactic. Select a gap and *Generate a
   detection* to prefill the scenario.
4. **Activity** — the audit log of every save, edit, review, validation,
   deployment, export and deletion, with who and when. Exportable as CSV.
5. **Platform** — active AI provider and model, Splunk connection (with a
   *Test connection* button), knowledge-base status and the latest evaluation.

---

## Quality checks and score

Every candidate, at generation time and again on every library save or edit,
runs through these checks. They are computed by IGNITE; anything the model
says about its own quality is discarded.

| Check | What it verifies | Weight | Fails when |
|---|---|---|---|
| Output format | Name, purpose, severity, Sigma, false positives, response actions present | 1 | No SPL (missing extras only warn) |
| ATT&CK mapping | IDs exist in the bundled ATT&CK dataset and carry evidence | 2 | An ID is invented, revoked or malformed |
| ATT&CK tactics | Sigma `attack.<tactic>` tags belong to the mapped techniques | 0.5 | — (warns) |
| Sigma structure | Valid YAML; title, logsource, detection; valid level/status | 2 | Invalid Sigma |
| Sigma condition | Condition references only selections that exist | 1 | Undefined selection |
| Sigma metadata | Rule id is a UUID | 0.5 | — (warns) |
| Sigma ATT&CK tags | `attack.tXXXX` tags match the mapping | 1 | Tags contradict the mapping |
| Sigma converts to SPL | The pySigma Splunk backend converts the rule | 2 | Conversion fails |
| SPL structure | Balanced quotes/brackets/macros, known commands, no match-everything wildcards | 2 | Unbalanced syntax, or `delete`, `collect`, `outputlookup`, `sendemail`, … |
| SPL scope | Base search limited by index, sourcetype, macro or data model | 1 | — (warns) |
| False positives | At least one specific benign scenario | 0.5 | — (warns) |
| Response actions | At least three concrete steps | 0.5 | — (warns) |
| Splunk parser | Splunk's own parser accepts the query | 2 | Splunk rejects it (skipped if not configured) |
| Test search | Runs once over recent data; flags noisy results | 1 | — (on demand, warns when noisy) |

**Score** = weighted average: a pass earns full weight, a warning half, a
failure nothing; skipped checks don't count. **Any failure caps the score at
49**, so a rule with a real defect can never read as "Good".
Grades: 85+ *Ready* · 70–84 *Good* · 50–69 *Needs work* · under 50 *Poor*.

**Automatic repair.** If a candidate fails a check, the exact failures are sent
back to the model with its previous answer (up to `IGNITE_MAX_REPAIR_ATTEMPTS`).
A repaired answer is kept only if it has no more failures than the previous one.
If repair fails or the provider errors, the earlier, genuinely generated answer
is returned with its failures shown, never hidden and never replaced by
template output.

---

## Rule library and review workflow

```
generated ──► draft ──► approved ──► deployed (disabled / shadow / live)
                │           │
                ▼           └── edit ──► back to draft (re-approval required)
            rejected
```

Enforced by the backend, not just the UI:

- **Server-side re-verification.** A candidate posted from the browser is
  re-checked against ATT&CK and re-scored; client-supplied scores are ignored.
- **Override with justification.** Approving a rule that still fails a check
  requires a written justification (≥ 20 characters by default), stored with
  the approval and flagged `OVERRIDE` in the audit log. Rejecting needs a note.
- **Only approved rules deploy.** Editing an approved rule returns it to draft.
  Editing a deployed rule marks the deployment *outdated* until redeployed.
- **Version history.** Every edit stores the previous version; any version can
  be viewed.
- **Optimistic locking.** Edits carry the version they were based on; a stale
  edit is rejected (HTTP 409) instead of silently overwriting a colleague.
- **Append-only audit log.** SQLite triggers reject `UPDATE` and `DELETE` on
  the audit table.
- **Learning from approvals.** Approved rules join retrieval with a ranking
  boost, so new rules converge on your team's index names, fields and style.

**Importing rules from the earlier IGNITE-Streamlit project:**

```bash
./venv/bin/python scripts/import_streamlit_history.py PATH/TO/ignite/data/history/rules.jsonl
```

Imported rules arrive as drafts, re-scored by these checks, with ATT&CK
mappings marked *needs review* (the old tool recorded no evidence).

---

## Splunk integration

Set `SPLUNK_URL` (management port **8089**, not the web port) and
`SPLUNK_TOKEN` (Splunk → Settings → Tokens) in `.env`. Then:

| Capability | Where |
|---|---|
| Parser validation of every generated or edited rule | Automatic (*Splunk parser* check) |
| Test search over the last hour / day / week, with a noise threshold | Rule Library → Review & deploy |
| Deploy an approved rule as a saved search | Rule Library → Review & deploy |

Deploy modes: **disabled** (saved, not scheduled) · **shadow** (scheduled;
results go to Triggered Alerts only, no notifications — recommended first) ·
**live** (fires the alert actions you name; the UI asks for confirmation).
Redeploying updates the existing saved search. Deleting a rule from the library
does **not** delete it from Splunk; the audit entry says so.

Free local test instance:

```bash
docker run -d -p 8000:8000 -p 8089:8089 -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD='ChangeMe123!' --name splunk splunk/splunk:latest
```

(Port 8000 clashes with the IGNITE API; map Splunk web to another port, e.g.
`-p 8001:8000`, and set `SPLUNK_VERIFY_SSL=false` for its self-signed cert.)

---

## Knowledge base, retrieval and evaluation

Before generating, IGNITE retrieves the most similar known detections (TF-IDF)
and gives them to the model as references. The UI lists which references
grounded each candidate.

| Source | Where |
|---|---|
| Bundled sample (9 detections) | `data/knowledge/sample/` — used until you build |
| Splunk ESCU + SigmaHQ | Built into `data/knowledge/processed/` |
| Your approved rules | Library, automatically, with a ranking boost |

```bash
./venv/bin/python scripts/download_sources.py             # shallow-clones ESCU + SigmaHQ (~1–2 GB)
./venv/bin/python scripts/build_dataset.py --product windows
```

The download also gives the legacy template pipeline its Sigma corpus: it reads
`data/knowledge/raw/sigma/rules/` (override with `IGNITE_SIGMA_PATH`), indexed
once at API start-up. The sidebar's *Sigma corpus* indicator shows whether it
is loaded. On Windows the script enables git long-path support, because some
SigmaHQ paths exceed the 260-character limit in deep folders.

The dataset is split **by technique**, so the test split contains only
techniques the retriever has never seen. To measure generation quality on it:

```bash
./venv/bin/python scripts/evaluate.py --limit 10    # spends provider quota
```

It reports generation success, all-checks pass rate, first-try pass rate,
ATT&CK exact and parent-technique match (the technique is hidden from the
request), average quality and average repairs. The latest result appears on the
Platform page.

---

## AI providers

**Switching from the dashboard.** The AI menu in the header (and the AI
provider panel on the Platform page) lists every provider plus **Demo (no AI)**.
Keys are never entered in the browser: a provider whose key is missing from
`.env` is shown greyed out with the variable to add, and Ollama shows whether
the server is running and the configured model is installed. The choice applies
to rule generation and the Assistant, is remembered across restarts, is recorded
in the audit log, and **Use .env default** returns to `IGNITE_LLM_PROVIDER`.
After adding a key to `.env`, restart the API.

| Provider | `IGNITE_LLM_PROVIDER` | Notes |
|---|---|---|
| Google Gemini | `gemini` (default) | REST API. Free-tier requests may be used by Google to improve services — review terms before using real data. |
| Anthropic Claude | `anthropic` | Official SDK. Default `claude-opus-5-5`. Uses server-side refusal fallback on supported models. |
| OpenAI | `openai` | Official SDK. `OPENAI_BASE_URL` for Azure OpenAI or a compatible gateway. |
| Ollama | `ollama` | Local model server; **no prompt leaves your network**. `ollama pull llama3.1` first. |
| ELLM | `ellm` | Your own LLM behind an **OpenAI-compatible endpoint** (internal gateway, vLLM, LiteLLM, LM Studio). Set `ELLM_BASE_URL` (usually ending in `/v1`), `ELLM_MODEL`, and `ELLM_API_KEY` if the endpoint needs one. |

All providers share the same timeouts, prompt-injection fencing and failure
statuses (`not_configured`, `unauthorized`, `rate_limited`, `timeout`,
`unreachable`, `provider_error`, `malformed`, `blocked`). A provider failure
never falls back to template output.

**What is sent:** the attack scenario, retrieved reference detections, the
rule being repaired or explained, validation findings and ATT&CK mappings.
Never credentials, API keys or raw telemetry.

---

## What is and is not validated

Five separate stages. **Passing one never implies the next.**

| Stage | Performed |
| --- | --- |
| Static text checks | Always |
| Weighted quality checks (Sigma, ATT&CK, SPL lint, …) | Always |
| Local sample test (Testing Lab subset evaluator) | When you run it |
| Splunk parser validation | When Splunk is configured |
| Real telemetry (test search, shadow deployment) | When you run a test search or deploy |

Every candidate's provenance records which stages ran. Model-supplied
`validated`, `score` or `production_ready` fields are discarded. Scores are
heuristics over the rule's text and structure — not probabilities, and not
measures of real-world detection effectiveness. **Measure real alert volume in
shadow mode before enabling live alerting.**

**ATT&CK verification.** IDs are checked against `data/mitre.json` (697 current
techniques; 161 revoked/deprecated excluded). `reference_verified` means the
ID exists; `mapping_supported` means evidence links this detection to it. The
two are never conflated; unevidenced mappings show as *needs review*.

---

## Other features

### AI Detection Assistant
Explains and critiques the selected rule (explain, gaps, false positives,
validation findings, ATT&CK, telemetry). Uses the configured provider. Model
output is rendered as plain text, never HTML. Attack descriptions and rules are
fenced as untrusted data; embedded instructions are treated as content to
report, not commands.

### Detection Rule Testing Lab
Tests the selected rule against synthetic JSON events with IGNITE's local
evaluator — **not Splunk**. Supported: `field=value`, `!=`, wildcards, numeric
comparisons, AND/OR/NOT with parentheses. Transforming commands, subsearches,
macros, lookups and `IN (...)` are reported as unsupported and never folded
into a verdict; `UNEVALUABLE` is a first-class outcome.

### Saved investigations
A whole analysis (results, selected rule, test cases) saved server-side in
SQLite, with search, duplicate, export and delete. Records are schema-versioned.

### Demo mode
`DETECTION_GENERATION_MODE=demo` covers only PowerShell download cradles,
certutil transfers and scheduled-task persistence. Anything else returns zero
candidates with an explanation rather than an unrelated rule. Demo output is
labelled DEMO everywhere, still runs the quality checks, and is never described
as LLM-generated.

### Legacy template pipeline and Streamlit fallback
`POST /api/analyze` and `streamlit run app.py` use the original keyword →
template pipeline in `modules/`. It works offline but selects a hardcoded
template by keyword rather than generating for your scenario.

---

## Tests

```bash
./venv/bin/python -m pytest -q          # backend: API, generation, quality gates, library, providers
cd frontend
npm run typecheck && npm test && npm run build
```

All provider, Splunk and network calls are mocked; every backend test uses its
own temporary database. One existing backend test
(`test_ai_status_reports_unavailable_when_server_is_down`) expects no local
Ollama server and fails if one is running.

---

## Project layout

```
api/
  main.py                  FastAPI app + CORS
  settings.py              environment configuration
  routes/
    detection.py           health, legacy analyze, AI summary
    workbench.py           generation, AI Detection Assistant, Testing Lab, investigations
    library.py             rule library, review, deploy, export, audit, coverage, platform
  schemas/                 Pydantic request/response models
  services/
    rule_generator.py      retrieve → generate → validate → repair
    validators.py          14 weighted quality checks and the score
    sigma_tools.py         Sigma validation and Sigma → SPL (pySigma)
    knowledge.py           knowledge base, TF-IDF retrieval, dataset builder
    library.py             rules, versions, review workflow, append-only audit log
    splunk_client.py       Splunk REST: parse, test search, deploy
    exporters.py           contentctl, savedsearches.conf, Sigma, Markdown, JSON
    coverage.py            ATT&CK coverage matrix
    llm.py                 Gemini / Anthropic / OpenAI / Ollama providers
    attack.py              ATT&CK verification against data/mitre.json
    spl_eval.py            Testing Lab local evaluator
    store.py               SQLite connection and saved investigations
frontend/src/
  app/                     shell (navigation) and root component
  features/                analysis, detection-rules, rule-library, coverage,
                           activity, platform, copilot, testlab, validation, export
  components/ui/           panels, badges, code panel, quality checks, forms
scripts/                   download_sources, build_dataset, evaluate, import_streamlit_history
data/                      mitre.json, knowledge/sample, telemetry catalog
modules/, ui/, app.py      legacy template pipeline and Streamlit fallback
legacy/                    archived manual scripts and old copies (see legacy/README.md)
tests/                     backend tests
```

---

## Security notes

- Provider keys and the Splunk token live only in the backend environment;
  status endpoints report whether they are set, never their values.
- Splunk TLS verification is on by default.
- CORS is restricted to the configured frontend origins.
- Detections may not use data-modifying or output commands (`delete`,
  `collect`, `outputlookup`, `sendemail`, `script`, …); the quality gate fails
  them.
- Deploy input (mode, cron, time window, alert actions) is validated against
  strict patterns.
- The audit log is append-only at the database level.

---

## Limitations and next steps

**Current limitations**
- **No authentication or roles yet.** The audit log records `IGNITE_OPERATOR`
  (or the OS user running the API), which identifies the operator, not an
  individual signed-in user. Add SSO before multi-user deployment;
  `library.current_actor()` is the single place to plug it in.
- SQLite suits a single team on one server; use a managed database for high
  availability.
- Retrieval is TF-IDF; embeddings would rank better once the dataset is large.
- The Testing Lab evaluator implements only a subset of SPL.

**Sensible next steps**
1. SSO (OIDC/SAML) with reviewer vs. author roles, including no self-approval.
2. Replay ESCU attack-data samples into a test index for true-positive checks.
3. Record analyst true/false-positive verdicts on deployed alerts and use them to
   promote shadow rules to live.
4. Embedding-based retrieval; fine-tuning once thousands of validated rules exist.

Respect the licences of Splunk security_content (Apache 2.0) and SigmaHQ
(Detection Rule License) when redistributing derived data.
