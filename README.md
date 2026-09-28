# IGNITE 2.0 — AI Detection Rule Generator

Describe an attack in plain English; get candidate Splunk SPL detection rules,
MITRE ATT&CK mappings, extracted entities, validation findings and exports.

There are **two front ends** over the same Python detection engine:

| Front end | Stack | Status |
| --- | --- | --- |
| `frontend/` + `api/` | React 19 · TypeScript · Vite · Tailwind 4 · FastAPI | Primary |
| `app.py` | Streamlit | Fallback, still fully functional |

The detection engine in `modules/` is shared by both and is unchanged.

---

## Prerequisites

- **Python 3.12+**
- **Node.js 20+** (developed against v24) — only for the React front end
- **Ollama** (optional) — the AI summary is a convenience feature; rule
  generation works without it

> If `python3 -m venv` fails with *"ensurepip is not available"*, either
> `sudo apt install python3-venv` or use [uv](https://astral.sh/uv):
> `uv venv venv`.

---

## Install

### Backend

```bash
python3 -m venv venv                      # or: uv venv venv
./venv/bin/pip install -r requirements.txt # or: uv pip install --python venv/bin/python -r requirements.txt
```

### Frontend

```bash
cd frontend
npm install
```

---

## Run

Two terminals.

**Terminal 1 — API (port 8000):**

```bash
./venv/bin/uvicorn api.main:app --reload --port 8000
```

**Terminal 2 — web app (port 5173):**

```bash
cd frontend
npm run dev
```

Open **http://localhost:5173**. Interactive API docs are at
**http://localhost:8000/docs**.

> Vite proxies `/api` to `http://localhost:8000`, so the browser stays
> same-origin in development. If port 5173 is taken, Vite picks the next free
> port and prints it.

### Streamlit fallback

```bash
./venv/bin/streamlit run app.py     # http://localhost:8501
```

---

## Environment configuration

All optional — the defaults work for local development.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Model server address. Set this if the API and Ollama are not on the same host or network namespace (e.g. containers), since `localhost` inside a container is the container itself. |
| `IGNITE_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated origins permitted to call the API. |
| `IGNITE_AI_STATUS_TTL` | `30` | Seconds an AI availability check is cached, so ordinary renders do not repeatedly probe the model server. |
| `IGNITE_API_URL` | `http://localhost:8000` | Proxy target used by the Vite dev server. |
| `VITE_API_BASE` | `/api` | API base path used by the browser client. |

---

## Using the application

1. Describe an attack scenario in the editor, or click an example chip.
2. Press **Generate detection rules** (or `Ctrl`/`Cmd` + `Enter`).
3. Read the results across five tabs:
   - **Overview** — best rule, scores, warnings, primary technique
   - **Detection Rules** — candidate comparison, SPL, copy/download
   - **Attack Intelligence** — ATT&CK techniques, entities, telemetry
   - **Validation** — validation and quality findings, with caveats
   - **Export** — JSON and `.spl` downloads
4. **AI analysis** at the bottom is optional and independent of rule
   generation.

Recent analyses are kept in **your browser's localStorage only** — this is not
server-side or multi-user persistence, and the sidebar offers a clear action.

---

## What the scores mean

Be careful reading these — they are deliberately labelled in the UI:

- **Candidate rule score** uses its own `0–125` scale (the underlying scorer
  stacks indicator bonuses and can exceed 100). It is never displayed as a
  percentage.
- **Validation score** comes from static text checks on the generated query —
  presence of an index, event code, fields and known attack indicators.
- **Quality score** is a heuristic over the same text.

None of these is a calibrated probability, and none measures real-world
detection effectiveness. **No rule generated here is validated against a live
Splunk instance** — nothing in this tool parses or executes SPL.

---

## Tests

```bash
# Backend — API, pipeline adapter, Streamlit app  (74 tests)
./venv/bin/python -m pytest tests/ -q

# Frontend — type checking, unit and interaction tests, production build
cd frontend
npm run typecheck
npm test          # 29 tests
npm run build
```

All network and model calls are mocked; no test requires a running Ollama.

---

## Project layout

```
api/                 FastAPI layer over the existing engine
  main.py              app + CORS
  routes/detection.py  endpoints
  schemas/analysis.py  Pydantic request/response models
  services/detection.py adapts modules/ output to the schemas
  settings.py          environment configuration

frontend/            React + TypeScript + Vite + Tailwind
  src/app/             shell and root component
  src/components/ui/   buttons, panels, badges, code panel, toasts
  src/features/        analysis, detection-rules, attack-intelligence,
                       validation, export
  src/hooks/           analysis state, AI status, localStorage history
  src/lib/             API client, formatting helpers
  src/types/           API contract types

modules/             Detection engine (unchanged)
ui/                  Shared pipeline adapter + Streamlit presentation layer
tests/               Python tests
app.py               Streamlit fallback front end
data/                MITRE ATT&CK bundle, telemetry catalog, Sigma corpus
```

---

---

---

## Two generation paths — know which one you used

IGNITE has **two independent** ways to produce a detection. They are not
interchangeable and the UI labels which produced a result.

| | Deterministic pipeline (`POST /api/analyze`) | LLM generation (`POST /api/rules/generate`) |
| --- | --- | --- |
| Driven by | Keyword match on the scenario | The scenario text itself |
| SPL source | **Hardcoded f-string templates** in `modules/` | Generated per scenario |
| ATT&CK source | 13 hardcoded keyword→ID pairs | Model-proposed, **independently verified** |
| Needs an API key | No | **Yes** |
| On failure | n/a | Explicit error, **no fallback rules** |

> The deterministic pipeline does **not** call an LLM. It selects a template
> by keyword. It is kept because it works offline, but it does not "generate"
> a rule for your scenario in any meaningful sense.

### What the LLM path verifies independently

Nothing the model says about its own output is trusted:

- **ATT&CK IDs** are checked against `data/mitre.json`. Invented IDs are
  flagged `unknown_id`. Canonical names come from the dataset, not the model.
- **Static checks** (unbalanced quotes/parens, missing data source,
  match-everything wildcards, trailing pipes) are computed by us.
- Any `validated`, `score` or `production_ready` field the model emits is
  **discarded**.

### Reference vs. mapping

Two different claims, never conflated:

- `reference_verified` — this technique ID exists and is current.
- `mapping_supported` — evidence was also supplied linking *this detection* to
  it. Without evidence the mapping is `needs_review`.

---

## ATT&CK data

Bundled STIX 2.0 enterprise bundle at `data/mitre.json`.

- **697 current techniques**; **161 revoked/deprecated are excluded** so they
  can never be shown as current.
- Version is the latest `modified` timestamp in the bundle, reported by
  `GET /api/attack/dataset` and recorded in every candidate's provenance.
- Loaded once per process and cached (the file is ~48 MB).
- Offline by design — no dataset is fetched at request time. To update,
  replace the file from the official MITRE CTI repository.

---

## Validation levels

Four separate stages. **Passing one never implies the next.**

| Stage | Status value | Performed |
| --- | --- | --- |
| Static checks | `run` | Yes — deterministic text checks |
| Local sample test | `not_run` until you run it | Yes — subset evaluator |
| Splunk syntax validation | `not_configured` | **No** |
| Real telemetry validation | `not_run` | **No** |

No Splunk instance is contacted anywhere in this codebase. An
`ExternalValidator` seam exists in `api/services/spl_eval.py` for a future
adapter; it raises `NotImplementedError` rather than faking an integration.

### Local evaluator — exact supported subset

**Supported:** `field=value`, `field!=value`, `*` wildcards, numeric `>` `<`
`>=` `<=`, AND across terms, OR within parentheses, multivalue fields (matches
if any value matches).

**Not supported — reported, never silently ignored:**

| Construct | Behaviour |
| --- | --- |
| `NOT` | Every event returns **`UNEVALUABLE`** — no match verdict is given |
| `\| stats`, `\| eval`, … | Listed as unsupported; not applied |
| Subsearches, macros, lookups, `IN (...)` | Listed as unsupported |

`UNEVALUABLE` is a first-class outcome. It is **never** counted as a pass or a
failure — that would mean reporting a verdict on logic that was not evaluated.

---

## What the scores actually mean

All scores are **heuristics over query text**. None is a probability, and none
measures real-world detection effectiveness.

- **Validation score** — deducts for missing index/EventCode/fields. It is
  possible for a useless rule to score well; a rule of `Image="*"` scores
  100/100 under these checks, which is why the newer static checks flag
  match-everything wildcards separately.
- **Quality score** — adds points for the presence of fields.
- **Candidate score** — ranking heuristic on its own 0–125 scale.

Never read "Static checks passed" as "this rule works".

---

## Offline demo mode

For demonstrating the app without a provider (or when the free-tier quota is
exhausted):

```bash
DETECTION_GENERATION_MODE=demo ./venv/bin/uvicorn api.main:app --port 8000
```

`gemini` is the default; an unrecognised value falls back to `gemini` with a
warning, so demo mode is always opt-in.

### What demo mode will and will not do

| | Behaviour |
| --- | --- |
| Supported | PowerShell download cradles, certutil transfers, scheduled-task persistence |
| Anything else | **Zero candidates** plus an explanation — never an unrelated rule |
| Labelling | `[DEMO]` in the name, a DEMO badge, and a warning banner |
| Provenance | `generator: template`, `provider: none`, `model: ""` |
| ATT&CK | Still verified against the bundled dataset; evidence cites the matched keyword |
| Scores | Validation and quality remain **not scored** — nothing is invented |

### Why it refuses most scenarios

The legacy template pipeline answers *any* input, but outside a few keywords
it returns:

```
index=sysmon EventCode=1 | stats count by host user Image CommandLine ParentImage
```

That query contains no attack indicator and matches every process-creation
event — yet the legacy validator scores it 80/100 and marks it `valid: true`.
Returning it for, say, a ransomware scenario would present an unrelated rule
as a working detection, so demo mode refuses instead.

**A Gemini failure never falls back to demo output.** Template rules must not
be presented as the result of a model request.

## AI Detection Copilot (optional)

Explains and critiques the selected rule using a hosted LLM. **Everything else
works without it.**

### Configure

```bash
cp .env.example .env
# edit .env and set GEMINI_API_KEY
```

Get a key at [aistudio.google.com](https://aistudio.google.com/) → "Get API key".
Verify current free-tier models at
[ai.google.dev/gemini-api/docs/models](https://ai.google.dev/gemini-api/docs/models).

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | *(empty)* | Enables the Copilot. Without it the panel explains how to configure it. |
| `GEMINI_MODEL` | `gemini-3.5-flash` | Model ID. Provider catalogues change, so this is configurable. |
| `GEMINI_BASE_URL` | Google endpoint | Override for a proxy or regional endpoint. |
| `IGNITE_LLM_MAX_OUTPUT_TOKENS` | `1200` | Bounds response size. |
| `IGNITE_LLM_MAX_INPUT_CHARS` | `12000` | Bounds context size. |
| `IGNITE_DB_PATH` | `data/investigations.db` | SQLite file for saved investigations. |

The key is read by the backend only. It is never sent to the browser, never
placed in a response, and never logged. `.env` is git-ignored.

### What is sent to the provider

Only the attack scenario, the selected rule, validation findings, ATT&CK
mappings and extracted tool names. Never credentials, API keys or raw
telemetry.

### Privacy and quotas

Free-tier requests may be used by the provider to improve their services.
**Review Google's current terms before sending real organisational data.**
Free-tier rate limits change over time — check your limits in
[AI Studio](https://aistudio.google.com/).

### Prompt-injection handling

Attack descriptions and rule text are treated as untrusted. They are fenced in
the prompt and the model is instructed to treat embedded instructions as data
to report, never commands to follow. Model output is rendered as plain text —
never as HTML — and cannot execute code, run commands or modify files.

---

## Detection Rule Testing Lab

Tests the selected rule against synthetic JSON events, so you can answer:
*does this match what I expect, and what might it miss?*

### Three distinct validation statuses

| Status | What it means | Performed here |
| --- | --- | --- |
| **Static checks** | Text inspection for required fields and indicators | Yes |
| **Local sample test** | Matched against synthetic events by IGNITE's own evaluator | Yes |
| **External runtime validation** | Executed by a real Splunk instance | **No** |

> The local evaluator is **not Splunk**. It supports field comparisons,
> wildcards, numeric operators and negation. Transforming commands (`| stats`),
> subsearches, macros, lookups and `IN (...)` are **reported as unsupported and
> not applied** — never silently folded into a verdict.

An `ExternalValidator` interface exists as a seam for a future real Splunk
adapter; it raises `NotImplementedError` rather than faking an integration.

---

## Saved Investigations

Persisted server-side in SQLite (`data/investigations.db`, git-ignored). Save,
reopen, duplicate, search, export and delete — with the analysis, selected
rule and test cases preserved.

Records are schema-versioned. A record written by a different version loads on
a best-effort basis with a visible warning rather than failing silently.

---

## What works offline

| Feature | Needs a key? |
| --- | --- |
| Detection rule generation, ranking, export | No |
| ATT&CK mapping, entity extraction | No |
| Static validation and quality heuristics | No |
| Testing Lab (local sample matching) | No |
| Saved investigations | No |
| **AI Detection Copilot** | **Yes — `GEMINI_API_KEY`** |
| Legacy AI summary panel | Needs local Ollama (separate) |

---

## Limitations and next steps

**Current limitations**
- `data/sigma/` is empty, so the Sigma pipeline matches nothing.
- The keyword map routes 13 phrases against 858 loaded ATT&CK techniques.
- No SPL syntax validation; no Splunk instance is ever contacted.
- The local evaluator requires all conditions to hold, so its verdict may
  differ from Splunk for rules using `OR`/`NOT` — it says so when it detects them.
- Single-user and local by design: no auth, no multi-tenancy.

**Sensible next steps**
1. Populate `data/sigma/` with the SigmaHQ corpus.
2. Widen the technique keyword map, or replace it with embedding-based retrieval.
3. Build a real Splunk adapter behind the existing `ExternalValidator` seam.
4. Expand the evaluator's boolean support so `OR`/`NOT` are evaluated faithfully.
