# Prompt Injection Firewall (PIF)

**ET AI Hackathon — Agentic Edition (The Economic Times × Accenture) · Problem 2: Agentic Cybersecurity — Prompt Injection Firewall**

A working, local, fail-closed firewall for AI agents: it inspects **every** piece of content before it reaches the model, detects and neutralizes all **nine attack classes** of the problem statement, gates agent **tool calls and outputs**, and allows legitimate content through with minimal disruption.

- **Declared rubric position: F3 × D1** — 9/9 attack types with first-class detectors (see [Grid declaration](#grid-declaration-f3--d1)).
- **Independent evidence**: 5 public Hugging Face datasets, **849 sha256-frozen rows** the rules were never trained or authored against — aggregate recall **0.465 deterministic → 0.776 with the behavioral layer** at a flat **8.6% benign FPR** (see [Measured results](#measured-results)).
- **Runs anywhere**: pure-Python core, `RUN.bat` one-click launcher on Windows, non-root Docker image with OCR built in.

---

## Table of contents

1. [The problem](#the-problem)
2. [What PIF does](#what-pif-does)
3. [High-level flow](#high-level-flow)
4. [Problem-statement coverage](#problem-statement-coverage)
5. [Grid declaration (F3 × D1)](#grid-declaration-f3--d1)
6. [Measured results](#measured-results)
7. [Architecture in depth](#architecture-in-depth)
8. [Components](#components)
9. [Quick start](#quick-start)
10. [API contract](#api-contract)
11. [Configuration](#configuration)
12. [Testing, CI and evaluation integrity](#testing-ci-and-evaluation-integrity)
13. [Security posture and limitations](#security-posture-and-limitations)
14. [Repository layout](#repository-layout)
15. [Provenance and prior art](#provenance-and-prior-art)
16. [Mapping to the hackathon evaluation framework](#mapping-to-the-hackathon-evaluation-framework)

---

## The problem

AI agents (LLM-based agents, copilots, chatbots) routinely ingest external content — web pages, PDFs, emails, documents, API responses — and invoke tools. That access exposes them to **direct and indirect prompt injection**: malicious instructions hidden in user input or retrieved data that hijack the agent into extracting private information, performing unauthorized tasks, or triggering unwanted behavior.

The problem statement asks for a **Prompt Injection Firewall** that:

> intercepts all incoming content before it influences the AI's behavior … detects and neutralizes malicious prompt injections while allowing legitimate content to pass with minimal disruption.

The firewall must handle **eleven input sources** (user messages, web pages, PDFs, emails, Markdown, HTML, Word documents, API responses, OCR text, source code, images via OCR) and detect **nine attack types**: instruction override, role change, secret extraction, tool abuse, credential theft, context poisoning, multi-step jailbreaks, encoded instructions, and indirect prompt injection.

**PIF is that firewall.** It is a synchronous inspection layer that sits between untrusted content and the model, plus a set of runtime guards that protect what an agent *does* with the content (tool calls) and what comes *out* of it (leaks).

## What PIF does

| Capability | How it is delivered |
| --- | --- |
| Intercept everything before the model | `POST /v1/scan` is the single gate every client (UI replica, CLI, host application) must pass; the engine is synchronous per request |
| Read any format safely | Format identification (magic bytes, not declared type), sandboxed parsers for PDF / DOCX / HTML / Markdown / email / JSON / text / code, image OCR, recursive attachments |
| See hidden attack channels | PDF white-text / 2-point / off-page text, DOCX vanish runs + headers/footers, CSS-hidden HTML, faint-text two-pass OCR, Unicode tag / zero-width / base64 / rot13 / leet decoding |
| Detect all 9 attack classes | 23 named rule families + calibrated TF-IDF/LogReg semantic classifier + fuzzy phrase matching + cross-turn context analysis (per-view and per-scan) |
| Behavioral verdict for gray-band content | Detonation chamber: a decoy agent holding HMAC-keyed canary secrets and fake tools detonates the content — the verdict is what the content *does* (canary leaks, tool fires, memory writes), inherently paraphrase-resistant |
| Optional AI escalation | Gray-band LLM judge, escalation-only (can never lower a decision) and fail-closed (degrades to off without a key) |
| Neutralize, not just block | Span redaction that preserves benign sentences (survivor spotlighting), sanitize-then-rescan escalation, quarantine with reason sidecars |
| Guard actions and outputs | Taint-aware ToolGuard (arguments traced to untrusted content), output-side leak guard (live keys, tokens, secrets never leave the agent), guarded URL fetch (DNS-rebinding-safe pinning) |
| Prove it works | 5 frozen public datasets, layer ablation, threshold calibration, false-positive/false-negative reports shipped with every build, CI release gates |
| Keep improving safely | Supervised self-tuning agent (perceive → plan → act → verify on shadow firewalls) with a **human approve/reject gate** before any production change |

## High-level flow

### Where PIF sits

PIF is not a chatbot and not an agent — it is the **security boundary between content and the agent**. Untrusted content from any source enters the firewall; only allowed or sanitized content reaches the model, every tool call is re-inspected at action time, and every outbound result is leak-checked.

```
   UNTRUSTED CONTENT                          PIF                      PROTECTED SIDE
   ─────────────────                          ───                      ──────────────
   user messages ──────┐
   web pages ──────────┤   guarded fetch     │
   PDF / DOCX / email ─┤   + parsers          │   allowed /           ┌──────────────┐
   HTML / Markdown ────┤   + hidden-channel   │   sanitized           │  LLM / agent │
   JSON / API resp. ───┼───forensics──────────┼───content only──────►│              │
   OCR text / images ──┤                      │                       └──────┬───────┘
   source code ────────┘                      │                              │
                                              │      ┌───────────────────────┤
                                              │      ▼                       ▼
                                              │  TOOL CALLS re-inspected  OUTPUTS leak-checked
                                              │  (taint-aware ToolGuard)  (output leak guard)
                                              │      │ denied tools never execute
                                              ▼      ▼
                                   side effects: quarantine/ + data/report.db + logs/
```

### The request lifecycle — eight checkpoints

Every scan (prompt, attachment, web page, RAG chunk, tool call) walks the same synchronous pipeline:

```
 content ─► 1 INPUT FORENSICS     format verification + parsers + hidden-content
            │                     extraction (PDF white/2pt/off-page, DOCX vanish
            │                     runs + headers/footers, CSS-hidden HTML, faint OCR)
            ├─► 2 NORMALIZATION   canonicalization + bounded recursive decoding
            │                     (base64 / rot13 / leet / reverse / unicode-tag;
            │                     budgets: ≤32 views, ≤1M chars, depth ≤2)
            ├─► 3 RULES           23 named rule families, per-rule policy overrides
            ├─► 4 SEMANTIC        checksummed TF-IDF+LogReg, PR-calibrated thresholds
            ├─► 5 CONTEXT         cross-turn sequences, payload splitting, crescendo,
            │                     decaying session risk, indirect-injection provenance
            ├─► 6 RISK FUSION     explainable factor fusion + hidden-content bonus
            │                     + detonation chamber (full-band behavioral verdict)
            │                     + gray-band LLM judge (escalation-only, fail-closed)
            ├─► 7 POLICY          allow / sanitize (span redaction + survivor
            │                     spotlighting + >80%-removed escalation) / isolate /
            │                     block; quarantine with reason sidecars
            └─► 8 ACTION GATES    taint-aware ToolGuard + output-side leak guard
                                  + guarded URL fetch (DNS-rebinding-safe pinning)
```

| Phase | Module(s) | Input → Output | Failure behavior |
| --- | --- | --- | --- |
| P1 Security boundary | `pif/api.py`, `pif/schemas.py`, `pif/sessions.py` | HTTP request → admitted request + scan/session IDs | 413/401/503/422/409; fail-closed on capacity |
| P2 Input processing | `pif/input/*` | bytes → `Segment[]` + `warnings[]` | every parser failure = warning → Phase 7 blocks |
| P3 Normalization | `pif/normalization.py` | text → named decode-view list | budget exceeded = warning, never a crash |
| P4 Detection | `pif/detection/*` | views + history → `Finding[]` + 9-category summary | detection exception → `detection_incomplete` → block |
| P5 Risk correlation | `pif/risk.py` | findings → fused risk + per-category contributions | capped at 1.0; no findings → 0.0 |
| P6 Policy + neutralization | `pif/policy.py`, `pif/quarantine.py` | risk → decision + `safe_content` (+ quarantine files) | neutralization failure → block |
| P7 Agent guards | `pif/guards.py`, `pif/output_guard.py`, `pif/fetch.py` | tool calls / chunks / HTML → ScanResults or `GuardDenied` | denied tools never execute |
| P8 Final result + telemetry | `pif/engncore.py`, `pif/report_db.py` | everything → `ScanResult` + journal + logs | scan exception → error journal + re-raise |

> **Full detail**: [FLOW_DIAGRAM.md](FLOW_DIAGRAM.md) is the complete flow documentation — Part A (system map, master flow, component matrix, config truth), Part B (per-component sub-flows), Part C (micro-level diagrams with worked examples).

### The decision model

Risk thresholds (hot-reloadable from `conf/policy.ini`):

| Fused risk | Decision |
| --- | --- |
| ≥ 0.95, or any credential-theft / tool-abuse finding (hard block) | **BLOCK** + quarantine + report |
| inspection incomplete / parser failure / oversized | **BLOCK** (fail closed — never "inspected") |
| ≥ 0.85 | **SANITIZE** — redact attack spans, keep benign sentences, re-scan the survivor; residual suspicion → BLOCK |
| ≥ 0.50 | **ISOLATE** — content continues flagged/quarantined per policy |
| < 0.50 | **ALLOW** |

The behavioral layers can only ever *raise* a decision (escalation-only), and both fail closed.

## Problem-statement coverage

### Input sources — all eleven handled

| Problem statement | PIF implementation |
| --- | --- |
| User messages | prompt field of `ScanRequest` (`pif/schemas.py`) |
| Web pages | guarded fetch `pif/fetch.py` + HTML parser + `guards.scan_page` |
| PDFs | `pif/input/parsers/pdf.py` (pages, metadata, white/2pt/off-page hidden text) |
| Emails | `pif/input/parsers/email.py` (headers, body, depth-two attachments) |
| Markdown | `pif/input/parsers/markdown.py` |
| HTML | `pif/input/parsers/html.py` (incl. CSS-hidden channel forensics) |
| Word documents | `pif/input/parsers/docx.py` (vanish runs, tiny/white text, headers/footers) |
| API responses | `source="api"` content items + `pif/input/parsers/json.py` |
| OCR text | `pif/input/ocr.py` (two-pass faint-text OCR; Tesseract in Docker) |
| Source code | text/code parser path (fenced blocks, comments) |
| Images (via OCR) | `pif/input/parsers/image.py` → OCR pipeline |

Format truth is established by magic bytes, not declared type (`pif/input/identify.py`); archives pass a ZIP sandbox (50 MiB uncompressed, 100:1 expansion ratio, depth-two attachments).

### The nine attack types — all nine detected

| # | Attack type | Detector |
| --- | --- | --- |
| 1 | Instruction override | RULE-001..023 families incl. non-English and memory-wipe rules |
| 2 | Role change | RULE-005 / RULE-013 |
| 3 | Secret extraction | RULE-004 / RULE-014 |
| 4 | Tool abuse | RULE-007 / RULE-008 / RULE-015 + action-time taint gate |
| 5 | Credential theft | RULE-006 / RULE-016 (hard-block category) |
| 6 | Context poisoning | RULE-009 / RULE-017 / RULE-021 |
| 7 | Multi-step jailbreaks | RULE-010 / RULE-018 + `pif/detection/context.py` (crescendo, payload splitting, decaying session risk) |
| 8 | Encoded instructions | `pif/detection/encoded.py` + `pif/normalization.py` decoding + view-differential evidence |
| 9 | Indirect prompt injection | `pif/detection/indirect.py` (IIND-001..004), provenance-gated |

Each finding carries the attack category, its numeric ID (1–9 per the spec), rule ID, evidence span and severity — the scan result's `attacks` field is the per-category summary.

## Grid declaration (F3 × D1)

The rubric requires teams to declare their 3×3 position and justify it; over-claiming is penalized.

**F3 — features: 9/9 attack types with first-class detectors.** Every attack class in the table above has a dedicated, named detector with test coverage and evidence output — the F3 bar is "detect at least 7", and all nine are implemented and demonstrated.

**D1 — depth: claimed; D2 is not.** Multimodal forensics (PDF/DOCX/HTML/image hidden channels) are implemented and tested, so the pipeline handles heterogeneous input — but D2's "high degree of demonstrable reliability" is not met by 0.776 recall at 8.6% FPR across five public datasets, so we stop at D1 and publish the numbers. The path to D2 is the same frozen-public-split evaluation loop with more datasets and the LLM layers measured with a key.

## Measured results

5 public datasets — **849 rows, sha256-frozen splits** (`data/eval/public/`, freeze manifest inside the report) the rules were never trained or authored against. Reproduce everything: `python scripts/build_public_eval.py` and `python scripts/ablation.py`.

| Dataset | Rows | Recall (rules+semantic) | Recall (+ behavioral layer) | Benign FPR |
| --- | ---: | ---: | ---: | ---: |
| Lakera/gandalf_ignore_instructions | 100 | 0.880 | 0.880 | — |
| microsoft/llmail-inject (indirect, email channel) | 258 | 0.209 | **0.868** | — |
| deepset/prompt-injections | 116 | 0.350 | 0.350 | 0.000 |
| jackhhao/jailbreak-classification | 262 | 0.691 | 0.712 | 0.098 |
| leolee99/NotInject (benign, trigger-heavy — FPR metric) | 113 | — | — | 0.115 |
| **Aggregate** | **849 (557 attacks / 292 benign)** | **0.465** | **0.776** | **0.086 (flat)** |

Measured latency across the public suites: **median 96–933 ms** per scan (p95 up to ≈2.7 s on the largest multi-turn suite), `reports/evaluation_public.json`.

### Three independent layers, each measured (ablation: `reports/ablation.json`)

| Layer | Mechanism | Independent recall | Independent FPR |
| --- | --- | ---: | ---: |
| 1. Content rules + semantic | 23 rule families + calibrated TF-IDF/LogReg | 0.465 | 0.086 |
| 2. + Behavioral canaries | detonation chamber, full band: a decoy agent holds HMAC canary secrets and fake tools; the verdict is what the content *does* (leaks, tool fires, memory writes) — inherently paraphrase-resistant | **0.776** (+31 pts) | 0.086 (flat) |
| 3. + Action-time taint | tool arguments traced to untrusted content; destinations planted by retrieved pages are denied regardless of wording | structural (no public dataset exercises live tool calls — demonstrated in `scripts/demo.py` scene 7) | — |

The gray-band LLM judge ships enabled with a documented no-key degraded mode (self-disables without `OPENAI_API_KEY`); the ablation harness has a third column ready for it — run with a key and `reports/ablation.json` fills it in. It is **not** counted in any number above.

### What the numbers honestly say

- **gandalf (0.880)** is the strongest independent result; the behavioral layer contributes **+31 recall points at flat FPR** — it catches directive-shaped attacks the text rules miss, and benign rows simply don't direct the decoy to leak anything.
- **deepset recall (0.350)** is capped by a labeling-scope difference: deepset counts in-context roleplay and out-of-context harmful requests as injections; this firewall requires attack evidence in the text itself. Published as-is, every miss listed in `reports/evaluation_public_misses.json`.
- **NotInject FPR (0.115)** is measured on benign prompts stuffed with trigger words — our worst honest number, published for exactly that reason.
- The internal matched-twin corpus (recall 0.971, FPR 0.000, CI-gated in `reports/evaluation.json`) is a **regression suite**, not generalization evidence — its provenance breakdown labels the self-authored groups "circular by construction".

## Architecture in depth

The engine (`pif/engncore.py`) orchestrates the eight checkpoints above. What lives where:

| Area | Modules | Notes |
| --- | --- | --- |
| API boundary | `pif/api.py`, `pif/schemas.py` | body-size gate → bearer auth → strict schema (extra fields forbidden) → trace ID (`x-pif-trace-id`) → capacity gate → session check |
| Input forensics | `pif/input/` (identify, base, parsers/, ocr.py) | magic-byte type truth, ZIP sandbox, per-parser hidden-channel extraction, two-slot subprocess gate with 20 s deadline |
| Normalization | `pif/normalization.py` | six-step canonical chain, BFS decode-view generation with hard budgets |
| Detection | `pif/detection/` (rules, semantic, fuzzy, context, encoded, indirect, llm_judge) | per-view rules → semantic → fuzzy; per-scan context; encoded/indirect specialists; escalation-only judge |
| Risk fusion | `pif/risk.py` | explainable factors: rule agreement, obfuscation bonus, external-source bonus, multi-category amplification |
| Policy | `pif/policy.py` | four decisions + span redaction + survivor spotlighting + sanitize-rescan |
| Quarantine | `pif/quarantine.py` | blocked attachments stored with reason + attack categories in a JSON sidecar; storage failures never raise into the pipeline |
| Guards | `pif/guards.py`, `pif/output_guard.py`, `pif/fetch.py` | web / RAG / tool boundaries re-enter the firewall per call; outbound leak guard; DNS-rebinding-safe fetch |
| Detonation | `pif/detonation.py` | offline deterministic emulator (default) or LLM decoy (`decoy = llm` + `PIF_DETONATION_SECRET`) |
| Sessions | `pif/sessions.py` | in-memory, TTL 900 s, max 1000, per-session risk decay for multi-step jailbreaks |
| Persistence | `pif/report_db.py` | every scan (request, decision, findings) → `data/report.db` SQLite; feeds the admin portal |
| Observability | `pif/observability.py` | JSON event log + human narrative log, phase-tagged P1..P8, correlated by scan/request ID |
| Self-tuning agent | `pif/agenticai_redteam.py` | perceive/plan/act/verify on **shadow firewalls**; writes candidates only; human gate merges to production policy |

## Components

| Component | Entry point | Port | What it is |
| --- | --- | --- | --- |
| **PIF API** (the firewall) | `scripts/main.py` | 8000 | FastAPI service exposing `POST /v1/scan`, `GET /health`, `GET /ready`, `DELETE /v1/sessions/{id}`; bearer-token auth |
| **UI_PIF — Admin portal** | `UI_PIF/pif_portal.py` | 8081 | Live telemetry (reads `report.db` directly), scan history, Rules & Engines console, manual scan playground, self-tuning **Agent Actions** (human approve/reject gate), Settings page (57 settings across 11 groups, type-validated, hot-reloading policy groups, write-only token) |
| **UI_AI_Replica — demo proxy** | `UI_AI_Replica/server.py` | 8080 | Hosts saved ChatGPT / Gemini / GenWizard chat pages on localhost and proxies every prompt + attachment through the PIF API — the firewall demonstrated inside a realistic chat UI |
| **CLI client** | `scripts/call.py` | — | Packs files to base64, posts a `ScanRequest`, exits 0 (allowed) / 2 (blocked) — the integration contract for host applications |
| **Guard library** | `pif/guards.py` | — | `scan_page` / `scan_chunks` / `ToolGuard` for embedding the firewall into any agent framework |
| **Five-minute demo** | `scripts/demo.py` | — | Seven recorded-ready scenes, every one a live scan through the real pipeline |

### The five-minute demo (`scripts/demo.py`)

1. **Benign content passes** — a quarterly-report summary → `allow`.
2. **Mixed input sanitized** — attack spans redacted, the benign sentence visibly preserved and spotlighted.
3. **Encoded attack blocked** — base64-obfuscated instruction caught through decoding views.
4. **Hidden-content attack blocked** — CSS-hidden `display:none` instruction caught by forensics.
5. **Detonation chamber** — a gray-band case gets a behavioral verdict (canary leak observed).
6. **Output-side leak guard** — a leaking tool result is withheld before it reaches the agent.
7. **Taint gate** — a destination URL planted by retrieved content is denied at tool-call time.

The same scenarios run from the browser via `UI_AI_Replica/server.py`.

## Quick start

### Windows one-click

```bat
RUN.bat
```

Starts all three components (API :8000, admin portal :8081, chat replica :8080), kills anything already on those ports, and opens each UI in the browser. Close the three server windows to stop.

### Manual (any OS, Python ≥ 3.11)

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev,ocr,forensics]"     # POSIX: .venv/bin/python
.venv/Scripts/python scripts/train_classifier.py --data data/processed/eval_full.jsonl
.venv/Scripts/python scripts/main.py --init-token                 # creates .pif-token (0600)
.venv/Scripts/python scripts/main.py                              # API on 127.0.0.1:8000
.venv/Scripts/python UI_PIF/pif_portal.py                         # portal on 127.0.0.1:8081
.venv/Scripts/python UI_AI_Replica/server.py                      # chat replica on 127.0.0.1:8080
.venv/Scripts/python scripts/demo.py                              # five-minute demo
```

OCR needs the Tesseract executable on PATH (the Docker image ships it).

### Docker

```bash
docker build -t pif .
docker run -p 8080:8080 pif
```

Non-root user, Tesseract included (OCR works out of the box), health check on `/health`, `PIF_HOST=0.0.0.0` — put your own auth in front for anything beyond loopback.

### Optional AI layers

Set `OPENAI_API_KEY` (and optionally `PIF_DETONATION_SECRET`) before starting to enable the gray-band LLM judge and the LLM detonation decoy. Without a key both degrade to off automatically — documented, fail-closed, never fabricated.

## API contract

```http
POST /v1/scan
Authorization: Bearer <token>          # .pif-token or PIF_API_TOKEN
x-pif-trace-id: <uuid>                 # optional, propagated everywhere

{
  "prompt": "user text …",
  "session_id": "uuid-or-null",
  "content": [
    {"source": "web", "text": "retrieved page text …"},
    {"source": "file", "name": "invoice.pdf", "type": "application/pdf",
     "data_base64": "…"}
  ]
}
```

Response (abridged):

```json
{
  "status": "ok",
  "malicious": true,
  "risk": 0.93,
  "decision": "block",
  "attacks": ["indirect_injection", "encoded_instruction"],
  "findings": [ … redacted evidence spans … ],
  "warnings": [],
  "safe_content": null,
  "risk_correlation": { "per-category factor contributions" },
  "coverage": { "what was actually inspected" },
  "session_id": "…"
}
```

Rules of the contract: risk is **not** a calibrated probability; incomplete inspection blocks with no safe content; `risk_correlation` explains *why* (per-category contributions); `coverage` discloses what was and wasn't inspected. `GET /health` and `GET /ready` for orchestration; `DELETE /v1/sessions/{id}` resets a session's context and risk decay.

`sample_clean_and_infected_files/` ships ready-made clean/infected pairs (PDF, DOCX, email, HTML, Markdown, JSON, code, images) and pre-built request JSONs under `requests/` for immediate API testing; `checksums.json` pins their integrity.

## Configuration

| File / variable | Role |
| --- | --- |
| `conf/pif.ini` | runtime settings: limits, thresholds, OCR, sessions, concurrency, quarantine, report DB, logging |
| `conf/policy.ini` | thresholds, action toggles, engine toggles, `[llm_judge]`, `[detonation]`, per-rule overrides, custom rules — **hot-reloaded every scan**; managed only through `scripts/policy.py` |
| `conf/thresholds.json` | calibrated threshold output of `scripts/calibrate.py` |
| `conf/reporting.ini` | reporting behavior |
| `.env` (see `.env.example`) | `PIF_PORT`, `PIF_API_TOKEN`, `PIF_RULES_ONLY`, `PIF_LOG_*`, `PIF_POLICY_FILE`, `PIF_QUARANTINE_DIR`, `PIF_REPORT_DB_PATH`, `PIF_OCR`, `PIF_PORTAL_PORT`, `PIF_URL` |

There is no automatic `.env` loading — export before starting. The admin portal's **Settings** page surfaces all 57 configurable values with documentation, source badge and how a change applies (policy groups hot-reload; core groups need an API restart). The API token is write-only; INI comments are preserved on edit.

## Testing, CI and evaluation integrity

```bash
python -m pytest                          # unit + integration suite
python scripts/evaluate.py                # frozen-corpus regression + release gates
python scripts/build_public_eval.py       # 5 frozen public datasets (the headline)
python scripts/ablation.py                # layer ablation table
python scripts/calibrate.py               # threshold sweep -> conf/thresholds.json
python -m pif.agenticai_redteam --tune    # FP-direction self-tuning
python -m pif.agenticai_redteam --probe   # FN-direction probe (mutations)
python -m pif.agenticai_redteam --approve CAND-0001   # human gate
```

CI (`.github/workflows/ci.yml`) on every push/PR:

1. test suite, 2. frozen-corpus regression replay, 3. **release gate** (recall ≥ 0.95 and FPR ≤ 0.02 on the internal frozen corpus, dataset-size gate), 4. Docker build + container smoke test on `/health`.

Evaluation integrity: training uses only `train` splits (family leakage rejected); thresholds calibrated on train with an FPR ceiling; public splits sha256-frozen (`freeze_manifest` in the report) and replayed verbatim; every build ships its false positives and false negatives in `reports/evaluation_negatives.json`; the detonation/judge layers can never lower a deterministic decision and both fail closed.

## Security posture and limitations

**Fail closed, everywhere.** Oversized, ambiguous or failed content is blocked, never silently marked inspected. Resource limits: 10 MiB total decoded files, 100 PDF pages, 50 MiB uncompressed DOCX, 100:1 ZIP expansion, depth-two attachments, 20M image pixels, 250,000 aggregate characters; parsers run in a two-slot subprocess gate with a 20-second deadline — **not OS memory sandboxes**.

**Loopback by default.** The API binds `127.0.0.1` (container: `0.0.0.0` behind your own auth). Guards must be wired by the host application via `pif/guards.py`.

**Logging.** Per-event JSON (`logs/pif.log`) + human narrative (`logs/PIL_SMOD.log`), rotated 10 MiB × 5; content previews opt-in (`PIF_LOG_CONTENT=1`) and bounded; tokens, credentials and session IDs redacted.

**Explicit limitations** (also the honest boundary of the D1 declaration):

- Independent recall is 0.776 with the behavioral layer at 8.6% benign FPR — real but not elite; the deepset labeling-scope gap and NotInject trigger FPR are published, not explained away.
- The classifier is discriminative TF-IDF+LogReg over a small corpus; the offline detonation emulator is directive-pattern-based — the LLM decoy/judge extend both to paraphrases when a key is configured.
- In-memory single-process sessions; SQLite single-node reports; loopback default.
- Arbitrary encryption without a key is out of scope; encoding alone is not an attack.

## Repository layout

```
pif/                  detection, policy, risk fusion, forensics, guards, detonation,
                      judge, fetch, sessions, quarantine, reporting, settings
pif/input/            format identification, parsers (pdf/docx/html/md/email/json/
                      image/text), OCR, ZIP sandbox
scripts/              main / call / demo / guard_demo / train / evaluate /
                      build_public_eval / ablation / calibrate / generate_corpus /
                      generate_fixtures / policy / rule_analytics / run_examples
UI_PIF/               admin portal (telemetry, history, rules, playground, agent gate, settings)
UI_AI_Replica/        saved ChatGPT / Gemini / GenWizard pages proxied through the PIF API
conf/                 pif.ini, policy.ini (hot-reloaded), thresholds.json, reporting.ini
models/               checksummed classifier artifact + manifest
data/training/        training corpus
data/processed/       eval_full.jsonl, frozen_v6.jsonl (regression)
data/eval/public/     sha256-frozen public-dataset splits
reports/              evaluation.json (+ provenance breakdown), evaluation_public.json
                      (+ freeze manifest + misses), ablation.json, negatives,
                      redteam memory / pending overrides / scheduler
sample_clean_and_infected_files/  clean/infected fixture pairs + ready-made API requests
tests/                unit + integration suite (executed in CI)
RUN.bat               one-click Windows launcher (API + portal + replica)
Dockerfile            non-root image with Tesseract
FLOW_DIAGRAM.md       complete flow documentation (system map → micro-flows with examples)
```

## Provenance and prior art (disclosure)

Mechanisms adopted after studying peer submissions are disclosed here; each is integrated into this codebase's architecture, not vendored:

| Mechanism | Adopted from | Where it lives here |
| --- | --- | --- |
| Per-character PDF hidden-text triage | SiddharthBhaduka18 | `pif/input/parsers/pdf.py` |
| DOCX run-level vanish/tiny/white flags | SiddharthBhaduka18 | `pif/input/parsers/docx.py` |
| Two-pass faint-text OCR | SiddharthBhaduka18 | `pif/input/ocr.py` |
| Sanitize escalation + survivor spotlighting | SiddharthBhaduka18 | `pif/policy.py` |
| View-differential encoding evidence | Nilaksh-MIB `ObfuscationDetector.cs` | `pif/detection/encoded.py` |
| Escalation-only fail-closed AI | Nilaksh-MIB | `pif/detection/llm_judge.py` |
| Canary detonation | Shivamjohri247 `detonator.py` | `pif/detonation.py` (offline emulator decoy + full-band operation added here) |
| DNS-rebinding-safe URL pinning | Shivamjohri247 `main.py` | `pif/fetch.py` |
| Public dataset IDs & split discipline | Shivamjohri247 `backend/eval/build_sets.py` | `scripts/build_public_eval.py` |
| Hiding bonus + matched-twin benchmark design | stas4000 | `pif/risk.py`, `scripts/generate_corpus.py` |
| Conservative normalization + quoted-instruction revocation | saidhinu | `pif/normalization.py`, `pif/detection/rules.py` |

Original to this codebase: the explainable risk-fusion model, the span-redaction policy engine, the supervised self-tuning loop + FN probe driver with human gates, the admin portal + AI-replica demo proxy, the output-side leak guard, the offline detonation emulator, and the full observability stack.

## Mapping to the hackathon evaluation framework

| Rubric parameter | Where PIF evidences it |
| --- | --- |
| Significance & relevance | Prompt injection is the named cybersecurity problem of the agentic era; PIF addresses it end-to-end (content, actions, outputs) |
| Innovation & originality | Behavioral detonation chamber (verdict from what content *does*, not what it says), view-differential encoding evidence, taint-tracked tool gating, span-redaction that preserves benign sentences |
| Effective use of AI | Calibrated ML classifier, optional LLM judge and LLM decoy — escalation-only and fail-closed so AI strengthens rather than becomes the single point of failure |
| Technical complexity & execution | 8-phase pipeline, sandboxed multimodal forensics, 5 frozen public datasets, ablation, calibration, CI release gates |
| Agentic / autonomous capability | Supervised self-tuning agent (perceive → plan → act → verify on shadow firewalls) with an explicit human approve/reject gate; scheduled nightly cycles that skip when inputs are unchanged |
| Business / user impact | Drops-in as a proxy/library for any LLM app; blocks exfiltration and unauthorized tool use while preserving benign content — measurable risk reduction with published FPR |
| Prototype quality & usability | One-click `RUN.bat`, three UIs, five-minute scripted demo, ready-made clean/infected fixtures, `/docs` OpenAPI |
| Scalability, Responsible AI & robustness | Concurrent scan/parser workers, loopback auth posture, quarantine + audit DB, redacted bounded logs, published misses, honest limitations, human-in-the-loop policy changes |

**Final submission components:** the working demo is `scripts/demo.py` (+ `UI_AI_Replica` and the admin portal for the browser walkthrough); the detailed structural architecture is [FLOW_DIAGRAM.md](FLOW_DIAGRAM.md) — process flow, key actions, decisions, model usage, and feature incorporation, phase by phase.
