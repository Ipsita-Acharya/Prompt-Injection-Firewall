# Prompt Injection Firewall (PIF) v6.2

A working, local prompt-injection firewall for AI agents: it inspects every piece of
content before it reaches the model, detects and neutralizes the nine attack classes
of the hackathon problem statement, and gates agent tool calls. 250 tests pass out
of the box (`python -m pytest`, ~55 s).

**Declared grid position: F3 × D1** — see [Grid declaration](#grid-declaration-f3--d1).

---

## Measured on attacks we did not write (the headline)

5 public datasets — **849 rows, sha256-frozen splits** (`data/eval/public/`, manifest
in the report) the rules were never trained or authored against. Every number below
is reproducible: `python scripts/build_public_eval.py` (cached rows replay verbatim)
and `python scripts/ablation.py`.

| Dataset | Rows | Recall | Benign FPR |
| --- | ---: | ---: | ---: |
| Lakera/gandalf_ignore_instructions | 100 | **0.880** | — |
| microsoft/llmail-inject-challenge (indirect, email channel) | 258 | 0.209 | — |
| deepset/prompt-injections | 116 | 0.350 | 0.000 |
| jackhhao/jailbreak-classification | 262 | 0.691 | 0.098 |
| leolee99/NotInject (benign trigger-heavy, FPR metric) | 113 | — | 0.115 |
| **Aggregate** | **557 attacks / 292 benign** | **0.465 deterministic → 0.776 with behavioral layer** | **0.086 (flat)** |

### Three independent layers, each measured (ablation: `reports/ablation.json`)

| Layer | Mechanism | Independent recall | Independent FPR |
| --- | --- | ---: | ---: |
| 1. Content rules + semantic | 23 rule families + calibrated TF-IDF/LogReg | 0.465 | 0.086 |
| 2. + Behavioral canaries | detonation chamber, full band: a decoy agent holds HMAC canary secrets and fake tools; the verdict is what the content *does* (leaks, tool fires, memory writes) — inherently paraphrase-resistant | **0.776** (+31 pts) | 0.086 (flat) |
| 3. + Action-time taint | tool arguments traced to untrusted content; destinations planted by retrieved pages are denied regardless of wording | structural (no public dataset exercises live tool calls — unit-tested, see `scripts/demo.py` scene 7) |

The gray-band LLM judge ships enabled with a documented no-key degraded mode
(self-disables without `OPENAI_API_KEY`); the ablation harness has a third column
ready for it — run with a key and `reports/ablation.json` fills it in. It is not
counted in any number above.

### What the numbers honestly say

- gandalf (0.880) is the strongest independent result; the behavioral layer
  contributes +31 recall points at **flat** FPR — it catches directive-shaped
  attacks the text rules miss, and benign rows simply don't direct the decoy to
  leak anything.
- deepset recall (0.350) is capped by a **labeling-scope difference**: deepset
  counts in-context roleplay and out-of-context harmful requests as injections;
  this firewall requires attack evidence in the text itself. The number is
  published as-is, with every miss listed in `reports/evaluation_public_misses.json`.
- NotInject FPR (0.115) is measured on benign prompts stuffed with trigger words —
  our worst honest number, published for exactly that reason.
- The internal matched-twin corpus (recall 0.971, FPR 0.000, CI-gated in
  `reports/evaluation.json`) is a **regression suite**, not generalization
  evidence — its provenance breakdown labels the self-authored groups "circular
  by construction".

## Grid declaration (F3 × D1)

The rubric makes this declaration mandatory; over-claiming is penalized.

**F3 — 9/9 attack types with first-class detectors** (rule/semantic/context layers,
each with named evidence):

| Attack type | Where |
| --- | --- |
| Instruction override | `pif/detection/rules.py` RULE-001..023 (incl. non-English, memory-wipe family) |
| Role change | RULE-005/013 |
| Secret extraction | RULE-004/014 |
| Tool abuse | RULE-007/008/015 |
| Credential theft | RULE-006/016 |
| Context poisoning | RULE-009/017/021 |
| Multi-step jailbreak | RULE-010/018 + `pif/detection/context.py` (payload splitting, trigger words, crescendo, decaying session risk) |
| Encoded instruction | `pif/detection/encoded.py` + Unicode-tag/hex/base64/rot13/leet decoding (`pif/normalization.py`), differential view-only evidence |
| Indirect injection | `pif/detection/indirect.py` (IIND-001..004), provenance-gated |

**D1 — claimed.** Multimodal forensics are implemented and tested (hidden-channel
extraction for PDF/DOCX/HTML/images), and independent recall on public data is now
published — but D2's "high demonstrable reliability" bar is not met by 0.776 at
8.6% FPR on 5 datasets, so it is **not claimed**. The path to D2 is the same
frozen-public-split loop with more datasets and the LLM layers measured.

## Architecture (eight checkpoints)

```
content ─► 1 INPUT FORENSICS     format verification + parsers + hidden-content
           │                     extraction (PDF white/2pt/off-page, DOCX vanish
           │                     runs + headers/footers, CSS-hidden HTML, faint OCR)
           ├─► 2 NORMALIZATION   canonicalization + bounded recursive decoding
           ├─► 3 RULES           23 named rule families, per-rule policy overrides
           ├─► 4 SEMANTIC        checksummed TF-IDF+LogReg, PR-calibrated thresholds
           ├─► 5 CONTEXT         cross-turn sequences, splitting, crescendo,
           │                     decaying session risk
           ├─► 6 RISK FUSION     explainable factor fusion + hidden-content bonus
           │                     + detonation chamber (full-band behavioral verdict)
           │                     + gray-band LLM judge (escalation-only, fail-closed)
           ├─► 7 POLICY          allow / sanitize (span redaction + survivor
           │                     spotlighting + >80%-removed escalation) / isolate /
           │                     block; quarantine with sidecars
           └─► 8 ACTION GATES    taint-aware ToolGuard + output-side leak guard
                                 + guarded URL fetch (DNS-rebinding-safe pinning)
```

## Provenance & prior art (disclosure)

Mechanisms adopted after studying peer submissions are disclosed here and in
`v6.0_Fixes.md`; each is integrated into this codebase's architecture, not vendored:

| Mechanism | Adopted from | Where it lives here |
| --- | --- | --- |
| Per-character PDF hidden-text triage | `pif/input/parsers/pdf.py` |
| DOCX run-level vanish/tiny/white flags  | `pif/input/parsers/docx.py` |
| Two-pass faint-text OCR | `pif/input/ocr.py` |
| Sanitize escalation + survivor spotlighting | `pif/policy.py` |
| View-differential encoding evidence | `ObfuscationDetector.cs` | `pif/detection/encoded.py` |
| Escalation-only fail-closed AI | `pif/detection/llm_judge.py` |
| Canary detonation | `detonator.py` | `pif/detonation.py` (offline emulator decoy + full-band operation added here) |
| DNS-rebinding-safe URL pinning | `main.py` | `pif/fetch.py` |
| Public dataset IDs & split discipline |`backend/eval/build_sets.py` | `scripts/build_public_eval.py` |
| Hiding bonus + matched-twin benchmark design | `pif/risk.py`, `scripts/generate_corpus.py` |
| Conservative normalization + quoted-instruction revocation | `pif/normalization.py`, `pif/detection/rules.py` |

Original to this codebase: the explainable risk-fusion model, the span-redaction
policy engine, the supervised self-tuning loop + FN probe driver with human gates,
the admin portal + AI-replica demo proxy, the output-side leak guard, the offline
detonation emulator, and the full observability stack.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev,ocr,forensics]'
.\.venv\Scripts\python.exe scripts\train_classifier.py --data data/processed/eval_full.jsonl
.\.venv\Scripts\python.exe scripts\main.py --init-token
.\.venv\Scripts\python.exe scripts\main.py          # API on 127.0.0.1:8000
.\.venv\Scripts\python.exe scripts\demo.py          # five-minute narrative demo
```

**Docker:** `docker build -t pif . && docker run -p 8080:8080 pif` — non-root, ships
Tesseract (OCR works out of the box in the image), health check on `/health`.

**Settings page** (portal → Configure → Settings): every configurable value in one
place — 57 settings across 11 groups, drawn from `conf/pif.ini`, `conf/policy.ini`
and code defaults, each with documentation, source badge, and how a change applies
(policy groups hot-reload in the running firewall; core groups apply on API
restart). The API token is write-only; values are type-validated before any file is
touched, and INI comments are preserved on edit.

**Five-minute demo** (`scripts/demo.py`, designed to be recorded): benign passes →
mixed input sanitized with the benign sentence visibly preserved and spotlighted →
encoded attack blocked → hidden-CSS attack blocked → the detonation chamber's
behavioral verdict on a gray-band case → a leaking tool result withheld by the
output guard → a planted destination denied by the taint gate. The same scenarios
run from the browser via `UI_AI_Replica/server.py` (hosts saved ChatGPT/Gemini pages
proxied through the PIF API).

## Tests, evaluation, self-tuning

```powershell
python -m pytest                                          # 242 tests
python scripts/evaluate.py                                # frozen-corpus regression + release gates
python scripts/build_public_eval.py                       # 5 frozen public datasets (the headline)
python scripts/ablation.py                                # layer ablation table
python scripts/calibrate.py                               # threshold sweep -> conf/thresholds.json
python -m pif.agenticai_redteam --tune                    # FP-direction self-tuning
python -m pif.agenticai_redteam --probe                   # FN-direction probe (mutations)
python -m pif.agenticai_redteam --approve CAND-0001       # human gate
```

Evaluation integrity: training uses only `train` splits (family leakage rejected);
thresholds are calibrated on train with an FPR ceiling; public splits are
sha256-frozen (`freeze_manifest` in the report) and replayed verbatim; every build's
false positives and false negatives ship in `reports/evaluation_negatives.json`; the
detonation/judge layers can never lower a deterministic decision, and both fail
closed. CI replays tests + frozen corpus + release gates + a container smoke test.

## JSON contract, limits, logging

`POST /v1/scan` requires `Authorization: Bearer <token>`; results carry `status`,
`malicious`, `risk`, `decision`, `attacks`, redacted `findings`, `warnings`,
`safe_content`, `risk_correlation` (per-category factor contributions), `coverage`,
`session_id`. Risk is not a calibrated probability. Incomplete inspection blocks
with no safe content. `GET /health`, `GET /ready`, `DELETE /v1/sessions/{id}`.

Resource limits: 10 MiB total decoded files, 100 PDF pages, 50 MiB uncompressed
DOCX, 100:1 ZIP expansion, depth-two attachments, 20M image pixels, 250,000
aggregate characters; parsers run in a two-slot subprocess gate with a 20-second
deadline and are **not OS memory sandboxes**. Oversized, ambiguous or failed
content is **blocked, never silently marked inspected** — the pipeline fails closed
at every stage (parsers, OCR, judge, detonation, guards).

Logging: per-event JSON (`logs/<component>.log`) + human narrative
(`logs/PIL_SMOD.log`), rotated 10 MiB × 5; content previews opt-in
(`PIF_LOG_CONTENT=1`) and bounded; tokens/credentials/session ids redacted.

## Limitations (explicit)

- Independent recall is 0.776 with the behavioral layer at 8.6% benign FPR — real
  but not elite; the deepset labeling-scope gap and NotInject trigger FPR are
  published, not explained away.
- The classifier is discriminative TF-IDF+LogReg over a small corpus; the offline
  detonation emulator is directive-pattern-based — the LLM decoy/judge extend both
  to paraphrases when a key is configured.
- In-memory single-process sessions; SQLite single-node reports; loopback default.
- No unauthenticated network exposure: the API binds loopback (container: 0.0.0.0
  behind your own auth). Guards must be wired by the host application.
- Arbitrary encryption without a key is out of scope; encoding alone is not an attack.

## Repository layout

```
pif/                  detection, policy, forensics, guards, detonation, judge, fetch
pif/input/            format identification, parsers, OCR
scripts/              train / evaluate / public eval / ablation / calibrate /
                      redteam / demo / serve
conf/                 policy.ini (rules, thresholds, [llm_judge], [detonation])
models/               checksummed classifier artifact + manifest
data/processed/       corpora, frozen_v6.jsonl (regression)
data/eval/public/     sha256-frozen public-dataset splits
reports/              evaluation.json (+ provenance breakdown), evaluation_public.json
                      (+ freeze manifest + misses), ablation.json, negatives, redteam memory
tests/                250 unit + integration tests
v6.0_Fixes.md         the full fix log: weaknesses, adopted mechanisms, lessons
```
