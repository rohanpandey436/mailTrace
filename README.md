# MailTrace

AI-powered email threat detection, geolocation and forensic intelligence, built
for **Smart India Hackathon 2026, problem statement PS 26106** (AICTE Cyber
Security Cell, theme Blockchain & Cybersecurity) by Team CodeVerse.

Give MailTrace a raw email (`.eml` upload or pasted source) and within seconds it
answers the questions an incident responder actually asks:

- **What is it?** One of five categories (Legitimate, Suspicious, Impersonated,
  Phishing, Fraud-Related) with a 0-100 risk score, a severity band and a
  plain-English rationale for every decision.
- **How sure are we?** Dual validation: a deterministic rule engine decides and an
  ML text classifier corroborates; disagreement is surfaced as a finding, never
  hidden.
- **Where did it come from?** The `Received` chain is rebuilt hop by hop, the
  originating IP is selected with a confidence value, and every public hop is
  geolocated (city, country, ISP, ASN) and checked against Tor exit lists,
  DNS blocklists and proxy / VPN / hosting heuristics.
- **Who is behind it?** Attribution as spoofed domain, lookalike domain,
  compromised account or direct attacker infrastructure, with the indicators an
  investigator should pivot on.
- **Have we seen this before?** Indicators (origin IP, sender, domains, URL hosts,
  attachment hashes, subject stems) are correlated across every prior case and
  clustered into campaigns with a merged relationship graph.
- **Can it stand up as evidence?** SHA-256 / MD5 at ingestion, an append-only
  hash-linked chain of custody, and a self-contained forensic report (JSON, HTML
  or PDF) prepared with the electronic-evidence certificate (Section 65B of the
  Indian Evidence Act, inserted by the IT Act 2000) in mind.

It starts with a single `python run.py` inside `backend/` on Windows, macOS or
Linux, needs no external database and no API key, and the **analysis engine** has
a genuine offline mode: with `MAILTRACE_ENABLE_NETWORK=false` every network
enrichment degrades to a valid result marked `source="offline"` and no lookup is
attempted.

**The dashboard is not offline.** `frontend/index.html` loads Tailwind from
`cdn.tailwindcss.com`, Leaflet 1.9.4 and d3 7.9.0 from `cdnjs.cloudflare.com`,
the Inter font from Google Fonts and map tiles from `tile.openstreetmap.org`.
Without internet in the *browser* the page still loads and the API still answers,
but it renders unstyled and the map and graph views do not draw. Plan for that if
the venue Wi-Fi is unreliable, or use the API directly.

Section 9 lists exactly which capabilities are live by default and which are
written but dormant. Read it before demoing.

Engine version: `app.schemas.ENGINE_VERSION` (currently `1.0.0`).

**About the numbers in this file.** Every measured figure below was produced on
2026-09-05 on the development machine (Windows 11, CPython 3.13, the repo's
`.venv`), with the command that produced it named beside it. Nothing is quoted
from an earlier run.

## Contents

1. [PS 26106 requirement mapping](#1-ps-26106-requirement-mapping)
2. [Architecture](#2-architecture)
3. [Directory structure](#3-directory-structure)
4. [Data model overview](#4-data-model-overview)
5. [Scoring and classification policy](#5-scoring-and-classification-policy)
6. [Attribution logic](#6-attribution-logic)
7. [Privacy and chain of custody](#7-privacy-and-chain-of-custody)
8. [Quick start](#8-quick-start)
9. [What is live, and what is dormant](#9-what-is-live-and-what-is-dormant)
10. [Configuration](#10-configuration)
11. [Demo walkthrough](#11-demo-walkthrough)
12. [API reference](#12-api-reference)
13. [Retraining the classifier](#13-retraining-the-classifier)
14. [Running the tests](#14-running-the-tests)
15. [Limitations and honest notes](#15-limitations-and-honest-notes)
16. [Legal note](#16-legal-note)

## 1. PS 26106 requirement mapping

| Requirement area | How MailTrace covers it | Where |
|---|---|---|
| Ingest suspicious emails as raw evidence | Multipart upload of one or many `.eml` / `.txt` files, or pasted RFC 822 source; the exact bytes are hashed and stored once under `<data dir>/evidence/<id>.eml` | `POST /api/analyze`, `POST /api/analyze/raw`, `backend/app/core/parser.py`, `backend/app/database/case_manager.py` |
| Header forensics and origin tracing | Every `Received` hop parsed (hosts, IP, protocol, TLS, timestamp), ordered chronologically, per-hop delay and anomalies (negative delay, private IP, missing TLS, forged order), originating IP with confidence and reasoning, `X-Originating-IP` handling | `backend/app/core/header_analyzer.py`, Trace tab |
| Spoofing detection (SPF / DKIM / DMARC) | `Authentication-Results` parsing plus live SPF evaluation, DKIM signature verification and DMARC policy lookup; relaxed alignment; Return-Path, Reply-To, Message-ID and display-name mismatch checks | `backend/app/core/auth_checker.py`, `backend/app/core/header_analyzer.py` |
| Geolocation and infrastructure intelligence | City / region / country, ISP, organisation, ASN and reverse DNS per public hop; Tor exit, VPN / proxy, hosting-provider, DNSBL, open-relay and botnet heuristics; AbuseIPDB with a key; route drawn on a map | `backend/app/core/geoip_mapper.py`, Leaflet map in the UI |
| Malicious link analysis | URL extraction from text and HTML (anchor text vs. href), lookalike / homoglyph / typosquat / punycode detection, shorteners, IP literals, userinfo tricks, open redirects, obfuscation, suspicious TLDs and keywords, plus an XGBoost link model that can only raise the rule score | `backend/app/core/link_analyzer.py`, `backend/app/ai/url_model.py` |
| Attachment analysis | Magic-byte sniffing against the declared type, double extensions, executables, macro documents, archives with risky members, password-protected archives, Shannon entropy, hashes | `backend/app/core/file_analyzer.py` |
| Domain intelligence | WHOIS age and registrar, DNS (A / MX / NS / SPF / DMARC), free-mail and disposable detection, lookalike-of-brand, abuse-prone TLD tagging. **URLhaus reputation is skipped unless `MAILTRACE_URLHAUS_KEY` is set** - abuse.ch has required an Auth-Key since 2025 and `domain_reputation` returns before making any request without one | `backend/app/core/domain_intel.py` |
| NLP and social-engineering analysis | Urgency, fear, authority, secrecy, reward and scarcity lexicons; credential and financial terms; generic greeting; "reply, do not click" pattern; BEC patterns (payment diversion, fake invoice, credential harvesting, executive impersonation) with confidence and evidence phrases | `backend/app/core/ai_engine.py` |
| AI classification with explainability | TF-IDF (word and character n-grams) with logistic regression over a labelled seed corpus; per-class probabilities, exact SHAP token attributions and a second, independent LIME explanation with its surrogate R^2; optional DistilRoBERTa backend | `backend/app/ai/model_trainer.py`, `backend/app/ai/lime_explainer.py`, `backend/app/ai/seed_corpus.json` |
| Risk scoring and dual validation | Five weighted component scores; deterministic first-match policy; ML corroboration modulates confidence; per-category floors; every step written to `verdict.rationale` | `backend/app/core/scoring.py` |
| Source attribution | Spoofed domain / lookalike domain / compromised account / direct attacker infrastructure / legitimate sender, with confidence, reasoning and pivot indicators | `scoring.attribute_source` |
| Threat-intel correlation and campaign detection | Normalised IOC keys per email, overlap search across all prior cases, automatic campaign creation and merging, shared-indicator pivots | `backend/app/core/threat_intel.py` |
| Relationship graph | Email, address, domain, IP, ASN, URL, attachment and campaign nodes with typed edges; merged per campaign | `backend/app/core/graph_builder.py`, `GET /api/graph` |
| Forensic reporting and chain of custody | Hash-linked custody ledger (`ingested`, `analyzed`, `viewed_unmasked`, `exported`, `report_generated`), ledger verification, JSON / HTML / PDF report with evidence integrity, timeline, IOCs, actions and legal notes | `backend/app/database/case_manager.py`, `backend/app/utils/pdf_generator.py`, `/api/reports`, `/api/custody` |
| Privacy | PII masking (addresses, names, phone numbers, Aadhaar, PAN, card numbers) on every API representation, configurable default, unmasked views recorded in custody | `backend/app/utils/pii_masker.py`, `?mask=` |
| Real-time alerting and dashboard | Alerts above a configurable risk threshold pushed to the browser over a WebSocket (with a Server-Sent-Events fallback) and as JSON webhooks to a SIEM or Slack; KPI dashboard, filterable case list, campaign views | `backend/app/api/alerts.py`, `frontend/index.html` |
| Output and act | CSV export of one case's report or of the whole filtered case list (every cell guarded against spreadsheet formula injection); quarantine / block decisions recorded in the custody ledger with the IOCs to hand to whatever enforces | `backend/app/utils/csv_exporter.py`, `backend/app/api/analyze.py` |

### Stage-by-stage compliance

The pitch deck describes the engine as five stages. Each is implemented as
follows, with a measurement taken in this pass to back it. Every "Measured"
cell was produced offline (`enable_network=False`) with
`org_domains=["acme-corp.in"]` and `sarthak srivastava` among the executives -
the configuration `deploy/.env.example` ships.

| Stage | Specified | Implementation | Measured (2026-09-05, this machine) |
|---|---|---|---|
| 1-2 | Native ingestion, sub-30 ms parse, headers/body/attachments separated | `parser.parse_email` times itself into `ParsedEmail.parse_ms` | 1.2-3.1 ms across the five samples (best of five repeats each), 10-25x headroom |
| 3A | DistilRoBERTa NLP intent, Shannon entropy > 7.0, SHAP token weights | Linear classifier with **exact** SHAP by default plus a from-scratch LIME; DistilRoBERTa behind `MAILTRACE_TRANSFORMER_MODEL` (dormant, see section 9); `attachments.shannon_entropy` against `Settings.entropy_threshold` | `python -m app.ai.model_trainer`: SHAP additivity residual 4.885e-15 over 34,643 features; `claim_form.pdf.exe` reads 7.90 bits/byte and trips `high_entropy` |
| 3B | Header chain, MaxMind DB, hop latency, time-delta anomalies, VPN/TOR | `geoip.maxmind_lookup` preferred when a `.mmdb` is configured (dormant - no database file ships), ip-api fallback; per-hop `delay_seconds` and anomaly flags | The `negative_delay` anomaly fires on hop 2 of the phishing sample; origin `45.148.10.72` selected at confidence 0.9 |
| 3C | WHOIS age, DNS/MX alignment, lookalike detection, blacklists | `domains.py` (WHOIS over port 43, dnspython, `is_lookalike`), Spamhaus and five other DNSBL zones; URLhaus needs a key | Offline: `sbi-kyc-update.xyz` is flagged an `extra_token` imitation of `sbi` and `acme-corp-in.com` of `acme-corp.in`. WHOIS/DNS ages need the network and were **not** measured in this pass |
| 4 | Calibrated 0-100 across 5 pillars with an explicit weighted formula | `RiskBreakdown.auth/text/url/network/entropy` at 0.20/0.35/0.25/0.10/0.10, normalised from `MAILTRACE_WEIGHT_AUTH/_TEXT/_URL/_NETWORK/_ENTROPY` | Sample verdicts **83 / 72 / 60 / 45 / 4** (phishing / BEC / lottery / CEO / GitHub) - see the note below |
| 5A | SimHash / TLSH fuzzy hashing for campaign grouping | Charikar SimHash in `parser.py`, TLSH when py-tlsh is present (dormant), distance matching in `campaigns.py` | The ten unrelated sample-body pairs sit at Hamming distance 20-35, twice the code's 10-bit clustering threshold (`deploy/.env.example` tightens it to 6) |
| 5B | Webhook alerts, Section 65B legal PDF with SHA-256 custody | `alerts.deliver_webhooks`, `reporting.render_pdf`, `Section65BCertificate` with clauses (a)-(d) | `render_pdf` on the phishing case: 15 pages, 41,997 bytes. The webhook path has no automated test and was not exercised in this pass |
| 5C | PII masking, stateless zero-persistence | `privacy.mask_result`, `Store(..., in_memory=True)` via `MAILTRACE_ZERO_PERSISTENCE` | No `mailtrace.db` and no `evidence/` directory is created. The classifier caches (`model.joblib`, `url_model.joblib`) **are** still written under the data directory |

**Those five verdicts are first-ingest-on-a-clean-store figures.** They were
taken by analysing each sample once against an empty database. Re-uploading a
message into a store that already holds it raises the score, because the copy
shares `ip:`, `sender:` and `domain:` indicators with the original and the
resulting `known_campaign_overlap` finding lifts the network pillar. Measured:
the phishing sample goes 83 -> 87 (network pillar 35.0 -> 76.7) and the BEC
sample 72 -> 79 on a second upload. If your demo numbers are higher than the
table, that is why - delete the data directory for a clean slate.

**On the deck's scoring slide.** The deck reads
`0.20 Auth + 0.35 Text + 0.25 URL + 0.10 Net + 0.10 Entropy`, and that is
exactly what the code computes: `config.DEFAULT_WEIGHTS` carries those five
weights and `scoring.component_scores` returns a `RiskBreakdown` with the
fields `auth`, `text`, `url`, `network` and `entropy`. There is no deviation to
declare. (An earlier build scored a different five - AI, Authentication,
GeoIP/Route, Domain, Threat Intel - and earlier revisions of this README
described that. Those fields no longer exist; threat-intelligence hits are now
folded into the network term and the AI signal into the text term.)

## 2. Architecture

```
                 .eml files / pasted source                    analyst browser
                          |                                  (frontend/index.html)
                          v                                     ^           ^
   +----------------------+-------------------------------------+-----------+------+
   |  FastAPI  backend/app/main.py + app/api/*    JSON / HTML    | WS + SSE alerts  |
   |  /api/analyze  /api/emails  /api/campaigns  /api/graph  /api/reports  /api/... |
   +----------------------+---------------------------------------------------------+
                          |  run_in_threadpool (one message at a time per request)
                          v
   +----------------------+---------------------------------------------------------+
   |  backend/app/core/pipeline.py                                                |
   |                                                                                |
   |  1 parser -> 2 headers -> 3 auth -> 4 urls (link extraction)                    |
   |     -> 5 three engines concurrently:  3A attachments+nlp(+ML)                   |
   |                                       3B geoip                                  |
   |                                       3C domains                                |
   |     -> 6 campaigns.correlate -> 7 scoring -> 8 graph -> 9 persist               |
   +-------------+------------------------------------------------+-----------------+
                 |                                                |
                 v                                                v
   +-------------+--------------------+       +-------------------+-----------------+
   |  backend/app/database/case_manager.py  SQLite (WAL) |       |  live enrichment (optional)         |
   |  emails, indicators, campaigns   |       |  DNS (dnspython)   WHOIS (sockets)  |
   |  custody ledger, alerts, cache   |       |  ip-api.com   Tor exit list   DNSBL |
   |  <data dir>/evidence/<id>.eml    |       |  AbuseIPDB / URLhaus / VT (keys)    |
   +----------------------------------+       +-------------------------------------+
```

### What the "AI" actually is, and why word lists sit next to it

Two independent judges look at every email, and the disagreement between them is
a feature rather than a bug.

**1. A trained machine-learning model** (`backend/app/ai/model_trainer.py`). Text is
turned into numbers with TF-IDF over word pairs and character triples, and a
multinomial logistic-regression classifier assigns one of the five categories. It
is trained on this machine the first time the server starts, from the **249
labelled emails** in `backend/app/ai/seed_corpus.json`, and cached to
`<data dir>/model.joblib`. Nothing is downloaded and no API is called. Measured
in this pass with `python -m app.ai.model_trainer` on a 20% stratified hold-out the
model never sees during training:

| Class | Precision | Recall |
|---|---|---|
| Phishing | 1.00 | 1.00 |
| Fraud-Related | 1.00 | 0.90 |
| Legitimate | 0.90 | 0.90 |
| Impersonated | 0.82 | 0.90 |
| Suspicious | 0.80 | 0.80 |

Overall accuracy is **0.900**. Reproduce it any time with
`cd backend && python -m app.ai.model_trainer`.

Every prediction carries **exact SHAP values**. For a linear model the Shapley
value of a feature is `phi_i = coef_i * (x_i - E[x_i])`, where the expectation is
the mean feature value over the training corpus, which is stored alongside the
model. That decomposition is exact rather than approximate: the same training run
reports that summing all **34,643** contributions reproduces the classifier's own
decision function to a residual of **4.885e-15**, which is float64 rounding
noise. Negative contributions are kept, so the dashboard can show that "verify"
and "login" argued *against* Impersonated and *toward* Phishing, which a plain
coefficient-times-feature view cannot express.

Beside SHAP the linear backend also fits **LIME**
(`backend/app/ai/lime_explainer.py`, a from-scratch implementation - the `lime`
package is an sdist-only build that drags in matplotlib and scikit-image). Where
SHAP reads the coefficients in closed form, LIME perturbs the message and fits a
local weighted surrogate to what the whole pipeline actually does, reporting its
R^2 as `lime_fidelity` so a reader can tell when not to trust it. **LIME is on by
default and it is the dominant cost in the pipeline**: measured this pass, 500
sequential ingestions take 83.2 s with it and 40.3 s with
`MAILTRACE_LIME=0`. See [`docs/scaling.md`](docs/scaling.md) for the full
figures.

A **DistilRoBERTa** backend is implemented and guarded behind
`MAILTRACE_TRANSFORMER_MODEL`. It is off by default because `torch` is roughly a
gigabyte and the free tier the public demo runs on has 512 MB of RAM. With the
optional packages in `backend/requirements-ml.txt` installed and a model id
configured, the transformer takes over and the linear model becomes the fallback;
token attributions there come from occlusion, and are labelled as such rather
than being called SHAP, and LIME is skipped entirely.

**2. A rule engine** (`backend/app/core/ai_engine.py`, `scoring.py` and friends).
This is where the keyword lists live. They are deliberately not the model, for
three reasons:

- **Authentication cannot be guessed from wording.** SPF, DKIM, DMARC, a forged
  Received chain or a lookalike domain are facts to be checked, not text to be
  classified. Most of the engine is this kind of protocol analysis.
- **A model trained on 249 examples is small.** Honest models of this size
  generalise poorly to wording they have never seen. The rules provide a floor:
  a message demanding an OTP through a copycat domain is caught even if the
  phrasing is novel.
- **A verdict has to be explainable.** A court or an incident report needs "SPF
  failed for this domain and the reply address differs", not "the model output
  0.83". Every finding therefore names the exact evidence behind it.

The rule engine decides the final category; the model modulates the confidence.
When both agree, confidence rises. When they disagree, MailTrace lowers the
confidence and says so on screen rather than hiding it, which is what the
`dual_validation_agreement` flag records. The SBI sample is a live example,
measured this pass: the rules say Phishing, the model says Impersonated at
p=0.52, and the verdict is reported at **0.70** confidence with a
`dual_validation_disagreement` finding.

Scaling up is a matter of data, not architecture. Point
`python -m app.ai.model_trainer --csv your_data.csv` at a larger labelled corpus and the
same pipeline retrains, with the rules unchanged underneath.

### Pipeline order (`backend/app/core/pipeline.py`)

1. `parser.parse_email` - structure, bodies, attachment bytes, raw SHA-256 / MD5,
   SimHash (and TLSH when py-tlsh is installed)
2. `headers.analyze_headers` - Received chain, origin selection with confidence,
   forged-field checks
3. `auth.evaluate_auth` - SPF / DKIM / DMARC from `Authentication-Results` plus
   live lookups; its findings are merged into the header analysis
4. `urls.analyze_urls` then `domains.collect_domains` - **link extraction runs on
   its own, before the engines**, because it is cheap, offline, and a
   prerequisite of two of the three: the AI core scores the lure links and the
   domain engine enriches the hosts they point at
5. **Three intelligence engines, genuinely concurrent** in a
   `ThreadPoolExecutor(max_workers=3)`. 3A is CPU-bound while 3B and 3C mostly
   wait on the network, so overlapping them turns the sum of their times into
   roughly the slowest one. Each is wrapped so a failure degrades that engine's
   contribution and never aborts the analysis:
   - **3A, the AI core** - `attachments.analyze_attachments` (magic bytes,
     archives, Shannon entropy), then `nlp.analyze_content` (lexicons, BEC
     patterns, the ML classification, SHAP and LIME) which consumes the
     attachment report, and finally the optional VirusTotal hash lookup, placed
     last so a network stall can only delay the attachment findings and never the
     NLP verdict
   - **3B, GeoIP / route** - `geoip.analyze_infrastructure`: origin geolocation,
     reverse DNS, Tor exit list, DNSBL, VPN / proxy / hosting flags
   - **3C, domain intel** - `domains.analyze_domains`: WHOIS age, DNS posture,
     lookalike detection, reputation tags
6. `campaigns.correlate` - normalised indicators, prior-incident overlap, fuzzy
   digest matching
7. `scoring.evaluate` - the five component scores, the rule verdict, dual
   validation, attribution, merged findings
8. `graph.build_graph` - relationship graph
9. Persist: `ingested` custody event, campaign assignment, `save_analysis`,
   `analyzed` custody event. Skipped entirely when `store is None`, which is how
   the tests and the benchmarks run.

### Data flow

- The API layer is deliberately thin: validate the request, run `analyze_bytes` in a
  worker thread, raise an alert if warranted, mask PII if requested, return the
  `AnalysisResult` or a projection of it.
- `AnalysisResult` is the only persisted analysis artefact (`emails.result_json`);
  case lists, campaign views, graphs and reports are all projections of it, so the
  UI and the report can never disagree.
- Custody rows are written by the pipeline (`ingested`, `analyzed`) and by the API
  (`viewed_unmasked`, `exported`, `report_generated`, decisions); nothing updates
  or deletes a custody row.
- Alerts: pipeline result -> `maybe_alert` -> SQLite + `Broadcaster.publish` ->
  `loop.call_soon_threadsafe` -> each WebSocket / SSE subscriber queue -> browser
  bell and toast.

### Why FastAPI, SQLite and scikit-learn

- **FastAPI**: the pydantic v2 models in `backend/app/schemas.py` are both the
  internal contract and the API schema, OpenAPI docs come for free at `/docs`, and
  async I/O serves the alert stream while the synchronous engine runs in a thread pool.
- **SQLite** (WAL mode, one file): zero setup for judges and analysts, transactional,
  trivially handed over as part of an evidence bundle. An investigation workstation
  should not depend on a database server. An optional PostgreSQL adapter exists;
  see section 9.
- **scikit-learn**: trains in seconds on a CPU, is deterministic, and admits an
  exact SHAP decomposition rather than an approximation, so every verdict can be
  traced to individual tokens. It needs no GPU, ONNX runtime or model download.
  The rule engine, not the model, makes the final call, so the model can stay
  small and auditable.

### Why no bundled GeoIP database

Commercial GeoIP databases require a licence key, periodic downloads and hundreds
of megabytes. MailTrace queries `ip-api.com` at analysis time (city, ISP, ASN,
proxy and hosting flags), caches every answer in SQLite for
`MAILTRACE_CACHE_TTL_SECONDS`, and complements it with reverse DNS, the live Tor
exit list, DNSBL zones and optional AbuseIPDB. The `maxminddb` reader **is**
installed (it is in `backend/requirements.txt`) and is preferred whenever
`MAILTRACE_MAXMIND_DB` points at a `.mmdb` file - but no such file ships, so that
path is dormant until you supply one. With `MAILTRACE_ENABLE_NETWORK=false` each
enrichment returns a valid object marked `source="offline"` and every other stage
is unaffected.

## 3. Directory structure

The Python service moved into `backend/` and the dashboard into `frontend/`.
`render.yaml` stays at the repository root because Render only reads a Blueprint
from there; it sets `rootDir: backend`.

```
mailtrace/
  README.md
  render.yaml               Render Blueprint (must live at the root)
  .dockerignore
  .github/workflows/ci.yml  Python 3.12, import check, pytest
  backend/                  the FastAPI service - run everything from here
    run.py                  uvicorn entry point (python run.py)
    pytest.ini              testpaths = tests, addopts = -q
    requirements.txt        runtime dependencies
    requirements-dev.txt    runtime + pytest
    requirements-ml.txt     OPTIONAL transformers + torch (DistilRoBERTa)
    requirements-pg.txt     OPTIONAL psycopg (PostgreSQL backend)
    app/
      config.py             Settings dataclass; MAILTRACE_* environment / .env loader
      schemas.py            pydantic v2 data contracts (ENGINE_VERSION lives here)
      db.py                 Store: SQLite/PostgreSQL persistence, custody ledger, alerts, cache
      main.py               FastAPI app factory, lifespan, error handlers, index route
      api/
        deps.py             get_store / get_settings / mask_param dependencies
        analyze.py          upload, raw paste, case list, case detail, CSV, raw export,
                            quarantine / block decisions, stats
        cases.py            campaigns and relationship graphs
        reports.py          forensic report (JSON / HTML / PDF / CSV) and custody chain
        alerts.py           alert list / ack, WebSocket + SSE streams, Broadcaster, maybe_alert
      engine/
        pipeline.py         orchestration (order above)
        knowledge.py        brands, free-mail, shorteners, risky extensions, DNSBLs, confusables
        parser.py           RFC 822 / MIME parsing, hashes, SimHash/TLSH, native-engine adapter
        attachments.py      magic sniffing, macro / archive inspection, entropy, attachment risk
        headers.py          Received chain, origin selection, forged-field checks
        auth.py             SPF / DKIM / DMARC (Authentication-Results + live)
        urls.py             URL extraction, lookalike engine, registrable_domain
        domains.py          WHOIS, DNS and reputation per domain
        nlp.py              lexicons, BEC patterns, ML inference, SHAP + LIME wiring
        geoip.py            ip-api, MaxMind, reverse DNS, Tor, DNSBL, AbuseIPDB
        virustotal.py       OPTIONAL VirusTotal v3 hash reputation for attachments
        scoring.py          component scores, rule policy, dual validation, attribution
        graph.py            relationship graph build and merge
        campaigns.py        indicators, correlation, campaign assignment
        privacy.py          PII masking
        reporting.py        forensic report builder, HTML and Section 65B PDF renderers
        csvexport.py        CSV export with formula-injection guards
      ml/
        train.py            build / train / load / predict / explain + CLI
        lime_text.py        from-scratch LIME for the text classifier
        url_model.py        XGBoost URL/domain model (optional at runtime)
        seed_corpus.json    249 labelled seed messages (five classes)
    tests/                  pytest suite (offline); 140 tests, 6 of them skipped without the C++ engine
    data/                   runtime, git-ignored: mailtrace.db, evidence/, model.joblib,
                            url_model.joblib  (the default MAILTRACE_DATA_DIR)
  frontend/
    index.html              single-file analyst UI (Tailwind, Leaflet, d3 - all from CDNs)
  samples/                  five demo messages and their README
  engine/                   OPTIONAL C++20 parse extension - built and benchmarked, see engine/README.md
  deploy/
    Dockerfile              build from the repository root
    .env.example            every configuration key, with demo values
    README.md
  docs/
    scaling.md              Neo4j / Celery design work - designed, not deployed
```

## 4. Data model overview

`AnalysisResult` is produced once per analysed message and is the API's primary
object (`backend/app/schemas.py`):

| Field | Type | Contents |
|---|---|---|
| `id`, `filename`, `analyzed_at`, `engine_version`, `processing_ms`, `masked` | scalars | identity and provenance of the analysis |
| `email` | `ParsedEmail` | message-id, subject, date, sender / reply_to / return_path / to / cc as `AddressInfo`, all headers in original order, text and HTML bodies, attachment metadata, `raw_sha256` / `raw_md5` / `raw_size`, `parse_ms`, `fuzzy` (SimHash / TLSH), mailer |
| `headers` | `HeaderAnalysis` | `hops[]` (`Hop`: hosts, IP, protocol, timestamp, delay, anomalies, `geo`), `originating_ip` with confidence and reasoning, mismatch flags, `auth` (`AuthResult`: SPF / DKIM / DMARC results, sources, policy, alignment), anomaly score, findings |
| `urls` | `UrlAnalysis` | `UrlInfo[]` (host, registrable domain, anchor mismatch, obfuscation, lookalike_of, risk, reasons), unique domains, score |
| `attachments` | `AttachmentAnalysis` | enriched `AttachmentMeta[]` (hashes, magic type, MIME mismatch, macros, archive, double extension, `shannon_entropy`, `high_entropy`, risk), score |
| `nlp` | `NlpAnalysis` | language, urgency score and phrases, social-engineering cues, financial / credential / threat terms, `ml_category`, `ml_probabilities`, `ml_top_terms` (SHAP), LIME weights and `lime_fidelity`, `bec_patterns[]`, score |
| `domains` | `DomainIntel[]` | per domain: role, registrar, created / age, MX / A / NS, SPF and DMARC records, free-mail / disposable, lookalike and technique, reputation, source |
| `infrastructure` | `InfraAnalysis` | `origin_geo` (`GeoInfo`), Tor / VPN-proxy / hosting / blacklisted / open-relay flags, botnet indicators, score |
| `intel` | `ThreatIntel` | normalised indicators, IP blacklists, domain reputation, Tor exits, related incidents, campaign id |
| `attribution` | `Attribution` | `source_type`, confidence, reasoning, pivot indicators |
| `graph` | `AttributionGraph` | typed nodes and edges for the force-directed view |
| `verdict` | `Verdict` | category, confidence, `risk_score`, severity, `breakdown` (`RiskBreakdown`: `auth`, `text`, `url`, `network`, `entropy`, each 0-100, plus the normalised `weights`), `ml_category`, `rule_category`, `dual_validation_agreement`, rationale, recommended actions |
| `findings` | `Finding[]` | every evidence-backed observation from every module, deduplicated and sorted by severity |
| `campaign_id` | string or null | campaign membership |

Projections: `CaseSummary` (case-list rows, stored as indexed columns),
`Campaign`, `CustodyEvent` / `CustodyChain`, `Alert`, `CaseDecision`,
`ForensicReport` (executive summary, key indicators, evidence integrity,
timeline, actions, legal notes, custody, full analysis) and `DashboardStats`.

Storage (`backend/app/database/case_manager.py`): tables `emails` (summary columns plus
`result_json`), `indicators`, `campaigns`, `campaign_members`, `custody`,
`alerts` and `cache`; raw messages under `<data dir>/evidence/<id>.eml`.

## 5. Scoring and classification policy

**The five pillars** (0-100 each, exposed as `verdict.breakdown`). These are the
fields of `RiskBreakdown` and the terms of the deck's threat-score formula; the
table is written from `backend/app/core/scoring.py`:

| Pillar | Default weight | Derived from |
|---|---|---|
| `auth` | 0.20 | `_auth_pillar` = authentication result plus forged sender fields. SPF fail 45 / softfail 25 / none or neutral 15 / unverifiable, temperror, permerror 10; DKIM fail 35 / none 10 / unverifiable 5; DMARC fail 40, or 60 under `p=reject` / none 10; +15 for each of SPF and DKIM misalignment; +20 when any of those failed on a protected or brand domain. Then forged identity: display-name spoof 45, Reply-To mismatch 35, Return-Path mismatch 25, Message-ID mismatch 15 |
| `text` | 0.35 | `_text_score` = `100 x (0.7 x nlp.score + 0.3 x strongest BEC-pattern confidence)`. `nlp.score` blends the classifier's non-legitimate probability mass, urgency, the strongest BEC pattern and cue diversity |
| `url` | 0.25 | `_deterministic_url_score` = `100 x urls.score`, raised to at least 85 for a lookalike domain, 75 under 30 days old, 50 under 90 days, 60 disposable, 70 when a non-free-mail sender domain does not resolve or 40 when it has no MX; link domains from the same table. The XGBoost model may then lift it - `max(floor, floor + (100 - floor) x 0.5 x P(malicious))` - and can never lower it |
| `network` | 0.10 | `_network_score` combines three parts and takes `strongest + 0.2 x mean(other two)`: origin infrastructure (`100 x infra.score`: Tor, VPN/proxy, hosting, blocklisted, open relay, botnet traits); delivery-path anomalies (forged Received order 40, negative hop delta 25, oversized delay 10, plaintext hop 10, HELO mismatch 10, unparseable 5, +20 private-only chain, +25 no chain at all, +10 low origin confidence); and threat-intel hits (Tor exit list 85, IP blocklist 80, infrastructure blocklist 75, prior-incident overlap `40 + 0.4 x worst related risk`) |
| `entropy` | 0.10 | `_entropy_score` = `100 x attachments.score`, raised to at least 90 when an attachment is both high-entropy (above `MAILTRACE_ENTROPY_THRESHOLD`, default 7.0 bits/byte) and rated high or critical |

`risk_score = round(sum(weight x pillar))` (`weighted_risk`). Weights come from
`MAILTRACE_WEIGHT_AUTH`, `_TEXT`, `_URL`, `_NETWORK` and `_ENTROPY` - the loop in
`config.Settings.from_env` builds each name as `"WEIGHT_" + key.upper()` over
`DEFAULT_WEIGHTS`, so no other spelling is read. They are normalised to sum to 1,
so they express relative importance rather than needing to add up by hand.

**Rule policy** (first match wins, recorded as `verdict.rule_category`):

1. **Fraud-Related** - payment-diversion or fake-invoice BEC pattern at confidence
   0.5 or more; or two or more financial terms combined with pressure (Reply-To
   mismatch, free-mail sender or urgency 0.5 or more) at risk 40 or more; or the
   classifier says Fraud-Related (p 0.6 or more) with financial terms; or executive
   impersonation (0.5 or more) paired with a money request. A dominant
   credential-harvesting pattern suppresses the first three, so a KYC lure that
   mentions money is still read as phishing.
2. **Phishing** - credential-harvesting BEC pattern at 0.5 or more; a high-risk
   link alongside credential terms; a `credential_harvest_link` finding; a lookalike
   link with credential terms; the classifier says Phishing (p 0.6 or more) with a
   medium-or-worse link; a critical attachment delivered with a credential lure.
3. **Impersonated** - display-name spoof; executive-impersonation pattern at 0.35
   or more; lookalike sender or Reply-To domain; SPF or DMARC failure on a protected
   or brand domain; the classifier says Impersonated (p 0.6 or more) with any
   authentication failure.
4. **Suspicious** - risk 25 or more, any high or critical finding, or a
   non-legitimate ML class at p 0.6 or more.
5. **Legitimate** otherwise.

**Dual validation** - the rule engine decides and the classifier modulates
confidence: on agreement `confidence = 0.75 + 0.25 x P(rule class)` (capped at
0.98); on disagreement 0.6, plus 0.1 when the risk score supports the rule, plus a
low-severity `dual_validation_disagreement` finding and a rationale line quoting
both views. `verdict.dual_validation_agreement` records the outcome.

**Consistency guards** - risk floors Phishing / Fraud-Related 60, Impersonated 45,
Suspicious 25 (with a `risk_floor_applied` finding when raised); a Legitimate
label is never issued at risk 40 or more (the category becomes Suspicious).
Severity bands: below 25 low, below 50 medium, below 75 high, otherwise critical;
a zero score with no findings is info.

## 6. Attribution logic

Evaluated in order, first hit wins (`attribution.source_type`):

| Source type | When | Confidence |
|---|---|---|
| `legitimate_sender` | the verdict is Legitimate | verdict confidence |
| `lookalike_domain` | the sender or Reply-To domain imitates a brand or protected domain (homoglyph, typosquat, TLD swap, extra token, subdomain abuse, punycode) | 0.8, or 0.9 when registered under 90 days ago |
| `spoofed_domain` | SPF or DMARC failure, or no authentication evidence at all, on an established domain (a year or older, a brand, or the protected organisation) that is not itself a lookalike | 0.75, or 0.85 with a DMARC failure |
| `compromised_account` | SPF and DKIM pass with alignment on a non-free-mail domain, yet the verdict is Phishing, Fraud-Related or Impersonated | 0.7 |
| `direct_attacker_infrastructure` | Tor exit, disposable domain, sender domain under 90 days old, VPN / proxy or hosting-provider origin; or a free-mail mailbox posing as an executive or brand ("throwaway mailbox") | 0.55 - 0.85 |
| `undetermined` | none of the above | 0.3 |

Two of these depend on configuration, which matters when you compare a demo
against this document. `lookalike_domain` and `spoofed_domain` only fire against
a *known* identity - a built-in brand or a domain listed in
`MAILTRACE_ORG_DOMAINS`. Measured this pass: the BEC sample attributes to
`lookalike_domain` when `MAILTRACE_ORG_DOMAINS=acme-corp.in` is configured, and
to `undetermined` with the stock default of `example.org`, because nothing then
knows that `acme-corp-in.com` is imitating anything.

Every attribution lists the pivot indicators (origin IP, ASN / ISP, sender,
Reply-To, URL hosts, attachment hashes) and `verdict.recommended_actions` turns the
verdict into a playbook: block the IOCs, verify bank changes out of band, reset
credentials, preserve the evidence, report to CERT-In and cybercrime.gov.in.

## 7. Privacy and chain of custody

**PII masking** (`backend/app/utils/pii_masker.py`). Email addresses become
`r***n@domain.tld`, names become initials, and phone numbers, Aadhaar numbers, PAN
numbers and Luhn-valid card numbers are masked. Masking is applied to addresses,
header values, bodies, subject, finding details and evidence, graph address nodes
(the node id becomes a hash), indicators and the report narrative. Domains, IPs,
URLs and hashes are deliberately kept intact because they are the investigative
value. `?mask=true|false` on every endpoint that returns analysis data overrides
`MAILTRACE_PII_MASK_DEFAULT` and the UI toggle persists the choice. When masking
is the default and an analyst explicitly requests the unmasked analysis, a
`viewed_unmasked` custody event is written.

**Chain of custody** (`backend/app/database/case_manager.py`). An append-only ledger in which every
row's hash is `sha256(prev_hash | seq | email_id | timestamp | actor | action |
detail_json | evidence_sha256)` (the fields joined with `|`; `detail_json` is the
canonical JSON of the detail dictionary, sorted keys and compact separators,
stored verbatim), with a genesis `prev_hash` of 64 zeros. Recorded actions:
`ingested` (filename, size, SHA-256, MD5), `analyzed` (verdict, engine version,
campaign), `viewed_unmasked`, `exported` (raw `.eml` download),
`report_generated` (format, masked) and the quarantine / block decisions.
`GET /api/custody/verify` recomputes every hash in sequence and returns the ledger
head; any edit to a stored row breaks validation. The forensic report embeds the
raw hashes, the custody head hash and its validity, and records its own generation
event.

## 8. Quick start

Requirements: Python 3.11 or newer and internet access for the first
`pip install`. The classifier is trained from the seed corpus on first start (a
few seconds) and cached in `backend/data/model.joblib`.

**Everything runs from `backend/`.** `run.py`, `requirements.txt` and the `app`
package all live there; the dashboard, the samples and `render.yaml` sit beside
it and are found relative to the package.

Windows PowerShell:

```powershell
cd C:\path\to\mailtrace
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # if blocked: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Copy-Item deploy\.env.example .env  # optional; recommended for the demo (sets the protected organisation)
cd backend
pip install -r requirements.txt
python run.py
```

macOS / Linux:

```bash
cd /path/to/mailtrace
python3 -m venv .venv
source .venv/bin/activate
cp deploy/.env.example .env         # optional
cd backend
pip install -r requirements.txt
python run.py
```

`.env` is read from both the project root and `backend/`, so either location
works; existing environment variables always win.

Open http://127.0.0.1:8000 for the UI or http://127.0.0.1:8000/docs for the
interactive API. Stop with Ctrl+C. Everything the server writes lives under
`backend/data/` (or `MAILTRACE_DATA_DIR`); delete that directory for a clean
slate - which also resets the campaign correlation, so demo scores match the
figures in this README.

Verified in this pass: `python run.py` from `backend/` starts uvicorn,
`GET /api/health` returns
`{"status":"ok","engine_version":"1.0.0", ... ,"database":"sqlite","native_engine":false}`,
`GET /` serves the 77 KB dashboard and `POST /api/analyze` with a sample file
returns a full `AnalysisResult`.

### Showing it on someone else's phone

`127.0.0.1` only works on the machine running the server. To let a judge open the
dashboard on their own phone, put both devices on the same Wi-Fi and bind to
every interface:

```powershell
cd backend
$env:MAILTRACE_HOST="0.0.0.0"; python run.py
```

Startup then prints the address to use, for example
`http://192.168.29.171:8000`. Turn that into a QR code with any generator. The
address changes with the network, so regenerate it at the venue rather than
reusing one made at home.

While bound this way anyone on that network can reach the dashboard, and it has
no login. Use it for the demo and stop the server afterwards.

## 9. What is live, and what is dormant

Some capabilities named in the deck and in this repository are implemented but
switched off, or need something this machine does not have. Nothing below is
vapour - the code exists and is listed - but only the first table runs when you
follow the quick start.

### Live by default

| Capability | Notes |
|---|---|
| RFC 822 / MIME parsing, hashes, SimHash | Pure Python (`backend/app/core/parser.py`) |
| Received-chain forensics, origin selection | Offline |
| SPF / DKIM / DMARC from `Authentication-Results` | Offline; live SPF, DKIM and DMARC lookups when the network is on |
| URL extraction, lookalike / homoglyph / typosquat detection | Offline |
| Attachment magic-byte, macro, archive and entropy analysis | Offline |
| NLP lexicons and BEC patterns | Offline |
| TF-IDF + logistic-regression classifier with exact SHAP | Trained from the 249-message seed corpus on first start |
| LIME second explanation | On by default (`MAILTRACE_LIME=1`); the single largest cost in the pipeline |
| XGBoost URL/domain model | On by default (`MAILTRACE_URL_MODEL=1`); `xgboost` is in `requirements.txt`. Removing it degrades cleanly to the rules |
| Section 65B PDF reporting | `reportlab` is in `requirements.txt` |
| ip-api.com geolocation, reverse DNS, Tor exit list, DNSBL | Live only with `MAILTRACE_ENABLE_NETWORK=true` (the default) |
| WHOIS and DNS domain intelligence | Same |
| SQLite store, custody ledger, campaigns, alerts, WebSocket + SSE | Always |

### Written but dormant

| Capability | Why it is off | What switches it on |
|---|---|---|
| **C++20 parse engine** (`engine/`) | Built and active on the development machine since 2026-09-05; whether it is active anywhere else depends on that host having a compiler at install time. `/api/health` reports `native_engine`, its version and its status, so you never have to guess which parser answered | A C++20 compiler plus `pip install pybind11 && pip install ./engine`. See [`engine/README.md`](engine/README.md). `MAILTRACE_NATIVE_ENGINE=0` forces the Python parser back |
| **DistilRoBERTa NLP backend** | `torch` and `transformers` are not installed and are deliberately absent from `requirements.txt` (torch alone is roughly 1 GB; the free tier has 512 MB) | `pip install -r backend/requirements-ml.txt` and `MAILTRACE_TRANSFORMER_MODEL=<hf-model-id>` |
| **MaxMind GeoLite2** | The `maxminddb` reader is installed, but no `.mmdb` database file ships with the repository | Download GeoLite2-City and set `MAILTRACE_MAXMIND_DB=/path/to/GeoLite2-City.mmdb` |
| **TLSH fuzzy digest** | `py-tlsh` is not installed; only SimHash digests are produced today. `campaigns.py` stores `tlsh:` indicators when they exist | `pip install py-tlsh`; tune with `MAILTRACE_TLSH_MAX_DISTANCE` |
| **PostgreSQL / Supabase store** | `psycopg` is not installed and no URL is set, so the store is the SQLite file. Untested against a real server | `pip install -r backend/requirements-pg.txt` and `MAILTRACE_DATABASE_URL=postgresql://...`. `/api/health` reports which backend won |
| **VirusTotal attachment reputation** | Needs an API key; with none set `virustotal.enrich` makes no request at all | `MAILTRACE_VIRUSTOTAL_KEY=<key>`. Only SHA-256 digests are ever sent |
| **AbuseIPDB IP reputation** | Needs an API key | `MAILTRACE_ABUSEIPDB_KEY=<key>` |
| **URLhaus domain reputation** | Needs an API key. `domains.domain_reputation` returns before the request when `cfg.urlhaus_key` is empty - abuse.ch has required an `Auth-Key` header since 2025 and answers 401 without one | `MAILTRACE_URLHAUS_KEY=<key>` |
| **Outbound alert webhooks** | No URLs configured. The delivery path has no automated test | `MAILTRACE_WEBHOOK_URLS=https://...` |
| **Neo4j graph store** | **Designed only. No code in this repository.** | Nothing yet - see [`docs/scaling.md`](docs/scaling.md) for the full design and its cost |
| **Celery + Redis bulk ingestion** | **Designed only. No code in this repository**, and it needs the PostgreSQL store plus three concurrency fixes first | Same document, section 2 |

## 10. Configuration

All settings are read from environment variables, optionally seeded from a `.env`
file beside the backend or at the project root (existing environment variables
win; list values are comma-separated and lower-cased). Every key is documented
with a comment in `deploy/.env.example`. See `backend/app/config.py`.

| Variable | Default | Meaning |
|---|---|---|
| `MAILTRACE_DATA_DIR` | `backend/data` | Runtime directory: `mailtrace.db`, `evidence/`, `model.joblib`, `url_model.joblib`. An empty value is treated as unset |
| `MAILTRACE_DATABASE_URL` | (empty) | Optional PostgreSQL / Supabase connection string; needs `requirements-pg.txt`. Empty keeps SQLite |
| `MAILTRACE_ORG_NAME` | `Protected Organisation` | Name of the organisation being protected |
| `MAILTRACE_ORG_DOMAINS` | `example.org` | Your mail domains; used for spoof, lookalike and internal-hop checks. **Set this or lookalike attribution cannot fire** |
| `MAILTRACE_EXECUTIVES` | `ceo,cfo,managing director` | Titles and names whose impersonation is flagged |
| `MAILTRACE_PROTECTED_BRANDS` | (empty) | Extra brand keywords added to the built-in brand list |
| `MAILTRACE_TRUSTED_RELAYS` | (empty) | Host suffixes treated as your own relays when selecting the origin hop |
| `MAILTRACE_ENABLE_NETWORK` | `true` | Live DNS, WHOIS, GeoIP, Tor, DNSBL and reputation lookups; `false` for offline demos |
| `MAILTRACE_LOOKUP_TIMEOUT` | `3.0` | Seconds per network lookup |
| `MAILTRACE_MAX_DOMAIN_LOOKUPS` | `6` | Domains enriched per message |
| `MAILTRACE_MAX_GEO_LOOKUPS` | `8` | IPs geolocated per message |
| `MAILTRACE_ABUSEIPDB_KEY` | (empty) | Optional AbuseIPDB API key for IP reputation |
| `MAILTRACE_URLHAUS_KEY` | (empty) | Optional abuse.ch URLhaus Auth-Key. **Without it the URLhaus lookup is skipped entirely** |
| `MAILTRACE_VIRUSTOTAL_KEY` | (empty) | Optional VirusTotal v3 key for attachment hash reputation; only SHA-256 is sent |
| `MAILTRACE_MAXMIND_DB` | (empty) | Path to a GeoLite2-City `.mmdb`; preferred over ip-api.com when set |
| `MAILTRACE_TRANSFORMER_MODEL` | (empty) | Hugging Face sequence-classification model id for the DistilRoBERTa backend; needs `requirements-ml.txt` |
| `MAILTRACE_URL_MODEL` | `true` | The XGBoost URL/domain model. `0` returns the URL pillar to the deterministic rules |
| `MAILTRACE_LIME` | `true` | The LIME second explanation. `0` roughly halves ingestion cost - see `docs/scaling.md` |
| `MAILTRACE_LIME_SAMPLES` | `160` | Perturbations per LIME explanation |
| `MAILTRACE_NATIVE_ENGINE` | `1` | `0` forces the pure-Python parser even when the C++ extension is built |
| `MAILTRACE_ENTROPY_THRESHOLD` | `7.0` | Bits/byte above which an attachment counts as packed or encrypted |
| `MAILTRACE_SIMHASH_MAX_DISTANCE` | `10` | Hamming distance under which two bodies are one campaign. Note that `deploy/.env.example` sets this to `6`, so copying it in tightens the clustering below the code default |
| `MAILTRACE_TLSH_MAX_DISTANCE` | `60` | TLSH diff under which two bodies are one campaign (needs py-tlsh) |
| `MAILTRACE_WEBHOOK_URLS` | (empty) | Comma-separated URLs that receive a JSON POST per alert |
| `MAILTRACE_ZERO_PERSISTENCE` | `false` | Analyse and return, writing no database and no evidence files |
| `MAILTRACE_CACHE_TTL_SECONDS` | `21600` | Lifetime of cached lookups (6 hours) |
| `MAILTRACE_PII_MASK_DEFAULT` | `false` | Mask PII unless a request says `mask=false` |
| `MAILTRACE_ALERT_THRESHOLD` | `70` | Risk score at which an alert is raised |
| `MAILTRACE_WEIGHT_AUTH` | `0.20` | Weight of the `auth` pillar (weights are normalised to sum to 1) |
| `MAILTRACE_WEIGHT_TEXT` | `0.35` | Weight of the `text` pillar |
| `MAILTRACE_WEIGHT_URL` | `0.25` | Weight of the `url` pillar |
| `MAILTRACE_WEIGHT_NETWORK` | `0.10` | Weight of the `network` pillar |
| `MAILTRACE_WEIGHT_ENTROPY` | `0.10` | Weight of the `entropy` pillar |
| `MAILTRACE_HOST` | `127.0.0.1` (`0.0.0.0` when `PORT` is set) | Bind address |
| `MAILTRACE_PORT` | `8000` (or `PORT`) | Bind port |
| `MAILTRACE_MAX_UPLOAD_BYTES` | `15728640` | Per-file upload limit (15 MiB); larger files get HTTP 413 |
| `MAILTRACE_LOG_LEVEL` | `info` | `critical`, `error`, `warning`, `info` or `debug` |

The five weight names are the only ones read. `config.Settings.from_env` builds
each variable as `"MAILTRACE_WEIGHT_" + key.upper()` over the keys of
`DEFAULT_WEIGHTS` (`auth`, `text`, `url`, `network`, `entropy`); any other
spelling - `_AUTHENTICATION`, `_CONTENT`, `_LINKS`, `_AI` - is silently ignored.

## 11. Demo walkthrough

The five messages in `samples/` are described one by one in
[`samples/README.md`](samples/README.md).

1. Copy `deploy/.env.example` to `.env` at the project root (or into `backend/`).
   It sets `MAILTRACE_ORG_DOMAINS=acme-corp.in` and adds `sarthak srivastava` to
   the executives, the identities the samples attack. Without it two of the five
   verdicts change - see `samples/README.md`.
2. From `backend/`, run `python run.py` and open http://127.0.0.1:8000. The
   dashboard shows the drop zone and the network / offline badge.
3. Drag all five files from `samples/` onto the drop zone. Measured verdicts on a
   clean store, offline: `phishing_sbi_kyc` **Phishing 83** (critical),
   `bec_payment_diversion` **Fraud-Related 72** (high),
   `fraud_lottery_advance_fee` **Fraud-Related 60** (high),
   `impersonation_ceo_gift_cards` **Impersonated 45** (medium),
   `legit_transactional` **Legitimate 4** (low). Live enrichment can raise these
   (the Tor flag on the BEC origin, for instance); it does not lower them.
4. Open the SBI case: the risk gauge, category badge and dual-validation chip
   (rules say Phishing, the model says Impersonated at p=0.52, confidence 0.70);
   the spoofing badge row (SPF fail, DMARC fail, Reply-To on Gmail, display-name
   spoof); the Trace tab with four hops, the origin `45.148.10.72` on hop 1 and
   the route on the map; Links & Files showing `sbi-online-kyc-verify.xyz` behind
   the anchor text `https://onlinesbi.sbi`; the Content tab with the urgency meter
   and the `credential_harvesting` pattern at 0.95; Domains & Infra; the Graph
   tab; and the Custody tab, where "Verify ledger" returns `valid: true`.
5. Open the BEC case: the `payment_diversion` pattern at confidence 1.00 with its
   evidence phrases, the lookalike `acme-corp-in.com`, the Proton Mail Reply-To,
   the `185.220.101.45` origin (a Tor exit range, flagged as such only with the
   network on) and the recommended action to verify the bank change by phone.
6. Open the lottery case: `claim_form.pdf.exe` flagged critical (double extension,
   MIME mismatch, `MZ` executable bytes, 7.90 bits/byte entropy), the Nigerian
   origin against the "held in Mumbai" claim, and passing SPF / DKIM / DMARC that
   still cannot vouch for the identity.
7. Open the CEO case: an Impersonated verdict with no links or attachments (both
   the `url` and `entropy` pillars are 0), resting on identity and language alone.
8. Open the GitHub receipt: the Legitimate baseline with green authentication badges.
9. Campaign clustering: upload `phishing_sbi_kyc.eml` a second time. The copy shares
   `ip:`, `sender:` and `domain:` indicators with the first, a campaign appears in the
   Campaigns view, and its detail page shows the merged graph with the campaign node
   and the shared pivot nodes. Note the copy scores **87**, not 83: the
   `known_campaign_overlap` finding lifts the network pillar from 35.0 to 76.7.
10. Alerts: the bell counts every result at or above `MAILTRACE_ALERT_THRESHOLD`
    live over the WebSocket (SSE fallback); acknowledge them in the Alerts view.
    With the default threshold of 70 and the `.env` above, the SBI phishing case
    (83) and the BEC case (72) raise alerts; the lottery (60), CEO (45) and GitHub
    (4) cases do not. Without the `.env`, the BEC case scores 60 and stays below
    the threshold.
11. Reports: "Open HTML report" gives the print-ready report; "Export JSON report"
    the structured one; `?format=pdf` gives the Section 65B PDF (15 pages, 42 KB
    for the phishing case). Flip the PII toggle and reopen: addresses are masked,
    the report says `masked: true`, and the custody table now lists
    `report_generated` rows with the format and masking state.
12. Offline mode: restart with `MAILTRACE_ENABLE_NETWORK=false`; the verdicts above
    are exactly the offline ones, and the geo / domain cards show `offline`.

Command-line equivalents (run from the project root):

```bash
curl -F "files=@samples/phishing_sbi_kyc.eml" -F "files=@samples/bec_payment_diversion.eml" "http://127.0.0.1:8000/api/analyze?actor=rohan"
curl "http://127.0.0.1:8000/api/emails?min_risk=60"
curl "http://127.0.0.1:8000/api/reports/<id>?format=html" -o report.html
curl "http://127.0.0.1:8000/api/custody/verify"
```

On Windows PowerShell use `curl.exe`; plain `curl` is an alias of `Invoke-WebRequest`.

## 12. API reference

| Method | Path | Parameters | Returns |
|---|---|---|---|
| GET | `/` | - | the analyst UI (`frontend/index.html`) |
| GET | `/api/health` | - | `{"status", "engine_version", "network", "pii_mask_default", "zero_persistence", "webhooks", "database", "native_engine", "native_engine_version", "native_engine_status"}` |
| POST | `/api/analyze` | multipart `files` (one or more), query `actor`, `mask` | `{"results": [AnalysisResult], "alerts": [Alert]}` |
| POST | `/api/analyze/raw` | JSON `{"raw", "filename"}`, query `actor`, `mask` | same shape with one result |
| GET | `/api/emails` | `q`, `category`, `min_risk`, `campaign_id`, `source_type`, `limit`, `offset`, `mask` (blank `category` / `source_type` = no filter) | `{"items": [CaseSummary], "total"}` |
| GET | `/api/emails/{id}` | `mask` | `AnalysisResult`; records `viewed_unmasked` when overriding a masked default |
| GET | `/api/emails/{id}/raw` | - | the original `.eml` as `text/plain` attachment; records `exported` |
| GET | `/api/emails/export.csv` | same filters as `/api/emails`, plus `limit` (max 5000), `mask` | the case list as one CSV row per case, for bulk analysis |
| POST | `/api/emails/{id}/quarantine` | `actor` | `CaseDecision`; records a `quarantine_decision` in the ledger and sets the case status. Records a decision, does not touch a mail gateway |
| POST | `/api/emails/{id}/block` | `actor` | `CaseDecision`; records a `block_decision` in the ledger and sets the case status. Records a decision, does not touch a mail gateway |
| GET | `/api/emails/{id}/decision` | - | `CaseDecision`: current status, the IOCs to export and the decision history |
| GET | `/api/stats` | - | `DashboardStats` |
| GET | `/api/campaigns` | - | `[Campaign]`, newest first |
| GET | `/api/campaigns/{id}` | `mask` | `{"campaign", "emails": [CaseSummary], "graph": AttributionGraph}` |
| GET | `/api/graph` | `email_id` or `campaign_id`, `mask` | `AttributionGraph` |
| GET | `/api/reports/{id}` | `format=json\|html\|pdf\|csv`, `mask` | `ForensicReport` JSON, a self-contained HTML page, the Section 65B PDF, or a CSV of the verdict, pillars, origin, IOCs and findings; records `report_generated` with the format |
| GET | `/api/custody/{id}` | - | `CustodyChain` for that email (validity computed over the whole ledger); 404 when the id has no custody events |
| GET | `/api/custody/verify` | - | `{"valid", "head_hash"}` |
| GET | `/api/alerts` | `limit`, `unacknowledged_only`, `mask` | `[Alert]`, newest first |
| POST | `/api/alerts/{id}/ack` | - | `{"ok": true}` |
| GET | `/api/alerts/stream` | `mask` | Server-Sent Events: `event: alert` with the Alert JSON, `: ping` every 15 s |
| WS | `/api/alerts/ws` | `mask` | WebSocket: one text frame of Alert JSON per alert, from the same broadcaster as `/stream`. The dashboard prefers this and falls back to SSE |

Every error response has the shape `{"error": "<message>"}` with status 400
(bad input), 404 (unknown id), 413 (upload too large), 422 (validation), 500
(unexpected) or 503 (startup not complete). The interactive schema is at `/docs`.

## 13. Retraining the classifier

Run these from `backend/`:

```bash
cd backend
python -m app.ai.model_trainer                                   # retrain from app/ai/seed_corpus.json, print holdout accuracy
python -m app.ai.model_trainer --csv my_mails.csv --text-col text --label-col label --out data/model.joblib
```

The CSV needs a text column (`body` or `text`, optionally with a `subject` column)
and a label column whose values are exactly `Legitimate`, `Suspicious`,
`Impersonated`, `Phishing` or `Fraud-Related`. The model is a `FeatureUnion` of a
word (1-2 gram) and a character (3-5 gram) TF-IDF vectoriser feeding a
class-balanced logistic regression (`tfidf-logreg-2`); the CLI prints accuracy on
a 20 % stratified holdout plus the SHAP additivity residual, and the joblib bundle
stores the SHA-256 of the corpus it was trained from along with the expected
feature vector the SHAP values are computed against.

The running server always reconciles `<data dir>/model.joblib` with
`app/ai/seed_corpus.json`: at startup and on first use it reloads the cached model
only while the stored corpus hash matches the seed corpus, otherwise it retrains
from the seed corpus. To change what the server uses, extend
`app/ai/seed_corpus.json` (same `{"subject", "body", "label"}` objects), delete
`data/model.joblib` and restart. Use `--csv ... --out <other path>` for
experiments and benchmarks on larger corpora. The classifier only modulates
confidence; the rule policy in `app/core/scoring.py` always decides the category.

## 14. Running the tests

Run these from `backend/`:

```bash
cd backend
pip install -r requirements-dev.txt
pytest -q
```

`pytest.ini` sets `testpaths = tests`, so plain `pytest` finds the suite.

Measured on 2026-09-05: **140 passed, 0 skipped**. The suite runs offline
(`enable_network=False`) against a temporary data directory.

The count depends on whether the optional C++ extension is built. Without it,
six parity tests in `tests/test_native_engine.py` skip with `mailtrace_engine is
not built` and the run reads `134 passed, 6 skipped`. The engine was compiled on
2026-09-05 (Visual Studio Build Tools, MSVC, CPython 3.13) and those six now
run, comparing the C++ against `hashlib`, against the Python entropy function,
node-for-node against `email.feedparser`, and for byte-identical `ParsedEmail`
output on all five demo messages. See section 9 and
[`engine/README.md`](engine/README.md).

## 15. Limitations and honest notes

- **Seed corpus.** The classifier is trained on the 249 synthetic examples in
  `backend/app/ai/seed_corpus.json`. It is a corroborating signal and an
  explainability aid, not a production model; retrain it on real labelled mail
  before relying on its probabilities.
- **The dashboard needs internet.** Tailwind, Leaflet, d3, the Inter font and the
  OpenStreetMap tiles are all fetched from CDNs. The engine's offline mode does
  not extend to the browser.
- **Free geolocation API.** `ip-api.com` is free and needs no key, but is HTTP only,
  rate-limited (45 requests per minute), city-level at best, and places mobile or
  CGNAT addresses at the carrier's region rather than the device. Results are
  cached; an HTTP 429 yields `source="unavailable"`.
- **Live DKIM verification** needs the complete raw message and DNS access; forwarded
  or list-processed mail can legitimately fail. Offline, DKIM relies on
  `Authentication-Results` and is marked `unverifiable` when no result exists.
- **SPF evaluation** is a compact implementation (`ip4`, `ip6`, `a`, `mx`, `include`,
  `redirect`, `all`, depth 10); `exists` and macro mechanisms are reported as
  `unverifiable` rather than guessed.
- **WHOIS** uses raw socket queries; registries rate-limit and format answers
  differently, so `age_days` may be unknown. `.in`, `.com`, `.net`, `.org` and `.io`
  have fixed servers; other TLDs go through the IANA referral.
- **Tor exit detection** fetches the live exit list (cached for an hour); offline mode
  cannot flag Tor.
- **Attachments** are inspected statically (magic bytes, structure, archive listing);
  nothing is executed or detonated, and encrypted archives are flagged, not opened.
- **Origin selection** trusts the earliest public hop. Attackers can forge `Received`
  lines below the first trustworthy relay; MailTrace flags inconsistent order and
  timestamps but cannot prove them false. Geolocation identifies sending
  infrastructure, never a person.
- **Scores are store-dependent.** Every risk figure in this README is a
  first-ingest-on-a-clean-store number. Correlation against prior cases is a real
  signal and it raises scores on re-upload; compare like with like.
- **Scale.** Single-process SQLite and one analysis per request thread suit an
  investigation workstation, not an inline mail gateway. `docs/scaling.md` has the
  measured numbers and the design for getting past them - none of which is built.
- **No authentication on the API.** The server binds to `127.0.0.1` by default and
  CORS is open; put an authenticating reverse proxy in front before exposing it
  beyond localhost.
- **The Docker image has never been built.** No Docker daemon was available; see
  `deploy/README.md`.
- **Sample expectations** in `samples/README.md` are measured offline with the
  demo `.env`; live WHOIS, geolocation and Tor answers can raise confidence values
  and scores.

## 16. Legal note

MailTrace is a decision-support and evidence-preservation tool. Its verdicts are
automated analysis intended to assist, not replace, a qualified examiner, and they
are not legal advice. Evidence is acquired as-is: the raw message is hashed
(SHA-256, MD5) at ingestion, stored unmodified, and every access that matters is
written to a hash-linked custody ledger that can be verified at any time. These
records are designed to support the certificate required for electronic evidence
in India (Section 65B of the Indian Evidence Act, 1872, inserted by the
Information Technology Act, 2000; Section 63 of the Bharatiya Sakshya Adhiniyam,
2023) but the certificate itself must be issued by the person responsible for the
system. Analyse only messages you are authorised to handle, keep PII masking on
when sharing output, and report confirmed incidents to CERT-In
(incident@cert-in.org.in) and the National Cybercrime Reporting Portal
(cybercrime.gov.in).
