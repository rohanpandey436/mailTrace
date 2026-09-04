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
  hash-linked chain of custody, and a self-contained forensic report (JSON or
  printable HTML) prepared with the electronic-evidence certificate (Section 65B
  of the Indian Evidence Act, inserted by the IT Act 2000) in mind.

It starts with a single `python run.py` on Windows, macOS or Linux, needs no
external database or API key, and keeps working offline: every network
enrichment degrades to a valid result marked `source="offline"`.

Engine version: `app.schemas.ENGINE_VERSION` (currently `1.0.0`).

## Contents

1. [PS 26106 requirement mapping](#1-ps-26106-requirement-mapping)
2. [Architecture](#2-architecture)
3. [Directory structure](#3-directory-structure)
4. [Data model overview](#4-data-model-overview)
5. [Scoring and classification policy](#5-scoring-and-classification-policy)
6. [Attribution logic](#6-attribution-logic)
7. [Privacy and chain of custody](#7-privacy-and-chain-of-custody)
8. [Quick start](#8-quick-start)
9. [Configuration](#9-configuration)
10. [Demo walkthrough](#10-demo-walkthrough)
11. [API reference](#11-api-reference)
12. [Retraining the classifier](#12-retraining-the-classifier)
13. [Running the tests](#13-running-the-tests)
14. [Limitations and honest notes](#14-limitations-and-honest-notes)
15. [Legal note](#15-legal-note)

## 1. PS 26106 requirement mapping

| Requirement area | How MailTrace covers it | Where |
|---|---|---|
| Ingest suspicious emails as raw evidence | Multipart upload of one or many `.eml` / `.txt` files, or pasted RFC 822 source; the exact bytes are hashed and stored once under `data/evidence/<id>.eml` | `POST /api/analyze`, `POST /api/analyze/raw`, `app/engine/parser.py`, `app/db.py` |
| Header forensics and origin tracing | Every `Received` hop parsed (hosts, IP, protocol, TLS, timestamp), ordered chronologically, per-hop delay and anomalies (negative delay, private IP, missing TLS, forged order), originating IP with confidence and reasoning, `X-Originating-IP` handling | `app/engine/headers.py`, Trace tab |
| Spoofing detection (SPF / DKIM / DMARC) | `Authentication-Results` parsing plus live SPF evaluation, DKIM signature verification and DMARC policy lookup; relaxed alignment; Return-Path, Reply-To, Message-ID and display-name mismatch checks | `app/engine/auth.py`, `app/engine/headers.py` |
| Geolocation and infrastructure intelligence | City / region / country, ISP, organisation, ASN and reverse DNS per public hop; Tor exit, VPN / proxy, hosting-provider, DNSBL, AbuseIPDB (optional key), open-relay and botnet heuristics; route drawn on a map | `app/engine/geoip.py`, Leaflet map in the UI |
| Malicious link analysis | URL extraction from text and HTML (anchor text vs. href), lookalike / homoglyph / typosquat / punycode detection, shorteners, IP literals, userinfo tricks, open redirects, obfuscation, suspicious TLDs and keywords | `app/engine/urls.py` |
| Attachment analysis | Magic-byte sniffing against the declared type, double extensions, executables, macro documents, archives with risky members, password-protected archives, hashes | `app/engine/attachments.py` |
| Domain intelligence | WHOIS age and registrar, DNS (A / MX / NS / SPF / DMARC), free-mail and disposable detection, lookalike-of-brand, URLhaus reputation | `app/engine/domains.py` |
| NLP and social-engineering analysis | Urgency, fear, authority, secrecy, reward and scarcity lexicons; credential and financial terms; generic greeting; "reply, do not click" pattern; BEC patterns (payment diversion, fake invoice, credential harvesting, executive impersonation) with confidence and evidence phrases | `app/engine/nlp.py` |
| AI classification with explainability | TF-IDF (word and character n-grams) with logistic regression over a labelled seed corpus; per-class probabilities and exact SHAP token attributions; optional DistilRoBERTa backend | `app/ml/train.py`, `app/ml/seed_corpus.json` |
| Risk scoring and dual validation | Five weighted component scores; deterministic first-match policy; ML corroboration modulates confidence; per-category floors; every step written to `verdict.rationale` | `app/engine/scoring.py` |
| Source attribution | Spoofed domain / lookalike domain / compromised account / direct attacker infrastructure / legitimate sender, with confidence, reasoning and pivot indicators | `scoring.attribute_source` |
| Threat-intel correlation and campaign detection | Normalised IOC keys per email, overlap search across all prior cases, automatic campaign creation and merging, shared-indicator pivots | `app/engine/campaigns.py` |
| Relationship graph | Email, address, domain, IP, ASN, URL, attachment and campaign nodes with typed edges; merged per campaign | `app/engine/graph.py`, `GET /api/graph` |
| Forensic reporting and chain of custody | Hash-linked custody ledger (`ingested`, `analyzed`, `viewed_unmasked`, `exported`, `report_generated`), ledger verification, JSON / HTML report with evidence integrity, timeline, IOCs, actions and legal notes | `app/db.py`, `app/engine/reporting.py`, `/api/reports`, `/api/custody` |
| Privacy | PII masking (addresses, names, phone numbers, Aadhaar, PAN, card numbers) on every API representation, configurable default, unmasked views recorded in custody | `app/engine/privacy.py`, `?mask=` |
| Real-time alerting and dashboard | Alerts above a configurable risk threshold pushed over Server-Sent Events to the browser and as JSON webhooks to a SIEM or Slack; KPI dashboard, filterable case list, campaign views | `app/api/alerts.py`, `app/static/index.html` |

### Stage-by-stage compliance

The pitch deck describes the engine as five stages. Each is implemented as
follows, with the measurement that backs it.

| Stage | Specified | Implementation | Measured |
|---|---|---|---|
| 1-2 | Native ingestion, sub-30 ms parse, headers/body/attachments separated | `parser.parse_email` times itself into `ParsedEmail.parse_ms` | 1.4-4.6 ms across the five samples, 6-20x headroom |
| 3A | DistilRoBERTa NLP intent, Shannon entropy > 7.0, SHAP token weights | Linear classifier with **exact** SHAP by default, DistilRoBERTa behind `MAILTRACE_TRANSFORMER_MODEL`; `attachments.shannon_entropy` with `Settings.entropy_threshold` | SHAP additivity residual 3e-15; packed sample reads 7.90 bits/byte |
| 3B | Header chain, MaxMind DB, hop latency, time-delta anomalies, VPN/TOR | `geoip.maxmind_lookup` preferred when a `.mmdb` is configured, ip-api fallback; per-hop `delay_seconds` and anomaly flags | Negative-delta anomaly fires on the phishing sample |
| 3C | WHOIS age, DNS/MX alignment, lookalike detection, blacklists | `domains.py` (WHOIS over port 43, dnspython, `is_lookalike`), Spamhaus and five other DNSBL zones | onlinesbi.sbi resolved at 2321 days on the live site |
| 4 | Calibrated 0-100 across 5 pillars with an explicit weighted formula | `RiskBreakdown.ai/authentication/geoip_route/domain/threat_intel`, weights normalised from `MAILTRACE_WEIGHT_*` | Sample verdicts 80 / 68 / 60 / 47 / 5 |
| 5A | SimHash / TLSH fuzzy hashing for campaign grouping | Charikar SimHash in `parser.py`, TLSH when py-tlsh is present, distance matching in `campaigns.py` | Rewritten body clusters at distance 5-9, unrelated bodies 22-32 |
| 5B | Webhook alerts, Section 65B legal PDF with SHA-256 custody | `alerts.deliver_webhooks`, `reporting.render_pdf`, `Section65BCertificate` with clauses (a)-(d) | 14-page PDF, 40 KB; webhook delivered while a slow endpoint still hung |
| 5C | PII masking, stateless zero-persistence | `privacy.mask_result`, `Store(in_memory=True)` via `MAILTRACE_ZERO_PERSISTENCE` | No database and no evidence directory created in that mode |

**One deviation, stated plainly.** The deck's scoring slide reads
`0.20 Auth + 0.35 Text + 0.25 URL + 0.10 Net + 0.10 Entropy`, which is a
different five than the stage list above (AI, Auth, GeoIP/Route, Domain, Threat
Intel). The code implements the stage list, because that is what the
architecture describes, and entropy is folded into the AI pillar where it
belongs. The weights are configurable, so if the slide is the version you
present, set `MAILTRACE_WEIGHT_*` to match it and the two agree again.

## 2. Architecture

```
                 .eml files / pasted source                    analyst browser
                          |                                (app/static/index.html)
                          v                                     ^           ^
   +----------------------+-------------------------------------+-----------+------+
   |  FastAPI   app/main.py + app/api/*        JSON / HTML       |   SSE alerts     |
   |  /api/analyze  /api/emails  /api/campaigns  /api/graph  /api/reports  /api/... |
   +----------------------+---------------------------------------------------------+
                          |  run_in_threadpool (one message at a time per request)
                          v
   +----------------------+---------------------------------------------------------+
   |  app/engine/pipeline.py                                                        |
   |                                                                                |
   |  1 parser -> 2 headers -> 3 auth -> 4 urls | attachments | nlp (+ML)           |
   |     -> 5 domains || geoip (threads, cached) -> 6 campaigns.correlate            |
   |     -> 7 scoring (rules x ML, floors, attribution) -> 8 graph -> 9 persist      |
   +-------------+------------------------------------------------+-----------------+
                 |                                                |
                 v                                                v
   +-------------+--------------------+       +-------------------+-----------------+
   |  app/db.py   SQLite (WAL)        |       |  live enrichment (optional)         |
   |  emails, indicators, campaigns   |       |  DNS (dnspython)   WHOIS (sockets)  |
   |  custody ledger, alerts, cache   |       |  ip-api.com   Tor exit list   DNSBL |
   |  data/evidence/<id>.eml          |       |  URLhaus   AbuseIPDB (with key)     |
   +----------------------------------+       +-------------------------------------+
```

### What the "AI" actually is, and why word lists sit next to it

Two independent judges look at every email, and the disagreement between them is
a feature rather than a bug.

**1. A trained machine-learning model** (`app/ml/train.py`). Text is turned into
numbers with TF-IDF over word pairs and character triples, and a multinomial
logistic-regression classifier assigns one of the five categories. It is trained
on this machine the first time the server starts, from the 249 labelled emails in
`app/ml/seed_corpus.json`, and cached to `data/model.joblib`. Nothing is
downloaded and no API is called. Measured on a 20% hold-out the model never sees
during training:

| Class | Precision | Recall |
|---|---|---|
| Phishing | 1.00 | 1.00 |
| Fraud-Related | 1.00 | 0.90 |
| Legitimate | 0.90 | 0.90 |
| Impersonated | 0.82 | 0.90 |
| Suspicious | 0.80 | 0.80 |

Overall accuracy is **0.90**. Reproduce it any time with `python -m app.ml.train`.

Every prediction carries **exact SHAP values**. For a linear model the Shapley
value of a feature is `phi_i = coef_i * (x_i - E[x_i])`, where the expectation is
the mean feature value over the training corpus, which is stored alongside the
model. That decomposition is exact rather than approximate: summing all 34,643
contributions reproduces the classifier's own decision function to a residual of
3e-15, which is float64 rounding noise. Negative contributions are kept, so the
dashboard can show that "verify" and "login" argued *against* Impersonated and
*toward* Phishing, which a plain coefficient-times-feature view cannot express.

A **DistilRoBERTa** backend is implemented and guarded behind
`MAILTRACE_TRANSFORMER_MODEL`. It is off by default because `torch` is roughly a
gigabyte and the free tier the public demo runs on has 512 MB of RAM. With the
optional packages in `requirements-ml.txt` installed and a model id configured,
the transformer takes over and the linear model becomes the fallback; token
attributions there come from occlusion, and are labelled as such rather than
being called SHAP.

**2. A rule engine** (`app/engine/nlp.py`, `scoring.py` and friends). This is
where the keyword lists live. They are deliberately not the model, for three
reasons:

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
`dual_validation_agreement` flag records. The SBI sample is a live example: the
rules say Phishing, the model says Impersonated, and the verdict is reported at
0.70 confidence.

Scaling up is a matter of data, not architecture. Point
`python -m app.ml.train --csv your_data.csv` at a larger labelled corpus and the
same pipeline retrains, with the rules unchanged underneath.

### Pipeline order (`app/engine/pipeline.py`)

1. `parser` - structure, bodies, attachment bytes, raw hashes
2. `headers` - Received chain, origin selection, forged-field checks
3. `auth` - SPF / DKIM / DMARC from `Authentication-Results` and live lookups
4. `urls`, `attachments`, `nlp` - offline content analysis (the ML model runs here)
5. `domains` and `geoip` - concurrent, cached, fault-tolerant network enrichment
6. `campaigns.correlate` - threat-intel flags and prior-incident overlap
7. `scoring` - component scores, rule verdict, dual validation, attribution, merged findings
8. `graph` - relationship graph
9. persist, cluster into a campaign, write custody events

### Data flow

- The API layer is deliberately thin: validate the request, run `analyze_bytes` in a
  worker thread, raise an alert if warranted, mask PII if requested, return the
  `AnalysisResult` or a projection of it.
- `AnalysisResult` is the only persisted analysis artefact (`emails.result_json`);
  case lists, campaign views, graphs and reports are all projections of it, so the
  UI and the report can never disagree.
- Custody rows are written by the pipeline (`ingested`, `analyzed`) and by the API
  (`viewed_unmasked`, `exported`, `report_generated`); nothing updates or deletes a
  custody row.
- Alerts: pipeline result -> `maybe_alert` -> SQLite + `Broadcaster.publish` ->
  `loop.call_soon_threadsafe` -> each SSE subscriber queue -> browser bell and toast.

### Why FastAPI, SQLite and scikit-learn

- **FastAPI**: the pydantic v2 models in `app/schemas.py` are both the internal
  contract and the API schema, OpenAPI docs come for free at `/docs`, and async I/O
  serves the SSE stream while the synchronous engine runs in a thread pool.
- **SQLite** (WAL mode, one file): zero setup for judges and analysts, transactional,
  trivially handed over as part of an evidence bundle. An investigation workstation
  should not depend on a database server.
- **scikit-learn**: trains in seconds on a CPU, is deterministic, and admits an
  exact SHAP decomposition rather than an approximation, so every verdict can be
  traced to individual tokens. It needs no GPU, ONNX runtime or model download.
  The rule engine, not the model, makes the final call, so the model can stay
  small and auditable. A DistilRoBERTa backend is available behind a setting for
  deployments that can afford the memory.

### Why no bundled GeoIP database

Commercial GeoIP databases require a licence key, periodic downloads and hundreds
of megabytes. MailTrace queries `ip-api.com` at analysis time (city, ISP, ASN,
proxy and hosting flags), caches every answer in SQLite for
`MAILTRACE_CACHE_TTL_SECONDS`, and complements it with reverse DNS, the live Tor
exit list, DNSBL zones and optional AbuseIPDB. With `MAILTRACE_ENABLE_NETWORK=false`
each enrichment returns a valid object marked `source="offline"` and every other
stage is unaffected.

## 3. Directory structure

```
mailtrace/
  run.py                    uvicorn entry point (python run.py)
  requirements.txt          runtime dependencies
  requirements-dev.txt      runtime dependencies + pytest
  .env.example              every configuration key (demo values for the protected organisation)
  README.md
  app/
    config.py               Settings dataclass; MAILTRACE_* environment / .env loader
    schemas.py              pydantic v2 data contracts (ENGINE_VERSION lives here)
    db.py                   Store: SQLite persistence, custody ledger, alerts, cache
    main.py                 FastAPI app factory, lifespan, error handlers, static index
    api/
      deps.py               get_store / get_settings / mask_param dependencies
      analyze.py            upload, raw paste, case list, case detail, raw export, stats
      cases.py              campaigns and relationship graphs
      reports.py            forensic report (JSON / HTML) and custody chain
      alerts.py             alert list / ack, SSE stream, Broadcaster, maybe_alert
    engine/
      pipeline.py           orchestration (order above)
      knowledge.py          brands, free-mail, shorteners, risky extensions, DNSBLs, confusables
      parser.py             RFC 822 / MIME parsing, hashes, tolerant header decoding
      attachments.py        magic sniffing, macro / archive inspection, attachment risk
      headers.py            Received chain, origin selection, forged-field checks
      auth.py               SPF / DKIM / DMARC (Authentication-Results + live)
      urls.py               URL extraction, lookalike engine, registrable_domain
      domains.py            WHOIS, DNS and reputation per domain
      nlp.py                lexicons, BEC patterns, ML inference
      geoip.py              ip-api, reverse DNS, Tor, DNSBL, AbuseIPDB, infrastructure flags
      scoring.py            component scores, rule policy, dual validation, attribution
      graph.py              relationship graph build and merge
      campaigns.py          indicators, correlation, campaign assignment
      privacy.py            PII masking
      reporting.py          forensic report builder and HTML renderer
    ml/
      train.py              build / train / load / predict / explain + CLI
      seed_corpus.json      labelled seed corpus (five classes)
    static/
      index.html            single-file analyst UI (Tailwind, Leaflet, d3)
  samples/                  five demo messages and their README
  tests/                    pytest suite (offline)
  data/                     runtime, git-ignored: mailtrace.db, evidence/, model.joblib
```

## 4. Data model overview

`AnalysisResult` is produced once per analysed message and is the API's primary
object (`app/schemas.py`):

| Field | Type | Contents |
|---|---|---|
| `id`, `filename`, `analyzed_at`, `engine_version`, `processing_ms`, `masked` | scalars | identity and provenance of the analysis |
| `email` | `ParsedEmail` | message-id, subject, date, sender / reply_to / return_path / to / cc as `AddressInfo`, all headers in original order, text and HTML bodies, attachment metadata, `raw_sha256` / `raw_md5` / `raw_size`, mailer |
| `headers` | `HeaderAnalysis` | `hops[]` (`Hop`: hosts, IP, protocol, timestamp, delay, anomalies, `geo`), `originating_ip` with confidence and reasoning, mismatch flags, `auth` (`AuthResult`: SPF / DKIM / DMARC results, sources, policy, alignment), anomaly score, findings |
| `urls` | `UrlAnalysis` | `UrlInfo[]` (host, registrable domain, anchor mismatch, obfuscation, lookalike_of, risk, reasons), unique domains, score |
| `attachments` | `AttachmentAnalysis` | enriched `AttachmentMeta[]` (hashes, magic type, MIME mismatch, macros, archive, double extension, risk), score |
| `nlp` | `NlpAnalysis` | language, urgency score and phrases, social-engineering cues, financial / credential / threat terms, `ml_category`, `ml_probabilities`, `ml_top_terms`, `bec_patterns[]`, score |
| `domains` | `DomainIntel[]` | per domain: role, registrar, created / age, MX / A / NS, SPF and DMARC records, free-mail / disposable, lookalike, reputation, source |
| `infrastructure` | `InfraAnalysis` | `origin_geo` (`GeoInfo`), Tor / VPN-proxy / hosting / blacklisted / open-relay flags, botnet indicators, score |
| `intel` | `ThreatIntel` | normalised indicators, IP blacklists, domain reputation, Tor exits, related incidents, campaign id |
| `attribution` | `Attribution` | `source_type`, confidence, reasoning, pivot indicators |
| `graph` | `AttributionGraph` | typed nodes and edges for the force-directed view |
| `verdict` | `Verdict` | category, confidence, `risk_score`, severity, `breakdown` (five 0-100 components and weights), `ml_category`, `rule_category`, `dual_validation_agreement`, rationale, recommended actions |
| `findings` | `Finding[]` | every evidence-backed observation from every module, deduplicated and sorted by severity |
| `campaign_id` | string or null | campaign membership |

Projections: `CaseSummary` (case-list rows, stored as indexed columns),
`Campaign`, `CustodyEvent` / `CustodyChain`, `Alert`, `ForensicReport`
(executive summary, key indicators, evidence integrity, timeline, actions, legal
notes, custody, full analysis) and `DashboardStats`.

Storage (`app/db.py`): tables `emails` (summary columns plus `result_json`),
`indicators`, `campaigns`, `campaign_members`, `custody`, `alerts` and `cache`;
raw messages under `data/evidence/<id>.eml`.

## 5. Scoring and classification policy

**The five pillars** (0-100 each, exposed as `verdict.breakdown`):

| Pillar | Default weight | Derived from |
|---|---|---|
| `ai` | 0.35 | max(intent, payload) x 100, +10 when both exceed 0.4. Intent = 0.7 x NLP score + 0.3 x strongest BEC pattern. Payload = max(URL score, 0.9 x attachment score), where the attachment score now includes the Shannon-entropy check |
| `authentication` | 0.20 | SPF fail 45 / softfail 25 / none 15 / unverifiable 10; DKIM fail 35 / missing 10; DMARC fail 40 (60 under `p=reject`); +15 per misalignment; +20 when a protected or brand domain fails; plus forged sender fields (display name 45, Reply-To 35, Return-Path 25, Message-ID 15) |
| `geoip_route` | 0.15 | Origin infrastructure (Tor, VPN/proxy, hosting, blocklisted address, suspected open relay, botnet traits) combined with delivery-path anomalies: forged Received order 40, negative hop delta 25, oversized delay 10, plaintext hop 10, HELO mismatch 10, private-only chain 20, missing chain 25, low origin confidence 10 |
| `domain` | 0.20 | Lookalike 85, registered under 30 days 80 / under 90 days 55 / under a year 25, disposable 60, sender domain that does not resolve 70 or has no MX 40, free-mail sender behind a spoofed display name 30; link domains count at 0.6 weight |
| `threat_intel` | 0.10 | Tor exit list 85, reputation feed hit 90, IP blocklist 80, AbuseIPDB or infrastructure blocklist 75, prior-incident overlap 40 + 0.4 x worst related risk |

`risk_score = round(sum(weight x pillar))`. Weights come from
`MAILTRACE_WEIGHT_AI`, `_AUTHENTICATION`, `_GEOIP_ROUTE`, `_DOMAIN`,
`_THREAT_INTEL` and are normalised to sum to 1, so they express relative
importance rather than needing to add up by hand.

**Rule policy** (first match wins, recorded as `verdict.rule_category`):

1. **Fraud-Related** - payment-diversion or fake-invoice BEC pattern at confidence
   0.5 or more; or two or more financial terms combined with pressure (Reply-To
   mismatch, free-mail sender or urgency 0.5 or more) at risk 40 or more; or the
   classifier says Fraud-Related (p 0.6 or more) with financial terms; or executive
   impersonation (0.5 or more) paired with a money request.
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

Every attribution lists the pivot indicators (origin IP, ASN / ISP, sender,
Reply-To, URL hosts, attachment hashes) and `verdict.recommended_actions` turns the
verdict into a playbook: block the IOCs, verify bank changes out of band, reset
credentials, preserve the evidence, report to CERT-In and cybercrime.gov.in.

## 7. Privacy and chain of custody

**PII masking** (`app/engine/privacy.py`). Email addresses become
`r***n@domain.tld`, names become initials, and phone numbers, Aadhaar numbers, PAN
numbers and Luhn-valid card numbers are masked. Masking is applied to addresses,
header values, bodies, subject, finding details and evidence, graph address nodes
(the node id becomes a hash), indicators and the report narrative. Domains, IPs,
URLs and hashes are deliberately kept intact because they are the investigative
value. `?mask=true|false` on every endpoint that returns analysis data overrides
`MAILTRACE_PII_MASK_DEFAULT` and the UI toggle persists the choice. When masking is the default and an analyst
explicitly requests the unmasked analysis, a `viewed_unmasked` custody event is
written.

**Chain of custody** (`app/db.py`). An append-only ledger in which every row's hash
is `sha256(prev_hash | seq | email_id | timestamp | actor | action | detail_json |
evidence_sha256)` (the fields joined with `|`; `detail_json` is the canonical JSON of
the detail dictionary, sorted keys and compact separators, stored verbatim), with a
genesis `prev_hash` of 64 zeros.
Recorded actions: `ingested` (filename, size, SHA-256, MD5), `analyzed` (verdict,
engine version, campaign), `viewed_unmasked`, `exported` (raw `.eml` download) and
`report_generated` (format, masked). `GET /api/custody/verify` recomputes every hash
in sequence and returns the ledger head; any edit to a stored row breaks
validation. The forensic report embeds the raw hashes, the custody head hash and
its validity, and records its own generation event.

## 8. Quick start

Requirements: Python 3.11 or newer and internet access for the first
`pip install`. The classifier is trained from the seed corpus on first start (a
few seconds) and cached in `data/model.joblib`.

Windows PowerShell:

```powershell
cd C:\path\to\mailtrace
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # if blocked: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
pip install -r requirements.txt
Copy-Item .env.example .env         # optional; recommended for the demo (sets the protected organisation)
python run.py
```

macOS / Linux:

```bash
cd /path/to/mailtrace
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                # optional
python run.py
```

Open http://127.0.0.1:8000 for the UI or http://127.0.0.1:8000/docs for the
interactive API. Stop with Ctrl+C. Everything the server writes lives under
`data/`; delete that directory for a clean slate.

### Showing it on someone else's phone

`127.0.0.1` only works on the machine running the server. To let a judge open the
dashboard on their own phone, put both devices on the same Wi-Fi and bind to
every interface:

```powershell
$env:MAILTRACE_HOST="0.0.0.0"; python run.py
```

Startup then prints the address to use, for example
`http://192.168.29.171:8000`. Turn that into a QR code with any generator. The
address changes with the network, so regenerate it at the venue rather than
reusing one made at home.

While bound this way anyone on that network can reach the dashboard, and it has
no login. Use it for the demo and stop the server afterwards.

## 9. Configuration

All settings are read from environment variables, optionally seeded from a `.env`
file in the project root (existing environment variables win; list values are
comma-separated and lower-cased). See `app/config.py`.

| Variable | Default | Meaning |
|---|---|---|
| `MAILTRACE_DATA_DIR` | `<project>/data` | Runtime directory: `mailtrace.db`, `evidence/`, `model.joblib` |
| `MAILTRACE_ORG_NAME` | `Protected Organisation` | Name of the organisation being protected |
| `MAILTRACE_ORG_DOMAINS` | `example.org` | Your mail domains; used for spoof, lookalike and internal-hop checks |
| `MAILTRACE_EXECUTIVES` | `ceo,cfo,managing director` | Titles and names whose impersonation is flagged |
| `MAILTRACE_PROTECTED_BRANDS` | (empty) | Extra brand keywords added to the built-in brand list |
| `MAILTRACE_TRUSTED_RELAYS` | (empty) | Host suffixes treated as your own relays when selecting the origin hop |
| `MAILTRACE_ENABLE_NETWORK` | `true` | Live DNS, WHOIS, GeoIP, Tor, DNSBL and reputation lookups; `false` for offline demos |
| `MAILTRACE_LOOKUP_TIMEOUT` | `3.0` | Seconds per network lookup |
| `MAILTRACE_MAX_DOMAIN_LOOKUPS` | `6` | Domains enriched per message |
| `MAILTRACE_MAX_GEO_LOOKUPS` | `8` | IPs geolocated per message |
| `MAILTRACE_ABUSEIPDB_KEY` | (empty) | Optional AbuseIPDB API key for IP reputation |
| `MAILTRACE_CACHE_TTL_SECONDS` | `21600` | Lifetime of cached lookups (6 hours) |
| `MAILTRACE_PII_MASK_DEFAULT` | `false` | Mask PII unless a request says `mask=false` |
| `MAILTRACE_ALERT_THRESHOLD` | `70` | Risk score at which an alert is raised |
| `MAILTRACE_WEIGHT_AUTHENTICATION` | `0.20` | Risk weight (weights are normalised to sum to 1) |
| `MAILTRACE_WEIGHT_CONTENT` | `0.35` | Risk weight |
| `MAILTRACE_WEIGHT_LINKS` | `0.25` | Risk weight |
| `MAILTRACE_WEIGHT_INFRASTRUCTURE` | `0.10` | Risk weight |
| `MAILTRACE_WEIGHT_ANOMALY` | `0.10` | Risk weight |
| `MAILTRACE_HOST` | `127.0.0.1` | Bind address |
| `MAILTRACE_PORT` | `8000` | Bind port |
| `MAILTRACE_MAX_UPLOAD_BYTES` | `15728640` | Per-file upload limit (15 MiB); larger files get HTTP 413 |
| `MAILTRACE_LOG_LEVEL` | `info` | `critical`, `error`, `warning`, `info` or `debug` |

## 10. Demo walkthrough

The five messages in `samples/` are described one by one in
[`samples/README.md`](samples/README.md).

1. Copy `.env.example` to `.env`. It sets `MAILTRACE_ORG_DOMAINS=acme-corp.in` and
   adds `sarthak srivastava` to the executives, the identities the samples attack.
2. Run `python run.py` and open http://127.0.0.1:8000. The dashboard shows the drop
   zone and the network / offline badge.
3. Drag all five files from `samples/` onto the drop zone. Expected verdicts:
   `phishing_sbi_kyc` Phishing, `bec_payment_diversion` Fraud-Related,
   `fraud_lottery_advance_fee` Fraud-Related, `impersonation_ceo_gift_cards`
   Impersonated, `legit_transactional` Legitimate.
4. Open the SBI case: the risk gauge, category badge and dual-validation chip; the
   spoofing badge row (SPF fail, DMARC fail, Reply-To on Gmail, display-name spoof);
   the Trace tab with four hops, the origin `45.148.10.72` and the route on the map;
   Links & Files showing `sbi-online-kyc-verify.xyz` behind the anchor text
   `https://onlinesbi.sbi`; the Content tab with the urgency meter and the
   `credential_harvesting` pattern; Domains & Infra; the Graph tab; and the Custody
   tab, where "Verify ledger" returns `valid: true`.
5. Open the BEC case: the `payment_diversion` pattern with its evidence phrases, the
   lookalike `acme-corp-in.com`, the Proton Mail Reply-To, the Tor-range origin and
   the recommended action to verify the bank change by phone.
6. Open the lottery case: `claim_form.pdf.exe` flagged critical (double extension,
   MIME mismatch, executable bytes), the Nigerian origin against the "held in Mumbai"
   claim, and passing SPF / DKIM / DMARC that still cannot vouch for the identity.
7. Open the CEO case: an Impersonated verdict with no links or attachments, resting
   on identity and language alone.
8. Open the GitHub receipt: the Legitimate baseline with green authentication badges.
9. Campaign clustering: upload `phishing_sbi_kyc.eml` a second time. The copy shares
   `ip:`, `sender:` and `domain:` indicators with the first, a campaign appears in the
   Campaigns view, and its detail page shows the merged graph with the campaign node
   and the shared pivot nodes.
10. Alerts: the bell counts every result at or above `MAILTRACE_ALERT_THRESHOLD`
    live over SSE; acknowledge them in the Alerts view. Note that the BEC sample
    settles exactly on the Fraud-Related risk floor of 60, below the default
    threshold of 70, so it is listed as a case but does not raise an alert; the SBI
    phishing sample does.
11. Reports: "Open HTML report" gives the print-ready report; "Export JSON report"
    the structured one. Flip the PII toggle and reopen: addresses are masked, the
    report says `masked: true`, and the custody table now lists `report_generated`
    rows with the format and masking state.
12. Offline mode: restart with `MAILTRACE_ENABLE_NETWORK=false`; verdicts stay the
    same and the geo / domain cards show `offline`.

Command-line equivalents:

```bash
curl -F "files=@samples/phishing_sbi_kyc.eml" -F "files=@samples/bec_payment_diversion.eml" "http://127.0.0.1:8000/api/analyze?actor=rohan"
curl "http://127.0.0.1:8000/api/emails?min_risk=60"
curl "http://127.0.0.1:8000/api/reports/<id>?format=html" -o report.html
curl "http://127.0.0.1:8000/api/custody/verify"
```

On Windows PowerShell use `curl.exe`; plain `curl` is an alias of `Invoke-WebRequest`.

## 11. API reference

| Method | Path | Parameters | Returns |
|---|---|---|---|
| GET | `/` | - | the analyst UI |
| GET | `/api/health` | - | `{"status", "engine_version", "network", "pii_mask_default"}` |
| POST | `/api/analyze` | multipart `files` (one or more), query `actor`, `mask` | `{"results": [AnalysisResult], "alerts": [Alert]}` |
| POST | `/api/analyze/raw` | JSON `{"raw", "filename"}`, query `actor`, `mask` | same shape with one result |
| GET | `/api/emails` | `q`, `category`, `min_risk`, `campaign_id`, `source_type`, `limit`, `offset`, `mask` (blank `category` / `source_type` = no filter) | `{"items": [CaseSummary], "total"}` |
| GET | `/api/emails/{id}` | `mask` | `AnalysisResult`; records `viewed_unmasked` when overriding a masked default |
| GET | `/api/emails/{id}/raw` | - | the original `.eml` as `text/plain` attachment; records `exported` |
| GET | `/api/stats` | - | `DashboardStats` |
| GET | `/api/campaigns` | - | `[Campaign]`, newest first |
| GET | `/api/campaigns/{id}` | `mask` | `{"campaign", "emails": [CaseSummary], "graph": AttributionGraph}` |
| GET | `/api/graph` | `email_id` or `campaign_id`, `mask` | `AttributionGraph` |
| GET | `/api/reports/{id}` | `format=json|html`, `mask` | `ForensicReport` JSON or a self-contained HTML page; records `report_generated` |
| GET | `/api/custody/{id}` | - | `CustodyChain` for that email (validity computed over the whole ledger); 404 when the id has no custody events |
| GET | `/api/custody/verify` | - | `{"valid", "head_hash"}` |
| GET | `/api/alerts` | `limit`, `unacknowledged_only`, `mask` | `[Alert]`, newest first |
| POST | `/api/alerts/{id}/ack` | - | `{"ok": true}` |
| GET | `/api/alerts/stream` | `mask` | Server-Sent Events: `event: alert` with the Alert JSON, `: ping` every 15 s |

Every error response has the shape `{"error": "<message>"}` with status 400
(bad input), 404 (unknown id), 413 (upload too large), 422 (validation), 500
(unexpected) or 503 (startup not complete). The interactive schema is at `/docs`.

## 12. Retraining the classifier

```bash
python -m app.ml.train                                   # retrain from app/ml/seed_corpus.json, print holdout accuracy
python -m app.ml.train --csv my_mails.csv --text-col text --label-col label --out data/model.joblib
```

The CSV needs a text column (`body` or `text`, optionally with a `subject` column)
and a label column whose values are exactly `Legitimate`, `Suspicious`,
`Impersonated`, `Phishing` or `Fraud-Related`. The model is a `FeatureUnion` of a
word (1-2 gram) and a character (3-5 gram) TF-IDF vectoriser feeding a
class-balanced logistic regression (`tfidf-logreg-2`); the CLI prints accuracy on
a 20 % stratified holdout plus the SHAP additivity residual, and the joblib bundle
stores the SHA-256 of the corpus it was trained from along with the expected
feature vector the SHAP values are computed against.

The running server always reconciles `data/model.joblib` with
`app/ml/seed_corpus.json`: at startup and on first use it reloads the cached model
only while the stored corpus hash matches the seed corpus, otherwise it retrains
from the seed corpus. To change what the server uses, extend
`app/ml/seed_corpus.json` (same `{"subject", "body", "label"}` objects), delete
`data/model.joblib` and restart. Use `--csv ... --out <other path>` for
experiments and benchmarks on larger corpora. The classifier only modulates
confidence; the rule policy in `app/engine/scoring.py` always decides the category.

## 13. Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The suite runs offline (`enable_network=False`) against a temporary data
directory and finishes in well under a minute; the ML test is skipped
automatically when scikit-learn is not installed.

## 14. Limitations and honest notes

- **Seed corpus.** The classifier is trained on roughly 230 synthetic examples. It is
  a corroborating signal and an explainability aid, not a production model; retrain
  it on real labelled mail before relying on its probabilities.
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
- **Scale.** Single-process SQLite and one analysis per request thread suit an
  investigation workstation, not an inline mail gateway.
- **No authentication on the API.** The server binds to `127.0.0.1` and CORS is open;
  put an authenticating reverse proxy in front before exposing it beyond localhost.
- **Sample expectations** in `samples/README.md` describe the design intent; live
  WHOIS, geolocation and Tor answers can move confidence values.

## 15. Legal note

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
