# How MailTrace works

One page. Read this before a demo or a viva and you can answer almost anything.

## The structure

```
mailtrace/
├── backend/
│   ├── run.py               starts the server
│   ├── app/
│   │   ├── main.py          builds the web app, /api/health
│   │   ├── config.py        every setting, read from MAILTRACE_* env vars
│   │   ├── schemas.py       the shape of all data (one class per concept)
│   │   ├── core/            THE ANALYSIS ENGINE  (see below)
│   │   ├── ai/              the machine-learning models
│   │   ├── utils/           report writing and privacy
│   │   ├── database/        storage
│   │   └── api/             the URLs the browser calls
│   └── tests/               140 automated tests
├── engine/src/parser.cpp    the C++20 parser
├── frontend/index.html      the dashboard
├── samples/                 five demo emails
└── docs/                    this file
```

## What each file does, in one line

**core/ — the analysis engine.** Twelve files, one job each.

| File | What it does |
|---|---|
| `pipeline.py` | The conductor. Calls everything below in order and assembles the result. **Start here when reading the code.** |
| `parser.py` | Opens the raw email: headers, body, attachments. Uses the C++ engine when built. |
| `header_analyzer.py` | Rebuilds the delivery path from `Received:` headers and picks the originating IP. |
| `auth_checker.py` | SPF, DKIM and DMARC. Is the sender who they claim to be? |
| `link_analyzer.py` | Every link: lookalike domains, hidden redirects, disguised text. |
| `file_analyzer.py` | Every attachment: real file type, macros, and Shannon entropy. |
| `ai_engine.py` | The wording. Urgency, threats, BEC patterns, and the ML verdict. |
| `geoip_mapper.py` | Turns IP addresses into places. Flags Tor, VPN and hosting providers. |
| `domain_intel.py` | Domain age (WHOIS), DNS and MX records, lookalike detection. |
| `threat_intel.py` | Blocklists, and grouping related emails into campaigns. |
| `scoring.py` | **The brain.** Combines everything into the 0-100 threat score and the verdict. |
| `graph_builder.py` | Draws the connections between senders, domains, IPs and links. |
| `knowledge.py` | Reference data: brand domains, free-mail providers, risky file types. |

**ai/ — the machine learning.**

| File | What it does |
|---|---|
| `model_trainer.py` | Trains and runs the text classifier. Also computes SHAP. |
| `url_model.py` | The XGBoost model that scores links. |
| `lime_explainer.py` | LIME, a second opinion on why the model decided what it did. |
| `seed_corpus.json` | The 249 labelled emails the model learns from. |

**utils/, database/, api/**

| File | What it does |
|---|---|
| `utils/pdf_generator.py` | The legal PDF report, including the Section 65B certificate. |
| `utils/pii_masker.py` | Hides names, addresses and ID numbers when privacy mode is on. |
| `utils/csv_exporter.py` | CSV export of a case or the whole list. |
| `utils/virustotal.py` | Optional: checks attachment hashes against VirusTotal. |
| `database/case_manager.py` | Saves cases, campaigns, alerts and the chain of custody. |
| `api/analyze.py` | Upload and list emails. |
| `api/reports.py` | Download reports (PDF, HTML, CSV). |
| `api/cases.py` | Campaigns and the connection graph. |
| `api/alerts.py` | Live alerts to the browser and to a SIEM. |

## What happens when you upload an email

Nine steps. This is `core/pipeline.py`, top to bottom.

1. **Parse** the raw bytes into headers, body and attachments. (C++ if built, Python otherwise. Both give identical results.)
2. **Read the headers**: rebuild the delivery path, find where it started.
3. **Check authentication**: SPF, DKIM, DMARC.
4. **Extract the links.**
5. **Three engines run at the same time**, because one waits on the network while another uses the processor:
   - AI: attachments and wording
   - GeoIP: where the IP is, and whether it is Tor or a VPN
   - Domain: WHOIS age, DNS, reputation
6. **Correlate**: has anything like this been seen before?
7. **Score**: combine into a number and a verdict.
8. **Build the graph** of connections.
9. **Save** and raise an alert if it is dangerous.

## The threat score

```
THREAT SCORE = 0.20 Auth + 0.35 Text + 0.25 URL + 0.10 Network + 0.10 Entropy
```

Five parts, each scored 0-100, then weighted. It lives in `core/scoring.py`, and
the weights are in `config.py` so you can change them without touching code.

## Questions a panel will ask

**"Where is the AI?"**
One place: `ai/model_trainer.py`. TF-IDF turns the words into numbers, then a
logistic-regression classifier picks one of five categories. It is trained on
your machine from the 249 emails in `seed_corpus.json`, and scores 0.90 accuracy
on emails it has never seen. Everything else in the system is forensic logic,
not AI, and that is deliberate: you cannot guess whether SPF passed.

**"Does the AI make the final decision?"**
No, and that is the design. The rule engine decides the category; the model
either agrees or disagrees. When they disagree the confidence drops and the
screen says so. Two independent judges are harder to fool than one.

**"Why C++?"**
The parser is the only part that touches every byte of every message. In C++ it
is about 3x faster on ordinary mail and 7-8x faster once messages reach
megabytes. If the C++ is not built, Python does the same job and the results are
byte-for-byte identical, which is checked by the tests.

**"How do you know the C++ is correct?"**
It is checked against Python's own parser on every message, and if they ever
disagree the C++ result is thrown away. That guard actually fired in production
once, on a Python version difference, and the system fell back safely.

**"What stops a wrong answer being hidden?"**
Every conclusion carries its evidence. `verdict.rationale` says why, in plain
English, and SHAP shows which words moved the model.

**"Can this be used as evidence?"**
The email is hashed on arrival, every action is written to a chain where each
entry locks in the one before it, and the report includes a Section 65B
certificate. Change anything and the chain breaks.

## Running it

```bash
cd backend
python run.py            # start it
pytest -q                # 140 tests
python -m app.ai.model_trainer   # retrain and print accuracy
```
