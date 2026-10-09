# MailTrace for Gmail

The Gmail add-on puts the MailTrace engine inside the user's Google account. It
is a Google Workspace add-on written in Apps Script, and the analysis code it
runs is a line-by-line port of the Python pipeline in `backend/app/core`,
verified against Python on tens of thousands of test vectors (see "How we know
it is the same engine" below).

Everything lives in [`gmail-addon/`](../gmail-addon/).

## What the user gets

| Promise | What happens |
|---|---|
| A risk label on every email | Each message receives one label, `MailTrace/Phishing`, `MailTrace/Fraud-Related`, `MailTrace/Impersonated`, `MailTrace/Suspicious` or `MailTrace/Legitimate`, coloured red, orange, purple, yellow or green. The label is applied when the message is opened and, for new mail, by a scan that runs once an hour. "Scan inbox now" on the home screen runs the same scan on demand |
| Score and reasons in the side panel | Opening a message shows the category, the 0-100 risk score, the severity band, the sender, the SPF / DKIM / DMARC results as Gmail recorded them, the classifier's category and probability, the top findings with their severity, and the first three recommended actions |
| Private mode (default) | The same rules and the same models (the TF-IDF + logistic-regression text classifier with exact SHAP weights, and the gradient-boosted URL model) run inside Apps Script. No request leaves the account. The manifest's `urlFetchWhitelist` allows only the MailTrace API host, and in Private mode nothing is fetched at all |
| Connected mode (opt in) | One switch on the home screen opens a consent card. After "Agree and turn on", two calls are made per analysed message: `POST /api/intel/lookup` with the registrable domains and public IP addresses from the message, and `POST /api/intel/match` with SHA-256 fingerprints of the message's indicators plus the body SimHash. The subject, body, addresses, names and attachments are never sent. The server answers from memory and stores nothing (`"stored": false` in both responses) |
| Investigate in one click | "Investigate on dashboard" sends that one email to `POST /api/analyze/raw` with `origin: "gmail"`. The case is unlisted (it is not in the case list, statistics, campaigns or alerts, and is reachable only through its link) and is deleted automatically 24 hours later unless someone freezes it as evidence on the dashboard. The card shows the case link and the deletion time |
| "From Gmail" on the dashboard | A case created this way shows a banner with its origin, the time left and a Freeze button; freezing records an `evidence_frozen` custody event and cancels the deletion |
| Zero configuration | Private mode is on from the first open, labels are created on first use, the hourly scan installs itself, and the protected organisation domain is taken from the user's own address (unless it is a free-mail provider such as gmail.com). There is nothing to configure |

## Installing it

You need Node.js 18 or newer and a Google account. Everything else is in the
repository.

```bash
cd gmail-addon
npm install
npx clasp login
npm run deploy
```

`npx clasp login` opens a browser window once; sign in with the account that
will use the add-on. `npm run deploy` bundles the engine, creates the Apps Script
project on first use, pushes the code and prints the last step:

1. Open the script link it prints.
2. Click **Deploy > Test deployments > Install**, then **Done**.
3. Open Gmail, click any email and open MailTrace in the right-hand side panel.
   Grant access when asked.

If `npm run deploy` says the Apps Script API is switched off, open
https://script.google.com/home/usersettings, turn on "Google Apps Script API",
wait a minute and run the command again.

There is no marketplace listing. A test deployment is installed for the account
that created it; for other accounts, share the script with them as editors and
have them install the same test deployment, or publish it through the Google
Workspace Marketplace SDK for a domain.

### Without Node.js

`npm run build` writes a `dist/` folder with eight files: `appsscript.json`,
`MailTrace.js` and six `data_*.js` files. They can be pasted into a new project
at https://script.google.com by hand (enable "Show appsscript.json manifest
file" in the project settings first), then installed with the same
Deploy > Test deployments > Install step. The clasp route above does exactly
this for you.

## What it asks permission for

| Scope | Why |
|---|---|
| `gmail.addons.execute` | Required by every Gmail add-on |
| `gmail.addons.current.message.readonly` | The id of the message that is open |
| `gmail.modify` | Read the raw RFC 822 bytes of a message and apply or change the MailTrace labels. The add-on never sends, deletes or moves mail |
| `script.external_request` | Connected mode and Investigate call the MailTrace API. The manifest restricts fetches to that host and Private mode makes none |
| `script.scriptapp` | Install the hourly scan trigger |

## How we know it is the same engine

`gmail-addon/src/mt_*.js` is a hand port of the Python pipeline. The data the
engine needs (brand and free-mail lists, lexicons, the source of every regular
expression, the text model vocabulary and weights, the URL model's trees, the
public suffix list, single-byte codec tables, HTML entities, the MIME type map)
is exported from Python by `tools/export_data.py`, so there is one source of
truth. The logic is then pinned to CPython 3.13 behaviour with vectors generated
by `tools/export_vectors.py` and `tools/export_fixtures.py` and checked by
`npm test`:

| Layer | Vectors | Result on 2026-09-30 |
|---|---|---|
| Number formatting, UTF-8, string helpers, exported regexes | 34,462 | all match |
| HTML parser events, `html_to_text`, `extract_urls` | 3 x 3,757 | all match |
| base64, quoted-printable, uuencode, BLAKE2b | 15,539 | all match |
| MIME tree (`email.feedparser`), `as_bytes` and `as_string` | 3 x 3,626 | all match |
| Header values, addresses, dates | 15,204 | all match |
| Parsed emails (`parser.parse_email`) | 3,135 | all match |
| Codecs: utf-7, escapes, punycode, idna, utf-16/32, 72 single-byte tables, and the 24 CJK codecs (Shift_JIS, EUC-JP, ISO-2022-JP family, GBK, GB18030, HZ, Big5, Big5-HKSCS, EUC-KR, CP949, Johab and relatives) decoding and encoding | 149,000+ | all match, including malformed bytes and lone surrogates |
| `ipaddress`, `urlsplit`, `normalize_url`, tldextract, `analyze_url`, Damerau-Levenshtein | 41,201 | all match |
| Text model probabilities, SHAP weights, explanations | 933 | all match to 1e-12 |
| URL model probabilities against onnxruntime | 400 | bit-identical |
| Full pipeline, every stage, corpus + samples + demo emails | 76 emails x 11 stages | identical category, risk, breakdown, attribution, findings |
| Full pipeline on fuzzed messages | 2,166 emails x 11 stages | identical |

The URL model is served by onnxruntime on the server. onnxruntime sums the 120
trees in float32 and, on a multi-core machine, splits the trees across threads,
which changes the rounding in the sixth significant digit. The server now pins
the session to one thread (`intra_op_num_threads = 1`), so the Python and
JavaScript probabilities are bit-identical and reproducible on any machine.

The CJK codecs and the `email` package are ported rather than delegated to the
platform, so the add-on behaves the same in Node and in Apps Script: the codec
tables are exported from CPython and the decoders reproduce CPython's error
lengths byte for byte. One theoretical difference remains, far from anything a
real message triggers: `nameprep` in the IDNA port follows CPython's Unicode
3.2 normalisation for code points assigned after Unicode 3.2, but not for the
handful of combining classes that later Unicode versions corrected.

## Limits worth knowing

- Apps Script gives a card callback 30 seconds and a trigger 6 minutes. The
  engine needs about 10 ms per email in Node and roughly 1 second including
  data loading in Apps Script, so the hourly scan labels up to 40 new messages
  per run and "Scan inbox now" stops after 20 seconds and asks to be tapped
  again if mail is left.
- Add-on triggers may not run more than once an hour, which is why new mail can
  wait up to an hour for its label. Opening the message labels it at once.
- The MailTrace API runs on Render's free tier, which sleeps after 15 minutes
  without traffic. The first Connected-mode lookup or Investigate after a pause
  can fail with a "server did not answer" message; the card says so and the next
  tap succeeds. Keeping the server awake (an uptime monitor pinging
  `/api/health` every five minutes, or a paid instance) removes this.
- Messages over 15 MB are analysed locally but cannot be sent to the dashboard
  (`MAX_UPLOAD_BYTES`).
- Gmail's own `Authentication-Results` header is what the add-on reads for SPF,
  DKIM and DMARC, in both modes; live DNS verification is not attempted from
  Apps Script.

## Files

| Path | Role |
|---|---|
| `src/mt_*.js` | The engine: Python semantics helpers, HTML parser, codecs including the CJK tables, `binascii`, `email` package, addresses and dates, MIME parsing, `ipaddress` / `urllib.parse` / tldextract, headers, authentication, attachments, NLP and the text model, the URL model, domains, infrastructure, threat intel, scoring, pipeline |
| `src/gas_platform.js` | The Apps Script adapter (gunzip and digests) |
| `src/gas_addon.js` | Cards, labels, scans, Connected-mode calls, Investigate, self-test, the trigger |
| `src/appsscript.json` | Manifest: scopes, URL allow-list, triggers |
| `src/data_*.js` | Generated data blobs (gzip + base64), 1.6 MB in total |
| `tools/export_data.py`, `tools/cjk_tables.py` | Regenerate the data blobs and the two model vector files; `--check` fails when the deterministic blobs are stale |
| `tools/export_fixtures.py`, `tools/export_vectors.py` | Regenerate `tests/fixtures/` (git-ignored, 40 MB); `--fuzz N` shortens the fuzzed sets |
| `tests/` | `npm test` runs every parity test plus `test_addon.js`, which drives the add-on through mocked Apps Script services (Gmail, CardService, UrlFetchApp, PropertiesService, ScriptApp) and checks labels, cards, consent, the exact request payloads, error handling and the bundled self-test |
| `tools/bundle.js`, `tools/deploy.js` | Build `dist/` and push it with clasp |

## Self-test inside Gmail

The home screen has "Run self-test". It analyses four bundled sample emails
inside the account and compares category, risk score, SHA-256 and the full list
of finding ids with the reference values recorded from Python. It is the quickest
way to prove, on stage, that the engine in the add-on is the engine on the
server.
