# Scaling MailTrace: Neo4j and Celery

**Status: designed, not deployed.** Nothing described in this document is
running. There is no Neo4j instance, no Redis, no Celery worker and no code in
the repository for either. This is the design work that would have to be true
before any of it could be stood up, written against the code as it exists today
so that the gaps are visible rather than hand-waved.

What *is* running: a single FastAPI process, a single SQLite file behind
`backend/app/db.py`, in-process correlation in `backend/app/engine/campaigns.py`,
and an in-process graph builder in `backend/app/engine/graph.py`. The optional
PostgreSQL adapter added alongside this document (`MAILTRACE_DATABASE_URL`) is
the one piece of shared-state infrastructure that has any code behind it, and it
too is unverified against a real server.

Measurements below were re-taken on 2026-09-05 on the development machine
(Windows 11, CPython 3.13, the repo's `.venv`, `MAILTRACE_ENABLE_NETWORK=false`,
`org_domains=["acme-corp.in"]`) with the five bundled samples cycled and
subject-varied so that correlation does not collapse into one campaign. The
model was trained once before the clock started, so no run includes training.
Every figure is **with the shipped defaults**, which since this document was
first written means **`MAILTRACE_LIME=1`**:

| workload | shipped defaults | with `MAILTRACE_LIME=0` |
|---|---|---|
| analysis only, no store (`analyze_bytes(..., store=None)`), 100 messages | **104 ms / message** (median 107) | 24 ms / message (median 23) |
| full ingestion, empty store (messages 1-100) | **126 ms / message** | 45 ms / message |
| full ingestion, messages 401-500 | **221 ms / message** | 130 ms / message |
| 500 messages, single process, sequential | **83.2 s total**, 166 ms / message mean | 40.3 s total, 81 ms / message mean |

**An earlier revision of this document quoted 25 ms, 63 ms, 124 ms and 41.8 s.**
Those numbers were taken before LIME was enabled by default and they are now
wrong by roughly 4x on the analysis-only figure and 2x on the batch. They match
the right-hand column almost exactly, which is how the cause was identified. The
left-hand column is what a user gets today; every derived figure in this document
has been recomputed from it.

Two effects are stacked in that table and it is worth separating them:

* **LIME is the single largest per-message cost.** It fits a local surrogate
  over `MAILTRACE_LIME_SAMPLES` (160) perturbations, which is one batched
  `predict_proba` over 160 rewritten copies of the message. Measured, it is
  roughly 80 ms per message on this hardware - four fifths of the analysis-only
  cost. It buys a second, independent explanation beside exact SHAP; that is a
  real product decision, not an accident, but it should be a *known* one.
* **Correlation degrades with store size.** The rise from 126 ms to 221 ms
  across 500 ingestions is the whole story of why this document exists, and it
  is explained in the Celery section: it is not the analysis getting slower, it
  is correlation reading a growing table. Note it is present in both columns
  (45 -> 130 ms with LIME off), so it is genuinely independent of LIME.

---

## 1. Neo4j

### 1.1 What already exists

`app/engine/graph.py` builds a real property graph in memory for every analysed
message. Node ids are already `"<type>:<key>"` with normalised keys, precisely so
that two messages' graphs can be overlaid (`merge_graphs`). The type vocabulary
is fixed in `app/schemas.py`:

```python
NodeType = Literal["email", "address", "domain", "ip", "asn", "url", "attachment", "campaign"]
```

So the projection into Neo4j is nearly mechanical: MailTrace is not being taught
graph modelling, it is being asked to persist a model it already computes.

### 1.2 Labels and properties

One label per `NodeType`, `key` carrying the same normalised value used in the
node id today (lower-cased address/host/domain, lower-case hash hex, raw IP
literal). `Email` is keyed by MailTrace's `id`, everything else by `key` - which
is what makes an IOC shared rather than duplicated per message.

| Label | Key | Properties from `graph.py` |
|---|---|---|
| `:Email` | `id` | `label` (subject), `risk`, `risk_score`, `category`, `analyzed_at`, `filename` |
| `:Address` | `key` (mailbox) | `risk`, `roles` (`["sender","reply_to","return_path"]`) |
| `:Domain` | `key` (registrable) | `risk`, `age_days`, `lookalike_of`, `reputation`, `is_free_mail` |
| `:Ip` | `key` | `risk`, `city`, `country`, `isp`, `tor`, `blacklists`, `is_origin` |
| `:Asn` | `key` | `risk` (always `INFO` today) |
| `:Url` | `key` (host) | `risk`, `count` |
| `:Attachment` | `key` (sha256) | `risk`, `size`, `magic`, `filename` |
| `:Campaign` | `id` | `name`, `max_risk`, `members` |

`risk` is the `Severity` string. Node-merge in `_GraphBuilder.add` keeps the
*higher* risk and fills blank attributes from the newcomer; reproducing that in
Cypher needs a numeric companion property, because Neo4j cannot order
`"CRITICAL" > "HIGH"` on its own. Store `risk_rank` (the existing
`SEVERITY_ORDER` value) beside `risk` and the merge becomes a `CASE`.

Constraints, which are also the indexes the pivot queries need:

```cypher
CREATE CONSTRAINT email_id   IF NOT EXISTS FOR (n:Email)      REQUIRE n.id  IS UNIQUE;
CREATE CONSTRAINT addr_key   IF NOT EXISTS FOR (n:Address)    REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT domain_key IF NOT EXISTS FOR (n:Domain)     REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT ip_key     IF NOT EXISTS FOR (n:Ip)         REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT asn_key    IF NOT EXISTS FOR (n:Asn)        REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT url_key    IF NOT EXISTS FOR (n:Url)        REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT att_key    IF NOT EXISTS FOR (n:Attachment) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT camp_id    IF NOT EXISTS FOR (n:Campaign)   REQUIRE n.id  IS UNIQUE;
```

### 1.3 Relationship types

These are exactly the `relation` strings `graph.py` emits, upper-cased:

| Relationship | From -> To | Emitted by |
|---|---|---|
| `:SENT_BY` | `Email -> Address` | sender mailbox |
| `:REPLY_TO` | `Email -> Address` | each `Reply-To` |
| `:RETURN_PATH` | `Email -> Address` | envelope sender |
| `:LINKS_TO` | `Email -> Url` | one per distinct link host |
| `:CONTAINS` | `Email -> Attachment` | one per attachment, keyed by content hash |
| `:ORIGINATED_FROM` | `Email -> Ip` | `header_analysis.originating_ip` |
| `:RELAYED_VIA` | `Email -> Ip` | each public hop; carries `hop` (the `weight` today) |
| `:HOSTED_ON` | `Ip -> Asn` | from geo enrichment |
| `:RESOLVES_TO` | `Address -> Domain`, `Url -> Domain`, `Domain -> Ip` | address/link domains, and A records |
| `:MEMBER_OF` | `Email -> Campaign` | `merge_graphs(..., campaign=...)` |

Note `:RESOLVES_TO` is deliberately reused across three source labels, as in the
current code. Keeping the current single relation name means the existing
dashboard legend needs no change; splitting it into `:IN_DOMAIN` and
`:RESOLVES_TO` would be cleaner Cypher and a UI change.

### 1.4 Writing a graph

`build_graph` already returns deduplicated nodes and edges, so ingestion is one
parameterised transaction per analysed message. Dynamic labels are not
expressible in plain Cypher, so nodes are grouped by type on the Python side and
one `UNWIND` runs per label - eight statements, not eight hundred:

```cypher
// $email = {id, label, risk, risk_rank, risk_score, category, analyzed_at}
MERGE (e:Email {id: $email.id})
SET   e += $email;

// $domains = [{key, risk, risk_rank, age_days, lookalike_of, reputation, is_free_mail}, ...]
UNWIND $domains AS d
MERGE (n:Domain {key: d.key})
ON CREATE SET n += d
ON MATCH  SET n.risk       = CASE WHEN d.risk_rank > coalesce(n.risk_rank, 0) THEN d.risk       ELSE n.risk       END,
              n.risk_rank  = CASE WHEN d.risk_rank > coalesce(n.risk_rank, 0) THEN d.risk_rank  ELSE n.risk_rank  END,
              // "blank attributes are filled from the newcomer" (_GraphBuilder.add)
              n.age_days      = coalesce(n.age_days, d.age_days),
              n.lookalike_of  = coalesce(n.lookalike_of, d.lookalike_of);

// $links = [{host, domain}, ...] - one statement per relationship type
UNWIND $links AS l
MATCH (e:Email {id: $email.id}), (u:Url {key: l.host})
MERGE (e)-[:LINKS_TO]->(u);
```

### 1.5 The campaign pivot query

This is the query the whole exercise is for. Today it is
`Store.find_emails_by_indicators` (one indexed `IN` lookup) followed by the
scoring rule in `campaigns.py::_related`: *keep a related message if it shares at
least one **strong** indicator, or at least two weak ones*, where strong is
`("ip:", "sender:", "domain:", "replyto:", "urlhost:", "file:")`.

In Cypher that becomes a single traversal, and the strong/weak split is a label
test rather than a string prefix:

```cypher
// Messages that share infrastructure with $email_id, scored the way
// app/engine/campaigns.py::_related scores it today.
MATCH (new:Email {id: $email_id})--(ioc)--(other:Email)
WHERE other.id <> new.id
  AND NOT ioc:Campaign
WITH other,
     collect(DISTINCT head(labels(ioc)) + ':' + ioc.key) AS shared,
     // Address / Domain / Ip / Url / Attachment are the STRONG_PREFIXES
     count(DISTINCT CASE WHEN ioc:Address OR ioc:Domain OR ioc:Ip
                          OR ioc:Url OR ioc:Attachment THEN ioc END) AS strong
WHERE strong >= 1 OR size(shared) >= 2
RETURN other.id AS email_id, shared, strong, size(shared) AS overlap
ORDER BY strong DESC, overlap DESC
LIMIT 50;
```

And the pivot points of an existing campaign - `merge_graphs`' `shared_by >= 2`,
which today requires loading and re-merging every member's stored analysis:

```cypher
MATCH (c:Campaign {id: $campaign_id})<-[:MEMBER_OF]-(e:Email)--(ioc)
WHERE NOT ioc:Email AND NOT ioc:Campaign
WITH ioc, count(DISTINCT e) AS shared_by
WHERE shared_by >= 2
RETURN head(labels(ioc)) AS type, ioc.key AS key, ioc.risk AS risk, shared_by
ORDER BY shared_by DESC, ioc.risk_rank DESC;
```

The genuine win is the query SQL cannot express at all - transitive
infrastructure overlap, where two messages share nothing directly but the
sender domain of one resolves to an IP the links of the other also resolve to:

```cypher
MATCH path = (new:Email {id: $email_id})
             -[:SENT_BY|LINKS_TO|RESOLVES_TO|ORIGINATED_FROM|HOSTED_ON*2..4]-
             (other:Email)
WHERE other.id <> new.id
RETURN other.id AS email_id,
       [n IN nodes(path) | head(labels(n)) + ':' + coalesce(n.key, n.id)] AS via,
       length(path) AS hops
ORDER BY hops ASC
LIMIT 25;
```

### 1.6 What Neo4j would *not* cover, honestly

Three parts of the current correlation do not move into the graph, and pretending
otherwise would produce a worse system than the SQLite one:

1. **Weak indicators have no nodes.** `campaigns.py` also stores `subject:`,
   `asn:` and `mailer:` keys, and its "two weak indicators" rule depends on them.
   `asn:` maps to `:Asn`, but `build_graph` emits no subject or mailer node at
   all. A faithful port needs two new labels (`:Subject`, `:Mailer`) added to
   `build_graph` first - otherwise Neo4j serves the strong pivots and the
   relational `indicators` table has to stay for the weak ones.
2. **Fuzzy digests do not become edges.** SimHash/TLSH matching
   (`_fuzzy_related`) is a *distance* query. Neo4j has no more of an answer to
   that than SQLite does; both end up scanning. The fix is the same in either
   store and is independent of this migration: banded LSH, storing each digest as
   several `(band, value)` keys so that a near-duplicate is found by equality on
   at least one band. In the graph that is a `:SimhashBand {band, value}` node
   with an index on `(band, value)`; in SQL it is a second indicator table.
3. **The custody ledger stays relational.** It is an append-only hash chain that
   is read back byte-for-byte to re-verify. It has no graph shape and would gain
   nothing.

So the honest end state is Neo4j *beside* the relational store as a query
accelerator for attribution, not instead of it. Two stores means the write path
has to keep them consistent, which is a real cost, not a free upgrade.

### 1.7 Cost to stand up

Indicative and worth re-checking before quoting anyone; prices move.

- **AuraDB Free**: one instance, capped at roughly 200k nodes / 400k
  relationships, pauses after several days idle, no SLA. Enough for a
  demonstration and for the SIH evaluation; enough for maybe a few tens of
  thousands of messages given each message adds 10-30 nodes.
- **AuraDB Professional**: starts around USD 65/month for a 1 GB instance.
- **Self-hosted Community Edition**: free licence, but Neo4j wants 2 GB of heap
  before it is comfortable, so realistically a 4 GB VM at roughly USD 20-25/month.
  It will not co-exist with the API on the current 512 MB Render free instance -
  not "will be slow", will not start.
- **Engineering**: the Python side is `neo4j` (the official driver, a pure-Python
  wheel, safe to make optional exactly like `psycopg` is), a `graph_store.py`
  adapter of roughly the size of `db.py`'s dialect layer, the two new node types
  from point 1 above, and dual-write plus reconciliation. Estimate several days,
  not several hours, and most of that is consistency, not Cypher.

---

## 2. Celery and Redis

### 2.1 What runs today

`POST /api/analyze` (`app/api/analyze.py`) reads every uploaded file into memory,
then loops:

```python
for filename, raw in payloads:
    result, alert = await run_in_threadpool(_process, raw, filename, actor, mask, store, settings)
```

Two things to be precise about, because the deck is looser than the code:

- It is **not** a `ThreadPoolExecutor`. `run_in_threadpool` is Starlette's
  wrapper over AnyIO's worker threads (a shared limiter, 40 tokens by default).
- The loop is **sequential and awaited**. Files are deliberately not fanned out,
  because `Store` is one SQLite connection behind one `threading.RLock` and the
  module docstring says so: "Files are processed sequentially so the store never
  interleaves writes from a single request."

So 500 files is one HTTP request that occupies one worker thread for the
measured **83.2 seconds**, holds all 500 raw messages plus 500 result dicts in
memory, and returns a single response the client must wait for. On a 512 MB
instance behind a proxy with a 30-second idle timeout, that request does not
complete; it times out, and there is no way to ask what happened to it. Even
with `MAILTRACE_LIME=0` it is 40.3 seconds - still past the timeout. Turning
LIME off is a real 2x saving but it does not make this endpoint safe for bulk
work; only getting the work out of the request does.

Note also *why* the per-message cost rose from 126 ms to 221 ms across those 500
files: it is `_fuzzy_related` doing `find_indicators_by_prefix('simhash:')`, a
full scan of every digest stored so far, on every single ingestion. Moving that
loop onto Celery workers makes the wall clock better and the total work *worse* -
N workers all scanning the same growing table. Queueing without fixing the scan
is treating the symptom.

### 2.2 Target shape

```
                        ┌───────────────┐
 POST /api/analyze ────▶│ FastAPI (web) │──── enqueue 500 tasks ──▶ Redis
   (returns 202 +       └───────┬───────┘                            │
    batch_id)                   │                                    ▼
                                │                          ┌──────────────────┐
 GET /api/batches/{id} ─────────┤                          │ Celery worker(s) │
   (progress)                   │                          │  analyze_message │
                                │                          └────────┬─────────┘
 WS /ws, GET /stream ◀──────────┴──── Redis pub/sub ◀───────────────┘
   (live alerts)                                                     │
                                                       PostgreSQL ◀──┘
```

- **Broker and result backend**: Redis. The broker is required; the result
  backend is optional if batch progress is tracked in the database instead, and
  tracking it in the database is better - it survives a Redis restart and it is
  the same place `/api/batches/{id}` would read from anyway.
- **Task**: `analyze_message(batch_id, filename, blob_key, actor, mask)`. Raw
  bytes do **not** travel through the broker. They are written once to the
  evidence store (or object storage) and the task carries a key. 500 messages
  averaging 40 KB is 20 MB of payload; Redis is a queue, not a file server.
- **Endpoint change**: `POST /api/analyze` gains `?mode=async`, returns `202` with
  `{"batch_id": ..., "queued": 500}`. Existing synchronous behaviour stays the
  default so the dashboard, the tests and the demo are untouched.

### 2.3 The three things that break, and what fixes them

This is the part that matters. Celery is easy; the current code's assumptions
about being one process are not.

**(a) The custody chain is not safe across processes.** `Store.record_custody`
reads the current head, computes `seq = last.seq + 1` and
`prev_hash = last.hash`, then inserts - atomic only because of a *process-local*
`threading.RLock`. Two workers doing this concurrently both read the same head
and write two links claiming the same `seq`; `verify_chain` then returns
`False`, and the forensic integrity guarantee - the one thing this project
cannot get wrong - is gone. It fails silently, at ingest time, and is discovered
later when a report is generated.

Fixes, in order of preference:

1. Serialise the ledger in the database. On PostgreSQL, take
   `SELECT pg_advisory_xact_lock(hashtext('mailtrace.custody'))` at the top of
   the `record_custody` transaction. One extra round trip, correct under any
   number of workers, no schema change.
2. Route custody writes to a dedicated Celery queue with `concurrency=1`. Works,
   but makes the ledger a throughput ceiling and adds a failure mode where an
   analysis is stored and its custody record is still queued.
3. Change the chain from one global sequence to one chain per email. A schema
   change and a change to what the ledger proves (per-message tamper evidence,
   not global append-only ordering). Do not do this quietly.

**(b) Campaign correlation is a read-modify-write race.** `campaigns.py`
looks up related messages, then creates a campaign, merges campaigns that turn
out to be the same, and deletes the losers (`store.delete_campaign`). Two workers
ingesting near-duplicate messages at the same time will each find no existing
campaign and each create one. The current code has no lock for this because it
never needed one. Same fix as (a): an advisory lock keyed by the campaign
candidate, or a unique constraint plus a retry.

**(c) Alerts raised in a worker never reach a browser.** `app/api/alerts.py`
holds an in-process `Broadcaster` bound to the web process's event loop
(`broadcaster.bind(asyncio.get_running_loop())`) which fans out to SSE and
WebSocket subscriber queues. A Celery worker is a different process; it can call
`maybe_alert` and write the alert row, but its `broadcaster` has no subscribers
and the dashboard sees nothing until it polls. The fix is a Redis pub/sub bridge:
the worker `PUBLISH`es the alert JSON to `mailtrace:alerts`, and the web process
runs one background subscriber task that feeds `broadcaster.publish`. That is
perhaps 40 lines and it is the piece the deck's "WebSockets" claim actually
depends on once work leaves the web process.

There is also a hard prerequisite: **SQLite cannot be the store**. Multiple
worker processes writing one SQLite file over a network filesystem is
corruption, and even locally it is lock contention. Celery presupposes the
PostgreSQL adapter, which is why that adapter was built first.

### 2.4 What it would actually buy

Arithmetic on the measured 126-221 ms per message: four worker processes ingest
500 messages in roughly **21-26 seconds** of wall clock instead of 83, and - the
real point - the HTTP request returns in milliseconds instead of timing out. (The
83.2 s is measured; the 21-26 s is 83.2 divided by four workers plus overhead,
not something anyone has run - there is no Celery in this repository.) Beyond
four workers the fuzzy-digest scan dominates and adding workers stops helping;
fix the scan (section 1.6, point 2) before buying more workers.

Two cheaper things come first, in this order, because both are free and neither
needs new infrastructure:

1. `MAILTRACE_LIME=0` halves the per-message cost outright (83.2 s -> 40.3 s on
   the 500-message run). It costs the LIME explanation; SHAP stays exact and
   available. If bulk throughput matters more than the second explanation, this
   is one environment variable.
2. Banded LSH for the fuzzy digests, which removes the 126 -> 221 ms growth
   rather than dividing it among workers.

Only after those does queueing earn its complexity.

### 2.5 Cost to stand up

- **Redis**: a managed free tier (Render Key Value, Upstash, Redis Cloud) is
  enough for a queue of this size - tens of MB, no persistence needed for a
  broker. Paid tiers start around USD 10/month if durability is wanted.
- **Worker process**: a background worker cannot share the free web instance;
  it is a second service. On Render that is roughly USD 7/month per worker at the
  starter size, and a worker needs about 300-400 MB resident (scikit-learn,
  numpy, the loaded classifier), so the 512 MB free instance cannot host both.
- **PostgreSQL**: a free managed tier exists on several hosts, typically capped
  at around 1 GB and expiring after some months; roughly USD 7-20/month beyond
  that. Note that the analyses are stored as full JSON, so size is driven by
  message count times a few KB.
- **Engineering**: `celery[redis]` as an optional dependency, a `tasks.py`, the
  batch-tracking table and endpoint, the pub/sub bridge, and - the bulk of it -
  the three concurrency fixes above with tests that actually run two workers
  against one database. Estimate a week, and treat any estimate that omits the
  custody-chain fix as wrong rather than optimistic.

---

## 3. Recommended order

0. Decide about LIME. Measured, it is the largest single per-message cost with
   the shipped defaults - roughly 80 ms of the 126 ms baseline ingestion, and
   the difference between 83.2 s and 40.3 s over 500 messages.
   `MAILTRACE_LIME=0` is free and immediate. Do this before buying any
   infrastructure, or at minimum know the number you are paying.
1. PostgreSQL adapter behind `MAILTRACE_DATABASE_URL` - *code exists, unverified*.
   Verify it against a real server. Nothing else can proceed until the store is
   shareable.
2. Advisory locks for `record_custody` and campaign creation. Cheap, and it is
   the correctness prerequisite for every later step.
3. Banded LSH for the fuzzy digests. This is the measured *growth* bottleneck -
   the 126 ms to 221 ms rise across 500 ingestions - and it needs no new
   infrastructure at all, only a second indicator table and a change to
   `_fuzzy_related`.
4. Celery + Redis for bulk ingestion, with the Redis pub/sub bridge for alerts.
5. Neo4j, last, as a query accelerator beside the relational store - and only
   after `:Subject` and `:Mailer` nodes exist, or it cannot reproduce the
   correlation rule it is meant to replace.
