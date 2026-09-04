# MailTrace parse engine (C++20)

Stage 2 of the pitch deck — *PARSE-C++: MIME dissection, header & relay
extraction, SHA-256 + Shannon entropy* — built as an **optional** Python
extension module called `mailtrace_engine`.

**Optional means optional.** Nothing in the normal install path builds this,
`backend/requirements.txt` does not mention it, and the service starts, serves
and analyses exactly the same way when it is absent. The deployed instance on
Render's free tier runs without it today. If you never build it, nothing here
affects you.

---

## What it does

| Function | Purpose |
| --- | --- |
| `dissect(raw) -> dict` | Structural dissection only: header name/value pairs and raw body byte ranges, with the tree shape CPython's `email.feedparser` would produce. This is what the backend consumes. |
| `parse_message(raw, decode=True) -> dict` | Convenience view: transfer-decoded bodies and attachment blobs with filenames, content types, SHA-256 and entropy. **The backend does not call this**; it is for CLI use, benchmarks and other embedders. |
| `sha256(data) -> str` | FIPS 180-4 SHA-256, lower-case hex. |
| `shannon_entropy(data) -> float` | Bits per byte over the 256-symbol alphabet, 0.0–8.0. |
| `decode_base64(data) -> bytes` | Lenient base64, matching `email._encoded_words.decode_b`. |
| `decode_quoted_printable(data) -> bytes` | Matching `binascii.a2b_qp`. |

### On OpenSSL

The deck's tech-stack slide lists OpenSSL. SHA-256 is implemented directly in
`src/sha256.cpp` instead (about 150 lines, transcribed from FIPS 180-4). That
is a deliberate choice, not a shortcut: SHA-256 is a fixed, fully specified
algorithm with no security benefit to linking a large TLS library, and every
build host with a missing or mismatched OpenSSL would otherwise lose the whole
extension. The result is a build with **zero external library dependencies**
beyond pybind11 and a C++20 compiler.

**It has never been verified against anything.** A parity test comparing this
SHA-256 to `hashlib` is written - `test_extension_sha256_matches_hashlib` in
`backend/tests/test_native_engine.py` - but it is guarded by
`@requires_extension` and it has been skipped on every run this repository has
ever had, because no C++ in this repository has ever been compiled. There is no
compiler on the machine MailTrace was developed on. Confirmed by running the
suite on 2026-09-05: `133 passed, 6 skipped`, all six skips reporting
`mailtrace_engine is not built`. Treat `src/sha256.cpp` as unexercised code
until you build the extension and the test actually runs.

---

## Building it

You need a C++20 compiler and pybind11. pybind11 is a **build-time** dependency
and is deliberately absent from `backend/requirements.txt`, because installing
it on a host with no compiler buys nothing and risks the deploy.

### Linux / macOS

```bash
# g++ 10+ or clang 12+
python -m pip install pybind11
python -m pip install ./engine
```

### Windows

Install the *Visual Studio Build Tools* with the "Desktop development with C++"
workload (MSVC 19.29+ / VS 2019 16.11 or newer), then from a Developer prompt:

```powershell
python -m pip install pybind11
python -m pip install .\engine
```

### In place, without installing

```bash
cd engine
python setup.py build_ext --inplace     # writes mailtrace_engine.<abi>.pyd/.so here
```

Then put `engine/` on `PYTHONPATH`, or copy the built module next to
`backend/app/`.

### CMake (alternative)

`setup.py` is the supported path. `CMakeLists.txt` is there for IDEs,
sanitiser builds and anyone who prefers to drive the compiler directly:

```bash
cmake -S engine -B build -DCMAKE_BUILD_TYPE=Release \
      -Dpybind11_DIR=$(python -m pybind11 --cmakedir)
cmake --build build --config Release
```

`-DMAILTRACE_FETCH_PYBIND11=ON` makes CMake download pybind11 itself.

---

## Verifying that it loaded

```bash
python -c "import mailtrace_engine; print(mailtrace_engine.__version__)"

# What the service thinks:
curl -s https://your-instance/api/health | python -m json.tool
#   "native_engine": true,
#   "native_engine_version": "1.0.0",
#   "native_engine_status": "active"
```

Or from Python:

```python
from app.engine import parser
print(parser.engine_status())
# {'native_engine': True, 'native_engine_version': '1.0.0',
#  'native_engine_status': 'active', 'parsed_native': 12,
#  'parsed_python': 0, 'native_declined': 0}
```

Those snippets show what a **successful build** looks like. What this repository
actually reports today, measured on 2026-09-05 against a locally started server:

```json
{"status":"ok","engine_version":"1.0.0","native_engine":false,
 "native_engine_version":"","native_engine_status":"not installed (pure-Python parser in use)"}
```

If `native_engine_status` is anything other than `"active"` it says why:
`not installed`, `present but not loadable` (ABI mismatch, missing runtime
DLL), `schema mismatch`, `self-check failed: ...`, or
`disabled by MAILTRACE_NATIVE_ENGINE`.

Set `MAILTRACE_NATIVE_ENGINE=0` to force the pure-Python parser regardless.

### Run the parity tests after building

```bash
cd backend
python -m pytest tests/test_native_engine.py -v
```

**Six** tests in that file are skipped while the extension is missing and run
automatically once it is built. Verified on 2026-09-05 with
`cd backend && python -m pytest -o addopts="" -q -rs`, which reported
`133 passed, 6 skipped` with all six skips in this file. They compare the
extension against `hashlib`, against the Python entropy implementation, and
node-for-node against a transcription of the same algorithm, and they assert
that all five sample messages produce byte-identical `ParsedEmail` objects with
and without it.

The rest of the file - the mirror tests, the cross-check tests and the
self-check tests - runs today against a pure-Python transcription of the
dissector, so the *contract* is exercised even though the C++ is not.

---

## The fallback is automatic, and the results are identical

`backend/app/engine/parser.py` imports the extension inside a `try`. When it is
missing, `parse_email` runs the pure-Python parser it always ran. When it is
present, the C++ finds the header and body byte ranges and Python assembles
them into a real `email.message.Message` tree — *the same object the standard
library would have built* — after which the rest of `parse_email` is
byte-for-byte the same code. Nothing downstream of the parse knows which ran.

Identical results are not a hope; three independent mechanisms enforce them.

1. **The engine declines what it does not claim to reproduce.** `dissect`
   returns `ok=False` for unix-from (mbox) lines in a header block, `message/*`
   parts other than `message/rfc822`, an empty or missing multipart boundary
   where CPython still finds one, a start boundary that never appears, header
   lines with an empty name, a header block opening with a continuation line,
   nesting deeper than 30, and more than 2000 parts. Python then parses the
   message. Declining costs a little speed; being wrong would cost correctness.

2. **Every message is cross-checked as the tree is rebuilt.** For each node the
   standard library's own `get_content_type()` and `get_boundary()` must agree
   with the structural decision the engine made. A part the engine called
   multipart must really be multipart with exactly that boundary; a part it
   flattened must not be one the standard library would nest. One disagreement
   discards the entire native result and the message is reparsed in Python.
   This is what makes the C++ side's simplified Content-Type parameter parsing
   safe.

3. **A self-check at import.** The engine must reproduce the Python parser's
   tree for a set of fixtures — CRLF and LF endings, folded headers, a header
   whose value begins on the continuation line, nested multiparts, base64 and
   quoted-printable payloads, an embedded `message/rfc822` with non-ASCII
   bytes, a multipart that never closes, and non-MIME junk — or it is switched
   off for the life of the process, with the reason logged and reported at
   `/api/health`. This is also the guard against interpreter differences: the
   exact unfolding rule in `compat32.header_source_parse` changed between
   CPython releases, and an interpreter that behaves differently from the one
   this engine was written against will fail the self-check rather than
   silently produce different header values.

### What stays in Python on purpose

The C++ decodes nothing. RFC 2047 encoded words, RFC 2231 parameter
continuations, charset handling, address parsing, filename extraction and
content-transfer decoding all remain in the standard library, on the rebuilt
`Message` objects. That is not laziness — it is what makes "identical results"
provable rather than merely tested. The expensive part of parsing a message is
the byte scanning, and that is what moved to C++.

For the same reason `parse_email` still uses `hashlib` for the raw SHA-256 and
`attachments.py` still computes entropy in Python. `hashlib` is already a C
implementation and is bit-exact by definition; two independent floating-point
entropy implementations would agree only to within rounding. The C++ versions
are exposed, parity-tested and used by `parse_message()`, but wiring them into
the pipeline would add a divergence risk for no measurable gain.

---

## Performance, honestly

Re-measured 2026-09-05 on the five demo messages with `python engine/bench.py`
(200 iterations each), **without** the extension — there is no C++ compiler on
the machine this was written on, so no native number has ever been produced and
the `native ms` and `speedup` columns print `-`:

```
message                                    size   python ms (median)
bec_payment_diversion.eml                  5087       0.140
fraud_lottery_advance_fee.eml             10151       0.259
impersonation_ceo_gift_cards.eml           3162       0.115
legit_transactional.eml                    5686       0.186
phishing_sbi_kyc.eml                       4823       0.135
```

Two things follow. The deck's "MIME dissection < 5 ms" is **already met by the
pure-Python parser** on messages of this size — the native engine is not what
makes that claim true. And the MIME parse is a small slice of `parse_email`,
which the same run measures at 1.21–3.07 ms median on these messages; most of
the rest is the SimHash body digest and the raw hashing.

Where the pure-Python parser genuinely hurts is size. Same machine, same day,
synthetic multipart messages of base64 attachments, timing
`parser._python_message` over seven repeats:

```
1.4 MB, 10 parts     python MIME parse median   19.7 ms
13.7 MB, 40 parts    python MIME parse median  184.5 ms
```

That is the case the native engine is for: a mailbox import or a bulk API
caller, not the demo. Run `python engine/bench.py` after building to get the
real speedup on your hardware, and please replace the numbers above with
measured ones rather than quoting a ratio nobody has observed.

---

## Layout

```
engine/
  include/mailtrace/sha256.hpp    FIPS 180-4 SHA-256, streaming, no allocation
  include/mailtrace/entropy.hpp   Shannon entropy over bytes
  include/mailtrace/mime.hpp      Dissection API + the compatibility contract
  src/sha256.cpp
  src/entropy.cpp
  src/mime.cpp                    The dissector; every CPython rule it mirrors
                                  is cited in the comments
  src/bindings.cpp                pybind11 surface
  setup.py                        Supported build
  pyproject.toml                  PEP 518: pybind11 as a build-only dependency
  CMakeLists.txt                  Alternative build
  bench.py                        Native vs Python timing
```

Implementation notes worth knowing before editing `src/mime.cpp`:

* Everything works on `std::string_view` slices of the caller's buffer and
  indexes only after a bounds test. There is no `new`, no `delete` and no
  owning raw pointer. Hostile input can end the walk early; it cannot read out
  of range.
* The line-splitting rule (`\r\n`, `\r`, `\n`, terminator retained), the
  header-block rule (`headerRE`), the boundary grammar (`boundaryendRE`) and
  RFC 2046's "the newline preceding a boundary belongs to the boundary" are all
  transcribed from CPython's `Lib/email/feedparser.py`, with the source cited
  at each site. Changing one of them without changing the Python mirror in
  `backend/tests/test_native_engine.py` will fail the tests, which is the
  point.
* The trailing-newline rule is subtler than it looks: it applies to whichever
  `Message` CPython's parser created *last*, which for a `message/rfc822` part
  is the nested message rather than the part. The engine therefore hands
  embedded messages back untrimmed and sets `trim_last`, and the Python adapter
  applies the rule after parsing them.
* `Dissection::ok == false` is a normal, expected answer, not an error. Add a
  decline rather than a second recovery path whenever CPython's behaviour is
  awkward to reproduce.
