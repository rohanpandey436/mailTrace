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

`sha256()` has two backends, chosen at build time. Where OpenSSL's development
headers are available it calls `EVP_Digest` and links `libcrypto`; where they
are not it uses the FIPS 180-4 implementation in `src/sha256.cpp` (about 150
lines). `mailtrace_engine.SHA256_BACKEND` reports which one a given build got,
and `/api/health` surfaces it as `native_engine_sha256`.

Both are always compiled and both are tested, because the fallback is not a
consolation prize: a host with a missing or mismatched OpenSSL would otherwise
lose the entire extension, and losing the C++ parser to gain a hash backend is
a bad trade. The digests are identical either way, which matters because a
chain-of-custody ledger written by one build has to verify under the other.

`setup.py` decides by compiling and linking a probe program, not by looking for
a header, since a header that exists is not a library that links. Three modes:

| `MAILTRACE_OPENSSL` | Behaviour |
|---|---|
| unset | Probe; use OpenSSL if it works, the built-in implementation if not. |
| `1` | Require OpenSSL. An unusable one fails the build instead of falling back. |
| `0` | Skip the probe and use the built-in implementation. |

The deployment image and the `engine` CI job both build with `=1`, so neither
can quietly ship the implementation it did not intend. CI additionally asserts
the digests match `hashlib` across every SHA-256 block boundary.

**It is verified against `hashlib`.** `test_extension_sha256_matches_hashlib`
in `backend/tests/test_native_engine.py` compares this implementation with the
standard library's over the demo corpus and a set of edge-case buffers. That
test, and the five other parity tests guarded by `@requires_extension`, were
skipped for as long as the repository had no compiler; they run now.

Built and measured on 2026-09-05 with Visual Studio Build Tools on Windows
(MSVC, CPython 3.13, `pip install ./engine`): the extension compiled on the
first attempt and the suite went from `133 passed, 6 skipped` to **`140 passed,
0 skipped`**. The parity tests check SHA-256 against `hashlib`, entropy against
the Python implementation, the dissection tree node-for-node against
`email.feedparser`, and byte-identical `ParsedEmail` output on all five demo
messages.

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
from app.core import parser
print(parser.engine_status())
# {'native_engine': True, 'native_engine_version': '1.0.0',
#  'native_engine_status': 'active', 'parsed_native': 12,
#  'parsed_python': 0, 'native_declined': 0}
```

That is what this repository reports today. Measured on 2026-09-05 against the
deployed instance at `https://mailtrace-t9vo.onrender.com/api/health`:

```json
{"status":"ok","engine_version":"1.0.0","native_engine":true,
 "native_engine_version":"1.0.0","native_engine_status":"active"}
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
automatically once it is built. With the engine built the suite reports
**`140 passed, 0 skipped`**; without it, `134 passed, 6 skipped`. They compare
the extension against `hashlib`, against the Python entropy implementation, and
node-for-node against a transcription of the same algorithm, and they assert
that all five sample messages produce byte-identical `ParsedEmail` objects with
and without it.

The rest of the file - the mirror tests, the cross-check tests and the
self-check tests - runs against a pure-Python transcription of the dissector, so
the *contract* is exercised even on a host with no compiler.

One caveat worth knowing before you deploy. The engine reproduces CPython's own
header handling, and `compat32`'s treatment of a value beginning on a
continuation line changed between 3.12 and 3.13. On 3.12 the self-check
correctly notices the mismatch and falls back, reporting
`self-check failed: engine produced a different tree for self-check fixture 4`.
That is the guard working, not a bug; `render.yaml` therefore pins Python 3.13.

---

## The fallback is automatic, and the results are identical

`backend/app/core/parser.py` imports the extension inside a `try`. When it is
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

Measured 2026-09-05 with the extension built (MSVC, CPython 3.13),
`python engine/bench.py`, 200 iterations each:

```
message                                    size   python ms   native ms   speedup
bec_payment_diversion.eml                  5087       0.140       0.043     3.22x
fraud_lottery_advance_fee.eml             10151       0.257       0.067     3.81x
impersonation_ceo_gift_cards.eml           3162       0.114       0.040     2.82x
legit_transactional.eml                    5686       0.186       0.063     2.96x
phishing_sbi_kyc.eml                       4823       0.135       0.043     3.15x
```

Two things follow, and the second is the honest one. The deck's "MIME
dissection < 5 ms" is **already met by the pure-Python parser** at this size, so
the native engine is not what makes that claim true. And the MIME parse is a
small slice of `parse_email`, which the same run measures at 1.08–2.74 ms
median; most of the remainder is the SimHash body digest and the raw hashing,
neither of which the native path touches.

Where the pure-Python parser genuinely hurts is size, and that is what this
engine is for. Synthetic multipart messages of base64 attachments, median of
five repeats, `parser._python_message` against `mailtrace_engine.dissect`:

```
message               python ms   native ms   speedup
0.2 MB,  2 parts            2.3         0.1      21.6x
1.4 MB,  4 parts           19.2         2.4       7.9x
7.0 MB, 10 parts           92.7        10.9       8.5x
28  MB, 20 parts          399.0        56.8       7.0x
```

So: roughly **3x on ordinary mail and 7–8x once messages reach megabytes**, which
is the mailbox-import and bulk-API case rather than the demo. Re-run
`python engine/bench.py` on your own hardware; these are one machine's numbers,
not a guarantee.

---

## Layout

```
engine/
  include/mailtrace/sha256.hpp    FIPS 180-4 SHA-256, streaming, no allocation
  include/mailtrace/entropy.hpp   Shannon entropy over bytes
  include/mailtrace/parser.hpp      Dissection API + the compatibility contract
  src/sha256.cpp
  src/entropy.cpp
  src/parser.cpp                    The dissector; every CPython rule it mirrors
                                  is cited in the comments
  src/bindings.cpp                pybind11 surface
  setup.py                        Supported build
  pyproject.toml                  PEP 518: pybind11 as a build-only dependency
  CMakeLists.txt                  Alternative build
  bench.py                        Native vs Python timing
```

Implementation notes worth knowing before editing `src/parser.cpp`:

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
