# MailTrace for Gmail

The MailTrace engine as a Gmail add-on: every email gets a `MailTrace/<Category>`
label, the side panel shows the risk score and the reasons, and in the default
Private mode nothing leaves the Google account.

Install (Node.js 18 or newer):

```bash
npm install
npx clasp login
npm run deploy
```

Then, in the browser link the command prints: Deploy > Test deployments >
Install. Open any email in Gmail and MailTrace appears in the side panel.

The full description, permissions, limits and the parity evidence against the
Python engine are in [`docs/gmail-addon.md`](../docs/gmail-addon.md).

| Command | Does |
|---|---|
| `npm test` | Every parity test plus the add-on behaviour test (`--fuzz` adds the 2,166 fuzzed messages) |
| `npm run build` | Writes `dist/` (manifest, `MailTrace.js`, six data files) |
| `npm run deploy` | Builds and pushes with clasp, creating the project on first use |
| `python tools/export_data.py` | Regenerates `src/data_*.js` from the Python engine and records the CPython release in `.python-version`, which CI checks the files with (`--check` reports stale files) |
| `python tools/export_fixtures.py`, `python tools/export_vectors.py` | Regenerate `tests/fixtures/` (git-ignored) |
