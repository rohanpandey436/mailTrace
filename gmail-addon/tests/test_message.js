"use strict";

const { load, fixture, Report, differences } = require("./harness");

function attempt(call) {
  try {
    return { ok: call() };
  } catch (error) {
    return { error: error.name || "Error" };
  }
}

function plain(MT, value) {
  if (value instanceof MT.message.Extended) return { extended: [value.charset, value.language, value.value] };
  return value;
}

function params(MT, msg, header) {
  const found = msg.paramsPreserve(header);
  if (found === MT.message.MISSING) return null;
  return found.map((pair) => [pair[0], plain(MT, MT.message.unquoteValue(pair[1]))]);
}

function tree(MT, msg) {
  const entry = {
    headers: msg.items(),
    type: msg.getContentType(),
    boundary: attempt(() => msg.getBoundary()),
    filename: attempt(() => msg.getFilename()),
    charset: attempt(() => msg.getContentCharset()),
    params: attempt(() => params(MT, msg, "content-type")),
    disposition: attempt(() => params(MT, msg, "content-disposition")),
    preamble: msg.preamble,
    epilogue: msg.epilogue,
    unixfrom: msg.unixfrom,
    defects: msg.defects.slice(),
  };
  if (Array.isArray(msg.payload)) {
    entry.parts = msg.payload.map((part) => tree(MT, part));
  } else {
    entry.payload = msg.payload;
    entry.decoded = attempt(() => MT.bytes.toBase64(msg.decodedPayload()));
  }
  return entry;
}

function readable(outcome) {
  if (outcome.ok === undefined) return `error`;
  return Buffer.from(outcome.ok, "base64").toString("latin1").replace(/={15}[0-9]{19}==(?:\.[0-9]+)?/g, "<generated boundary>");
}

function sameOutcome(actual, expected) {
  if (expected.error) return Boolean(actual.error);
  return !actual.error && actual.ok === expected.ok;
}

function run(filter) {
  const MT = load();
  const vectors = fixture("message_vectors.json");
  const structure = new Report("MIME tree like Python");
  const serialised = new Report("re-serialised messages like Python");
  const textual = new Report("as_string like Python");
  let fallbackNeeded = 0;
  const unportable = [];
  for (const item of vectors) {
    if (filter && !item.name.includes(filter)) continue;
    const raw = MT.bytes.fromBase64(item.raw);
    let msg = null;
    let failure = null;
    try {
      msg = MT.message.parseBytes(raw);
    } catch (error) {
      failure = error;
    }
    if (item.error) {
      structure.ok(failure !== null, `${item.name}: Python could not parse this message but JavaScript did`);
      continue;
    }
    if (failure) {
      structure.ok(false, `${item.name}: JavaScript failed with ${failure.name}: ${failure.message}\n${failure.stack}`);
      continue;
    }
    let actual;
    try {
      actual = tree(MT, msg);
    } catch (error) {
      structure.ok(false, `${item.name}: building the tree failed with ${error.name}: ${error.message}\n${error.stack}`);
      continue;
    }
    const found = differences(actual, item.tree, 0, "", [], 6);
    structure.ok(found.length === 0, `${item.name}:\n      ${found.join("\n      ")}`);

    const asText = attempt(() => MT.bytes.toBase64(MT.message.asText(MT.message.parseBytes(raw))));
    if (item.as_string.error) {
      textual.ok(Boolean(asText.error), `${item.name}: Python's as_string failed but JavaScript produced ${JSON.stringify(readable(asText)).slice(0, 300)}`);
    } else {
      textual.ok(!asText.error && readable(asText) === readable(item.as_string), `${item.name}: as_string differs
      expected ${JSON.stringify(readable(item.as_string)).slice(0, 700)}
      actual   ${JSON.stringify(readable(asText)).slice(0, 700)}`);
    }
    const expected = item.as_bytes.ok !== undefined ? item.as_bytes : item.as_string;
    let actualBytes = attempt(() => MT.bytes.toBase64(MT.message.asBytes(MT.message.parseBytes(raw))));
    if (actualBytes.error) {
      actualBytes = attempt(() => MT.bytes.toBase64(MT.message.asText(MT.message.parseBytes(raw))));
      if (item.as_bytes.error && item.as_string.ok !== undefined) fallbackNeeded += 1;
    }
    if (actualBytes.error === "Unportable" && expected.ok !== undefined) {
      unportable.push(item.name);
      continue;
    }
    const left = readable(actualBytes);
    const right = readable(expected);
    serialised.ok(left === right, `${item.name}: serialised form differs
      expected ${JSON.stringify(right).slice(0, 700)}
      actual   ${JSON.stringify(left).slice(0, 700)}`);
  }
  const results = [structure.finish(12), serialised.finish(12), textual.finish(12)];
  console.log(`     ${fallbackNeeded} message(s) needed Python's text fallback after as_bytes failed`);
  console.log(`     ${unportable.length} message(s) need re-encoding that is not ported: ${unportable.slice(0, 12).join(", ")}`);
  return results.every(Boolean);
}

if (require.main === module) process.exit(run(process.argv[2]) ? 0 : 1);

module.exports = { run };
