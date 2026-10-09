"use strict";

const { load, fixture, Report } = require("./harness");

function attempt(MT, data, codec, mode) {
  try {
    return { ok: MT.codecs.decode(data, codec, mode) };
  } catch (error) {
    return { error: error.name || "Error" };
  }
}

function same(actual, expected) {
  if (expected.error) return Boolean(actual.error);
  return actual.ok === expected.ok;
}

function attemptEncode(MT, text, codec, mode) {
  try {
    return { ok: MT.bytes.toBase64(MT.codecs.encode(text, codec, mode)) };
  } catch (error) {
    return { error: error.name || "Error" };
  }
}

function run(filter) {
  const MT = load();
  const vectors = fixture("codec_vectors.json");
  const reports = new Map();
  for (const item of vectors) {
    if (filter && item.codec !== filter) continue;
    if (item.encode) {
      const key = `${item.codec} encoding`;
      if (!reports.has(key)) reports.set(key, new Report(`${item.codec} encoding like Python`));
      const encoded = reports.get(key);
      for (const mode of ["strict", "surrogateescape"]) {
        const actual = attemptEncode(MT, item.text, item.codec, mode);
        encoded.ok(same(actual, item[mode]), `${mode} ${JSON.stringify(item.text).slice(0, 80)}: expected ${JSON.stringify(item[mode]).slice(0, 120)} got ${JSON.stringify(actual).slice(0, 120)}`);
      }
      continue;
    }
    if (!reports.has(item.codec)) reports.set(item.codec, new Report(`${item.codec} decoding like Python`));
    const report = reports.get(item.codec);
    const data = MT.bytes.fromBase64(item.data);
    const label = JSON.stringify(Buffer.from(data).toString("latin1")).slice(0, 120);
    for (const mode of ["strict", "replace"]) {
      const actual = attempt(MT, data, item.codec, mode);
      report.ok(same(actual, item[mode]), `${mode} ${label}: expected ${JSON.stringify(item[mode]).slice(0, 160)} got ${JSON.stringify(actual).slice(0, 160)}`);
    }
  }
  return Array.from(reports.values()).map((report) => report.finish(6)).every(Boolean);
}

if (require.main === module) process.exit(run(process.argv[2]) ? 0 : 1);

module.exports = { run };
