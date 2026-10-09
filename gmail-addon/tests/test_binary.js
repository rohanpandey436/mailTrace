"use strict";

const { load, fixture, Report } = require("./harness");

function attempt(MT, call) {
  try {
    return { ok: MT.bytes.toBase64(call()) };
  } catch (error) {
    return { error: error.name };
  }
}

function sameOutcome(actual, expected) {
  if (expected.error) return Boolean(actual.error);
  return actual.ok === expected.ok;
}

function run() {
  const MT = load();
  const vectors = fixture("binary_vectors.json");
  const reports = [];

  const base64 = new Report("base64 decoding like Python");
  for (const item of vectors.base64) {
    const data = MT.bytes.fromBase64(item.data);
    const label = JSON.stringify(Buffer.from(data).toString("latin1"));
    const lenient = attempt(MT, () => MT.binascii.a2bBase64(data, false));
    base64.ok(sameOutcome(lenient, item.lenient), `lenient ${label}: expected ${JSON.stringify(item.lenient)} got ${JSON.stringify(lenient)}`);
    const strict = attempt(MT, () => MT.binascii.a2bBase64(data, true));
    base64.ok(sameOutcome(strict, item.strict), `strict ${label}: expected ${JSON.stringify(item.strict)} got ${JSON.stringify(strict)}`);
    base64.equal(MT.bytes.toBase64(MT.binascii.decodeB(data)), item.decode_b, `decode_b ${label}`);
  }
  reports.push(base64);

  const qp = new Report("quoted-printable decoding like Python");
  for (const item of vectors.qp) {
    const data = MT.bytes.fromBase64(item.data);
    qp.equal(MT.bytes.toBase64(MT.binascii.a2bQp(data, item.header)), item.out, `qp ${JSON.stringify(Buffer.from(data).toString("latin1"))} header=${item.header}`);
  }
  reports.push(qp);

  const uu = new Report("uuencode decoding like Python");
  for (const item of vectors.uu) {
    const data = MT.bytes.fromBase64(item.data);
    const actual = attempt(MT, () => MT.binascii.a2bUu(data));
    uu.ok(sameOutcome(actual, item.out), `line ${JSON.stringify(Buffer.from(data).toString("latin1"))}: expected ${JSON.stringify(item.out)} got ${JSON.stringify(actual)}`);
  }
  for (const item of vectors.uu_documents) {
    const data = MT.bytes.fromBase64(item.data);
    const actual = attempt(MT, () => MT.binascii.decodeUu(data));
    uu.ok(sameOutcome(actual, item.out), `document ${JSON.stringify(Buffer.from(data).toString("latin1")).slice(0, 160)}: expected ${JSON.stringify(item.out).slice(0, 80)} got ${JSON.stringify(actual).slice(0, 80)}`);
  }
  reports.push(uu);

  const blake = new Report("BLAKE2b like Python");
  for (const item of vectors.blake2b) {
    const data = MT.bytes.fromBase64(item.data);
    blake.equal(MT.bytes.toHex(MT.binascii.blake2b(data, 8)), item.d8, `digest 8 of ${data.length} byte(s)`);
    blake.equal(MT.bytes.toHex(MT.binascii.blake2b(data, 20)), item.d20, `digest 20 of ${data.length} byte(s)`);
    blake.equal(MT.bytes.toHex(MT.binascii.blake2b(data, 64)), item.d64, `digest 64 of ${data.length} byte(s)`);
  }
  reports.push(blake);

  return reports.map((report) => report.finish()).every(Boolean);
}

if (require.main === module) process.exit(run() ? 0 : 1);

module.exports = { run };
