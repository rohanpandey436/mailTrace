"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const zlib = require("zlib");

const ROOT = path.join(__dirname, "..");
const SRC = path.join(ROOT, "src");
const FIXTURES = path.join(__dirname, "fixtures");

function decoder(labels, fatal) {
  for (const label of labels) {
    try {
      return new TextDecoder(label, { fatal, ignoreBOM: true });
    } catch (error) {
      continue;
    }
  }
  return null;
}

function platform() {
  return {
    name: "node",
    gunzip(bytes) {
      return new Uint8Array(zlib.gunzipSync(Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length)));
    },
    sha256(bytes) {
      return crypto.createHash("sha256").update(bytes).digest("hex");
    },
    md5(bytes) {
      return crypto.createHash("md5").update(bytes).digest("hex");
    },
    decode(bytes, labels) {
      const found = decoder(labels, true);
      if (!found) return null;
      try {
        return found.decode(bytes);
      } catch (error) {
        return null;
      }
    },
    decodeLossy(bytes, labels) {
      const found = decoder(labels, false);
      return found ? found.decode(bytes) : null;
    },
  };
}

function engineFiles() {
  return fs
    .readdirSync(SRC)
    .filter((name) => name.endsWith(".js") && (name.startsWith("mt_") || name.startsWith("data_")))
    .sort();
}

let loaded = false;

function load() {
  if (loaded) return global.MT;
  for (const name of engineFiles()) {
    vm.runInThisContext(fs.readFileSync(path.join(SRC, name), "utf8"), { filename: path.join(SRC, name) });
  }
  global.MT.platform = platform();
  loaded = true;
  return global.MT;
}

function fixture(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), "utf8"));
}

function hasFixture(name) {
  return fs.existsSync(path.join(FIXTURES, name));
}

class Report {
  constructor(title) {
    this.title = title;
    this.passed = 0;
    this.failures = [];
  }

  ok(condition, message) {
    if (condition) {
      this.passed += 1;
    } else {
      this.failures.push(message);
    }
    return Boolean(condition);
  }

  equal(actual, expected, message) {
    const same = Object.is(actual, expected) || JSON.stringify(actual) === JSON.stringify(expected);
    return this.ok(same, `${message}\n      expected ${JSON.stringify(expected)}\n      actual   ${JSON.stringify(actual)}`);
  }

  close(actual, expected, tolerance, message) {
    const same =
      actual === expected ||
      (typeof actual === "number" && typeof expected === "number" && Math.abs(actual - expected) <= tolerance);
    return this.ok(same, `${message}\n      expected ${expected}\n      actual   ${actual}`);
  }

  finish(limit = 25) {
    const total = this.passed + this.failures.length;
    const status = this.failures.length === 0 ? "ok  " : "FAIL";
    console.log(`${status} ${this.title}: ${this.passed}/${total}`);
    for (const failure of this.failures.slice(0, limit)) console.log(`    - ${failure}`);
    if (this.failures.length > limit) console.log(`    ... ${this.failures.length - limit} more`);
    return this.failures.length === 0;
  }
}

function differences(actual, expected, tolerance, where, out, limit) {
  if (out.length >= limit) return out;
  if (expected === null || expected === undefined) {
    if (actual !== null && actual !== undefined) out.push(`${where}: expected null, got ${JSON.stringify(actual)}`);
    return out;
  }
  if (typeof expected === "number") {
    const same = typeof actual === "number" && (actual === expected || Math.abs(actual - expected) <= tolerance);
    if (!same) out.push(`${where}: expected ${expected}, got ${JSON.stringify(actual)}`);
    return out;
  }
  if (typeof expected !== "object") {
    if (actual !== expected) out.push(`${where}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    return out;
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) {
      out.push(`${where}: expected a list of ${expected.length}, got ${JSON.stringify(actual)}`);
      return out;
    }
    if (actual.length !== expected.length) {
      out.push(`${where}: expected ${expected.length} item(s), got ${actual.length}: ${JSON.stringify(actual).slice(0, 300)} vs ${JSON.stringify(expected).slice(0, 300)}`);
    }
    for (let i = 0; i < Math.min(actual.length, expected.length); i += 1) {
      differences(actual[i], expected[i], tolerance, `${where}[${i}]`, out, limit);
    }
    return out;
  }
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) {
    out.push(`${where}: expected an object, got ${JSON.stringify(actual)}`);
    return out;
  }
  for (const key of Object.keys(expected)) {
    differences(actual[key], expected[key], tolerance, where ? `${where}.${key}` : key, out, limit);
  }
  for (const key of Object.keys(actual)) {
    if (!(key in expected)) out.push(`${where ? `${where}.` : ""}${key}: unexpected key with ${JSON.stringify(actual[key]).slice(0, 120)}`);
  }
  return out;
}

module.exports = { load, fixture, hasFixture, Report, differences, platform, SRC, ROOT, FIXTURES };
