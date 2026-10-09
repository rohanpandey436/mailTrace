"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const SRC = path.join(ROOT, "src");
const DIST = path.join(ROOT, "dist");

function sourceFiles() {
  const names = fs.readdirSync(SRC).sort();
  const engine = names.filter((name) => name.startsWith("mt_") && name.endsWith(".js"));
  const glue = names.filter((name) => name.startsWith("gas_") && name.endsWith(".js"));
  const data = names.filter((name) => name.startsWith("data_") && name.endsWith(".js"));
  return { engine, glue, data };
}

function bundle() {
  const { engine, glue, data } = sourceFiles();
  fs.rmSync(DIST, { recursive: true, force: true });
  fs.mkdirSync(DIST, { recursive: true });
  const parts = [...engine, ...glue].map((name) => fs.readFileSync(path.join(SRC, name), "utf8").replace(/\s+$/, "") + "\n");
  const code = parts.join("\n");
  fs.writeFileSync(path.join(DIST, "MailTrace.js"), code);
  for (const name of data) fs.copyFileSync(path.join(SRC, name), path.join(DIST, name));
  fs.copyFileSync(path.join(SRC, "appsscript.json"), path.join(DIST, "appsscript.json"));
  const written = fs.readdirSync(DIST).map((name) => `${name} (${fs.statSync(path.join(DIST, name)).size} bytes)`);
  return { files: written, engine, glue, data };
}

if (require.main === module) {
  const built = bundle();
  console.log(`bundled ${built.engine.length} engine + ${built.glue.length} add-on files and ${built.data.length} data files into dist/`);
  for (const line of built.files) console.log(`  ${line}`);
}

module.exports = { bundle, sourceFiles, DIST, SRC };
