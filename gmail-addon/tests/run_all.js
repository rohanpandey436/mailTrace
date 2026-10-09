"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const TESTS = ["test_py", "test_html", "test_binary", "test_message", "test_mime", "test_codecs", "test_urls", "test_models", "test_pipeline", "test_addon"];

function main(argv) {
  const fuzz = argv.includes("--fuzz");
  const chosen = argv.filter((item) => !item.startsWith("--"));
  let failed = 0;
  for (const name of TESTS) {
    if (chosen.length && !chosen.includes(name)) continue;
    const file = path.join(__dirname, `${name}.js`);
    if (!fs.existsSync(file)) continue;
    const args = [file];
    if (fuzz && name === "test_pipeline") args.push("--fuzz");
    const started = Date.now();
    const run = spawnSync(process.execPath, args, { stdio: "inherit" });
    const seconds = ((Date.now() - started) / 1000).toFixed(1);
    console.log(`     ${name}: exit ${run.status} in ${seconds}s\n`);
    if (run.status !== 0) failed += 1;
  }
  console.log(failed ? `${failed} test file(s) failed` : "all test files passed");
  return failed === 0;
}

if (require.main === module) process.exit(main(process.argv.slice(2)) ? 0 : 1);
