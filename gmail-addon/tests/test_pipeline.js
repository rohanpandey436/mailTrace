"use strict";

const { load, fixture, hasFixture, Report, differences } = require("./harness");

const STAGES = ["email", "headers", "urls", "attachments", "nlp", "domains", "infrastructure", "intel", "attribution", "verdict", "findings"];

function compareStage(report, name, stage, actual, expected, tolerance) {
  if (actual === undefined) return;
  const found = differences(actual, expected, tolerance, stage, [], 8);
  report.ok(found.length === 0, `${name} ${stage}:\n      ${found.join("\n      ")}`);
}

function run(argv) {
  const MT = load();
  const filter = argv[0] && !argv[0].startsWith("--") ? argv[0] : "";
  const useFuzz = argv.includes("--fuzz");
  const source = useFuzz && hasFixture("pipeline_vectors.json") ? fixture("pipeline_vectors.json") : fixture("expected.json");
  const config = source.config;
  const traced = [];
  MT.trace = (error) => {
    if (error && /^(TypeError|ReferenceError|RangeError|SyntaxError)$/.test(error.name)) traced.push(error);
  };
  const reports = new Map();
  STAGES.forEach((stage) => reports.set(stage, new Report(`${stage} like Python`)));
  let ran = 0;
  for (const item of source.cases) {
    if (filter && !item.name.includes(filter)) continue;
    const raw = MT.bytes.fromBase64(item.raw);
    let result;
    try {
      result = MT.pipeline.analyze(raw, item.name.split("/").pop() + ".eml", config, {});
    } catch (error) {
      reports.get("email").ok(false, `${item.name}: pipeline threw ${error.name}: ${error.message}\n${error.stack}`);
      continue;
    }
    ran += 1;
    for (const stage of STAGES) {
      if (!(stage in item.expected)) continue;
      compareStage(reports.get(stage), item.name, stage, result[stage], item.expected[stage], 1e-9);
    }
  }
  const ok = STAGES.map((stage) => reports.get(stage).finish(6)).every(Boolean);
  console.log(`     ${ran} email(s) analysed from ${useFuzz ? "pipeline_vectors.json" : "expected.json"}`);
  if (traced.length) {
    console.log(`     ${traced.length} unexpected JavaScript error(s) were swallowed, first: ${traced[0].stack}`);
    return false;
  }
  return ok;
}

if (require.main === module) process.exit(run(process.argv.slice(2)) ? 0 : 1);

module.exports = { run };
