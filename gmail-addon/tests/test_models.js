"use strict";

const { load, fixture, Report } = require("./harness");

const f = Math.fround;

function leafWeights(model, row) {
  return model.trees.map((nodes) => {
    let node = nodes[0];
    while (!node.leaf) {
      const value = f(row[node.feature]);
      const next = value !== value ? (node.missingYes ? node.yes : node.no) : value < node.threshold ? node.yes : node.no;
      node = nodes[next];
    }
    return node.weight;
  });
}

function partitioned(weights, threads) {
  const base = Math.floor(weights.length / threads);
  const remainder = weights.length % threads;
  let start = 0;
  let total = 0;
  for (let block = 0; block < threads; block += 1) {
    const size = base + (block < remainder ? 1 : 0);
    let partial = 0;
    for (let i = start; i < start + size; i += 1) partial = f(partial + weights[i]);
    total = f(total + partial);
    start += size;
  }
  return total;
}

function urlModel(MT) {
  const report = new Report("URL model like onnxruntime (single thread)");
  const model = MT.urlmodel.load();
  const vectors = fixture("url_model_vectors.json");
  const rows = vectors.map((v) => v.features.map((x) => (x === null ? NaN : x)));
  rows.forEach((row, i) => {
    report.close(MT.urlmodel.probability(row), vectors[i].probability, 0, `vector ${i}`);
  });
  const ok = report.finish(5);
  if (!ok) {
    const counts = [];
    for (let threads = 1; threads <= 64; threads += 1) {
      let matched = 0;
      rows.forEach((row, i) => {
        const p = MT.urlmodel.logistic(f(partitioned(leafWeights(model, row), threads) + model.baseValue));
        if (p === vectors[i].probability) matched += 1;
      });
      counts.push([threads, matched]);
    }
    counts.sort((a, b) => b[1] - a[1]);
    console.log(`     best thread partition: ${counts[0][0]} thread(s) reproduce ${counts[0][1]}/${rows.length}; regenerate the vectors with intra_op_num_threads=1`);
  }
  return ok;
}

function textModel(MT) {
  const report = new Report("text model like scikit-learn");
  const vectors = fixture("text_vectors.json");
  for (const vector of vectors) {
    const where = JSON.stringify(vector.text.slice(0, 40));
    const prediction = MT.textmodel.predict(vector.text);
    report.equal(prediction.label, vector.label, `${where} label`);
    for (const label of Object.keys(vector.probabilities)) {
      report.close(prediction.probabilities[label], vector.probabilities[label], 1e-12, `${where} probability ${label}`);
    }
    const shap = MT.textmodel.shapValues(vector.text, vector.label, 12, prediction.features);
    report.equal(
      shap.map((item) => item[0]),
      vector.shap.map((item) => item[0]),
      `${where} shap tokens`,
    );
    shap.forEach((item, i) => {
      if (vector.shap[i]) report.close(item[1], vector.shap[i][1], 1e-12, `${where} shap weight ${item[0]}`);
    });
    report.equal(MT.textmodel.explain(vector.text, vector.label, 8, prediction.features), vector.explain, `${where} explain`);
  }
  return report.finish(8);
}

function run() {
  const MT = load();
  const results = [urlModel(MT), textModel(MT)];
  return results.every(Boolean);
}

if (require.main === module) process.exit(run() ? 0 : 1);

module.exports = { run };
