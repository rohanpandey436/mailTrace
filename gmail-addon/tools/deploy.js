"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const { bundle } = require("./bundle");

const ROOT = path.join(__dirname, "..");
const CLASP_JSON = path.join(ROOT, ".clasp.json");
const NPX = process.platform === "win32" ? "npx.cmd" : "npx";

function clasp(args) {
  const run = spawnSync(NPX, ["--no-install", "clasp", ...args], { cwd: ROOT, stdio: ["inherit", "pipe", "pipe"], shell: process.platform === "win32" });
  const out = `${run.stdout || ""}${run.stderr || ""}`;
  process.stdout.write(out);
  return { code: run.status === null ? 1 : run.status, out };
}

function fail(message) {
  console.error(`\n${message}`);
  process.exit(1);
}

function scriptId() {
  try {
    return JSON.parse(fs.readFileSync(CLASP_JSON, "utf8")).scriptId || "";
  } catch (error) {
    return "";
  }
}

function main() {
  const built = bundle();
  console.log(`built dist/ with ${built.files.length} files`);

  const status = clasp(["login", "--status"]);
  if (status.code !== 0 || /not logged in/i.test(status.out)) {
    fail("You are not logged in to clasp yet. Run:  npx clasp login   (a browser window opens; sign in with the Google account that will use the add-on) and then run  npm run deploy  again.");
  }

  if (!scriptId()) {
    console.log("creating the Apps Script project ...");
    const created = clasp(["create-script", "--title", "MailTrace", "--type", "standalone", "--rootDir", "dist"]);
    if (created.code !== 0 || !scriptId()) {
      if (/Apps Script API/i.test(created.out) || /disabled/i.test(created.out)) {
        fail("The Apps Script API is switched off for your account. Open https://script.google.com/home/usersettings , turn on 'Google Apps Script API', wait a minute and run  npm run deploy  again.");
      }
      fail("clasp could not create the project (see the message above).");
    }
  }

  console.log("pushing the add-on code ...");
  const pushed = clasp(["push", "--force"]);
  if (pushed.code !== 0) fail("clasp push failed (see the message above).");

  const id = scriptId();
  console.log("\nDone. Last step, in your browser:");
  console.log(`  1. Open https://script.google.com/d/${id}/edit`);
  console.log("  2. Click Deploy > Test deployments > Install, then Done.");
  console.log("  3. Open Gmail, click any email and open MailTrace in the right-hand side panel. Grant access when asked.");
}

main();
