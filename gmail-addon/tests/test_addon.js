"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const zlib = require("zlib");
const { Report, SRC } = require("./harness");
const { bundle, DIST } = require("../tools/bundle");

const SURROGATE_VECTORS = [
  { bytes: [112, 108, 97, 105, 110, 32, 97, 115, 99, 105, 105], text: "plain ascii" },
  { bytes: [99, 97, 102, 195, 169, 32, 226, 130, 185, 32, 240, 159, 152, 128], text: "café ₹ 😀" },
  { bytes: [255, 254, 32, 98, 97, 100], text: "\udcff\udcfe bad" },
  { bytes: [195], text: "\udcc3" },
  { bytes: [226, 130], text: "\udce2\udc82" },
  { bytes: [237, 160, 128, 32, 244, 144, 128, 128, 32, 192, 175], text: "\udced\udca0\udc80 \udcf4\udc90\udc80\udc80 \udcc0\udcaf" },
  { bytes: [224, 164, 185, 224, 164, 191, 32, 224, 128, 128], text: "हि \udce0\udc80\udc80" },
];

function signed(bytes) {
  return Array.from(bytes, (b) => ((b & 0xff) > 127 ? (b & 0xff) - 256 : b & 0xff));
}

function unsigned(list) {
  return Uint8Array.from(list, (b) => b & 0xff);
}

function blob(bytes, contentType) {
  const data = Buffer.from(unsigned(bytes));
  return {
    getBytes: () => signed(data),
    getContentType: () => contentType || "",
    getDataAsString(charset) {
      let decoder;
      try {
        decoder = new TextDecoder(charset || "utf-8", { fatal: false, ignoreBOM: true });
      } catch (error) {
        throw new Error(`Unsupported charset ${charset}`);
      }
      return decoder.decode(data);
    },
  };
}

function utilities() {
  return {
    DigestAlgorithm: { SHA_256: "sha256", MD5: "md5" },
    Charset: { UTF_8: "utf8", US_ASCII: "ascii" },
    newBlob: (data, contentType) => blob(typeof data === "string" ? Buffer.from(data, "utf8") : unsigned(data), contentType),
    ungzip: (input) => blob(zlib.gunzipSync(Buffer.from(unsigned(input.getBytes())))),
    computeDigest: (algorithm, value) =>
      signed(crypto.createHash(algorithm).update(typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(unsigned(value))).digest()),
    base64DecodeWebSafe: (text) => signed(Buffer.from(text, "base64url")),
    base64EncodeWebSafe: (bytes) => Buffer.from(unsigned(bytes)).toString("base64url"),
  };
}

function builder(type) {
  const state = { type };
  const self = new Proxy(
    {},
    {
      get(_, prop) {
        if (prop === "build") return () => state;
        if (prop === "state") return state;
        if (prop === "toJSON") return () => state;
        if (typeof prop !== "string") return undefined;
        const unwrap = (value) => (value && typeof value === "object" && value.state ? value.state : value);
        if (["pushCard", "updateCard", "popCard", "popToRoot"].includes(prop)) {
          return (value) => {
            (state.steps = state.steps || []).push({ [prop]: unwrap(value) });
            return self;
          };
        }
        if (prop.startsWith("add")) {
          return (value) => {
            const key = `${prop.slice(3).toLowerCase()}s`;
            (state[key] = state[key] || []).push(unwrap(value));
            return self;
          };
        }
        if (prop.startsWith("set")) {
          return (value) => {
            const key = prop.slice(3);
            state[key.charAt(0).toLowerCase() + key.slice(1)] = unwrap(value);
            return self;
          };
        }
        return undefined;
      },
    },
  );
  return self;
}

function cardService() {
  const constants = {
    TextButtonStyle: { FILLED: "FILLED", TEXT: "TEXT" },
    OpenAs: { FULL_SIZE: "FULL_SIZE", OVERLAY: "OVERLAY" },
    ImageStyle: { CIRCLE: "CIRCLE", SQUARE: "SQUARE" },
    Icon: { NONE: "NONE" },
  };
  return new Proxy(constants, {
    get(target, prop) {
      if (prop in target) return target[prop];
      if (typeof prop === "string" && prop.startsWith("new")) return () => builder(prop.slice(3));
      return undefined;
    },
  });
}

function propertiesService() {
  const store = new Map();
  const user = {
    getProperty: (key) => (store.has(key) ? store.get(key) : null),
    setProperty(key, value) {
      store.set(key, String(value));
      return user;
    },
    deleteProperty(key) {
      store.delete(key);
      return user;
    },
    getProperties: () => Object.fromEntries(store),
  };
  return { service: { getUserProperties: () => user, getScriptProperties: () => user }, store };
}

function mailbox(profile) {
  const state = { profile, labels: [], messages: new Map(), modifications: [], listed: [] };
  const service = {
    Users: {
      getProfile: () => ({ emailAddress: state.profile }),
      Labels: {
        list: () => ({ labels: state.labels.map((label) => ({ ...label })) }),
        create(body) {
          if (body.color && body.color.backgroundColor === "#bad") throw new Error("Invalid color");
          const id = `Label_${state.labels.length + 1}`;
          state.labels.push({ id, name: body.name, color: body.color || null });
          return { id, name: body.name };
        },
      },
      Messages: {
        get(user, id, options) {
          const message = state.messages.get(id);
          if (!message) throw new Error(`Not Found: ${id}`);
          const out = { id, threadId: message.threadId, labelIds: message.labelIds.slice(), sizeEstimate: message.size };
          if (options && options.format === "raw") out.raw = message.raw;
          return out;
        },
        list(user, options) {
          state.listed.push(options.q);
          return { messages: Array.from(state.messages.keys()).map((id) => ({ id, threadId: "thread" })).slice(0, options.maxResults) };
        },
        modify(body, user, id) {
          const message = state.messages.get(id);
          message.labelIds = message.labelIds.filter((label) => !(body.removeLabelIds || []).includes(label));
          (body.addLabelIds || []).forEach((label) => {
            if (!message.labelIds.includes(label)) message.labelIds.push(label);
          });
          state.modifications.push({ id, body });
          return {};
        },
      },
    },
  };
  return { service, state };
}

function urlFetch() {
  const state = { calls: [], routes: {}, failure: null };
  const service = {
    fetch(url, options) {
      state.calls.push({ url, options });
      if (state.failure) throw new Error(state.failure);
      const route = Object.keys(state.routes).find((prefix) => url.includes(prefix));
      const reply = route ? state.routes[route](JSON.parse(options.payload || "{}")) : { code: 404, body: { detail: "no route" } };
      return { getResponseCode: () => reply.code || 200, getContentText: () => JSON.stringify(reply.body) };
    },
  };
  return { service, state };
}

function scriptApp() {
  const state = { triggers: [] };
  const service = {
    getProjectTriggers: () => state.triggers.map((name) => ({ getHandlerFunction: () => name })),
    newTrigger(name) {
      const chain = { timeBased: () => chain, everyHours: () => chain, create: () => state.triggers.push(name) && chain };
      return chain;
    },
  };
  return { service, state };
}

function environment(files, options) {
  const opts = options || {};
  const props = propertiesService();
  const mail = mailbox(opts.profile || "rohan@acme-corp.in");
  const fetcher = urlFetch();
  const triggers = scriptApp();
  const logs = [];
  const sandbox = {
    Utilities: utilities(),
    CardService: cardService(),
    PropertiesService: props.service,
    Gmail: mail.service,
    UrlFetchApp: fetcher.service,
    ScriptApp: triggers.service,
    console: { log: (line) => logs.push(String(line)), error: (line) => logs.push(`ERROR ${line}`), warn: (line) => logs.push(String(line)) },
    Date,
    JSON,
    Math,
    Map,
    Set,
    Uint8Array,
    Float64Array,
    DataView,
    ArrayBuffer,
    RegExp,
    String,
    Number,
    Array,
    Object,
    Error,
    TypeError,
    RangeError,
  };
  const context = vm.createContext(sandbox);
  for (const file of files) vm.runInContext(fs.readFileSync(file, "utf8"), context, { filename: file });
  return { context, props, mail, fetcher, triggers, logs };
}

function sourceFiles() {
  return fs
    .readdirSync(SRC)
    .filter((name) => name.endsWith(".js"))
    .sort()
    .map((name) => path.join(SRC, name));
}

function distFiles() {
  bundle();
  return fs
    .readdirSync(DIST)
    .filter((name) => name.endsWith(".js"))
    .sort((a, b) => (a === "MailTrace.js" ? -1 : b === "MailTrace.js" ? 1 : a.localeCompare(b)))
    .map((name) => path.join(DIST, name));
}

function text(node) {
  return JSON.stringify(node);
}

function seedMailbox(env, MT) {
  const data = MT.json("selftest");
  data.cases.forEach((item, index) => {
    const raw = Buffer.from(item.raw, "base64");
    env.mail.state.messages.set(`m${index + 1}`, { threadId: `t${index + 1}`, raw: raw.toString("base64url"), labelIds: ["INBOX"], size: raw.length });
  });
  return data;
}

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function geo(ip, overrides) {
  return {
    ip,
    country: "Russia",
    country_code: "RU",
    region: "Moscow",
    city: "Moscow",
    lat: 55.75,
    lon: 37.62,
    isp: "Bulletproof Hosting LLC",
    org: "Bulletproof Hosting LLC",
    asn: "AS64512",
    reverse_dns: "",
    is_private: false,
    is_proxy: false,
    is_hosting: true,
    is_mobile: false,
    is_tor_exit: false,
    blacklists: [],
    abuse_confidence: null,
    source: "ip-api",
    ...overrides,
  };
}

function domainIntel(domain, role) {
  return {
    domain,
    role,
    registrar: "Example Registrar",
    created: "2026-09-01T00:00:00Z",
    expires: null,
    age_days: 12,
    registrant_country: "",
    name_servers: [],
    mx: ["mx.example.net"],
    a_records: ["203.0.113.10"],
    spf_record: "",
    dmarc_record: "",
    has_mx: true,
    resolves: true,
    is_free_mail: false,
    is_disposable: false,
    lookalike_of: "",
    lookalike_technique: "",
    hosting_fingerprint: "",
    reputation: [],
    source: "live",
    findings: [
      {
        id: "domain_intel",
        module: "domains",
        severity: "info",
        title: `Domain intelligence: ${domain}`,
        detail: `role ${role}; registered 12 days ago.`,
        evidence: { domain, role, age_days: 12, mx: ["mx.example.net"], a_records: ["203.0.113.10"], reputation: [], source: "live" },
      },
      {
        id: "newly_registered_domain",
        module: "domains",
        severity: "high",
        title: "Newly registered sender domain",
        detail: `${domain} was registered 12 days ago.`,
        evidence: { domain, age_days: 12 },
      },
    ],
  };
}

function run() {
  const report = new Report("Gmail add-on behaviour");
  const env = environment(sourceFiles());
  const { context } = env;
  const MT = context.MT;
  const data = seedMailbox(env, MT);

  SURROGATE_VECTORS.forEach((vector, index) => {
    report.equal(MT.addon.utf8Escape(Uint8Array.from(vector.bytes)), vector.text, `surrogateescape vector ${index}`);
  });

  const manifest = JSON.parse(fs.readFileSync(path.join(SRC, "appsscript.json"), "utf8"));
  report.ok(manifest.addOns.gmail.contextualTriggers[0].onTriggerFunction === "onMessageOpen", "manifest wires onMessageOpen");
  report.ok(manifest.addOns.common.homepageTrigger.runFunction === "onHomepage", "manifest wires onHomepage");
  report.ok(manifest.urlFetchWhitelist.length === 1 && manifest.urlFetchWhitelist[0].startsWith(MT.addon.API), "manifest restricts UrlFetch to the MailTrace API");
  report.ok(manifest.oauthScopes.includes("https://www.googleapis.com/auth/gmail.modify"), "manifest requests gmail.modify for raw access and labels");
  ["onHomepage", "onMessageOpen", "onConnectedSwitch", "onConsentAccept", "onConsentDecline", "onScanNow", "onInvestigate", "onSelfTest", "hourlyScan"].forEach((name) => {
    report.ok(typeof context[name] === "function", `global handler ${name} exists`);
  });

  const home = context.onHomepage({});
  report.ok(text(home).includes("Private"), "homepage shows Private mode by default");
  report.ok(env.triggers.state.triggers.includes("hourlyScan"), "homepage creates the hourly trigger");
  report.ok(!MT.addon.isConnected(), "default mode is private");
  report.equal(env.fetcher.state.calls.length, 0, "private mode makes no network calls");

  const opened = context.onMessageOpen({ gmail: { messageId: "m1", threadId: "t1" } });
  const openedText = text(opened);
  report.ok(openedText.includes("Phishing"), "message card names the Phishing verdict");
  report.ok(openedText.includes("Investigate on dashboard"), "message card offers Investigate");
  report.ok(openedText.includes("Nothing is sent anywhere"), "message card explains private mode");
  const phishingLabel = env.mail.state.labels.find((label) => label.name === "MailTrace/Phishing");
  report.ok(Boolean(phishingLabel), "MailTrace/Phishing label was created");
  report.ok(env.mail.state.labels.length === 5, "all five category labels were created");
  report.ok(phishingLabel && phishingLabel.color && phishingLabel.color.backgroundColor === "#fb4c2f", "Phishing label is red");
  report.ok(env.mail.state.messages.get("m1").labelIds.includes(phishingLabel.id), "opened message carries the Phishing label");
  report.equal(env.fetcher.state.calls.length, 0, "opening a message in private mode makes no network calls");
  report.equal(env.props.store.get("mt_org"), "acme-corp.in", "organisation domain derived from the profile");
  const modifications = env.mail.state.modifications.length;
  context.onMessageOpen({ gmail: { messageId: "m1" } });
  report.equal(env.mail.state.modifications.length, modifications, "re-opening a labelled message does not modify it again");

  const noMessage = context.onMessageOpen({});
  report.ok(text(noMessage).includes("Open an email"), "missing message id gives a friendly card");

  const senderAddress = "alerts@sbi-kyc-update.xyz";
  const subjectText = "Your SBI account will be suspended";
  env.fetcher.state.routes["/api/intel/lookup"] = (payload) => {
    report.ok(Array.isArray(payload.domains) && payload.domains.every((item) => item.domain && item.role), "lookup payload lists domains with roles");
    report.ok(Array.isArray(payload.ips), "lookup payload lists ips");
    const domains = payload.domains.map((item) => domainIntel(item.domain, item.role));
    const ips = payload.ips.map((ip) => geo(ip, ip === payload.origin_ip ? { is_tor_exit: true } : {}));
    return { code: 200, body: { domains, ips, network: true, stored: false } };
  };
  let matchPayload = null;
  env.fetcher.state.routes["/api/intel/match"] = (payload) => {
    matchPayload = payload;
    return {
      code: 200,
      body: {
        incidents: [{ risk_score: 88, category: "Phishing", analyzed_at: null, in_campaign: true, shared: payload.fingerprints.slice(0, 2), fuzzy: ["simhash~2"] }],
        campaigns: 1,
        worst_risk: 88,
        stored: false,
      },
    };
  };
  const switched = context.onConnectedSwitch({ commonEventObject: { formInputs: { connected: { stringInputs: { value: ["on"] } } } } });
  report.ok(text(switched).includes("Turn on Connected mode?"), "switching on shows the consent card");
  report.ok(!MT.addon.isConnected(), "consent card alone does not enable connected mode");
  context.onConsentAccept({});
  report.ok(MT.addon.isConnected(), "accepting consent enables connected mode");
  report.ok(Boolean(env.props.store.get("mt_consent")), "consent time recorded");

  const connected = MT.addon.analyze("m1");
  const findingIds = connected.result.findings.map((f) => `${f.module}:${f.id}`);
  report.ok(findingIds.includes("intel:known_campaign_overlap"), "connected analysis reports the campaign overlap");
  report.ok(findingIds.includes("geoip:tor_exit_node"), "connected analysis uses the server geolocation (tor exit)");
  report.ok(findingIds.includes("domains:newly_registered_domain"), "connected analysis uses the server domain intelligence");
  report.ok(connected.result.intel.related_incidents.length === 1 && connected.result.intel.related_incidents[0].risk_score === 88, "related incident mapped from the match response");
  report.ok(
    connected.result.intel.related_incidents[0].shared_indicators.every((item) => /^[a-z]+:/.test(item) || /^simhash~/.test(item)),
    "shared digests were mapped back to indicator names",
  );
  report.ok(matchPayload && matchPayload.fingerprints.every((item) => /^[0-9a-f]{64}$/.test(item)), "campaign matching sends SHA-256 fingerprints only");
  report.ok(matchPayload && matchPayload.fingerprints.includes(digest(`sender:${senderAddress}`)), "fingerprints include the hashed sender indicator");
  const payloads = env.fetcher.state.calls.map((call) => call.options.payload);
  report.ok(payloads.length === 2, "connected analysis makes exactly two calls");
  report.ok(payloads.every((payload) => !payload.includes(senderAddress)), "no payload carries the sender address in clear");
  report.ok(payloads.every((payload) => !payload.includes(subjectText) && !payload.includes("sbi.kyc.helpdesk@gmail.com")), "no payload carries the subject, body or reply-to address");
  report.ok(env.fetcher.state.calls.every((call) => call.url.startsWith(MT.addon.API)), "all calls go to the MailTrace API");
  const connectedCard = text(MT.addon.messageCard(connected));
  report.ok(connectedCard.includes("1 earlier case(s)"), "connected card mentions the earlier case");

  env.fetcher.state.failure = "Address unavailable";
  const degraded = MT.addon.analyze("m2");
  report.ok(degraded.result.verdict.category === "Legitimate", "server failure still yields the offline verdict");
  report.ok(text(MT.addon.messageCard(degraded)).includes("could not be reached"), "server failure is explained on the card");
  env.fetcher.state.failure = null;

  env.fetcher.state.routes["/api/analyze/raw"] = (payload) => {
    report.equal(payload.origin, "gmail", "investigate submits origin gmail");
    report.ok(payload.filename.startsWith("gmail-m1"), "investigate names the file after the message");
    const raw = Buffer.from(env.mail.state.messages.get("m1").raw, "base64url");
    report.equal(payload.raw, MT.addon.utf8Escape(raw), "investigate sends the exact raw bytes");
    return {
      code: 200,
      body: {
        results: [{ id: "abc123def456", verdict: { category: "Phishing", risk_score: 83 } }],
        alerts: [],
        retention: [{ email_id: "abc123def456", origin: "gmail", listed: false, state: "expiring", expires_at: "2026-10-01T10:00:00Z" }],
      },
    };
  };
  const investigated = context.onInvestigate({ commonEventObject: { parameters: { messageId: "m1" } } });
  const investigatedText = text(investigated);
  report.ok(investigatedText.includes(`${MT.addon.DASHBOARD}/#/email/abc123def456`), "investigate links to the dashboard case");
  report.ok(investigatedText.includes("deleted automatically"), "investigate explains the 24 hour deletion");
  env.fetcher.state.failure = "Address unavailable: mailtrace-t9vo.onrender.com";
  const failed = context.onInvestigate({ parameters: { messageId: "m1" } });
  report.ok(text(failed).includes("try again in about a minute"), "sleeping server gives a retry hint");
  env.fetcher.state.failure = null;

  MT.addon.setMode(false);
  const scanned = context.onScanNow({});
  const scannedText = text(scanned);
  report.ok(scannedText.includes("Labelled 3 email(s)"), `scan labels the three unlabelled messages (${scannedText.slice(0, 120)})`);
  report.ok(scannedText.includes("1 already labelled"), "scan skips the already labelled message");
  report.ok(env.mail.state.listed[0].includes("-label:MailTrace/Phishing"), "scan query excludes labelled mail");
  const expected = Object.fromEntries(data.cases.map((item, index) => [`m${index + 1}`, item.category]));
  Object.keys(expected).forEach((id) => {
    const label = env.mail.state.labels.find((item) => item.name === `MailTrace/${expected[id]}`);
    report.ok(env.mail.state.messages.get(id).labelIds.includes(label.id), `${id} labelled ${expected[id]}`);
  });
  report.ok(text(context.onHomepage({})).includes('"text":"4"'), "homepage counts four labelled emails today");

  const declined = context.onConsentDecline({});
  report.ok(text(declined).includes("Private mode stays on"), "declining consent keeps private mode");

  const selfTest = context.onSelfTest({});
  report.ok(text(selfTest).includes("Self-test passed"), "bundled self-test passes in the source layout");

  const dist = environment(distFiles());
  seedMailbox(dist, dist.context.MT);
  const distSelfTest = text(dist.context.onSelfTest({}));
  report.ok(distSelfTest.includes("Self-test passed"), "bundled self-test passes in the dist layout");
  const distOpen = text(dist.context.onMessageOpen({ gmail: { messageId: "m3" } }));
  report.ok(distOpen.includes("Fraud-Related"), "dist bundle analyses a fraud sample");
  const errors = env.logs.concat(dist.logs).filter((line) => line.startsWith("ERROR") && !/investigate failed|profile lookup/.test(line));
  report.ok(errors.length === 0, `no unexpected errors were logged: ${errors.slice(0, 3).join(" | ")}`);
  return report.finish(12);
}

if (require.main === module) process.exit(run() ? 0 : 1);

module.exports = { run, environment, sourceFiles, distFiles };
