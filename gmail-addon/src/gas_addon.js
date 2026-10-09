var MT = MT || {};

(function (MT) {
  var API = "https://mailtrace-t9vo.onrender.com";
  var DASHBOARD = "https://mail-trace-three.vercel.app";
  var LABEL_ROOT = "MailTrace";
  var CATEGORIES = ["Phishing", "Fraud-Related", "Impersonated", "Suspicious", "Legitimate"];
  var LABEL_COLORS = {
    Phishing: { backgroundColor: "#fb4c2f", textColor: "#ffffff" },
    "Fraud-Related": { backgroundColor: "#ffad47", textColor: "#000000" },
    Impersonated: { backgroundColor: "#a479e2", textColor: "#ffffff" },
    Suspicious: { backgroundColor: "#fad165", textColor: "#000000" },
    Legitimate: { backgroundColor: "#16a766", textColor: "#ffffff" },
  };
  var TEXT_COLORS = { Phishing: "#c5221f", "Fraud-Related": "#b06000", Impersonated: "#7627bb", Suspicious: "#b06000", Legitimate: "#188038" };
  var SEVERITY_COLORS = { critical: "#a50e0e", high: "#c5221f", medium: "#b06000", low: "#5f6368", info: "#5f6368" };
  var PROPS = { mode: "mt_mode", consent: "mt_consent", trigger: "mt_trigger", labels: "mt_labels", stats: "mt_stats", org: "mt_org", lastScan: "mt_last_scan" };
  var SCAN_QUERY = "in:inbox newer_than:2d";
  var SCAN_LIMIT = 40;
  var MAX_INVESTIGATE_BYTES = 15 * 1024 * 1024;
  var UNDIGESTED = ["simhash:", "tlsh:"];
  var MAX_REASONS = 5;
  var MAX_ACTIONS = 3;

  function props() {
    return PropertiesService.getUserProperties();
  }

  function getProp(key, fallback) {
    var value = props().getProperty(key);
    return value === null || value === undefined ? fallback : value;
  }

  function setProp(key, value) {
    props().setProperty(key, value);
  }

  function isConnected() {
    return getProp(PROPS.mode, "private") === "connected";
  }

  function setMode(connected) {
    setProp(PROPS.mode, connected ? "connected" : "private");
    if (connected) setProp(PROPS.consent, new Date().toISOString());
  }

  function toUnsigned(list) {
    var out = new Uint8Array(list.length);
    for (var i = 0; i < list.length; i += 1) out[i] = list[i] & 0xff;
    return out;
  }

  function utf8Escape(bytes) {
    var out = [];
    var i = 0;
    var length = bytes.length;
    var push = function (code) {
      out.push(code > 0xffff ? String.fromCharCode(0xd800 + ((code - 0x10000) >> 10), 0xdc00 + ((code - 0x10000) & 0x3ff)) : String.fromCharCode(code));
    };
    while (i < length) {
      var b0 = bytes[i];
      if (b0 < 0x80) {
        push(b0);
        i += 1;
        continue;
      }
      var need = b0 >= 0xc2 && b0 <= 0xdf ? 1 : b0 >= 0xe0 && b0 <= 0xef ? 2 : b0 >= 0xf0 && b0 <= 0xf4 ? 3 : 0;
      var code = need === 1 ? b0 & 0x1f : need === 2 ? b0 & 0x0f : b0 & 0x07;
      var ok = need > 0;
      var j = 1;
      while (ok && j <= need) {
        var b = i + j < length ? bytes[i + j] : -1;
        var low = 0x80;
        var high = 0xbf;
        if (j === 1 && need === 2 && b0 === 0xe0) low = 0xa0;
        if (j === 1 && need === 2 && b0 === 0xed) high = 0x9f;
        if (j === 1 && need === 3 && b0 === 0xf0) low = 0x90;
        if (j === 1 && need === 3 && b0 === 0xf4) high = 0x8f;
        if (b < low || b > high) ok = false;
        else code = (code << 6) | (b & 0x3f);
        j += 1;
      }
      if (ok) {
        push(code);
        i += need + 1;
      } else {
        push(0xdc00 + b0);
        i += 1;
      }
    }
    return out.join("");
  }

  function escapeHtml(text) {
    return String(text === undefined || text === null ? "" : text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function clip(text, limit) {
    var value = String(text || "");
    return value.length <= limit ? value : value.slice(0, limit - 1) + "…";
  }

  function orgDomains() {
    var cached = getProp(PROPS.org, null);
    if (cached === null) {
      var domain = "";
      try {
        var profile = Gmail.Users.getProfile("me");
        var address = String((profile && profile.emailAddress) || "").toLowerCase();
        var at = address.lastIndexOf("@");
        if (at >= 0) domain = address.slice(at + 1);
      } catch (error) {
        console.error("profile lookup failed: " + error);
      }
      var registrable = domain ? MT.urls.registrableDomain(domain) || domain : "";
      if (!registrable || MT.K("knowledge").FREEMAIL_DOMAINS.has(registrable)) registrable = "";
      cached = registrable;
      setProp(PROPS.org, cached);
    }
    return cached ? [cached] : [];
  }

  function config() {
    var org = orgDomains();
    return org.length ? { org_domains: org } : {};
  }

  function rawMessage(id) {
    var message = Gmail.Users.Messages.get("me", id, { format: "raw" });
    return {
      id: id,
      threadId: message.threadId || "",
      bytes: toUnsigned(Utilities.base64DecodeWebSafe(message.raw || "")),
      labelIds: message.labelIds || [],
      size: message.sizeEstimate || 0,
    };
  }

  function labelName(category) {
    return LABEL_ROOT + "/" + category;
  }

  function createLabel(category) {
    var body = { name: labelName(category), labelListVisibility: "labelShow", messageListVisibility: "show" };
    try {
      var coloured = {};
      Object.keys(body).forEach(function (key) {
        coloured[key] = body[key];
      });
      coloured.color = LABEL_COLORS[category];
      return Gmail.Users.Labels.create(coloured, "me").id;
    } catch (error) {
      return Gmail.Users.Labels.create(body, "me").id;
    }
  }

  function labelIds() {
    var cached = null;
    try {
      cached = JSON.parse(getProp(PROPS.labels, "null"));
    } catch (error) {
      cached = null;
    }
    var complete =
      cached &&
      CATEGORIES.every(function (category) {
        return typeof cached[category] === "string" && cached[category];
      });
    if (complete) return cached;
    var existing = {};
    var listing = Gmail.Users.Labels.list("me");
    (listing.labels || []).forEach(function (label) {
      existing[label.name] = label.id;
    });
    var ids = {};
    CATEGORIES.forEach(function (category) {
      ids[category] = existing[labelName(category)] || createLabel(category);
    });
    setProp(PROPS.labels, JSON.stringify(ids));
    return ids;
  }

  function mailTraceLabel(currentLabelIds, ids) {
    for (var i = 0; i < CATEGORIES.length; i += 1) {
      if (currentLabelIds.indexOf(ids[CATEGORIES[i]]) >= 0) return CATEGORIES[i];
    }
    return "";
  }

  function applyLabel(id, category, currentLabelIds) {
    var ids = labelIds();
    var add = ids[category];
    var remove = [];
    CATEGORIES.forEach(function (other) {
      if (other !== category && currentLabelIds.indexOf(ids[other]) >= 0) remove.push(ids[other]);
    });
    if (currentLabelIds.indexOf(add) >= 0 && !remove.length) return false;
    Gmail.Users.Messages.modify({ addLabelIds: [add], removeLabelIds: remove }, "me", id);
    return true;
  }

  function post(path, payload) {
    var response = UrlFetchApp.fetch(API + path, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
    });
    var code = response.getResponseCode();
    var text = response.getContentText();
    if (code < 200 || code >= 300) throw new Error("HTTP " + code + " from " + path + ": " + clip(text, 200));
    return JSON.parse(text);
  }

  function sha256Hex(text) {
    return MT.platform.hex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, text, Utilities.Charset.UTF_8));
  }

  function lookup(request) {
    if (!request.domains.length && !request.ips.length) return null;
    return post("/api/intel/lookup", request);
  }

  function match(indicators, fuzzy) {
    var digests = {};
    indicators.forEach(function (indicator) {
      var skip = UNDIGESTED.some(function (prefix) {
        return indicator.slice(0, prefix.length) === prefix;
      });
      if (!skip) digests[sha256Hex(indicator)] = indicator;
    });
    var payload = { fingerprints: Object.keys(digests), simhash: (fuzzy && fuzzy.simhash) || "", body_length: (fuzzy && fuzzy.body_length) || 0 };
    if (!payload.fingerprints.length && !payload.simhash) return { incidents: [], campaign_id: null, campaigns: 0, worst_risk: 0 };
    var response = post("/api/intel/match", payload);
    return {
      incidents: (response.incidents || []).map(function (incident) {
        return {
          email_id: "",
          subject: "",
          sender: "",
          risk_score: incident.risk_score || 0,
          category: incident.category || "Legitimate",
          shared_indicators: (incident.shared || [])
            .map(function (digest) {
              return digests[digest] || digest;
            })
            .concat(incident.fuzzy || []),
        };
      }),
      campaign_id: null,
      campaigns: response.campaigns || 0,
      worst_risk: response.worst_risk || 0,
    };
  }

  function analyze(id) {
    var message = rawMessage(id);
    var connected = isConnected();
    var network = { domains: 0, ips: 0, incidents: 0, campaigns: 0, failed: "" };
    var opts = {};
    if (connected) {
      opts.lookup = function (request) {
        network.domains = request.domains.length;
        network.ips = request.ips.length;
        try {
          return lookup(request);
        } catch (error) {
          network.failed = String(error && error.message ? error.message : error);
          return null;
        }
      };
      opts.match = function (indicators, fuzzy) {
        try {
          var found = match(indicators, fuzzy);
          network.incidents = found.incidents.length;
          network.campaigns = found.campaigns;
          return found;
        } catch (error) {
          network.failed = String(error && error.message ? error.message : error);
          return null;
        }
      };
    }
    var started = Date.now();
    var result = MT.pipeline.analyze(message.bytes, "gmail-" + id + ".eml", config(), opts);
    return { id: id, result: result, message: message, connected: connected, network: network, ms: Date.now() - started };
  }

  function bumpStats(category) {
    var today = new Date().toISOString().slice(0, 10);
    var stats;
    try {
      stats = JSON.parse(getProp(PROPS.stats, "null"));
    } catch (error) {
      stats = null;
    }
    if (!stats || stats.day !== today) stats = { day: today, labelled: 0, categories: {} };
    stats.labelled += 1;
    stats.categories[category] = (stats.categories[category] || 0) + 1;
    setProp(PROPS.stats, JSON.stringify(stats));
    return stats;
  }

  function readStats() {
    var today = new Date().toISOString().slice(0, 10);
    try {
      var stats = JSON.parse(getProp(PROPS.stats, "null"));
      if (stats && stats.day === today) return stats;
    } catch (error) {
      return { day: today, labelled: 0, categories: {} };
    }
    return { day: today, labelled: 0, categories: {} };
  }

  function labelAnalysis(analysis) {
    var category = analysis.result.verdict.category;
    var changed = applyLabel(analysis.id, category, analysis.message.labelIds);
    if (changed) bumpStats(category);
    return changed;
  }

  function scan(budgetMs) {
    var started = Date.now();
    var ids = labelIds();
    var query = SCAN_QUERY;
    CATEGORIES.forEach(function (category) {
      query += " -label:" + labelName(category);
    });
    var listing = Gmail.Users.Messages.list("me", { q: query, maxResults: SCAN_LIMIT });
    var messages = listing.messages || [];
    var counts = { candidates: messages.length, labelled: 0, skipped: 0, failed: 0, stopped: false };
    for (var i = 0; i < messages.length; i += 1) {
      if (Date.now() - started > budgetMs) {
        counts.stopped = true;
        break;
      }
      try {
        var message = rawMessage(messages[i].id);
        if (mailTraceLabel(message.labelIds, ids)) {
          counts.skipped += 1;
          continue;
        }
        var result = MT.pipeline.analyze(message.bytes, "gmail-" + message.id + ".eml", config(), {});
        applyLabel(message.id, result.verdict.category, message.labelIds);
        bumpStats(result.verdict.category);
        counts.labelled += 1;
      } catch (error) {
        counts.failed += 1;
        console.error("scan failed for " + messages[i].id + ": " + (error && error.stack ? error.stack : error));
      }
    }
    setProp(PROPS.lastScan, new Date().toISOString());
    return counts;
  }

  function ensureTrigger() {
    if (getProp(PROPS.trigger, "") === "1") return false;
    var present = ScriptApp.getProjectTriggers().some(function (trigger) {
      return trigger.getHandlerFunction() === "hourlyScan";
    });
    if (!present) ScriptApp.newTrigger("hourlyScan").timeBased().everyHours(1).create();
    setProp(PROPS.trigger, "1");
    return !present;
  }

  function investigate(id) {
    var message = rawMessage(id);
    if (message.size > MAX_INVESTIGATE_BYTES) throw new Error("This email is larger than 15 MB, which is more than the MailTrace server accepts.");
    var response = post("/api/analyze/raw", { raw: utf8Escape(message.bytes), filename: "gmail-" + id + ".eml", origin: "gmail" });
    var result = response.results && response.results[0];
    if (!result || !result.id) throw new Error("The server did not return a case id.");
    var retention = (response.retention || [])[0] || null;
    return {
      id: result.id,
      category: result.verdict.category,
      risk: result.verdict.risk_score,
      url: DASHBOARD + "/#/email/" + result.id,
      expires: retention && retention.expires_at ? retention.expires_at : null,
    };
  }

  function selfTest() {
    var data = MT.json("selftest");
    var started = Date.now();
    var lines = [];
    var ok = true;
    data.cases.forEach(function (item) {
      var raw = MT.bytes.fromBase64(item.raw);
      var line = { name: item.name, expected: item.category + " " + item.risk_score, pass: false, detail: "" };
      try {
        var result = MT.pipeline.analyze(raw, item.name + ".eml", data.config, {});
        var ids = result.findings.map(function (f) {
          return f.module + ":" + f.id;
        });
        var same =
          result.verdict.category === item.category &&
          result.verdict.risk_score === item.risk_score &&
          result.email.raw_sha256 === item.sha256 &&
          JSON.stringify(ids) === JSON.stringify(item.finding_ids);
        line.pass = same;
        line.detail = result.verdict.category + " " + result.verdict.risk_score + (same ? "" : " (expected " + line.expected + ")");
      } catch (error) {
        line.detail = "error: " + clip(String(error && error.message ? error.message : error), 120);
      }
      if (!line.pass) ok = false;
      lines.push(line);
    });
    return { ok: ok, lines: lines, ms: Date.now() - started, engine: MT.json("knowledge").engine_version };
  }

  function messageIdFrom(e) {
    if (e && e.gmail && e.gmail.messageId) return String(e.gmail.messageId);
    return parameter(e, "messageId");
  }

  function parameter(e, name) {
    if (e && e.commonEventObject && e.commonEventObject.parameters && e.commonEventObject.parameters[name] !== undefined) {
      return String(e.commonEventObject.parameters[name]);
    }
    if (e && e.parameters && e.parameters[name] !== undefined) return String(e.parameters[name]);
    return "";
  }

  function formValue(e, name) {
    var inputs = e && e.commonEventObject && e.commonEventObject.formInputs;
    if (inputs && inputs[name] && inputs[name].stringInputs && inputs[name].stringInputs.value && inputs[name].stringInputs.value.length) {
      return String(inputs[name].stringInputs.value[0]);
    }
    if (e && e.formInput && e.formInput[name] !== undefined) return String(e.formInput[name]);
    return "";
  }

  function action(name, parameters) {
    var built = CardService.newAction().setFunctionName(name);
    if (parameters) built.setParameters(parameters);
    return built;
  }

  function paragraph(html) {
    return CardService.newTextParagraph().setText(html);
  }

  function button(text, name, parameters, filled) {
    var built = CardService.newTextButton().setText(text).setOnClickAction(action(name, parameters));
    if (filled) built.setTextButtonStyle(CardService.TextButtonStyle.FILLED);
    return built;
  }

  function linkButton(text, url) {
    return CardService.newTextButton().setText(text).setOpenLink(CardService.newOpenLink().setUrl(url).setOpenAs(CardService.OpenAs.FULL_SIZE));
  }

  function header(title, subtitle) {
    var built = CardService.newCardHeader().setTitle(title);
    if (subtitle) built.setSubtitle(subtitle);
    return built;
  }

  function modeText(connected) {
    return connected
      ? "Connected mode: domains and IP addresses are checked against the MailTrace server and campaigns are matched by hashed fingerprints. Subject, body, addresses and attachments stay in your account."
      : "Private mode: the same rules and model run inside your Google account. Nothing is sent anywhere.";
  }

  function verdictHtml(verdict) {
    var colour = TEXT_COLORS[verdict.category] || "#202124";
    return '<font color="' + colour + '"><b>' + escapeHtml(verdict.category) + "</b></font> &nbsp;·&nbsp; risk " + verdict.risk_score + "/100 &nbsp;·&nbsp; " + escapeHtml(verdict.severity) + " severity";
  }

  function reasonWidget(finding) {
    var colour = SEVERITY_COLORS[finding.severity] || "#5f6368";
    return CardService.newDecoratedText()
      .setTopLabel(finding.severity.toUpperCase())
      .setText('<font color="' + colour + '"><b>' + escapeHtml(finding.title) + "</b></font>")
      .setBottomLabel(clip(finding.detail, 220))
      .setWrapText(true);
  }

  function reasons(findings) {
    var ranked = findings.filter(function (f) {
      return f.severity !== "info";
    });
    if (!ranked.length) ranked = findings.slice(0, 2);
    return ranked.slice(0, MAX_REASONS);
  }

  function messageCard(analysis) {
    var result = analysis.result;
    var verdict = result.verdict;
    var card = CardService.newCardBuilder().setHeader(header("MailTrace verdict", clip(result.email.subject || "(no subject)", 80)));
    var verdictSection = CardService.newCardSection().addWidget(paragraph(verdictHtml(verdict)));
    var sender = result.email.sender && result.email.sender.address ? result.email.sender.address : "";
    if (sender) verdictSection.addWidget(CardService.newDecoratedText().setTopLabel("Sender").setText(escapeHtml(sender)).setWrapText(true));
    var auth = result.headers.auth;
    verdictSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Authentication")
        .setText("SPF " + escapeHtml(auth.spf) + " · DKIM " + escapeHtml(auth.dkim) + " · DMARC " + escapeHtml(auth.dmarc))
        .setWrapText(true),
    );
    var probability = result.nlp.ml_probabilities[result.nlp.ml_category];
    verdictSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Classifier")
        .setText(escapeHtml(result.nlp.ml_category) + (typeof probability === "number" ? " (p=" + probability.toFixed(2) + ")" : ""))
        .setBottomLabel(verdict.dual_validation_agreement ? "Rules and model agree" : "Rules and model disagree; rules decide")
        .setWrapText(true),
    );
    card.addSection(verdictSection);

    var why = CardService.newCardSection().setHeader("Why");
    reasons(result.findings).forEach(function (finding) {
      why.addWidget(reasonWidget(finding));
    });
    card.addSection(why);

    var actions = verdict.recommended_actions.slice(0, MAX_ACTIONS);
    if (actions.length) {
      var todo = CardService.newCardSection().setHeader("What to do");
      actions.forEach(function (text, index) {
        todo.addWidget(paragraph("<b>" + (index + 1) + ".</b> " + escapeHtml(text)));
      });
      card.addSection(todo);
    }

    var footer = CardService.newCardSection().setHeader("Investigate");
    footer.addWidget(
      paragraph(
        "Send this one email to the MailTrace dashboard for the full forensic report. The case is unlisted and is deleted after 24 hours unless you freeze it as evidence.",
      ),
    );
    footer.addWidget(CardService.newButtonSet().addButton(button("Investigate on dashboard", "onInvestigate", { messageId: analysis.id }, true)));
    var note = modeText(analysis.connected);
    if (analysis.connected) {
      if (analysis.network.failed) note += " The server could not be reached for this email, so the result is the private (offline) analysis.";
      else if (analysis.network.incidents) note += " " + analysis.network.incidents + " earlier case(s) share indicators with this email.";
      else note += " No earlier case shares indicators with this email.";
    }
    footer.addWidget(paragraph("<i>" + escapeHtml(note) + "</i>"));
    card.addSection(footer);
    return card.build();
  }

  function homeCard(notice) {
    var connected = isConnected();
    var stats = readStats();
    var card = CardService.newCardBuilder().setHeader(header("MailTrace", "Email forensics inside Gmail"));
    var top = CardService.newCardSection();
    if (notice) top.addWidget(paragraph("<b>" + escapeHtml(notice) + "</b>"));
    var toggle = CardService.newSwitch().setFieldName("connected").setValue("on").setSelected(connected).setOnChangeAction(action("onConnectedSwitch"));
    top.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Mode")
        .setText(connected ? "<b>Connected</b>" : "<b>Private</b> (default)")
        .setBottomLabel(modeText(connected))
        .setWrapText(true)
        .setSwitchControl(toggle),
    );
    card.addSection(top);

    var labels = CardService.newCardSection().setHeader("Labels");
    labels.addWidget(
      paragraph(
        "Every email gets a <b>MailTrace/&lt;Category&gt;</b> label automatically: when you open it and once an hour for new mail. Open any email to see its score and the reasons.",
      ),
    );
    var parts = CATEGORIES.filter(function (category) {
      return stats.categories[category];
    }).map(function (category) {
      return category + " " + stats.categories[category];
    });
    labels.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Labelled today")
        .setText(String(stats.labelled))
        .setBottomLabel(parts.length ? parts.join(" · ") : "Nothing labelled yet today")
        .setWrapText(true),
    );
    labels.addWidget(CardService.newButtonSet().addButton(button("Scan inbox now", "onScanNow", null, true)));
    card.addSection(labels);

    var more = CardService.newCardSection().setHeader("More");
    more.addWidget(CardService.newButtonSet().addButton(linkButton("Open dashboard", DASHBOARD)).addButton(button("Run self-test", "onSelfTest")));
    card.addSection(more);
    return card.build();
  }

  function consentCard() {
    var card = CardService.newCardBuilder().setHeader(header("Turn on Connected mode?"));
    var section = CardService.newCardSection();
    section.addWidget(
      paragraph(
        "<b>What is sent:</b> only the domain names and IP addresses found in an email's headers and links, for reputation and geolocation checks, plus SHA-256 fingerprints of indicators so the server can tell you whether the same campaign was seen before.",
      ),
    );
    section.addWidget(paragraph("<b>What is never sent:</b> the subject, body, addresses, names and attachments. The server keeps nothing from these lookups."));
    section.addWidget(paragraph("You can switch back to Private mode at any time from the MailTrace home screen."));
    section.addWidget(CardService.newButtonSet().addButton(button("Agree and turn on", "onConsentAccept", null, true)).addButton(button("Not now", "onConsentDecline")));
    card.addSection(section);
    return card.build();
  }

  function investigateCard(outcome) {
    var card = CardService.newCardBuilder().setHeader(header("Case created", "MailTrace dashboard"));
    var section = CardService.newCardSection();
    section.addWidget(paragraph("Case <b>" + escapeHtml(outcome.id) + "</b>: " + escapeHtml(outcome.category) + ", risk " + outcome.risk + "/100."));
    var expiry = outcome.expires ? "It will be deleted automatically at " + escapeHtml(outcome.expires.replace("T", " ").slice(0, 16)) + " UTC unless you freeze it as evidence." : "";
    section.addWidget(paragraph("The case is unlisted: only people with the link can open it. " + expiry));
    section.addWidget(CardService.newButtonSet().addButton(linkButton("Open case", outcome.url)));
    card.addSection(section);
    return card.build();
  }

  function selfTestCard(report) {
    var card = CardService.newCardBuilder().setHeader(header(report.ok ? "Self-test passed" : "Self-test failed", "engine " + report.engine + ", " + report.ms + " ms"));
    var section = CardService.newCardSection();
    report.lines.forEach(function (line) {
      var colour = line.pass ? "#188038" : "#c5221f";
      section.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(line.name)
          .setText('<font color="' + colour + '">' + (line.pass ? "pass" : "FAIL") + "</font> " + escapeHtml(line.detail))
          .setWrapText(true),
      );
    });
    section.addWidget(paragraph("<i>Four bundled sample emails were analysed inside your account and compared with the reference verdicts.</i>"));
    card.addSection(section);
    return card.build();
  }

  function infoCard(title, text) {
    return CardService.newCardBuilder().setHeader(header(title)).addSection(CardService.newCardSection().addWidget(paragraph(escapeHtml(text)))).build();
  }

  function errorText(error) {
    var message = String(error && error.message ? error.message : error);
    if (/HTTP 5|Address unavailable|timed out|Timeout|DNS|connect/i.test(message)) {
      return "The MailTrace server did not answer (" + clip(message, 60) + "). Free hosting sleeps when idle; please try again in about a minute.";
    }
    return clip(message, 180);
  }

  function respond(navigation, notice) {
    var builder = CardService.newActionResponseBuilder();
    if (navigation) builder.setNavigation(navigation);
    if (notice) builder.setNotification(CardService.newNotification().setText(clip(notice, 200)));
    return builder.build();
  }

  MT.addon = {
    API: API,
    DASHBOARD: DASHBOARD,
    CATEGORIES: CATEGORIES,
    PROPS: PROPS,
    utf8Escape: utf8Escape,
    escapeHtml: escapeHtml,
    isConnected: isConnected,
    setMode: setMode,
    orgDomains: orgDomains,
    config: config,
    rawMessage: rawMessage,
    labelName: labelName,
    labelIds: labelIds,
    applyLabel: applyLabel,
    labelAnalysis: labelAnalysis,
    match: match,
    lookup: lookup,
    analyze: analyze,
    scan: scan,
    ensureTrigger: ensureTrigger,
    investigate: investigate,
    selfTest: selfTest,
    messageIdFrom: messageIdFrom,
    parameter: parameter,
    formValue: formValue,
    messageCard: messageCard,
    homeCard: homeCard,
    consentCard: consentCard,
    investigateCard: investigateCard,
    selfTestCard: selfTestCard,
    infoCard: infoCard,
    errorText: errorText,
    respond: respond,
    readStats: readStats,
  };
})(MT);

function onHomepage(e) {
  try {
    MT.addon.ensureTrigger();
  } catch (error) {
    console.error("trigger setup failed: " + error);
  }
  return MT.addon.homeCard("");
}

function onMessageOpen(e) {
  var id = MT.addon.messageIdFrom(e);
  if (!id) return MT.addon.infoCard("MailTrace", "Open an email to see its verdict.");
  try {
    MT.addon.ensureTrigger();
  } catch (error) {
    console.error("trigger setup failed: " + error);
  }
  var analysis;
  try {
    analysis = MT.addon.analyze(id);
  } catch (error) {
    console.error("analysis failed: " + (error && error.stack ? error.stack : error));
    return MT.addon.infoCard("MailTrace could not analyse this email", MT.addon.errorText(error));
  }
  try {
    MT.addon.labelAnalysis(analysis);
  } catch (error) {
    console.error("labelling failed: " + error);
  }
  return MT.addon.messageCard(analysis);
}

function onConnectedSwitch(e) {
  var wantsConnected = MT.addon.formValue(e, "connected") === "on";
  if (wantsConnected) return MT.addon.respond(CardService.newNavigation().pushCard(MT.addon.consentCard()), "");
  MT.addon.setMode(false);
  return MT.addon.respond(CardService.newNavigation().updateCard(MT.addon.homeCard("Private mode is on. Nothing leaves your account.")), "");
}

function onConsentAccept(e) {
  MT.addon.setMode(true);
  return MT.addon.respond(CardService.newNavigation().popToRoot().updateCard(MT.addon.homeCard("Connected mode is on.")), "Connected mode is on.");
}

function onConsentDecline(e) {
  MT.addon.setMode(false);
  return MT.addon.respond(CardService.newNavigation().popToRoot().updateCard(MT.addon.homeCard("")), "Private mode stays on.");
}

function onScanNow(e) {
  var counts;
  try {
    counts = MT.addon.scan(20000);
  } catch (error) {
    return MT.addon.respond(null, "Scan failed: " + MT.addon.errorText(error));
  }
  var notice = "Labelled " + counts.labelled + " email(s)";
  if (counts.skipped) notice += ", " + counts.skipped + " already labelled";
  if (counts.failed) notice += ", " + counts.failed + " failed";
  notice += counts.stopped ? ". Tap again for more." : ".";
  return MT.addon.respond(CardService.newNavigation().updateCard(MT.addon.homeCard("")), notice);
}

function onInvestigate(e) {
  var id = MT.addon.parameter(e, "messageId");
  if (!id) return MT.addon.respond(null, "Open an email first.");
  var outcome;
  try {
    outcome = MT.addon.investigate(id);
  } catch (error) {
    console.error("investigate failed: " + (error && error.stack ? error.stack : error));
    return MT.addon.respond(null, MT.addon.errorText(error));
  }
  return MT.addon.respond(CardService.newNavigation().pushCard(MT.addon.investigateCard(outcome)), "Case " + outcome.id + " created.");
}

function onSelfTest(e) {
  var report = MT.addon.selfTest();
  return MT.addon.respond(CardService.newNavigation().pushCard(MT.addon.selfTestCard(report)), report.ok ? "Self-test passed." : "Self-test failed.");
}

function hourlyScan() {
  var counts = MT.addon.scan(240000);
  console.log("hourly scan: " + JSON.stringify(counts));
}
