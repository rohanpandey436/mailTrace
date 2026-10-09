var MT = MT || {};

(function (MT) {
  var SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  var LEGITIMATE = "Legitimate";
  var SHAP_TOP_K = 12;
  var ATTRIBUTION_METHOD = { linear: "exact-shap-linear", transformer: "occlusion", unavailable: "none" };
  var SCAM_TITLES = {
    extortion: ["extortion_demand", "Money demanded under threat", "Extortion indicators"],
    violent_threat: ["violent_threat_pattern", "Violent threat", "Threat indicators"],
    investment_scam: ["investment_scam", "Investment scam lure", "Investment-scam indicators"],
    callback_scam: ["callback_scam", "Tech-support / call-back scam", "Call-back scam indicators"],
  };
  var UPPER = /^\p{Lu}$/u;

  function py() {
    return MT.py;
  }

  function K() {
    return MT.K("ai_engine");
  }

  function RX(name) {
    return MT.RX("ai_engine", name);
  }

  function pattern(name) {
    return MT.RX("ai_engine", "_PATTERNS." + name);
  }

  function dedupe(items) {
    var seen = new Set();
    var out = [];
    items.forEach(function (item) {
      if (item && !seen.has(item)) {
        seen.add(item);
        out.push(item);
      }
    });
    return out.slice(0, 8);
  }

  function hits(name, text) {
    var seen = new Set();
    var found = [];
    var collapse = py().re("\\s+");
    pattern(name)
      .finditer(text)
      .forEach(function (match) {
        var phrase = collapse.sub(" ", match[0].toLowerCase());
        if (!seen.has(phrase)) {
          seen.add(phrase);
          found.push(phrase);
        }
      });
    return found;
  }

  function paymentHandles(text) {
    var found = [];
    RX("_UPI_HANDLE_RE")
      .finditer(text)
      .forEach(function (m) {
        found.push("UPI " + m[0].toLowerCase());
      });
    RX("_WALLET_RE")
      .finditer(text)
      .forEach(function (m) {
        found.push("wallet " + m[0]);
      });
    RX("_IFSC_RE")
      .finditer(text)
      .forEach(function (m) {
        found.push("IFSC " + m[0]);
      });
    RX("_REMITTANCE_RE")
      .finditer(text)
      .forEach(function (m) {
        found.push(m[0].toLowerCase());
      });
    return dedupe(found);
  }

  function registrable(host) {
    return MT.urls.registrableDomain(host);
  }

  function firstPartyLinks(parsed, urlAnalysis, cfg, auth) {
    if (auth === null || auth === undefined || !urlAnalysis.urls.length) return false;
    if (auth.spf.toLowerCase() !== "pass" && auth.dkim.toLowerCase() !== "pass") return false;
    if (!(auth.spf_aligned || auth.dkim_aligned) || auth.dmarc.toLowerCase() === "fail") return false;
    var senderRd = registrable(parsed.sender.domain);
    if (!senderRd) return false;
    var allowed = new Set([senderRd]);
    cfg.org_domains.forEach(function (d) {
      if (d) allowed.add(registrable(d));
    });
    MT.K("knowledge").BRANDS.forEach(function (domains) {
      if (domains.indexOf(senderRd) >= 0) {
        domains.forEach(function (d) {
          allowed.add(registrable(d));
        });
      }
    });
    var hosts = urlAnalysis.urls.filter(function (u) {
      return u.host;
    });
    return (
      hosts.length > 0 &&
      hosts.every(function (u) {
        return allowed.has(u.registrable_domain || registrable(u.host));
      })
    );
  }

  function normalizeText(subject, body) {
    var combined = (subject || "") + "\n" + (body || "");
    combined = combined.normalize("NFKC");
    var replace = function (from, to) {
      combined = py().replaceAll(combined, String.fromCharCode(from), to);
    };
    replace(0x2019, "'");
    replace(0x2018, "'");
    replace(0x201c, '"');
    replace(0x201d, '"');
    replace(0x2013, "-");
    replace(0x2014, "-");
    combined = combined.replace(/[ \t\r\f\v\xa0]+/g, " ");
    combined = combined.replace(/ *\n */g, "\n");
    combined = combined.replace(/\n{2,}/g, "\n");
    return py().slice(py().strip(combined).toLowerCase(), 0, 200000);
  }

  function bodyText(parsed) {
    if (parsed.text_body) return parsed.text_body;
    if (parsed.html_body) return MT.mime.htmlToText(parsed.html_body);
    return "";
  }

  function modelInput(parsed) {
    return normalizeText(parsed.subject, bodyText(parsed));
  }

  function detectLanguage(text) {
    var letters = RX("_LETTER_RE").findall(text || "");
    if (!letters.length) return "en";
    var devanagari = RX("_DEVANAGARI_RE");
    var count = 0;
    letters.forEach(function (ch) {
      if (devanagari.match(ch)) count += 1;
    });
    return count / letters.length > 0.3 ? "hi" : "en";
  }

  function clamp01(value) {
    return Math.max(0.0, Math.min(1.0, value));
  }

  function senderIsExternal(parsed, cfg) {
    var senderRd = registrable(parsed.sender.domain);
    var org = new Set();
    cfg.org_domains.forEach(function (d) {
      if (d) org.add(registrable(d));
    });
    return Boolean(senderRd) && !org.has(senderRd);
  }

  function replyToMismatch(parsed) {
    var senderRd = registrable(parsed.sender.domain);
    return parsed.reply_to.some(function (r) {
      return r.domain && registrable(r.domain) !== senderRd;
    });
  }

  function displayNameSignals(parsed, cfg) {
    var name = (parsed.sender.display_name || "").toLowerCase();
    if (!name) return [];
    var titles = MT.K("knowledge").EXEC_TITLES.concat(
      cfg.executives.filter(function (e) {
        return e;
      }),
    );
    for (var i = 0; i < titles.length; i += 1) {
      var title = py().strip(titles[i].toLowerCase());
      if (title && py().re("(?<![\\w])" + py().reEscape(title) + "(?![\\w])").search(name)) {
        return ["display name '" + parsed.sender.display_name + "' matches '" + title + "'"];
      }
    }
    return [];
  }

  function bec(name, confidence, evidence) {
    return { pattern: name, confidence: clamp01(confidence), evidence: dedupe(evidence) };
  }

  function detectBecPatterns(text, parsed, urlAnalysis, attAnalysis, cfg, auth) {
    var patterns = [];
    var urgency = hits("urgency", text);
    var secrecy = hits("secrecy", text);
    var threat = hits("threat", text);
    var replyCues = hits("reply", text);
    var external = senderIsExternal(parsed, cfg);
    var senderFree = MT.K("knowledge").FREEMAIL_DOMAINS.has(registrable(parsed.sender.domain));
    var replyMismatch = replyToMismatch(parsed);
    var wordCount = RX("_WORD_RE").findall(text).length;
    var firstParty = firstPartyLinks(parsed, urlAnalysis, cfg, auth);
    var riskyUrls = urlAnalysis.urls.filter(function (u) {
      return SEVERITY_ORDER[u.risk] >= SEVERITY_ORDER.medium;
    });
    var highUrls = urlAnalysis.urls.filter(function (u) {
      return SEVERITY_ORDER[u.risk] >= SEVERITY_ORDER.high;
    });
    var keywordUrls = firstParty
      ? []
      : urlAnalysis.urls.filter(function (u) {
          return u.suspicious_keywords.length;
        });
    var highAtts = attAnalysis.attachments.filter(function (a) {
      return SEVERITY_ORDER[a.risk] >= SEVERITY_ORDER.high;
    });

    var bank = hits("bank_change", text);
    var change = hits("change", text);
    var explicitPay = hits("payment_explicit", text);
    var action = hits("payment_action", text);
    if (bank.length && change.length && !explicitPay.length && RX("_UNCHANGED_RE").search(text)) change = [];
    var conf = 0.0;
    var evidence = [];
    if (bank.length && change.length && action.length) {
      conf = 0.4;
      evidence = evidence.concat(bank.slice(0, 2), change.slice(0, 2), action.slice(0, 2));
      if (urgency.length) {
        conf += 0.15;
        evidence.push(urgency[0]);
      }
      if (secrecy.length) {
        conf += 0.15;
        evidence.push(secrecy[0]);
      }
      if (replyMismatch) {
        conf += 0.15;
        evidence.push("reply-to domain differs from sender");
      }
    }
    if (explicitPay.length) {
      conf = Math.max(conf, 0.7);
      evidence = explicitPay.slice(0, 2).concat(
        evidence.filter(function (e) {
          return explicitPay.indexOf(e) < 0;
        }),
      );
      if (urgency.length || secrecy.length || replyMismatch) conf += 0.15;
    }
    if (conf >= 0.35) patterns.push(bec("payment_diversion", conf, evidence));

    var invoice = hits("invoice", text);
    var due = hits("due", text);
    conf = 0.0;
    evidence = [];
    if (invoice.length && due.length) {
      conf = 0.3;
      evidence = evidence.concat(invoice.slice(0, 2), due.slice(0, 2));
    }
    var lure = RX("_ATTACHMENT_LURE_RE");
    var lureAtts = attAnalysis.attachments.filter(function (a) {
      return lure.search(a.filename);
    });
    if (lureAtts.length && (invoice.length || due.length)) {
      conf = Math.max(conf, 0.3);
      if (
        lureAtts.some(function (a) {
          return SEVERITY_ORDER[a.risk] >= SEVERITY_ORDER.medium;
        })
      ) {
        conf += 0.25;
        evidence.push("attachment '" + lureAtts[0].filename + "' (" + lureAtts[0].risk + " risk)");
      } else {
        evidence.push("attachment '" + lureAtts[0].filename + "'");
      }
    }
    if (conf > 0 && highAtts.length) {
      conf += 0.2;
      evidence.push("dangerous attachment '" + highAtts[0].filename + "'");
    }
    if (conf > 0 && urgency.length) {
      conf += 0.1;
      evidence.push(urgency[0]);
    }
    if (conf > 0 && (replyMismatch || senderFree) && invoice.length) {
      conf += 0.1;
      evidence.push(senderFree ? "free-mail sender" : "reply-to domain differs from sender");
    }
    if (conf >= 0.35) patterns.push(bec("fake_invoice", conf, evidence));

    var cred = hits("credential", text);
    var cta = hits("cta", text);
    var explicitCred = hits("cred_explicit", text);
    conf = 0.0;
    evidence = [];
    var linkSignal = Boolean(riskyUrls.length || keywordUrls.length);
    if (cred.length && (linkSignal || cta.length)) {
      conf = 0.4;
      evidence = evidence.concat(cred.slice(0, 3));
      if (cta.length) evidence.push(cta[0]);
      if (linkSignal) {
        var sample = (riskyUrls.length ? riskyUrls : keywordUrls)[0];
        evidence.push("link " + (sample.host || py().slice(sample.url, 0, 60)));
      }
      if (explicitCred.length) {
        conf += 0.2;
        evidence = evidence.concat(explicitCred.slice(0, 2));
      }
      if (highUrls.length) conf += 0.15;
      if (threat.length) {
        conf += 0.1;
        evidence.push(threat[0]);
      }
      if (urgency.length) conf += 0.1;
    } else if (cred.length >= 3 && (replyCues.length || explicitCred.length) && !urlAnalysis.urls.length) {
      conf = 0.45;
      evidence = evidence.concat(cred.slice(0, 3), replyCues.length ? replyCues.slice(0, 1) : explicitCred.slice(0, 1));
      evidence.push("credentials requested by reply");
    } else if (explicitCred.length && cred.length) {
      conf = 0.35;
      evidence = evidence.concat(explicitCred.slice(0, 2));
    }
    if (conf > 0 && firstParty && !highUrls.length) {
      conf *= 0.5;
      evidence.push("every link stays on the authenticated sender's own domain");
    }
    if (conf >= 0.35) patterns.push(bec("credential_harvesting", conf, evidence));

    var financial = hits("financial", text);
    var demand = hits("money_demand", text);
    var handles = paymentHandles(text);
    var violence = hits("violence", text);
    var extortion = hits("extortion", text);
    var strongTerms = K().STRONG_MONEY_TERMS;
    var strongMoney = financial.filter(function (t) {
      return strongTerms.has(t);
    });
    var amounts = RX("_MONEY_AMOUNT_RE")
      .finditer(text)
      .map(function (m) {
        return py().strip(m[0]);
      });
    var money = Boolean(strongMoney.length || demand.length || handles.length || amounts.length);
    conf = 0.0;
    evidence = [];
    if (violence.length) {
      conf = 0.55 + Math.min(0.2, 0.1 * (violence.length - 1));
      evidence = evidence.concat(violence.slice(0, 3));
      if (extortion.length) {
        conf += 0.15;
        evidence = evidence.concat(extortion.slice(0, 2));
      }
    } else if (extortion.length && money) {
      conf = 0.45 + Math.min(0.25, 0.1 * extortion.length);
      evidence = evidence.concat(extortion.slice(0, 3));
    }
    if (conf > 0 && money) {
      conf += 0.1;
      evidence = evidence.concat(amounts.slice(0, 1).concat(strongMoney.slice(0, 2), demand.slice(0, 1), handles.slice(0, 1)).slice(0, 3));
    }
    if (conf > 0 && urgency.length) conf += 0.05;
    if (conf >= 0.35) patterns.push(bec(money ? "extortion" : "violent_threat", conf, evidence));

    var invest = hits("investment", text);
    var reward = hits("reward", text);
    var scarcity = hits("scarcity", text);
    conf = 0.0;
    evidence = [];
    if (invest.length >= 2 || (invest.length && (reward.length || scarcity.length || handles.length))) {
      conf = 0.4 + 0.1 * Math.min(3, Math.max(0, invest.length - 1));
      evidence = evidence.concat(invest.slice(0, 3));
      if (urlAnalysis.urls.length || handles.length) {
        conf += 0.1;
        evidence.push(urlAnalysis.urls.length ? "link " + urlAnalysis.urls[0].host : handles[0]);
      }
      if (scarcity.length || urgency.length) {
        conf += 0.1;
        evidence = evidence.concat((scarcity.length ? scarcity : urgency).slice(0, 1));
      }
      if (reward.length) evidence = evidence.concat(reward.slice(0, 1));
    }
    if (conf >= 0.35) patterns.push(bec("investment_scam", conf, evidence));

    var tech = hits("techsupport", text);
    var phones = RX("_PHONE_RE")
      .finditer(text)
      .map(function (m) {
        return py().strip(m[0]);
      });
    var authority = hits("authority", text);
    conf = 0.0;
    evidence = [];
    if (tech.length >= 2 && (phones.length || urgency.length || threat.length)) {
      conf = 0.4 + 0.1 * Math.min(3, tech.length - 2);
      evidence = evidence.concat(tech.slice(0, 3));
      if (phones.length) {
        conf += 0.2;
        evidence.push("phone " + phones[0]);
      }
      if (authority.length) {
        conf += 0.1;
        evidence = evidence.concat(authority.slice(0, 1));
      }
      if (urgency.length) evidence = evidence.concat(urgency.slice(0, 1));
    }
    if (conf >= 0.35) patterns.push(bec("callback_scam", conf, evidence));

    var nameSignals = displayNameSignals(parsed, cfg);
    var execPhrases = hits("exec", text);
    conf = 0.0;
    evidence = [];
    if (nameSignals.length) {
      conf += 0.35;
      evidence = evidence.concat(nameSignals);
    }
    if (execPhrases.length) {
      conf += Math.min(0.45, 0.15 * execPhrases.length);
      evidence = evidence.concat(execPhrases.slice(0, 4));
    }
    if (conf > 0) {
      if (wordCount < 120) {
        conf += 0.1;
        evidence.push("short message (" + wordCount + " words)");
      }
      if (senderFree || external) {
        conf += 0.1;
        evidence.push(senderFree ? "free-mail sender" : "sender outside the protected organisation");
      }
      if (replyCues.length) conf += 0.05;
    }
    if (conf >= 0.35) patterns.push(bec("executive_impersonation", conf, evidence));
    return patterns;
  }

  function heuristicProbabilities(cred, fin, threat, reward, secrecy, authority, urgency, execConf, linkSignal, totalWords) {
    var weights = {
      Phishing: 1.0 * cred + (linkSignal ? 2.0 : 0.0) + 0.5 * threat,
      "Fraud-Related": 1.0 * fin + 0.7 * reward + 0.5 * secrecy,
      Impersonated: 3.0 * execConf + 0.5 * authority,
      Suspicious: 0.5 + 2.0 * urgency,
      Legitimate: totalWords ? 3.0 : 1.0,
    };
    var total = 0.0;
    Object.keys(weights).forEach(function (key) {
      total += weights[key];
    });
    if (!total) total = 1.0;
    var out = {};
    Object.keys(weights).forEach(function (key) {
      out[key] = py().round(weights[key] / total, 4);
    });
    return out;
  }

  function runModel(text) {
    try {
      var prediction = MT.textmodel.predict(text);
      var weights = MT.textmodel.shapValues(text, prediction.label, SHAP_TOP_K, prediction.features);
      return {
        label: prediction.label,
        probs: prediction.probabilities,
        topTerms: MT.textmodel.explain(text, prediction.label, 8, prediction.features),
        attributions: weights,
        name: MT.textmodel.version(),
        backend: "linear",
      };
    } catch (error) {
      if (MT.trace) MT.trace(error);
      return { label: null, probs: {}, topTerms: [], attributions: [], name: "unavailable", backend: "unavailable" };
    }
  }

  function finding(id, severity, title, detail, evidence) {
    return { id: id, module: "nlp", severity: severity, title: title, detail: detail, evidence: evidence };
  }

  function analyzeContent(parsed, urlAnalysis, attAnalysis, cfg, auth) {
    var body = bodyText(parsed);
    var text = normalizeText(parsed.subject, body);
    var words = RX("_WORD_RE").findall(text);
    var analysis = {
      language: detectLanguage(text),
      word_count: words.length,
      urgency_score: 0.0,
      urgency_phrases: [],
      social_engineering_cues: [],
      financial_terms: [],
      payment_handles: [],
      credential_terms: [],
      threat_terms: [],
      generic_greeting: false,
      requests_reply_not_click: false,
      ml_category: LEGITIMATE,
      ml_probabilities: {},
      ml_top_terms: [],
      shap_weights: [],
      lime_weights: [],
      lime_fidelity: 0.0,
      lime_method: "",
      ml_model: "",
      ml_backend: "",
      bec_patterns: [],
      score: 0.0,
      findings: [],
    };

    var urgency = hits("urgency", text);
    var threat = hits("threat", text);
    var financial = hits("financial", text);
    var violence = hits("violence", text);
    var handles = paymentHandles(text);
    var credential = hits("credential", text);
    var authority = hits("authority", text);
    var secrecy = hits("secrecy", text);
    var reward = hits("reward", text);
    var scarcity = hits("scarcity", text);
    var curiosity = hits("curiosity", text);
    var greeting = hits("greeting", py().slice(text, 0, 400));
    var replyCues = hits("reply", text);

    var exclamations = py().count(text, "!");
    var exclamationDensity = exclamations / Math.max(1, words.length);
    var subjectLetters = py()
      .points(parsed.subject || "")
      .filter(function (c) {
        return py().isAlpha(c);
      });
    var subjectCaps = 0.0;
    if (subjectLetters.length >= 8) {
      var upper = 0;
      subjectLetters.forEach(function (c) {
        if (UPPER.test(c)) upper += 1;
      });
      subjectCaps = upper / subjectLetters.length;
    }
    var urgencyScore = clamp01(0.25 * urgency.length + 0.15 * threat.length + Math.min(0.2, exclamationDensity) + (subjectCaps > 0.5 ? 0.1 : 0.0));

    var cues = [];
    if (authority.length) cues.push("authority");
    if (threat.length || violence.length) cues.push("fear");
    if (scarcity.length || urgency.length) cues.push("scarcity");
    if (secrecy.length) cues.push("secrecy");
    if (reward.length) cues.push("reward");
    if (curiosity.length) cues.push("curiosity");

    analysis.urgency_score = urgencyScore;
    analysis.urgency_phrases = urgency.slice(0, 10);
    analysis.social_engineering_cues = cues;
    analysis.financial_terms = financial.slice(0, 15);
    analysis.payment_handles = handles.slice(0, 10);
    analysis.credential_terms = credential.slice(0, 15);
    analysis.threat_terms = threat.concat(violence).slice(0, 10);
    analysis.generic_greeting = greeting.length > 0;
    var riskyLinks = urlAnalysis.urls.some(function (u) {
      return SEVERITY_ORDER[u.risk] >= SEVERITY_ORDER.medium;
    });
    analysis.requests_reply_not_click = replyCues.length > 0 && !riskyLinks;

    var patterns = detectBecPatterns(text, parsed, urlAnalysis, attAnalysis, cfg, auth);
    analysis.bec_patterns = patterns;
    var maxBec = 0.0;
    var execConf = 0.0;
    patterns.forEach(function (p) {
      maxBec = Math.max(maxBec, p.confidence);
      if (p.pattern === "executive_impersonation") execConf = Math.max(execConf, p.confidence);
    });

    var outcome = runModel(text);
    var label = outcome.label;
    var probs = outcome.probs;
    if (label === null) {
      probs = heuristicProbabilities(
        credential.length,
        financial.length,
        threat.length,
        reward.length,
        secrecy.length,
        authority.length,
        urgencyScore,
        execConf,
        riskyLinks ||
          urlAnalysis.urls.some(function (u) {
            return u.suspicious_keywords.length;
          }),
        words.length,
      );
      label = null;
      Object.keys(probs).forEach(function (key) {
        if (label === null || probs[key] > probs[label]) label = key;
      });
    }
    var categories = MT.K("model_trainer").LABELS;
    analysis.ml_category = categories.indexOf(label) >= 0 ? label : LEGITIMATE;
    var rounded = {};
    Object.keys(probs).forEach(function (key) {
      rounded[key] = py().round(probs[key], 4);
    });
    analysis.ml_probabilities = rounded;
    analysis.ml_top_terms = outcome.topTerms;
    analysis.shap_weights = outcome.attributions.map(function (item) {
      return { token: String(item[0]), weight: py().round(item[1], 6) };
    });
    analysis.ml_model = outcome.name;
    analysis.ml_backend = outcome.backend;

    var nonLegit = 1.0 - (MT.own(probs, LEGITIMATE) ? probs[LEGITIMATE] : 0.0);
    analysis.score = clamp01(0.45 * nonLegit + 0.25 * urgencyScore + 0.2 * maxBec + (cues.length >= 2 ? 0.1 : 0.0));

    var findings = [];
    if (urgencyScore >= 0.25) {
      findings.push(
        finding(
          "urgency_language",
          urgencyScore >= 0.5 ? "medium" : "low",
          "Urgency pressure",
          "The message pushes for immediate action (urgency score " + py().fixed(urgencyScore, 2) + "): " + (urgency.slice(0, 4).join(", ") || "tone/punctuation") + ".",
          { score: py().round(urgencyScore, 3), phrases: urgency.slice(0, 10), exclamations: exclamations },
        ),
      );
    }
    if (threat.length) {
      findings.push(
        finding(
          "fear_or_threat_language",
          threat.length >= 2 ? "medium" : "low",
          "Fear / threat language",
          "Consequences are threatened to force compliance: " + threat.slice(0, 4).join(", ") + ".",
          { phrases: threat.slice(0, 10) },
        ),
      );
    }
    if (violence.length) {
      findings.push(
        finding(
          "violent_threat",
          "critical",
          "Threat of physical harm",
          "The message threatens violence or stalks the recipient: " +
            violence.slice(0, 4).join(", ") +
            ". This is criminal intimidation, not spam, and should be preserved for the police.",
          { phrases: violence.slice(0, 10) },
        ),
      );
    }
    if (handles.length) {
      findings.push(
        finding(
          "payment_handle",
          "medium",
          "Direct payment instructions",
          "The text names where to send money: " +
            handles.slice(0, 3).join(", ") +
            ". Genuine billing points at an invoice or a portal; scams and extortion name a UPI ID, wallet or remittance service in the body.",
          { handles: handles.slice(0, 10) },
        ),
      );
    }
    var credConf = 0.0;
    patterns.forEach(function (p) {
      if (p.pattern === "credential_harvesting") credConf = Math.max(credConf, p.confidence);
    });
    if (credential.length) {
      var sev = credConf >= 0.5 ? "high" : credential.length >= 2 ? "medium" : "low";
      findings.push(
        finding(
          "credential_request",
          sev,
          "Credential / identity data requested",
          "The text asks for or refers to secrets and identity data: " + credential.slice(0, 5).join(", ") + ".",
          { terms: credential.slice(0, 15), harvest_confidence: py().round(credConf, 3) },
        ),
      );
    }
    if (financial.length >= 2) {
      var pressure = Boolean(reward.length || secrecy.length || urgencyScore >= 0.5);
      findings.push(
        finding(
          "financial_lure",
          financial.length >= 3 && pressure ? "medium" : "low",
          "Financial lure",
          "Money-related language " + financial.slice(0, 5).join(", ") + (pressure ? " combined with pressure cues." : "."),
          { terms: financial.slice(0, 15), pressure: pressure },
        ),
      );
    }
    if (greeting.length) {
      findings.push(
        finding("generic_greeting", "low", "Generic greeting", "The message opens with '" + greeting[0] + "' instead of addressing the recipient by name.", {
          greeting: greeting[0],
        }),
      );
    }
    if (secrecy.length) {
      findings.push(
        finding(
          "secrecy_cue",
          "medium",
          "Secrecy requested",
          "The sender asks for discretion (" + secrecy.slice(0, 3).join(", ") + "), a hallmark of BEC and advance-fee fraud.",
          { phrases: secrecy.slice(0, 10) },
        ),
      );
    }
    if (authority.length) {
      findings.push(
        finding("authority_cue", "low", "Authority invoked", "The message leans on an authority figure or institution: " + authority.slice(0, 4).join(", ") + ".", {
          phrases: authority.slice(0, 10),
        }),
      );
    }
    if (reward.length >= 2) {
      findings.push(
        finding("reward_lure", financial.length ? "medium" : "low", "Reward / prize lure", "Promises a reward or win: " + reward.slice(0, 4).join(", ") + ".", {
          phrases: reward.slice(0, 10),
        }),
      );
    }
    patterns.forEach(function (p) {
      var sev = p.confidence >= 0.75 ? "critical" : p.confidence >= 0.5 ? "high" : "medium";
      var pretty = py().replaceAll(p.pattern, "_", " ");
      var fid;
      var title;
      var lead;
      if (MT.own(SCAM_TITLES, p.pattern)) {
        fid = SCAM_TITLES[p.pattern][0];
        title = SCAM_TITLES[p.pattern][1];
        lead = SCAM_TITLES[p.pattern][2];
        if (p.pattern === "extortion" || p.pattern === "violent_threat") sev = p.confidence >= 0.5 ? "critical" : "high";
      } else {
        fid = "bec_" + p.pattern;
        title = "BEC pattern: " + pretty;
        lead = py().capitalize(pretty) + " indicators";
      }
      findings.push(
        finding(fid, sev, title, lead + " with confidence " + py().fixed(p.confidence, 2) + ": " + p.evidence.slice(0, 4).join(", ") + ".", {
          pattern: p.pattern,
          confidence: py().round(p.confidence, 3),
          evidence: p.evidence,
        }),
      );
    });
    if (analysis.requests_reply_not_click) {
      findings.push(
        finding(
          "reply_not_click",
          "low",
          "Asks for a reply rather than a click",
          "The sender steers the conversation to email replies (" + replyCues[0] + "), typical of BEC and advance-fee scams.",
          { phrases: replyCues.slice(0, 5) },
        ),
      );
    }
    var method = MT.own(ATTRIBUTION_METHOD, outcome.backend) ? ATTRIBUTION_METHOD[outcome.backend] : "none";
    var shapEvidence = analysis.shap_weights.slice(0, 8).map(function (w) {
      return { token: w.token, weight: py().round(w.weight, 4) };
    });
    var shapSummary = analysis.shap_weights
      .slice(0, 5)
      .map(function (w) {
        return w.token + " " + py().signedFixed(w.weight, 3);
      })
      .join(", ");
    var probability = MT.own(analysis.ml_probabilities, analysis.ml_category) ? analysis.ml_probabilities[analysis.ml_category] : 0.0;
    findings.push(
      finding(
        "ml_classification",
        "info",
        "ML classification",
        "Classifier " +
          outcome.name +
          " favours " +
          analysis.ml_category +
          " (p=" +
          py().fixed(probability, 2) +
          "); top terms: " +
          (outcome.topTerms.slice(0, 5).join(", ") || "n/a") +
          ". Token weights (" +
          method +
          "): " +
          (shapSummary || "n/a") +
          ".",
        {
          model: outcome.name,
          backend: outcome.backend,
          attribution: method,
          category: analysis.ml_category,
          probabilities: analysis.ml_probabilities,
          top_terms: outcome.topTerms,
          shap_weights: shapEvidence,
        },
      ),
    );
    analysis.findings = findings;
    return analysis;
  }

  MT.nlp = {
    analyzeContent: analyzeContent,
    normalizeText: normalizeText,
    modelInput: modelInput,
    detectBecPatterns: detectBecPatterns,
    paymentHandles: paymentHandles,
    detectLanguage: detectLanguage,
    hits: hits,
  };
})(MT);
