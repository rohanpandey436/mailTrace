var MT = MT || {};

(function (MT) {
  var SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  var LEGITIMATE = "Legitimate";
  var SUSPICIOUS = "Suspicious";
  var IMPERSONATED = "Impersonated";
  var PHISHING = "Phishing";
  var FRAUD = "Fraud-Related";
  var CATEGORIES = [LEGITIMATE, SUSPICIOUS, IMPERSONATED, PHISHING, FRAUD];
  var ATTACK = [PHISHING, FRAUD, IMPERSONATED];
  var ROLE_LABELS = { sender: "Sender", reply_to: "Reply-To", return_path: "Return-Path" };
  var URL_MODEL_ALPHA = 0.5;

  function py() {
    return MT.py;
  }

  function K() {
    return MT.K("scoring");
  }

  function clamp(value, low, high) {
    var lo = low === undefined ? 0.0 : low;
    var hi = high === undefined ? 100.0 : high;
    var number = typeof value === "number" ? value : Number(value);
    if (number !== number) return lo;
    return Math.max(lo, Math.min(hi, number));
  }

  function sev(value) {
    return MT.own(SEVERITY_ORDER, value) ? SEVERITY_ORDER[value] : 0;
  }

  function short(text, limit) {
    var max = limit === undefined ? 80 : limit;
    var joined = py().joinWords(text || "");
    return py().length(joined) <= max ? joined : py().slice(joined, 0, max - 3) + "...";
  }

  function quote(items, limit) {
    var max = limit === undefined ? 3 : limit;
    var values = items
      .map(function (v) {
        return py().strip(String(v));
      })
      .filter(Boolean);
    var shown = values
      .slice(0, max)
      .map(function (v) {
        return "'" + v + "'";
      })
      .join(", ");
    var extra = values.length - max;
    return extra > 0 ? shown + " (+" + extra + " more)" : shown;
  }

  function unique(items) {
    return py().unique(items.filter(Boolean));
  }

  function registrable(host) {
    var text = py().rstrip(py().strip(host || "").toLowerCase(), ".");
    if (!text) return "";
    return (MT.urls.registrableDomain(text) || text).toLowerCase();
  }

  function isFreemail(domain) {
    var lowered = (domain || "").toLowerCase();
    var freemail = MT.K("knowledge").FREEMAIL_DOMAINS;
    return Boolean(lowered) && (freemail.has(lowered) || freemail.has(registrable(lowered)));
  }

  function orgDomains(cfg) {
    var set = new Set();
    cfg.org_domains.forEach(function (d) {
      if (d) set.add(registrable(d));
    });
    return set;
  }

  function brandDomains() {
    return MT.urls.legitDomains();
  }

  function isProtectedDomain(domain, cfg) {
    return Boolean(domain) && (orgDomains(cfg).has(domain) || brandDomains().has(domain));
  }

  function asCategory(value) {
    return CATEGORIES.indexOf(value) >= 0 ? value : LEGITIMATE;
  }

  function mlProb(probs, category) {
    if (!probs) return 0.0;
    var cat = asCategory(category);
    var raw = MT.own(probs, cat) ? probs[cat] : 0.0;
    return clamp(raw, 0.0, 1.0);
  }

  function becConfidence(nlp, name) {
    var best = 0.0;
    var evidence = [];
    nlp.bec_patterns.forEach(function (item) {
      var conf = clamp(item.confidence, 0.0, 1.0);
      if (item.pattern === name && conf >= best) {
        best = conf;
        evidence = item.evidence.slice();
      }
    });
    return [best, evidence];
  }

  function findById(findings, id) {
    for (var i = 0; i < findings.length; i += 1) if (findings[i].id === id) return findings[i];
    return null;
  }

  function lookalikeSenderDomains(domainIntel) {
    return domainIntel.filter(function (d) {
      return d.lookalike_of && (d.role === "sender" || d.role === "reply_to");
    });
  }

  function roleLabel(role) {
    if (MT.own(ROLE_LABELS, role)) return ROLE_LABELS[role];
    return py().title(py().replaceAll(role || "domain", "_", " "));
  }

  function describeUrl(url) {
    var reason = url.reasons.length ? ": " + url.reasons[0] : "";
    return (url.host || short(url.url, 60)) + " [" + url.risk + reason + "]";
  }

  function severityFor(score, hasFindings) {
    var value = clamp(score);
    if (value <= 0 && !hasFindings) return "info";
    if (value < 25) return "low";
    if (value < 50) return "medium";
    if (value < 75) return "high";
    return "critical";
  }

  function authenticationScore(auth, senderDomain, cfg) {
    var spf = auth.spf.toLowerCase();
    var dkim = auth.dkim.toLowerCase();
    var dmarc = auth.dmarc.toLowerCase();
    var score = 0.0;
    if (spf === "fail") score += 45;
    else if (spf === "softfail") score += 25;
    else if (spf === "none" || spf === "neutral") score += 15;
    else if (spf === "unverifiable" || spf === "temperror" || spf === "permerror") score += 10;
    if (dkim === "fail") score += 35;
    else if (dkim === "none") score += 10;
    else if (dkim === "unverifiable" || dkim === "temperror" || dkim === "permerror") score += 5;
    if (dmarc === "fail") score += auth.dmarc_policy.toLowerCase() === "reject" ? 60 : 40;
    else if (dmarc === "none") score += 10;
    if (auth.spf_aligned === false) score += 15;
    if (auth.dkim_aligned === false) score += 15;
    var anyFailure = spf === "fail" || spf === "softfail" || dkim === "fail" || dmarc === "fail";
    if (anyFailure && isProtectedDomain(senderDomain, cfg)) score += 20;
    return clamp(score);
  }

  function textScore(nlp) {
    var maxBec = 0.0;
    nlp.bec_patterns.forEach(function (p) {
      maxBec = Math.max(maxBec, clamp(p.confidence, 0.0, 1.0));
    });
    return clamp(100 * (0.7 * clamp(nlp.score, 0.0, 1.0) + 0.3 * maxBec));
  }

  function deterministicUrlScore(urls, domainIntel, brandVariant) {
    var score = 100 * clamp(urls.score, 0.0, 1.0);
    domainIntel.forEach(function (d) {
      if (d.lookalike_of && !(brandVariant && d.role === "sender")) score = Math.max(score, 85.0);
      if (d.age_days !== null && d.age_days < 30 && !d.is_free_mail) score = Math.max(score, 75.0);
      else if (d.age_days !== null && d.age_days < 90 && !d.is_free_mail) score = Math.max(score, 50.0);
      if (d.is_disposable) score = Math.max(score, 60.0);
      if (d.role === "sender" && !d.is_free_mail && d.source !== "offline" && d.source !== "unavailable") {
        if (!d.resolves) score = Math.max(score, 70.0);
        else if (!d.has_mx) score = Math.max(score, 40.0);
      }
    });
    return clamp(score);
  }

  function urlScore(urls, domainIntel, urlModel, brandVariant) {
    var floor = deterministicUrlScore(urls, domainIntel, brandVariant);
    var probability = urlModel !== null ? clamp(urlModel.max_probability, 0.0, 1.0) : 0.0;
    return clamp(Math.max(floor, floor + (100.0 - floor) * URL_MODEL_ALPHA * probability));
  }

  function entropyScore(atts) {
    var score = 100 * clamp(atts.score, 0.0, 1.0);
    atts.attachments.forEach(function (a) {
      if (a.high_entropy && sev(a.risk) >= SEVERITY_ORDER.high) score = Math.max(score, 90.0);
    });
    return clamp(score);
  }

  function identityForgeryScore(headerAnalysis) {
    var score = 0.0;
    if (headerAnalysis.display_name_spoof) score += 45;
    if (headerAnalysis.reply_to_mismatch) score += 35;
    if (headerAnalysis.return_path_mismatch) score += 25;
    if (headerAnalysis.message_id_mismatch) score += 15;
    return score;
  }

  function authPillar(auth, headerAnalysis, senderDomain, cfg) {
    var forgery = identityForgeryScore(headerAnalysis);
    if (headerAnalysis.return_path_mismatch && auth.dkim.toLowerCase() === "pass" && auth.dkim_aligned) forgery -= 15;
    return clamp(authenticationScore(auth, senderDomain, cfg) + forgery);
  }

  function networkScore(headerAnalysis, infra, intel) {
    var infraPart = 100 * clamp(infra.score, 0.0, 1.0);
    var seen = new Set();
    headerAnalysis.hops.forEach(function (hop) {
      hop.anomalies.forEach(function (a) {
        seen.add(a);
      });
    });
    var routing = 0.0;
    K()._ROUTING_ANOMALIES.forEach(function (weight, name) {
      if (seen.has(name)) routing += weight;
    });
    var anyPublic = headerAnalysis.hops.some(function (h) {
      return h.from_ip && !h.is_private_ip;
    });
    if (headerAnalysis.hops.length && !anyPublic) routing += 20;
    if (!headerAnalysis.hops.length) routing += 25;
    if (headerAnalysis.originating_ip && headerAnalysis.origin_confidence < 0.5) routing += 10;
    var intelPart = 0.0;
    if (Object.keys(intel.ip_blacklists).length) intelPart = Math.max(intelPart, 80.0);
    if (intel.tor_exits.length) intelPart = Math.max(intelPart, 85.0);
    if (infra.blacklisted) intelPart = Math.max(intelPart, 75.0);
    if (intel.related_incidents.length) {
      var worst = 0;
      intel.related_incidents.forEach(function (r) {
        worst = Math.max(worst, r.risk_score);
      });
      intelPart = Math.max(intelPart, 40.0 + 0.4 * worst);
    }
    var routingPart = clamp(routing);
    var strongest = Math.max(infraPart, routingPart, intelPart);
    var others = [infraPart, routingPart, intelPart]
      .sort(function (a, b) {
        return b - a;
      })
      .slice(1);
    var sum = 0.0;
    others.forEach(function (v) {
      sum += v;
    });
    return clamp(strongest + (0.2 * sum) / Math.max(1, others.length));
  }

  function normalizedWeights(cfg) {
    var defaults = MT.K("config").DEFAULT_WEIGHTS;
    var configured = cfg.weights || {};
    var weights = {};
    var total = 0.0;
    defaults.forEach(function (value, name) {
      weights[name] = clamp(MT.own(configured, name) ? configured[name] : value, 0.0, 1e6);
      total += weights[name];
    });
    if (total <= 0.0) {
      total = 0.0;
      defaults.forEach(function (value, name) {
        weights[name] = value;
        total += value;
      });
    }
    var out = {};
    Object.keys(weights).forEach(function (name) {
      out[name] = weights[name] / total;
    });
    return out;
  }

  function componentScores(headerAnalysis, urlAnalysis, attAnalysis, nlpAnalysis, domainIntel, infra, intel, cfg, senderDomain, urlModel, brandVariant) {
    var sender = senderDomain;
    if (!sender) {
      for (var i = 0; i < domainIntel.length; i += 1) {
        if (domainIntel[i].role === "sender") {
          sender = domainIntel[i].domain.toLowerCase();
          break;
        }
      }
    }
    return {
      auth: authPillar(headerAnalysis.auth, headerAnalysis, sender, cfg),
      text: textScore(nlpAnalysis),
      url: urlScore(urlAnalysis, domainIntel, urlModel, brandVariant),
      network: networkScore(headerAnalysis, infra, intel),
      entropy: entropyScore(attAnalysis),
      weights: normalizedWeights(cfg),
    };
  }

  function weightedRisk(breakdown) {
    var total = 0.0;
    MT.K("config").PILLARS.forEach(function (name) {
      total += (MT.own(breakdown.weights, name) ? breakdown.weights[name] : 0.0) * breakdown[name];
    });
    return py().roundInt(clamp(total));
  }

  function breakdownLine(breakdown, risk) {
    var parts = MT.K("config")
      .PILLARS.map(function (name) {
        return name + " " + py().fixed(breakdown[name], 0) + " x " + py().fixed(MT.own(breakdown.weights, name) ? breakdown.weights[name] : 0.0, 2);
      })
      .join(", ");
    return "Weighted risk " + risk + "/100 = " + parts + ".";
  }

  function pressureCues(parsed, headerAnalysis, nlp, senderDomain, senderFree) {
    var cues = [];
    if (headerAnalysis.reply_to_mismatch) {
      var replyDomains = unique(
        parsed.reply_to
          .filter(function (r) {
            return r.domain;
          })
          .map(function (r) {
            return registrable(r.domain);
          }),
      );
      var other = null;
      for (var i = 0; i < replyDomains.length; i += 1) {
        if (replyDomains[i] !== senderDomain) {
          other = replyDomains[i];
          break;
        }
      }
      if (other === null) other = replyDomains.length ? replyDomains[0] : "another domain";
      cues.push("Reply-To domain " + other + " differs from sender domain " + (senderDomain || "unknown"));
    }
    if (senderFree) cues.push("free-mail sender domain " + senderDomain);
    if (nlp.urgency_score >= 0.5) {
      var phrases = nlp.urgency_phrases.length ? " (" + quote(nlp.urgency_phrases, 2) + ")" : "";
      cues.push("urgency score " + py().fixed(nlp.urgency_score, 2) + phrases);
    }
    return cues;
  }

  function phishingAttachments(attAnalysis) {
    return attAnalysis.attachments.filter(function (a) {
      return a.reasons.some(function (r) {
        return r.indexOf("credential-phishing") >= 0;
      });
    });
  }

  function brandOwnedVariant(parsed, headerAnalysis, urlAnalysis, attAnalysis, nlpAnalysis, domainIntel) {
    var sender = null;
    for (var i = 0; i < domainIntel.length; i += 1) {
      if (domainIntel[i].role === "sender" && domainIntel[i].lookalike_of) {
        sender = domainIntel[i];
        break;
      }
    }
    if (sender === null || sender.lookalike_technique !== "tld_swap") return "";
    var auth = headerAnalysis.auth;
    if (auth.spf.toLowerCase() !== "pass" || auth.dkim.toLowerCase() !== "pass" || auth.dmarc.toLowerCase() === "fail") return "";
    if (!(auth.spf_aligned || auth.dkim_aligned) || headerAnalysis.reply_to_mismatch) return "";
    var genuine = new Set();
    var brands = MT.K("knowledge").BRANDS;
    (brands.has(sender.lookalike_of) ? brands.get(sender.lookalike_of) : []).forEach(function (d) {
      genuine.add(registrable(d));
    });
    genuine.add(registrable(sender.domain));
    for (var u = 0; u < urlAnalysis.urls.length; u += 1) {
      var url = urlAnalysis.urls[u];
      if (url.host && !genuine.has(registrable(url.host))) return "";
    }
    if (
      attAnalysis.attachments.some(function (a) {
        return sev(a.risk) >= SEVERITY_ORDER.high;
      })
    ) {
      return "";
    }
    if (nlpAnalysis.credential_terms.length || nlpAnalysis.payment_handles.length) return "";
    if (
      nlpAnalysis.bec_patterns.some(function (p) {
        return p.confidence >= 0.35;
      })
    ) {
      return "";
    }
    return sender.lookalike_of;
  }

  function ruleClassify(parsed, headerAnalysis, urlAnalysis, attAnalysis, nlpAnalysis, domainIntel, findings, riskScore, cfg, brandVariant) {
    var auth = headerAnalysis.auth;
    var senderDomain = registrable(parsed.sender.domain);
    var senderFree = isFreemail(senderDomain);
    var finTerms = nlpAnalysis.financial_terms;
    var credTerms = nlpAnalysis.credential_terms;
    var handles = nlpAnalysis.payment_handles;
    var mlCat = asCategory(nlpAnalysis.ml_category);
    var mlP = mlProb(nlpAnalysis.ml_probabilities, mlCat);
    var payment = becConfidence(nlpAnalysis, "payment_diversion");
    var invoice = becConfidence(nlpAnalysis, "fake_invoice");
    var cred = becConfidence(nlpAnalysis, "credential_harvesting");
    var exec = becConfidence(nlpAnalysis, "executive_impersonation");
    var extortion = becConfidence(nlpAnalysis, "extortion");
    var violent = becConfidence(nlpAnalysis, "violent_threat");
    var invest = becConfidence(nlpAnalysis, "investment_scam");
    var callback = becConfidence(nlpAnalysis, "callback_scam");
    var spf = auth.spf.toLowerCase();
    var dkim = auth.dkim.toLowerCase();
    var dmarc = auth.dmarc.toLowerCase();
    var spfFail = spf === "fail";
    var dmarcFail = dmarc === "fail";
    var anyAuthFailure = spf === "fail" || spf === "softfail" || dkim === "fail" || dmarcFail;
    var unauthenticated = spf !== "pass" && dkim !== "pass";
    var protectedSender = isProtectedDomain(senderDomain, cfg);
    var internalSender = Boolean(senderDomain) && orgDomains(cfg).has(senderDomain);
    var highUrls = urlAnalysis.urls.filter(function (u) {
      return sev(u.risk) >= SEVERITY_ORDER.high;
    });
    var mediumUrls = urlAnalysis.urls.filter(function (u) {
      return sev(u.risk) >= SEVERITY_ORDER.medium;
    });
    var criticalUrls = urlAnalysis.urls.filter(function (u) {
      return sev(u.risk) >= SEVERITY_ORDER.critical;
    });
    var criticalAtts = attAnalysis.attachments.filter(function (a) {
      return sev(a.risk) >= SEVERITY_ORDER.critical;
    });
    var phishAtts = phishingAttachments(attAnalysis);
    var harvest = findById(findings, "credential_harvest_link");
    var lookalikeLink = findById(findings, "lookalike_domain_link");
    var fix2 = function (value) {
      return py().fixed(value, 2);
    };

    var why = [];
    phishAtts.slice(0, 1).forEach(function (att) {
      why.push("Attachment '" + att.filename + "' is an HTML page with a login form: a credential-phishing page delivered as a file");
    });
    criticalUrls.slice(0, 1).forEach(function (url) {
      why.push("Critical link " + describeUrl(url));
    });
    if (harvest !== null) why.push("Link flagged as a credential-harvest page: " + harvest.detail);
    if (why.length) return [PHISHING, why];

    why = [];
    var credentialDominant = cred[0] >= 0.5 && cred[0] >= Math.max(payment[0], invoice[0]);
    if (payment[0] >= 0.5 && !credentialDominant) {
      why.push("Payment-diversion BEC pattern (confidence " + fix2(payment[0]) + "): " + (quote(payment[1]) || "request to pay into new bank details"));
    }
    if (invoice[0] >= 0.5 && !credentialDominant) {
      why.push("Fake-invoice BEC pattern (confidence " + fix2(invoice[0]) + "): " + (quote(invoice[1]) || "invoice/payment demand with pressure"));
    }
    if (extortion[0] >= 0.5) why.push("Money is demanded under threat (extortion, confidence " + fix2(extortion[0]) + "): " + quote(extortion[1]));
    if (invest[0] >= 0.5) why.push("Investment-scam lure (confidence " + fix2(invest[0]) + "): " + quote(invest[1]));
    if (callback[0] >= 0.5) why.push("Tech-support / call-back scam (confidence " + fix2(callback[0]) + "): " + quote(callback[1]));
    var pressure = pressureCues(parsed, headerAnalysis, nlpAnalysis, senderDomain, senderFree);
    var pushes = pressure.filter(function (cue) {
      return cue.slice(0, 9) !== "free-mail";
    });
    var cueSet = new Set(nlpAnalysis.social_engineering_cues);
    pushes = pushes.concat(
      py().sorted(
        ["reward", "secrecy", "fear", "scarcity"].filter(function (c) {
          return cueSet.has(c);
        }),
      ),
    );
    if (
      nlpAnalysis.urgency_score >= 0.25 &&
      !pushes.some(function (cue) {
        return cue.slice(0, 7) === "urgency";
      })
    ) {
      pushes.push("urgency score " + fix2(nlpAnalysis.urgency_score));
    }
    if (handles.length && !internalSender && pushes.length) {
      why.push(
        "The message names where to send money (" +
          quote(handles, 2) +
          ") and pushes with " +
          pushes.join("; ") +
          ", from " +
          (senderFree ? "a free-mail" : unauthenticated ? "an unverified" : "an external") +
          " sender",
      );
    }
    if (finTerms.length >= 2 && pressure.length && riskScore >= 40 && !credentialDominant && !highUrls.length) {
      why.push("Financial lure " + quote(finTerms) + " combined with " + pressure.join("; ") + " at risk " + riskScore + "/100");
    }
    if (mlCat === FRAUD && mlP >= 0.6 && finTerms.length && cred[0] < 0.5 && !highUrls.length) {
      why.push("ML classifier rates Fraud-Related at p=" + fix2(mlP) + " and the text carries financial terms " + quote(finTerms));
    }
    if (exec[0] >= 0.5 && finTerms.length) {
      why.push(
        "Executive-impersonation pattern (confidence " + fix2(exec[0]) + ", " + (quote(exec[1], 2) || "executive persona") + ") paired with a money request " + quote(finTerms),
      );
    }
    if (why.length) return [FRAUD, why];

    why = [];
    if (cred[0] >= 0.5) {
      why.push("Credential-harvesting BEC pattern (confidence " + fix2(cred[0]) + "): " + (quote(cred[1]) || "credential request paired with a link"));
    }
    if (highUrls.length && credTerms.length) why.push("High-risk link " + describeUrl(highUrls[0]) + " alongside credential terms " + quote(credTerms));
    if (lookalikeLink !== null && (credTerms.length || finTerms.length || handles.length)) {
      var asks = credTerms.length ? credTerms : finTerms.length ? finTerms : handles;
      why.push("Lookalike-domain link (" + lookalikeLink.detail + ") combined with a request for " + quote(asks));
    }
    if (mlCat === PHISHING && mlP >= 0.6 && mediumUrls.length) {
      why.push("ML classifier rates Phishing at p=" + fix2(mlP) + " and the message links to " + describeUrl(mediumUrls[0]));
    }
    if (criticalAtts.length && credTerms.length) {
      var att = criticalAtts[0];
      var reason = att.reasons.length ? att.reasons[0] : att.magic_type || att.extension || "critical risk";
      why.push("Critical attachment '" + att.filename + "' (" + reason + ") delivered with a credential lure " + quote(credTerms));
    }
    if (why.length) return [PHISHING, why];

    why = [];
    if (headerAnalysis.display_name_spoof && !brandVariant) {
      var name = parsed.sender.display_name || parsed.sender.raw || "(empty)";
      var brand = headerAnalysis.display_name_brand || "a trusted identity";
      why.push("Display name '" + short(name, 60) + "' imitates " + brand + " while the sender domain is " + (senderDomain || "unknown"));
    }
    if (exec[0] >= 0.35) {
      why.push("Executive-impersonation pattern (confidence " + fix2(exec[0]) + "): " + (quote(exec[1]) || "first-touch request from an executive persona"));
    }
    lookalikeSenderDomains(domainIntel).forEach(function (d) {
      if (brandVariant && d.role === "sender") return;
      why.push(roleLabel(d.role) + " domain " + d.domain + " is a " + (d.lookalike_technique || "lookalike") + " imitation of " + d.lookalike_of);
    });
    if ((spfFail || dmarcFail) && protectedSender) {
      var failed = [
        ["SPF", spfFail],
        ["DMARC", dmarcFail],
      ]
        .filter(function (pair) {
          return pair[1];
        })
        .map(function (pair) {
          return pair[0];
        })
        .join(" and ");
      var owner = orgDomains(cfg).has(senderDomain) ? "protected organisation" : "brand";
      why.push(failed + " fail for " + owner + " domain " + senderDomain + ": the message did not come from the domain it claims");
    }
    if (mlCat === IMPERSONATED && mlP >= 0.6 && anyAuthFailure) {
      why.push("ML classifier rates Impersonated at p=" + fix2(mlP) + " with authentication failure (SPF " + spf + ", DKIM " + dkim + ", DMARC " + dmarc + ")");
    }
    if (why.length) return [IMPERSONATED, why];

    why = [];
    if (violent[0] >= 0.5) why.push("Violent threat or stalking language without a money demand (confidence " + fix2(violent[0]) + "): " + quote(violent[1]));
    if (riskScore >= 25) why.push("Weighted risk score " + riskScore + "/100 is at or above the suspicious threshold of 25");
    var severe = findings.filter(function (f) {
      return sev(f.severity) >= SEVERITY_ORDER.high;
    });
    if (severe.length) {
      why.push(
        severe.length +
          " high/critical finding(s): " +
          quote(
            severe.map(function (f) {
              return f.title;
            }),
          ),
      );
    }
    if (mlCat !== LEGITIMATE && mlP >= 0.6) why.push("ML classifier favours " + mlCat + " at p=" + fix2(mlP));
    if (why.length) return [SUSPICIOUS, why];

    return [
      LEGITIMATE,
      [
        "No policy rule matched: SPF " +
          spf +
          ", DKIM " +
          dkim +
          ", DMARC " +
          dmarc +
          "; " +
          urlAnalysis.urls.length +
          " link(s), " +
          attAnalysis.attachments.length +
          " attachment(s), " +
          nlpAnalysis.bec_patterns.length +
          " BEC pattern(s); risk " +
          riskScore +
          "/100",
      ],
    ];
  }

  function fuseCategory(ruleCat, mlCat, mlProbs, riskScore) {
    var rule = asCategory(ruleCat);
    var ml = asCategory(mlCat);
    var agreement = rule === ml;
    var confidence;
    if (agreement) {
      confidence = Math.min(0.98, 0.75 + 0.25 * mlProb(mlProbs, rule));
    } else {
      confidence = 0.6;
      var ruleIsThreat = rule !== LEGITIMATE;
      if ((ruleIsThreat && riskScore >= 50) || (!ruleIsThreat && riskScore < 25)) confidence += 0.1;
    }
    return [rule, clamp(confidence, 0.0, 1.0), agreement];
  }

  function attributionIndicators(parsed, headerAnalysis, urlAnalysis, attAnalysis, infra) {
    var items = [];
    var shared = headerAnalysis.origin_shared_provider;
    if (headerAnalysis.originating_ip && !shared) items.push("origin_ip:" + headerAnalysis.originating_ip);
    var geo = infra.origin_geo;
    if (geo !== null && !shared) {
      if (geo.asn) items.push("asn:" + geo.asn);
      if (geo.isp) items.push("isp:" + geo.isp);
      if (geo.country_code) items.push("origin_country:" + geo.country_code);
    }
    if (shared) items.push("origin_relay:" + shared);
    if (parsed.sender.address) items.push("sender:" + parsed.sender.address.toLowerCase());
    var senderDomain = registrable(parsed.sender.domain);
    if (senderDomain) items.push("sender_domain:" + senderDomain);
    parsed.reply_to.forEach(function (reply) {
      if (reply.address) items.push("reply_to:" + reply.address.toLowerCase());
    });
    unique(
      urlAnalysis.urls
        .filter(function (u) {
          return u.host;
        })
        .map(function (u) {
          return u.host.toLowerCase();
        }),
    )
      .slice(0, 10)
      .forEach(function (host) {
        items.push("url_host:" + host);
      });
    attAnalysis.attachments.slice(0, 10).forEach(function (att) {
      if (att.sha256) items.push("attachment_sha256:" + att.sha256);
    });
    return unique(items);
  }

  function attributeSource(parsed, headerAnalysis, urlAnalysis, attAnalysis, domainIntel, infra, category, confidence, findings, cfg) {
    var cat = asCategory(category);
    var auth = headerAnalysis.auth;
    var senderDomain = registrable(parsed.sender.domain);
    var senderFree = isFreemail(senderDomain);
    var senderIntel = null;
    var i;
    for (i = 0; i < domainIntel.length; i += 1) {
      if (domainIntel[i].role === "sender") {
        senderIntel = domainIntel[i];
        break;
      }
    }
    if (senderIntel === null) {
      for (i = 0; i < domainIntel.length; i += 1) {
        if (domainIntel[i].domain.toLowerCase() === senderDomain) {
          senderIntel = domainIntel[i];
          break;
        }
      }
    }
    var age = senderIntel !== null ? senderIntel.age_days : null;
    var findingIds = new Set(
      findings.map(function (f) {
        return f.id;
      }),
    );
    var indicators = attributionIndicators(parsed, headerAnalysis, urlAnalysis, attAnalysis, infra);
    var origin = headerAnalysis.originating_ip || "unknown";
    var authSummary = "SPF " + auth.spf + ", DKIM " + auth.dkim + ", DMARC " + auth.dmarc;
    var make = function (source, conf, reasoning) {
      return { source_type: source, confidence: clamp(conf, 0.0, 1.0), reasoning: reasoning, indicators: indicators };
    };

    if (cat === LEGITIMATE) {
      return make("legitimate_sender", confidence, [
        "No threat category was assigned; " + (parsed.sender.address || "the sender") + " passed policy review (" + authSummary + ").",
      ]);
    }

    var lookalikes = lookalikeSenderDomains(domainIntel);
    if (lookalikes.length) {
      var d = lookalikes[0];
      var newly = d.age_days !== null && d.age_days < 90;
      var reasoning = [
        roleLabel(d.role) +
          " domain " +
          d.domain +
          " imitates " +
          d.lookalike_of +
          " (" +
          (d.lookalike_technique || "lookalike") +
          "); the attacker registered a deceptive domain instead of spoofing the real one.",
      ];
      if (newly) reasoning.push("The domain was registered only " + d.age_days + " day(s) ago, typical of purpose-built attack infrastructure.");
      return make("lookalike_domain", newly ? 0.9 : 0.8, reasoning);
    }

    var spfFail = auth.spf.toLowerCase() === "fail";
    var dmarcFail = auth.dmarc.toLowerCase() === "fail";
    var authMissing = findingIds.has("auth_all_missing");
    var established = (age !== null && age >= 365) || isProtectedDomain(senderDomain, cfg);
    var senderLookalike = Boolean(senderIntel !== null && senderIntel.lookalike_of);
    if ((spfFail || dmarcFail || authMissing) && established && !senderLookalike) {
      var failed = [
        ["SPF fail", spfFail],
        ["DMARC fail", dmarcFail],
        ["no SPF/DKIM/DMARC evidence", authMissing],
      ]
        .filter(function (pair) {
          return pair[1];
        })
        .map(function (pair) {
          return pair[0];
        })
        .join(", ");
      var pedigree = age !== null ? "registered " + age + " days ago" : "a known brand or protected organisation";
      var lines = [senderDomain + " is an established domain (" + pedigree + ") but the message failed authentication (" + failed + "): the From address was forged."];
      if (origin !== "unknown") lines.push("Delivery originated from " + origin + ", which is not an authorised sender for " + senderDomain + ".");
      return make("spoofed_domain", dmarcFail ? 0.85 : 0.75, lines);
    }

    var alignedAny = Boolean(auth.spf_aligned) || Boolean(auth.dkim_aligned);
    if (auth.spf.toLowerCase() === "pass" && auth.dkim.toLowerCase() === "pass" && alignedAny && ATTACK.indexOf(cat) >= 0 && !senderFree) {
      return make("compromised_account", 0.7, [
        "SPF and DKIM pass with domain alignment for " +
          senderDomain +
          ", so the message went through that domain's genuine mail system; a " +
          cat +
          " message from a real account points to a compromised mailbox (" +
          parsed.sender.address +
          ").",
      ]);
    }

    var infraReasons = [];
    var infraConf = 0.0;
    var geo = infra.origin_geo;
    var provider = geo !== null ? geo.isp || geo.org : "";
    if (infra.tor_exit) {
      infraReasons.push("Origin IP " + origin + " is a Tor exit node (anonymised attacker infrastructure).");
      infraConf = Math.max(infraConf, 0.85);
    }
    if (senderIntel !== null && senderIntel.is_disposable) {
      infraReasons.push("Sender domain " + senderDomain + " is a disposable mailbox provider.");
      infraConf = Math.max(infraConf, 0.8);
    }
    if (age !== null && age < 90 && !senderFree) {
      infraReasons.push("Sender domain " + senderDomain + " was registered only " + age + " day(s) ago.");
      infraConf = Math.max(infraConf, 0.75);
    }
    if (infra.vpn_or_proxy) {
      infraReasons.push("Origin IP " + origin + " is a VPN/proxy egress point" + (provider ? " (" + provider + ")" : "") + ".");
      infraConf = Math.max(infraConf, 0.7);
    }
    if (infra.hosting_provider) {
      infraReasons.push("Origin IP " + origin + " belongs to a hosting provider" + (provider ? " (" + provider + ")" : "") + " rather than a mail service or ISP.");
      infraConf = Math.max(infraConf, 0.65);
    }
    if (infraReasons.length) return make("direct_attacker_infrastructure", infraConf, infraReasons);

    if (senderFree && (headerAnalysis.display_name_spoof || cat === FRAUD || cat === PHISHING)) {
      var who = headerAnalysis.display_name_brand || parsed.sender.display_name;
      var posture = who ? "posing as " + who : "used for a " + cat + " message";
      return make("direct_attacker_infrastructure", headerAnalysis.display_name_spoof ? 0.6 : 0.55, [
        "Free-mail mailbox " + parsed.sender.address + " " + posture + ": a throwaway account under the attacker's direct control.",
      ]);
    }

    return make("undetermined", 0.3, ["No decisive attribution signal: " + authSummary + "; sender domain " + (senderDomain || "unknown") + "; origin " + origin + "."]);
  }

  function recommendedActions(category, findings, parsed, headerAnalysis, urlAnalysis, attAnalysis, attribution) {
    var cat = asCategory(category);
    var findingIds = new Set(
      findings.map(function (f) {
        return f.id;
      }),
    );
    var sender = parsed.sender.address || "the sender address";
    var senderDomain = registrable(parsed.sender.domain);
    var originIp = headerAnalysis.originating_ip;
    var riskyHosts = unique(
      urlAnalysis.urls
        .filter(function (u) {
          return u.host && sev(u.risk) >= SEVERITY_ORDER.medium;
        })
        .map(function (u) {
          return u.host;
        }),
    );
    var riskyAtts = attAnalysis.attachments.filter(function (a) {
      return sev(a.risk) >= SEVERITY_ORDER.high;
    });
    var actions = [];

    if (cat === LEGITIMATE) {
      var notable = findings
        .filter(function (f) {
          return sev(f.severity) >= SEVERITY_ORDER.medium;
        })
        .map(function (f) {
          return f.title;
        });
      if (notable.length) actions.push("Deliver normally, but keep the residual observations on file for the analyst: " + quote(notable) + ".");
      else actions.push("No action required: the message shows no threat indicators and can be delivered normally.");
      return actions;
    }

    var blockScope = isFreemail(senderDomain) || !senderDomain ? sender : sender + " and the domain " + senderDomain;
    var block = "Block " + blockScope + " at the mail gateway and purge copies of this message from user mailboxes.";
    var threatening = findingIds.has("violent_threat") || findingIds.has("extortion_demand") || findingIds.has("violent_threat_pattern");

    if (threatening) {
      actions.push(
        "Do not pay, reply or negotiate. This is criminal intimidation / extortion, not spam: preserve the original message with its headers and report it to the police through the cybercrime helpline 1930 or cybercrime.gov.in; if the threat is immediate, call 112.",
      );
      actions.push(
        "Ask the mailbox provider's abuse desk (abuse@" +
          (senderDomain || "the sender domain") +
          ") to preserve the account and login records for " +
          sender +
          "; only the provider can identify who was behind the webmail session.",
      );
    }
    if (findingIds.has("payment_handle") && ATTACK.indexOf(cat) >= 0) {
      actions.push(
        "Report the payment handle named in the message (UPI ID, wallet or remittance reference) to the payment provider and NPCI so the account can be frozen before further victims pay.",
      );
    }

    if (cat === FRAUD) {
      if (findingIds.has("bec_payment_diversion") || findingIds.has("bec_fake_invoice")) {
        actions.push(
          "Do not act on any payment or bank-detail instruction in this message: have Finance verify the change with the counterparty on a previously known phone number, never by replying to this thread.",
        );
      } else if (findingIds.has("callback_scam")) {
        actions.push("Do not call the number in the message or install any remote-access tool it asks for; genuine vendors never raise support cases by unsolicited email.");
      } else if (!threatening) {
        actions.push("Treat every request for money, fees or personal identifiers in this message as fraudulent; do not respond, pay or share documents.");
      }
      actions.push(block);
    } else if (cat === PHISHING) {
      actions.push("Reset passwords and revoke active sessions for any recipient who followed the link or entered credentials; enforce MFA on the affected accounts.");
      if (riskyHosts.length) actions.push("Block the phishing host(s) " + quote(riskyHosts) + " at the web proxy / DNS filter.");
      actions.push(block);
    } else if (cat === IMPERSONATED) {
      var who = headerAnalysis.display_name_brand || parsed.sender.display_name || "the claimed sender";
      actions.push("Verify any request in this message with " + who + " through an independent, known channel (phone or in person); do not reply to the message.");
      actions.push(block);
      if (headerAnalysis.display_name_spoof && parsed.sender.display_name) {
        actions.push("Add a gateway rule that flags external mail using the display name '" + short(parsed.sender.display_name, 60) + "'.");
      }
    } else if (threatening) {
      actions.push(block);
    } else {
      actions.push("Quarantine the message pending analyst review; do not open attachments or follow links until the sender is verified.");
      actions.push("Verify the sender (" + sender + ") through a known contact channel before responding.");
    }

    riskyAtts.slice(0, 2).forEach(function (att) {
      var reason = att.reasons.length ? att.reasons[0] : att.magic_type || att.extension || att.content_type || "risky file type";
      var hashNote = att.sha256 ? " and block its SHA-256 " + att.sha256.slice(0, 16) + "..." : "";
      actions.push("Do not open attachment '" + att.filename + "' (" + att.risk + ": " + reason + "); detonate it in a sandbox" + hashNote + ".");
    });
    if (findingIds.has("tor_exit_node")) {
      actions.push("The origin IP is a Tor exit node and does not identify the actor; pivot on the Reply-To address, link hosts and attachment hashes instead.");
    }
    if (attribution !== null && attribution.source_type === "compromised_account" && senderDomain) {
      actions.push("Notify the administrator of " + senderDomain + " that the mailbox " + sender + " appears compromised so they can secure it.");
    }
    if (findingIds.has("known_campaign_overlap")) {
      actions.push("This message overlaps with prior incidents: extend containment to every member of the campaign and review the shared indicators.");
    }

    var iocs = [];
    if (originIp && !headerAnalysis.origin_shared_provider) iocs.push("origin IP " + originIp);
    riskyHosts.slice(0, 3).forEach(function (host) {
      iocs.push("host " + host);
    });
    attAnalysis.attachments.slice(0, 2).forEach(function (att) {
      if (att.sha256) iocs.push("SHA-256 " + att.sha256);
    });
    parsed.reply_to.forEach(function (reply) {
      if (reply.address) iocs.push("Reply-To " + reply.address);
    });
    if (iocs.length) actions.push("Add these IOCs to the mail gateway / SIEM blocklists: " + iocs.join("; ") + ".");

    if (cat === SUSPICIOUS && !threatening) {
      actions.push("Monitor for further messages from " + sender + (originIp ? " and origin IP " + originIp : "") + "; escalate if the pattern repeats.");
    } else {
      actions.push(
        "Preserve the original .eml and this report as evidence (hashes are recorded in the custody ledger) and report the incident to CERT-In (incident@cert-in.org.in) and the National Cybercrime Reporting Portal (cybercrime.gov.in).",
      );
    }
    var subject = short(parsed.subject, 60) || "(no subject)";
    actions.push("Circulate a short user-awareness note describing this lure (subject: '" + subject + "') so recipients recognise similar messages.");
    return unique(actions).slice(0, 10);
  }

  function sortFindings(findings) {
    return py().sorted(findings, function (f) {
      return [-sev(f.severity), f.module, f.id];
    });
  }

  function softenBrandVariant(findings, headerAnalysis, brand) {
    var note =
      " The domain authenticates with SPF, DKIM and DMARC and every link points to " +
      brand +
      "'s genuine sites, so this looks like an alternate domain owned by " +
      brand +
      " rather than an imitation; treat it as informational.";
    findings.forEach(function (f) {
      if ((f.module === "domains" && f.id === "lookalike_domain") || (f.module === "headers" && f.id === "display_name_spoof")) {
        f.severity = "low";
        f.detail = py().rstrip(f.detail) + note;
      }
    });
    headerAnalysis.display_name_spoof = false;
    var sorted = sortFindings(findings);
    findings.length = 0;
    sorted.forEach(function (f) {
      findings.push(f);
    });
  }

  function collectFindings(groups) {
    var seen = new Set();
    var merged = [];
    groups.forEach(function (group) {
      if (!group) return;
      group.forEach(function (f) {
        var key = f.module + "\u0000" + f.id;
        if (seen.has(key)) return;
        seen.add(key);
        merged.push(f);
      });
    });
    return sortFindings(merged);
  }

  function scoreUrlsWithModel(urlAnalysis, domainIntel) {
    if (!urlAnalysis.urls.length) return [null, null];
    var outcome;
    try {
      outcome = MT.urlmodel.scoreUrls(urlAnalysis.urls, domainIntel);
    } catch (error) {
      if (MT.trace) MT.trace(error);
      return [null, null];
    }
    if (outcome === null) return [null, null];
    var worst = outcome.per_url.length ? outcome.per_url[0] : ["", 0.0];
    var probability = clamp(outcome.max_probability, 0.0, 1.0);
    var severity = probability >= 0.8 ? "high" : probability >= 0.5 ? "medium" : "info";
    var finding = {
      id: "url_model_assessment",
      module: "scoring",
      severity: severity,
      title: "ML link assessment",
      detail:
        "The gradient-boosted URL model (" +
        outcome.model +
        ") rates the worst of " +
        outcome.n_urls +
        " link(s) at p=" +
        py().fixed(probability, 2) +
        " malicious (" +
        short(worst[0], 70) +
        "). It runs alongside the deterministic link rules and can only raise the URL pillar, never lower it.",
      evidence: {
        model: outcome.model,
        max_probability: py().round(probability, 4),
        n_urls: outcome.n_urls,
        n_with_domain_intel: outcome.n_with_intel,
        per_url: outcome.per_url.slice(0, 8).map(function (pair) {
          return { url: pair[0], probability: py().round(pair[1], 4) };
        }),
        blend: "url = max(rules, rules + (100 - rules) * " + URL_MODEL_ALPHA + " * p)",
      },
    };
    return [outcome, finding];
  }

  function evaluate(parsed, headerAnalysis, urlAnalysis, attAnalysis, nlpAnalysis, domainIntel, infra, intel, cfg) {
    var findings = collectFindings(
      [headerAnalysis.findings, urlAnalysis.findings, attAnalysis.findings, nlpAnalysis.findings].concat(
        domainIntel.map(function (d) {
          return d.findings;
        }),
        [infra.findings, intel.findings],
      ),
    );
    var senderDomain = registrable(parsed.sender.domain);
    var brandVariant = brandOwnedVariant(parsed, headerAnalysis, urlAnalysis, attAnalysis, nlpAnalysis, domainIntel);
    if (brandVariant) softenBrandVariant(findings, headerAnalysis, brandVariant);
    var scored = scoreUrlsWithModel(urlAnalysis, domainIntel);
    var urlModel = scored[0];
    var urlModelFinding = scored[1];
    var breakdown = componentScores(headerAnalysis, urlAnalysis, attAnalysis, nlpAnalysis, domainIntel, infra, intel, cfg, senderDomain, urlModel, brandVariant);
    var rawRisk = weightedRisk(breakdown);
    var rationale = [breakdownLine(breakdown, rawRisk)];
    if (brandVariant) {
      rationale.push(
        "Sender domain " +
          senderDomain +
          " is a TLD variant of " +
          brandVariant +
          " that authenticates (SPF, DKIM, DMARC) and links only to " +
          brandVariant +
          "'s genuine sites, so it is treated as a brand-owned alternate domain, not an imitation.",
      );
    }
    if (urlModel !== null) {
      var ruleOnly = deterministicUrlScore(urlAnalysis, domainIntel, "");
      rationale.push(
        "URL model " +
          urlModel.model +
          " rates the worst of " +
          urlModel.n_urls +
          " link(s) at p=" +
          py().fixed(urlModel.max_probability, 2) +
          " malicious; URL pillar " +
          py().fixed(ruleOnly, 0) +
          " -> " +
          py().fixed(breakdown.url, 0) +
          " (rules stay the floor).",
      );
    }

    var ruled = ruleClassify(parsed, headerAnalysis, urlAnalysis, attAnalysis, nlpAnalysis, domainIntel, findings, rawRisk, cfg, brandVariant);
    var ruleCat = ruled[0];
    var ruleLines = ruled[1];
    ruleLines.forEach(function (line) {
      rationale.push(line);
    });

    var mlCat = asCategory(nlpAnalysis.ml_category);
    var mlP = mlProb(nlpAnalysis.ml_probabilities, mlCat);
    var modelName = nlpAnalysis.ml_model || "unavailable";
    var fused = fuseCategory(ruleCat, mlCat, nlpAnalysis.ml_probabilities, rawRisk);
    var category = fused[0];
    var confidence = fused[1];
    var agreement = fused[2];
    var scoringFindings = urlModelFinding !== null ? [urlModelFinding] : [];
    if (agreement) {
      rationale.push("ML classifier (" + modelName + ") agrees: " + mlCat + " (p=" + py().fixed(mlP, 2) + "); confidence " + py().fixed(confidence, 2) + ".");
    } else {
      var because = ruleLines.length ? ruleLines[0] : "the policy rules above";
      rationale.push(
        "ML model favoured " + mlCat + " (p=" + py().fixed(mlP, 2) + "); rule engine selected " + ruleCat + " because " + because + ". Confidence lowered to " + py().fixed(confidence, 2) + ".",
      );
      scoringFindings.push({
        id: "dual_validation_disagreement",
        module: "scoring",
        severity: "low",
        title: "Rule engine and ML classifier disagree",
        detail:
          "The rule engine classified the message as " +
          ruleCat +
          " while the ML model favoured " +
          mlCat +
          " (p=" +
          py().fixed(mlP, 2) +
          "). The rule verdict stands; confidence was reduced to " +
          py().fixed(confidence, 2) +
          ".",
        evidence: { rule_category: ruleCat, ml_category: mlCat, ml_probability: py().round(mlP, 3), ml_model: modelName, risk_score: rawRisk },
      });
    }

    var risk = rawRisk;
    var ceiling = K().LEGITIMATE_RISK_CEILING;
    if (category === LEGITIMATE && risk >= ceiling) {
      category = SUSPICIOUS;
      rationale.push("Risk score " + risk + "/100 is too high for a Legitimate verdict (ceiling " + ceiling + "); category raised to Suspicious.");
    }
    var floors = K().RISK_FLOORS;
    var floor = floors.has(category) ? floors.get(category) : 0;
    var violent = becConfidence(nlpAnalysis, "violent_threat");
    if (violent[0] >= 0.5 && category !== LEGITIMATE) floor = Math.max(floor, K().VIOLENT_THREAT_RISK_FLOOR);
    if (risk < floor) {
      rationale.push("Risk score raised from " + risk + " to the " + category + " floor of " + floor + ".");
      scoringFindings.push({
        id: "risk_floor_applied",
        module: "scoring",
        severity: "info",
        title: "Risk floor applied",
        detail: "The weighted score was " + risk + "/100 but a " + category + " verdict carries a minimum risk of " + floor + "; the score was raised to " + floor + ".",
        evidence: { category: category, weighted_risk: risk, floor: floor },
      });
      risk = floor;
    }

    var allFindings = collectFindings([findings, scoringFindings]);
    var attribution = attributeSource(parsed, headerAnalysis, urlAnalysis, attAnalysis, domainIntel, infra, category, confidence, allFindings, cfg);
    var verdict = {
      category: category,
      confidence: confidence,
      risk_score: risk,
      severity: severityFor(risk, allFindings.length > 0),
      breakdown: breakdown,
      ml_category: mlCat,
      rule_category: ruleCat,
      dual_validation_agreement: agreement,
      rationale: rationale,
      recommended_actions: recommendedActions(category, allFindings, parsed, headerAnalysis, urlAnalysis, attAnalysis, attribution),
    };
    return { verdict: verdict, attribution: attribution, findings: allFindings };
  }

  MT.scoring = {
    evaluate: evaluate,
    componentScores: componentScores,
    weightedRisk: weightedRisk,
    ruleClassify: ruleClassify,
    fuseCategory: fuseCategory,
    attributeSource: attributeSource,
    recommendedActions: recommendedActions,
    collectFindings: collectFindings,
    severityFor: severityFor,
  };
})(MT);
