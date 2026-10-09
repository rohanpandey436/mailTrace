var MT = MT || {};

(function (MT) {
  var RISK_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  var LABELS = { sender: "Sender", reply_to: "Reply-To", return_path: "Return-Path", url: "Link", message_id: "Message-ID" };

  function py() {
    return MT.py;
  }

  function isIp(value) {
    return MT.net.tryAddress(value) !== null;
  }

  function finding(id, severity, title, detail, evidence) {
    return { id: id, module: "domains", severity: severity, title: title, detail: detail, evidence: evidence };
  }

  function domainReputation(domain) {
    var tags = [];
    if (!domain) return tags;
    var knowledge = MT.K("knowledge");
    if (knowledge.DISPOSABLE_DOMAINS.has(domain)) tags.push("disposable");
    var tld = py().rsplit(domain, ".", 1).pop();
    if (knowledge.SUSPICIOUS_TLDS.has(tld) && !knowledge.FREEMAIL_DOMAINS.has(domain)) tags.push("suspicious_tld");
    return tags;
  }

  function emptyIntel(domain, role) {
    return {
      domain: domain,
      role: role || "",
      registrar: "",
      created: null,
      expires: null,
      age_days: null,
      registrant_country: "",
      name_servers: [],
      mx: [],
      a_records: [],
      spf_record: "",
      dmarc_record: "",
      has_mx: false,
      resolves: false,
      is_free_mail: false,
      is_disposable: false,
      lookalike_of: "",
      lookalike_technique: "",
      hosting_fingerprint: "",
      reputation: [],
      source: "",
      findings: [],
    };
  }

  function analyzeDomain(input, role, cfg) {
    var domain = py().rstrip(py().strip(input || "").toLowerCase(), ".");
    var intel = emptyIntel(domain, role);
    if (!domain) return intel;
    var knowledge = MT.K("knowledge");
    intel.is_free_mail = knowledge.FREEMAIL_DOMAINS.has(domain);
    intel.is_disposable = knowledge.DISPOSABLE_DOMAINS.has(domain);
    var org = MT.urls.orgDomains(cfg);
    var lookalike = MT.urls.isLookalike(domain, cfg);
    intel.lookalike_of = lookalike[0];
    intel.lookalike_technique = lookalike[1];
    intel.source = "offline";
    intel.reputation = domainReputation(domain);

    var findings = [];
    var label = MT.own(LABELS, role) ? LABELS[role] : "Domain";
    if (lookalike[0]) {
      var critical = org.has(lookalike[0]) || MT.K("domain_intel")._BANK_BRANDS.has(lookalike[0]);
      findings.push(
        finding(
          "lookalike_domain",
          critical ? "critical" : "high",
          "Lookalike " + label.toLowerCase() + " domain",
          domain + " imitates " + lookalike[0] + " using the " + py().replaceAll(lookalike[1], "_", " ") + " technique.",
          { domain: domain, imitates: lookalike[0], technique: lookalike[1], role: role },
        ),
      );
    }
    if (role === "sender" && intel.is_free_mail) {
      findings.push(
        finding("free_mail_sender", "low", "Free-mail sender", "The sender uses a free public mailbox provider (" + domain + "); business or institutional mail rarely does.", {
          domain: domain,
        }),
      );
    }
    if (intel.is_disposable) {
      findings.push(finding("disposable_domain", "high", "Disposable " + label.toLowerCase() + " domain", domain + " is a throwaway/temporary mailbox provider.", { domain: domain }));
    }
    var feeds = intel.reputation.filter(function (t) {
      return t !== "disposable" && t !== "suspicious_tld";
    });
    if (feeds.length) {
      findings.push(
        finding("domain_blocklisted", "critical", label + " domain on threat feed", domain + " is listed by " + feeds.join(", ") + " as hosting malicious content.", {
          domain: domain,
          feeds: feeds,
        }),
      );
    }
    var bits = ["role " + (role || "n/a")];
    bits.push("DNS not queried");
    if (intel.reputation.length) bits.push("tags " + intel.reputation.join(", "));
    findings.push(
      finding("domain_intel", "info", "Domain intelligence: " + domain, bits.join("; ") + ".", {
        domain: domain,
        role: role,
        age_days: intel.age_days,
        mx: intel.mx,
        a_records: intel.a_records,
        reputation: intel.reputation,
        source: intel.source,
      }),
    );
    intel.findings = findings;
    return intel;
  }

  function collectDomains(parsed, headerAnalysis, urlAnalysis, cfg) {
    var hosts = MT.K("knowledge").COMMON_URL_HOSTS;
    var common = new Set();
    hosts.forEach(function (h) {
      common.add(MT.urls.registrableDomain(h));
      common.add(h);
    });
    var seen = new Set();
    var targets = [];
    var add = function (host, role) {
      var rd = MT.urls.registrableDomain(host);
      if (!rd || seen.has(rd) || isIp(rd) || rd.indexOf(".") < 0) return;
      if (role === "url" && common.has(rd)) return;
      seen.add(rd);
      targets.push([rd, role]);
    };
    add(parsed.sender.domain, "sender");
    parsed.reply_to.forEach(function (reply) {
      add(reply.domain, "reply_to");
    });
    add(parsed.return_path.domain, "return_path");
    add(headerAnalysis.message_id_domain, "message_id");
    var ranked = py().sorted(urlAnalysis.urls, function (u) {
      return -RISK_RANK[u.risk];
    });
    ranked.forEach(function (url) {
      add(url.registrable_domain || url.host, "url");
    });
    var limit = Math.max(1, Math.floor(cfg.max_domain_lookups || 6));
    return targets.slice(0, limit);
  }

  function analyzeDomains(targets, cfg, enrichment) {
    if (!targets.length) return [];
    return targets.map(function (target) {
      var domain = target[0];
      var role = target[1];
      if (enrichment && enrichment.domains && enrichment.domains.has(domain)) {
        var provided = JSON.parse(JSON.stringify(enrichment.domains.get(domain)));
        provided.role = role;
        return provided;
      }
      try {
        return analyzeDomain(domain, role, cfg);
      } catch (error) {
        if (MT.trace) MT.trace(error);
        var fallback = emptyIntel(domain, role);
        fallback.source = "unavailable";
        return fallback;
      }
    });
  }

  MT.domains = {
    analyzeDomain: analyzeDomain,
    analyzeDomains: analyzeDomains,
    collectDomains: collectDomains,
    domainReputation: domainReputation,
    emptyIntel: emptyIntel,
  };
})(MT);
