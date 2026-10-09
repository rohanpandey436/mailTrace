var MT = MT || {};

(function (MT) {
  function py() {
    return MT.py;
  }

  function K() {
    return MT.K("threat_intel");
  }

  function isIp(value) {
    return MT.net.tryAddress(value) !== null;
  }

  function normalizeSubject(subject) {
    var text = MT.RX("threat_intel", "_SUBJECT_PREFIX_RE").sub("", (subject || "").toLowerCase());
    text = py().re("\\d+").sub("#", text);
    text = py().strip(py().re("\\s+").sub(" ", text));
    return py().slice(text, 0, 80);
  }

  function isStrong(indicator) {
    return K().STRONG_PREFIXES.some(function (prefix) {
      return indicator.slice(0, prefix.length) === prefix;
    });
  }

  function extractIndicators(parsed, headerAnalysis, urlAnalysis, attAnalysis, domainIntel, infra) {
    var indicators = [];
    var geo = infra.origin_geo;
    var sharedOrigin = Boolean(headerAnalysis.origin_shared_provider) || Boolean(geo !== null && MT.knowledge.sharedProvider(geo.reverse_dns));
    if (headerAnalysis.originating_ip && !sharedOrigin) indicators.push("ip:" + headerAnalysis.originating_ip);
    var sender = (parsed.sender.address || "").toLowerCase();
    if (sender) indicators.push("sender:" + sender);
    var senderRd = MT.urls.registrableDomain(parsed.sender.domain);
    var knowledge = MT.K("knowledge");
    if (senderRd && !knowledge.FREEMAIL_DOMAINS.has(senderRd) && !isIp(senderRd)) indicators.push("domain:" + senderRd);
    parsed.reply_to.forEach(function (reply) {
      if (reply.address) indicators.push("replyto:" + reply.address.toLowerCase());
    });
    var common = new Set(knowledge.COMMON_URL_HOSTS);
    knowledge.COMMON_URL_HOSTS.forEach(function (h) {
      common.add(MT.urls.registrableDomain(h));
    });
    urlAnalysis.urls.forEach(function (url) {
      var host = (url.host || "").toLowerCase();
      if (!host || common.has(host) || common.has(url.registrable_domain) || isIp(host)) return;
      indicators.push("urlhost:" + host);
    });
    attAnalysis.attachments.forEach(function (att) {
      if (att.sha256 && att.content_type.toLowerCase().slice(0, 6) !== "image/") indicators.push("file:" + att.sha256);
    });
    var subject = normalizeSubject(parsed.subject);
    if (py().length(subject) >= 12) indicators.push("subject:" + subject);
    if (geo !== null && geo.asn && !sharedOrigin) indicators.push("asn:" + geo.asn.toUpperCase());
    if (parsed.mailer) indicators.push("mailer:" + py().slice(parsed.mailer.toLowerCase(), 0, 60));
    if (parsed.fuzzy.body_length >= K().FUZZY_MIN_BODY) {
      if (parsed.fuzzy.simhash) indicators.push("simhash:" + parsed.fuzzy.simhash);
      if (parsed.fuzzy.tlsh) indicators.push("tlsh:" + parsed.fuzzy.tlsh);
    }
    return py().unique(indicators);
  }

  function finding(id, severity, title, detail, evidence) {
    return { id: id, module: "intel", severity: severity, title: title, detail: detail, evidence: evidence };
  }

  function correlate(parsed, headerAnalysis, urlAnalysis, attAnalysis, domainIntel, infra, matches, cfg) {
    var indicators = extractIndicators(parsed, headerAnalysis, urlAnalysis, attAnalysis, domainIntel, infra);
    var intel = {
      indicators: indicators,
      ip_blacklists: {},
      domain_reputation: {},
      tor_exits: [],
      related_incidents: [],
      campaign_id: null,
      findings: [],
    };
    var geos = headerAnalysis.hops
      .filter(function (hop) {
        return hop.geo !== null;
      })
      .map(function (hop) {
        return hop.geo;
      });
    if (infra.origin_geo !== null) geos.push(infra.origin_geo);
    geos.forEach(function (geo) {
      if (geo.blacklists.length) {
        var merged = new Set(MT.own(intel.ip_blacklists, geo.ip) ? intel.ip_blacklists[geo.ip] : []);
        geo.blacklists.forEach(function (zone) {
          merged.add(zone);
        });
        intel.ip_blacklists[geo.ip] = py().sorted(Array.from(merged));
      }
      if (geo.is_tor_exit && intel.tor_exits.indexOf(geo.ip) < 0) intel.tor_exits.push(geo.ip);
    });
    var localTags = K()._LOCAL_TAGS;
    domainIntel.forEach(function (domain) {
      var feeds = domain.reputation.filter(function (t) {
        return !localTags.has(t);
      });
      if (feeds.length) intel.domain_reputation[domain.domain] = feeds;
    });

    var findings = [];
    var blacklistIps = Object.keys(intel.ip_blacklists);
    var flaggedDomains = Object.keys(intel.domain_reputation);
    if (blacklistIps.length || flaggedDomains.length || intel.tor_exits.length) {
      var parts = [];
      blacklistIps.forEach(function (ip) {
        parts.push(ip + " listed on " + intel.ip_blacklists[ip].join(", "));
      });
      flaggedDomains.forEach(function (domain) {
        parts.push(domain + " flagged by " + intel.domain_reputation[domain].join(", "));
      });
      intel.tor_exits.forEach(function (ip) {
        parts.push(ip + " is a Tor exit node");
      });
      findings.push(
        finding("threat_feed_hit", "high", "Threat-intelligence feed hit", parts.join("; ") + ".", {
          ip_blacklists: intel.ip_blacklists,
          domain_reputation: intel.domain_reputation,
          tor_exits: intel.tor_exits,
        }),
      );
    }

    if (matches !== null && matches !== undefined) {
      var related = matches.incidents || [];
      related.forEach(function (incident) {
        intel.related_incidents.push({
          email_id: incident.email_id || "",
          subject: incident.subject || "",
          sender: incident.sender || "",
          risk_score: incident.risk_score,
          category: incident.category,
          shared_indicators: incident.shared_indicators || [],
        });
      });
      if (intel.related_incidents.length) {
        var worst = 0;
        var sharedSet = new Set();
        intel.related_incidents.forEach(function (r) {
          worst = Math.max(worst, r.risk_score);
          r.shared_indicators.forEach(function (s) {
            sharedSet.add(s);
          });
        });
        var shared = py().sorted(Array.from(sharedSet));
        var fuzzyPrefixes = K().FUZZY_MATCH_PREFIXES;
        var isFuzzy = function (s) {
          return fuzzyPrefixes.some(function (prefix) {
            return s.slice(0, prefix.length) === prefix;
          });
        };
        var fuzzyTags = shared.filter(isFuzzy);
        var detail =
          intel.related_incidents.length +
          " earlier message(s) share indicators " +
          shared.slice(0, 4).join(", ") +
          (shared.length > 4 ? " ..." : "") +
          "; highest prior risk " +
          worst +
          "/100.";
        if (fuzzyTags.length) {
          var exactOnly = shared.filter(function (s) {
            return !isFuzzy(s);
          });
          detail +=
            " " +
            (exactOnly.length ? "Part of that overlap is" : "That overlap is") +
            " a near-duplicate body rather than an exact indicator (" +
            fuzzyTags.slice(0, 3).join(", ") +
            " - the number is the fuzzy-digest distance, 0 being identical text), so re-worded copies of the same lure still group together.";
        }
        findings.push(
          finding("known_campaign_overlap", worst >= 50 ? "high" : "medium", "Overlaps with prior incidents", detail, {
            related: intel.related_incidents.map(function (r) {
              return r.email_id;
            }),
            shared_indicators: shared,
            fuzzy_matches: fuzzyTags,
            body_length: parsed.fuzzy.body_length,
          }),
        );
        intel.campaign_id = matches.campaign_id || null;
      } else {
        findings.push(
          finding("no_prior_incidents", "info", "No prior incidents", "None of this message's indicators appear in previously analysed emails.", {
            indicators: indicators.slice(0, 12),
          }),
        );
      }
    }
    intel.findings = findings;
    return intel;
  }

  MT.intel = {
    extractIndicators: extractIndicators,
    correlate: correlate,
    normalizeSubject: normalizeSubject,
    isStrong: isStrong,
  };
})(MT);
