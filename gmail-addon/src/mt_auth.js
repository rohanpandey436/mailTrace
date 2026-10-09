var MT = MT || {};

(function (MT) {
  var MODULE = "auth";

  function py() {
    return MT.py;
  }

  function K() {
    return MT.K("auth_checker");
  }

  function RX(name) {
    return MT.RX("auth_checker", name);
  }

  function stripComments(text) {
    return MT.headers.stripComments(text);
  }

  function splitTopLevel(text, separator) {
    var parts = [];
    var depth = 0;
    var start = 0;
    for (var i = 0; i < text.length; i += 1) {
      var ch = text[i];
      if (ch === "(") {
        depth += 1;
      } else if (ch === ")") {
        if (depth > 0) depth -= 1;
      } else if (ch === separator && depth === 0) {
        parts.push(text.slice(start, i));
        start = i + 1;
      }
    }
    parts.push(text.slice(start));
    return parts
      .map(function (p) {
        return py().strip(p);
      })
      .filter(Boolean);
  }

  function unquote(value) {
    return py().strip(py().strip(py().strip(py().strip(value), '"'), "<>"));
  }

  function domainPart(input) {
    var value = unquote(input);
    if (value.indexOf("@") >= 0) value = py().rsplit(value, "@", 1)[1];
    return py().rstrip(value.toLowerCase(), ".");
  }

  function normaliseResult(value) {
    var result = py().strip(value).toLowerCase();
    var aliases = K()._RESULT_ALIASES;
    return aliases.has(result) ? aliases.get(result) : result;
  }

  function hostIn(host, domains) {
    return MT.headers.hostMatches(host, domains);
  }

  function isPublic(ip) {
    if (MT.net.tryAddress(py().strip(ip)) === null) return false;
    return !MT.headers.isPrivateIp(ip);
  }

  function aligned(domain, senderRd) {
    if (!domain || !senderRd) return null;
    return MT.urls.registrableDomain(domain) === senderRd;
  }

  function properties(pattern, text) {
    var props = new Map();
    pattern.finditer(text).forEach(function (match) {
      props.set(match[1].toLowerCase(), unquote(match[2]));
    });
    return props;
  }

  function parseAuthenticationResults(headers) {
    var spf = ["", ""];
    var dkim = ["", "", ""];
    var dmarc = ["", ""];
    headers.forEach(function (field) {
      var name = field.name.toLowerCase();
      if (name !== "authentication-results" && name !== "arc-authentication-results") return;
      var dkimHere = [];
      splitTopLevel(py().joinWords(field.value), ";").forEach(function (segment) {
        var match = RX("_AR_METHOD_RE").match(stripComments(segment));
        if (!match) return;
        var method = match[1].toLowerCase();
        var result = normaliseResult(match[2]);
        var props = properties(RX("_AR_PROPERTY_RE"), segment);
        var get = function (key) {
          return props.has(key) ? props.get(key) : "";
        };
        if (method === "spf" && !spf[0]) {
          var domain = domainPart(get("smtp.mailfrom")) || domainPart(get("smtp.helo"));
          spf = [result, domain];
        } else if (method === "dkim") {
          var signer = domainPart(get("header.d")) || domainPart(get("header.i"));
          dkimHere.push([result, signer, get("header.s").toLowerCase()]);
        } else if (method === "dmarc" && !dmarc[0]) {
          var policy = RX("_DMARC_POLICY_RE").search(segment);
          dmarc = [result, policy ? policy[1].toLowerCase() : ""];
        }
      });
      if (dkimHere.length && !dkim[0]) {
        var passing = dkimHere.filter(function (entry) {
          return entry[0] === "pass";
        });
        dkim = passing.length ? passing[0] : dkimHere[0];
      }
    });
    if (!spf[0]) {
      for (var i = 0; i < headers.length; i += 1) {
        var field = headers[i];
        if (field.name.toLowerCase() !== "received-spf") continue;
        var text = py().joinWords(field.value);
        var match = py().re("\\s*([A-Za-z]+)").match(text);
        if (!match) continue;
        var props = properties(RX("_RECEIVED_SPF_PROPERTY_RE"), text);
        var get = function (key) {
          return props.has(key) ? props.get(key) : "";
        };
        var domain = domainPart(get("envelope-from"));
        if (!domain) {
          var found = RX("_RECEIVED_SPF_DOMAIN_RE").search(text);
          domain = found ? py().rstrip(found[1].toLowerCase(), ".") : "";
        }
        if (!domain) domain = domainPart(get("helo"));
        spf = [normaliseResult(match[1]), domain];
        break;
      }
    }
    return { spf: spf, dkim: dkim, dmarc: dmarc };
  }

  function parseTags(value) {
    var tags = new Map();
    value.split(";").forEach(function (part) {
      if (part.indexOf("=") < 0) return;
      var pieces = py().partition(part, "=");
      var key = py().strip(pieces[0]).toLowerCase();
      if (key && !tags.has(key)) tags.set(key, py().split(pieces[2]).join(""));
    });
    return tags;
  }

  function parseDkimSignature(headers) {
    for (var i = 0; i < headers.length; i += 1) {
      if (headers[i].name.toLowerCase() !== "dkim-signature") continue;
      var tags = parseTags(headers[i].value);
      var get = function (key) {
        return tags.has(key) ? tags.get(key) : "";
      };
      return { d: py().rstrip(get("d").toLowerCase(), "."), s: get("s"), a: get("a").toLowerCase(), h: get("h").toLowerCase() };
    }
    return null;
  }

  function boundaryHop(headerAnalysis, cfg) {
    var hops = headerAnalysis.hops;
    for (var i = hops.length - 1; i >= 0; i -= 1) {
      var hop = hops[i];
      if (hop.from_ip && !hop.is_private_ip && !hostIn(hop.from_host, cfg.org_domains) && !hostIn(hop.from_host, cfg.trusted_relays)) return hop;
    }
    return null;
  }

  function finding(id, severity, title, detail, evidence) {
    return { id: id, module: MODULE, severity: severity, title: title, detail: detail, evidence: evidence };
  }

  function evaluateAuth(parsed, headerAnalysis, cfg) {
    var notes = [];
    var recorded = parseAuthenticationResults(parsed.headers);
    var arSpf = recorded.spf[0];
    var arSpfDomain = recorded.spf[1];
    var arDkim = recorded.dkim[0];
    var arDkimDomain = recorded.dkim[1];
    var arDkimSelector = recorded.dkim[2];
    var arDmarc = recorded.dmarc[0];
    var arDmarcPolicy = recorded.dmarc[1];
    var signature = parseDkimSignature(parsed.headers);
    var hasRecorded = Boolean(arSpf || arDkim || arDmarc);
    var registrable = MT.urls.registrableDomain;

    var senderDomain = py().rstrip((parsed.sender.domain || "").toLowerCase(), ".");
    var senderRd = senderDomain ? registrable(senderDomain) : "";
    var boundary = boundaryHop(headerAnalysis, cfg);
    var boundaryIp = boundary ? boundary.from_ip : isPublic(headerAnalysis.originating_ip) ? headerAnalysis.originating_ip : "";
    var heloDomain = boundary ? boundary.from_host : "";
    var spfDomain = py().rstrip((parsed.return_path.domain || "").toLowerCase(), ".") || arSpfDomain || heloDomain;

    notes.push("network enrichment disabled: verdicts derived from Authentication-Results headers only");

    var spf;
    var spfSource;
    if (arSpf) {
      spf = arSpf;
      spfSource = "authentication-results";
    } else {
      spf = "none";
      spfSource = "offline";
    }
    var spfAligned = aligned(spfDomain, senderRd);

    var sigDomain = signature ? signature.d : "";
    var sigSelector = signature ? signature.s : "";
    var dkimDomain = sigDomain || arDkimDomain;
    var dkimSelector = sigSelector || arDkimSelector;
    var dkim;
    var dkimSource;
    if (arDkim) {
      dkim = arDkim;
      dkimSource = "authentication-results";
    } else if (signature) {
      dkim = "unverifiable";
      dkimSource = "offline";
    } else {
      dkim = "none";
      dkimSource = "none";
    }
    var dkimAligned = aligned(dkimDomain, senderRd);

    var dmarc;
    var dmarcSource;
    if (arDmarc) {
      dmarc = arDmarc;
      dmarcSource = "authentication-results";
    } else if ((spf === "pass" && spfAligned === true) || (dkim === "pass" && dkimAligned === true)) {
      dmarc = "pass";
      dmarcSource = "computed";
    } else {
      dmarc = "none";
      dmarcSource = "offline";
    }
    var dmarcPolicy = arDmarcPolicy;

    notes.push("summary: spf=" + spf + " (" + spfSource + "), dkim=" + dkim + " (" + dkimSource + "), dmarc=" + dmarc + " (" + dmarcSource + ")");
    var result = {
      spf: spf,
      spf_domain: spfDomain,
      spf_source: spfSource,
      dkim: dkim,
      dkim_domain: dkimDomain,
      dkim_selector: dkimSelector,
      dkim_source: dkimSource,
      dmarc: dmarc,
      dmarc_policy: dmarcPolicy,
      dmarc_source: dmarcSource,
      spf_aligned: spfAligned,
      dkim_aligned: dkimAligned,
      notes: notes,
    };

    var findings = [];
    var spfWhere = boundaryIp ? boundaryIp + " " : "";
    var spfEvidence = { result: spf, domain: spfDomain, ip: boundaryIp, source: spfSource };
    if (spf === "pass") {
      findings.push(finding("spf_pass", "info", "SPF pass", "The sending server " + spfWhere + "is authorised by the SPF policy of " + spfDomain + " (source: " + spfSource + ").", spfEvidence));
    } else if (spf === "fail") {
      findings.push(
        finding(
          "spf_fail",
          "high",
          "SPF fail",
          "The sending server " + spfWhere + "is not authorised by the SPF policy of " + spfDomain + "; the envelope sender is forged or the message was relayed through unauthorised infrastructure.",
          spfEvidence,
        ),
      );
    } else if (spf === "softfail") {
      findings.push(
        finding(
          "spf_softfail",
          "medium",
          "SPF softfail",
          spfDomain + " marks the sending server " + spfWhere + "as probably not authorised (~all); treat the envelope sender as unproven.",
          spfEvidence,
        ),
      );
    } else if (spf === "none" || spf === "neutral") {
      var spfDetail;
      if (spf === "neutral") {
        spfDetail = "The SPF policy of " + spfDomain + " is neutral for the sending server " + spfWhere + "and provides no assurance.";
      } else if (spfSource === "none" || spfSource === "offline") {
        spfDetail =
          "No SPF verdict is available for " +
          (spfDomain || "the sender domain") +
          ": the message carries no receiver verdict and no live evaluation was performed (source: " +
          spfSource +
          ").";
      } else {
        spfDetail = (spfDomain || "The sender domain") + " publishes no SPF record, so anyone can send on its behalf.";
      }
      findings.push(finding("spf_none", "low", "No usable SPF policy", spfDetail, spfEvidence));
    } else {
      findings.push(
        finding(
          "spf_unverifiable",
          "low",
          "SPF could not be verified",
          "No SPF verdict could be established for " + (spfDomain || "the sender") + " (" + spf + "; source: " + spfSource + ").",
          spfEvidence,
        ),
      );
    }

    var dkimEvidence = { result: dkim, domain: dkimDomain, selector: dkimSelector, source: dkimSource };
    if (dkim === "pass") {
      findings.push(
        finding(
          "dkim_pass",
          "info",
          "DKIM pass",
          "The message carries a valid DKIM signature by " + (dkimDomain || "the signing domain") + " (selector " + (dkimSelector || "?") + "; source: " + dkimSource + ").",
          dkimEvidence,
        ),
      );
    } else if (dkim === "fail") {
      findings.push(
        finding(
          "dkim_fail",
          "high",
          "DKIM signature invalid",
          "The DKIM signature by " + (dkimDomain || "the signing domain") + " does not verify; the message was altered in transit or the signature was fabricated.",
          dkimEvidence,
        ),
      );
    } else if (dkim === "none") {
      findings.push(
        finding(
          "dkim_missing",
          "low",
          "No DKIM signature",
          "The message is not DKIM-signed, so its content and headers are not cryptographically bound to any domain.",
          { result: dkim, source: dkimSource },
        ),
      );
    } else {
      findings.push(
        finding(
          "dkim_unverifiable",
          "low",
          "DKIM could not be verified",
          "A DKIM signature by " + (dkimDomain || "an unknown domain") + " exists but no verdict could be established (" + dkim + "; source: " + dkimSource + ").",
          dkimEvidence,
        ),
      );
    }

    var orgDomains = new Set();
    cfg.org_domains.forEach(function (d) {
      orgDomains.add(py().strip(d.toLowerCase()));
      if (d) orgDomains.add(registrable(d));
    });
    var protectedSender = Boolean(senderRd) && (orgDomains.has(senderRd) || MT.urls.legitDomains().has(senderRd));
    var dmarcEvidence = { result: dmarc, policy: dmarcPolicy, domain: senderRd, source: dmarcSource };
    if (dmarc === "pass") {
      findings.push(
        finding(
          "dmarc_pass",
          "info",
          "DMARC pass",
          "The visible sender domain " + (senderRd || senderDomain) + " is covered by an aligned SPF or DKIM pass (source: " + dmarcSource + ").",
          dmarcEvidence,
        ),
      );
    } else if (dmarc === "fail") {
      dmarcEvidence.protected_domain = protectedSender;
      findings.push(
        finding(
          "dmarc_fail",
          dmarcPolicy === "reject" && protectedSender ? "critical" : "high",
          "DMARC fail",
          "Neither SPF nor DKIM passes in alignment with the visible sender domain " +
            (senderRd || senderDomain) +
            (dmarcPolicy ? ", whose published policy is p=" + dmarcPolicy : "") +
            "; the From address is not authenticated.",
          dmarcEvidence,
        ),
      );
    } else {
      findings.push(
        finding(
          "dmarc_no_record",
          "low",
          "No DMARC verdict",
          "No DMARC policy or verdict is available for " + (senderRd || senderDomain || "the sender domain") + " (source: " + dmarcSource + "); the From address is unprotected against spoofing.",
          dmarcEvidence,
        ),
      );
    }

    if (spf === "pass" && spfAligned === false) {
      findings.push(
        finding(
          "spf_misaligned",
          "medium",
          "SPF passes for a different domain",
          "SPF authorises " + spfDomain + ", not the visible sender domain " + senderRd + "; the sender controls the envelope domain but not necessarily the From identity.",
          { spf_domain: spfDomain, sender_domain: senderRd },
        ),
      );
    }
    if (dkim === "pass" && dkimAligned === false) {
      findings.push(
        finding(
          "dkim_misaligned",
          "medium",
          "DKIM signed by a different domain",
          "The DKIM signature belongs to " + dkimDomain + ", not the visible sender domain " + senderRd + "; a third party vouches for the message, not the claimed sender.",
          { dkim_domain: dkimDomain, sender_domain: senderRd },
        ),
      );
    }
    if (!hasRecorded && !signature && (spfSource === "none" || spfSource === "offline")) {
      findings.push(
        finding(
          "auth_all_missing",
          "medium",
          "No authentication evidence",
          "The message carries no Authentication-Results, Received-SPF or DKIM-Signature headers and no live verdict could be obtained; the sender identity is entirely unverified.",
          { network: false },
        ),
      );
    }
    return { result: result, findings: findings };
  }

  MT.auth = {
    evaluateAuth: evaluateAuth,
    parseAuthenticationResults: parseAuthenticationResults,
    parseDkimSignature: parseDkimSignature,
  };
})(MT);
