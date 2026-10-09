var MT = MT || {};

(function (MT) {
  var MODULE = "headers";

  function py() {
    return MT.py;
  }

  function K() {
    return MT.K("header_analyzer");
  }

  function RX(name) {
    return MT.RX("header_analyzer", name);
  }

  function depthMap(text) {
    var depths = [];
    var depth = 0;
    for (var i = 0; i < text.length; i += 1) {
      depths.push(depth);
      var ch = text[i];
      if (ch === "(") depth += 1;
      else if (ch === ")" && depth > 0) depth -= 1;
    }
    return depths;
  }

  function stripComments(text) {
    var kept = [];
    var depth = 0;
    for (var i = 0; i < text.length; i += 1) {
      var ch = text[i];
      if (ch === "(") {
        depth += 1;
      } else if (ch === ")") {
        if (depth > 0) depth -= 1;
      } else if (depth === 0) {
        kept.push(ch);
      }
    }
    return py().joinWords(kept.join(""));
  }

  function firstToken(text) {
    var parts = py().split(text);
    return parts.length ? parts[0] : "";
  }

  function validIp(value) {
    var address = MT.net.tryAddress(py().strip(value));
    return address === null ? "" : address.toString();
  }

  function wordMatch(phrase, text) {
    return py().re("(?<![a-z0-9])" + py().reEscape(phrase) + "(?![a-z0-9])").test(text);
  }

  function hostMatches(input, domains) {
    var host = py().rstrip((input || "").toLowerCase(), ".");
    if (!host) return false;
    for (var i = 0; i < domains.length; i += 1) {
      var domain = py().rstrip(py().strip((domains[i] || "").toLowerCase()), ".");
      if (domain && (host === domain || host.endsWith("." + domain))) return true;
    }
    return false;
  }

  function isInternalHost(host, cfg) {
    return hostMatches(host, cfg.org_domains) || hostMatches(host, cfg.trusted_relays);
  }

  function isPrivateIp(ip) {
    var address = MT.net.tryAddress(py().strip(ip));
    if (address === null) return false;
    var net = MT.net;
    if (address.version === 6) {
      var mapped = address.ipv4Mapped();
      if (mapped !== null) return isPrivateIp(mapped.toString());
      var embedded = address.sixToFour();
      if (embedded !== null) return isPrivateIp(embedded.toString());
      return (
        net.isPrivate(address) ||
        net.isLoopback(address) ||
        net.isLinkLocal(address) ||
        net.isSiteLocal(address) ||
        net.isMulticast(address) ||
        net.isReserved(address) ||
        net.isUnspecified(address)
      );
    }
    return (
      net.isPrivate(address) ||
      net.isLoopback(address) ||
      net.isLinkLocal(address) ||
      net.isMulticast(address) ||
      net.isReserved(address) ||
      net.isUnspecified(address) ||
      net.isShared(address)
    );
  }

  function isPublicIp(ip) {
    return Boolean(ip) && Boolean(validIp(ip)) && !isPrivateIp(ip);
  }

  function extractIps(input) {
    if (!input) return [];
    var text = RX("_IPV6_PREFIX_RE").sub("", input);
    var found = [];
    var spans = [];
    RX("_IPV6_RE")
      .finditer(text)
      .forEach(function (match) {
        var ip = validIp(match[0]);
        if (ip) {
          found.push([match.start, ip]);
          spans.push([match.start, match.end]);
        }
      });
    RX("_IPV4_RE")
      .finditer(text)
      .forEach(function (match) {
        var inside = spans.some(function (span) {
          return span[0] <= match.start && match.start < span[1];
        });
        if (inside) return;
        var ip = validIp(match[0]);
        if (ip) found.push([match.start, ip]);
      });
    found = py().sorted(found, function (item) {
      return item[0];
    });
    var result = [];
    found.forEach(function (item) {
      if (result.indexOf(item[1]) < 0) result.push(item[1]);
    });
    return result;
  }

  function splitClauses(body) {
    var depths = depthMap(body);
    var matches = RX("_CLAUSE_RE")
      .finditer(body)
      .filter(function (m) {
        return depths[m.start] === 0;
      });
    var clauses = new Map();
    matches.forEach(function (match, position) {
      var end = position + 1 < matches.length ? matches[position + 1].start : body.length;
      var key = match[1].toLowerCase();
      if (!clauses.has(key)) clauses.set(key, py().strip(body.slice(match.end, end)));
    });
    return clauses;
  }

  function parseFromClause(input) {
    var clause = py().strip(input);
    if (!clause) return ["", "", ""];
    var head = py().re("[\\s(]").split(clause, 1)[0];
    var token = py().rstrip(RX("_IPV6_PREFIX_RE").sub("", py().strip(head, "[]")), ".").toLowerCase();
    var fromHost;
    if (!token || token === "unknown" || validIp(token)) {
      var helo = RX("_HELO_RE").search(clause);
      fromHost = helo ? py().rstrip(helo[1], ".").toLowerCase() : "";
      if (validIp(fromHost)) fromHost = "";
    } else {
      fromHost = token;
    }
    var depths = depthMap(clause);
    var commentLiteral = "";
    var bareLiteral = "";
    RX("_BRACKET_IP_RE")
      .finditer(clause)
      .forEach(function (match) {
        var ip = validIp(match[1]);
        if (!ip) return;
        if (depths[match.start] > 0) commentLiteral = commentLiteral || ip;
        else bareLiteral = bareLiteral || ip;
      });
    var fromIp = commentLiteral || bareLiteral;
    if (!fromIp) {
      var candidates = extractIps(clause);
      fromIp = candidates.length ? candidates[0] : "";
    }
    var rdns = "";
    var rdnsMatch = RX("_RDNS_RE").search(clause);
    if (rdnsMatch) {
      var name = rdnsMatch[1].toLowerCase();
      if (name !== "unknown" && !validIp(name)) rdns = name;
    }
    return [fromHost, fromIp, rdns];
  }

  function protocolFrom(withText) {
    if (!withText) return "";
    if (withText.toLowerCase().slice(0, 21) === "microsoft smtp server") return "Microsoft SMTP Server";
    var token = py().strip(firstToken(withText), ";,");
    return RX("_SMTP_PROTOCOL_RE").match(token) ? token.toUpperCase() : token;
  }

  function parseTimestamp(value) {
    var text = stripComments(value);
    if (!text) return null;
    return MT.address.parseDate(text);
  }

  function parseReceivedFull(value) {
    var text = py().joinWords(value || "");
    var depths = depthMap(text);
    var splitAt = -1;
    for (var i = 0; i < text.length; i += 1) {
      if (text[i] === ";" && depths[i] === 0) splitAt = i;
    }
    var body = text;
    var dateText = "";
    if (splitAt >= 0) {
      body = text.slice(0, splitAt);
      dateText = text.slice(splitAt + 1);
    }
    var clauses = splitClauses(body);
    var get = function (key) {
      return clauses.has(key) ? clauses.get(key) : "";
    };
    var from = parseFromClause(get("from"));
    var withText = stripComments(get("with"));
    var protocol = protocolFrom(withText);
    var upper = protocol.toUpperCase();
    return {
      raw: text,
      from_host: from[0],
      from_ip: from[1],
      by_host: py().rstrip(py().strip(firstToken(stripComments(get("by"))), "[];,"), ".").toLowerCase(),
      protocol: protocol,
      hop_id: py().strip(firstToken(stripComments(get("id"))), ";,"),
      timestamp: parseTimestamp(dateText),
      for_addr: py().strip(firstToken(stripComments(get("for"))), "<>;,").toLowerCase(),
      rdns: from[2],
      tls: Boolean(RX("_TLS_RE").search(text)) || upper.endsWith("SMTPS") || upper.endsWith("SMTPSA"),
      authenticated: Boolean(RX("_AUTH_RE").search(text)),
      parsed: clauses.size > 0,
    };
  }

  function buildHops(infos, cfg) {
    var hops = [];
    var previous = null;
    infos.forEach(function (info, index) {
      var fromIp = info.from_ip;
      var fromHost = info.from_host;
      var timestamp = info.timestamp;
      var isPrivate = Boolean(fromIp) && isPrivateIp(fromIp);
      var anomalies = [];
      if (!info.parsed && timestamp === null) anomalies.push("unparseable");
      else if (timestamp === null) anomalies.push("missing_timestamp");
      if (isPrivate) anomalies.push("private_ip");
      var delay = null;
      if (timestamp !== null && previous !== null) {
        delay = timestamp - previous;
        if (delay < -60) anomalies.push("negative_delay");
        else if (delay > 6 * 3600) anomalies.push("large_delay");
      }
      if (timestamp !== null) previous = timestamp;
      var rdns = info.rdns;
      if (
        fromHost &&
        rdns &&
        fromHost.indexOf(".") >= 0 &&
        rdns.indexOf(".") >= 0 &&
        MT.urls.registrableDomain(fromHost) !== MT.urls.registrableDomain(rdns)
      ) {
        anomalies.push("helo_mismatch");
      }
      if (fromIp && !isPrivate && info.protocol && RX("_PLAINTEXT_PROTOCOL_RE").match(info.protocol) && !info.tls) {
        anomalies.push("no_tls");
      }
      hops.push({
        index: index,
        raw: info.raw,
        from_host: fromHost,
        from_ip: fromIp,
        by_host: info.by_host,
        protocol: info.protocol,
        hop_id: info.hop_id,
        timestamp: MT.time.iso(timestamp),
        delay_seconds: delay,
        is_private_ip: isPrivate,
        is_internal: isInternalHost(info.by_host, cfg) || isInternalHost(fromHost, cfg),
        anomalies: anomalies,
        geo: null,
      });
    });
    return hops;
  }

  function flagForgedOrder(hops, cfg) {
    hops.forEach(function (hop, position) {
      if (!isInternalHost(hop.by_host, cfg)) return;
      for (var k = position + 1; k < hops.length; k += 1) {
        var later = hops[k];
        if (later.from_host && isInternalHost(later.from_host, cfg)) break;
        if (later.from_ip && !later.is_private_ip && !isInternalHost(later.from_host, cfg)) {
          hop.anomalies.push("forged_received_order");
          break;
        }
      }
    });
  }

  function xOriginatingIp(parsed) {
    var names = K()._CLIENT_IP_HEADERS;
    for (var i = 0; i < parsed.headers.length; i += 1) {
      var header = parsed.headers[i];
      if (!names.has(header.name.toLowerCase())) continue;
      var ips = extractIps(header.value);
      for (var k = 0; k < ips.length; k += 1) if (!isPrivateIp(ips[k])) return ips[k];
    }
    return "";
  }

  function selectOrigin(hops, infos, xOrigin, cfg) {
    if (!hops.length) {
      if (xOrigin) {
        return [xOrigin, null, 0.6, "No Received headers are present; using the client address recorded in an X-Originating-IP style header.", ""];
      }
      return ["", null, 0.0, "No Received headers are present, so the routing path cannot be reconstructed.", ""];
    }
    var doubtNames = K()._CHAIN_DOUBT;
    for (var i = 0; i < hops.length; i += 1) {
      var hop = hops[i];
      if (!hop.from_ip || hop.is_private_ip || isInternalHost(hop.from_host, cfg)) continue;
      var doubtSet = new Set();
      hops.slice(0, hop.index + 1).forEach(function (h) {
        h.anomalies.forEach(function (a) {
          if (doubtNames.has(a)) doubtSet.add(a);
        });
      });
      var doubts = py().sorted(Array.from(doubtSet));
      var confidence = doubts.length ? 0.7 : 0.9;
      var submission = Boolean(infos[hop.index].authenticated);
      var provider = submission ? "" : MT.knowledge.sharedProvider(hop.from_host);
      var reason;
      if (hop.index === 1 && hops[0].is_private_ip && submission) {
        reason =
          "Authenticated submission from a client behind NAT: hop 0 shows the private address " +
          hops[0].from_ip +
          " and hop 1 is an authenticated submission from " +
          hop.from_ip +
          " to " +
          (hop.by_host || "the submission server") +
          ".";
      } else if (submission) {
        reason =
          "Earliest public hop is an authenticated submission (" +
          (hop.protocol || "SMTP AUTH") +
          ") from " +
          hop.from_ip +
          " to " +
          (hop.by_host || "the submission server") +
          ".";
      } else if (provider) {
        confidence = Math.min(confidence, 0.5);
        reason =
          "Earliest public hop is " +
          hop.from_ip +
          " (" +
          hop.from_host +
          "), an outbound relay that " +
          provider +
          " shares between all of its users. " +
          provider +
          " does not expose the sender's own address, so this IP locates the provider's mail servers, not the sender.";
      } else {
        reason =
          "Earliest public, non-trusted hop: " +
          hop.from_ip +
          " handed the message to " +
          (hop.by_host || "an unnamed relay") +
          " via " +
          (hop.protocol || "an unknown protocol") +
          ".";
      }
      if (doubts.length) reason += " Confidence reduced because the chain below this hop shows: " + doubts.join(", ") + ".";
      return [hop.from_ip, hop.index, confidence, reason, provider];
    }
    if (xOrigin) {
      return [
        xOrigin,
        null,
        0.6,
        "The Received chain exposes no public external address; using the client address recorded by the submission server in an X-Originating-IP style header.",
        "",
      ];
    }
    for (var k = 0; k < hops.length; k += 1) {
      var candidate = hops[k];
      if (candidate.from_ip && !candidate.is_private_ip) {
        return [
          candidate.from_ip,
          candidate.index,
          0.4,
          "Only trusted or organisation relays expose public addresses; falling back to the earliest of them (" +
            candidate.from_ip +
            " at hop " +
            candidate.index +
            ").",
          "",
        ];
      }
    }
    return ["", null, 0.0, "Every hop shows a private or missing address; the true origin is hidden behind internal infrastructure.", ""];
  }

  function messageIdDomain(messageId) {
    var value = py().strip(py().strip(py().strip(messageId || ""), "<>"));
    if (value.indexOf("@") < 0) return "";
    return py().rstrip(py().strip(py().strip(py().rsplit(value, "@", 1)[1]), ">"), ".").toLowerCase();
  }

  function brandInDisplayName(name, cfg) {
    var aliases = K()._BRAND_ALIASES;
    var phrases = K()._ALIAS_PHRASES;
    var brandsTable = MT.K("knowledge").BRANDS;
    var i;
    for (i = 0; i < phrases.length; i += 1) {
      if (wordMatch(phrases[i], name)) {
        var key = aliases.get(phrases[i]);
        return [key, brandsTable.has(key) ? brandsTable.get(key).slice() : []];
      }
    }
    var keys = K()._BRAND_KEYS;
    for (i = 0; i < keys.length; i += 1) {
      if (wordMatch(keys[i], name)) return [keys[i], brandsTable.get(keys[i]).slice()];
    }
    for (i = 0; i < cfg.protected_brands.length; i += 1) {
      var brand = py().strip(cfg.protected_brands[i]).toLowerCase();
      if (brand && wordMatch(brand, name)) return [brand, cfg.org_domains.slice()];
    }
    return ["", []];
  }

  function executiveInDisplayName(name, cfg) {
    var tokens = new Set();
    cfg.executives.concat(MT.K("knowledge").EXEC_TITLES).forEach(function (t) {
      if (py().strip(t)) tokens.add(py().strip(t).toLowerCase());
    });
    var ordered = py().sorted(Array.from(tokens), function (item) {
      return [-py().length(item), item];
    });
    for (var i = 0; i < ordered.length; i += 1) if (wordMatch(ordered[i], name)) return ordered[i];
    return "";
  }

  function finding(id, severity, title, detail, evidence) {
    return { id: id, module: MODULE, severity: severity, title: title, detail: detail, evidence: evidence };
  }

  function hopLabel(hop) {
    return "hop " + hop.index + " (" + (hop.from_ip || hop.from_host || "unnamed") + " -> " + (hop.by_host || "unnamed") + ")";
  }

  function sentence(text) {
    return text.slice(0, 1).toUpperCase() + text.slice(1);
  }

  function timingSentence(hop) {
    var delay = hop.delay_seconds || 0.0;
    if (delay < 0) return hopLabel(hop) + " is stamped " + py().fixed(Math.abs(delay), 0) + " s earlier than the previous hop";
    return hopLabel(hop) + " waited " + py().fixed(delay / 3600, 1) + " h after the previous hop";
  }

  function emptyAuth() {
    return {
      spf: "none",
      spf_domain: "",
      spf_source: "none",
      dkim: "none",
      dkim_domain: "",
      dkim_selector: "",
      dkim_source: "none",
      dmarc: "none",
      dmarc_policy: "",
      dmarc_source: "none",
      spf_aligned: null,
      dkim_aligned: null,
      notes: [],
    };
  }

  function analyzeHeaders(parsed, cfg) {
    var received = parsed.headers
      .filter(function (h) {
        return h.name.toLowerCase() === "received";
      })
      .map(function (h) {
        return h.value;
      });
    var infos = received.slice().reverse().map(parseReceivedFull);
    var hops = buildHops(infos, cfg);
    flagForgedOrder(hops, cfg);
    var xOrigin = xOriginatingIp(parsed);
    var origin = selectOrigin(hops, infos, xOrigin, cfg);
    var originIp = origin[0];
    var originIndex = origin[1];
    var originConfidence = origin[2];
    var originReasoning = origin[3];
    var originProvider = origin[4];
    var registrable = MT.urls.registrableDomain;
    var freemail = MT.K("knowledge").FREEMAIL_DOMAINS;
    var relayProviders = K()._RELAY_PROVIDER_DOMAINS;

    var senderAddress = parsed.sender.address.toLowerCase();
    var senderDomain = (parsed.sender.domain || "").toLowerCase();
    var senderRd = senderDomain ? registrable(senderDomain) : "";
    var senderFreemail = freemail.has(senderRd);
    var returnPathDomain = (parsed.return_path.domain || "").toLowerCase();
    var returnPathRd = returnPathDomain ? registrable(returnPathDomain) : "";
    var returnPathMismatch = Boolean(senderRd && returnPathRd && senderRd !== returnPathRd);

    var mismatchedReply = [];
    var mismatchedReplyDomains = [];
    parsed.reply_to.forEach(function (reply) {
      if (reply.domain && senderRd) {
        var replyRd = registrable(reply.domain.toLowerCase());
        var label = (reply.address || reply.domain).toLowerCase();
        if (replyRd !== senderRd && mismatchedReply.indexOf(label) < 0) {
          mismatchedReply.push(label);
          mismatchedReplyDomains.push(replyRd);
        }
      }
    });
    var replyToMismatch = mismatchedReply.length > 0;

    var midDomain = messageIdDomain(parsed.message_id);
    var midRd = midDomain ? registrable(midDomain) : "";
    var relayDomains = new Set();
    hops.forEach(function (h) {
      if (h.by_host) relayDomains.add(registrable(h.by_host));
    });
    var messageIdMismatch = Boolean(midRd && senderRd && midRd !== senderRd && !relayDomains.has(midRd) && !relayProviders.has(midRd));

    var displayName = py().joinWords(parsed.sender.display_name || "");
    var displayLower = displayName.toLowerCase();
    var displayNameSpoof = false;
    var displayNameBrand = "";
    var brand = displayLower ? brandInDisplayName(displayLower, cfg) : ["", []];
    var brandKey = brand[0];
    var brandDomains = brand[1];
    var lowerBrandDomains = new Set(
      brandDomains.map(function (d) {
        return d.toLowerCase();
      }),
    );
    var brandSpoof = Boolean(brandKey && senderRd && !lowerBrandDomains.has(senderRd));
    if (brandSpoof) {
      displayNameSpoof = true;
      displayNameBrand = brandKey;
    }
    var embedded = RX("_EMAIL_RE").search(displayName);
    var embeddedDomain = embedded ? embedded[1].toLowerCase() : "";
    var embeddedSpoof = Boolean(embeddedDomain && senderRd && registrable(embeddedDomain) !== senderRd);
    if (embeddedSpoof) {
      displayNameSpoof = true;
      displayNameBrand = displayNameBrand || embeddedDomain;
    }
    var execToken = "";
    if (displayLower && senderRd && !hostMatches(senderDomain, cfg.org_domains)) execToken = executiveInDisplayName(displayLower, cfg);
    if (execToken) {
      displayNameSpoof = true;
      displayNameBrand = displayNameBrand || execToken;
    }

    var mailer = py().joinWords(parsed.mailer || "");
    var bulkMailer = Boolean(mailer && RX("_BULK_MAILER_RE").search(mailer));

    var publicHops = hops.filter(function (h) {
      return h.from_ip && !h.is_private_ip;
    });
    var privateOnly = hops.length > 0 && !publicHops.length;
    var has = function (name) {
      return function (h) {
        return h.anomalies.indexOf(name) >= 0;
      };
    };
    var negativeHops = hops.filter(has("negative_delay"));
    var timingHops = hops.filter(function (h) {
      return h.anomalies.indexOf("negative_delay") >= 0 || h.anomalies.indexOf("large_delay") >= 0;
    });
    var forgedHops = hops.filter(has("forged_received_order"));
    var noTlsHops = hops.filter(has("no_tls"));
    var heloHops = hops.filter(has("helo_mismatch"));

    var score = 0.0;
    if (replyToMismatch) score += 0.35;
    if (returnPathMismatch) score += 0.25;
    if (displayNameSpoof) score += 0.45;
    if (messageIdMismatch) score += 0.15;
    if (forgedHops.length) score += 0.4;
    if (negativeHops.length) score += 0.2;
    if (privateOnly) score += 0.2;
    if (bulkMailer) score += 0.1;
    score = Math.min(1.0, Math.max(0.0, score));

    var findings = [];
    if (!hops.length) {
      findings.push(
        finding(
          "empty_received_chain",
          "medium",
          "No Received headers",
          "The message carries no Received headers, so its delivery path cannot be reconstructed; mail that was genuinely delivered over SMTP always has at least one.",
          { received_count: 0 },
        ),
      );
    }
    if (originIp) {
      var originHop = originIndex !== null ? hops[originIndex] : null;
      findings.push(
        finding(
          "origin_identified",
          "info",
          "Origin IP " + originIp,
          originIp + " is the most likely origin of the message (confidence " + py().fixed(originConfidence, 2) + "). " + originReasoning,
          {
            ip: originIp,
            hop_index: originIndex,
            confidence: originConfidence,
            from_host: originHop ? originHop.from_host : "",
            by_host: originHop ? originHop.by_host : "",
            protocol: originHop ? originHop.protocol : "",
            hop_count: hops.length,
            mailer: mailer,
          },
        ),
      );
    }
    if (xOrigin) {
      findings.push(
        finding(
          "x_originating_ip",
          "info",
          "Submitting client IP recorded by the mail service",
          "An X-Originating-IP style header records " +
            xOrigin +
            " as the client that submitted the message; such headers are written by the submission server, not by the sender.",
          { ip: xOrigin, used_as_origin: xOrigin === originIp },
        ),
      );
    }
    if (privateOnly) {
      findings.push(
        finding(
          "private_ip_origin",
          "low",
          "Only private addresses in the routing chain",
          "Every Received hop shows a private, loopback or missing address, so the message was generated inside internal infrastructure or the external hops were stripped.",
          {
            hops: hops.map(function (h) {
              return { index: h.index, from_ip: h.from_ip, by_host: h.by_host };
            }),
          },
        ),
      );
    }
    if (forgedHops.length) {
      findings.push(
        finding(
          "forged_received_order",
          "high",
          "Received chain order is inconsistent",
          "Hop(s) " +
            forgedHops
              .map(function (h) {
                return String(h.index);
              })
              .join(", ") +
            " claim delivery by an organisation server before the message was received from an external relay; such lines are typically injected by the sender to make the message look internal.",
          {
            hops: forgedHops.map(function (h) {
              return { index: h.index, by_host: h.by_host, raw: h.raw };
            }),
          },
        ),
      );
    }
    if (timingHops.length) {
      findings.push(
        finding(
          "timestamp_anomaly",
          negativeHops.length ? "medium" : "low",
          "Hop timestamps are inconsistent",
          sentence(timingHops.map(timingSentence).join("; ")) +
            ". Backwards clocks suggest forged or manipulated Received headers; very long gaps suggest queued or replayed mail.",
          {
            hops: timingHops.map(function (h) {
              return { index: h.index, delay_seconds: h.delay_seconds, from_ip: h.from_ip, by_host: h.by_host, timestamp: h.timestamp ? MT.time.isoOffset(h.timestamp) : null };
            }),
          },
        ),
      );
    }
    if (noTlsHops.length) {
      var protocols = new Set();
      noTlsHops.forEach(function (h) {
        protocols.add(h.protocol);
      });
      findings.push(
        finding(
          "no_tls_hop",
          "low",
          "Plaintext SMTP hop from a public address",
          noTlsHops.length +
            " public hop(s) delivered the message with plain " +
            py().sorted(Array.from(protocols)).join(", ") +
            " and no TLS: " +
            noTlsHops.map(hopLabel).join("; ") +
            ". Modern mail services negotiate TLS; scripted senders and open relays often do not.",
          {
            hops: noTlsHops.map(function (h) {
              return { index: h.index, from_ip: h.from_ip, by_host: h.by_host, protocol: h.protocol };
            }),
          },
        ),
      );
    }
    if (heloHops.length) {
      findings.push(
        finding(
          "helo_mismatch",
          "low",
          "HELO name does not match reverse DNS",
          sentence(
            heloHops
              .map(function (h) {
                return "hop " + h.index + " announced itself as " + h.from_host + " but the connecting address " + h.from_ip + " resolves to " + infos[h.index].rdns;
              })
              .join("; "),
          ) + ". Legitimate mail servers normally identify themselves consistently.",
          {
            hops: heloHops.map(function (h) {
              return { index: h.index, from_host: h.from_host, reverse_dns: infos[h.index].rdns, from_ip: h.from_ip };
            }),
          },
        ),
      );
    }
    if (replyToMismatch) {
      var replyFreemail = mismatchedReplyDomains.some(function (d) {
        return freemail.has(d);
      });
      findings.push(
        finding(
          "reply_to_mismatch",
          replyFreemail && !senderFreemail ? "high" : "medium",
          "Reply-To points to a different domain",
          "Replies would go to " +
            mismatchedReply.join(", ") +
            " instead of the sender's domain " +
            senderRd +
            "; redirecting the conversation to an attacker-controlled mailbox is a classic BEC and phishing technique.",
          { reply_to: mismatchedReply, sender: senderAddress, sender_domain: senderRd },
        ),
      );
    }
    if (returnPathMismatch) {
      findings.push(
        finding(
          "return_path_mismatch",
          relayProviders.has(returnPathRd) ? "low" : "medium",
          "Return-Path domain differs from the From domain",
          "The envelope sender " +
            parsed.return_path.address.toLowerCase() +
            " belongs to " +
            returnPathRd +
            " while the visible From address belongs to " +
            senderRd +
            "; the message was sent on behalf of the From identity by a different party.",
          {
            return_path: parsed.return_path.address.toLowerCase(),
            sender: senderAddress,
            return_path_domain: returnPathRd,
            sender_domain: senderRd,
          },
        ),
      );
    }
    if (messageIdMismatch) {
      findings.push(
        finding(
          "message_id_mismatch",
          "low",
          "Message-ID generated by an unrelated host",
          "The Message-ID was generated at " +
            midDomain +
            ", which matches neither the sender domain " +
            senderRd +
            " nor any relay in the Received chain; mail composed by scripts or on rogue hosts often shows this.",
          {
            message_id: parsed.message_id,
            message_id_domain: midDomain,
            sender_domain: senderRd,
            relay_domains: py().sorted(Array.from(relayDomains).filter(Boolean)),
          },
        ),
      );
    }
    if (brandSpoof || embeddedSpoof) {
      var detail;
      if (brandSpoof) {
        detail =
          'The display name "' +
          displayName +
          '" references ' +
          brandKey +
          " but the message comes from " +
          senderDomain +
          ", which is not a " +
          brandKey +
          " domain" +
          (brandDomains.length ? " (legitimate: " + brandDomains.join(", ") + ")" : "") +
          ".";
      } else {
        detail =
          'The display name "' +
          displayName +
          '" embeds the address ' +
          (embedded ? embedded[0] : "") +
          " whose domain differs from the real sender " +
          senderDomain +
          "; recipients see the fake address instead of the true one.";
      }
      findings.push(
        finding("display_name_spoof", "high", "Display name imitates " + displayNameBrand, detail, {
          display_name: displayName,
          brand: displayNameBrand,
          sender: senderAddress,
          sender_domain: senderDomain,
          legitimate_domains: brandDomains,
        }),
      );
    }
    if (execToken) {
      findings.push(
        finding(
          "executive_impersonation_display",
          senderFreemail ? "high" : "medium",
          "Display name claims an executive identity",
          'The display name "' +
            displayName +
            '" carries the executive marker "' +
            execToken +
            '" while the message originates outside the organisation\'s domains (' +
            senderDomain +
            "); this is the hallmark of CEO-fraud first-touch emails.",
          {
            display_name: displayName,
            marker: execToken,
            sender: senderAddress,
            sender_domain: senderDomain,
            free_mail_sender: senderFreemail,
          },
        ),
      );
    }
    if (bulkMailer) {
      findings.push(
        finding(
          "bulk_mailer",
          "low",
          "Scripted or bulk mailing software",
          "The message was generated by " + mailer + ", a scripting or bulk-mailing library that is rarely used for personal or transactional correspondence.",
          { mailer: mailer },
        ),
      );
    }

    var anomalies = [];
    hops.forEach(function (hop) {
      hop.anomalies.forEach(function (a) {
        if (anomalies.indexOf(a) < 0) anomalies.push(a);
      });
    });
    [
      [privateOnly, "private_only_chain"],
      [!hops.length, "empty_received_chain"],
      [replyToMismatch, "reply_to_mismatch"],
      [returnPathMismatch, "return_path_mismatch"],
      [messageIdMismatch, "message_id_mismatch"],
      [brandSpoof || embeddedSpoof, "display_name_spoof"],
      [Boolean(execToken), "executive_impersonation"],
      [bulkMailer, "bulk_mailer"],
    ].forEach(function (pair) {
      if (pair[0] && anomalies.indexOf(pair[1]) < 0) anomalies.push(pair[1]);
    });

    return {
      hops: hops,
      originating_ip: originIp,
      originating_hop_index: originIndex,
      origin_confidence: originConfidence,
      origin_reasoning: originReasoning,
      origin_shared_provider: originProvider,
      x_originating_ip: xOrigin,
      message_id_domain: midDomain,
      message_id_mismatch: messageIdMismatch,
      return_path_mismatch: returnPathMismatch,
      reply_to_mismatch: replyToMismatch,
      display_name_spoof: displayNameSpoof,
      display_name_brand: displayNameBrand,
      auth: emptyAuth(),
      anomalies: anomalies,
      score: score,
      findings: findings,
      infos: infos,
    };
  }

  MT.headers = {
    analyzeHeaders: analyzeHeaders,
    parseReceivedFull: parseReceivedFull,
    extractIps: extractIps,
    isPrivateIp: isPrivateIp,
    isPublicIp: isPublicIp,
    stripComments: stripComments,
    hostMatches: hostMatches,
    isInternalHost: isInternalHost,
    validIp: validIp,
    emptyAuth: emptyAuth,
  };
})(MT);
