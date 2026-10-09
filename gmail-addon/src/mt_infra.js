var MT = MT || {};

(function (MT) {
  var MODULE = "geoip";
  var RESOLVED_SOURCES = ["ip-api", "maxmind", "cache"];
  var ARROW = " " + String.fromCharCode(0x2192) + " ";

  function py() {
    return MT.py;
  }

  function K() {
    return MT.K("geoip_mapper");
  }

  function RX(name) {
    return MT.RX("geoip_mapper", name);
  }

  function parseIp(value) {
    var text = py().strip(py().strip(value || ""), "[]");
    if (text.toLowerCase().slice(0, 5) === "ipv6:") text = text.slice(5);
    var address = MT.net.tryAddress(text);
    if (address === null) return null;
    if (address.version === 6) {
      var mapped = address.ipv4Mapped();
      if (mapped !== null) return mapped;
    }
    return address;
  }

  function normalizeIp(value) {
    var address = parseIp(value);
    return address === null ? "" : address.toString();
  }

  function isPublicIp(ip) {
    var address = parseIp(ip);
    if (address === null || MT.net.isShared(address)) return false;
    var net = MT.net;
    return !(
      net.isPrivate(address) ||
      net.isLoopback(address) ||
      net.isLinkLocal(address) ||
      net.isMulticast(address) ||
      net.isReserved(address) ||
      net.isUnspecified(address)
    );
  }

  function geoInfo(ip, overrides) {
    var geo = {
      ip: ip,
      country: "",
      country_code: "",
      region: "",
      city: "",
      lat: null,
      lon: null,
      isp: "",
      org: "",
      asn: "",
      reverse_dns: "",
      is_private: false,
      is_proxy: false,
      is_hosting: false,
      is_mobile: false,
      is_tor_exit: false,
      blacklists: [],
      abuse_confidence: null,
      source: "",
    };
    if (overrides) {
      Object.keys(overrides).forEach(function (key) {
        geo[key] = overrides[key];
      });
    }
    return geo;
  }

  function privateGeo(ip) {
    return geoInfo(ip, { is_private: true, source: "private" });
  }

  function cloneGeo(geo) {
    return JSON.parse(JSON.stringify(geo));
  }

  function registrable(host) {
    var text = py().rstrip(py().strip(py().strip(host), "[]"), ".").toLowerCase();
    if (!text || text === "unknown" || parseIp(text) !== null) return "";
    return MT.urls.registrableDomain(text);
  }

  function enrichOffline(ip, full) {
    var geo = geoInfo(ip, { source: "offline" });
    if (geo.is_private || !isPublicIp(geo.ip)) return geo;
    geo.is_tor_exit = Boolean(RX("_TOR_RDNS_RE").search(geo.reverse_dns));
    if (full) {
      geo.blacklists = [];
      geo.abuse_confidence = null;
    }
    return geo;
  }

  function publicIpsInOrder(headerAnalysis, origin) {
    var candidates = [origin];
    headerAnalysis.hops.forEach(function (hop) {
      candidates.push(hop.from_ip);
    });
    candidates.push(headerAnalysis.x_originating_ip);
    var ordered = [];
    candidates.forEach(function (candidate) {
      var ip = normalizeIp(candidate);
      if (ip && isPublicIp(ip) && ordered.indexOf(ip) < 0) ordered.push(ip);
    });
    return ordered;
  }

  function enrichMany(targets, origin, enrichment) {
    var results = new Map();
    targets.forEach(function (ip) {
      var provided = enrichment && enrichment.ips && enrichment.ips.has(ip) ? cloneGeo(enrichment.ips.get(ip)) : null;
      results.set(ip, provided || enrichOffline(ip, ip === origin));
    });
    return results;
  }

  function providerText(geo) {
    return geo.isp + " " + geo.org + " " + geo.reverse_dns;
  }

  function isMailServiceEgress(geo) {
    var owner = (geo.isp + " " + geo.org).toLowerCase();
    var rdns = geo.reverse_dns.toLowerCase();
    var table = K()._MAIL_SERVICE_EGRESS;
    for (var i = 0; i < table.length; i += 1) {
      var keyword = table[i][0];
      var suffixes = table[i][1];
      if (
        owner.indexOf(keyword) >= 0 &&
        suffixes.some(function (suffix) {
          return rdns === suffix || rdns.endsWith("." + suffix);
        })
      ) {
        return true;
      }
    }
    return false;
  }

  function plainSmtpHop(hop) {
    if (hop.anomalies.indexOf("no_tls") >= 0) return true;
    var tokens = py().split(hop.protocol.toUpperCase());
    var protocol = tokens.length ? tokens[0] : "";
    return (protocol === "SMTP" || protocol === "ESMTP") && !RX("_TLS_HINT_RE").search(hop.raw) && !RX("_AUTH_HINT_RE").search(hop.raw);
  }

  function genericRdns(rdns, ip) {
    var name = rdns.toLowerCase();
    var octets = ip.split(".");
    if (octets.length === 4) {
      var reversed = octets.slice().reverse();
      var forms = [octets.join("-"), octets.join("."), reversed.join("-"), reversed.join(".")];
      if (
        forms.some(function (form) {
          return name.indexOf(form) >= 0;
        })
      ) {
        return true;
      }
    }
    return Boolean(RX("_RESIDENTIAL_RDNS_RE").search(name) || RX("_GENERIC_RDNS_RE").search(name));
  }

  function anonymousHost(geo) {
    if (geo.reverse_dns) return genericRdns(geo.reverse_dns, geo.ip);
    return RESOLVED_SOURCES.indexOf(geo.source) >= 0;
  }

  function openRelayHops(hops) {
    var suspects = [];
    hops.forEach(function (hop) {
      var geo = hop.geo;
      if (geo === null || geo.is_private || hop.is_internal || !plainSmtpHop(hop)) return;
      var byDomain = registrable(hop.by_host);
      if (!byDomain || registrable(hop.from_host) === byDomain) return;
      if (geo.blacklists.length || anonymousHost(geo)) suspects.push(hop);
    });
    return suspects;
  }

  function residentialOrigin(geo) {
    if (geo.is_hosting) return false;
    return Boolean(geo.is_mobile || RX("_RESIDENTIAL_ISP_RE").search(geo.isp + " " + geo.org) || RX("_RESIDENTIAL_RDNS_RE").search(geo.reverse_dns));
  }

  function deliveredDirectToMx(hops, originIndex) {
    if (originIndex === null || originIndex === undefined || !(originIndex >= 0 && originIndex < hops.length)) return false;
    var originHop = hops[originIndex];
    if (RX("_AUTH_HINT_RE").search(originHop.raw) || RX("_AUTH_HINT_RE").search(originHop.protocol)) return false;
    var finalDomain = registrable(hops[hops.length - 1].by_host);
    for (var i = originIndex; i < hops.length; i += 1) {
      var byDomain = registrable(hops[i].by_host);
      if (!(hops[i].is_internal || (byDomain && byDomain === finalDomain))) return false;
    }
    return true;
  }

  function botnetIndicators(headerAnalysis, originGeo) {
    if (originGeo === null || originGeo.is_private) return [];
    var hops = headerAnalysis.hops;
    var index = headerAnalysis.originating_hop_index;
    var originHop = index !== null && index !== undefined && index >= 0 && index < hops.length ? hops[index] : null;
    var rdns = originGeo.reverse_dns;
    var dynamic = Boolean(rdns && RX("_RESIDENTIAL_RDNS_RE").search(rdns));
    var indicators = [];
    if (dynamic && originGeo.blacklists.length) {
      indicators.push("Origin reverse DNS '" + rdns + "' looks like a dynamic/residential address and the IP is listed on " + originGeo.blacklists.join(", ") + ".");
    }
    if (dynamic && originHop !== null && plainSmtpHop(originHop)) {
      indicators.push("Origin reverse DNS '" + rdns + "' looks like a dynamic/residential address and the message was handed over without TLS or authentication.");
    }
    if (residentialOrigin(originGeo) && deliveredDirectToMx(hops, index)) {
      var provider = originGeo.isp || originGeo.org || "a consumer ISP";
      indicators.push(
        "Origin " + originGeo.ip + " sits on a residential/mobile network (" + provider + ") and delivered the message straight to the recipient's mail server, bypassing any mail provider.",
      );
    }
    return indicators;
  }

  function finding(id, severity, title, detail, evidence) {
    return { id: id, module: MODULE, severity: severity, title: title, detail: detail, evidence: evidence };
  }

  function geoEvidence(geo) {
    return {
      ip: geo.ip,
      city: geo.city,
      region: geo.region,
      country: geo.country,
      country_code: geo.country_code,
      isp: geo.isp,
      org: geo.org,
      asn: geo.asn,
      reverse_dns: geo.reverse_dns,
      lat: geo.lat,
      lon: geo.lon,
      source: geo.source,
    };
  }

  function originFinding(geo, sharedProvider) {
    var place = [geo.city, geo.region, geo.country].filter(Boolean).join(", ") || "an unknown location";
    var provider = geo.isp || geo.org || "an unknown network";
    var asn = geo.asn ? " (" + geo.asn + ")" : "";
    var detail = "The originating IP " + geo.ip + " is located in " + place + " and announced by " + provider + asn + ".";
    if (geo.reverse_dns) detail += " Reverse DNS: " + geo.reverse_dns + ".";
    if (sharedProvider) {
      detail += " This address is one of " + sharedProvider + "'s shared outbound mail servers, so the location is the provider's data centre, not where the sender was.";
    }
    var evidence = geoEvidence(geo);
    evidence.shared_provider = sharedProvider;
    return finding("origin_geolocated", "info", "Origin IP geolocated", detail, evidence);
  }

  function geoUnavailableFinding(origin, originGeo, hops) {
    var detail;
    if (!origin) {
      detail = hops.length
        ? "No public originating IP could be identified from the Received chain, so the sender could not be geolocated."
        : "The message carries no Received headers, so there is no routing information to geolocate.";
    } else if (originGeo === null) {
      detail = "The originating IP " + origin + " was not geolocated because geolocation lookups are disabled (max_geo_lookups).";
    } else if (originGeo.is_private) {
      detail = "The originating IP " + origin + " is a private/internal address and has no public geolocation.";
    } else if (originGeo.source === "offline") {
      detail = "Network enrichment is disabled, so the originating IP " + origin + " was not geolocated.";
    } else {
      detail = "The geolocation service could not resolve " + origin + " (timeout, rate limit or lookup failure).";
    }
    return finding("geo_unavailable", "info", "Origin geolocation unavailable", detail, {
      originating_ip: origin,
      source: originGeo !== null ? originGeo.source : "",
      hops: hops.length,
    });
  }

  function relayFinding(relayHops) {
    var evidence = relayHops.map(function (hop) {
      return {
        hop: hop.index,
        from_ip: hop.from_ip,
        from_host: hop.from_host,
        by_host: hop.by_host,
        protocol: hop.protocol,
        reverse_dns: hop.geo !== null ? hop.geo.reverse_dns : "",
        blacklists: hop.geo !== null ? hop.geo.blacklists : [],
      };
    });
    var first = evidence[0];
    var identity = first.reverse_dns || "a host without reverse DNS";
    return finding(
      "open_relay_suspected",
      "high",
      "Unauthenticated relay accepted mail from an anonymous host",
      "Hop " + first.hop + " (" + first.by_host + ") accepted the message over plain, unauthenticated SMTP from " + first.from_ip + " (" + identity + "), which suggests an open relay or an abused mail server.",
      { hops: evidence },
    );
  }

  function trailFinding(hops) {
    var trail = [];
    hops.forEach(function (hop) {
      var geo = hop.geo;
      if (geo !== null && geo.country_code) trail.push({ hop: hop.index, ip: geo.ip, country_code: geo.country_code, city: geo.city });
    });
    if (!trail.length) return null;
    var codes = trail.map(function (step) {
      return String(step.country_code);
    });
    var countries = py().unique(codes);
    var path = codes.join(ARROW);
    var detail;
    if (countries.length > 1) {
      detail =
        "The message passed through " + trail.length + " geolocated relay(s) across " + countries.length + " countries (" + path + "); multi-country routing is worth checking against the claimed sender location.";
    } else {
      detail = "All " + trail.length + " geolocated relay(s) are in " + countries[0] + " (" + path + ").";
    }
    return finding("hop_geo_trail", "info", "Geographic routing trail", detail, { trail: trail, countries: countries });
  }

  function clamp(value) {
    if (value !== value) return 0.0;
    return Math.max(0.0, Math.min(1.0, value));
  }

  function analyzeInfrastructure(headerAnalysis, cfg, enrichment) {
    var hops = headerAnalysis.hops;
    var origin = normalizeIp(headerAnalysis.originating_ip);
    var publicIps = publicIpsInOrder(headerAnalysis, origin);
    var enriched = enrichMany(publicIps.slice(0, Math.max(0, cfg.max_geo_lookups)), origin, enrichment);

    hops.forEach(function (hop) {
      var ip = normalizeIp(hop.from_ip);
      if (enriched.has(ip)) hop.geo = enriched.get(ip);
      else if (ip && !isPublicIp(ip)) hop.geo = privateGeo(ip);
    });

    var originGeo = null;
    if (enriched.has(origin)) originGeo = enriched.get(origin);
    else if (origin && !isPublicIp(origin)) originGeo = privateGeo(origin);

    var torExit = originGeo !== null && originGeo.is_tor_exit;
    var vpnMatch = originGeo !== null ? RX("_VPN_RE").search(providerText(originGeo)) : null;
    var vpnOrProxy = originGeo !== null && !isMailServiceEgress(originGeo) && (originGeo.is_proxy || vpnMatch !== null);
    var hostingMatch = originGeo !== null ? RX("_HOSTING_RE").search(providerText(originGeo)) : null;
    var hostingProvider = originGeo !== null && !isMailServiceEgress(originGeo) && (originGeo.is_hosting || hostingMatch !== null);
    var listed = {};
    var listedCount = 0;
    enriched.forEach(function (geo) {
      if (geo.blacklists.length) {
        listed[geo.ip] = geo.blacklists;
        listedCount += 1;
      }
    });
    var abuse = originGeo !== null ? originGeo.abuse_confidence : null;
    var abuseHigh = abuse !== null && abuse >= 50;
    var blacklisted = listedCount > 0 || abuseHigh;
    var relayHops = openRelayHops(hops);
    var botnet = botnetIndicators(headerAnalysis, originGeo);
    var privateOnly = (originGeo !== null && originGeo.is_private) || (hops.length > 0 && !publicIps.length);

    var signals = [];
    if (torExit) signals.push(0.9);
    if (blacklisted) signals.push(abuse !== null && abuse >= 80 ? 0.9 : 0.8);
    if (vpnOrProxy) signals.push(0.5);
    if (hostingProvider) signals.push(0.35);
    if (relayHops.length) signals.push(0.5);
    if (botnet.length) signals.push(0.6);
    if (privateOnly) signals.push(0.1);
    var score = signals.length ? clamp(Math.max.apply(null, signals) + 0.1 * (signals.length - 1)) : 0.0;

    var findings = [];
    if (originGeo !== null) {
      var provider = originGeo.isp || originGeo.org || "unknown provider";
      if (torExit) {
        var rdnsHit = RX("_TOR_RDNS_RE").search(originGeo.reverse_dns) !== null;
        findings.push(
          finding(
            "tor_exit_node",
            "critical",
            "Origin IP is a Tor exit node",
            "The originating IP " + originGeo.ip + " is a Tor exit node, which anonymises the real sender and is almost never used for legitimate business email.",
            { ip: originGeo.ip, reverse_dns: originGeo.reverse_dns, matched_by: rdnsHit ? "reverse DNS pattern" : "Tor bulk exit list" },
          ),
        );
      }
      if (abuseHigh) {
        findings.push(
          finding(
            "abuseipdb_high",
            "high",
            "AbuseIPDB reports abuse from the origin IP",
            "AbuseIPDB gives " + originGeo.ip + " an abuse confidence of " + abuse + "% from reports in the last 90 days.",
            { ip: originGeo.ip, abuse_confidence: abuse },
          ),
        );
      }
      if (vpnOrProxy) {
        findings.push(
          finding(
            "vpn_or_proxy_origin",
            "medium",
            "Origin IP is a VPN or proxy egress",
            originGeo.ip + " (" + provider + ") is a VPN/proxy endpoint, so the real location of the sender is hidden.",
            { ip: originGeo.ip, isp: originGeo.isp, org: originGeo.org, ip_api_proxy: originGeo.is_proxy, matched: vpnMatch !== null ? vpnMatch[0] : "" },
          ),
        );
      }
      if (hostingProvider) {
        findings.push(
          finding(
            "hosting_provider_origin",
            "medium",
            "Origin IP belongs to a hosting provider",
            originGeo.ip + " is allocated to a hosting/cloud provider (" + provider + ") rather than a mail service or consumer ISP, a pattern typical of attacker-controlled infrastructure.",
            { ip: originGeo.ip, isp: originGeo.isp, org: originGeo.org, asn: originGeo.asn, ip_api_hosting: originGeo.is_hosting, matched: hostingMatch !== null ? hostingMatch[0] : "" },
          ),
        );
      }
    }
    if (listedCount) {
      var zoneSet = new Set();
      Object.keys(listed).forEach(function (ip) {
        listed[ip].forEach(function (zone) {
          zoneSet.add(zone);
        });
      });
      var zones = py().sorted(Array.from(zoneSet));
      findings.push(
        finding(
          "ip_blacklisted",
          "high",
          "Origin IP listed on DNS blocklists",
          Object.keys(listed).join(", ") + " is listed on " + zones.length + " DNS blocklist(s): " + zones.join(", ") + ". Listed addresses are known sources of spam or malware.",
          { listed: listed },
        ),
      );
    }
    if (relayHops.length) findings.push(relayFinding(relayHops));
    if (botnet.length) {
      findings.push(
        finding("botnet_indicator", "high", "Botnet-style delivery indicators", botnet.slice(0, 2).join(" "), {
          indicators: botnet,
          origin_ip: originGeo !== null ? originGeo.ip : "",
        }),
      );
    }
    if (originGeo !== null && RESOLVED_SOURCES.indexOf(originGeo.source) >= 0) findings.push(originFinding(originGeo, headerAnalysis.origin_shared_provider));
    else findings.push(geoUnavailableFinding(origin, originGeo, hops));
    var trail = trailFinding(hops);
    if (trail !== null) findings.push(trail);

    return {
      origin_geo: originGeo,
      tor_exit: torExit,
      vpn_or_proxy: vpnOrProxy,
      hosting_provider: hostingProvider,
      blacklisted: blacklisted,
      open_relay_suspected: relayHops.length > 0,
      botnet_indicators: botnet,
      score: score,
      findings: findings,
    };
  }

  MT.infra = {
    analyzeInfrastructure: analyzeInfrastructure,
    normalizeIp: normalizeIp,
    isPublicIp: isPublicIp,
    publicIpsInOrder: publicIpsInOrder,
    geoInfo: geoInfo,
  };
})(MT);
