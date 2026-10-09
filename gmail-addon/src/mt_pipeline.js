var MT = MT || {};

(function (MT) {
  function defaults(config) {
    var weights = MT.K("config").DEFAULT_WEIGHTS;
    var base = {
      org_domains: [],
      executives: [],
      protected_brands: [],
      trusted_relays: [],
      entropy_threshold: 7.0,
      max_domain_lookups: 6,
      max_geo_lookups: 8,
      simhash_max_distance: 12,
      weights: {},
    };
    weights.forEach(function (value, key) {
      base.weights[key] = value;
    });
    var cfg = {};
    Object.keys(base).forEach(function (key) {
      cfg[key] = base[key];
    });
    if (config) {
      Object.keys(config).forEach(function (key) {
        if (config[key] !== undefined && config[key] !== null) cfg[key] = config[key];
      });
    }
    cfg.enable_network = false;
    return cfg;
  }

  function lookupRequest(headers, targets, cfg) {
    var origin = MT.infra.normalizeIp(headers.originating_ip);
    var ips = MT.infra.publicIpsInOrder(headers, origin).slice(0, Math.max(0, cfg.max_geo_lookups));
    return {
      domains: targets.map(function (target) {
        return { domain: target[0], role: target[1] };
      }),
      ips: ips,
      origin_ip: origin && MT.infra.isPublicIp(origin) ? origin : "",
    };
  }

  function enrichmentFrom(response) {
    if (!response) return null;
    var enrichment = { domains: new Map(), ips: new Map() };
    (response.domains || []).forEach(function (intel) {
      if (intel && intel.domain) enrichment.domains.set(String(intel.domain).toLowerCase(), intel);
    });
    (response.ips || []).forEach(function (geo) {
      if (geo && geo.ip) enrichment.ips.set(String(geo.ip), geo);
    });
    return enrichment;
  }

  function analyze(raw, filename, config, options) {
    var cfg = defaults(config);
    var opts = options || {};
    var parsedResult = MT.mime.parseEmail(raw);
    var parsed = parsedResult.email;
    var rawAttachments = parsedResult.attachments;
    var result = {
      filename: filename,
      engine_version: MT.json("knowledge").engine_version,
      masked: false,
      email: parsed,
    };

    var headers = MT.headers.analyzeHeaders(parsed, cfg);
    var auth = MT.auth.evaluateAuth(parsed, headers, cfg);
    headers.auth = auth.result;
    auth.findings.forEach(function (f) {
      headers.findings.push(f);
    });
    result.headers = headers;

    var urls = MT.urls.analyzeUrls(parsed, cfg);
    result.urls = urls;

    var attachments = MT.files.analyzeAttachments(rawAttachments, cfg);
    result.attachments = attachments;

    var targets = MT.domains.collectDomains(parsed, headers, urls, cfg);
    result.nlp = MT.nlp.analyzeContent(parsed, urls, attachments, cfg, headers.auth);

    var enrichment = opts.enrichment || null;
    if (!enrichment && typeof opts.lookup === "function") {
      enrichment = enrichmentFrom(opts.lookup(lookupRequest(headers, targets, cfg)));
    }
    result.infrastructure = MT.infra.analyzeInfrastructure(headers, cfg, enrichment);
    result.domains = MT.domains.analyzeDomains(targets, cfg, enrichment);

    var matches = opts.matches || null;
    if (!matches && typeof opts.match === "function") {
      var indicators = MT.intel.extractIndicators(parsed, headers, urls, attachments, result.domains, result.infrastructure);
      matches = opts.match(indicators, parsed.fuzzy);
    }
    result.intel = MT.intel.correlate(parsed, headers, urls, attachments, result.domains, result.infrastructure, matches, cfg);

    var scored = MT.scoring.evaluate(parsed, headers, urls, attachments, result.nlp, result.domains, result.infrastructure, result.intel, cfg);
    result.verdict = scored.verdict;
    result.attribution = scored.attribution;
    result.findings = scored.findings;
    delete headers.infos;
    return result;
  }

  MT.pipeline = {
    analyze: analyze,
    defaults: defaults,
    lookupRequest: lookupRequest,
    enrichmentFrom: enrichmentFrom,
  };
})(MT);
