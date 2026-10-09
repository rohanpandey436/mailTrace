var MT = MT || {};

(function (MT) {
  var model = null;

  function load() {
    if (model) return model;
    var data = MT.json("url_model");
    model = {
      version: data.version,
      features: data.features,
      baseValue: Math.fround(data.base_value),
      trees: data.trees.map(function (nodes) {
        return nodes.map(function (node) {
          return {
            leaf: node[0] === 1,
            feature: node[1],
            threshold: Math.fround(node[2]),
            yes: node[3],
            no: node[4],
            missingYes: node[5] === 1,
            weight: Math.fround(node[6]),
          };
        });
      }),
    };
    return model;
  }

  function shannonEntropy(text) {
    if (!text) return 0.0;
    var counts = new Map();
    var order = [];
    var points = MT.py.points(text);
    points.forEach(function (ch) {
      if (!counts.has(ch)) {
        counts.set(ch, 0);
        order.push(ch);
      }
      counts.set(ch, counts.get(ch) + 1);
    });
    var total = points.length;
    var sum = 0.0;
    order.forEach(function (ch) {
      var n = counts.get(ch);
      sum += (n / total) * Math.log2(n / total);
    });
    return -sum;
  }

  function sld(registrable) {
    return registrable ? registrable.split(".")[0] : "";
  }

  function brandKeys() {
    var keys = [];
    MT.K("knowledge").BRANDS.forEach(function (domains, key) {
      if (key.length >= 4) keys.push(key);
    });
    return MT.py.sorted(MT.py.unique(keys));
  }

  function lookalikeDistance(host) {
    var second = sld(MT.urls.registrableDomain(host));
    if (!second) return 1.0;
    var best = 1.0;
    var keys = brandKeys();
    var length = MT.py.length(second);
    for (var i = 0; i < keys.length; i += 1) {
      var key = keys[i];
      var span = Math.max(length, key.length);
      if (!span || Math.abs(length - key.length) / span >= best) continue;
      best = Math.min(best, MT.urls.damerauLevenshtein(second, key) / span);
      if (best === 0.0) break;
    }
    return MT.py.round(Math.min(1.0, Math.max(0.0, best)), 6);
  }

  function intelFeatures(intel) {
    if (intel === null || intel === undefined) return [NaN, NaN, NaN];
    var age = intel.age_days === null || intel.age_days === undefined ? NaN : intel.age_days;
    var observed = intel.source === "live" || intel.source === "cache";
    var resolves = observed ? (intel.resolves ? 1.0 : 0.0) : NaN;
    var hasMx = observed ? (intel.has_mx ? 1.0 : 0.0) : NaN;
    return [age, resolves, hasMx];
  }

  function features(info, intel) {
    var py = MT.py;
    var normalized = info.normalized || info.url || "";
    var host = (info.host || "").toLowerCase();
    var path = info.path || "";
    var query;
    try {
      query = MT.urls.urlsplit(normalized).query;
    } catch (error) {
      if (!(error instanceof MT.urls.ValueError)) throw error;
      query = "";
    }
    var labels = host.split(".").filter(Boolean);
    var rd = info.registrable_domain || "";
    var digits = 0;
    py.points(host).forEach(function (c) {
      if (py.isDigit(c)) digits += 1;
    });
    var obfuscation = info.obfuscation || [];
    var keywords = info.suspicious_keywords || [];
    var last = py.rsplit(path, "/", 1).pop();
    var extension = last.indexOf(".") >= 0 ? py.rsplit(last, ".", 1).pop().toLowerCase() : "";
    var knowledge = MT.K("knowledge");
    var knownGood = Boolean(rd && (MT.urls.legitDomains().has(rd) || knowledge.COMMON_URL_HOSTS.has(rd) || knowledge.COMMON_URL_HOSTS.has(host)));
    var extra = intelFeatures(intel);
    var hostLength = py.length(host);
    var risk = knowledge.RISKY_EXTENSIONS.get(extension);
    var credential = MT.K("url_model")._CREDENTIAL_KEYWORDS;
    var values = {
      url_length: py.length(normalized),
      host_length: hostLength,
      path_length: py.length(path),
      query_length: py.length(query),
      host_digit_count: digits,
      host_digit_ratio: host ? digits / hostLength : 0.0,
      host_hyphen_count: py.count(host, "-"),
      host_dot_count: py.count(host, "."),
      subdomain_depth: rd && host.endsWith(rd) ? Math.max(0, py.count(host, ".") - py.count(rd, ".")) : 0,
      path_depth: path.split("/").filter(Boolean).length,
      host_entropy: py.round(shannonEntropy(host), 6),
      longest_label_length: labels.length
        ? Math.max.apply(
            null,
            labels.map(function (label) {
              return py.length(label);
            }),
          )
        : 0,
      is_ip_literal: info.is_ip_literal ? 1 : 0,
      is_shortener: info.is_shortener ? 1 : 0,
      is_punycode: info.is_punycode ? 1 : 0,
      has_userinfo: info.has_userinfo ? 1 : 0,
      anchor_mismatch: info.anchor_mismatch ? 1 : 0,
      is_https: (info.scheme || "").toLowerCase() === "https" ? 1 : 0,
      tld_risk: knowledge.SUSPICIOUS_TLDS.has(info.tld || "") ? 1 : 0,
      keyword_hits: keywords.length,
      credential_keyword_hits: keywords.filter(function (kw) {
        return credential.has(kw);
      }).length,
      obfuscation_count: obfuscation.length,
      brand_in_subdomain: obfuscation.indexOf("brand_in_subdomain") >= 0 ? 1 : 0,
      redirect_parameter: obfuscation.indexOf("redirect_parameter") >= 0 ? 1 : 0,
      executable_path: risk === "critical" || risk === "high" ? 1 : 0,
      known_good_domain: knownGood ? 1 : 0,
      lookalike_flag: info.lookalike_of ? 1 : 0,
      lookalike_distance: lookalikeDistance(host),
      domain_age_days: extra[0],
      resolves: extra[1],
      has_mx: extra[2],
    };
    return load().features.map(function (name) {
      return values[name];
    });
  }

  function score(row) {
    var m = load();
    var total = 0.0;
    for (var t = 0; t < m.trees.length; t += 1) {
      var nodes = m.trees[t];
      var node = nodes[0];
      while (!node.leaf) {
        var value = Math.fround(row[node.feature]);
        var next;
        if (value !== value) next = node.missingYes ? node.yes : node.no;
        else next = value < node.threshold ? node.yes : node.no;
        node = nodes[next];
      }
      total = Math.fround(total + node.weight);
    }
    return logistic(Math.fround(total + m.baseValue));
  }

  function logistic(value) {
    var v = Math.fround(1.0 / Math.fround(1.0 + Math.fround(Math.exp(-Math.abs(value)))));
    return value < 0 ? Math.fround(1.0 - v) : v;
  }

  function probability(row) {
    return score(row);
  }

  function intelIndex(domainIntel) {
    var index = new Map();
    (domainIntel || []).forEach(function (intel) {
      var key = (intel.domain || "").toLowerCase();
      if (key && !index.has(key)) index.set(key, intel);
    });
    return index;
  }

  function scoreUrls(urls, domainIntel) {
    var items = (urls || []).filter(function (u) {
      return u.url;
    });
    if (!items.length) return null;
    var index = intelIndex(domainIntel);
    var matched = 0;
    var probabilities = items.map(function (info) {
      var intel = index.get((info.registrable_domain || "").toLowerCase()) || index.get((info.host || "").toLowerCase()) || null;
      if (intel) matched += 1;
      return probability(features(info, intel));
    });
    var perUrl = MT.py.sorted(
      items.map(function (info, i) {
        return [MT.py.slice(info.url, 0, 300), probabilities[i]];
      }),
      function (item) {
        return -item[1];
      },
    );
    return {
      max_probability: Math.max.apply(null, probabilities),
      per_url: perUrl,
      model: load().version,
      n_urls: items.length,
      n_with_intel: matched,
    };
  }

  MT.urlmodel = {
    load: load,
    features: features,
    probability: probability,
    scoreUrls: scoreUrls,
    logistic: logistic,
    lookalikeDistance: lookalikeDistance,
    shannonEntropy: shannonEntropy,
  };
})(MT);
