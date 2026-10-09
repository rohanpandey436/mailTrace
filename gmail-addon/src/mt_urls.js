var MT = MT || {};

(function (MT) {
  var SCHEME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.";
  var USES_NETLOC = [
    "", "ftp", "http", "gopher", "nntp", "telnet", "imap", "wais", "file", "mms", "https", "shttp", "snews",
    "prospero", "rtsp", "rtsps", "rtspu", "rsync", "svn", "svn+ssh", "sftp", "nfs", "git", "git+ssh", "ws", "wss",
    "itms-services",
  ];
  var IPV_FUTURE = /^[vV][a-fA-F0-9]+\..+$/;
  var SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  var py = null;

  function P() {
    if (!py) py = MT.py;
    return py;
  }

  function ValueError(message) {
    this.name = "ValueError";
    this.message = message;
  }
  ValueError.prototype = Object.create(Error.prototype);

  function isControlOrSpace(code) {
    return code <= 0x20;
  }

  function stripUnsafe(text) {
    var out = [];
    for (var i = 0; i < text.length; i += 1) {
      var ch = text[i];
      if (ch !== "\t" && ch !== "\r" && ch !== "\n") out.push(ch);
    }
    return out.join("");
  }

  function checkBracketedHost(hostname) {
    if (hostname[0] === "v" || hostname[0] === "V") {
      if (!IPV_FUTURE.test(hostname)) throw new ValueError("IPvFuture address is invalid");
      return;
    }
    var address;
    try {
      address = MT.net.ipAddress(hostname);
    } catch (error) {
      if (error instanceof MT.net.AddressValueError) throw new ValueError(hostname + " does not appear to be an IPv4 or IPv6 address");
      throw error;
    }
    if (address.version === 4) throw new ValueError("An IPv4 address cannot be in brackets");
  }

  function checkBracketedNetloc(netloc) {
    var hostAndPort = P().rpartition(netloc, "@")[2];
    var pieces = P().partition(hostAndPort, "[");
    var hostname;
    if (pieces[1]) {
      if (pieces[0]) throw new ValueError("Invalid IPv6 URL");
      var inner = P().partition(pieces[2], "]");
      hostname = inner[0];
      if (inner[2] && inner[2][0] !== ":") throw new ValueError("Invalid IPv6 URL");
    } else {
      hostname = P().partition(hostAndPort, ":")[0];
    }
    checkBracketedHost(hostname);
  }

  function checkNetloc(netloc) {
    if (!netloc || MT.codecs.isAscii(netloc)) return;
    var n = P().replaceAll(P().replaceAll(P().replaceAll(P().replaceAll(netloc, "@", ""), ":", ""), "#", ""), "?", "");
    var normalized = n.normalize("NFKC");
    if (n === normalized) return;
    var specials = "/?#@:";
    for (var i = 0; i < specials.length; i += 1) {
      if (normalized.indexOf(specials[i]) >= 0) throw new ValueError("netloc contains invalid characters under NFKC normalization");
    }
  }

  function SplitResult(scheme, netloc, path, query, fragment) {
    this.scheme = scheme;
    this.netloc = netloc;
    this.path = path;
    this.query = query;
    this.fragment = fragment;
  }

  SplitResult.prototype.hostInfo = function () {
    var hostinfo = P().rpartition(this.netloc, "@")[2];
    var pieces = P().partition(hostinfo, "[");
    var hostname;
    var port;
    if (pieces[1]) {
      var inner = P().partition(pieces[2], "]");
      hostname = inner[0];
      port = P().partition(inner[2], ":")[2];
    } else {
      var plain = P().partition(hostinfo, ":");
      hostname = plain[0];
      port = plain[2];
    }
    return [hostname, port || null];
  };

  SplitResult.prototype.hostname = function () {
    var hostname = this.hostInfo()[0];
    if (!hostname) return null;
    var pieces = P().partition(hostname, "%");
    return pieces[0].toLowerCase() + pieces[1] + pieces[2];
  };

  SplitResult.prototype.port = function () {
    var port = this.hostInfo()[1];
    if (port === null) return null;
    if (!/^[0-9]+$/.test(port)) throw new ValueError("Port could not be cast to integer value as " + port);
    var value = Number(port);
    if (value < 0 || value > 65535) throw new ValueError("Port out of range 0-65535");
    return value;
  };

  SplitResult.prototype.userInfo = function () {
    var pieces = P().rpartition(this.netloc, "@");
    if (!pieces[1]) return [null, null];
    var user = P().partition(pieces[0], ":");
    return [user[0], user[1] ? user[2] : null];
  };

  function splitNetloc(url, start) {
    var delim = url.length;
    var delimiters = "/?#";
    for (var i = 0; i < delimiters.length; i += 1) {
      var found = url.indexOf(delimiters[i], start);
      if (found >= 0) delim = Math.min(delim, found);
    }
    return [url.slice(start, delim), url.slice(delim)];
  }

  function urlsplit(input) {
    var url = String(input);
    var lead = 0;
    while (lead < url.length && isControlOrSpace(url.charCodeAt(lead))) lead += 1;
    url = stripUnsafe(url.slice(lead));
    var scheme = "";
    var netloc = "";
    var query = "";
    var fragment = "";
    var i = url.indexOf(":");
    if (i > 0 && /^[A-Za-z]/.test(url)) {
      var valid = true;
      for (var k = 0; k < i; k += 1) {
        if (SCHEME_CHARS.indexOf(url[k]) < 0) {
          valid = false;
          break;
        }
      }
      if (valid) {
        scheme = url.slice(0, i).toLowerCase();
        url = url.slice(i + 1);
      }
    }
    if (url.slice(0, 2) === "//") {
      var pieces = splitNetloc(url, 2);
      netloc = pieces[0];
      url = pieces[1];
      var open = netloc.indexOf("[") >= 0;
      var close = netloc.indexOf("]") >= 0;
      if ((open && !close) || (close && !open)) throw new ValueError("Invalid IPv6 URL");
      if (open && close) checkBracketedNetloc(netloc);
    }
    if (url.indexOf("#") >= 0) {
      var hash = P().split(url, "#", 1);
      url = hash[0];
      fragment = hash[1];
    }
    if (url.indexOf("?") >= 0) {
      var question = P().split(url, "?", 1);
      url = question[0];
      query = question[1];
    }
    checkNetloc(netloc);
    return new SplitResult(scheme, netloc, url, query, fragment);
  }

  function urlunsplit(scheme, netloc, path, query, fragment) {
    var url = path;
    if (netloc) {
      if (url && url[0] !== "/") url = "/" + url;
      url = "//" + netloc + url;
    } else if (url.slice(0, 2) === "//") {
      url = "//" + url;
    } else if (scheme && USES_NETLOC.indexOf(scheme) >= 0 && (!url || url[0] === "/")) {
      url = "//" + url;
    }
    if (scheme) url = scheme + ":" + url;
    if (query) url = url + "?" + query;
    if (fragment) url = url + "#" + fragment;
    return url;
  }

  function unquoteBytes(text) {
    var bits = MT.bytes.utf8Encode(text);
    var out = [];
    var i = 0;
    var first = true;
    var segments = [];
    var start = 0;
    for (i = 0; i <= bits.length; i += 1) {
      if (i === bits.length || bits[i] === 37) {
        segments.push(bits.subarray(start, i));
        start = i + 1;
      }
    }
    if (segments.length === 1) return bits;
    segments.forEach(function (segment) {
      if (first) {
        first = false;
        for (var k = 0; k < segment.length; k += 1) out.push(segment[k]);
        return;
      }
      var a = segment[0];
      var b = segment[1];
      var hexA = a !== undefined && ((a >= 48 && a <= 57) || (a >= 65 && a <= 70) || (a >= 97 && a <= 102));
      var hexB = b !== undefined && ((b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102));
      var rest;
      if (hexA && hexB) {
        out.push(parseInt(String.fromCharCode(a, b), 16));
        rest = 2;
      } else {
        out.push(37);
        rest = 0;
      }
      for (var m = rest; m < segment.length; m += 1) out.push(segment[m]);
    });
    return new Uint8Array(out);
  }

  function unquote(text, encoding) {
    if (text.indexOf("%") < 0) return text;
    var codec = encoding || "utf-8";
    var out = [];
    var i = 0;
    while (i < text.length) {
      var start = i;
      while (i < text.length && text.charCodeAt(i) > 0x7f) i += 1;
      if (i > start) out.push(text.slice(start, i));
      start = i;
      while (i < text.length && text.charCodeAt(i) <= 0x7f) i += 1;
      if (i > start) out.push(MT.codecs.decode(unquoteBytes(text.slice(start, i)), codec, "replace"));
    }
    return out.join("");
  }

  function unquotePlus(text) {
    return unquote(P().replaceAll(text, "+", " "));
  }

  function parseQsl(qs, keepBlank) {
    if (!qs) return [];
    var out = [];
    qs.split("&").forEach(function (pair) {
      if (!pair) return;
      var pieces = P().partition(pair, "=");
      if (pieces[2] || keepBlank) out.push([unquotePlus(pieces[0]), unquotePlus(pieces[2])]);
    });
    return out;
  }

  var trie = null;
  var suffixSet = null;
  var fallbackSuffixes = null;

  function psl() {
    if (trie) return trie;
    var data = MT.json("psl");
    var root = { matches: new Map(), end: false };
    data.suffixes.forEach(function (suffix) {
      var node = root;
      var labels = suffix.split(".").reverse();
      labels.forEach(function (label) {
        if (!node.matches.has(label)) node.matches.set(label, { matches: new Map(), end: false });
        node = node.matches.get(label);
      });
      node.end = true;
    });
    suffixSet = new Set(data.suffixes);
    fallbackSuffixes = new Set(data.fallback);
    trie = root;
    return trie;
  }

  function schemelessUrl(url) {
    var at = url.indexOf("//");
    if (at === 0) return url.slice(2);
    if (at < 2 || url[at - 1] !== ":") return url;
    var head = url.slice(0, at - 1);
    for (var i = 0; i < head.length; i += 1) if (SCHEME_CHARS.indexOf(head[i]) < 0) return url;
    return url.slice(at + 2);
  }

  function lenientNetloc(url) {
    var after = P().rpartition(P().partition(P().partition(P().partition(schemelessUrl(url), "/")[0], "?")[0], "#")[0], "@")[2];
    if (after && after[0] === "[") {
      var maybe = P().partition(after, "]");
      if (maybe[1] === "]") return maybe[0] + "]";
    }
    var hostname = P().strip(P().partition(after, ":")[0]);
    return P().rstrip(hostname, "." + String.fromCharCode(0x3002, 0xff0e, 0xff61));
  }

  var IP_RE = /^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;

  function looksLikeIp(text) {
    if (!text || !P().isDecimal(P().points(text)[0])) return false;
    return IP_RE.test(text);
  }

  function looksLikeIpv6(text) {
    try {
      var address = MT.net.ipAddress(text);
      return address.version === 6;
    } catch (error) {
      if (error instanceof MT.net.AddressValueError) return false;
      throw error;
    }
  }

  function suffixIndex(labels) {
    var node = psl();
    var regNode = node;
    var suffixIdx = labels.length;
    var regIdx = labels.length;
    var labelIdx = labels.length;
    for (var i = labels.length - 1; i >= 0; i -= 1) {
      var decoded = MT.idna.pslLabel(labels[i]);
      if (node.matches.has(decoded)) {
        labelIdx -= 1;
        node = node.matches.get(decoded);
        if (node.end) {
          suffixIdx = labelIdx;
          regNode = node;
          regIdx = labelIdx;
        }
        continue;
      }
      if (node.matches.has("*")) {
        var exception = node.matches.has("!" + decoded);
        return { suffix: exception ? labelIdx : labelIdx - 1, registry: regIdx };
      }
      break;
    }
    if (suffixIdx === labels.length) return null;
    return { suffix: suffixIdx, registry: regIdx };
  }

  function extractNetloc(netloc) {
    var dots = P().replaceAll(P().replaceAll(P().replaceAll(netloc, String.fromCharCode(0x3002), "."), String.fromCharCode(0xff0e), "."), String.fromCharCode(0xff61), ".");
    if (dots.length >= 4 && dots[0] === "[" && dots[dots.length - 1] === "]" && looksLikeIpv6(dots.slice(1, -1))) {
      return { subdomain: "", domain: dots, suffix: "" };
    }
    var labels = dots.split(".");
    var found = suffixIndex(labels);
    if (!found && labels.length === 4 && looksLikeIp(dots)) return { subdomain: "", domain: dots, suffix: "" };
    if (!found) return { subdomain: labels.slice(0, -1).join("."), domain: labels[labels.length - 1], suffix: "" };
    var index = found.suffix;
    return {
      subdomain: index >= 2 ? labels.slice(0, index - 1).join(".") : "",
      domain: index > 0 ? labels[index - 1] : "",
      suffix: labels.slice(index).join("."),
    };
  }

  function extract(url) {
    return extractNetloc(lenientNetloc(url));
  }

  function isIp(value) {
    return MT.net.tryAddress(value) !== null;
  }

  function registrableDomain(input) {
    var host = P().rstrip(P().strip(input || "").toLowerCase(), ".");
    if (!host) return "";
    if (host[0] === "[" && host[host.length - 1] === "]") host = host.slice(1, -1);
    if (isIp(host)) return host;
    var ext = null;
    try {
      ext = extract(host);
    } catch (error) {
      if (!(error instanceof MT.urls.ValueError) && !(error instanceof RangeError)) throw error;
    }
    if (ext && ext.domain && ext.suffix) return ext.domain + "." + ext.suffix;
    if (ext && ext.domain) return ext.domain;
    psl();
    var labels = host.split(".").filter(Boolean);
    if (labels.length >= 3 && fallbackSuffixes.has(labels.slice(-2).join("."))) return labels.slice(-3).join(".");
    if (labels.length >= 2) return labels.slice(-2).join(".");
    return host;
  }

  var brandLegit = null;
  var domainToBrand = null;

  function brands() {
    return MT.K("knowledge").BRANDS;
  }

  function legitDomains() {
    if (brandLegit) return brandLegit;
    brandLegit = new Set();
    domainToBrand = new Map();
    brands().forEach(function (domains, key) {
      domains.forEach(function (domain) {
        brandLegit.add(domain.toLowerCase());
        if (!domainToBrand.has(domain.toLowerCase())) domainToBrand.set(domain.toLowerCase(), key);
      });
    });
    return brandLegit;
  }

  function K() {
    return MT.K("link_analyzer");
  }

  function unreserved() {
    return K()._UNRESERVED;
  }

  function unquoteUnreserved(value) {
    return MT.RX("link_analyzer", "_PCT_RE").sub(function (found) {
      var ch = String.fromCharCode(parseInt(found[1], 16));
      return unreserved().has(ch) ? ch : found[0].toUpperCase();
    }, value);
  }

  function normalizeUrl(input) {
    var url = P().strip(input || "");
    if (!url) return "";
    var lowered = url.toLowerCase();
    if (lowered.slice(0, 5) === "data:" || lowered.slice(0, 11) === "javascript:") {
      var pieces = P().partition(url, ":");
      return pieces[0].toLowerCase() + ":" + P().strip(pieces[2]);
    }
    if (url.indexOf("://") < 0) url = url.slice(0, 2) === "//" ? "http:" + url : "http://" + url;
    var parts;
    try {
      parts = urlsplit(url);
    } catch (error) {
      if (error instanceof ValueError) return "";
      throw error;
    }
    var scheme = parts.scheme.toLowerCase();
    var host;
    var port;
    try {
      host = P().rstrip((parts.hostname() || "").toLowerCase(), ".");
      port = parts.port();
    } catch (error) {
      if (!(error instanceof ValueError)) throw error;
      host = parts.netloc.toLowerCase();
      port = null;
    }
    if (!host) return "";
    if (host.indexOf(":") >= 0 && host[0] !== "[") host = "[" + host + "]";
    var netloc = host;
    if (port && !((scheme === "http" && port === 80) || (scheme === "https" && port === 443))) netloc = host + ":" + port;
    var user = parts.userInfo();
    if (user[0]) netloc = user[0] + (user[1] ? ":" + user[1] : "") + "@" + netloc;
    var path = unquoteUnreserved(parts.path) || "/";
    var query = unquoteUnreserved(parts.query);
    return urlunsplit(scheme, netloc, path, query, "");
  }

  function damerauLevenshtein(left, right) {
    if (left === right) return 0;
    var a = P().points(left);
    var b = P().points(right);
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    var previous2 = [];
    var previous = [];
    var j;
    for (j = 0; j <= b.length; j += 1) previous.push(j);
    for (var i = 1; i <= a.length; i += 1) {
      var current = [i];
      for (j = 1; j <= b.length; j += 1) {
        var cost = a[i - 1] === b[j - 1] ? 0 : 1;
        var value = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) value = Math.min(value, previous2[j - 2] + 1);
        current.push(value);
      }
      previous2 = previous;
      previous = current;
    }
    return previous[b.length];
  }

  function foldHomoglyphs(value) {
    var table = MT.K("knowledge").HOMOGLYPHS;
    return P()
      .points(value)
      .map(function (ch) {
        return table.has(ch) ? table.get(ch) : ch;
      })
      .join("");
  }

  function foldMultichar(value) {
    var out = value;
    K()._MULTI_CHAR_CONFUSABLES.forEach(function (pair) {
      out = P().replaceAll(out, pair[0], pair[1]);
    });
    return out;
  }

  function decodeIdna(host) {
    return MT.idna.decodeHost(host);
  }

  function sld(registrable) {
    return registrable ? registrable.split(".")[0] : "";
  }

  function candidates(cfg) {
    var result = new Map();
    brands().forEach(function (domains, key) {
      result.set(key, {
        name: key,
        legit: new Set(
          domains.map(function (d) {
            return d.toLowerCase();
          }),
        ),
      });
    });
    cfg.org_domains.forEach(function (org) {
      var rd = registrableDomain(org);
      var key = sld(rd);
      if (key) result.set(key, { name: rd, legit: new Set([rd]) });
    });
    cfg.protected_brands.forEach(function (raw) {
      var brand = P().strip(raw).toLowerCase();
      if (!brand) return;
      if (brand.indexOf(".") >= 0) {
        var rd = registrableDomain(brand);
        var key = sld(rd);
        if (key && !result.has(key)) result.set(key, { name: rd, legit: new Set([rd]) });
      } else if (!result.has(brand)) {
        result.set(brand, { name: brand, legit: new Set() });
      }
    });
    return result;
  }

  function tokenContains(value, key) {
    if (key.length < 3 || value.indexOf(key) < 0 || value === key) return false;
    return MT.py.re("(?:^|[-_.0-9])" + P().reEscape(key) + "(?:[-_.0-9]|$)").test(value);
  }

  function orgDomains(cfg) {
    var set = new Set();
    cfg.org_domains.forEach(function (d) {
      if (d) set.add(registrableDomain(d));
    });
    return set;
  }

  function isLookalike(input, cfg) {
    var host = P().rstrip(P().strip(input || "").toLowerCase(), ".");
    if (!host || isIp(host)) return ["", ""];
    var org = orgDomains(cfg);
    var rd = registrableDomain(host);
    var legit = legitDomains();
    var freemail = MT.K("knowledge").FREEMAIL_DOMAINS;
    if (!rd || org.has(rd) || legit.has(rd) || freemail.has(rd)) return ["", ""];
    var options = candidates(cfg);
    var allLegit = new Set(legit);
    org.forEach(function (d) {
      allLegit.add(d);
    });
    var prefix = "";
    if (host.indexOf("xn--") >= 0) {
      var decoded = decodeIdna(host);
      if (decoded !== host) {
        prefix = "punycode";
        host = decoded;
        rd = registrableDomain(host);
        if (allLegit.has(rd)) return [domainToBrand.has(rd) ? domainToBrand.get(rd) : rd, "punycode"];
      }
    }
    var second = sld(rd);
    if (!second) return ["", ""];
    var result = function (name, technique) {
      return [name, prefix || technique];
    };
    var folded = foldHomoglyphs(second);
    var entries = Array.from(options.entries());
    var i;
    if (folded !== second) {
      var suffix = rd.length > second.length ? rd.slice(second.length + 1) : "";
      for (i = 0; i < entries.length; i += 1) {
        if (folded === entries[i][0] || (suffix && entries[i][1].legit.has(folded + "." + suffix))) {
          return result(entries[i][1].name, "homoglyph");
        }
      }
      if (suffix && allLegit.has(folded + "." + suffix)) {
        var joined = folded + "." + suffix;
        return result(domainToBrand.has(joined) ? domainToBrand.get(joined) : joined, "homoglyph");
      }
    }
    var multichar = foldMultichar(foldHomoglyphs(second));
    for (i = 0; i < entries.length; i += 1) {
      var key = entries[i][0];
      var entry = entries[i][1];
      if (key.length < 5 || second === key || entry.legit.has(rd)) continue;
      if (multichar === key) return result(entry.name, "typosquat");
      if (second[0] !== key[0] || Math.abs(P().length(second) - P().length(key)) > K()._MAX_TYPOSQUAT_DISTANCE) continue;
      var distance = damerauLevenshtein(second, key);
      if (distance === 1) return result(entry.name, "typosquat");
      if (distance === 2 && key.length >= 8) return result(entry.name, "typosquat");
    }
    for (i = 0; i < entries.length; i += 1) {
      if (second === entries[i][0] && !entries[i][1].legit.has(rd)) return result(entries[i][1].name, "tld_swap");
    }
    for (i = 0; i < entries.length; i += 1) {
      if (!entries[i][1].legit.has(rd) && tokenContains(second, entries[i][0])) return result(entries[i][1].name, "extra_token");
    }
    var sub = host.endsWith(rd) && host.length > rd.length ? P().rstrip(host.slice(0, host.length - rd.length), ".") : "";
    if (sub) {
      var labels = sub.split(".");
      var dotted = "." + sub + ".";
      var tenants = K()._SAAS_TENANT_DOMAINS;
      for (i = 0; i < entries.length; i += 1) {
        var name = entries[i][1].name;
        if (org.has(name) && tenants.has(rd)) continue;
        var inLegit = false;
        entries[i][1].legit.forEach(function (d) {
          if (dotted.indexOf("." + d + ".") >= 0) inLegit = true;
        });
        if (labels.indexOf(entries[i][0]) >= 0 || inLegit) return result(name, "subdomain_abuse");
      }
    }
    return ["", ""];
  }

  function anchorHost(anchorText) {
    var text = P().strip(anchorText || "").toLowerCase();
    if (!text) return "";
    var first = P().split(text)[0];
    var found = MT.RX("link_analyzer", "_HOST_IN_TEXT_RE").search(first);
    if (!found) return "";
    var host = found[1];
    var explicit = first.indexOf("://") >= 0 || first.slice(0, 4) === "www.";
    if (!explicit && !K()._PLAUSIBLE_TLDS.has(P().rsplit(host, ".", 1).pop())) return "";
    return host;
  }

  function numericIpForm(host) {
    if (P().isDigit(host)) {
      var value = P().toInt(host);
      if (value === null) throw new ValueError("invalid literal for int() with base 10: " + host);
      if (value > 255) return true;
    }
    if (MT.RX("link_analyzer", "_HEX_IP_RE").match(host)) return true;
    return Boolean(MT.RX("link_analyzer", "_DOTTED_NUMERIC_RE").match(host)) && !isIp(host);
  }

  function targetHost(target) {
    var text = target;
    if (text.slice(0, 2) === "//") text = "http:" + text;
    else if (text.indexOf("://") < 0) text = "http://" + text;
    try {
      return (urlsplit(text).hostname() || "").toLowerCase();
    } catch (error) {
      if (error instanceof ValueError) return "";
      throw error;
    }
  }

  function looksBase64(value) {
    if (!MT.RX("link_analyzer", "_B64_RE").match(value)) return false;
    var padded = value + "=".repeat((4 - (value.length % 4)) % 4);
    var attempts = [padded, P().replaceAll(P().replaceAll(padded, "-", "+"), "_", "/")];
    for (var i = 0; i < attempts.length; i += 1) {
      var decoded;
      try {
        decoded = MT.binascii.a2bBase64(MT.bytes.fromLatin1(attempts[i]), false);
      } catch (error) {
        if (error instanceof MT.binascii.Error) continue;
        throw error;
      }
      if (!decoded.length) continue;
      var printable = 0;
      for (var k = 0; k < decoded.length; k += 1) if (decoded[k] >= 32 && decoded[k] < 127) printable += 1;
      if (printable / decoded.length > 0.8) return true;
    }
    return false;
  }

  function pathExtension(path) {
    var segment = P().rsplit(path, "/", 1).pop();
    if (segment.indexOf(".") < 0) return "";
    return P().rsplit(segment, ".", 1).pop().toLowerCase();
  }

  function newInfo(url, normalized, anchor) {
    return {
      url: url,
      normalized: normalized,
      scheme: "",
      host: "",
      registrable_domain: "",
      tld: "",
      path: "",
      anchor_text: anchor,
      anchor_mismatch: false,
      is_ip_literal: false,
      is_shortener: false,
      is_punycode: false,
      has_userinfo: false,
      obfuscation: [],
      suspicious_keywords: [],
      lookalike_of: "",
      risk: "info",
      reasons: [],
    };
  }

  function analyzeUrl(input, anchorText, cfg) {
    var original = P().strip(input || "");
    var normalized = normalizeUrl(original);
    var info = newInfo(P().slice(original, 0, 2048), P().slice(normalized, 0, 2048), P().slice(anchorText || "", 0, 200));
    var reasons = [];
    var obfuscation = [];
    var lowered = normalized.toLowerCase();
    var knowledge = MT.K("knowledge");

    if (lowered.slice(0, 5) === "data:") {
      info.scheme = "data";
      obfuscation.push("data_uri");
      reasons.push("Link is an inline data: URI (hidden payload delivered inside the message)");
      info.obfuscation = obfuscation;
      info.reasons = reasons;
      info.risk = "high";
      return info;
    }
    if (lowered.slice(0, 11) === "javascript:") {
      info.scheme = "javascript";
      obfuscation.push("javascript_uri");
      reasons.push("Link executes script (javascript: URI) instead of opening a page");
      info.obfuscation = obfuscation;
      info.reasons = reasons;
      info.risk = "high";
      return info;
    }
    if (!normalized) {
      info.risk = "info";
      info.reasons = ["Could not be parsed as a URL"];
      return info;
    }

    var parts = urlsplit(normalized);
    var host = (parts.hostname() || "").toLowerCase();
    var port;
    try {
      port = parts.port();
    } catch (error) {
      if (!(error instanceof ValueError)) throw error;
      port = null;
    }
    var userinfo = parts.netloc.indexOf("@") >= 0;
    var rawNetloc;
    try {
      rawNetloc = urlsplit(original.indexOf("://") >= 0 ? original : "http://" + original).netloc;
    } catch (error) {
      if (!(error instanceof ValueError)) throw error;
      rawNetloc = "";
    }
    info.scheme = parts.scheme;
    info.host = host;
    info.path = parts.path;
    info.registrable_domain = registrableDomain(host);
    info.tld = host.indexOf(".") >= 0 ? P().rsplit(host, ".", 1).pop() : "";
    var org = orgDomains(cfg);
    var legit = legitDomains();
    var legitBrand = legit.has(info.registrable_domain) || org.has(info.registrable_domain);

    if (isIp(host)) {
      info.is_ip_literal = true;
      reasons.push("Link points at a raw IP address (" + host + ") instead of a domain name");
    } else if (numericIpForm(host)) {
      info.is_ip_literal = true;
      obfuscation.push("numeric_ip_form");
      reasons.push("Host '" + host + "' is an obfuscated numeric IP address");
    }
    if (knowledge.URL_SHORTENERS.has(info.registrable_domain) || knowledge.URL_SHORTENERS.has(host)) {
      info.is_shortener = true;
      reasons.push("URL shortener " + info.registrable_domain + " hides the real destination");
    }
    if (host.indexOf("xn--") >= 0) {
      info.is_punycode = true;
      reasons.push("Internationalised (punycode) host " + host + " can imitate a familiar name");
    }
    if (userinfo) {
      info.has_userinfo = true;
      reasons.push("Authority contains '@': the text before it is a decoy, the real host follows it");
    }

    if (rawNetloc.indexOf("%") >= 0) obfuscation.push("percent_encoded_host");
    if (host && !info.is_ip_literal) {
      var extraLabels = P().count(host, ".") - P().count(info.registrable_domain, ".");
      if (extraLabels > 3) obfuscation.push("excessive_subdomains");
    }
    if (P().length(normalized) > 120) obfuscation.push("long_url");
    var queryPairs = parseQsl(parts.query, true);
    if (
      queryPairs.some(function (pair) {
        return looksBase64(pair[1]);
      })
    ) {
      obfuscation.push("base64_in_query");
    }
    var tail = normalized.indexOf("://") >= 0 ? P().split(normalized, "://", 1)[1] : normalized;
    if (tail.indexOf("://") >= 0 || /https?(?::|%3a)/i.test(tail)) obfuscation.push("double_scheme");
    if (MT.RX("link_analyzer", "_PCT_RE").findall(parts.path + parts.query).length >= 3 || lowered.indexOf("\\x") >= 0) {
      obfuscation.push("hex_escapes");
    }
    var redirect = false;
    for (var q = 0; q < queryPairs.length; q += 1) {
      var key = queryPairs[q][0];
      var target = unquote(queryPairs[q][1]).toLowerCase();
      var startsHttp = target.slice(0, 7) === "http://" || target.slice(0, 8) === "https://" || target.slice(0, 2) === "//";
      if (K()._REDIRECT_KEYS.has(key.toLowerCase()) && (startsHttp || target.indexOf("://") >= 0)) {
        var th = targetHost(target);
        if (th && info.registrable_domain && registrableDomain(th) === info.registrable_domain) continue;
        redirect = true;
        break;
      }
    }
    if (redirect) {
      obfuscation.push("redirect_parameter");
      reasons.push("Query string carries a redirect target: the visible host is only a relay");
    }
    var subPart = info.registrable_domain && host.endsWith(info.registrable_domain) ? P().rstrip(host.slice(0, host.length - info.registrable_domain.length), ".") : "";
    if (subPart && !legitBrand) {
      var subLabels = subPart.split(".");
      var brandsInSub = [];
      brands().forEach(function (domains, brandKey) {
        var hit = subLabels.indexOf(brandKey) >= 0;
        if (!hit) {
          hit = domains.some(function (d) {
            return d === subPart || subPart.endsWith("." + d);
          });
        }
        if (hit) brandsInSub.push(brandKey);
      });
      if (brandsInSub.length) {
        obfuscation.push("brand_in_subdomain");
        reasons.push("Brand '" + brandsInSub[0] + "' appears in the sub-domain but the site belongs to " + info.registrable_domain);
      }
    }
    if (knowledge.SUSPICIOUS_TLDS.has(info.tld) && !legitBrand) {
      obfuscation.push("suspicious_tld");
      reasons.push("Top-level domain ." + info.tld + " is heavily abused in phishing");
    }
    if (port && [80, 443, 8080, 8443].indexOf(port) < 0) {
      obfuscation.push("port_unusual");
      reasons.push("Unusual port " + port);
    }
    var extension = pathExtension(normalized ? parts.path : "");
    var riskyValue = knowledge.RISKY_EXTENSIONS.get(extension);
    var executable = riskyValue === "critical" || riskyValue === "high";
    if (executable) {
      obfuscation.push("file_extension_executable");
      reasons.push("Link downloads a ." + extension + " file");
    }

    var haystack = normalized ? host + " " + unquote(parts.path).toLowerCase() : host;
    info.suspicious_keywords = knowledge.URL_SUSPICIOUS_KEYWORDS.filter(function (kw) {
      return haystack.indexOf(kw) >= 0;
    });
    var lookalike = legitBrand ? ["", ""] : isLookalike(host, cfg);
    var imitated = lookalike[0];
    if (imitated) {
      info.lookalike_of = imitated;
      reasons.push("Host " + host + " imitates " + imitated + " (" + lookalike[1] + ")");
    }

    var visible = anchorHost(anchorText);
    if (visible) {
      var anchorRd = registrableDomain(visible);
      if (anchorRd && info.registrable_domain && anchorRd !== info.registrable_domain) {
        info.anchor_mismatch = true;
        reasons.push("Visible link text shows " + visible + " but the link opens " + host);
      }
    }

    var credKeywords = info.suspicious_keywords.filter(function (kw) {
      return K()._CREDENTIAL_KEYWORDS.has(kw);
    });
    if (credKeywords.length && !legitBrand) {
      reasons.push("Path/host contains credential-harvest keywords " + credKeywords.slice(0, 4).join(", "));
    }

    var beforeAt = lowered.split("@")[0];
    var brandUserinfo =
      info.has_userinfo &&
      Array.from(brands().keys()).some(function (brandKey) {
        return beforeAt.indexOf(brandKey) >= 0;
      });
    var risk;
    if (executable || ((imitated || obfuscation.indexOf("brand_in_subdomain") >= 0) && info.suspicious_keywords.length) || brandUserinfo) {
      risk = "critical";
    } else if (
      info.is_ip_literal ||
      info.anchor_mismatch ||
      info.is_punycode ||
      info.has_userinfo ||
      imitated ||
      (redirect && info.suspicious_keywords.length)
    ) {
      risk = "high";
    } else if (
      info.is_shortener ||
      obfuscation.indexOf("suspicious_tld") >= 0 ||
      obfuscation.indexOf("brand_in_subdomain") >= 0 ||
      obfuscation.length >= 2
    ) {
      risk = "medium";
    } else if (obfuscation.length || (credKeywords.length >= 2 && !legitBrand)) {
      risk = "low";
    } else {
      risk = "info";
    }
    if (legitBrand && (risk === "low" || risk === "medium") && !info.anchor_mismatch && !info.has_userinfo) risk = "info";
    info.obfuscation = obfuscation;
    info.reasons = reasons;
    info.risk = risk;
    return info;
  }

  function cleanTextUrl(raw) {
    var url = P().strip(raw);
    var trailing = K()._TRAILING_PUNCT;
    while (url && trailing.indexOf(url[url.length - 1]) >= 0) url = url.slice(0, -1);
    while (url.endsWith(")") && P().count(url, "(") < P().count(url, ")")) url = url.slice(0, -1);
    return url;
  }

  function keep(url) {
    var lowered = P().strip(url).toLowerCase();
    if (!lowered || lowered[0] === "#") return false;
    return !K()._SKIP_SCHEMES.some(function (scheme) {
      return lowered.slice(0, scheme.length) === scheme;
    });
  }

  function LinkCollector() {
    this.links = [];
    this.href = null;
    this.text = [];
    this.skipDepth = 0;
  }

  LinkCollector.prototype.flush = function () {
    var href = this.href || "";
    var text = P().joinWords(this.text.join(" "));
    if (href) this.links.push([href, text]);
    this.href = null;
    this.text = [];
  };

  LinkCollector.prototype.handlers = function () {
    var self = this;
    return {
      starttag: function (tag, attrs) {
        var attributes = new Map();
        attrs.forEach(function (pair) {
          attributes.set(pair[0].toLowerCase(), pair[1] || "");
        });
        if (tag === "script" || tag === "style") {
          self.skipDepth += 1;
          return;
        }
        if (tag === "a" || tag === "area") {
          if (self.href !== null) self.flush();
          self.href = P().strip(attributes.get("href") || "");
          self.text = [];
        } else if (tag === "form") {
          var action = P().strip(attributes.get("action") || "");
          if (action) self.links.push([action, ""]);
        } else if (tag === "iframe") {
          var src = P().strip(attributes.get("src") || "");
          if (src) self.links.push([src, ""]);
        }
      },
      endtag: function (tag) {
        if (tag === "script" || tag === "style") {
          self.skipDepth = Math.max(0, self.skipDepth - 1);
        } else if ((tag === "a" || tag === "area") && self.href !== null) {
          self.flush();
        }
      },
      data: function (data) {
        if (self.href !== null && !self.skipDepth) self.text.push(data);
      },
    };
  };

  function extractUrls(text, html) {
    var found = new Map();
    var add = function (url, anchor) {
      var cleaned = P().strip(MT.html.unescape(url));
      if (!keep(cleaned)) return;
      var key = normalizeUrl(cleaned);
      if (!key) return;
      if (found.has(key)) {
        var existing = found.get(key);
        if (!existing[1] && anchor) found.set(key, [existing[0], anchor]);
        return;
      }
      found.set(key, [cleaned, anchor]);
    };
    if (html) {
      var collector = new LinkCollector();
      var parser = new MT.html.Parser(collector.handlers());
      try {
        parser.feed(html);
        parser.close();
      } catch (error) {
        if (MT.trace) MT.trace(error);
      }
      if (collector.href !== null) collector.flush();
      collector.links.forEach(function (pair) {
        add(pair[0], pair[1]);
      });
      var stripped = MT.RX("link_analyzer", "_TAG_RE").sub(" ", html);
      MT.RX("link_analyzer", "_TEXT_URL_RE")
        .finditer(stripped)
        .forEach(function (match) {
          add(cleanTextUrl(match[0]), "");
        });
    }
    if (text) {
      MT.RX("link_analyzer", "_TEXT_URL_RE")
        .finditer(text)
        .forEach(function (match) {
          add(cleanTextUrl(match[0]), "");
        });
    }
    return Array.from(found.values()).slice(0, K()._MAX_URLS);
  }

  function finding(id, severity, title, detail, evidence) {
    return { id: id, module: "urls", severity: severity, title: title, detail: detail, evidence: evidence };
  }

  function uniqueValues(list) {
    return P().unique(list);
  }

  function analyzeUrls(parsed, cfg) {
    var pairs = extractUrls(parsed.text_body || "", parsed.html_body || "");
    var urls = [];
    pairs.forEach(function (pair) {
      try {
        urls.push(analyzeUrl(pair[0], pair[1], cfg));
      } catch (error) {
        if (MT.trace) MT.trace(error);
      }
    });
    var uniqueDomains = [];
    urls.forEach(function (u) {
      if (u.registrable_domain && uniqueDomains.indexOf(u.registrable_domain) < 0) uniqueDomains.push(u.registrable_domain);
    });
    var riskValue = K()._RISK_VALUE;
    var severe = urls.filter(function (u) {
      return SEVERITY_ORDER[u.risk] >= SEVERITY_ORDER.high;
    });
    var top = 0;
    urls.forEach(function (u) {
      top = Math.max(top, riskValue.get(u.risk));
    });
    var score = Math.min(1, top + 0.05 * Math.max(0, severe.length - 1));

    var findings = [];
    var org = orgDomains(cfg);
    var legit = legitDomains();
    var where = function (predicate) {
      return urls.filter(predicate);
    };
    var evidenceFor = function (items) {
      return {
        urls: items.slice(0, 8).map(function (u) {
          return P().slice(u.url, 0, 300);
        }),
        count: items.length,
      };
    };
    var withExtra = function (base, extra) {
      Object.keys(extra).forEach(function (key) {
        base[key] = extra[key];
      });
      return base;
    };

    var harvest = where(function (u) {
      return (
        u.suspicious_keywords.some(function (kw) {
          return K()._CREDENTIAL_KEYWORDS.has(kw);
        }) &&
        SEVERITY_ORDER[u.risk] >= SEVERITY_ORDER.medium &&
        !legit.has(u.registrable_domain) &&
        !org.has(u.registrable_domain)
      );
    });
    if (harvest.length) {
      var hosts = uniqueValues(
        harvest.slice(0, 3).map(function (u) {
          return u.host;
        }),
      ).join(", ");
      findings.push(
        finding(
          "credential_harvest_link",
          "high",
          "Credential-harvest link",
          harvest.length + " link(s) lead to login/verification pages on non-brand hosts (" + hosts + ").",
          evidenceFor(harvest),
        ),
      );
    }
    var lookalikes = where(function (u) {
      return Boolean(u.lookalike_of);
    });
    if (lookalikes.length) {
      var imitated = uniqueValues(
        lookalikes.map(function (u) {
          return u.lookalike_of;
        }),
      ).join(", ");
      var sev = lookalikes.some(function (u) {
        return org.has(u.lookalike_of);
      })
        ? "critical"
        : "high";
      findings.push(
        finding(
          "lookalike_domain_link",
          sev,
          "Link to a lookalike domain",
          "Link host(s) imitate " +
            imitated +
            ": " +
            uniqueValues(
              lookalikes.slice(0, 3).map(function (u) {
                return u.host;
              }),
            ).join(", ") +
            ".",
          withExtra(evidenceFor(lookalikes), { imitated: imitated }),
        ),
      );
    }
    var mismatched = where(function (u) {
      return u.anchor_mismatch;
    });
    if (mismatched.length) {
      var sample = mismatched[0];
      findings.push(
        finding(
          "anchor_href_mismatch",
          "high",
          "Visible link text differs from real destination",
          "The text '" + P().slice(sample.anchor_text, 0, 80) + "' opens " + sample.host + " instead of the site it displays.",
          withExtra(evidenceFor(mismatched), { anchor_text: P().slice(sample.anchor_text, 0, 120) }),
        ),
      );
    }
    var ipLinks = where(function (u) {
      return u.is_ip_literal;
    });
    if (ipLinks.length) {
      findings.push(
        finding(
          "ip_literal_link",
          "high",
          "Link to a raw IP address",
          ipLinks.length + " link(s) use an IP address instead of a domain, which bypasses domain reputation.",
          evidenceFor(ipLinks),
        ),
      );
    }
    var shorteners = where(function (u) {
      return u.is_shortener;
    });
    if (shorteners.length) {
      findings.push(
        finding(
          "url_shortener",
          "medium",
          "Shortened link hides destination",
          shorteners.length +
            " link(s) go through URL shorteners (" +
            uniqueValues(
              shorteners.slice(0, 3).map(function (u) {
                return u.registrable_domain;
              }),
            ).join(", ") +
            ").",
          evidenceFor(shorteners),
        ),
      );
    }
    var puny = where(function (u) {
      return u.is_punycode;
    });
    if (puny.length) {
      findings.push(
        finding(
          "punycode_url",
          "high",
          "Internationalised domain in link",
          "Punycode hosts render as familiar-looking Unicode names and are a classic homograph technique.",
          evidenceFor(puny),
        ),
      );
    }
    var userinfoLinks = where(function (u) {
      return u.has_userinfo;
    });
    if (userinfoLinks.length) {
      findings.push(
        finding(
          "userinfo_trick",
          "high",
          "Decoy text before '@' in link",
          "The part before '@' is ignored by browsers; the real host is the one after it.",
          evidenceFor(userinfoLinks),
        ),
      );
    }
    var redirects = where(function (u) {
      return u.obfuscation.indexOf("redirect_parameter") >= 0;
    });
    if (redirects.length) {
      findings.push(
        finding(
          "open_redirect",
          "high",
          "Redirect parameter in link",
          "The link bounces through a redirect parameter, so the visible host is not the final destination.",
          evidenceFor(redirects),
        ),
      );
    }
    var executables = where(function (u) {
      return u.obfuscation.indexOf("file_extension_executable") >= 0;
    });
    if (executables.length) {
      findings.push(
        finding(
          "executable_link",
          "critical",
          "Link downloads an executable",
          executables.length + " link(s) point directly at executable or script files.",
          evidenceFor(executables),
        ),
      );
    }
    var badTld = where(function (u) {
      return u.obfuscation.indexOf("suspicious_tld") >= 0;
    });
    if (badTld.length) {
      findings.push(
        finding(
          "suspicious_tld_link",
          "medium",
          "Link on an abuse-prone TLD",
          "Top-level domains used: " +
            uniqueValues(
              badTld.slice(0, 4).map(function (u) {
                return "." + u.tld;
              }),
            ).join(", ") +
            ".",
          evidenceFor(badTld),
        ),
      );
    }
    var dataUris = where(function (u) {
      return u.obfuscation.indexOf("data_uri") >= 0 || u.obfuscation.indexOf("javascript_uri") >= 0;
    });
    if (dataUris.length) {
      findings.push(
        finding(
          "data_uri",
          "high",
          "Inline data/script URI",
          "Links embed their payload (data:) or run script (javascript:) rather than opening a web page.",
          evidenceFor(dataUris),
        ),
      );
    }
    var plain = ["redirect_parameter", "file_extension_executable", "suspicious_tld", "data_uri", "javascript_uri"];
    var otherObfuscated = where(function (u) {
      return u.obfuscation.some(function (o) {
        return plain.indexOf(o) < 0;
      });
    });
    if (otherObfuscated.length) {
      var techniques = new Set();
      otherObfuscated.forEach(function (u) {
        u.obfuscation.forEach(function (o) {
          techniques.add(o);
        });
      });
      var sortedTechniques = P().sorted(Array.from(techniques));
      var heavy = otherObfuscated.some(function (u) {
        return u.obfuscation.length >= 3;
      });
      findings.push(
        finding(
          "obfuscated_url",
          heavy ? "high" : "medium",
          "Obfuscated link structure",
          "Techniques observed: " + sortedTechniques.join(", ") + ".",
          withExtra(evidenceFor(otherObfuscated), { techniques: sortedTechniques }),
        ),
      );
    }
    if (urls.length) {
      findings.push(
        finding(
          "link_inventory",
          "info",
          "Link inventory",
          urls.length + " link(s) across " + uniqueDomains.length + " domain(s): " + uniqueDomains.slice(0, 6).join(", ") + ".",
          {
            count: urls.length,
            domains: uniqueDomains,
            urls: urls.slice(0, 20).map(function (u) {
              return P().slice(u.url, 0, 300);
            }),
          },
        ),
      );
    }
    return { urls: urls, unique_domains: uniqueDomains, score: score, findings: findings };
  }

  MT.urls = {
    ValueError: ValueError,
    urlsplit: urlsplit,
    urlunsplit: urlunsplit,
    unquote: unquote,
    unquotePlus: unquotePlus,
    parseQsl: parseQsl,
    lenientNetloc: lenientNetloc,
    extract: extract,
    suffixIndex: suffixIndex,
    registrableDomain: registrableDomain,
    normalizeUrl: normalizeUrl,
    damerauLevenshtein: damerauLevenshtein,
    isLookalike: isLookalike,
    analyzeUrl: analyzeUrl,
    analyzeUrls: analyzeUrls,
    extractUrls: extractUrls,
    legitDomains: legitDomains,
    orgDomains: orgDomains,
    isIp: isIp,
    SEVERITY_ORDER: SEVERITY_ORDER,
  };
})(MT);
