"use strict";

const { load, fixture, Report, differences } = require("./harness");

function attempt(call) {
  try {
    return { ok: call() };
  } catch (error) {
    return { error: error.name || "Error" };
  }
}

function same(actual, expected) {
  if (expected.error) return Boolean(actual.error);
  return !actual.error && JSON.stringify(actual.ok) === JSON.stringify(expected.ok);
}

function run(filter) {
  const MT = load();
  const vectors = fixture("url_vectors.json");
  const config = fixture("expected.json").config;
  const reports = [];

  if (!filter || filter === "ips") {
    const ips = new Report("ipaddress like Python");
    for (const item of vectors.ips) {
      const label = JSON.stringify(item.text);
      if (item.network) {
        const actual = attempt(() => MT.net.ipNetwork(item.text));
        if (item.error) {
          ips.ok(Boolean(actual.error), `network ${label}: expected an error, got ${JSON.stringify(actual)}`);
          continue;
        }
        if (!ips.ok(!actual.error, `network ${label}: unexpected ${actual.error}`)) continue;
        ips.equal(actual.ok.toString(), item.str, `network text ${label}`);
        const contains = ["10.1.2.3", "1.2.3.200", "1.2.4.1", "2001:db8::5", "2001:db9::1", "::"].filter((probe) => {
          const address = MT.net.ipAddress(probe);
          return address.version === actual.ok.version && actual.ok.contains(address);
        });
        ips.equal(contains, item.contains, `network membership ${label}`);
        continue;
      }
      const parsed = attempt(() => MT.net.ipAddress(item.text));
      if (item.error) {
        ips.ok(Boolean(parsed.error), `address ${label}: expected an error, got ${JSON.stringify(parsed.ok && parsed.ok.toString())}`);
        continue;
      }
      if (!ips.ok(!parsed.error, `address ${label}: unexpected ${parsed.error}`)) continue;
      const address = parsed.ok;
      ips.equal(address.toString(), item.str, `address text ${label}`);
      ips.equal(address.version, item.version, `address version ${label}`);
      const props = {
        private: MT.net.isPrivate(address),
        loopback: MT.net.isLoopback(address),
        link_local: MT.net.isLinkLocal(address),
        multicast: MT.net.isMulticast(address),
        reserved: MT.net.isReserved(address),
        unspecified: MT.net.isUnspecified(address),
        site_local: MT.net.isSiteLocal(address),
        mapped: address.version === 6 && address.ipv4Mapped() ? address.ipv4Mapped().toString() : null,
        sixtofour: address.version === 6 && address.sixToFour() ? address.sixToFour().toString() : null,
        shared: MT.net.isShared(address),
      };
      ips.equal(props, item.props, `address properties ${label}`);
    }
    reports.push(ips);
  }

  if (!filter || filter === "split") {
    const split = new Report("urlsplit and normalize_url like Python");
    for (const item of vectors.split) {
      const label = JSON.stringify(item.url).slice(0, 140);
      const parts = attempt(() => MT.urls.urlsplit(item.url));
      if (item.error) {
        split.ok(Boolean(parts.error), `urlsplit ${label}: expected ValueError, got ${JSON.stringify(parts.ok)}`);
        continue;
      }
      if (!split.ok(!parts.error, `urlsplit ${label}: unexpected ${parts.error}`)) continue;
      const result = parts.ok;
      split.equal([result.scheme, result.netloc, result.path, result.query, result.fragment], item.parts, `parts ${label}`);
      split.equal(result.hostname(), item.hostname, `hostname ${label}`);
      split.ok(same(attempt(() => result.port()), item.port), `port ${label}: expected ${JSON.stringify(item.port)}`);
      split.equal(result.userInfo(), [item.username, item.password], `userinfo ${label}`);
      split.equal(MT.urls.normalizeUrl(item.url), item.normalized, `normalize ${label}`);
      split.equal(MT.urls.parseQsl(result.query, true), item.qsl, `parse_qsl ${label}`);
      split.equal(MT.urls.unquote(result.path), item.unquoted, `unquote ${label}`);
      split.equal(MT.urls.lenientNetloc(item.url), item.lenient_netloc, `lenient_netloc ${label}`);
    }
    reports.push(split);
  }

  if (!filter || filter === "hosts") {
    const hosts = new Report("registrable domains and lookalikes like Python");
    for (const item of vectors.hosts) {
      const label = JSON.stringify(item.host).slice(0, 120);
      hosts.equal(MT.urls.registrableDomain(item.host), item.registrable, `registrable_domain ${label}`);
      if (item.extract) {
        const ext = attempt(() => MT.urls.extract(item.host));
        hosts.ok(!ext.error && JSON.stringify([ext.ok.subdomain, ext.ok.domain, ext.ok.suffix]) === JSON.stringify(item.extract), `tldextract ${label}: expected ${JSON.stringify(item.extract)} got ${JSON.stringify(ext)}`);
      }
      hosts.equal(MT.urls.isLookalike(item.host, config), item.lookalike, `is_lookalike ${label}`);
    }
    reports.push(hosts);
  }

  if (!filter || filter === "analyze") {
    const analyze = new Report("analyze_url like Python");
    for (const item of vectors.analyze) {
      const label = JSON.stringify(item.url).slice(0, 120);
      const actual = attempt(() => MT.urls.analyzeUrl(item.url, item.anchor, config));
      if (item.error) {
        analyze.ok(Boolean(actual.error), `analyze_url ${label}: expected an error, got ${JSON.stringify(actual.ok || actual.error).slice(0, 200)}`);
        continue;
      }
      if (!analyze.ok(!actual.error, `analyze_url ${label}: unexpected ${actual.error}`)) continue;
      const found = differences(actual.ok, item.info, 0, "", [], 5);
      analyze.ok(found.length === 0, `analyze_url ${label} anchor ${JSON.stringify(item.anchor)}:\n      ${found.join("\n      ")}`);
    }
    reports.push(analyze);
  }

  if (!filter || filter === "distances") {
    const distances = new Report("damerau_levenshtein like Python");
    for (const item of vectors.distances) {
      distances.equal(MT.urls.damerauLevenshtein(item[0], item[1]), item[2], `distance ${JSON.stringify(item[0])} ${JSON.stringify(item[1])}`);
    }
    reports.push(distances);
  }

  return reports.map((report) => report.finish(10)).every(Boolean);
}

if (require.main === module) process.exit(run(process.argv[2]) ? 0 : 1);

module.exports = { run };
