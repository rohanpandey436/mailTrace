from __future__ import annotations

import ipaddress
import random
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from mime_cases import mutate

BS = chr(92)
HOSTS = [
    "example.com", "www.example.com", "EXAMPLE.COM.", "sub.domain.example.co.in", "example.co.in", "bbc.co.uk",
    "a.b.c.d.e.example.org", "localhost", "example", "192.168.1.1", "8.8.8.8", "[::1]", "::1", "2001:db8::1",
    "xn--p1ai", "xn--80ak6aa92e.com", "пример.рф", "xn--e1afmkfd.xn--p1ai", "café.example", "xn--caf-dma.example",
    "www.xn--pple-43d.com", "apple.com", "www.paypal.com", "paypa1.com", "paypal.com.evil.top", "sbi-online.co.in",
    "onlinesbi.sbi", "onlinesbi.com.verify.top", "hdfcbank.com", "hdfcbank.co", "hdfc-bank.com", "hdfcbnak.com",
    "microsoftonline-login.xyz", "rnicrosoft.com", "goog1e.com", "amaz0n.in", "acme-corp.in", "acme-corp-in.com",
    "acmecorp.in", "acme-corp.co", "mail.acme-corp.in", "acme-corp.in.evil.top", "acme-corp.zendesk.com",
    "github.io", "user.github.io", "blogspot.com", "myblog.blogspot.com", "s3.amazonaws.com", "bucket.s3.amazonaws.com",
    "city.kawasaki.jp", "www.city.kawasaki.jp", "foo.kawasaki.jp", "bar.foo.kawasaki.jp", "test.ck", "www.ck",
    "a.com", "1.2.3", "300.1.1.1", "0x7f000001", "017700000001", "1.2.3.4.5", "example.zip", "verify.example.top",
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "wa.me", "outlook.office365.com", "login.microsoftonline.com",
    "微软.中国", "xn--fiqs8s", "xn--0zwm56d.xn--fiqs8s", "उदाहरण.भारत", "xn--p1b6ci4b4b3a.xn--h2brj9c",
    "co.uk", "uk", "com", ".", "..", "a..b", "-", "a-.com", "-a.com", "a_b.com", "a b.com", "a" + chr(9) + "b.com",
    "example.com:8080", "user@example.com", "user:pass@example.com", "example.com/path", "example.com?q=1",
    "http://example.com", "https://EXAMPLE.com/x", "ftp://example.com", "//example.com", "mailto:a@example.com",
    "Example.Com", "www.Example.COM", "xn--", "xn--a", "xn--abc-", "XN--P1AI", "xn--p1ai.", "example.com.",
    "e.g.example.com", "a" * 64 + ".com", "a" * 63 + ".com", "sub." + "b" * 70 + ".example.com", "²", "٣٤", "1٢.3.4",
]
URLS = [
    "https://example.com", "http://example.com/", "HTTPS://EXAMPLE.COM/Path/To?Q=1#frag", "example.com/login",
    "www.example.com/verify?next=https://evil.top/", "https://example.com:443/x", "https://example.com:8443/x",
    "http://example.com:80/x", "http://example.com:0/x", "http://example.com:99999/x", "http://example.com:abc/x",
    "https://user:pass@example.com/", "https://paypal.com@evil.top/login", "https://paypal.com%40evil.top/",
    "http://192.168.1.1/admin", "http://8.8.8.8/", "http://0x7f000001/", "http://2130706433/", "http://017700000001/",
    "http://[::1]/", "http://[2001:db8::1]:8080/x", "http://[::1", "http://::1]/", "http://[1.2.3.4]/",
    "http://[v1.fe80::a]/", "http://[vX.y]/", "https://xn--pple-43d.com/", "https://аpple.com/", "https://例え.jp/",
    "https://sbi-online.verify.top/kyc", "https://onlinesbi.sbi/", "https://hdfcbank.com/netbanking",
    "https://hdfcbank.com.evil.xyz/login", "https://secure-login.microsoftonline-verify.top/owa/auth",
    "https://bit.ly/3abc", "https://t.co/x", "https://drive.google.com/file/d/1/view", "https://example.top/",
    "https://example.zip/", "https://example.com/file.exe", "https://example.com/setup.msi?x=1", "https://example.com/doc.pdf",
    "https://example.com/redirect?url=https://evil.top/", "https://example.com/r?next=//evil.top",
    "https://example.com/r?u=https%3A%2F%2Fevil.top%2F", "https://example.com/r?goto=https://example.com/home",
    "https://example.com/?q=aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=", "https://example.com/?q=SGVsbG8-d29ybGQ_",
    "https://example.com/a/b/c/d/e/f/g/h?" + "k=v&" * 30, "https://a.b.c.d.e.f.example.com/", "https://example.com/%41%42%43",
    "https://example.com/%e2%82%b9/%zz", "https://example.com/" + BS + "x41", "https://example.com/x" + chr(10) + "https://evil.top/",
    "javascript:alert(1)", "JAVASCRIPT:void(0)", "data:text/html;base64,PGI+", "mailto:a@example.com", "tel:+91",
    "#top", "", " ", "https://", "https:///path", "http:", "//example.com/x", "example.com", "EXAMPLE.COM/X",
    "https://example.com/../..//x", "https://example.com/?", "https://example.com/#", "https://example.com?x#y",
    "https://example.com/a?b=c&d=&e", "https://example.com/?a=1&a=2", "https://example.com/?%61=%62",
    "https://user@example.com/", "https://:pass@example.com/", "https://@example.com/", "https://example.com@/",
    "https://example.com./x", "https://example.com../x", "https://example.com%2F/x", "https://example.com" + BS + "evil.top",
    "https://example.com/path with spaces", "https://example.com/‽", "https://example.com/ñ", "https://éxample.com/",
    "https://ｅｘａｍｐｌｅ.com/", "https://example.com／x", "https://example.com｡x/", "https://xn--e1afmkfd.xn--p1ai/",
    "https://xn--zzz.com/", "https://xn--.com/", "https://xn--80ak6aa92e.com/", "http://[fe80::1%25eth0]/",
    "https://1.2.3/", "https://1.2.3.4.5/", "https://300.1.1.1/", "https://0.0.0.0/", "https://255.255.255.255/",
    "http://%2e%2e/", "https://acme-corp.in/", "https://acme-corp-in.com/", "https://acme-corp.zendesk.com/",
    "https://accounts.acme-corp.in.verify.top/", "https://acme-corp.in.evil.top/", "http://acmecorp.in/",
    "https://²/", "https://٣٤/", "https://1٢.3.4/", "https://example.com/?next=https://²/", "http://12345678901234567890/",
]
ANCHORS = ["", "click here", "https://www.paypal.com/", "www.sbi.co.in", "paypal.com", "example.com/login", "Sign in",
           "https://example.com", "http://google.com/", "acme-corp.in", "hdfcbank.com.evil.xyz", "rnicrosoft.com"]
IPS = [
    "1.2.3.4", "01.2.3.4", "1.2.3.04", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.4 ", " 1.2.3.4", "0.0.0.0",
    "255.255.255.255", "127.0.0.1", "10.0.0.1", "172.16.0.1", "172.32.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1",
    "100.127.255.255", "100.128.0.0", "192.0.0.1", "192.0.0.9", "192.0.0.10", "192.0.0.170", "192.0.0.171", "192.0.2.1",
    "198.18.0.1", "198.51.100.1", "203.0.113.5", "224.0.0.1", "240.0.0.1", "8.8.8.8", "1a.2.3.4", "１.2.3.4",
    "::", "::1", "::2", "fe80::1", "fec0::1", "fc00::1", "fd12::1", "ff02::1", "2001:db8::1", "2001::1", "2001:1::1",
    "2001:1::2", "2001:1::3", "2001:3::1", "2001:4:112::1", "2001:20::1", "2001:30::1", "2001:40::1", "2002:0808:0808::1",
    "64:ff9b:1::1", "64:ff9b::1", "100::1", "100:1::1", "3fff::1", "::ffff:8.8.8.8", "::ffff:10.0.0.1", "::ffff:192.0.2.1",
    "::ffff:c0a8:101", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", ":1", "1:", "1::2::3", "::1::", "1:2:3:4:5:6:1.2.3.4",
    "::1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4", "fe80::1%eth0", "fe80::1%", "fe80::1%a%b", "2001:DB8::1", "2001:db8:0:0:0:0:0:1",
    "2001:db8::0:0:1", "0:0:0:0:0:0:0:0", "1234567:1::", "g::1", "2001:db8::/32", "1.2.3.4/24", "", "abc", "::ffff:1.2.3.4.5",
    "A000::1", "8000::1", "4000::1", "2000::1", "3000::1", "e000::1", "f000::1", "f800::1", "fe00::1", "feff::1",
]
NETWORKS = ["10.0.0.0/8", "1.2.3.4/24", "1.2.3.4", "1.2.3.4/255.255.255.0", "1.2.3.4/0.0.0.255", "1.2.3.4/0.0.0.0",
            "1.2.3.4/255.255.255.255", "1.2.3.4/33", "1.2.3.4/-1", "1.2.3.4/255.0.255.0", "2001:db8::/32", "2001:db8::1/128",
            "2001:db8::1/129", "2001:db8::1/ffff::", "::/0", "1.2.3.4/24/1", "1.2.3.4/ 24", "1.2.3.4/+24"]
PROBES = ["10.1.2.3", "1.2.3.200", "1.2.4.1", "2001:db8::5", "2001:db9::1", "::"]


def attempt(call: Any) -> dict[str, Any]:
    try:
        return {"ok": call()}
    except Exception as exc:
        return {"error": type(exc).__name__}


def ip_vectors(rng: random.Random) -> list[dict[str, Any]]:
    inputs = list(IPS)
    for _ in range(2500):
        base = rng.choice(IPS).encode("utf-8")
        inputs.append(mutate(rng, base).decode("utf-8", errors="replace") if base else "")
    out = []
    seen: set[str] = set()
    for text in inputs:
        if text in seen:
            continue
        seen.add(text)
        entry: dict[str, Any] = {"text": text}
        try:
            addr = ipaddress.ip_address(text)
        except ValueError as exc:
            entry["error"] = type(exc).__name__
            out.append(entry)
            continue
        entry["str"] = str(addr)
        entry["version"] = addr.version
        entry["props"] = {
            "private": addr.is_private, "loopback": addr.is_loopback, "link_local": addr.is_link_local,
            "multicast": addr.is_multicast, "reserved": addr.is_reserved, "unspecified": addr.is_unspecified,
            "site_local": getattr(addr, "is_site_local", False),
            "mapped": str(addr.ipv4_mapped) if getattr(addr, "ipv4_mapped", None) is not None else None,
            "sixtofour": str(addr.sixtofour) if getattr(addr, "sixtofour", None) is not None else None,
            "shared": addr in ipaddress.ip_network("100.64.0.0/10"),
        }
        out.append(entry)
    for text in NETWORKS + [mutate(rng, rng.choice(NETWORKS).encode()).decode("utf-8", "replace") for _ in range(400)]:
        entry = {"network": True, "text": text}
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            entry["error"] = type(exc).__name__
        else:
            entry["str"] = str(net)
            entry["contains"] = [
                probe for probe in PROBES
                if ipaddress.ip_address(probe).version == net.version and ipaddress.ip_address(probe) in net
            ]
        out.append(entry)
    return out


def url_vectors(rng: random.Random, cfg: Any) -> dict[str, Any]:
    import tldextract

    from app.core import link_analyzer, parser
    from export_fixtures import collect

    urls = list(URLS)
    hosts = list(HOSTS)
    for _name, raw in collect():
        parsed, _ = parser.parse_email(raw)
        for url, _anchor in link_analyzer.extract_urls(parsed.text_body or "", parsed.html_body or ""):
            urls.append(url)
            host = urlsplit(link_analyzer.normalize_url(url)).hostname or ""
            if host:
                hosts.append(host)
    base_urls = list(urls)
    base_hosts = list(hosts)
    for _ in range(3000):
        urls.append(mutate(rng, rng.choice(base_urls).encode("utf-8")).decode("utf-8", errors="replace"))
    for _ in range(2500):
        hosts.append(mutate(rng, rng.choice(base_hosts).encode("utf-8")).decode("utf-8", errors="replace"))

    split_cases = []
    for url in dict.fromkeys(urls):
        entry: dict[str, Any] = {"url": url}
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            entry["error"] = type(exc).__name__
            split_cases.append(entry)
            continue
        entry["parts"] = [parts.scheme, parts.netloc, parts.path, parts.query, parts.fragment]
        entry["hostname"] = parts.hostname
        entry["port"] = attempt(lambda: parts.port)
        entry["username"] = parts.username
        entry["password"] = parts.password
        entry["normalized"] = link_analyzer.normalize_url(url)
        entry["qsl"] = [list(pair) for pair in parse_qsl(parts.query, keep_blank_values=True)]
        entry["unquoted"] = unquote(parts.path)
        entry["lenient_netloc"] = tldextract.remote.lenient_netloc(url)
        split_cases.append(entry)

    host_cases = []
    extractor = link_analyzer._EXTRACTOR
    for host in dict.fromkeys(hosts):
        entry = {"host": host, "registrable": link_analyzer.registrable_domain(host)}
        try:
            ext = extractor(host)
            entry["extract"] = [ext.subdomain, ext.domain, ext.suffix]
        except Exception as exc:
            entry["extract_error"] = type(exc).__name__
        entry["lookalike"] = list(link_analyzer.is_lookalike(host, cfg))
        host_cases.append(entry)

    analyze_cases = []
    for url in dict.fromkeys(urls):
        anchor = rng.choice(ANCHORS)
        entry = {"url": url, "anchor": anchor}
        try:
            entry["info"] = link_analyzer.analyze_url(url, anchor, cfg).model_dump(mode="json")
        except Exception as exc:
            entry["error"] = type(exc).__name__
        analyze_cases.append(entry)

    words = ["paypal", "paypa1", "pyapal", "payapl", "paypall", "aypal", "google", "goggle", "gogle", "amazon", "amazn",
             "microsoft", "rnicrosoft", "micros0ft", "sbi", "hdfc", "hdfcbank", "hdfcbnak", "acme-corp", "acmecorp", "",
             "a", "ab", "abc", "café", "cafe", "₹₹", "😀a", "a😀", "abcdefghij", "abcdefghji"]
    distances = [[a, b, link_analyzer.damerau_levenshtein(a, b)] for a in words for b in words]
    return {"split": split_cases, "hosts": host_cases, "analyze": analyze_cases, "distances": distances}


def build(rng: random.Random) -> dict[str, Any]:
    import tempfile
    from pathlib import Path

    from export_fixtures import settings

    cfg = settings(Path(tempfile.mkdtemp(prefix="mailtrace-urls-")))
    document = url_vectors(rng, cfg)
    document["ips"] = ip_vectors(rng)
    return document
