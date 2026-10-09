var MT = MT || {};

(function (MT) {
  var TWO32 = 4294967296;

  function AddressValueError(message) {
    this.name = "AddressValueError";
    this.message = message;
  }
  AddressValueError.prototype = Object.create(Error.prototype);

  function isDigits(text) {
    return /^[0-9]+$/.test(text);
  }

  function parseOctet(text) {
    if (!text) throw new AddressValueError("Empty octet not permitted");
    if (!isDigits(text)) throw new AddressValueError("Only decimal digits permitted in " + text);
    if (text.length > 3) throw new AddressValueError("At most 3 characters permitted in " + text);
    if (text !== "0" && text[0] === "0") throw new AddressValueError("Leading zeros are not permitted in " + text);
    var value = Number(text);
    if (value > 255) throw new AddressValueError("Octet " + value + " (> 255) not permitted");
    return value;
  }

  function v4FromString(text) {
    if (!text) throw new AddressValueError("Address cannot be empty");
    var octets = text.split(".");
    if (octets.length !== 4) throw new AddressValueError("Expected 4 octets in " + text);
    var value = 0;
    for (var i = 0; i < 4; i += 1) value = value * 256 + parseOctet(octets[i]);
    return value;
  }

  function v4ToString(value) {
    return [Math.floor(value / 16777216) & 255, Math.floor(value / 65536) & 255, Math.floor(value / 256) & 255, value & 255].join(".");
  }

  function parseHextet(text) {
    if (!/^[0-9A-Fa-f]*$/.test(text)) throw new AddressValueError("Only hex digits permitted in " + text);
    if (text.length > 4) throw new AddressValueError("At most 4 characters permitted in " + text);
    return parseInt(text || "0", 16);
  }

  function v6FromString(text) {
    if (!text) throw new AddressValueError("Address cannot be empty");
    if (text.length > 45) throw new AddressValueError("At most 45 characters expected");
    var parts = MT.py.split(text, ":", 9);
    if (parts.length < 3) throw new AddressValueError("At least 3 parts expected in " + text);
    if (parts[parts.length - 1].indexOf(".") >= 0) {
      var last = parts.pop();
      var ipv4 = v4FromString(last);
      parts.push((Math.floor(ipv4 / 65536) & 0xffff).toString(16));
      parts.push((ipv4 & 0xffff).toString(16));
    }
    if (parts.length > 9) throw new AddressValueError("At most 8 colons permitted in " + text);
    var skip = null;
    for (var i = 1; i < parts.length - 1; i += 1) {
      if (!parts[i]) {
        if (skip !== null) throw new AddressValueError("At most one '::' permitted in " + text);
        skip = i;
      }
    }
    var high;
    var low;
    var skipped;
    if (skip !== null) {
      high = skip;
      low = parts.length - skip - 1;
      if (!parts[0]) {
        high -= 1;
        if (high) throw new AddressValueError("Leading ':' only permitted as part of '::' in " + text);
      }
      if (!parts[parts.length - 1]) {
        low -= 1;
        if (low) throw new AddressValueError("Trailing ':' only permitted as part of '::' in " + text);
      }
      skipped = 8 - (high + low);
      if (skipped < 1) throw new AddressValueError("Expected at most 7 other parts with '::' in " + text);
    } else {
      if (parts.length !== 8) throw new AddressValueError("Exactly 8 parts expected without '::' in " + text);
      if (!parts[0]) throw new AddressValueError("Leading ':' only permitted as part of '::' in " + text);
      if (!parts[parts.length - 1]) throw new AddressValueError("Trailing ':' only permitted as part of '::' in " + text);
      high = parts.length;
      low = 0;
      skipped = 0;
    }
    var hextets = [];
    var k;
    for (k = 0; k < high; k += 1) hextets.push(parseHextet(parts[k]));
    for (k = 0; k < skipped; k += 1) hextets.push(0);
    for (k = parts.length - low; k < parts.length; k += 1) hextets.push(parseHextet(parts[k]));
    return hextets;
  }

  function compressHextets(hextets) {
    var bestStart = -1;
    var bestLength = 0;
    var start = -1;
    var length = 0;
    var index;
    for (index = 0; index < hextets.length; index += 1) {
      if (hextets[index] === "0") {
        length += 1;
        if (start === -1) start = index;
        if (length > bestLength) {
          bestLength = length;
          bestStart = start;
        }
      } else {
        length = 0;
        start = -1;
      }
    }
    if (bestLength > 1) {
      var end = bestStart + bestLength;
      var list = hextets.slice();
      if (end === list.length) list.push("");
      list.splice(bestStart, bestLength, "");
      if (bestStart === 0) list.unshift("");
      return list;
    }
    return hextets;
  }

  function v6ToString(hextets) {
    var text = hextets.map(function (value) {
      return value.toString(16);
    });
    return compressHextets(text).join(":");
  }

  function IPv4(value) {
    this.version = 4;
    this.value = value;
  }

  IPv4.prototype.toString = function () {
    return v4ToString(this.value);
  };

  IPv4.prototype.inNetwork = function (network) {
    if (network.version !== 4) return false;
    var mask = network.prefix === 0 ? 0 : Math.floor(this.value / Math.pow(2, 32 - network.prefix));
    return mask === network.base;
  };

  IPv4.prototype.equals = function (other) {
    return other.version === 4 && other.value === this.value;
  };

  function IPv6(hextets, scope) {
    this.version = 6;
    this.hextets = hextets;
    this.scope = scope === undefined ? null : scope;
  }

  IPv6.prototype.ipv4Mapped = function () {
    for (var i = 0; i < 5; i += 1) if (this.hextets[i] !== 0) return null;
    if (this.hextets[5] !== 0xffff) return null;
    return new IPv4(this.hextets[6] * 65536 + this.hextets[7]);
  };

  IPv6.prototype.sixToFour = function () {
    if (this.hextets[0] !== 0x2002) return null;
    return new IPv4(this.hextets[1] * 65536 + this.hextets[2]);
  };

  IPv6.prototype.toString = function () {
    var mapped = this.ipv4Mapped();
    var text;
    if (mapped === null) {
      text = v6ToString(this.hextets);
    } else {
      text = v6ToString(this.hextets.slice(0, 6).concat([0, 0]));
      var cut = text.lastIndexOf(":");
      var head = v6ToString([0, 0, 0, 0, 0, 0xffff]);
      text = head + ":" + mapped.toString();
      void cut;
    }
    return this.scope ? text + "%" + this.scope : text;
  };

  IPv6.prototype.bits = function () {
    var out = [];
    for (var i = 0; i < 8; i += 1) {
      for (var b = 15; b >= 0; b -= 1) out.push((this.hextets[i] >> b) & 1);
    }
    return out;
  };

  IPv6.prototype.inNetwork = function (network) {
    if (network.version !== 6) return false;
    var mine = this.bits();
    var base = network.baseBits;
    for (var i = 0; i < network.prefix; i += 1) if (mine[i] !== base[i]) return false;
    return true;
  };

  IPv6.prototype.equals = function (other) {
    if (other.version !== 6) return false;
    for (var i = 0; i < 8; i += 1) if (other.hextets[i] !== this.hextets[i]) return false;
    return other.scope === this.scope;
  };

  function splitScope(text) {
    var parts = MT.py.partition(text, "%");
    if (!parts[1]) return [text, null];
    if (!parts[2] || parts[2].indexOf("%") >= 0) throw new AddressValueError("Invalid IPv6 address: " + text);
    return [parts[0], parts[2]];
  }

  function ipAddress(text) {
    var value = String(text);
    try {
      return new IPv4(v4FromString(value));
    } catch (error) {
      if (!(error instanceof AddressValueError)) throw error;
    }
    if (value.indexOf("/") >= 0) throw new AddressValueError("Unexpected '/' in " + value);
    var pieces = splitScope(value);
    return new IPv6(v6FromString(pieces[0]), pieces[1]);
  }

  function tryAddress(text) {
    try {
      return ipAddress(text);
    } catch (error) {
      if (error instanceof AddressValueError) return null;
      throw error;
    }
  }

  function prefixFromString(text, maximum) {
    if (!/^[0-9]+$/.test(text)) throw new AddressValueError(text + " is not a valid netmask");
    var value = Number(text);
    if (value < 0 || value > maximum) throw new AddressValueError(text + " is not a valid netmask");
    return value;
  }

  function prefixFromV4Mask(text) {
    var value;
    try {
      value = v4FromString(text);
    } catch (error) {
      throw new AddressValueError(text + " is not a valid netmask");
    }
    var attempts = [value, TWO32 - 1 - value];
    for (var i = 0; i < attempts.length; i += 1) {
      var candidate = attempts[i];
      var zeros = 0;
      while (zeros < 32 && candidate % 2 === 0) {
        candidate = Math.floor(candidate / 2);
        zeros += 1;
      }
      var prefix = 32 - zeros;
      var ones = Math.pow(2, prefix) - 1;
      if (candidate === ones) return prefix;
    }
    throw new AddressValueError(text + " is not a valid netmask");
  }

  function Network(address, prefix) {
    this.version = address.version;
    this.prefix = prefix;
    if (address.version === 4) {
      this.base = prefix === 0 ? 0 : Math.floor(address.value / Math.pow(2, 32 - prefix));
      this.address = new IPv4(prefix === 0 ? 0 : this.base * Math.pow(2, 32 - prefix));
    } else {
      var bits = address.bits();
      this.baseBits = bits.map(function (bit, index) {
        return index < prefix ? bit : 0;
      });
      var hextets = [];
      for (var i = 0; i < 8; i += 1) {
        var value = 0;
        for (var b = 0; b < 16; b += 1) value = value * 2 + this.baseBits[i * 16 + b];
        hextets.push(value);
      }
      this.address = new IPv6(hextets, null);
    }
  }

  Network.prototype.contains = function (address) {
    return address.inNetwork(this);
  };

  Network.prototype.toString = function () {
    return this.address.toString() + "/" + this.prefix;
  };

  function ipNetwork(text) {
    var value = String(text);
    var pieces = value.split("/");
    if (pieces.length > 2) throw new AddressValueError("Only one '/' permitted in " + value);
    var address = null;
    var prefix;
    try {
      address = new IPv4(v4FromString(pieces[0]));
      prefix = 32;
      if (pieces.length === 2) {
        try {
          prefix = prefixFromString(pieces[1], 32);
        } catch (error) {
          prefix = prefixFromV4Mask(pieces[1]);
        }
      }
      return new Network(address, prefix);
    } catch (error) {
      if (!(error instanceof AddressValueError)) throw error;
      if (address !== null) throw error;
    }
    var scoped = splitScope(pieces[0]);
    if (scoped[1] !== null) throw new AddressValueError("scoped networks are not supported");
    address = new IPv6(v6FromString(pieces[0]), null);
    prefix = pieces.length === 2 ? prefixFromString(pieces[1], 128) : 128;
    return new Network(address, prefix);
  }

  var networks = null;

  function tables() {
    if (networks) return networks;
    var n = function (list) {
      return list.map(ipNetwork);
    };
    networks = {
      v4Private: n([
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
        "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "240.0.0.0/4", "255.255.255.255/32",
      ]),
      v4PrivateExceptions: n(["192.0.0.9/32", "192.0.0.10/32"]),
      v4Loopback: ipNetwork("127.0.0.0/8"),
      v4LinkLocal: ipNetwork("169.254.0.0/16"),
      v4Multicast: ipNetwork("224.0.0.0/4"),
      v4Reserved: ipNetwork("240.0.0.0/4"),
      v4Shared: ipNetwork("100.64.0.0/10"),
      v6Private: n([
        "::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
        "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10",
      ]),
      v6PrivateExceptions: n(["2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48", "2001:20::/28", "2001:30::/28"]),
      v6Reserved: n([
        "::/8", "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "4000::/3", "6000::/3", "8000::/3",
        "A000::/3", "C000::/3", "E000::/4", "F000::/5", "F800::/6", "FE00::/9",
      ]),
      v6LinkLocal: ipNetwork("fe80::/10"),
      v6SiteLocal: ipNetwork("fec0::/10"),
      v6Multicast: ipNetwork("ff00::/8"),
    };
    return networks;
  }

  function anyOf(address, list) {
    for (var i = 0; i < list.length; i += 1) if (address.inNetwork(list[i])) return true;
    return false;
  }

  function isPrivate(address) {
    var t = tables();
    if (address.version === 4) return anyOf(address, t.v4Private) && !anyOf(address, t.v4PrivateExceptions);
    var mapped = address.ipv4Mapped();
    if (mapped) return isPrivate(mapped);
    return anyOf(address, t.v6Private) && !anyOf(address, t.v6PrivateExceptions);
  }

  function isLoopback(address) {
    if (address.version === 4) return address.inNetwork(tables().v4Loopback);
    var mapped = address.ipv4Mapped();
    if (mapped) return isLoopback(mapped);
    return address.hextets.slice(0, 7).every(function (v) {
      return v === 0;
    }) && address.hextets[7] === 1;
  }

  function isLinkLocal(address) {
    if (address.version === 4) return address.inNetwork(tables().v4LinkLocal);
    var mapped = address.ipv4Mapped();
    if (mapped) return isLinkLocal(mapped);
    return address.inNetwork(tables().v6LinkLocal);
  }

  function isSiteLocal(address) {
    return address.version === 6 && address.inNetwork(tables().v6SiteLocal);
  }

  function isMulticast(address) {
    if (address.version === 4) return address.inNetwork(tables().v4Multicast);
    var mapped = address.ipv4Mapped();
    if (mapped) return isMulticast(mapped);
    return address.inNetwork(tables().v6Multicast);
  }

  function isReserved(address) {
    if (address.version === 4) return address.inNetwork(tables().v4Reserved);
    var mapped = address.ipv4Mapped();
    if (mapped) return isReserved(mapped);
    return anyOf(address, tables().v6Reserved);
  }

  function isUnspecified(address) {
    if (address.version === 4) return address.value === 0;
    var mapped = address.ipv4Mapped();
    if (mapped) return isUnspecified(mapped);
    return address.hextets.every(function (v) {
      return v === 0;
    });
  }

  function isShared(address) {
    return address.version === 4 && address.inNetwork(tables().v4Shared);
  }

  MT.net = {
    AddressValueError: AddressValueError,
    IPv4: IPv4,
    IPv6: IPv6,
    Network: Network,
    ipAddress: ipAddress,
    tryAddress: tryAddress,
    ipNetwork: ipNetwork,
    isPrivate: isPrivate,
    isLoopback: isLoopback,
    isLinkLocal: isLinkLocal,
    isSiteLocal: isSiteLocal,
    isMulticast: isMulticast,
    isReserved: isReserved,
    isUnspecified: isUnspecified,
    isShared: isShared,
  };
})(MT);
