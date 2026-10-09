var MT = MT || {};

(function (MT) {
  var REPLACEMENT = 0xfffd;
  var BACKSLASH = 92;

  function DecodeError(message) {
    return new MT.codecs.DecodeError(message);
  }

  function fromCodes(codes) {
    if (codes.length < 8192) return String.fromCharCode.apply(null, codes);
    var parts = [];
    for (var i = 0; i < codes.length; i += 8192) parts.push(String.fromCharCode.apply(null, codes.slice(i, i + 8192)));
    return parts.join("");
  }

  function pushPoint(codes, point) {
    if (point > 0xffff) {
      var offset = point - 0x10000;
      codes.push(0xd800 + (offset >> 10), 0xdc00 + (offset & 0x3ff));
    } else {
      codes.push(point);
    }
  }

  function isBase64(ch) {
    return (ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122) || (ch >= 48 && ch <= 57) || ch === 43 || ch === 47;
  }

  function fromBase64(ch) {
    if (ch >= 65 && ch <= 90) return ch - 65;
    if (ch >= 97 && ch <= 122) return ch - 97 + 26;
    if (ch >= 48 && ch <= 57) return ch - 48 + 52;
    return ch === 43 ? 62 : 63;
  }

  function utf7(bytes, mode) {
    var out = [];
    var i = 0;
    var n = bytes.length;
    var inShift = false;
    var bits = 0;
    var buffer = 0;
    var surrogate = 0;

    function fail(end, message) {
      if (mode === "strict") throw DecodeError("utf7: " + message);
      out.push(REPLACEMENT);
      i = end;
    }

    while (i < n) {
      var ch = bytes[i];
      if (inShift) {
        if (isBase64(ch)) {
          buffer = (buffer << 6) | fromBase64(ch);
          bits += 6;
          i += 1;
          if (bits >= 16) {
            var unit = (buffer >> (bits - 16)) & 0xffff;
            bits -= 16;
            buffer &= (1 << bits) - 1;
            if (surrogate) {
              if (unit >= 0xdc00 && unit <= 0xdfff) {
                out.push(surrogate, unit);
                surrogate = 0;
                continue;
              }
              out.push(surrogate);
              surrogate = 0;
            }
            if (unit >= 0xd800 && unit <= 0xdbff) {
              surrogate = unit;
            } else {
              out.push(unit);
            }
          }
        } else {
          inShift = false;
          if (bits > 0) {
            if (bits >= 6) {
              i += 1;
              fail(i, "partial character in shift sequence");
              continue;
            }
            if (buffer !== 0) {
              i += 1;
              fail(i, "non-zero padding bits in shift sequence");
              continue;
            }
          }
          if (surrogate && ch <= 127 && ch !== 43) out.push(surrogate);
          surrogate = 0;
          if (ch === 45) i += 1;
        }
      } else if (ch === 43) {
        i += 1;
        if (i < n && bytes[i] === 45) {
          i += 1;
          out.push(43);
        } else if (i < n && !isBase64(bytes[i])) {
          i += 1;
          fail(i, "ill-formed sequence");
        } else {
          inShift = true;
          surrogate = 0;
          bits = 0;
          buffer = 0;
        }
      } else if (ch <= 127) {
        i += 1;
        out.push(ch);
      } else {
        i += 1;
        fail(i, "unexpected special character");
      }
    }
    if (inShift && (surrogate || bits >= 6 || (bits > 0 && buffer !== 0))) fail(n, "unterminated shift sequence");
    return fromCodes(out);
  }

  function isHex(code) {
    return (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102);
  }

  function hexValue(code) {
    if (code <= 57) return code - 48;
    if (code <= 70) return code - 55;
    return code - 87;
  }

  function unicodeEscape(bytes, mode, raw) {
    var out = [];
    var i = 0;
    var n = bytes.length;

    function fail(end, message) {
      if (mode === "strict") throw DecodeError((raw ? "rawunicodeescape: " : "unicodeescape: ") + message);
      out.push(REPLACEMENT);
      i = end;
    }

    while (i < n) {
      var c = bytes[i];
      i += 1;
      if (c !== BACKSLASH) {
        out.push(c);
        continue;
      }
      if (i >= n) {
        if (raw) {
          out.push(BACKSLASH);
          continue;
        }
        fail(n, "backslash at end of string");
        continue;
      }
      c = bytes[i];
      i += 1;
      var count = 0;
      if (c === 117) {
        count = 4;
      } else if (c === 85) {
        count = 8;
      } else if (raw) {
        out.push(BACKSLASH);
        if (c === BACKSLASH) {
          out.push(BACKSLASH);
        } else {
          i -= 1;
        }
        continue;
      } else if (c === 10) {
        continue;
      } else if (c === BACKSLASH || c === 39 || c === 34) {
        out.push(c);
        continue;
      } else if (c === 98) {
        out.push(8);
        continue;
      } else if (c === 102) {
        out.push(12);
        continue;
      } else if (c === 116) {
        out.push(9);
        continue;
      } else if (c === 110) {
        out.push(10);
        continue;
      } else if (c === 114) {
        out.push(13);
        continue;
      } else if (c === 118) {
        out.push(11);
        continue;
      } else if (c === 97) {
        out.push(7);
        continue;
      } else if (c >= 48 && c <= 55) {
        var octal = c - 48;
        if (i < n && bytes[i] >= 48 && bytes[i] <= 55) {
          octal = (octal << 3) + bytes[i] - 48;
          i += 1;
          if (i < n && bytes[i] >= 48 && bytes[i] <= 55) {
            octal = (octal << 3) + bytes[i] - 48;
            i += 1;
          }
        }
        pushPoint(out, octal);
        continue;
      } else if (c === 120) {
        count = 2;
      } else if (c === 78) {
        if (i < n && bytes[i] === 123) {
          var close = i + 1;
          while (close < n && bytes[close] !== 125) close += 1;
          if (close >= n) {
            fail(n, "malformed name escape");
            continue;
          }
          if (close > i + 1) {
            fail(close + 1, "unknown Unicode character name");
            continue;
          }
          fail(i + 1, "malformed name escape");
          continue;
        }
        fail(i, "malformed name escape");
        continue;
      } else {
        out.push(BACKSLASH);
        i -= 1;
        continue;
      }
      var value = 0;
      var digits = count;
      while (digits > 0 && i < n && isHex(bytes[i])) {
        value = value * 16 + hexValue(bytes[i]);
        i += 1;
        digits -= 1;
      }
      if (digits > 0) {
        fail(i, "truncated escape");
        continue;
      }
      if (value > 0x10ffff) {
        fail(i, "illegal Unicode character");
        continue;
      }
      pushPoint(out, value);
    }
    return fromCodes(out);
  }

  function toPoints(text) {
    var out = [];
    for (var i = 0; i < text.length; i += 1) {
      var point = text.codePointAt(i);
      if (point > 0xffff) i += 1;
      out.push(point);
    }
    return out;
  }

  function fromPoints(points) {
    var codes = [];
    points.forEach(function (point) {
      pushPoint(codes, point);
    });
    return fromCodes(codes);
  }

  function punyT(j, bias) {
    var res = 36 * (j + 1) - bias;
    if (res < 1) return 1;
    if (res > 26) return 26;
    return res;
  }

  function punyAdapt(delta, first, numchars) {
    delta = first ? Math.floor(delta / 700) : Math.floor(delta / 2);
    delta += Math.floor(delta / numchars);
    var divisions = 0;
    while (delta > 455) {
      delta = Math.floor(delta / 35);
      divisions += 36;
    }
    return divisions + Math.floor((36 * delta) / (delta + 38));
  }

  function generalizedNumber(extended, extpos, bias, mode) {
    var result = 0;
    var w = 1;
    var j = 0;
    for (;;) {
      if (extpos >= extended.length) {
        if (mode === "strict") throw DecodeError("punycode: incomplete punycode string");
        return [extpos + 1, null];
      }
      var ch = extended[extpos];
      extpos += 1;
      var digit;
      if (ch >= 0x41 && ch <= 0x5a) {
        digit = ch - 0x41;
      } else if (ch >= 0x30 && ch <= 0x39) {
        digit = ch - 22;
      } else if (mode === "strict") {
        throw DecodeError("punycode: Invalid extended code point");
      } else {
        return [extpos, null];
      }
      var t = punyT(j, bias);
      result += digit * w;
      if (digit < t) return [extpos, result];
      w *= 36 - t;
      j += 1;
    }
  }

  function insertionSort(base, extended, mode) {
    var ch = 0x80;
    var pos = -1;
    var bias = 72;
    var extpos = 0;
    while (extpos < extended.length) {
      var found = generalizedNumber(extended, extpos, bias, mode);
      var newpos = found[0];
      var delta = found[1];
      if (delta === null) return base;
      pos += delta + 1;
      ch += Math.floor(pos / (base.length + 1));
      if (ch > 0x10ffff) {
        if (mode === "strict") throw DecodeError("punycode: Invalid character");
        ch = 63;
      }
      pos = pos % (base.length + 1);
      base = base.slice(0, pos).concat([ch], base.slice(pos));
      bias = punyAdapt(delta, extpos === 0, base.length);
      extpos = newpos;
    }
    return base;
  }

  function punycodeDecode(bytes, mode) {
    var pos = -1;
    for (var k = bytes.length - 1; k >= 0; k -= 1) {
      if (bytes[k] === 45) {
        pos = k;
        break;
      }
    }
    var base = [];
    var extended;
    if (pos === -1) {
      extended = bytes;
    } else {
      for (var b = 0; b < pos; b += 1) {
        if (bytes[b] < 128) {
          base.push(bytes[b]);
        } else if (mode === "strict") {
          throw DecodeError("ascii: ordinal not in range(128)");
        } else if (mode === "replace") {
          base.push(REPLACEMENT);
        }
      }
      extended = bytes.subarray(pos + 1);
    }
    var upper = new Uint8Array(extended.length);
    for (var u = 0; u < extended.length; u += 1) {
      var code = extended[u];
      upper[u] = code >= 97 && code <= 122 ? code - 32 : code;
    }
    return fromPoints(insertionSort(base, upper, mode));
  }

  function punycodeEncode(text) {
    var points = toPoints(text);
    var base = [];
    var extendedSet = new Set();
    points.forEach(function (point) {
      if (point < 128) base.push(point);
      else extendedSet.add(point);
    });
    var extended = Array.from(extendedSet).sort(function (a, b) {
      return a - b;
    });
    var deltas = [];
    var oldchar = 0x80;
    var oldindex = -1;
    extended.forEach(function (ch) {
      var curlen = 0;
      points.forEach(function (point) {
        if (point < ch) curlen += 1;
      });
      var delta = (curlen + 1) * (ch - oldchar);
      var index = -1;
      var pos = -1;
      for (;;) {
        var next = -1;
        var nextIndex = index;
        var p = pos;
        for (;;) {
          p += 1;
          if (p === points.length) break;
          if (points[p] === ch) {
            next = p;
            nextIndex += 1;
            break;
          }
          if (points[p] < ch) nextIndex += 1;
        }
        if (next === -1) break;
        index = nextIndex;
        pos = next;
        delta += index - oldindex;
        deltas.push(delta - 1);
        oldindex = index;
        delta = 0;
      }
      oldchar = ch;
    });
    var digits = "abcdefghijklmnopqrstuvwxyz0123456789";
    var out = [];
    var bias = 72;
    deltas.forEach(function (delta, position) {
      var value = delta;
      var j = 0;
      for (;;) {
        var t = punyT(j, bias);
        if (value < t) {
          out.push(digits[value]);
          break;
        }
        out.push(digits[t + ((value - t) % (36 - t))]);
        value = Math.floor((value - t) / (36 - t));
        j += 1;
      }
      bias = punyAdapt(delta, position === 0, base.length + position + 1);
    });
    var prefix = fromCodes(base);
    return base.length ? prefix + "-" + out.join("") : out.join("");
  }

  function tables() {
    return MT.json("knowledge").stringprep;
  }

  function legacyNfkc(data, text) {
    var out = [];
    var run = [];
    var flush = function () {
      if (run.length) out.push(run.join("").normalize("NFKC"));
      run = [];
    };
    toPoints(text).forEach(function (point) {
      if (MT.py.inRanges(data.unassigned, point)) {
        flush();
        out.push(String.fromCodePoint(point));
        return;
      }
      var key = String(point);
      run.push(MT.own(data.nfkc, key) ? data.nfkc[key] : String.fromCodePoint(point));
    });
    flush();
    return out.join("");
  }

  function nameprep(label) {
    var data = tables();
    var mapped = [];
    toPoints(label).forEach(function (point) {
      if (MT.py.inRanges(data.b1, point)) return;
      var key = String(point);
      mapped.push(MT.own(data.b2, key) ? data.b2[key] : String.fromCodePoint(point));
    });
    var text = legacyNfkc(data, mapped.join(""));
    var points = toPoints(text);
    points.forEach(function (point) {
      if (MT.py.inRanges(data.prohibited, point)) throw DecodeError("idna: Invalid character");
    });
    var randal = points.map(function (point) {
      return MT.py.inRanges(data.d1, point);
    });
    if (randal.some(Boolean)) {
      var hasL = points.some(function (point) {
        return MT.py.inRanges(data.d2, point);
      });
      if (hasL) throw DecodeError("idna: Violation of BIDI requirement 2");
      if (!randal[0] || !randal[randal.length - 1]) throw DecodeError("idna: Violation of BIDI requirement 3");
    }
    return text;
  }

  function toAscii(label) {
    if (MT.codecs.isAscii(label)) {
      if (label.length > 0 && label.length < 64) return label;
      throw DecodeError("idna: label empty or too long");
    }
    var prepared = nameprep(label);
    if (MT.codecs.isAscii(prepared)) {
      if (prepared.length > 0 && prepared.length < 64) return prepared;
      throw DecodeError("idna: label empty or too long");
    }
    if (prepared.slice(0, 4) === "xn--") throw DecodeError("idna: Label starts with ACE prefix");
    var encoded = "xn--" + punycodeEncode(prepared);
    if (encoded.length > 0 && encoded.length < 64) return encoded;
    throw DecodeError("idna: label empty or too long");
  }

  function asciiLower(text) {
    var out = [];
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      out.push(code >= 65 && code <= 90 ? String.fromCharCode(code + 32) : text[i]);
    }
    return out.join("");
  }

  function toUnicode(label) {
    if (label.length > 1024) throw DecodeError("idna: label way too long");
    for (var i = 0; i < label.length; i += 1) {
      if (label[i] > 127) throw DecodeError("ascii: ordinal not in range(128)");
    }
    var text = MT.bytes.toLatin1(label);
    var lowered = asciiLower(text);
    if (lowered.slice(0, 4) !== "xn--") return text;
    var result = punycodeDecode(label.subarray(4), "strict");
    var again = toAscii(result);
    if (lowered !== again) throw DecodeError("idna: IDNA does not round-trip");
    return result;
  }

  function hasAcePrefix(bytes) {
    for (var i = 0; i + 3 < bytes.length; i += 1) {
      var x = bytes[i] | 0x20;
      var n = bytes[i + 1] | 0x20;
      if (x === 120 && n === 110 && bytes[i + 2] === 45 && bytes[i + 3] === 45) return true;
    }
    return false;
  }

  function idnaDecode(bytes, mode) {
    if (!bytes.length) return "";
    if (mode !== "strict") throw DecodeError("idna: Unsupported error handling " + mode);
    if (!hasAcePrefix(bytes)) {
      var plain = true;
      for (var i = 0; i < bytes.length; i += 1) {
        if (bytes[i] > 127) {
          plain = false;
          break;
        }
      }
      if (plain) return MT.bytes.toLatin1(bytes);
    }
    var labels = [];
    var start = 0;
    for (var k = 0; k <= bytes.length; k += 1) {
      if (k === bytes.length || bytes[k] === 46) {
        labels.push(bytes.subarray(start, k));
        start = k + 1;
      }
    }
    var trailing = "";
    if (labels.length && labels[labels.length - 1].length === 0) {
      trailing = ".";
      labels.pop();
    }
    return labels.map(toUnicode).join(".") + trailing;
  }

  function charmap(bytes) {
    var codes = new Array(bytes.length);
    for (var i = 0; i < bytes.length; i += 1) codes[i] = bytes[i];
    return fromCodes(codes);
  }

  function undefinedCodec(bytes) {
    if (!bytes.length) return "";
    throw DecodeError("undefined encoding");
  }

  var UTF7_DIRECT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'(),-./:?!" + String.fromCharCode(34) + "#$%&*;<=>@[]^_`{|} " + String.fromCharCode(9, 13, 10);
  var BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  function utf7Encode(text) {
    var out = [];
    var inShift = false;
    var bits = 0;
    var buffer = 0;
    var flushBits = function () {
      while (bits >= 6) {
        out.push(BASE64_ALPHABET.charCodeAt((buffer >>> (bits - 6)) & 63));
        bits -= 6;
      }
      buffer &= (1 << bits) - 1;
    };
    var pushUnit = function (unit) {
      bits += 16;
      buffer = (buffer << 16) | unit;
      flushBits();
    };
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      var direct = code > 0 && code < 128 && UTF7_DIRECT.indexOf(String.fromCharCode(code)) >= 0;
      if (inShift) {
        if (direct) {
          if (bits) {
            out.push(BASE64_ALPHABET.charCodeAt((buffer << (6 - bits)) & 63));
            buffer = 0;
            bits = 0;
          }
          inShift = false;
          if (BASE64_ALPHABET.indexOf(String.fromCharCode(code)) >= 0 || code === 45) out.push(45);
          out.push(code);
          continue;
        }
      } else if (code === 43) {
        out.push(43, 45);
        continue;
      } else if (direct) {
        out.push(code);
        continue;
      } else {
        out.push(43);
        inShift = true;
      }
      pushUnit(code);
    }
    if (bits) out.push(BASE64_ALPHABET.charCodeAt((buffer << (6 - bits)) & 63));
    if (inShift) out.push(45);
    return new Uint8Array(out);
  }

  MT.special = {
    utf7Encode: utf7Encode,
    utf_7: utf7,
    unicode_escape: function (bytes, mode) {
      return unicodeEscape(bytes, mode, false);
    },
    raw_unicode_escape: function (bytes, mode) {
      return unicodeEscape(bytes, mode, true);
    },
    punycode: punycodeDecode,
    idna: idnaDecode,
    charmap: charmap,
    undefined: undefinedCodec,
  };

  MT.idna = {
    nameprep: nameprep,
    toAscii: toAscii,
    toUnicode: toUnicode,
    decode: idnaDecode,
    punycodeDecode: punycodeDecode,
    punycodeEncode: punycodeEncode,
    decodeHost: function (host) {
      if (!MT.codecs.isAscii(host)) return host;
      try {
        return idnaDecode(MT.bytes.fromLatin1(host), "strict");
      } catch (error) {
        if (error instanceof MT.codecs.DecodeError || error instanceof MT.codecs.LookupError) return host;
        throw error;
      }
    },
    pslLabel: function (label) {
      var lowered = label.toLowerCase();
      if (lowered.slice(0, 4) !== "xn--") return lowered;
      var map = MT.json("psl").punycode;
      return MT.own(map, lowered) ? map[lowered] : lowered;
    },
  };
})(MT);
