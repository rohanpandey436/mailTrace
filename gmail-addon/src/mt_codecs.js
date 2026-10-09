var MT = MT || {};

(function (MT) {
  var REPLACEMENT = String.fromCharCode(0xfffd);

  function NullByteError(message) {
    this.name = "ValueError";
    this.message = message;
  }
  NullByteError.prototype = Object.create(Error.prototype);

  function LookupError(message) {
    this.name = "LookupError";
    this.message = message;
  }
  LookupError.prototype = Object.create(Error.prototype);

  function DecodeError(message) {
    this.name = "UnicodeDecodeError";
    this.message = message;
  }
  DecodeError.prototype = Object.create(Error.prototype);

  function EncodeError(message) {
    this.name = "UnicodeEncodeError";
    this.message = message;
  }
  EncodeError.prototype = Object.create(Error.prototype);

  function tables() {
    return MT.json("knowledge").codecs;
  }

  function normalise(name) {
    var text = String(name === null || name === undefined ? "" : name);
    if (text.indexOf(String.fromCharCode(0)) >= 0) throw new NullByteError("embedded null character");
    var out = [];
    var punct = false;
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      var upper = code >= 65 && code <= 90;
      var keep = upper || (code >= 97 && code <= 122) || (code >= 48 && code <= 57) || code === 46;
      if (keep) {
        if (punct && out.length) out.push("_");
        punct = false;
        out.push(String.fromCharCode(upper ? code + 32 : code));
      } else {
        punct = true;
      }
    }
    return out.join("");
  }

  var resolved = new Map();

  function kindOf(module) {
    var data = tables();
    if (MT.own(data.single, module)) return "single";
    if (data.unicode.indexOf(module) >= 0) return "unicode";
    if (data.multibyte.indexOf(module) >= 0) return "multibyte";
    if (data.special.indexOf(module) >= 0) return "special";
    return null;
  }

  function lookup(name) {
    var key = String(name);
    if (resolved.has(key)) {
      var cached = resolved.get(key);
      if (cached === null) throw new LookupError("unknown encoding: " + key);
      return cached;
    }
    var data = tables();
    var norm = normalise(key);
    var aliased = null;
    if (MT.own(data.aliases, norm)) aliased = data.aliases[norm];
    else if (MT.own(data.aliases, norm.split(".").join("_"))) aliased = data.aliases[norm.split(".").join("_")];
    var candidates = aliased !== null ? [aliased, norm] : [norm];
    var found = null;
    for (var i = 0; i < candidates.length && found === null; i += 1) {
      var module = candidates[i];
      if (!module || module.indexOf(".") >= 0) continue;
      var kind = kindOf(module);
      if (kind) found = { module: module, kind: kind };
    }
    resolved.set(key, found);
    if (found === null) throw new LookupError("unknown encoding: " + key);
    return found;
  }

  function known(name) {
    try {
      lookup(name);
      return true;
    } catch (error) {
      return false;
    }
  }

  function fromCodes(codes) {
    if (codes.length < 8192) return String.fromCharCode.apply(null, codes);
    var parts = [];
    for (var i = 0; i < codes.length; i += 8192) {
      parts.push(String.fromCharCode.apply(null, codes.slice(i, i + 8192)));
    }
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

  function single(bytes, mode, entry) {
    var high = entry.high;
    var table = entry.table;
    var codes = [];
    for (var i = 0; i < bytes.length; i += 1) {
      var value = bytes[i];
      var point = table ? table[value] : value < 0x80 ? value : high[value - 0x80];
      if (point < 0) {
        if (mode === "strict") throw new DecodeError("byte 0x" + value.toString(16) + " in position " + i);
        point = mode === "surrogateescape" ? 0xdc00 + value : 0xfffd;
      }
      pushPoint(codes, point);
    }
    return fromCodes(codes);
  }

  function utf8(bytes, mode, skipBom) {
    var data = bytes;
    if (skipBom && data.length >= 3 && data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) data = data.subarray(3);
    try {
      return MT.bytes.utf8Decode(data, mode !== "strict");
    } catch (error) {
      throw new DecodeError(error.message);
    }
  }

  function utf16(bytes, mode, order) {
    var start = 0;
    var little = order !== "be";
    if (order === "auto" && bytes.length >= 2) {
      if (bytes[0] === 0xff && bytes[1] === 0xfe) {
        start = 2;
      } else if (bytes[0] === 0xfe && bytes[1] === 0xff) {
        start = 2;
        little = false;
      }
    }
    var codes = [];
    var i = start;
    var n = bytes.length;

    function bad(message) {
      if (mode === "strict") throw new DecodeError(message);
      codes.push(0xfffd);
    }

    function unit(at) {
      return little ? bytes[at] | (bytes[at + 1] << 8) : (bytes[at] << 8) | bytes[at + 1];
    }

    while (i < n) {
      if (i + 1 >= n) {
        bad("truncated data");
        break;
      }
      var first = unit(i);
      if (first < 0xd800 || first > 0xdfff) {
        codes.push(first);
        i += 2;
      } else if (first >= 0xdc00) {
        bad("illegal encoding");
        i += 2;
      } else if (i + 3 >= n) {
        bad("unexpected end of data");
        break;
      } else {
        var second = unit(i + 2);
        if (second >= 0xdc00 && second <= 0xdfff) {
          codes.push(first, second);
          i += 4;
        } else {
          bad("illegal UTF-16 surrogate");
          i += 2;
        }
      }
    }
    return fromCodes(codes);
  }

  function utf32(bytes, mode, order) {
    var start = 0;
    var little = order !== "be";
    if (order === "auto" && bytes.length >= 4) {
      if (bytes[0] === 0xff && bytes[1] === 0xfe && bytes[2] === 0 && bytes[3] === 0) {
        start = 4;
      } else if (bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0xfe && bytes[3] === 0xff) {
        start = 4;
        little = false;
      }
    }
    var codes = [];
    var n = bytes.length;

    function bad(message) {
      if (mode === "strict") throw new DecodeError(message);
      codes.push(0xfffd);
    }

    for (var i = start; i < n; i += 4) {
      if (i + 3 >= n) {
        bad("truncated data");
        break;
      }
      var point = little
        ? bytes[i] + bytes[i + 1] * 0x100 + bytes[i + 2] * 0x10000 + bytes[i + 3] * 0x1000000
        : bytes[i] * 0x1000000 + bytes[i + 1] * 0x10000 + bytes[i + 2] * 0x100 + bytes[i + 3];
      if (point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) {
        bad("code point not in range(0x110000)");
      } else {
        pushPoint(codes, point);
      }
    }
    return fromCodes(codes);
  }

  function unicode(bytes, mode, module) {
    if (module === "utf_8") return utf8(bytes, mode, false);
    if (module === "utf_8_sig") return utf8(bytes, mode, true);
    if (module === "utf_16") return utf16(bytes, mode, "auto");
    if (module === "utf_16_le") return utf16(bytes, mode, "le");
    if (module === "utf_16_be") return utf16(bytes, mode, "be");
    if (module === "utf_32") return utf32(bytes, mode, "auto");
    if (module === "utf_32_le") return utf32(bytes, mode, "le");
    return utf32(bytes, mode, "be");
  }

  function multibyte(bytes, mode, module) {
    return MT.cjk.decode(module, bytes, mode);
  }

  function singlePoint(module, value) {
    var entry = tables().single[module];
    if (!entry) return -1;
    if (entry.table) return entry.table[value];
    return value < 0x80 ? value : entry.high[value - 0x80];
  }

  function decode(bytes, encoding, errors) {
    var mode = errors || "strict";
    var codec = lookup(encoding);
    if (codec.kind === "single") return single(bytes, mode, tables().single[codec.module]);
    if (codec.kind === "unicode") return unicode(bytes, mode, codec.module);
    if (codec.kind === "special") return MT.special[codec.module](bytes, mode);
    return multibyte(bytes, mode, codec.module);
  }

  var reverse = {};

  function reverseTable(module) {
    if (!MT.own(reverse, module)) {
      var entry = tables().single[module];
      var set = new Set();
      for (var value = 0; value < 256; value += 1) {
        var point = entry.table ? entry.table[value] : value < 0x80 ? value : entry.high[value - 0x80];
        if (point >= 0) set.add(point);
      }
      reverse[module] = set;
    }
    return reverse[module];
  }

  function encodable(text, encoding) {
    var codec = lookup(encoding);
    if (codec.kind === "unicode") return !hasSurrogates(text);
    if (codec.kind === "multibyte" || codec.kind === "special") return !hasSurrogates(text);
    var allowed = reverseTable(codec.module);
    for (var i = 0; i < text.length; i += 1) {
      var point = text.codePointAt(i);
      if (point > 0xffff) i += 1;
      if (!allowed.has(point)) return false;
    }
    return true;
  }

  function failEncode(out, point, mode, position) {
    if (mode === "surrogateescape" && point >= 0xdc80 && point <= 0xdcff) {
      out.push(point - 0xdc00);
      return;
    }
    if (mode === "ignore") return;
    if (mode === "replace") {
      out.push(0x3f);
      return;
    }
    throw new EncodeError("character U+" + hex(point, 4) + " at position " + position + " cannot be encoded");
  }

  var forward = {};

  function forwardTable(module) {
    if (!MT.own(forward, module)) {
      var map = new Map();
      for (var value = 0; value < 256; value += 1) {
        var point = singlePoint(module, value);
        if (point >= 0 && !map.has(point)) map.set(point, value);
      }
      forward[module] = map;
    }
    return forward[module];
  }

  function codePoints(text) {
    var points = [];
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
        var next = text.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          points.push(0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00));
          i += 1;
          continue;
        }
      }
      points.push(code);
    }
    return points;
  }

  function encodeSingle(text, mode, module) {
    var map = forwardTable(module);
    var points = codePoints(text);
    var out = [];
    for (var i = 0; i < points.length; i += 1) {
      var value = map.get(points[i]);
      if (value === undefined) failEncode(out, points[i], mode, i);
      else out.push(value);
    }
    return new Uint8Array(out);
  }

  function pushUnit(out, unit, little) {
    if (little) out.push(unit & 0xff, unit >> 8);
    else out.push(unit >> 8, unit & 0xff);
  }

  function encodeUnicode(text, mode, module) {
    var points = codePoints(text);
    var out = [];
    var i;
    if (module === "utf_8" || module === "utf_8_sig") {
      if (module === "utf_8_sig") out.push(0xef, 0xbb, 0xbf);
      for (i = 0; i < points.length; i += 1) {
        var code = points[i];
        if (code >= 0xd800 && code <= 0xdfff) {
          failEncode(out, code, mode, i);
        } else if (code < 0x80) {
          out.push(code);
        } else if (code < 0x800) {
          out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        } else if (code < 0x10000) {
          out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        } else {
          out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
      }
      return new Uint8Array(out);
    }
    var wide = module.indexOf("utf_32") === 0;
    var little = module !== "utf_16_be" && module !== "utf_32_be";
    if (module === "utf_16") out.push(0xff, 0xfe);
    if (module === "utf_32") out.push(0xff, 0xfe, 0, 0);
    for (i = 0; i < points.length; i += 1) {
      var point = points[i];
      if (point >= 0xd800 && point <= 0xdfff) {
        if (mode === "ignore") continue;
        if (mode !== "replace") throw new EncodeError("surrogates not allowed at position " + i);
        point = 0x3f;
      }
      if (wide) {
        if (little) out.push(point & 0xff, (point >> 8) & 0xff, (point >> 16) & 0xff, 0);
        else out.push(0, (point >> 16) & 0xff, (point >> 8) & 0xff, point & 0xff);
      } else if (point >= 0x10000) {
        var offset = point - 0x10000;
        pushUnit(out, 0xd800 + (offset >> 10), little);
        pushUnit(out, 0xdc00 + (offset & 0x3ff), little);
      } else {
        pushUnit(out, point, little);
      }
    }
    return new Uint8Array(out);
  }

  function encode(text, encoding, errors) {
    var mode = errors || "strict";
    var codec = lookup(encoding);
    if (codec.kind === "single") return encodeSingle(text, mode, codec.module);
    if (codec.kind === "unicode") return encodeUnicode(text, mode, codec.module);
    if (codec.kind === "multibyte") return MT.cjk.encode(codec.module, text, mode);
    if (codec.module === "utf_7") return MT.special.utf7Encode(text);
    throw new EncodeError("encoding text as " + encoding + " is not supported");
  }

  function escapeDecode(bytes) {
    var codes = new Array(bytes.length);
    for (var i = 0; i < bytes.length; i += 1) codes[i] = bytes[i] < 0x80 ? bytes[i] : 0xdc00 + bytes[i];
    return fromCodes(codes);
  }

  function escapeEncode(text) {
    var out = new Uint8Array(text.length);
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      if (code < 0x80) {
        out[i] = code;
      } else if (code >= 0xdc80 && code <= 0xdcff) {
        out[i] = code - 0xdc00;
      } else {
        throw new EncodeError("character at " + i + " is not ASCII");
      }
    }
    return out;
  }

  function hasSurrogates(text) {
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      if (code < 0xd800 || code > 0xdfff) continue;
      if (code <= 0xdbff) {
        var next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
        if (next >= 0xdc00 && next <= 0xdfff) {
          i += 1;
          continue;
        }
      }
      return true;
    }
    return false;
  }

  function isAscii(text) {
    for (var i = 0; i < text.length; i += 1) if (text.charCodeAt(i) > 127) return false;
    return true;
  }

  function hex(value, width) {
    var text = value.toString(16);
    while (text.length < width) text = "0" + text;
    return text;
  }

  function rawUnicodeEscape(text) {
    var out = [];
    for (var i = 0; i < text.length; i += 1) {
      var code = text.codePointAt(i);
      if (code > 0xffff) i += 1;
      if (code < 0x100) {
        out.push(code);
        continue;
      }
      var piece = code > 0xffff ? "\\U" + hex(code, 8) : "\\u" + hex(code, 4);
      for (var j = 0; j < piece.length; j += 1) out.push(piece.charCodeAt(j));
    }
    return new Uint8Array(out);
  }

  function escapedAsReplacement(text) {
    var out = [];
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      out.push(code >= 0xdc80 && code <= 0xdcff ? REPLACEMENT : text[i]);
    }
    return out.join("");
  }

  MT.codecs = {
    singlePoint: singlePoint,
    normalise: normalise,
    lookup: lookup,
    known: known,
    decode: decode,
    encode: encode,
    codePoints: codePoints,
    encodable: encodable,
    escapeDecode: escapeDecode,
    escapeEncode: escapeEncode,
    escapedAsReplacement: escapedAsReplacement,
    hasSurrogates: hasSurrogates,
    isAscii: isAscii,
    rawUnicodeEscape: rawUnicodeEscape,
    LookupError: LookupError,
    NullByteError: NullByteError,
    DecodeError: DecodeError,
    EncodeError: EncodeError,
    REPLACEMENT: REPLACEMENT,
  };
})(MT);
