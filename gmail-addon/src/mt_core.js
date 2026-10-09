var MT = MT || {};

(function (MT) {
  var BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var lookup = null;

  function base64Lookup() {
    if (lookup) return lookup;
    lookup = new Int16Array(256).fill(-1);
    for (var i = 0; i < BASE64.length; i += 1) lookup[BASE64.charCodeAt(i)] = i;
    lookup["-".charCodeAt(0)] = 62;
    lookup["_".charCodeAt(0)] = 63;
    return lookup;
  }

  function fromBase64(text) {
    var table = base64Lookup();
    var clean = 0;
    var i;
    for (i = 0; i < text.length; i += 1) {
      if (table[text.charCodeAt(i) & 255] >= 0 && text.charCodeAt(i) < 256) clean += 1;
    }
    var out = new Uint8Array(Math.floor((clean * 3) / 4));
    var buffer = 0;
    var bits = 0;
    var position = 0;
    for (i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      if (code > 255) continue;
      var value = table[code];
      if (value < 0) continue;
      buffer = (buffer << 6) | value;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[position] = (buffer >> bits) & 255;
        position += 1;
      }
    }
    return position === out.length ? out : out.subarray(0, position);
  }

  function toBase64(bytes) {
    var parts = [];
    var chunk = [];
    for (var i = 0; i < bytes.length; i += 3) {
      var a = bytes[i];
      var b = i + 1 < bytes.length ? bytes[i + 1] : 0;
      var c = i + 2 < bytes.length ? bytes[i + 2] : 0;
      chunk.push(BASE64[a >> 2], BASE64[((a & 3) << 4) | (b >> 4)]);
      chunk.push(i + 1 < bytes.length ? BASE64[((b & 15) << 2) | (c >> 6)] : "=");
      chunk.push(i + 2 < bytes.length ? BASE64[c & 63] : "=");
      if (chunk.length >= 8192) {
        parts.push(chunk.join(""));
        chunk = [];
      }
    }
    parts.push(chunk.join(""));
    return parts.join("");
  }

  var HEX = "0123456789abcdef";

  function toHex(bytes) {
    var out = new Array(bytes.length);
    for (var i = 0; i < bytes.length; i += 1) out[i] = HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
    return out.join("");
  }

  function fromLatin1(text) {
    var out = new Uint8Array(text.length);
    for (var i = 0; i < text.length; i += 1) out[i] = text.charCodeAt(i) & 255;
    return out;
  }

  function toLatin1(bytes, start, end) {
    var from = start === undefined ? 0 : start;
    var to = end === undefined ? bytes.length : end;
    var parts = [];
    for (var i = from; i < to; i += 8192) {
      parts.push(String.fromCharCode.apply(null, bytes.subarray(i, Math.min(to, i + 8192))));
    }
    return parts.join("");
  }

  function Utf8Error(message) {
    this.name = "Utf8Error";
    this.message = message;
  }
  Utf8Error.prototype = Object.create(Error.prototype);

  function utf8Decode(bytes, replace) {
    var parts = [];
    var chunk = [];
    var i = 0;
    var length = bytes.length;

    function bad(advance) {
      if (!replace) throw new Utf8Error("invalid utf-8 at byte " + i);
      chunk.push(0xfffd);
      i += advance;
    }

    while (i < length) {
      var first = bytes[i];
      if (first < 0x80) {
        chunk.push(first);
        i += 1;
      } else if (first < 0xc2) {
        bad(1);
      } else if (first < 0xe0) {
        if (i + 1 >= length || (bytes[i + 1] & 0xc0) !== 0x80) {
          bad(1);
        } else {
          chunk.push(((first & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
          i += 2;
        }
      } else if (first < 0xf0) {
        var low = first === 0xe0 ? 0xa0 : 0x80;
        var high = first === 0xed ? 0x9f : 0xbf;
        if (i + 1 >= length || bytes[i + 1] < low || bytes[i + 1] > high) {
          bad(1);
        } else if (i + 2 >= length || (bytes[i + 2] & 0xc0) !== 0x80) {
          bad(2);
        } else {
          chunk.push(((first & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f));
          i += 3;
        }
      } else if (first < 0xf5) {
        var floor = first === 0xf0 ? 0x90 : 0x80;
        var ceiling = first === 0xf4 ? 0x8f : 0xbf;
        if (i + 1 >= length || bytes[i + 1] < floor || bytes[i + 1] > ceiling) {
          bad(1);
        } else if (i + 2 >= length || (bytes[i + 2] & 0xc0) !== 0x80) {
          bad(2);
        } else if (i + 3 >= length || (bytes[i + 3] & 0xc0) !== 0x80) {
          bad(3);
        } else {
          var point =
            ((first & 0x07) << 18) | ((bytes[i + 1] & 0x3f) << 12) | ((bytes[i + 2] & 0x3f) << 6) | (bytes[i + 3] & 0x3f);
          point -= 0x10000;
          chunk.push(0xd800 + (point >> 10), 0xdc00 + (point & 0x3ff));
          i += 4;
        }
      } else {
        bad(1);
      }
      if (chunk.length >= 8192) {
        parts.push(String.fromCharCode.apply(null, chunk));
        chunk = [];
      }
    }
    parts.push(String.fromCharCode.apply(null, chunk));
    return parts.join("");
  }

  function utf8Encode(text) {
    var out = [];
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff) {
        var next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
        if (next < 0xdc00 || next > 0xdfff) throw new Utf8Error("lone surrogate at " + i);
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        i += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        throw new Utf8Error("lone surrogate at " + i);
      }
      if (code < 0x80) {
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

  function concat(list) {
    var total = 0;
    var i;
    for (i = 0; i < list.length; i += 1) total += list[i].length;
    var out = new Uint8Array(total);
    var offset = 0;
    for (i = 0; i < list.length; i += 1) {
      out.set(list[i], offset);
      offset += list[i].length;
    }
    return out;
  }

  MT.bytes = {
    fromBase64: fromBase64,
    toBase64: toBase64,
    toHex: toHex,
    fromLatin1: fromLatin1,
    toLatin1: toLatin1,
    utf8Decode: utf8Decode,
    utf8Encode: utf8Encode,
    concat: concat,
    Utf8Error: Utf8Error,
  };

  var blobs = {};
  var documents = {};

  function own(value, key) {
    return Object.prototype.hasOwnProperty.call(value, key);
  }

  function revive(value) {
    if (Array.isArray(value)) {
      for (var i = 0; i < value.length; i += 1) value[i] = revive(value[i]);
      return value;
    }
    if (value && typeof value === "object") {
      if (own(value, "__set__")) return new Set(revive(value.__set__));
      if (own(value, "__bytes__")) return fromBase64(value.__bytes__);
      if (own(value, "__dict__")) {
        var map = new Map();
        value.__dict__.forEach(function (pair) {
          map.set(revive(pair[0]), revive(pair[1]));
        });
        return map;
      }
      Object.keys(value).forEach(function (key) {
        value[key] = revive(value[key]);
      });
    }
    return value;
  }

  MT.blob = function (name) {
    if (!own(blobs, name)) {
      if (typeof MT_DATA === "undefined" || typeof MT_DATA[name] !== "function") {
        throw new Error("MailTrace data file '" + name + "' is missing");
      }
      blobs[name] = MT.platform.gunzip(fromBase64(MT_DATA[name]().gzip));
    }
    return blobs[name];
  };

  MT.json = function (name) {
    if (!own(documents, name)) {
      documents[name] = revive(JSON.parse(utf8Decode(MT.blob(name), false)));
      delete blobs[name];
    }
    return documents[name];
  };

  MT.K = function (module) {
    var constants = MT.json("knowledge").constants;
    if (!own(constants, module)) throw new Error("no constants for module '" + module + "'");
    return constants[module];
  };

  var compiled = {};

  MT.RX = function (module, name) {
    var key = module + "." + name;
    if (!own(compiled, key)) {
      var patterns = MT.json("knowledge").patterns;
      if (!own(patterns, module) || !own(patterns[module], name)) throw new Error("no pattern " + key);
      var entry = patterns[module][name];
      compiled[key] = MT.py.re(entry.pattern, entry.flags);
    }
    return compiled[key];
  };

  MT.own = own;
  MT.ENGINE = "mailtrace-addon-1";
})(MT);
