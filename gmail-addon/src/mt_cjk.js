var MT = MT || {};

(function (MT) {
  var ESC = 0x1b;
  var SO = 0x0e;
  var SI = 0x0f;
  var LF = 0x0a;
  var DBCS = String.fromCharCode(0x80);
  var MAX_ESCSEQLEN = 16;
  var REPLACEMENT = "�";

  var DBCS_CODECS = {
    gb2312: { table: "gb2312" },
    gbk: { table: "gbk" },
    gb18030: { table: "gb18030", gb18030: true },
    big5: { table: "big5" },
    cp950: { table: "cp950" },
    big5hkscs: { table: "big5hkscs" },
    euc_kr: { table: "euc_kr", jamo: true },
    cp949: { table: "cp949" },
    johab: { table: "johab" },
    shift_jis: { table: "shift_jis" },
    cp932: { table: "cp932" },
    shift_jis_2004: { table: "shift_jis_2004" },
    shift_jisx0213: { table: "shift_jisx0213" },
    euc_jp: { table: "euc_jp", three: "euc_jp_3" },
    euc_jis_2004: { table: "euc_jis_2004", three: "euc_jis_2004_3" },
    euc_jisx0213: { table: "euc_jisx0213", three: "euc_jisx0213_3" },
  };

  var ISO2022_CODECS = {
    iso2022_jp: { marks: ["B", "B" + DBCS, "@" + DBCS, "J"], noShift: true, ext: true },
    iso2022_jp_1: { marks: ["B", "B" + DBCS, "D" + DBCS, "@" + DBCS, "J"], noShift: true, ext: true },
    iso2022_jp_2: { marks: ["B", "B" + DBCS, "D" + DBCS, "C" + DBCS, "A" + DBCS, "@" + DBCS, "J", "A", "F"], noShift: true, ext: true, useG2: true },
    iso2022_jp_2004: { marks: ["B", "Q" + DBCS, "B" + DBCS, "P" + DBCS], noShift: true, ext: true },
    iso2022_jp_3: { marks: ["B", "O" + DBCS, "B" + DBCS, "P" + DBCS], noShift: true, ext: true },
    iso2022_jp_ext: { marks: ["B", "B" + DBCS, "D" + DBCS, "I", "J", "@" + DBCS], noShift: true, ext: true },
    iso2022_kr: { marks: ["B", "C" + DBCS], noShift: false, ext: false },
  };

  var CHARSET_TABLES = {};
  CHARSET_TABLES["A" + DBCS] = "gb2312_iso";
  CHARSET_TABLES["B" + DBCS] = "jisx0208";
  CHARSET_TABLES["@" + DBCS] = "jisx0208";
  CHARSET_TABLES["C" + DBCS] = "ksc5601";
  CHARSET_TABLES["D" + DBCS] = "jisx0212";
  CHARSET_TABLES["O" + DBCS] = "jisx0213_1_2000";
  CHARSET_TABLES["P" + DBCS] = "jisx0213_2";
  CHARSET_TABLES["Q" + DBCS] = "jisx0213_1_2004";

  var data = null;
  var built = {};
  var singles = {};
  var longErrors = {};
  var forwards = {};
  var isoForwards = {};
  var jamoReverse = null;

  function blob() {
    if (data === null) data = MT.json("cjk");
    return data;
  }

  function error(message) {
    return new MT.codecs.DecodeError(message);
  }

  function isSinglePoint(text) {
    return text.length === 1 || (text.length === 2 && text.charCodeAt(0) >= 0xd800 && text.charCodeAt(0) <= 0xdbff);
  }

  function sortedKeys(map) {
    return Array.from(map.keys()).sort(function (a, b) {
      return a - b;
    });
  }

  function addRun(map, start, text) {
    var key = start;
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      var chunk = text.charAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
        chunk += text.charAt(i + 1);
        i += 1;
      }
      map.set(key, chunk);
      key += 1;
    }
  }

  function table(name) {
    if (MT.own(built, name)) return built[name];
    var spec = blob().tables[name];
    if (!spec) throw new Error("missing CJK table " + name);
    var map = new Map();
    if (spec.base) {
      table(spec.base).forEach(function (value, key) {
        map.set(key, value);
      });
    }
    if (spec.derive) {
      table(spec.derive).forEach(function (value, key) {
        var lead = key >> 8;
        var trail = key & 0xff;
        if (lead >= 0xa1 && trail >= 0xa1) map.set(((lead & 0x7f) << 8) | (trail & 0x7f), value);
      });
    }
    spec.removed.forEach(function (key) {
      map.delete(key);
    });
    spec.runs.forEach(function (run) {
      addRun(map, run[0], run[1]);
    });
    spec.pairs.forEach(function (pair) {
      map.set(pair[0], pair[1]);
    });
    built[name] = map;
    return map;
  }

  function singleTable(codec) {
    if (MT.own(singles, codec)) return singles[codec];
    var raw = blob().singles[codec] || {};
    var map = new Map();
    Object.keys(raw).forEach(function (key) {
      map.set(Number(key), raw[key]);
    });
    singles[codec] = map;
    return map;
  }

  function longErrorSet(codec) {
    if (MT.own(longErrors, codec)) return longErrors[codec];
    var set = new Set(blob().errlen2[codec] || []);
    longErrors[codec] = set;
    return set;
  }

  function Output(codec, bytes, mode) {
    this.codec = codec;
    this.bytes = bytes;
    this.mode = mode;
    this.parts = [];
  }

  Output.prototype.push = function (text) {
    this.parts.push(text);
  };

  Output.prototype.fail = function (start, length, reason) {
    var mode = this.mode;
    if (mode === "strict") {
      throw error(this.codec + ": " + reason + " at position " + start + "-" + (start + length));
    }
    if (mode === "ignore") return;
    if (mode === "surrogateescape") {
      for (var i = start; i < start + length; i += 1) {
        var value = this.bytes[i];
        if (value < 0x80) throw error(this.codec + ": " + reason + " at position " + start);
        this.parts.push(String.fromCharCode(0xdc00 + value));
      }
      return;
    }
    this.parts.push(REPLACEMENT);
  };

  Output.prototype.text = function () {
    return this.parts.join("");
  };

  function gb18030Range(linear) {
    var ranges = blob().gb18030_ranges;
    var low = 0;
    var high = ranges.length - 1;
    while (low <= high) {
      var mid = (low + high) >> 1;
      var entry = ranges[mid];
      if (linear < entry[0]) high = mid - 1;
      else if (linear >= entry[0] + entry[2]) low = mid + 1;
      else return entry[1] + (linear - entry[0]);
    }
    return -1;
  }

  function fromPoint(point) {
    if (point < 0x10000) return String.fromCharCode(point);
    var offset = point - 0x10000;
    return String.fromCharCode(0xd800 + (offset >> 10), 0xdc00 + (offset & 0x3ff));
  }

  function jamoIndex(kind, value) {
    var entry = blob().jamo[kind][String(value)];
    return entry === undefined ? -1 : entry;
  }

  function decodeDbcs(codec, bytes, mode) {
    var spec = DBCS_CODECS[codec];
    var out = new Output(codec, bytes, mode);
    var single = singleTable(codec);
    var pairs = table(spec.table);
    var three = spec.three ? table(spec.three) : null;
    var twoByteErrors = longErrorSet(codec);
    var n = bytes.length;
    var i = 0;
    while (i < n) {
      var b1 = bytes[i];
      var one = single.get(b1);
      if (one !== undefined) {
        out.push(one);
        i += 1;
        continue;
      }
      if (three !== null && b1 === 0x8f) {
        if (i + 2 >= n) {
          out.fail(i, n - i, "incomplete multibyte sequence");
          break;
        }
        var triple = three.get((bytes[i + 1] << 8) | bytes[i + 2]);
        if (triple !== undefined) {
          out.push(triple);
          i += 3;
        } else {
          out.fail(i, 1, "illegal multibyte sequence");
          i += 1;
        }
        continue;
      }
      if (i + 1 >= n) {
        out.fail(i, n - i, "incomplete multibyte sequence");
        break;
      }
      var b2 = bytes[i + 1];
      if (spec.jamo && b1 === 0xa4 && b2 === 0xd4) {
        if (i + 7 >= n) {
          out.fail(i, n - i, "incomplete multibyte sequence");
          break;
        }
        var cho = bytes[i + 2] === 0xa4 ? jamoIndex("cho", bytes[i + 3]) : -1;
        var jung = bytes[i + 4] === 0xa4 ? jamoIndex("jung", bytes[i + 5]) : -1;
        var jong = bytes[i + 6] === 0xa4 ? (bytes[i + 7] === 0xd4 ? 0 : jamoIndex("jong", bytes[i + 7])) : -1;
        if (cho < 0 || jung < 0 || jong < 0) {
          out.fail(i, 1, "illegal multibyte sequence");
          i += 1;
        } else {
          out.push(String.fromCharCode(0xac00 + cho * 588 + jung * 28 + jong));
          i += 8;
        }
        continue;
      }
      if (spec.gb18030 && b2 >= 0x30 && b2 <= 0x39) {
        if (i + 3 >= n) {
          out.fail(i, n - i, "incomplete multibyte sequence");
          break;
        }
        var b3 = bytes[i + 2];
        var b4 = bytes[i + 3];
        var point = -1;
        if (b1 >= 0x81 && b3 >= 0x81 && b3 <= 0xfe && b4 >= 0x30 && b4 <= 0x39) {
          if (b1 < 0x90) {
            point = gb18030Range((b1 - 0x81) * 12600 + (b2 - 0x30) * 1260 + (b3 - 0x81) * 10 + (b4 - 0x30));
          } else if (b1 <= 0xe3) {
            var linear = (b1 - 0x90) * 12600 + (b2 - 0x30) * 1260 + (b3 - 0x81) * 10 + (b4 - 0x30);
            if (linear <= 0xfffff) point = 0x10000 + linear;
          }
        }
        if (point < 0) {
          out.fail(i, 1, "illegal multibyte sequence");
          i += 1;
        } else {
          out.push(fromPoint(point));
          i += 4;
        }
        continue;
      }
      var key = (b1 << 8) | b2;
      var pair = pairs.get(key);
      if (pair !== undefined) {
        out.push(pair);
        i += 2;
        continue;
      }
      var length = twoByteErrors.has(key) ? 2 : 1;
      out.fail(i, length, "illegal multibyte sequence");
      i += length;
    }
    return out.text();
  }

  function decodeHz(bytes, mode) {
    var out = new Output("hz", bytes, mode);
    var gb = table("gb2312_iso");
    var n = bytes.length;
    var i = 0;
    var shifted = false;
    while (i < n) {
      var c = bytes[i];
      if (c === 0x7e) {
        if (i + 1 >= n) {
          out.fail(i, n - i, "incomplete multibyte sequence");
          break;
        }
        var c2 = bytes[i + 1];
        if (c2 === 0x7e && !shifted) {
          out.push("~");
          i += 2;
        } else if (c2 === 0x7b && !shifted) {
          shifted = true;
          i += 2;
        } else if (c2 === 0x7d && shifted) {
          shifted = false;
          i += 2;
        } else if (c2 === LF && !shifted) {
          i += 2;
        } else {
          out.fail(i, 1, "illegal multibyte sequence");
          i += 1;
        }
        continue;
      }
      if (c & 0x80) {
        out.fail(i, 1, "illegal multibyte sequence");
        i += 1;
        continue;
      }
      if (!shifted) {
        out.push(String.fromCharCode(c));
        i += 1;
        continue;
      }
      if (i + 1 >= n) {
        out.fail(i, n - i, "incomplete multibyte sequence");
        break;
      }
      var entry = gb.get((c << 8) | bytes[i + 1]);
      if (entry !== undefined) {
        out.push(entry);
        i += 2;
      } else {
        out.fail(i, 1, "illegal multibyte sequence");
        i += 1;
      }
    }
    return out.text();
  }

  function isEscEnd(c) {
    return (c >= 0x41 && c <= 0x5a) || c === 0x40;
  }

  function isIso2022Esc(c) {
    return c === 0x28 || c === 0x29 || c === 0x24 || c === 0x2e || c === 0x26;
  }

  function markOf(byte, dbcs) {
    return String.fromCharCode(byte) + (dbcs ? DBCS : "");
  }

  function processEscape(config, state, bytes, i, out) {
    var n = bytes.length;
    var esclen = 0;
    var j;
    for (j = 1; j < MAX_ESCSEQLEN; j += 1) {
      if (i + j >= n) {
        out.fail(i, n - i, "incomplete multibyte sequence");
        return -1;
      }
      var c = bytes[i + j];
      if (isEscEnd(c)) {
        esclen = j + 1;
        break;
      } else if (config.ext && i + j + 1 < n && c === 0x26 && bytes[i + j + 1] === 0x40) {
        j += 2;
      }
    }
    if (j >= MAX_ESCSEQLEN) {
      out.fail(i, 1, "illegal multibyte sequence");
      return 1;
    }
    var charset;
    var designation;
    if (esclen === 3) {
      if (bytes[i + 1] === 0x24) {
        charset = markOf(bytes[i + 2], true);
        designation = 0;
      } else {
        charset = markOf(bytes[i + 2], false);
        var second = bytes[i + 1];
        if (second === 0x28) designation = 0;
        else if (second === 0x29) designation = 1;
        else if (config.useG2 && second === 0x2e) designation = 2;
        else {
          out.fail(i, 3, "illegal multibyte sequence");
          return 3;
        }
      }
    } else if (esclen === 4) {
      if (bytes[i + 1] !== 0x24) {
        out.fail(i, 4, "illegal multibyte sequence");
        return 4;
      }
      charset = markOf(bytes[i + 3], true);
      var third = bytes[i + 2];
      if (third === 0x28) designation = 0;
      else if (third === 0x29) designation = 1;
      else {
        out.fail(i, 4, "illegal multibyte sequence");
        return 4;
      }
    } else if (esclen === 6) {
      if (config.ext && bytes[i + 3] === ESC && bytes[i + 4] === 0x24 && bytes[i + 5] === 0x42) {
        charset = "B" + DBCS;
        designation = 0;
      } else {
        out.fail(i, 6, "illegal multibyte sequence");
        return 6;
      }
    } else {
      out.fail(i, esclen, "illegal multibyte sequence");
      return esclen;
    }
    if (charset !== "B" && config.marks.indexOf(charset) < 0) {
      out.fail(i, esclen, "illegal multibyte sequence");
      return esclen;
    }
    state.g[designation] = charset;
    return esclen;
  }

  function decodeCharset(charset, bytes, i, out) {
    var c = bytes[i];
    if (charset === "J") {
      if (c === 0x5c) return { text: "¥", width: 1 };
      if (c === 0x7e) return { text: "‾", width: 1 };
      return { text: String.fromCharCode(c), width: 1 };
    }
    if (charset === "I") {
      if (c >= 0x21 && c <= 0x5f) return { text: String.fromCharCode(0xff40 + c), width: 1 };
      return { text: null, width: 1 };
    }
    if (charset === "A" || charset === "F") return { text: null, width: 1 };
    var name = CHARSET_TABLES[charset];
    if (!name) return { text: null, width: 1 };
    if (i + 1 >= bytes.length) return { text: null, width: 2, incomplete: true };
    var entry = table(name).get((c << 8) | bytes[i + 1]);
    return { text: entry === undefined ? null : entry, width: 2 };
  }

  function decodeIso2022(codec, bytes, mode) {
    var config = ISO2022_CODECS[codec];
    var out = new Output(codec, bytes, mode);
    var state = { g: ["B", "B", ""], shifted: false, escThroughout: false };
    var n = bytes.length;
    var i = 0;
    while (i < n) {
      var c = bytes[i];
      if (state.escThroughout) {
        out.push(String.fromCharCode(c));
        i += 1;
        if (isEscEnd(c)) state.escThroughout = false;
        continue;
      }
      if (c === ESC) {
        if (i + 1 >= n) {
          out.fail(i, n - i, "incomplete multibyte sequence");
          break;
        }
        var c2 = bytes[i + 1];
        if (isIso2022Esc(c2)) {
          var consumed = processEscape(config, state, bytes, i, out);
          if (consumed < 0) break;
          i += consumed;
        } else if (config.useG2 && c2 === 0x4e) {
          if (i + 2 >= n) {
            out.fail(i, n - i, "incomplete multibyte sequence");
            break;
          }
          var c3 = bytes[i + 2];
          var g2 = state.g[2];
          if (c3 >= 0x80) {
            out.fail(i, 3, "illegal multibyte sequence");
          } else if (g2 === "A") {
            out.push(String.fromCharCode(c3 | 0x80));
          } else if (g2 === "F") {
            var point = MT.codecs.singlePoint("iso8859_7", c3 | 0x80);
            if (point < 0) out.fail(i, 3, "illegal multibyte sequence");
            else out.push(String.fromCharCode(point));
          } else {
            out.push(String.fromCharCode(c3));
          }
          i += 3;
        } else {
          out.push(String.fromCharCode(ESC));
          state.escThroughout = true;
          i += 1;
        }
        continue;
      }
      if (c === SI && !config.noShift) {
        state.shifted = false;
        i += 1;
        continue;
      }
      if (c === SO && !config.noShift) {
        state.shifted = true;
        i += 1;
        continue;
      }
      if (c === LF) {
        state.shifted = false;
        out.push("\n");
        i += 1;
        continue;
      }
      if (c < 0x20) {
        out.push(String.fromCharCode(c));
        i += 1;
        continue;
      }
      if (c >= 0x80) {
        out.fail(i, 1, "illegal multibyte sequence");
        i += 1;
        continue;
      }
      var charset = state.shifted ? state.g[1] : state.g[0];
      if (charset === "B" || charset === "") {
        out.push(String.fromCharCode(c));
        i += 1;
        continue;
      }
      var decoded = decodeCharset(charset, bytes, i, out);
      if (decoded.incomplete) {
        out.fail(i, n - i, "incomplete multibyte sequence");
        break;
      }
      if (decoded.text === null) {
        out.fail(i, decoded.width, "illegal multibyte sequence");
      } else {
        out.push(decoded.text);
      }
      i += decoded.width;
    }
    return out.text();
  }

  function decode(codec, bytes, mode) {
    if (MT.own(DBCS_CODECS, codec)) return decodeDbcs(codec, bytes, mode);
    if (MT.own(ISO2022_CODECS, codec)) return decodeIso2022(codec, bytes, mode);
    if (codec === "hz") return decodeHz(bytes, mode);
    throw new MT.codecs.LookupError("unknown encoding: " + codec);
  }

  function encodeSpec(codec) {
    return blob().encode[codec] || { overrides: [], pairs: [], removed: [] };
  }

  function setDefault(target, key, value) {
    if (!target.has(key)) target.set(key, value);
  }

  function applyOverrides(entry, spec, iso) {
    spec.removed.forEach(function (text) {
      entry.map.delete(text);
      entry.pairs.delete(text);
    });
    spec.overrides.forEach(function (item) {
      entry.map.set(item[0], iso ? [item[1], item[2]] : item[1]);
    });
    spec.pairs.forEach(function (item) {
      entry.pairs.set(item[0], iso ? [item[1], item[2]] : item[1]);
    });
  }

  function forwardTable(codec) {
    if (MT.own(forwards, codec)) return forwards[codec];
    var entry = { map: new Map(), pairs: new Map() };
    if (codec === "hz") {
      var gb = table("gb2312_iso");
      sortedKeys(gb).forEach(function (key) {
        setDefault(entry.map, gb.get(key), [key >> 8, key & 0xff]);
      });
    } else {
      var spec = DBCS_CODECS[codec];
      var single = singleTable(codec);
      sortedKeys(single).forEach(function (byte) {
        setDefault(entry.map, single.get(byte), [byte]);
      });
      var sources = [[table(spec.table), 2]];
      if (spec.three) sources.push([table(spec.three), 3]);
      sources.forEach(function (source) {
        var map = source[0];
        var width = source[1];
        sortedKeys(map).forEach(function (key) {
          var text = map.get(key);
          var bytes = width === 3 ? [0x8f, key >> 8, key & 0xff] : [key >> 8, key & 0xff];
          setDefault(isSinglePoint(text) ? entry.map : entry.pairs, text, bytes);
        });
      });
    }
    applyOverrides(entry, encodeSpec(codec), false);
    forwards[codec] = entry;
    return entry;
  }

  function isoForward(codec) {
    if (MT.own(isoForwards, codec)) return isoForwards[codec];
    var entry = { map: new Map(), pairs: new Map() };
    var spec = encodeSpec(codec);
    (spec.order || []).forEach(function (mark) {
      if (mark === "J") {
        setDefault(entry.map, "¥", ["J", [0x5c]]);
        setDefault(entry.map, "‾", ["J", [0x7e]]);
        return;
      }
      if (mark === "I") {
        for (var code = 0xff61; code < 0xffa0; code += 1) setDefault(entry.map, String.fromCharCode(code), ["I", [code - 0xff40]]);
        return;
      }
      var map = table(CHARSET_TABLES[mark]);
      sortedKeys(map).forEach(function (key) {
        var text = map.get(key);
        setDefault(isSinglePoint(text) ? entry.map : entry.pairs, text, [mark, [key >> 8, key & 0xff]]);
      });
    });
    applyOverrides(entry, spec, true);
    isoForwards[codec] = entry;
    return entry;
  }

  function gb18030Four(point) {
    if (point >= 0xd800 && point <= 0xdfff) return null;
    var linear;
    var lead;
    if (point >= 0x10000) {
      linear = point - 0x10000;
      lead = 0x90 + Math.floor(linear / 12600);
    } else {
      var ranges = blob().gb18030_ranges;
      linear = -1;
      for (var i = 0; i < ranges.length; i += 1) {
        var entry = ranges[i];
        if (point >= entry[1] && point < entry[1] + entry[2]) {
          linear = entry[0] + (point - entry[1]);
          break;
        }
      }
      if (linear < 0) return null;
      lead = 0x81 + Math.floor(linear / 12600);
    }
    var rest = linear % 12600;
    return [lead, 0x30 + Math.floor(rest / 1260), 0x81 + Math.floor((rest % 1260) / 10), 0x30 + (rest % 10)];
  }

  function jamoEncode(point) {
    if (point < 0xac00 || point > 0xd7a3) return null;
    if (jamoReverse === null) {
      jamoReverse = { cho: {}, jung: {}, jong: { 0: 0xd4 } };
      ["cho", "jung", "jong"].forEach(function (kind) {
        var source = blob().jamo[kind];
        Object.keys(source).forEach(function (byte) {
          jamoReverse[kind][source[byte]] = Number(byte);
        });
      });
    }
    var offset = point - 0xac00;
    var cho = jamoReverse.cho[Math.floor(offset / 588)];
    var jung = jamoReverse.jung[Math.floor((offset % 588) / 28)];
    var jong = jamoReverse.jong[offset % 28];
    if (cho === undefined || jung === undefined || jong === undefined) return null;
    return [0xa4, 0xd4, 0xa4, cho, 0xa4, jung, 0xa4, jong];
  }

  function failEncode(out, point, mode, position, codec) {
    if (mode === "surrogateescape" && point >= 0xdc80 && point <= 0xdcff) {
      out.push(point - 0xdc00);
      return;
    }
    if (mode === "ignore") return;
    if (mode === "replace") {
      out.push(0x3f);
      return;
    }
    throw new MT.codecs.EncodeError(codec + ": character U+" + point.toString(16) + " at position " + position + " cannot be encoded");
  }

  function pushAll(out, bytes) {
    for (var i = 0; i < bytes.length; i += 1) out.push(bytes[i]);
  }

  function encodeDbcs(codec, text, mode) {
    var spec = DBCS_CODECS[codec];
    var entry = forwardTable(codec);
    var points = MT.codecs.codePoints(text);
    var out = [];
    var i = 0;
    while (i < points.length) {
      var ch = fromPoint(points[i]);
      if (entry.pairs.size && i + 1 < points.length) {
        var pair = entry.pairs.get(ch + fromPoint(points[i + 1]));
        if (pair !== undefined) {
          pushAll(out, pair);
          i += 2;
          continue;
        }
      }
      var bytes = entry.map.get(ch);
      if (bytes === undefined && spec.gb18030) bytes = gb18030Four(points[i]);
      if (bytes === undefined && spec.jamo) bytes = jamoEncode(points[i]);
      if (bytes === undefined || bytes === null) failEncode(out, points[i], mode, i, codec);
      else pushAll(out, bytes);
      i += 1;
    }
    return new Uint8Array(out);
  }

  function designation(mark) {
    if (mark === "J") return [ESC, 0x28, 0x4a];
    if (mark === "I") return [ESC, 0x28, 0x49];
    var letter = mark.charCodeAt(0);
    if (letter === 0x40 || letter === 0x42) return [ESC, 0x24, letter];
    return [ESC, 0x24, 0x28, letter];
  }

  function encodeIso2022(codec, text, mode) {
    var config = ISO2022_CODECS[codec];
    var entry = isoForward(codec);
    var points = MT.codecs.codePoints(text);
    var out = [];
    var g0 = "B";
    var designated = false;
    var shifted = false;
    var i = 0;
    while (i < points.length) {
      var point = points[i];
      if (point < 0x80) {
        if (config.noShift) {
          if (g0 !== "B") {
            pushAll(out, [ESC, 0x28, 0x42]);
            g0 = "B";
          }
        } else if (shifted) {
          out.push(SI);
          shifted = false;
        }
        out.push(point);
        i += 1;
        continue;
      }
      var ch = fromPoint(point);
      var found = null;
      var consumed = 1;
      if (entry.pairs.size && i + 1 < points.length) {
        var pair = entry.pairs.get(ch + fromPoint(points[i + 1]));
        if (pair !== undefined) {
          found = pair;
          consumed = 2;
        }
      }
      if (found === null) found = entry.map.get(ch) || null;
      if (found === null) {
        failEncode(out, point, mode, i, codec);
        i += 1;
        continue;
      }
      var mark = found[0];
      if (config.noShift) {
        if (g0 !== mark) {
          pushAll(out, designation(mark));
          g0 = mark;
        }
      } else {
        if (!designated) {
          pushAll(out, [ESC, 0x24, 0x29, mark.charCodeAt(0)]);
          designated = true;
        }
        if (!shifted) {
          out.push(SO);
          shifted = true;
        }
      }
      pushAll(out, found[1]);
      i += consumed;
    }
    if (config.noShift) {
      if (g0 !== "B") pushAll(out, [ESC, 0x28, 0x42]);
    } else if (shifted) {
      out.push(SI);
    }
    return new Uint8Array(out);
  }

  function encodeHz(text, mode) {
    var entry = forwardTable("hz");
    var points = MT.codecs.codePoints(text);
    var out = [];
    var gb = false;
    for (var i = 0; i < points.length; i += 1) {
      var point = points[i];
      if (point < 0x80) {
        if (gb) {
          out.push(0x7e, 0x7d);
          gb = false;
        }
        if (point === 0x7e) out.push(0x7e, 0x7e);
        else out.push(point);
        continue;
      }
      var bytes = entry.map.get(fromPoint(point));
      if (bytes === undefined) {
        failEncode(out, point, mode, i, "hz");
        continue;
      }
      if (!gb) {
        out.push(0x7e, 0x7b);
        gb = true;
      }
      pushAll(out, bytes);
    }
    if (gb) out.push(0x7e, 0x7d);
    return new Uint8Array(out);
  }

  function encode(codec, text, mode) {
    var errors = mode || "strict";
    if (MT.own(DBCS_CODECS, codec)) return encodeDbcs(codec, text, errors);
    if (MT.own(ISO2022_CODECS, codec)) return encodeIso2022(codec, text, errors);
    if (codec === "hz") return encodeHz(text, errors);
    throw new MT.codecs.LookupError("unknown encoding: " + codec);
  }

  function supports(codec) {
    return MT.own(DBCS_CODECS, codec) || MT.own(ISO2022_CODECS, codec) || codec === "hz";
  }

  MT.cjk = {
    decode: decode,
    encode: encode,
    supports: supports,
    table: table,
  };
})(MT);
