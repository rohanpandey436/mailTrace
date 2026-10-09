var MT = MT || {};

(function (MT) {
  var FLAG_I = 2;
  var FLAG_M = 8;
  var FLAG_S = 16;
  var FLAG_X = 64;
  var FLAG_A = 256;

  var WORD = "\\p{L}\\p{N}_";
  var WORD_ASCII = "A-Za-z0-9_";
  var DIGIT = "\\p{Nd}";
  var DIGIT_ASCII = "0-9";
  var SPACE = "\\t\\n\\r\\f\\v \\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
  var SPACE_ASCII = "\\t\\n\\r\\f\\v ";
  var SYNTAX = "^$\\.*+?()[]{}|/";
  var WHITESPACE = " \t\n\r\f\v";

  function hex(code) {
    return "\\u{" + code.toString(16) + "}";
  }

  function translate(pattern, flags) {
    var ascii = (flags & FLAG_A) !== 0;
    var multiline = (flags & FLAG_M) !== 0;
    var dotall = (flags & FLAG_S) !== 0;
    var verbose = (flags & FLAG_X) !== 0;
    var ignore = (flags & FLAG_I) !== 0;
    var word = ascii ? WORD_ASCII : WORD;
    var digit = ascii ? DIGIT_ASCII : DIGIT;
    var space = ascii ? SPACE_ASCII : SPACE;
    var out = [];
    var inClass = false;
    var classStart = false;
    var i = 0;
    var length = pattern.length;

    function escaped(ch) {
      if (ch === "w") return inClass ? word : "[" + word + "]";
      if (ch === "d") return inClass ? digit : ascii ? "[0-9]" : DIGIT;
      if (ch === "s") return inClass ? space : "[" + space + "]";
      if (ch === "W" || ch === "D" || ch === "S") {
        if (inClass) throw new Error("negated shorthand inside a character class is not supported: " + pattern);
        return "[^" + (ch === "W" ? word : ch === "D" ? digit : space) + "]";
      }
      if (ch === "b") {
        if (inClass) return "\\x08";
        return "(?:(?<=[" + word + "])(?![" + word + "])|(?<![" + word + "])(?=[" + word + "]))";
      }
      if (ch === "B") {
        return "(?:(?<=[" + word + "])(?=[" + word + "])|(?<![" + word + "])(?![" + word + "]))";
      }
      if (ch === "A") return "(?<![\\s\\S])";
      if (ch === "Z") return "(?![\\s\\S])";
      if (ch === "a") return "\\x07";
      if (ch === "n" || ch === "t" || ch === "r" || ch === "f" || ch === "v") return "\\" + ch;
      return null;
    }

    while (i < length) {
      var ch = pattern[i];
      if (ch === "\\") {
        var next = pattern[i + 1];
        if (next === undefined) throw new Error("dangling backslash in " + pattern);
        var special = escaped(next);
        if (special !== null) {
          out.push(special);
          i += 2;
          classStart = false;
          continue;
        }
        if (next === "x") {
          out.push("\\x" + pattern.substr(i + 2, 2));
          i += 4;
        } else if (next === "u") {
          out.push("\\u" + pattern.substr(i + 2, 4));
          i += 6;
        } else if (next === "U") {
          out.push(hex(parseInt(pattern.substr(i + 2, 8), 16)));
          i += 10;
        } else if (next >= "0" && next <= "9") {
          var digits = /^[0-9]{1,3}/.exec(pattern.substr(i + 1))[0];
          var octal = /^[0-7]{3}$/.test(digits) || (next === "0" && /^[0-7]+$/.test(digits));
          if (inClass || octal) {
            var oct = /^[0-7]{1,3}/.exec(pattern.substr(i + 1))[0];
            out.push(hex(parseInt(oct, 8)));
            i += 1 + oct.length;
          } else {
            var ref = /^[1-9][0-9]?/.exec(pattern.substr(i + 1))[0];
            out.push("\\" + ref);
            i += 1 + ref.length;
          }
        } else if (SYNTAX.indexOf(next) >= 0) {
          out.push("\\" + next);
          i += 2;
        } else if (next === "-") {
          out.push(inClass ? "\\-" : "-");
          i += 2;
        } else {
          out.push(hex(pattern.codePointAt(i + 1)));
          i += 1 + String.fromCodePoint(pattern.codePointAt(i + 1)).length;
        }
        classStart = false;
        continue;
      }
      if (inClass) {
        if (ch === "]" && !classStart) {
          inClass = false;
          out.push("]");
        } else if (ch === "[") {
          out.push("\\[");
        } else if (ch === "]") {
          out.push("\\]");
        } else {
          out.push(ch);
        }
        classStart = false;
        i += 1;
        continue;
      }
      if (verbose) {
        if (WHITESPACE.indexOf(ch) >= 0) {
          i += 1;
          continue;
        }
        if (ch === "#") {
          while (i < length && pattern[i] !== "\n") i += 1;
          continue;
        }
      }
      if (ch === "[") {
        inClass = true;
        out.push("[");
        i += 1;
        if (pattern[i] === "^") {
          out.push("^");
          i += 1;
        }
        classStart = true;
        continue;
      }
      if (ch === "(" && pattern[i + 1] === "?") {
        var rest = pattern.substr(i + 2, 40);
        var named = /^P<([A-Za-z_][A-Za-z0-9_]*)>/.exec(rest);
        var back = /^P=([A-Za-z_][A-Za-z0-9_]*)\)/.exec(rest);
        var inline = /^([aiLmsux]+)\)/.exec(rest);
        if (named) {
          out.push("(?<" + named[1] + ">");
          i += 2 + named[0].length;
          continue;
        }
        if (back) {
          out.push("\\k<" + back[1] + ">");
          i += 2 + back[0].length;
          continue;
        }
        if (inline) {
          if (inline[1].indexOf("i") >= 0) ignore = true;
          if (inline[1].indexOf("s") >= 0) dotall = true;
          if (inline[1].indexOf("m") >= 0) multiline = true;
          if (inline[1].indexOf("x") >= 0) verbose = true;
          i += 2 + inline[0].length;
          continue;
        }
        if (rest[0] === "#") {
          while (i < length && pattern[i] !== ")") i += 1;
          i += 1;
          continue;
        }
        if (rest[0] === ">" || /^[aiLmsux-]+:/.test(rest)) {
          throw new Error("unsupported group in " + pattern);
        }
        out.push("(?");
        i += 2;
        continue;
      }
      if (ch === ".") {
        out.push(dotall ? "[\\s\\S]" : "[^\\n]");
      } else if (ch === "^") {
        out.push(multiline ? "(?:(?<![\\s\\S])|(?<=\\n))" : "(?<![\\s\\S])");
      } else if (ch === "$") {
        out.push(multiline ? "(?=\\n|(?![\\s\\S]))" : "(?=\\n?(?![\\s\\S]))");
      } else if (ch === "{") {
        var open = /^\{,([0-9]+)\}/.exec(pattern.substr(i, 12));
        var quantifier = /^\{[0-9]+(,[0-9]*)?\}/.exec(pattern.substr(i, 24));
        if (open) {
          out.push("{0," + open[1] + "}");
          i += open[0].length;
          continue;
        }
        if (quantifier) {
          out.push(quantifier[0]);
          i += quantifier[0].length;
          continue;
        }
        out.push("\\{");
      } else if (ch === "}") {
        out.push("\\}");
      } else if (ch === "]") {
        out.push("\\]");
      } else if (ch === "/") {
        out.push("\\/");
      } else {
        out.push(ch);
      }
      i += 1;
    }
    if (inClass) throw new Error("unterminated character class in " + pattern);
    return { source: out.join(""), flags: "u" + (ignore ? "i" : "") };
  }

  function Pattern(pattern, flags) {
    var translated = translate(pattern, flags || 0);
    this.pattern = pattern;
    this.source = translated.source;
    this.flags = translated.flags;
    this.global = new RegExp(this.source, this.flags + "g");
    this.sticky = new RegExp(this.source, this.flags + "y");
  }

  function wrap(found, text) {
    if (!found) return null;
    found.start = found.index;
    found.end = found.index + found[0].length;
    found.text = text;
    return found;
  }

  Pattern.prototype.search = function (text, position) {
    this.global.lastIndex = position || 0;
    return wrap(this.global.exec(text), text);
  };

  Pattern.prototype.match = function (text, position) {
    this.sticky.lastIndex = position || 0;
    return wrap(this.sticky.exec(text), text);
  };

  Pattern.prototype.fullmatch = function (text) {
    var found = this.match(text, 0);
    if (found && found.end === text.length) return found;
    if (!found) return null;
    var anchored = new RegExp("(?:" + this.source + ")(?![\\s\\S])", this.flags + "y");
    anchored.lastIndex = 0;
    return wrap(anchored.exec(text), text);
  };

  Pattern.prototype.test = function (text) {
    return this.search(text, 0) !== null;
  };

  Pattern.prototype.finditer = function (text) {
    var results = [];
    var regex = this.global;
    regex.lastIndex = 0;
    var found = regex.exec(text);
    while (found) {
      results.push(wrap(found, text));
      if (found[0].length === 0) {
        var code = text.codePointAt(regex.lastIndex);
        regex.lastIndex += code !== undefined && code > 0xffff ? 2 : 1;
        if (regex.lastIndex > text.length) break;
      }
      found = regex.exec(text);
    }
    return results;
  };

  Pattern.prototype.findall = function (text) {
    return this.finditer(text).map(function (found) {
      if (found.length === 1) return found[0];
      if (found.length === 2) return found[1] === undefined ? "" : found[1];
      return Array.prototype.slice.call(found, 1).map(function (group) {
        return group === undefined ? "" : group;
      });
    });
  };

  Pattern.prototype.sub = function (replacement, text, count) {
    var matches = this.finditer(text);
    if (count) matches = matches.slice(0, count);
    var out = [];
    var last = 0;
    matches.forEach(function (found) {
      out.push(text.slice(last, found.start));
      out.push(typeof replacement === "function" ? replacement(found) : replacement);
      last = found.end;
    });
    out.push(text.slice(last));
    return out.join("");
  };

  Pattern.prototype.split = function (text, maxsplit) {
    var matches = this.finditer(text).filter(function (found) {
      return true;
    });
    if (maxsplit) matches = matches.slice(0, maxsplit);
    var out = [];
    var last = 0;
    matches.forEach(function (found) {
      out.push(text.slice(last, found.start));
      for (var g = 1; g < found.length; g += 1) out.push(found[g] === undefined ? null : found[g]);
      last = found.end;
    });
    out.push(text.slice(last));
    return out;
  };

  var cache = new Map();

  function re(pattern, flags) {
    var key = (flags || 0) + ":" + pattern;
    var found = cache.get(key);
    if (!found) {
      found = new Pattern(pattern, flags || 0);
      cache.set(key, found);
    }
    return found;
  }

  function reEscape(text) {
    return text.replace(/[()[\]{}?*+\-|^$\\.&~# \t\n\r\v\f]/g, "\\$&");
  }

  var PY_SPACE = new RegExp("[" + SPACE + "]");

  function isSpace(ch) {
    return PY_SPACE.test(ch);
  }

  function lstrip(text, chars) {
    var i = 0;
    if (chars === undefined) {
      while (i < text.length && isSpace(text[i])) i += 1;
    } else {
      while (i < text.length && chars.indexOf(text[i]) >= 0) i += 1;
    }
    return text.slice(i);
  }

  function rstrip(text, chars) {
    var i = text.length;
    if (chars === undefined) {
      while (i > 0 && isSpace(text[i - 1])) i -= 1;
    } else {
      while (i > 0 && chars.indexOf(text[i - 1]) >= 0) i -= 1;
    }
    return text.slice(0, i);
  }

  function strip(text, chars) {
    return lstrip(rstrip(text, chars), chars);
  }

  function splitSpace(text, maxsplit) {
    var out = [];
    var i = 0;
    var length = text.length;
    var limit = maxsplit === undefined ? -1 : maxsplit;
    while (i < length) {
      while (i < length && isSpace(text[i])) i += 1;
      if (i >= length) break;
      if (limit >= 0 && out.length >= limit) {
        out.push(rstrip(text.slice(i)));
        return out;
      }
      var start = i;
      while (i < length && !isSpace(text[i])) i += 1;
      out.push(text.slice(start, i));
    }
    return out;
  }

  function split(text, separator, maxsplit) {
    if (separator === undefined || separator === null) return splitSpace(text, maxsplit);
    var limit = maxsplit === undefined ? -1 : maxsplit;
    var out = [];
    var position = 0;
    while (limit < 0 || out.length < limit) {
      var index = text.indexOf(separator, position);
      if (index < 0) break;
      out.push(text.slice(position, index));
      position = index + separator.length;
    }
    out.push(text.slice(position));
    return out;
  }

  function rsplit(text, separator, maxsplit) {
    var limit = maxsplit === undefined ? -1 : maxsplit;
    var out = [];
    var end = text.length;
    while (limit < 0 || out.length < limit) {
      var index = text.lastIndexOf(separator, end - separator.length);
      if (index < 0 || end - separator.length < 0) break;
      out.unshift(text.slice(index + separator.length, end));
      end = index;
    }
    out.unshift(text.slice(0, end));
    return out;
  }

  function partition(text, separator) {
    var index = text.indexOf(separator);
    if (index < 0) return [text, "", ""];
    return [text.slice(0, index), separator, text.slice(index + separator.length)];
  }

  function rpartition(text, separator) {
    var index = text.lastIndexOf(separator);
    if (index < 0) return ["", "", text];
    return [text.slice(0, index), separator, text.slice(index + separator.length)];
  }

  function bound(index, size, fallback) {
    if (index === undefined || index === null) return fallback;
    if (index < 0) return Math.max(0, size + index);
    return Math.min(index, size);
  }

  function count(text, needle, start, end) {
    var from = bound(start, text.length, 0);
    var to = bound(end, text.length, text.length);
    if (from > to) return 0;
    if (!needle) return to - from + 1;
    var total = 0;
    var position = text.indexOf(needle, from);
    while (position >= 0 && position + needle.length <= to) {
      total += 1;
      position = text.indexOf(needle, position + needle.length);
    }
    return total;
  }

  function find(text, needle, start, end) {
    var from = bound(start, text.length, 0);
    var to = bound(end, text.length, text.length);
    if (from > to) return -1;
    if (start !== undefined && start !== null && start > text.length) return -1;
    var position = text.indexOf(needle, from);
    if (position < 0 || position + needle.length > to) return -1;
    return position;
  }

  var LINE_BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85" + String.fromCharCode(0x2028, 0x2029);

  function splitlines(text, keepends) {
    var out = [];
    var start = 0;
    var i = 0;
    var length = text.length;
    while (i < length) {
      var ch = text[i];
      if (LINE_BREAKS.indexOf(ch) < 0) {
        i += 1;
        continue;
      }
      var end = i;
      i += ch === "\r" && text[i + 1] === "\n" ? 2 : 1;
      out.push(text.slice(start, keepends ? i : end));
      start = i;
    }
    if (start < length) out.push(text.slice(start));
    return out;
  }

  function isSpaceText(text) {
    if (!text) return false;
    for (var i = 0; i < text.length; i += 1) if (!isSpace(text[i])) return false;
    return true;
  }

  var NUMERAL = /^\p{Nd}$/u;

  function digitValue(point) {
    if (point >= 48 && point <= 57) return point - 48;
    if (point < 128 || !NUMERAL.test(String.fromCodePoint(point))) return -1;
    var first = point;
    while (first > 0 && NUMERAL.test(String.fromCodePoint(first - 1))) first -= 1;
    return (point - first) % 10;
  }

  function inRanges(table, point) {
    var low = 0;
    var high = table.length - 1;
    while (low <= high) {
      var middle = (low + high) >> 1;
      if (point < table[middle][0]) {
        high = middle - 1;
      } else if (point > table[middle][1]) {
        low = middle + 1;
      } else {
        return true;
      }
    }
    return false;
  }

  function everyIn(name, text) {
    if (!text) return false;
    var table = MT.json("knowledge").unicode[name];
    for (var i = 0; i < text.length; i += 1) {
      var point = text.codePointAt(i);
      if (point > 0xffff) i += 1;
      if (point < 128) {
        var digit = point >= 48 && point <= 57;
        var letter = (point >= 65 && point <= 90) || (point >= 97 && point <= 122);
        if (name === "digit" ? !digit : name === "alpha" ? !letter : !(digit || letter)) return false;
      } else if (!inRanges(table, point)) {
        return false;
      }
    }
    return true;
  }

  function isDigit(text) {
    return everyIn("digit", text);
  }

  function toInt(text) {
    var body = strip(String(text));
    var sign = 1;
    if (body[0] === "+" || body[0] === "-") {
      if (body[0] === "-") sign = -1;
      body = body.slice(1);
    }
    if (!body) return null;
    var value = 0;
    var previousDigit = false;
    var list = points(body);
    for (var i = 0; i < list.length; i += 1) {
      if (list[i] === "_") {
        if (!previousDigit || i === list.length - 1) return null;
        previousDigit = false;
        continue;
      }
      var digit = digitValue(list[i].codePointAt(0));
      if (digit < 0) return null;
      value = value * 10 + digit;
      previousDigit = true;
    }
    if (!previousDigit) return null;
    return sign * value === 0 ? 0 : sign * value;
  }

  function replaceAll(text, needle, replacement) {
    return needle ? text.split(needle).join(replacement) : text;
  }

  function joinWords(text) {
    return splitSpace(text).join(" ");
  }

  function points(text) {
    return Array.from(text);
  }

  function length(text) {
    var total = 0;
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
        var next = text.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) i += 1;
      }
      total += 1;
    }
    return total;
  }

  function slice(text, start, end) {
    if (text.length <= (end === undefined ? Infinity : end) && !start && !/[\ud800-\udbff]/.test(text)) return text;
    var list = points(text);
    return list.slice(start || 0, end === undefined ? list.length : end).join("");
  }

  function compare(a, b) {
    if (a === b) return 0;
    var i = 0;
    var j = 0;
    while (i < a.length && j < b.length) {
      var x = a.codePointAt(i);
      var y = b.codePointAt(j);
      if (x !== y) return x < y ? -1 : 1;
      i += x > 0xffff ? 2 : 1;
      j += y > 0xffff ? 2 : 1;
    }
    if (i >= a.length && j >= b.length) return 0;
    return i >= a.length ? -1 : 1;
  }

  function sorted(list, key) {
    var decorated = list.map(function (item, index) {
      return { item: item, key: key ? key(item) : item, index: index };
    });
    decorated.sort(function (left, right) {
      var order = compareKeys(left.key, right.key);
      return order !== 0 ? order : left.index - right.index;
    });
    return decorated.map(function (entry) {
      return entry.item;
    });
  }

  function compareKeys(a, b) {
    if (Array.isArray(a) && Array.isArray(b)) {
      for (var i = 0; i < Math.min(a.length, b.length); i += 1) {
        var order = compareKeys(a[i], b[i]);
        if (order !== 0) return order;
      }
      return a.length - b.length;
    }
    if (typeof a === "string" && typeof b === "string") return compare(a, b);
    if (a === b) return 0;
    return a < b ? -1 : 1;
  }

  function unique(list) {
    var seen = new Set();
    var out = [];
    list.forEach(function (item) {
      if (!seen.has(item)) {
        seen.add(item);
        out.push(item);
      }
    });
    return out;
  }

  function exactDigits(value) {
    var text = Math.abs(value).toFixed(100);
    var dot = text.indexOf(".");
    return { whole: text.slice(0, dot), fraction: text.slice(dot + 1) };
  }

  function increment(digits) {
    var list = digits.split("");
    var i = list.length - 1;
    while (i >= 0) {
      if (list[i] === "9") {
        list[i] = "0";
        i -= 1;
      } else {
        list[i] = String(Number(list[i]) + 1);
        return list.join("");
      }
    }
    return "1" + list.join("");
  }

  function fixed(value, places) {
    if (typeof value !== "number" || !isFinite(value)) {
      if (value !== value) return "nan";
      return value > 0 ? "inf" : "-inf";
    }
    if (Math.abs(value) >= 1e21) return String(value);
    var parts = exactDigits(value);
    var kept = parts.whole + parts.fraction.slice(0, places);
    var rest = parts.fraction.slice(places);
    var first = rest.charCodeAt(0) - 48;
    var tail = /[1-9]/.test(rest.slice(1));
    var roundUp = first > 5 || (first === 5 && (tail || (kept.charCodeAt(kept.length - 1) - 48) % 2 === 1));
    if (roundUp) {
      var grown = increment(kept);
      if (grown.length > kept.length) parts.whole = grown.slice(0, grown.length - places);
      kept = grown;
    }
    var wholeLength = kept.length - places;
    var whole = kept.slice(0, wholeLength);
    var fraction = kept.slice(wholeLength);
    var negative = value < 0 || (value === 0 && 1 / value < 0);
    var body = places > 0 ? whole + "." + fraction : whole;
    return (negative ? "-" : "") + body;
  }

  function signedFixed(value, places) {
    var text = fixed(value, places);
    return text[0] === "-" ? text : "+" + text;
  }

  function round(value, places) {
    if (typeof value !== "number" || !isFinite(value)) return value;
    var result = Number(fixed(value, places || 0));
    return result === 0 ? 0 : result;
  }

  function roundInt(value) {
    return round(value, 0);
  }

  function scientific(value, places) {
    if (value === 0) return (Object.is(value, -0) ? "-" : "") + "0." + "0".repeat(places) + "e+00";
    var text = value.toExponential(places + 30);
    var mantissa = text.slice(0, text.indexOf("e"));
    var exponent = Number(text.slice(text.indexOf("e") + 1));
    var digits = mantissa.replace("-", "").replace(".", "");
    var kept = digits.slice(0, places + 1);
    var rest = digits.slice(places + 1);
    var first = rest.charCodeAt(0) - 48;
    var tail = /[1-9]/.test(rest.slice(1));
    if (first > 5 || (first === 5 && (tail || (kept.charCodeAt(kept.length - 1) - 48) % 2 === 1))) {
      var grown = increment(kept);
      if (grown.length > kept.length) {
        grown = grown.slice(0, kept.length);
        exponent += 1;
      }
      kept = grown;
    }
    var sign = exponent < 0 ? "-" : "+";
    var magnitude = String(Math.abs(exponent));
    if (magnitude.length < 2) magnitude = "0" + magnitude;
    return (value < 0 ? "-" : "") + kept[0] + (places > 0 ? "." + kept.slice(1) : "") + "e" + sign + magnitude;
  }

  function repr(value) {
    if (typeof value !== "number") return String(value);
    if (value !== value) return "nan";
    if (!isFinite(value)) return value > 0 ? "inf" : "-inf";
    if (Object.is(value, -0)) return "-0.0";
    if (Number.isInteger(value) && Math.abs(value) < 1e16) return value.toFixed(1);
    var text = String(value);
    var found = /^(-?)(\d)(?:\.(\d+))?e([+-])(\d+)$/.exec(text);
    if (!found) {
      var magnitude = Math.abs(value);
      if (magnitude < 1e-4) {
        var exp = value.toExponential();
        var parsed = /^(-?)(\d)(?:\.(\d+))?e([+-])(\d+)$/.exec(exp);
        var digits2 = parsed[5].length < 2 ? "0" + parsed[5] : parsed[5];
        return parsed[1] + parsed[2] + (parsed[3] ? "." + parsed[3] : "") + "e" + parsed[4] + digits2;
      }
      return text;
    }
    var digits = found[5].length < 2 ? "0" + found[5] : found[5];
    return found[1] + found[2] + (found[3] ? "." + found[3] : "") + "e" + found[4] + digits;
  }

  var ALPHA = /^\p{L}$/u;
  var UPPER = /^\p{Lu}$/u;
  var LOWER = /^\p{Ll}$/u;
  var ALNUM = /^[\p{L}\p{N}]$/u;
  var DECIMAL = /^\p{Nd}$/u;

  function every(text, regex) {
    if (!text) return false;
    var list = points(text);
    for (var i = 0; i < list.length; i += 1) if (!regex.test(list[i])) return false;
    return true;
  }

  var CASED = /^\p{Cased}$/u;
  var CASE_IGNORABLE = /^\p{Case_Ignorable}$/u;
  var SIGMA = String.fromCharCode(0x3a3);
  var SMALL_SIGMA = String.fromCharCode(0x3c3);
  var FINAL_SIGMA = String.fromCharCode(0x3c2);
  var DIGRAPH_TITLES = {
    0x1c4: 0x1c5, 0x1c5: 0x1c5, 0x1c6: 0x1c5, 0x1c7: 0x1c8, 0x1c8: 0x1c8, 0x1c9: 0x1c8,
    0x1ca: 0x1cb, 0x1cb: 0x1cb, 0x1cc: 0x1cb, 0x1f1: 0x1f2, 0x1f2: 0x1f2, 0x1f3: 0x1f2,
  };

  function titleChar(ch) {
    var point = ch.codePointAt(0);
    if (Object.prototype.hasOwnProperty.call(DIGRAPH_TITLES, point)) return String.fromCharCode(DIGRAPH_TITLES[point]);
    var upper = points(ch.toUpperCase());
    if (upper.length > 1) return upper[0] + upper.slice(1).join("").toLowerCase();
    return upper.join("");
  }

  function lowerAt(list, index) {
    var ch = list[index];
    if (ch !== SIGMA) return ch.toLowerCase();
    var before = index - 1;
    while (before >= 0 && CASE_IGNORABLE.test(list[before])) before -= 1;
    var after = index + 1;
    while (after < list.length && CASE_IGNORABLE.test(list[after])) after += 1;
    var final = before >= 0 && CASED.test(list[before]) && !(after < list.length && CASED.test(list[after]));
    return final ? FINAL_SIGMA : SMALL_SIGMA;
  }

  function capitalize(text) {
    if (!text) return text;
    var list = points(text);
    var out = [titleChar(list[0])];
    for (var i = 1; i < list.length; i += 1) out.push(lowerAt(list, i));
    return out.join("");
  }

  function title(text) {
    var out = [];
    var previousCased = false;
    var list = points(text);
    list.forEach(function (ch, index) {
      out.push(previousCased ? lowerAt(list, index) : titleChar(ch));
      previousCased = CASED.test(ch);
    });
    return out.join("");
  }

  function normalize(text, form) {
    try {
      return text.normalize(form);
    } catch (error) {
      return text;
    }
  }

  MT.py = {
    re: re,
    reEscape: reEscape,
    translate: translate,
    isSpace: isSpace,
    strip: strip,
    lstrip: lstrip,
    rstrip: rstrip,
    split: split,
    rsplit: rsplit,
    partition: partition,
    rpartition: rpartition,
    count: count,
    find: find,
    splitlines: splitlines,
    isSpaceText: isSpaceText,
    digitValue: digitValue,
    isDigit: isDigit,
    inRanges: inRanges,
    toInt: toInt,
    replaceAll: replaceAll,
    joinWords: joinWords,
    points: points,
    length: length,
    slice: slice,
    compare: compare,
    compareKeys: compareKeys,
    sorted: sorted,
    unique: unique,
    fixed: fixed,
    signedFixed: signedFixed,
    round: round,
    roundInt: roundInt,
    scientific: scientific,
    repr: repr,
    isAlpha: function (text) {
      return everyIn("alpha", text);
    },
    isUpper: function (ch) {
      return UPPER.test(ch);
    },
    isLower: function (ch) {
      return LOWER.test(ch);
    },
    isAlnum: function (text) {
      return everyIn("alnum", text);
    },
    isDecimal: function (text) {
      return every(text, DECIMAL);
    },
    isAsciiDigits: function (text) {
      return /^[0-9]+$/.test(text);
    },
    capitalize: capitalize,
    title: title,
    normalize: normalize,
    FLAGS: { I: FLAG_I, M: FLAG_M, S: FLAG_S, X: FLAG_X, A: FLAG_A, U: 32 },
  };
})(MT);
