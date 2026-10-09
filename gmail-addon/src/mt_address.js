var MT = MT || {};

(function (MT) {
  var SPECIALS = '()<>@,:;."[]';
  var LWS = " \t";
  var CR = "\r\n";
  var FWS = LWS + CR;
  var ATOM_ENDS = SPECIALS + LWS + CR;
  var PHRASE_ENDS = ATOM_ENDS.split(".").join("");
  var INVALID = "('', '')";

  var MONTHS = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december",
  ];
  var DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
  var ZONES = {
    UT: 0, UTC: 0, GMT: 0, Z: 0, AST: -400, ADT: -300, EST: -500, EDT: -400, CST: -600, CDT: -500,
    MST: -700, MDT: -600, PST: -800, PDT: -700,
  };
  var MONTH_DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  var MIN_EPOCH = -62135596800;
  var MAX_EPOCH = 253402300799;

  function quote(text) {
    return MT.py.replaceAll(MT.py.replaceAll(text, "\\", "\\\\"), '"', '\\"');
  }

  function Parser(field) {
    this.pos = 0;
    this.field = field;
    this.comments = [];
  }

  Parser.prototype.more = function () {
    return this.pos < this.field.length;
  };

  Parser.prototype.at = function () {
    return this.field[this.pos];
  };

  Parser.prototype.gotoNext = function () {
    var spaces = [];
    while (this.more()) {
      var ch = this.at();
      if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
        if (ch !== "\n" && ch !== "\r") spaces.push(ch);
        this.pos += 1;
      } else if (ch === "(") {
        this.comments.push(this.getComment());
      } else {
        break;
      }
    }
    return spaces.join("");
  };

  Parser.prototype.getAddressList = function () {
    var result = [];
    while (this.more()) {
      var found = this.getAddress();
      if (found.length) {
        found.forEach(function (pair) {
          result.push(pair);
        });
      } else {
        result.push(["", ""]);
      }
    }
    return result;
  };

  Parser.prototype.getAddress = function () {
    this.comments = [];
    this.gotoNext();
    var oldPos = this.pos;
    var oldComments = this.comments;
    var phrases = this.getPhraseList();
    this.gotoNext();
    var result = [];
    if (!this.more()) {
      if (phrases.length) result = [[this.comments.join(" "), phrases[0]]];
    } else if (this.at() === "." || this.at() === "@") {
      this.pos = oldPos;
      this.comments = oldComments;
      var spec = this.getAddrSpec();
      result = [[this.comments.join(" "), spec]];
    } else if (this.at() === ":") {
      var length = this.field.length;
      this.pos += 1;
      while (this.more()) {
        this.gotoNext();
        if (this.pos < length && this.at() === ";") {
          this.pos += 1;
          break;
        }
        result = result.concat(this.getAddress());
      }
    } else if (this.at() === "<") {
      var route = this.getRouteAddr();
      if (this.comments.length) {
        result = [[phrases.join(" ") + " (" + this.comments.join(" ") + ")", route]];
      } else {
        result = [[phrases.join(" "), route]];
      }
    } else if (phrases.length) {
      result = [[this.comments.join(" "), phrases[0]]];
    } else if (SPECIALS.indexOf(this.at()) >= 0) {
      this.pos += 1;
    }
    this.gotoNext();
    if (this.more() && this.at() === ",") this.pos += 1;
    return result;
  };

  Parser.prototype.getRouteAddr = function () {
    if (this.at() !== "<") return null;
    var expectRoute = false;
    this.pos += 1;
    this.gotoNext();
    var list = "";
    while (this.more()) {
      if (expectRoute) {
        this.getDomain();
        expectRoute = false;
      } else if (this.at() === ">") {
        this.pos += 1;
        break;
      } else if (this.at() === "@") {
        this.pos += 1;
        expectRoute = true;
      } else if (this.at() === ":") {
        this.pos += 1;
      } else {
        list = this.getAddrSpec();
        this.pos += 1;
        break;
      }
      this.gotoNext();
    }
    return list;
  };

  function blank(text) {
    return !MT.py.strip(text);
  }

  Parser.prototype.getAddrSpec = function () {
    var list = [];
    this.gotoNext();
    while (this.more()) {
      var preserve = true;
      var ch = this.at();
      if (ch === ".") {
        if (list.length && blank(list[list.length - 1])) list.pop();
        list.push(".");
        this.pos += 1;
        preserve = false;
      } else if (ch === '"') {
        list.push('"' + quote(this.getQuote()) + '"');
      } else if (ATOM_ENDS.indexOf(ch) >= 0) {
        if (list.length && blank(list[list.length - 1])) list.pop();
        break;
      } else {
        list.push(this.getAtom());
      }
      var spaces = this.gotoNext();
      if (preserve && spaces) list.push(spaces);
    }
    if (!this.more() || this.at() !== "@") return list.join("");
    list.push("@");
    this.pos += 1;
    this.gotoNext();
    var domain = this.getDomain();
    if (!domain) return "";
    return list.join("") + domain;
  };

  Parser.prototype.getDomain = function () {
    var list = [];
    while (this.more()) {
      var ch = this.at();
      if (LWS.indexOf(ch) >= 0) {
        this.pos += 1;
      } else if (ch === "(") {
        this.comments.push(this.getComment());
      } else if (ch === "[") {
        list.push(this.getDomainLiteral());
      } else if (ch === ".") {
        this.pos += 1;
        list.push(".");
      } else if (ch === "@") {
        return "";
      } else if (ATOM_ENDS.indexOf(ch) >= 0) {
        break;
      } else {
        list.push(this.getAtom());
      }
    }
    return list.join("");
  };

  Parser.prototype.getDelimited = function (begin, ends, allowComments) {
    if (this.at() !== begin) return "";
    var list = [""];
    var quoted = false;
    this.pos += 1;
    while (this.more()) {
      var ch = this.at();
      if (quoted) {
        list.push(ch);
        quoted = false;
      } else if (ends.indexOf(ch) >= 0) {
        this.pos += 1;
        break;
      } else if (allowComments && ch === "(") {
        list.push(this.getComment());
        continue;
      } else if (ch === "\\") {
        quoted = true;
      } else {
        list.push(ch);
      }
      this.pos += 1;
    }
    return list.join("");
  };

  Parser.prototype.getQuote = function () {
    return this.getDelimited('"', '"\r', false);
  };

  Parser.prototype.getComment = function () {
    return this.getDelimited("(", ")\r", true);
  };

  Parser.prototype.getDomainLiteral = function () {
    return "[" + this.getDelimited("[", "]\r", false) + "]";
  };

  Parser.prototype.getAtom = function (ends) {
    var stops = ends === undefined ? ATOM_ENDS : ends;
    var start = this.pos;
    while (this.more() && stops.indexOf(this.at()) < 0) this.pos += 1;
    return this.field.slice(start, this.pos);
  };

  Parser.prototype.getPhraseList = function () {
    var list = [];
    while (this.more()) {
      var ch = this.at();
      if (FWS.indexOf(ch) >= 0) {
        this.pos += 1;
      } else if (ch === '"') {
        list.push(this.getQuote());
      } else if (ch === "(") {
        this.comments.push(this.getComment());
      } else if (PHRASE_ENDS.indexOf(ch) >= 0) {
        break;
      } else {
        list.push(this.getAtom(PHRASE_ENDS));
      }
    }
    return list;
  };

  function addressList(field) {
    if (!field) return [];
    return new Parser(field).getAddressList();
  }

  function escapedChars(text) {
    var out = [];
    var escape = false;
    var pos = 0;
    for (pos = 0; pos < text.length; pos += 1) {
      var ch = text[pos];
      if (escape) {
        out.push([pos, "\\" + ch]);
        escape = false;
      } else if (ch === "\\") {
        escape = true;
      } else {
        out.push([pos, ch]);
      }
    }
    if (escape) out.push([text.length - 1, "\\"]);
    return out;
  }

  function stripQuotedRealnames(text) {
    if (text.indexOf('"') < 0) return text;
    var start = 0;
    var open = null;
    var result = [];
    escapedChars(text).forEach(function (item) {
      if (item[1] !== '"') return;
      if (open === null) {
        open = item[0];
      } else {
        if (start !== open) result.push(text.slice(start, open));
        start = item[0] + 1;
        open = null;
      }
    });
    if (start < text.length) result.push(text.slice(start));
    return result.join("");
  }

  function checkParenthesis(text) {
    var opens = 0;
    var chars = escapedChars(stripQuotedRealnames(text));
    for (var i = 0; i < chars.length; i += 1) {
      if (chars[i][1] === "(") {
        opens += 1;
      } else if (chars[i][1] === ")") {
        opens -= 1;
        if (opens < 0) return false;
      }
    }
    return opens === 0;
  }

  function preValidate(value) {
    return checkParenthesis(value) ? value : INVALID;
  }

  function postValidate(pairs) {
    return pairs.map(function (pair) {
      return pair[1] !== null && pair[1].indexOf("[") >= 0 ? ["", ""] : pair;
    });
  }

  function parseaddr(value) {
    var pairs = postValidate(addressList(preValidate(value)));
    if (pairs.length !== 1) return ["", ""];
    return pairs[0];
  }

  function getaddresses(values) {
    var accepted = values.map(function (value) {
      return preValidate(String(value));
    });
    var result = postValidate(addressList(accepted.join(", ")));
    var expected = 0;
    accepted.forEach(function (value) {
      expected += 1 + MT.py.count(stripQuotedRealnames(value), ",");
    });
    if (result.length !== expected) return [["", ""]];
    return result;
  }

  function parseDateParts(text) {
    if (!text) return null;
    var data = MT.py.split(text);
    if (!data.length) return null;
    var i;
    if (data[0].slice(-1) === "," || DAYS.indexOf(data[0].toLowerCase()) >= 0) {
      data.shift();
    } else {
      i = data[0].lastIndexOf(",");
      if (i >= 0) data[0] = data[0].slice(i + 1);
    }
    if (data.length === 3) {
      var stuff = data[0].split("-");
      if (stuff.length === 3) data = stuff.concat(data.slice(1));
    }
    if (data.length === 4) {
      var s = data[3];
      i = s.indexOf("+");
      if (i === -1) i = s.indexOf("-");
      if (i > 0) {
        data.splice(3, 1, s.slice(0, i), s.slice(i));
      } else {
        data.push("");
      }
    }
    if (data.length < 5) return null;
    var dd = data[0];
    var mm = data[1];
    var yy = data[2];
    var tm = data[3];
    var tz = data[4];
    var swap;
    if (!(dd && mm && yy)) return null;
    mm = mm.toLowerCase();
    if (MONTHS.indexOf(mm) < 0) {
      swap = dd.toLowerCase();
      dd = mm;
      mm = swap;
      if (MONTHS.indexOf(mm) < 0) return null;
    }
    var month = MONTHS.indexOf(mm) + 1;
    if (month > 12) month -= 12;
    if (dd.slice(-1) === ",") dd = dd.slice(0, -1);
    i = yy.indexOf(":");
    if (i > 0) {
      swap = yy;
      yy = tm;
      tm = swap;
    }
    if (yy.slice(-1) === ",") {
      yy = yy.slice(0, -1);
      if (!yy) return null;
    }
    if (!yy) throw new RangeError("the year is empty");
    if (!MT.py.isDigit(MT.py.points(yy)[0])) {
      swap = yy;
      yy = tz;
      tz = swap;
    }
    if (!tm) throw new RangeError("the time is empty");
    if (tm.slice(-1) === ",") tm = tm.slice(0, -1);
    var pieces = tm.split(":");
    var thh;
    var tmm;
    var tss;
    if (pieces.length === 2) {
      thh = pieces[0];
      tmm = pieces[1];
      tss = "0";
    } else if (pieces.length === 3) {
      thh = pieces[0];
      tmm = pieces[1];
      tss = pieces[2];
    } else if (pieces.length === 1 && pieces[0].indexOf(".") >= 0) {
      pieces = pieces[0].split(".");
      if (pieces.length === 2) {
        thh = pieces[0];
        tmm = pieces[1];
        tss = "0";
      } else if (pieces.length === 3) {
        thh = pieces[0];
        tmm = pieces[1];
        tss = pieces[2];
      } else {
        return null;
      }
    } else {
      return null;
    }
    var year = MT.py.toInt(yy);
    var day = MT.py.toInt(dd);
    var hour = MT.py.toInt(thh);
    var minute = MT.py.toInt(tmm);
    var second = MT.py.toInt(tss);
    if (year === null || day === null || hour === null || minute === null || second === null) return null;
    if (year < 100) year += year > 68 ? 1900 : 2000;
    var offset = null;
    tz = tz.toUpperCase();
    if (MT.own(ZONES, tz)) {
      offset = ZONES[tz];
    } else {
      offset = MT.py.toInt(tz);
      if (offset === 0 && tz[0] === "-") offset = null;
    }
    if (offset) {
      var sign = offset < 0 ? -1 : 1;
      var magnitude = Math.abs(offset);
      offset = sign * (Math.floor(magnitude / 100) * 3600 + (magnitude % 100) * 60);
    }
    return { year: year, month: month, day: day, hour: hour, minute: minute, second: second, offset: offset };
  }

  function leap(year) {
    return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  }

  function daysBefore(year, month, day) {
    var y = month <= 2 ? year - 1 : year;
    var era = Math.floor(y / 400);
    var yoe = y - era * 400;
    var mp = (month + 9) % 12;
    var doy = Math.floor((153 * mp + 2) / 5) + day - 1;
    var doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
    return era * 146097 + doe - 719468;
  }

  function toEpoch(parts) {
    if (parts === null) return null;
    var safe = [parts.year, parts.month, parts.day, parts.hour, parts.minute, parts.second].every(function (value) {
      return Number.isFinite(value) && Math.abs(value) < 1e15;
    });
    if (!safe) return null;
    if (parts.year < 1 || parts.year > 9999) return null;
    if (parts.month < 1 || parts.month > 12) return null;
    var limit = parts.month === 2 && leap(parts.year) ? 29 : MONTH_DAYS[parts.month - 1];
    if (parts.day < 1 || parts.day > limit) return null;
    if (parts.hour < 0 || parts.hour > 23) return null;
    if (parts.minute < 0 || parts.minute > 59) return null;
    if (parts.second < 0 || parts.second > 59) return null;
    var offset = parts.offset === null ? 0 : parts.offset;
    if (!Number.isFinite(offset) || Math.abs(offset) >= 86400) return null;
    var epoch = daysBefore(parts.year, parts.month, parts.day) * 86400 + parts.hour * 3600 + parts.minute * 60 + parts.second - offset;
    if (epoch < MIN_EPOCH || epoch > MAX_EPOCH) return null;
    return epoch;
  }

  function parseDate(text) {
    var parts;
    try {
      parts = parseDateParts(text);
    } catch (error) {
      if (error instanceof RangeError) return null;
      throw error;
    }
    return toEpoch(parts);
  }

  function pad(value, width) {
    var text = String(value);
    while (text.length < width) text = "0" + text;
    return text;
  }

  function civil(epoch) {
    var days = Math.floor(epoch / 86400);
    var rest = epoch - days * 86400;
    var z = days + 719468;
    var era = Math.floor(z / 146097);
    var doe = z - era * 146097;
    var yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
    var doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
    var mp = Math.floor((5 * doy + 2) / 153);
    var day = doy - Math.floor((153 * mp + 2) / 5) + 1;
    var month = mp < 10 ? mp + 3 : mp - 9;
    var year = yoe + era * 400 + (month <= 2 ? 1 : 0);
    var whole = Math.floor(rest);
    return {
      year: year,
      month: month,
      day: day,
      hour: Math.floor(whole / 3600),
      minute: Math.floor((whole % 3600) / 60),
      second: whole % 60,
      fraction: rest - whole,
      weekday: (((days + 3) % 7) + 7) % 7,
    };
  }

  function iso(epoch) {
    if (epoch === null || epoch === undefined) return null;
    var c = civil(epoch);
    var text = pad(c.year, 4) + "-" + pad(c.month, 2) + "-" + pad(c.day, 2) + "T" + pad(c.hour, 2) + ":" + pad(c.minute, 2) + ":" + pad(c.second, 2);
    if (c.fraction > 0) {
      var micro = pad(Math.round(c.fraction * 1e6), 6);
      text += "." + micro;
    }
    return text + "Z";
  }

  function fromIso(text) {
    if (!text) return null;
    var found = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/.exec(text);
    if (!found) return null;
    var epoch =
      daysBefore(Number(found[1]), Number(found[2]), Number(found[3])) * 86400 +
      Number(found[4]) * 3600 +
      Number(found[5]) * 60 +
      Number(found[6]);
    if (found[7]) epoch += Number(found[7]);
    if (found[8] && found[8] !== "Z") {
      var sign = found[8][0] === "-" ? -1 : 1;
      var digits = found[8].slice(1).replace(":", "");
      epoch -= sign * (Number(digits.slice(0, 2)) * 3600 + Number(digits.slice(2)) * 60);
    }
    return epoch;
  }

  MT.address = {
    Parser: Parser,
    addressList: addressList,
    parseaddr: parseaddr,
    getaddresses: getaddresses,
    quote: quote,
    parseDateParts: parseDateParts,
    parseDate: parseDate,
    toEpoch: toEpoch,
  };

  function isoOffset(text) {
    if (!text) return null;
    return text.slice(-1) === "Z" ? text.slice(0, -1) + "+00:00" : text;
  }

  MT.time = {
    iso: iso,
    isoOffset: isoOffset,
    fromIso: fromIso,
    civil: civil,
    daysBefore: daysBefore,
    pad: pad,
  };
})(MT);
