var MT = MT || {};

(function (MT) {
  var INVALID_CHARREFS = {
    0x00: 0xfffd, 0x0d: 0x0d, 0x80: 0x20ac, 0x81: 0x81, 0x82: 0x201a, 0x83: 0x0192, 0x84: 0x201e, 0x85: 0x2026,
    0x86: 0x2020, 0x87: 0x2021, 0x88: 0x02c6, 0x89: 0x2030, 0x8a: 0x0160, 0x8b: 0x2039, 0x8c: 0x0152, 0x8d: 0x8d,
    0x8e: 0x017d, 0x8f: 0x8f, 0x90: 0x90, 0x91: 0x2018, 0x92: 0x2019, 0x93: 0x201c, 0x94: 0x201d, 0x95: 0x2022,
    0x96: 0x2013, 0x97: 0x2014, 0x98: 0x02dc, 0x99: 0x2122, 0x9a: 0x0161, 0x9b: 0x203a, 0x9c: 0x0153, 0x9d: 0x9d,
    0x9e: 0x017e, 0x9f: 0x0178,
  };

  function invalidCodepoint(num) {
    if (num >= 0x1 && num <= 0x8) return true;
    if (num >= 0xe && num <= 0x1f) return true;
    if (num >= 0x7f && num <= 0x9f) return true;
    if (num >= 0xfdd0 && num <= 0xfdef) return true;
    if (num === 0xb) return true;
    return (num & 0xfffe) === 0xfffe && num <= 0x10ffff;
  }

  var patterns = null;

  function rx() {
    if (patterns) return patterns;
    var re = MT.py.re;
    var X = MT.py.FLAGS.X;
    patterns = {
      charrefAny: re("&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\\t\\n\\f <&#;]{1,32};?)"),
      incomplete: re("&[a-zA-Z#]"),
      entityref: re("&([a-zA-Z][-.a-zA-Z0-9]*)[^a-zA-Z0-9]"),
      charref: re("&#(?:[0-9]+|[xX][0-9a-fA-F]+)[^0-9a-fA-F]"),
      incompleteCharref: re("&#(?:[0-9]|[xX][0-9a-fA-F])"),
      attrCharref: re("&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*)[;=]?"),
      starttagopen: re("<[a-zA-Z]"),
      endtagopen: re("</[a-zA-Z]"),
      commentclose: re("--!?>"),
      commentabruptclose: re("-?>"),
      tagfind: re("([a-zA-Z][^\\t\\n\\r\\f />]*)(?:[\\t\\n\\r\\f ]|/(?!>))*"),
      attrfind: re(
        "((?<=['\"\\t\\n\\r\\f /])[^\\t\\n\\r\\f />][^\\t\\n\\r\\f /=>]*)" +
          "([\\t\\n\\r\\f ]*=[\\t\\n\\r\\f ]*('[^']*'|\"[^\"]*\"|(?!['\"])[^>\\t\\n\\r\\f ]*))?" +
          "(?:[\\t\\n\\r\\f ]|/(?!>))*",
      ),
      locatetagend: re(
        "[a-zA-Z][^\\t\\n\\r\\f />]*[\\t\\n\\r\\f /]*" +
          "(?:(?<=['\"\\t\\n\\r\\f /])[^\\t\\n\\r\\f />][^\\t\\n\\r\\f /=>]*" +
          "(?:[\\t\\n\\r\\f ]*=[\\t\\n\\r\\f ]*(?:'[^']*'|\"[^\"]*\"|(?!['\"])[^>\\t\\n\\r\\f ]*))?" +
          "[\\t\\n\\r\\f /]*)*>?",
      ),
      ampEnd: re("[\\t\\n\\r\\f ;]"),
      verbose: X,
    };
    return patterns;
  }

  function entities() {
    return MT.json("knowledge").entities;
  }

  function replaceCharref(found) {
    var s = found[1];
    if (s[0] === "#") {
      var digits = MT.py.rstrip(s.slice(s[1] === "x" || s[1] === "X" ? 2 : 1), ";");
      var num = s[1] === "x" || s[1] === "X" ? parseInt(digits, 16) : parseInt(digits, 10);
      if (MT.own(INVALID_CHARREFS, num)) return String.fromCharCode(INVALID_CHARREFS[num]);
      if ((num >= 0xd800 && num <= 0xdfff) || num > 0x10ffff) return String.fromCharCode(0xfffd);
      if (invalidCodepoint(num)) return "";
      return String.fromCodePoint(num);
    }
    var table = entities();
    if (MT.own(table, s)) return table[s];
    for (var x = s.length - 1; x > 1; x -= 1) {
      if (MT.own(table, s.slice(0, x))) return table[s.slice(0, x)] + s.slice(x);
    }
    return "&" + s;
  }

  function unescape(text) {
    if (text.indexOf("&") < 0) return text;
    return rx().charrefAny.sub(replaceCharref, text);
  }

  function unescapeAttr(text) {
    var table = entities();
    return rx().attrCharref.sub(function (found) {
      var ref = found[0];
      if (ref.slice(0, 2) === "&#") return unescape(ref);
      if (ref[ref.length - 1] !== "=" && MT.own(table, ref.slice(1))) return unescape(ref);
      return ref;
    }, text);
  }

  var CDATA_ELEMENTS = ["script", "style", "xmp", "iframe", "noembed", "noframes"];
  var RCDATA_ELEMENTS = ["textarea", "title"];

  function Parser(handlers) {
    this.handlers = handlers || {};
    this.rawdata = "";
    this.lasttag = "???";
    this.interesting = null;
    this.cdataElem = null;
    this.escapable = true;
    this.supportCdata = true;
  }

  Parser.prototype.emit = function (name, a, b) {
    var handler = this.handlers[name];
    if (handler) handler.call(this.handlers, a, b);
  };

  Parser.prototype.handleStartEnd = function (tag, attrs) {
    if (this.handlers.startendtag) {
      this.handlers.startendtag(tag, attrs);
      return;
    }
    this.emit("starttag", tag, attrs);
    this.emit("endtag", tag);
  };

  Parser.prototype.setCdataMode = function (elem, escapable) {
    this.cdataElem = elem.toLowerCase();
    this.escapable = escapable;
    if (this.cdataElem === "plaintext") {
      this.interesting = MT.py.re("\\Z");
    } else {
      this.interesting = MT.py.re(
        "</" + MT.py.reEscape(this.cdataElem) + "(?=[\\t\\n\\r\\f />])",
        MT.py.FLAGS.I | MT.py.FLAGS.A,
      );
    }
  };

  Parser.prototype.clearCdataMode = function () {
    this.interesting = null;
    this.cdataElem = null;
    this.escapable = true;
  };

  Parser.prototype.feed = function (data) {
    if (data.length < 1) return;
    this.rawdata += data;
    this.goahead(false);
  };

  Parser.prototype.close = function () {
    this.goahead(true);
  };

  Parser.prototype.data = function (text) {
    this.emit("data", text);
  };

  Parser.prototype.goahead = function (end) {
    var R = rx();
    var rawdata = this.rawdata;
    var i = 0;
    var n = rawdata.length;
    var j;
    var k;
    var found;
    while (i < n) {
      if (!this.cdataElem) {
        j = rawdata.indexOf("<", i);
        if (j < 0) {
          var amppos = rawdata.lastIndexOf("&");
          if (amppos < Math.max(i, n - 34)) amppos = -1;
          if (amppos >= 0 && !R.ampEnd.search(rawdata, amppos)) break;
          j = n;
        }
      } else {
        found = this.interesting.search(rawdata, i);
        if (found) {
          j = found.start;
        } else {
          break;
        }
      }
      if (i < j) {
        this.data(this.escapable ? unescape(rawdata.slice(i, j)) : rawdata.slice(i, j));
      }
      i = j;
      if (i === n) break;
      if (rawdata[i] === "<") {
        if (R.starttagopen.match(rawdata, i)) {
          k = this.parseStartTag(i);
        } else if (rawdata.startsWith("</", i)) {
          k = this.parseEndTag(i);
        } else if (rawdata.startsWith("<!--", i)) {
          k = this.parseComment(i);
        } else if (rawdata.startsWith("<?", i)) {
          k = this.parsePi(i);
        } else if (rawdata.startsWith("<!", i)) {
          k = this.parseDeclaration(i);
        } else if (i + 1 < n || end) {
          this.data("<");
          k = i + 1;
        } else {
          break;
        }
        if (k < 0) {
          if (!end) break;
          if (R.starttagopen.match(rawdata, i)) {
            k = n;
          } else if (rawdata.startsWith("</", i)) {
            if (i + 2 === n) this.data("</");
            k = n;
          } else {
            k = n;
          }
        }
        i = k;
      } else {
        throw new Error("the HTML scanner stopped on an unexpected character");
      }
    }
    if (end && i < n) {
      this.data(this.escapable ? unescape(rawdata.slice(i, n)) : rawdata.slice(i, n));
      i = n;
    }
    this.rawdata = rawdata.slice(i);
  };

  Parser.prototype.parseDeclaration = function (i) {
    var rawdata = this.rawdata;
    if (rawdata.slice(i, i + 4) === "<!--") return this.parseComment(i);
    if (rawdata.slice(i, i + 9) === "<![CDATA[" && this.supportCdata) {
      var j = rawdata.indexOf("]]>", i + 9);
      return j < 0 ? -1 : j + 3;
    }
    if (rawdata.slice(i, i + 9).toLowerCase() === "<!doctype") {
      var gtpos = rawdata.indexOf(">", i + 9);
      return gtpos === -1 ? -1 : gtpos + 1;
    }
    return this.parseBogusComment(i);
  };

  Parser.prototype.parseComment = function (i) {
    var R = rx();
    var found = R.commentabruptclose.match(this.rawdata, i + 4);
    if (!found) {
      found = R.commentclose.search(this.rawdata, i + 4);
      if (!found) return -1;
    }
    return found.end;
  };

  Parser.prototype.parseBogusComment = function (i) {
    var pos = this.rawdata.indexOf(">", i + 2);
    return pos === -1 ? -1 : pos + 1;
  };

  Parser.prototype.parsePi = function (i) {
    var pos = this.rawdata.indexOf(">", i + 2);
    return pos === -1 ? -1 : pos + 1;
  };

  Parser.prototype.wholeStartTag = function (i) {
    var found = rx().locatetagend.match(this.rawdata, i + 1);
    var j = found.end;
    return this.rawdata[j - 1] !== ">" ? -1 : j;
  };

  Parser.prototype.parseStartTag = function (i) {
    var R = rx();
    var endpos = this.wholeStartTag(i);
    if (endpos < 0) return endpos;
    var rawdata = this.rawdata;
    var attrs = [];
    var found = R.tagfind.match(rawdata, i + 1);
    var k = found.end;
    var tag = found[1].toLowerCase();
    this.lasttag = tag;
    while (k < endpos) {
      var m = R.attrfind.match(rawdata, k);
      if (!m) break;
      var name = m[1];
      var rest = m[2];
      var value = m[3];
      if (!rest) {
        value = null;
      } else if (
        (value.slice(0, 1) === "'" && value.slice(-1) === "'") ||
        (value.slice(0, 1) === '"' && value.slice(-1) === '"')
      ) {
        value = value.slice(1, -1);
      }
      if (value) value = unescapeAttr(value);
      attrs.push([name.toLowerCase(), value]);
      k = m.end;
    }
    var tail = MT.py.strip(rawdata.slice(k, endpos));
    if (tail !== ">" && tail !== "/>") {
      this.data(rawdata.slice(i, endpos));
      return endpos;
    }
    if (tail === "/>") {
      this.handleStartEnd(tag, attrs);
    } else {
      this.emit("starttag", tag, attrs);
      if (CDATA_ELEMENTS.indexOf(tag) >= 0 || tag === "plaintext") {
        this.setCdataMode(tag, false);
      } else if (RCDATA_ELEMENTS.indexOf(tag) >= 0) {
        this.setCdataMode(tag, true);
      }
    }
    return endpos;
  };

  Parser.prototype.parseEndTag = function (i) {
    var R = rx();
    var rawdata = this.rawdata;
    if (rawdata.indexOf(">", i + 2) < 0) return -1;
    if (!R.endtagopen.match(rawdata, i)) {
      if (rawdata.slice(i + 2, i + 3) === ">") return i + 3;
      return this.parseBogusComment(i);
    }
    var found = R.locatetagend.match(rawdata, i + 2);
    var j = found.end;
    if (rawdata[j - 1] !== ">") return -1;
    var tag = R.tagfind.match(rawdata, i + 2)[1].toLowerCase();
    this.emit("endtag", tag);
    this.clearCdataMode();
    return j;
  };

  function parse(html, handlers) {
    var parser = new Parser(handlers);
    parser.feed(html);
    parser.close();
    return parser;
  }

  MT.html = {
    unescape: unescape,
    unescapeAttr: unescapeAttr,
    Parser: Parser,
    parse: parse,
  };
})(MT);
