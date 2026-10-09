var MT = MT || {};

(function (MT) {
  var UNKNOWN8BIT = "unknown-8bit";
  var SHORTEST = 3;
  var BASE64 = 2;
  var QP = 1;
  var MISSING = { missing: true };

  var HEADER_LINE = /^(?:From |[\x21-\x39\x3b-\x7e]*:|[\t ])/;
  var NEWLINE_START = /^(?:\r\n|\r|\n)/;
  var NEWLINE_END = /(?:\r\n|\r|\n)$/;
  var NEWLINE_ANY = /\r\n|\r|\n/;
  var CONTINUATION = /^([A-Za-z0-9_]+)\*(([0-9]+)\*?)?$/;
  var EMBEDDED_HEADER = /\n[^ \t]+:/;
  var NEWLINE_WITHOUT_SPACE = /\r\n[^ \t]|\r[^ \n\t]|\n[^ \t]/;
  var FOLDING_SPACE = /([ \t]+)/;
  var QUOTED_HEX = /=[a-fA-F0-9]{2}/g;
  var TSPECIALS = /[ ()<>@,;:\\"/\[\]?=]/;
  var ALWAYS_SAFE = /^[A-Za-z0-9_.~-]$/;
  var HEX = "0123456789ABCDEF";
  var QP_HEADER_SAFE = "-!*+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  var QP_BODY_SAFE = " !\"#$%&'()*+,-./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\t";

  var patterns = null;

  function rx() {
    if (!patterns) {
      patterns = {
        encodedWord: MT.py.re("=\\?(?P<charset>[^?]*?)\\?(?P<encoding>[qQbB])\\?(?P<encoded>.*?)\\?=", MT.py.FLAGS.M),
        boundaryEnd: MT.py.re("(?P<end>--)?(?P<ws>[ \\t]*)(?P<linesep>\\r\\n|\\r|\\n)?$"),
      };
    }
    return patterns;
  }

  function MessageError(name, message) {
    this.name = name;
    this.message = message;
  }
  MessageError.prototype = Object.create(Error.prototype);

  function Extended(charset, language, value) {
    this.charset = charset;
    this.language = language;
    this.value = value;
  }

  function quote(text) {
    return MT.py.replaceAll(MT.py.replaceAll(text, "\\", "\\\\"), '"', '\\"');
  }

  function unquote(text) {
    if (text.length > 1) {
      if (text[0] === '"' && text[text.length - 1] === '"') {
        return MT.py.replaceAll(MT.py.replaceAll(text.slice(1, -1), "\\\\", "\\"), '\\"', '"');
      }
      if (text[0] === "<" && text[text.length - 1] === ">") return text.slice(1, -1);
    }
    return text;
  }

  function unquoteValue(value) {
    if (value instanceof Extended) return new Extended(value.charset, value.language, unquote(value.value));
    return unquote(value);
  }

  function splitParam(value) {
    var parts = MT.py.partition(String(value), ";");
    if (!parts[1]) return [MT.py.strip(parts[0]), null];
    return [MT.py.strip(parts[0]), MT.py.strip(parts[2])];
  }

  function parseParam(value) {
    var s = ";" + String(value);
    var plist = [];
    var start = 0;
    while (MT.py.find(s, ";", start) === start) {
      start += 1;
      var end = MT.py.find(s, ";", start);
      var ind = start;
      var diff = 0;
      while (end > 0) {
        diff += MT.py.count(s, '"', ind, end) - MT.py.count(s, '\\"', ind, end);
        if (diff % 2 === 0) break;
        var previous = ind;
        ind = MT.py.find(s, ";", end + 1);
        end = previous;
      }
      if (end < 0) end = s.length;
      var i = MT.py.find(s, "=", start, end);
      var field;
      if (i === -1) {
        field = s.slice(start, end);
      } else {
        field = MT.py.rstrip(s.slice(start, i)).toLowerCase() + "=" + MT.py.lstrip(s.slice(i + 1, end));
      }
      plist.push(MT.py.strip(field));
      start = end;
    }
    return plist;
  }

  function unquotePercent(text) {
    if (text.indexOf("%") < 0) return text;
    var out = [];
    var i = 0;
    var length = text.length;
    while (i < length) {
      var code = text.charCodeAt(i);
      if (code > 0x7f) {
        out.push(text[i]);
        i += 1;
        continue;
      }
      var end = i;
      while (end < length && text.charCodeAt(end) <= 0x7f) end += 1;
      var bits = text.slice(i, end).split("%");
      var bytes = [];
      var k;
      for (k = 0; k < bits[0].length; k += 1) bytes.push(bits[0].charCodeAt(k));
      for (var b = 1; b < bits.length; b += 1) {
        var item = bits[b];
        var pair = item.slice(0, 2);
        var rest;
        if (/^[0-9A-Fa-f]{2}$/.test(pair)) {
          bytes.push(parseInt(pair, 16));
          rest = item.slice(2);
        } else {
          bytes.push(37);
          rest = item;
        }
        for (k = 0; k < rest.length; k += 1) bytes.push(rest.charCodeAt(k));
      }
      out.push(MT.bytes.toLatin1(new Uint8Array(bytes)));
      i = end;
    }
    return out.join("");
  }

  function decodeRfc2231(text) {
    var parts = MT.py.split(text, "'", 2);
    if (parts.length <= 2) return new Extended(null, null, text);
    return new Extended(parts[0], parts[1], parts[2]);
  }

  function decodeParams(params) {
    var out = [params[0]];
    var extended = new Map();
    for (var i = 1; i < params.length; i += 1) {
      var name = params[i][0];
      var encoded = name.slice(-1) === "*";
      var value = unquote(params[i][1]);
      var found = CONTINUATION.exec(name);
      if (found) {
        var base = found[1];
        var num = found[3] === undefined ? null : Number(found[3]);
        if (!extended.has(base)) extended.set(base, []);
        extended.get(base).push([num, value, encoded]);
      } else {
        out.push([name, '"' + quote(value) + '"']);
      }
    }
    extended.forEach(function (continuations, base) {
      var hasZero = continuations.some(function (entry) {
        return entry[0] === 0;
      });
      var list;
      if (hasZero) {
        list = continuations.filter(function (entry) {
          return entry[0] !== null;
        });
      } else {
        list = continuations.map(function (entry) {
          return [entry[0] || 0, entry[1], entry[2]];
        });
      }
      list = list
        .map(function (entry, index) {
          return { entry: entry, index: index };
        })
        .sort(function (left, right) {
          return left.entry[0] - right.entry[0] || left.index - right.index;
        })
        .map(function (item) {
          return item.entry;
        });
      var pieces = [];
      var isExtended = false;
      list.forEach(function (entry) {
        var text = entry[1];
        if (entry[2]) {
          text = unquotePercent(text);
          isExtended = true;
        }
        pieces.push(text);
      });
      var joined = quote(pieces.join(""));
      if (isExtended) {
        var decoded = decodeRfc2231(joined);
        out.push([base, new Extended(decoded.charset, decoded.language, '"' + decoded.value + '"')]);
      } else {
        out.push([base, '"' + joined + '"']);
      }
    });
    return out;
  }

  function collapse(value) {
    if (!(value instanceof Extended)) return unquote(value);
    var charset = value.charset === null ? "us-ascii" : value.charset;
    var raw = MT.codecs.rawUnicodeEscape(value.value);
    try {
      return MT.codecs.decode(raw, charset, "replace");
    } catch (error) {
      if (error instanceof MT.codecs.LookupError) return unquote(value.value);
      throw error;
    }
  }

  function sanitize(value) {
    return MT.codecs.hasSurrogates(value) ? MT.codecs.escapedAsReplacement(value) : value;
  }

  function Message() {
    this.headers = [];
    this.unixfrom = null;
    this.payload = null;
    this.preamble = null;
    this.epilogue = null;
    this.defects = [];
    this.defaultType = "text/plain";
  }

  Message.prototype.isMultipart = function () {
    return Array.isArray(this.payload);
  };

  Message.prototype.attach = function (part) {
    if (this.payload === null) {
      this.payload = [part];
    } else if (Array.isArray(this.payload)) {
      this.payload.push(part);
    } else {
      throw new MessageError("TypeError", "Attach is not valid on a message with a non-multipart payload");
    }
  };

  Message.prototype.has = function (name) {
    var wanted = name.toLowerCase();
    for (var i = 0; i < this.headers.length; i += 1) {
      if (this.headers[i][0].toLowerCase() === wanted) return true;
    }
    return false;
  };

  Message.prototype.get = function (name, fallback) {
    var wanted = name.toLowerCase();
    for (var i = 0; i < this.headers.length; i += 1) {
      if (this.headers[i][0].toLowerCase() === wanted) return sanitize(this.headers[i][1]);
    }
    return fallback;
  };

  Message.prototype.getAll = function (name) {
    var wanted = name.toLowerCase();
    var values = [];
    for (var i = 0; i < this.headers.length; i += 1) {
      if (this.headers[i][0].toLowerCase() === wanted) values.push(sanitize(this.headers[i][1]));
    }
    return values.length ? values : null;
  };

  Message.prototype.items = function () {
    return this.headers.map(function (pair) {
      return [pair[0], sanitize(pair[1])];
    });
  };

  Message.prototype.getContentType = function () {
    var value = this.get("content-type", MISSING);
    if (value === MISSING) return this.defaultType;
    var ctype = splitParam(value)[0].toLowerCase();
    if (MT.py.count(ctype, "/") !== 1) return "text/plain";
    return ctype;
  };

  Message.prototype.getContentMaintype = function () {
    return this.getContentType().split("/")[0];
  };

  Message.prototype.getContentSubtype = function () {
    return this.getContentType().split("/")[1];
  };

  Message.prototype.paramsPreserve = function (header) {
    var value = this.get(header, MISSING);
    if (value === MISSING) return MISSING;
    var params = parseParam(value).map(function (p) {
      var at = p.indexOf("=");
      if (at < 0) return [MT.py.strip(p), ""];
      return [MT.py.strip(p.slice(0, at)), MT.py.strip(p.slice(at + 1))];
    });
    return decodeParams(params);
  };

  Message.prototype.getParam = function (param, header, keepQuotes) {
    var name = header || "content-type";
    if (!this.has(name)) return MISSING;
    var params = this.paramsPreserve(name);
    var wanted = param.toLowerCase();
    for (var i = 0; i < params.length; i += 1) {
      if (params[i][0].toLowerCase() === wanted) return keepQuotes ? params[i][1] : unquoteValue(params[i][1]);
    }
    return MISSING;
  };

  Message.prototype.getFilename = function () {
    var filename = this.getParam("filename", "content-disposition");
    if (filename === MISSING) filename = this.getParam("name", "content-type");
    if (filename === MISSING) return null;
    return MT.py.strip(collapse(filename));
  };

  Message.prototype.getBoundary = function () {
    var boundary = this.getParam("boundary");
    if (boundary === MISSING) return null;
    return MT.py.rstrip(collapse(boundary));
  };

  Message.prototype.getContentCharset = function (fallback) {
    var missing = fallback === undefined ? null : fallback;
    var charset = this.getParam("charset");
    if (charset === MISSING) return missing;
    if (charset instanceof Extended) {
      var declared = charset.charset || "us-ascii";
      try {
        charset = MT.codecs.decode(MT.codecs.rawUnicodeEscape(charset.value), declared, "strict");
      } catch (error) {
        if (!(error instanceof MT.codecs.LookupError) && !(error instanceof MT.codecs.DecodeError)) throw error;
        charset = charset.value;
      }
    }
    if (!MT.codecs.isAscii(charset)) return missing;
    return charset.toLowerCase();
  };

  Message.prototype.transferEncoding = function () {
    return MT.py.strip(String(this.get("content-transfer-encoding", ""))).toLowerCase();
  };

  Message.prototype.payloadBytes = function () {
    var payload = this.payload;
    if (typeof payload !== "string") return new Uint8Array(0);
    try {
      return MT.codecs.escapeEncode(payload);
    } catch (error) {
      return MT.codecs.rawUnicodeEscape(payload);
    }
  };

  Message.prototype.decodedPayload = function () {
    if (this.isMultipart()) return null;
    if (typeof this.payload !== "string") return null;
    var cte = this.transferEncoding();
    var raw = this.payloadBytes();
    if (cte === "quoted-printable") return MT.binascii.a2bQp(raw, false);
    if (cte === "base64") return MT.binascii.decodeB(MT.bytes.concat(MT.binascii.splitLines(raw)));
    if (cte === "x-uuencode" || cte === "uuencode" || cte === "uue" || cte === "x-uue") {
      try {
        return MT.binascii.decodeUu(raw);
      } catch (error) {
        if (error instanceof MT.binascii.ValueError || error instanceof MT.binascii.Error) return raw;
        throw error;
      }
    }
    return raw;
  };

  Message.prototype.textPayload = function () {
    var payload = this.payload;
    if (typeof payload !== "string" || !MT.codecs.hasSurrogates(payload)) return payload;
    var raw;
    try {
      raw = MT.codecs.escapeEncode(payload);
    } catch (error) {
      return payload;
    }
    try {
      return MT.codecs.decode(raw, this.getContentCharset("ascii"), "replace");
    } catch (error) {
      if (error instanceof MT.codecs.LookupError) return MT.codecs.decode(raw, "ascii", "replace");
      throw error;
    }
  };

  function splitLines(text) {
    var lines = [];
    var start = 0;
    var length = text.length;
    for (var i = 0; i < length; i += 1) {
      var code = text.charCodeAt(i);
      if (code !== 10 && code !== 13) continue;
      if (code === 13 && i + 1 < length && text.charCodeAt(i + 1) === 10) i += 1;
      lines.push(text.slice(start, i + 1));
      start = i + 1;
    }
    if (start < length) lines.push(text.slice(start));
    return lines;
  }

  function Input(lines) {
    this.lines = lines;
    this.index = 0;
    this.pending = [];
    this.matchers = [];
  }

  Input.prototype.readline = function () {
    var line;
    if (this.pending.length) {
      line = this.pending.pop();
    } else if (this.index < this.lines.length) {
      line = this.lines[this.index];
      this.index += 1;
    } else {
      return "";
    }
    for (var i = this.matchers.length - 1; i >= 0; i -= 1) {
      if (this.matchers[i](line)) {
        this.pending.push(line);
        return "";
      }
    }
    return line;
  };

  Input.prototype.unreadline = function (line) {
    this.pending.push(line);
  };

  function startsNewline(line) {
    return NEWLINE_START.test(line);
  }

  function withoutEnding(text) {
    var found = NEWLINE_END.exec(text);
    return found ? text.slice(0, text.length - found[0].length) : text;
  }

  function Parser(text) {
    this.input = new Input(splitLines(text));
    this.stack = [];
    this.cur = null;
    this.last = null;
    this.depth = 0;
  }

  Parser.prototype.defect = function (name) {
    if (this.cur) this.cur.defects.push(name);
  };

  Parser.prototype.newMessage = function () {
    var msg = new Message();
    if (this.cur && this.cur.headers.length && this.cur.getContentType() === "multipart/digest") {
      msg.defaultType = "message/rfc822";
    }
    if (this.stack.length) this.stack[this.stack.length - 1].attach(msg);
    this.stack.push(msg);
    this.cur = msg;
    this.last = msg;
  };

  Parser.prototype.popMessage = function () {
    var popped = this.stack.pop();
    this.cur = this.stack.length ? this.stack[this.stack.length - 1] : null;
    return popped;
  };

  Parser.prototype.rest = function () {
    var lines = [];
    var line = this.input.readline();
    while (line !== "") {
      lines.push(line);
      line = this.input.readline();
    }
    return lines;
  };

  Parser.prototype.nested = function () {
    this.depth += 1;
    if (this.depth > 900) throw new MessageError("RecursionError", "the message nests too deeply");
    try {
      this.parse();
    } finally {
      this.depth -= 1;
    }
  };

  Parser.prototype.parse = function () {
    this.newMessage();
    var headers = [];
    var line = this.input.readline();
    while (line !== "") {
      if (!HEADER_LINE.test(line)) {
        if (!startsNewline(line)) {
          this.defect("MissingHeaderBodySeparatorDefect");
          this.input.unreadline(line);
        }
        break;
      }
      headers.push(line);
      line = this.input.readline();
    }
    this.parseHeaders(headers);

    var contentType = this.cur.getContentType();
    if (contentType === "message/delivery-status") {
      for (;;) {
        this.input.matchers.push(startsNewline);
        this.nested();
        this.popMessage();
        this.input.matchers.pop();
        this.input.readline();
        line = this.input.readline();
        if (line === "") break;
        this.input.unreadline(line);
      }
      return;
    }
    var maintype = this.cur.getContentMaintype();
    if (maintype === "message") {
      this.nested();
      this.popMessage();
      return;
    }
    if (maintype === "multipart") {
      this.parseMultipart();
      return;
    }
    this.cur.payload = this.rest().join("");
  };

  Parser.prototype.parseMultipart = function () {
    var boundary = this.cur.getBoundary();
    if (boundary === null) {
      this.defect("NoBoundaryInMultipartDefect");
      this.cur.payload = this.rest().join("");
      return;
    }
    var cte = String(this.cur.get("content-transfer-encoding", "8bit")).toLowerCase();
    if (cte !== "7bit" && cte !== "8bit" && cte !== "binary") {
      this.defect("InvalidMultipartContentTransferEncodingDefect");
    }
    var separator = "--" + boundary;
    var boundaryEnd = rx().boundaryEnd;

    function boundaryMatch(line) {
      if (line.slice(0, separator.length) !== separator) return null;
      return boundaryEnd.match(line, separator.length);
    }

    var capturing = true;
    var preamble = [];
    var linesep = false;
    var closeSeen = false;
    var line;
    var found;
    for (;;) {
      line = this.input.readline();
      if (line === "") break;
      found = boundaryMatch(line);
      if (!found) {
        preamble.push(line);
        continue;
      }
      if (found.groups.end) {
        closeSeen = true;
        linesep = found.groups.linesep;
        break;
      }
      if (capturing) {
        if (preamble.length) {
          preamble[preamble.length - 1] = withoutEnding(preamble[preamble.length - 1]);
          this.cur.preamble = preamble.join("");
        }
        capturing = false;
        this.input.unreadline(line);
        continue;
      }
      for (;;) {
        line = this.input.readline();
        if (!boundaryMatch(line)) {
          this.input.unreadline(line);
          break;
        }
      }
      this.input.matchers.push(boundaryMatch);
      this.nested();
      if (this.last.getContentMaintype() === "multipart") {
        var epilogueText = this.last.epilogue;
        if (epilogueText === "") {
          this.last.epilogue = null;
        } else if (epilogueText !== null) {
          this.last.epilogue = withoutEnding(epilogueText);
        }
      } else if (typeof this.last.payload === "string") {
        this.last.payload = withoutEnding(this.last.payload);
      }
      this.input.matchers.pop();
      this.popMessage();
      this.last = this.cur;
    }
    if (capturing) {
      this.defect("StartBoundaryNotFoundDefect");
      this.cur.payload = preamble.join("");
      this.rest();
      this.cur.epilogue = "";
      return;
    }
    if (!closeSeen) {
      this.defect("CloseBoundaryNotFoundDefect");
      return;
    }
    var epilogue = linesep ? [""] : [];
    this.rest().forEach(function (item) {
      epilogue.push(item);
    });
    if (epilogue.length) {
      var opening = NEWLINE_START.exec(epilogue[0]);
      if (opening) epilogue[0] = epilogue[0].slice(opening[0].length);
    }
    this.cur.epilogue = epilogue.join("");
  };

  function sourceParse(lines) {
    var first = lines[0];
    var colon = first.indexOf(":");
    var name = first.slice(0, colon);
    var value = MT.py.lstrip(first.slice(colon + 1) + lines.slice(1).join(""), " \t\r\n");
    return [name, MT.py.rstrip(value, "\r\n")];
  }

  Parser.prototype.parseHeaders = function (lines) {
    var lastHeader = "";
    var lastValue = [];
    for (var lineno = 0; lineno < lines.length; lineno += 1) {
      var line = lines[lineno];
      if (line[0] === " " || line[0] === "\t") {
        if (!lastHeader) {
          this.defect("FirstHeaderLineIsContinuationDefect");
          continue;
        }
        lastValue.push(line);
        continue;
      }
      if (lastHeader) {
        this.cur.headers.push(sourceParse(lastValue));
        lastHeader = "";
        lastValue = [];
      }
      if (line.slice(0, 5) === "From ") {
        if (lineno === 0) {
          this.cur.unixfrom = withoutEnding(line);
          continue;
        } else if (lineno === lines.length - 1) {
          this.input.unreadline(line);
          return;
        }
        this.defect("MisplacedEnvelopeHeaderDefect");
        continue;
      }
      var i = line.indexOf(":");
      if (i === 0) {
        this.defect("InvalidHeaderDefect");
        continue;
      }
      lastHeader = line.slice(0, i);
      lastValue = [line];
    }
    if (lastHeader) this.cur.headers.push(sourceParse(lastValue));
  };

  function parseBytes(bytes) {
    var parser = new Parser(MT.codecs.escapeDecode(bytes));
    parser.parse();
    var root = parser.popMessage();
    if (root.getContentMaintype() === "multipart" && !root.isMultipart()) {
      root.defects.push("MultipartInvariantViolationDefect");
    }
    return root;
  }

  function Charset(name) {
    var text = String(name);
    if (!MT.codecs.isAscii(text)) throw new MessageError("CharsetError", text);
    var data = MT.json("knowledge").email_charsets;
    var input = text.toLowerCase();
    if (MT.own(data.aliases, input)) input = data.aliases[input];
    var row = MT.own(data.charsets, input) ? data.charsets[input] : [SHORTEST, BASE64, null];
    var conversion = row[2] || input;
    this.name = input;
    this.headerEncoding = row[0];
    this.bodyEncoding = row[1];
    this.outputCharset = MT.own(data.aliases, conversion) ? data.aliases[conversion] : conversion;
    this.inputCodec = MT.own(data.codec_map, input) ? data.codec_map[input] : input;
    this.outputCodec = MT.own(data.codec_map, this.outputCharset) ? data.codec_map[this.outputCharset] : this.outputCharset;
  }

  function charsetEncode(text, codec) {
    if (codec === UNKNOWN8BIT) return MT.codecs.escapeEncode(text);
    return MT.codecs.encode(text, codec, "strict");
  }

  function hexByte(value) {
    return "=" + HEX.charAt(value >> 4) + HEX.charAt(value & 15);
  }

  function qpHeaderLength(bytes) {
    var total = 0;
    for (var i = 0; i < bytes.length; i += 1) {
      var value = bytes[i];
      total += value === 0x20 || QP_HEADER_SAFE.indexOf(String.fromCharCode(value)) >= 0 ? 1 : 3;
    }
    return total;
  }

  function qpHeaderEncode(bytes, charset) {
    if (!bytes.length) return "";
    var out = [];
    for (var i = 0; i < bytes.length; i += 1) {
      var value = bytes[i];
      if (value === 0x20) out.push("_");
      else if (QP_HEADER_SAFE.indexOf(String.fromCharCode(value)) >= 0) out.push(String.fromCharCode(value));
      else out.push(hexByte(value));
    }
    return "=?" + charset + "?q?" + out.join("") + "?=";
  }

  function base64HeaderLength(bytes) {
    var total = Math.floor(bytes.length / 3) * 4;
    if (bytes.length % 3) total += 4;
    return total;
  }

  function base64HeaderEncode(bytes, charset) {
    if (!bytes.length) return "";
    return "=?" + charset + "?b?" + MT.bytes.toBase64(bytes) + "?=";
  }

  function base64BodyEncode(bytes) {
    if (!bytes.length) return "";
    var out = [];
    for (var i = 0; i < bytes.length; i += 57) out.push(MT.bytes.toBase64(bytes.subarray(i, i + 57)) + "\n");
    return out.join("");
  }

  function qpBodyEncode(body) {
    if (!body) return body;
    var translated = [];
    for (var i = 0; i < body.length; i += 1) {
      var code = body.charCodeAt(i);
      if (code === 13 || code === 10 || QP_BODY_SAFE.indexOf(body.charAt(i)) >= 0) translated.push(body.charAt(i));
      else translated.push(hexByte(code));
    }
    var text = translated.join("");
    var softBreak = "=\n";
    var maxlinelen = 76;
    var maxlinelen1 = 75;
    var encoded = [];
    MT.py.splitlines(text).forEach(function (line) {
      var start = 0;
      var laststart = line.length - 1 - maxlinelen;
      while (start <= laststart) {
        var stop = start + maxlinelen1;
        if (line.charAt(stop - 2) === "=") {
          encoded.push(line.slice(start, stop - 1));
          start = stop - 2;
        } else if (line.charAt(stop - 1) === "=") {
          encoded.push(line.slice(start, stop));
          start = stop - 1;
        } else {
          encoded.push(line.slice(start, stop) + "=");
          start = stop;
        }
      }
      var last = line.charAt(line.length - 1);
      if (line && (last === " " || last === "\t")) {
        var room = start - laststart;
        var quoted;
        if (room >= 3) quoted = hexByte(last.charCodeAt(0));
        else if (room === 2) quoted = last + softBreak;
        else quoted = softBreak + hexByte(last.charCodeAt(0));
        encoded.push(line.slice(start, -1) + quoted);
      } else {
        encoded.push(line.slice(start));
      }
    });
    var ending = text.charAt(text.length - 1);
    if (ending === "\r" || ending === "\n") encoded.push("");
    return encoded.join("\n");
  }

  Charset.prototype.getOutputCharset = function () {
    return this.outputCharset || this.name;
  };

  Charset.prototype.getBodyEncoding = function () {
    if (this.bodyEncoding === QP) return "quoted-printable";
    if (this.bodyEncoding === BASE64) return "base64";
    return null;
  };

  Charset.prototype.encoderFor = function (bytes) {
    if (this.headerEncoding === BASE64) return "base64";
    if (this.headerEncoding === QP) return "qp";
    if (this.headerEncoding === SHORTEST) return base64HeaderLength(bytes) < qpHeaderLength(bytes) ? "base64" : "qp";
    return null;
  };

  Charset.prototype.headerEncodeLines = function (text, maxlengths) {
    var codec = this.outputCodec || "us-ascii";
    var headerBytes = charsetEncode(text, codec);
    var encoder = this.encoderFor(headerBytes);
    var lengthOf = encoder === "base64" ? base64HeaderLength : qpHeaderLength;
    var encodeWith = encoder === "base64" ? base64HeaderEncode : qpHeaderEncode;
    var charset = this.getOutputCharset();
    var extra = charset.length + 7;
    var lines = [];
    var current = [];
    var maxlen = maxlengths() - extra;
    var points = MT.py.points(text);
    for (var i = 0; i < points.length; i += 1) {
      current.push(points[i]);
      var length = lengthOf(charsetEncode(current.join(""), charset));
      if (length > maxlen) {
        current.pop();
        if (!lines.length && !current.length) {
          lines.push(null);
        } else {
          lines.push(encodeWith(charsetEncode(current.join(""), codec), codec));
        }
        current = [points[i]];
        maxlen = maxlengths() - extra;
      }
    }
    lines.push(encodeWith(charsetEncode(current.join(""), codec), codec));
    return lines;
  };

  Charset.prototype.bodyEncode = function (value) {
    if (!value.length) return value;
    var bytes;
    if (this.bodyEncoding === BASE64) {
      bytes = typeof value === "string" ? MT.codecs.encode(value, this.outputCharset, "strict") : value;
      return base64BodyEncode(bytes);
    }
    if (this.bodyEncoding === QP) {
      bytes = typeof value === "string" ? MT.codecs.encode(value, this.outputCharset, "strict") : value;
      return qpBodyEncode(MT.bytes.toLatin1(bytes));
    }
    if (typeof value === "string") return MT.codecs.decode(MT.codecs.encode(value, this.outputCharset, "strict"), "ascii", "strict");
    return value;
  };

  function charsetName(charset) {
    if (charset === null || charset === undefined) return "none";
    if (charset instanceof Charset) return charset.name;
    return String(charset).toLowerCase();
  }

  function sameCharset(left, right) {
    if (left === right) return true;
    if (!(left instanceof Charset) && !(right instanceof Charset)) return false;
    return charsetName(left) === charsetName(right);
  }

  function isPlain(charset) {
    if (charset === null) return true;
    var name = charsetName(charset);
    return name === "none" || name === "us-ascii";
  }

  function nonCtext(ch) {
    return MT.py.isSpaceText(ch) || ch === "(" || ch === ")" || ch === "\\";
  }

  function firstPoint(text) {
    return text ? String.fromCodePoint(text.codePointAt(0)) : "";
  }

  function lastPoint(text) {
    if (!text) return "";
    var list = MT.py.points(text.slice(-2));
    return list[list.length - 1];
  }

  function Header(headerName, maxLineLength) {
    this.chunks = [];
    this.headerLength = headerName === undefined || headerName === null ? 0 : MT.py.length(headerName) + 2;
    this.maxLineLength = maxLineLength === undefined || maxLineLength === null ? 78 : maxLineLength;
  }

  Header.prototype.append = function (value, charset) {
    var chosen = charset === null || charset === undefined ? new Charset("us-ascii") : charset;
    var text = value;
    if (typeof text !== "string") {
      var inputCodec = chosen.inputCodec || "us-ascii";
      if (inputCodec === UNKNOWN8BIT) {
        text = MT.codecs.escapeDecode(text);
      } else {
        text = MT.codecs.decode(text, inputCodec, "strict");
      }
    }
    var outputCodec = chosen.outputCodec || "us-ascii";
    if (outputCodec !== UNKNOWN8BIT) {
      var fits = outputCodec === "us-ascii" ? MT.codecs.isAscii(text) : MT.codecs.encodable(text, outputCodec);
      if (!fits) {
        if (outputCodec !== "us-ascii") throw new MessageError("UnicodeEncodeError", "cannot encode the header as " + outputCodec);
        chosen = new Charset("utf-8");
      }
    }
    this.chunks.push([text, chosen]);
  };

  Header.prototype.normalize = function () {
    var chunks = [];
    var lastCharset = null;
    var lastChunk = [];
    this.chunks.forEach(function (chunk) {
      if (sameCharset(chunk[1], lastCharset)) {
        lastChunk.push(chunk[0]);
      } else {
        if (lastCharset !== null) chunks.push([lastChunk.join(" "), lastCharset]);
        lastChunk = [chunk[0]];
        lastCharset = chunk[1];
      }
    });
    if (lastChunk.length) chunks.push([lastChunk.join(" "), lastCharset]);
    this.chunks = chunks;
  };

  Header.prototype.toString = function () {
    this.normalize();
    var out = [];
    var lastCharset = null;
    var lastSpace = null;
    this.chunks.forEach(function (chunk) {
      var text = chunk[0];
      var nextCharset = chunk[1];
      if (charsetName(nextCharset) === UNKNOWN8BIT && nextCharset !== null) {
        text = MT.codecs.decode(MT.codecs.escapeEncode(text), "ascii", "replace");
      }
      if (out.length) {
        var hasSpace = text && nonCtext(firstPoint(text));
        if (!isPlain(lastCharset)) {
          if (isPlain(nextCharset) && !hasSpace) {
            out.push(" ");
            nextCharset = null;
          }
        } else if (!isPlain(nextCharset) && !lastSpace) {
          out.push(" ");
        }
      }
      lastSpace = text && nonCtext(lastPoint(text));
      lastCharset = nextCharset;
      out.push(text);
    });
    return out.join("");
  };

  function Accumulator(initialSize) {
    this.initialSize = initialSize;
    this.parts = [];
  }

  Accumulator.prototype.push = function (fws, text) {
    this.parts.push([fws, text]);
  };

  Accumulator.prototype.popFrom = function (index) {
    return this.parts.splice(index, this.parts.length - index);
  };

  Accumulator.prototype.pop = function () {
    if (!this.parts.length) return ["", ""];
    return this.parts.pop();
  };

  Accumulator.prototype.size = function () {
    var total = this.initialSize;
    for (var i = 0; i < this.parts.length; i += 1) {
      total += MT.py.length(this.parts[i][0]) + MT.py.length(this.parts[i][1]);
    }
    return total;
  };

  Accumulator.prototype.text = function () {
    return this.parts
      .map(function (part) {
        return part[0] + part[1];
      })
      .join("");
  };

  Accumulator.prototype.reset = function (start) {
    this.parts = start || [];
    this.initialSize = 0;
  };

  Accumulator.prototype.isOnlySpace = function () {
    return this.initialSize === 0 && (this.size() === 0 || MT.py.isSpaceText(this.text()));
  };

  function Formatter(headerLength, maxLength, splitChars) {
    this.maxLength = maxLength;
    this.splitChars = splitChars;
    this.lines = [];
    this.current = new Accumulator(headerLength);
  }

  Formatter.prototype.render = function (linesep) {
    this.newline();
    return this.lines.join(linesep);
  };

  Formatter.prototype.newline = function () {
    var ending = this.current.pop();
    if (ending[0] !== " " || ending[1] !== "") this.current.push(ending[0], ending[1]);
    if (this.current.size() > 0) {
      if (this.current.isOnlySpace() && this.lines.length) {
        this.lines[this.lines.length - 1] += this.current.text();
      } else {
        this.lines.push(this.current.text());
      }
    }
    this.current.reset();
  };

  Formatter.prototype.addTransition = function () {
    this.current.push(" ", "");
  };

  Formatter.prototype.feed = function (fws, text, charset) {
    if (charset.headerEncoding === null) {
      var parts = (fws + text).split(FOLDING_SPACE);
      if (parts[0]) {
        parts.unshift("");
      } else {
        parts.shift();
      }
      for (var i = 0; i + 1 < parts.length; i += 2) this.appendChunk(parts[i], parts[i + 1]);
      return;
    }
    var self = this;
    var first = true;
    var maxlengths = function () {
      if (first) {
        first = false;
        return self.maxLength - self.current.size();
      }
      return self.maxLength - 1;
    };
    var encodedLines = charset.headerEncodeLines(text, maxlengths);
    if (!encodedLines.length) return;
    var firstLine = encodedLines.shift();
    if (firstLine !== null) this.appendChunk(fws, firstLine);
    if (!encodedLines.length) return;
    var lastLine = encodedLines.pop();
    this.newline();
    this.current.push(" ", lastLine);
    encodedLines.forEach(function (line) {
      self.lines.push(" " + line);
    });
  };

  Formatter.prototype.appendChunk = function (fws, text) {
    this.current.push(fws, text);
    if (this.current.size() <= this.maxLength) return;
    var parts = this.current.parts;
    var splitAt = -1;
    for (var c = 0; c < this.splitChars.length && splitAt < 0; c += 1) {
      var ch = this.splitChars[c];
      var space = MT.py.isSpace(ch);
      for (var i = parts.length - 1; i > 0; i -= 1) {
        if (space) {
          var lead = parts[i][0];
          if (lead && lead[0] === ch) {
            splitAt = i;
            break;
          }
        }
        var previous = parts[i - 1][1];
        if (previous && previous[previous.length - 1] === ch) {
          splitAt = i;
          break;
        }
      }
    }
    if (splitAt < 0) {
      var popped = this.current.pop();
      var leading = popped[0];
      if (this.current.initialSize > 0) {
        this.newline();
        if (!leading) leading = " ";
      }
      this.current.push(leading, popped[1]);
      return;
    }
    var remainder = this.current.popFrom(splitAt);
    this.lines.push(this.current.text());
    this.current.reset(remainder);
  };

  Header.prototype.encode = function (linesep, maxLineLength) {
    this.normalize();
    var limit = maxLineLength === undefined || maxLineLength === null ? this.maxLineLength : maxLineLength;
    if (limit === 0) limit = 1000000;
    var formatter = new Formatter(this.headerLength, limit, ";, \t");
    var lastCharset = null;
    var hasSpace = null;
    var lastSpace = null;
    this.chunks.forEach(function (chunk) {
      var text = chunk[0];
      var charset = chunk[1];
      if (hasSpace !== null) {
        hasSpace = text && nonCtext(firstPoint(text));
        if (!isPlain(lastCharset)) {
          if (!hasSpace || !isPlain(charset)) formatter.addTransition();
        } else if (!isPlain(charset) && !lastSpace) {
          formatter.addTransition();
        }
      }
      lastSpace = text && nonCtext(lastPoint(text));
      lastCharset = charset;
      hasSpace = false;
      var lines = MT.py.splitlines(text);
      formatter.feed("", lines.length ? lines[0] : "", charset);
      for (var i = 1; i < lines.length; i += 1) {
        formatter.newline();
        var stripped = MT.py.lstrip(lines[i]);
        var fws = lines[i].slice(0, lines[i].length - stripped.length);
        if (charset.headerEncoding !== null) formatter.feed(" ", " " + stripped, charset);
        else formatter.feed(fws, stripped, charset);
      }
      if (lines.length > 1) formatter.newline();
    });
    if (this.chunks.length) formatter.addTransition();
    var value = formatter.render(linesep);
    if (EMBEDDED_HEADER.test(value)) {
      throw new MessageError("HeaderParseError", "header value appears to contain an embedded header");
    }
    return value;
  };

  function headerDecodeQ(text) {
    return MT.py.replaceAll(text, "_", " ").replace(QUOTED_HEX, function (found) {
      return String.fromCharCode(parseInt(found.slice(1), 16));
    });
  }

  function decodeHeader(header) {
    var pattern = rx().encodedWord;
    if (!pattern.search(header)) return [[header, null]];
    var words = [];
    MT.py.splitlines(header).forEach(function (line) {
      var parts = pattern.split(line);
      var first = true;
      while (parts.length) {
        var unencoded = parts.shift();
        if (first) {
          unencoded = MT.py.lstrip(unencoded);
          first = false;
        }
        if (unencoded) words.push([unencoded, null, null]);
        if (parts.length) {
          var charset = parts.shift().toLowerCase();
          var encoding = parts.shift().toLowerCase();
          var encoded = parts.shift();
          words.push([encoded, encoding, charset]);
        }
      }
    });
    var drop = [];
    words.forEach(function (word, n) {
      if (n > 1 && word[1] && words[n - 2][1] && MT.py.isSpaceText(words[n - 1][0])) drop.push(n - 1);
    });
    for (var d = drop.length - 1; d >= 0; d -= 1) words.splice(drop[d], 1);

    var decoded = [];
    words.forEach(function (word) {
      var text = word[0];
      if (word[1] === null) {
        decoded.push([text, word[2]]);
      } else if (word[1] === "q") {
        decoded.push([headerDecodeQ(text), word[2]]);
      } else {
        var padError = MT.py.length(text) % 4;
        if (padError) text += "===".slice(0, 4 - padError);
        var raw;
        if (!text) {
          raw = new Uint8Array(0);
        } else {
          try {
            raw = MT.binascii.a2bBase64(MT.codecs.rawUnicodeEscape(text), false);
          } catch (error) {
            if (error instanceof MT.binascii.Error) throw new MessageError("HeaderParseError", "Base64 decoding error");
            throw error;
          }
        }
        decoded.push([raw, word[2]]);
      }
    });

    var collapsed = [];
    var lastWord = null;
    var lastCharset = null;
    decoded.forEach(function (item) {
      var word = typeof item[0] === "string" ? MT.codecs.rawUnicodeEscape(item[0]) : item[0];
      var charset = item[1];
      if (lastWord === null) {
        lastWord = word;
        lastCharset = charset;
      } else if (charset !== lastCharset) {
        collapsed.push([lastWord, lastCharset]);
        lastWord = word;
        lastCharset = charset;
      } else if (lastCharset === null) {
        lastWord = MT.bytes.concat([lastWord, new Uint8Array([32]), word]);
      } else {
        lastWord = MT.bytes.concat([lastWord, word]);
      }
    });
    collapsed.push([lastWord, lastCharset]);
    return collapsed;
  }

  function makeHeader(sequence) {
    var header = new Header();
    sequence.forEach(function (item) {
      header.append(item[0], item[1] === null ? null : new Charset(item[1]));
    });
    return header;
  }

  function cloneMessage(msg) {
    var copy = new Message();
    copy.headers = msg.headers.map(function (pair) {
      return [pair[0], pair[1]];
    });
    copy.unixfrom = msg.unixfrom;
    copy.payload = msg.payload;
    copy.preamble = msg.preamble;
    copy.epilogue = msg.epilogue;
    copy.defects = msg.defects.slice();
    copy.defaultType = msg.defaultType;
    return copy;
  }

  function deleteHeader(msg, name) {
    var wanted = name.toLowerCase();
    msg.headers = msg.headers.filter(function (pair) {
      return pair[0].toLowerCase() !== wanted;
    });
  }

  function appendHeader(msg, name, value) {
    msg.headers.push([name, value]);
  }

  function replaceHeader(msg, name, value) {
    var wanted = name.toLowerCase();
    for (var i = 0; i < msg.headers.length; i += 1) {
      if (msg.headers[i][0].toLowerCase() === wanted) {
        msg.headers[i] = [msg.headers[i][0], value];
        return;
      }
    }
    throw new MessageError("KeyError", name);
  }

  function percentEncode(bytes) {
    var out = [];
    for (var i = 0; i < bytes.length; i += 1) {
      var ch = String.fromCharCode(bytes[i]);
      if (ALWAYS_SAFE.test(ch)) out.push(ch);
      else out.push("%" + HEX.charAt(bytes[i] >> 4) + HEX.charAt(bytes[i] & 15));
    }
    return out.join("");
  }

  function encodeRfc2231(text, charset, language) {
    var encoded = percentEncode(MT.codecs.encode(text, charset === null ? "ascii" : charset, "strict"));
    if (charset === null && language === null) return encoded;
    return (charset === null ? "None" : charset) + "'" + (language === null ? "" : language) + "'" + encoded;
  }

  function formatParam(param, value) {
    if (value === null || value === undefined) return param;
    if (value instanceof Extended) return param + "*=" + encodeRfc2231(value.value, value.charset, value.language);
    if (!value.length) return param;
    if (!MT.codecs.isAscii(value)) return param + "*=" + encodeRfc2231(value, "utf-8", "");
    return param + '="' + quote(value) + '"';
  }

  function getParams(msg, header) {
    var params = msg.paramsPreserve(header);
    if (params === MISSING) return [];
    return params.map(function (pair) {
      return [pair[0], unquoteValue(pair[1])];
    });
  }

  function setParam(msg, param, value) {
    var header = "Content-Type";
    var ctype = msg.has(header) ? msg.get(header) : "text/plain";
    var existing = msg.getParam(param, header);
    if (existing === MISSING || !existing) {
      ctype = ctype ? ctype + "; " + formatParam(param, value) : formatParam(param, value);
    } else {
      ctype = "";
      getParams(msg, header).forEach(function (pair) {
        var piece = pair[0].toLowerCase() === param.toLowerCase() ? formatParam(param, value) : formatParam(pair[0], pair[1]);
        ctype = ctype ? ctype + "; " + piece : piece;
      });
    }
    if (ctype !== msg.get(header, null)) {
      deleteHeader(msg, header);
      appendHeader(msg, header, ctype);
    }
  }

  function encode7or8bit(msg) {
    var original = msg.decodedPayload();
    if (original === null) {
      appendHeader(msg, "Content-Transfer-Encoding", "7bit");
      return;
    }
    var ascii = true;
    for (var i = 0; i < original.length; i += 1) {
      if (original[i] > 0x7f) {
        ascii = false;
        break;
      }
    }
    appendHeader(msg, "Content-Transfer-Encoding", ascii ? "7bit" : "8bit");
  }

  function setCharset(msg, charset) {
    if (!msg.has("Content-Type")) appendHeader(msg, "Content-Type", "text/plain; " + formatParam("charset", charset.getOutputCharset()));
    else setParam(msg, "charset", charset.getOutputCharset());
    if (charset.name !== charset.getOutputCharset().toLowerCase()) msg.payload = charset.bodyEncode(msg.payload);
    if (msg.has("Content-Transfer-Encoding")) return;
    var cte = charset.getBodyEncoding();
    if (cte === null) {
      encode7or8bit(msg);
      return;
    }
    var payload = msg.payload;
    if (payload) {
      var bytes;
      try {
        bytes = MT.codecs.escapeEncode(payload);
      } catch (error) {
        if (!(error instanceof MT.codecs.EncodeError)) throw error;
        bytes = MT.codecs.encode(payload, charset.outputCharset, "strict");
      }
      msg.payload = charset.bodyEncode(bytes);
    } else {
      msg.payload = charset.bodyEncode(payload);
    }
    appendHeader(msg, "Content-Transfer-Encoding", cte);
  }

  function setPayload(msg, text, charsetParam) {
    if (charsetParam instanceof Extended) throw new MessageError("TypeError", "the charset parameter is not a string");
    var charset = new Charset(charsetParam);
    var encoded = MT.codecs.encode(text, charset.outputCharset, "surrogateescape");
    msg.payload = MT.codecs.escapeDecode(encoded);
    setCharset(msg, charset);
  }

  function Generator(maxLineLength, asText) {
    this.maxLineLength = maxLineLength;
    this.asText = Boolean(asText);
    this.mungeCte = null;
  }

  Generator.prototype.child = function () {
    return new Generator(this.maxLineLength, this.asText);
  };

  Generator.prototype.fold = function (name, value) {
    var parts = [name + ": "];
    var header;
    if (MT.codecs.hasSurrogates(value)) {
      if (this.asText) {
        header = new Header(name);
        header.append(value, new Charset(UNKNOWN8BIT));
        parts.push(header.encode("\n", this.maxLineLength));
      } else {
        parts.push(value);
      }
    } else {
      header = new Header(name);
      header.append(value, null);
      parts.push(header.encode("\n", this.maxLineLength));
    }
    parts.push("\n");
    return parts.join("");
  };

  Generator.prototype.headers = function (msg) {
    var out = [];
    for (var i = 0; i < msg.headers.length; i += 1) {
      var folded = this.fold(msg.headers[i][0], msg.headers[i][1]);
      if (NEWLINE_WITHOUT_SPACE.test(folded.slice(0, -1))) {
        throw new MessageError("HeaderWriteError", "folded header contains newline");
      }
      out.push(folded);
    }
    out.push("\n");
    return out.join("");
  };

  function writeLines(out, text) {
    if (!text) return;
    var lines = text.split(NEWLINE_ANY);
    for (var i = 0; i < lines.length - 1; i += 1) out.push(lines[i], "\n");
    if (lines[lines.length - 1]) out.push(lines[lines.length - 1]);
  }

  Generator.prototype.text = function (msg, out) {
    if (msg.payload === null) return;
    if (typeof msg.payload !== "string") throw new MessageError("TypeError", "string payload expected");
    if (!this.asText) {
      writeLines(out, msg.payload);
      return;
    }
    var payload = msg.textPayload();
    if (MT.codecs.hasSurrogates(msg.payload)) {
      var charset = msg.getParam("charset");
      if (charset !== MISSING) {
        var copy = cloneMessage(msg);
        deleteHeader(copy, "content-transfer-encoding");
        setPayload(copy, copy.payload, charset);
        payload = copy.textPayload();
        this.mungeCte = [copy.get("content-transfer-encoding", null), copy.get("content-type", null)];
      }
    }
    writeLines(out, payload);
  };

  Generator.prototype.boundaryFor = function (texts) {
    var all = texts.join("\n");
    var digest = MT.bytes.toHex(MT.binascii.blake2b(MT.codecs.rawUnicodeEscape(all), 8));
    var token = String(parseInt(digest.slice(0, 13), 16));
    while (token.length < 19) token = "0" + token;
    var boundary = "===============" + token + "==";
    var candidate = boundary;
    var counter = 0;
    var lines = all.split("\n");
    var taken = function (value) {
      return lines.some(function (line) {
        var bare = line.slice(-1) === "\r" ? line.slice(0, -1) : line;
        return bare === "--" + value || bare === "--" + value + "--";
      });
    };
    while (taken(candidate)) {
      candidate = boundary + "." + counter;
      counter += 1;
    }
    return candidate;
  };

  Generator.prototype.multipart = function (msg, out) {
    var subparts = msg.payload;
    if (subparts === null) {
      subparts = [];
    } else if (typeof subparts === "string") {
      var text = msg.textPayload();
      if (!this.asText && !MT.codecs.isAscii(text) && !isEscapedOnly(text)) {
        throw new MessageError("UnicodeEncodeError", "the multipart body is not ASCII");
      }
      out.push(text);
      return;
    }
    var self = this;
    var texts = subparts.map(function (part) {
      return self.child().flatten(part);
    });
    var boundary = msg.getBoundary();
    if (!boundary) {
      boundary = this.boundaryFor(texts);
      setBoundary(msg, boundary);
    }
    if (msg.preamble !== null) {
      writeLines(out, msg.preamble);
      out.push("\n");
    }
    out.push("--" + boundary + "\n");
    if (texts.length) out.push(texts.shift());
    texts.forEach(function (body) {
      out.push("\n--" + boundary + "\n");
      out.push(body);
    });
    out.push("\n--" + boundary + "--\n");
    if (msg.epilogue !== null) writeLines(out, msg.epilogue);
  };

  function tupleText(value) {
    var items = [value.charset, value.language, value.value].map(function (item) {
      if (item === null) return "None";
      var escaped = MT.py.replaceAll(item, "\\", "\\\\");
      if (item.indexOf("'") >= 0 && item.indexOf('"') < 0) return '"' + escaped + '"';
      return "'" + MT.py.replaceAll(escaped, "'", "\\'") + "'";
    });
    return "(" + items.join(", ") + ")";
  }

  function setBoundary(msg, boundary) {
    var params = msg.paramsPreserve("content-type");
    if (params === MISSING) throw new MessageError("HeaderParseError", "No Content-Type header found");
    var next = [];
    var found = false;
    params.forEach(function (pair) {
      if (pair[0].toLowerCase() === "boundary") {
        next.push(["boundary", '"' + boundary + '"']);
        found = true;
      } else {
        next.push(pair);
      }
    });
    if (!found) next.push(["boundary", '"' + boundary + '"']);
    var value = next
      .map(function (pair) {
        if (pair[1] === "") return pair[0];
        return pair[0] + "=" + (pair[1] instanceof Extended ? tupleText(pair[1]) : pair[1]);
      })
      .join("; ");
    msg.headers = msg.headers.map(function (pair) {
      return pair[0].toLowerCase() === "content-type" ? [pair[0], value] : pair;
    });
  }

  function isEscapedOnly(text) {
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      if (code > 127 && (code < 0xdc80 || code > 0xdcff)) return false;
    }
    return true;
  }

  Generator.prototype.multipartSigned = function (msg, out) {
    var kept = this.maxLineLength;
    this.maxLineLength = 0;
    try {
      this.multipart(msg, out);
    } finally {
      this.maxLineLength = kept;
    }
  };

  Generator.prototype.deliveryStatus = function (msg, out) {
    var payload = msg.payload;
    if (payload === null) throw new MessageError("TypeError", "the delivery status has no blocks");
    if (typeof payload === "string") {
      if (payload) throw new MessageError("AttributeError", "the delivery status is not a list of blocks");
      return;
    }
    var self = this;
    var blocks = payload.map(function (part) {
      var text = self.child().flatten(part);
      var lines = text.split("\n");
      if (lines.length && lines[lines.length - 1] === "") return lines.slice(0, -1).join("\n");
      return text;
    });
    out.push(blocks.join("\n"));
  };

  Generator.prototype.message = function (msg, out) {
    var payload = msg.payload;
    if (Array.isArray(payload)) {
      if (!payload.length) throw new MessageError("IndexError", "the embedded message is missing");
      out.push(this.child().flatten(payload[0]));
      return;
    }
    if (payload === null) throw new MessageError("AttributeError", "the embedded message is missing");
    if (!this.asText && !MT.codecs.isAscii(payload)) {
      throw new MessageError("UnicodeEncodeError", "the embedded message is not ASCII");
    }
    out.push(payload);
  };

  var HANDLERS = {
    text: "text",
    multipart: "multipart",
    multipart_signed: "multipartSigned",
    message: "message",
    message_delivery_status: "deliveryStatus",
  };

  Generator.prototype.dispatch = function (msg, out) {
    var main = msg.getContentMaintype();
    var sub = msg.getContentSubtype();
    var specific = MT.py.replaceAll(main + "_" + sub, "-", "_");
    var method = MT.own(HANDLERS, specific) ? HANDLERS[specific] : null;
    if (method === null) {
      var generic = MT.py.replaceAll(main, "-", "_");
      method = MT.own(HANDLERS, generic) ? HANDLERS[generic] : "text";
    }
    this[method](msg, out);
  };

  Generator.prototype.flatten = function (msg) {
    var body = [];
    this.mungeCte = null;
    this.dispatch(msg, body);
    var target = msg;
    if (this.mungeCte !== null) {
      target = cloneMessage(msg);
      if (target.get("content-transfer-encoding", null) === null) appendHeader(target, "Content-Transfer-Encoding", this.mungeCte[0]);
      else replaceHeader(target, "content-transfer-encoding", this.mungeCte[0]);
      replaceHeader(target, "content-type", this.mungeCte[1]);
      this.mungeCte = null;
    }
    return this.headers(target) + body.join("");
  };

  function asBytes(msg) {
    return MT.codecs.escapeEncode(new Generator(78, false).flatten(msg));
  }

  function asText(msg) {
    var text = new Generator(0, true).flatten(msg);
    var out = [];
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
        var next = text.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          out.push(text[i], text[i + 1]);
          i += 1;
          continue;
        }
      }
      out.push(code >= 0xd800 && code <= 0xdfff ? "?" : text[i]);
    }
    return MT.bytes.utf8Encode(out.join(""));
  }

  MT.message = {
    Message: Message,
    Parser: Parser,
    Extended: Extended,
    Charset: Charset,
    Header: Header,
    MISSING: MISSING,
    Error: MessageError,
    parseBytes: parseBytes,
    splitLines: splitLines,
    splitParam: splitParam,
    unquoteValue: unquoteValue,
    parseParam: parseParam,
    decodeParams: decodeParams,
    collapse: collapse,
    unquote: unquote,
    quote: quote,
    unquotePercent: unquotePercent,
    decodeHeader: decodeHeader,
    makeHeader: makeHeader,
    asBytes: asBytes,
    asText: asText,
    qpBodyEncode: qpBodyEncode,
    base64BodyEncode: base64BodyEncode,
  };
})(MT);
