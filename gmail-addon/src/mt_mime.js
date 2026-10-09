var MT = MT || {};

(function (MT) {
  var HTML_SPACE = /[ \t\r\f\v\xa0]+/g;
  var AROUND_NEWLINE = / *\n */g;
  var MANY_NEWLINES = /\n{3,}/g;
  var PATH_SEPARATOR = /[\\/]/;

  function K() {
    return MT.K("parser");
  }

  function lenient(call, fallback) {
    try {
      return call();
    } catch (error) {
      if (MT.trace) MT.trace(error);
      return fallback;
    }
  }

  function isCodecError(error) {
    return (
      error instanceof MT.codecs.LookupError ||
      error instanceof MT.codecs.DecodeError ||
      error instanceof MT.codecs.NullByteError
    );
  }

  function unfold(value) {
    return MT.py.joinWords(MT.RX("parser", "_FOLD_RE").sub(" ", value));
  }

  function decodeHeaderValue(value) {
    if (value === null || value === undefined) return "";
    var text = unfold(String(value));
    if (text.indexOf("=?") < 0) return text;
    var decoded = lenient(function () {
      return unfold(MT.message.makeHeader(MT.message.decodeHeader(text)).toString());
    }, "");
    if (decoded) return decoded;
    var chunks = lenient(function () {
      return MT.message.decodeHeader(text);
    }, []);
    if (!chunks.length) return text;
    var out = [];
    chunks.forEach(function (chunk) {
      if (typeof chunk[0] === "string") {
        out.push(chunk[0]);
        return;
      }
      var piece = "";
      var encodings = [chunk[1], "utf-8", "latin-1"];
      for (var i = 0; i < encodings.length; i += 1) {
        if (!encodings[i]) continue;
        try {
          piece = MT.codecs.decode(chunk[0], encodings[i], "replace");
          break;
        } catch (error) {
          if (isCodecError(error)) continue;
          throw error;
        }
      }
      out.push(piece || MT.codecs.decode(chunk[0], "latin-1", "replace"));
    });
    return unfold(out.join(""));
  }

  function emptyAddress() {
    return { raw: "", display_name: "", address: "", local_part: "", domain: "" };
  }

  function addressFromPair(name, addr, raw) {
    var py = MT.py;
    var address = py.strip(py.strip(py.strip(addr || ""), "<>")).toLowerCase();
    var display = name;
    if (address.indexOf("@") < 0) {
      var found = MT.RX("parser", "_EMAIL_RE").search(raw);
      if (found) {
        address = found[0].toLowerCase();
        if (!display) display = py.replaceAll(raw, found[0], "");
      }
    }
    display = MT.RX("parser", "_CONTROL_RE").sub("", display || "");
    display = py.strip(py.strip(py.strip(py.strip(py.strip(py.strip(display), "<>")), '"'), "'"));
    var localPart = address;
    var domain = "";
    if (address.indexOf("@") >= 0) {
      var parts = py.rpartition(address, "@");
      localPart = parts[0];
      domain = parts[2];
    }
    return { raw: raw, display_name: display, address: address, local_part: localPart, domain: domain };
  }

  function parseAddress(value) {
    var raw = MT.py.strip(decodeHeaderValue(value || ""));
    if (!raw) return emptyAddress();
    var pair = lenient(function () {
      return MT.address.parseaddr(raw);
    }, ["", ""]);
    return addressFromPair(pair[0], pair[1], raw);
  }

  function parseAddressList(value) {
    var raw = MT.py.strip(decodeHeaderValue(value || ""));
    if (!raw) return [];
    var result = [];
    var pairs = lenient(function () {
      return MT.address.getaddresses([raw]);
    }, []);
    pairs.forEach(function (pair) {
      var name = pair[0];
      var addr = pair[1];
      if (addr && addr.indexOf("@") >= 0) {
        result.push(addressFromPair(name, addr, name ? MT.py.strip(name + " <" + addr + ">") : addr));
      }
    });
    if (!result.length) {
      MT.RX("parser", "_EMAIL_RE")
        .finditer(raw)
        .forEach(function (found) {
          result.push(addressFromPair("", found[0], found[0]));
        });
    }
    return result;
  }

  function firstHeader(msg, name) {
    var value = lenient(function () {
      return msg.get(name, null);
    }, null);
    return value !== null ? decodeHeaderValue(value) : "";
  }

  function joinedHeaders(msg, name) {
    var values = lenient(function () {
      return msg.getAll(name) || [];
    }, []);
    return values
      .filter(function (value) {
        return value !== null && value !== undefined;
      })
      .map(decodeHeaderValue)
      .join(", ");
  }

  function parseDate(value) {
    if (!value) return null;
    return MT.time.iso(MT.address.parseDate(value));
  }

  function htmlToText(html) {
    if (!html) return "";
    var block = K()._BLOCK_TAGS;
    var skip = K()._SKIP_TAGS;
    var chunks = [];
    var skipDepth = 0;
    lenient(function () {
      MT.html.parse(html, {
        starttag: function (tag) {
          if (skip.has(tag)) {
            skipDepth += 1;
            return;
          }
          if (block.has(tag)) chunks.push("\n");
          if (tag === "li") {
            chunks.push("- ");
          } else if (tag === "td" || tag === "th") {
            chunks.push(" ");
          }
        },
        endtag: function (tag) {
          if (skip.has(tag)) {
            skipDepth = Math.max(0, skipDepth - 1);
          } else if (block.has(tag)) {
            chunks.push("\n");
          }
        },
        data: function (data) {
          if (!skipDepth) chunks.push(data);
        },
      });
    }, null);
    var text = chunks.join("");
    text = text.replace(HTML_SPACE, " ");
    text = text.replace(AROUND_NEWLINE, "\n");
    text = text.replace(MANY_NEWLINES, "\n\n");
    return MT.py.strip(text);
  }

  function contentType(part) {
    return lenient(function () {
      return part.getContentType().toLowerCase();
    }, K()._OCTET_STREAM);
  }

  function header(part, name) {
    return lenient(function () {
      return String(part.get(name, null) || "");
    }, "");
  }

  function walk(part, depth, visit) {
    if (depth > K()._MAX_DEPTH) return true;
    var ctype = contentType(part);
    if (ctype === "message/rfc822") return visit("rfc822", part);
    if (part.isMultipart()) {
      for (var i = 0; i < part.payload.length; i += 1) {
        if (!walk(part.payload[i], depth + 1, visit)) return false;
      }
      return true;
    }
    return visit("leaf", part);
  }

  function sanitizeFilename(name) {
    var cleaned = MT.py.strip(MT.RX("parser", "_CONTROL_RE").sub("", name || ""));
    var pieces = cleaned.split(PATH_SEPARATOR);
    return MT.py.slice(MT.py.strip(pieces[pieces.length - 1]), 0, 255);
  }

  function pythonText(value) {
    if (value === null) return "None";
    return String(value);
  }

  function partFilename(part) {
    var name = lenient(function () {
      return part.getFilename();
    }, null);
    if (!name) {
      name = lenient(function () {
        var found = part.getParam("name");
        return found === MT.message.MISSING ? null : found;
      }, null);
    }
    if (name instanceof MT.message.Extended) {
      var encoded = name;
      name = lenient(function () {
        return MT.message.collapse(encoded);
      }, encoded.value);
    } else if (!name) {
      return "";
    }
    return sanitizeFilename(decodeHeaderValue(pythonText(name)));
  }

  function extension(filename) {
    if (filename.indexOf(".") < 0) return "";
    var pieces = MT.py.rsplit(filename, ".", 1);
    var ext = MT.py.strip(pieces[pieces.length - 1]).toLowerCase();
    return ext && MT.py.length(ext) <= 10 && MT.py.isAlnum(ext) ? ext : "";
  }

  function decodePayload(part) {
    var payload = lenient(function () {
      return part.decodedPayload();
    }, null);
    if (payload === null) {
      payload = lenient(function () {
        var raw = part.isMultipart() ? null : part.textPayload();
        return typeof raw === "string" ? utf8Replace(raw) : new Uint8Array(0);
      }, new Uint8Array(0));
    }
    return payload;
  }

  function utf8Replace(text) {
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

  function normalNewlines(text) {
    return MT.py.replaceAll(text, "\r\n", "\n");
  }

  function decodeText(part, issues, label) {
    var data = decodePayload(part);
    if (!data.length) return "";
    var charset = lenient(function () {
      return part.getContentCharset();
    }, null);
    var encodings = [charset, "utf-8"];
    for (var i = 0; i < encodings.length; i += 1) {
      if (!encodings[i]) continue;
      try {
        return normalNewlines(MT.codecs.decode(data, encodings[i], "strict"));
      } catch (error) {
        if (isCodecError(error)) continue;
        throw error;
      }
    }
    var text;
    try {
      text = MT.codecs.decode(data, charset || "cp1252", "replace");
    } catch (error) {
      if (!isCodecError(error)) throw error;
      text = MT.codecs.decode(data, "cp1252", "replace");
    }
    issues.push(label + " part could not be decoded cleanly (declared charset " + (charset || "none") + ")");
    return normalNewlines(text);
  }

  function embeddedMessageBytes(part) {
    var payload = part.payload;
    if (Array.isArray(payload) && payload.length) {
      var inner = payload[0];
      var data = lenient(function () {
        return MT.message.asBytes(inner);
      }, new Uint8Array(0));
      if (data.length) return data;
      return lenient(function () {
        return MT.message.asText(inner);
      }, new Uint8Array(0));
    }
    return decodePayload(part);
  }

  function basicMeta(attachment) {
    return {
      filename: attachment.filename,
      content_type: attachment.content_type,
      size: attachment.data.length,
      sha256: MT.platform.sha256(attachment.data),
      md5: MT.platform.md5(attachment.data),
      extension: extension(attachment.filename),
      magic_type: "",
      mime_mismatch: false,
      is_archive: false,
      has_macros: false,
      double_extension: false,
      shannon_entropy: 0.0,
      high_entropy: false,
      risk: "info",
      reasons: [],
    };
  }

  function shingles(text) {
    var words = MT.RX("parser", "_WORD_RE").findall((text || "").toLowerCase());
    var counts = new Map();
    if (!words.length) return counts;
    var size = K()._SHINGLE_SIZE;
    var add = function (key) {
      counts.set(key, (counts.get(key) || 0) + 1);
    };
    if (words.length < size) {
      words.forEach(add);
      return counts;
    }
    for (var index = 0; index + size <= words.length; index += 1) add(words.slice(index, index + size).join(" "));
    return counts;
  }

  function simhashHex(text) {
    var counts = shingles(text);
    if (!counts.size) return "0000000000000000";
    var columns = new Float64Array(64);
    counts.forEach(function (weight, shingle) {
      var digest = MT.binascii.blake2b(MT.bytes.utf8Encode(MT.codecs.hasSurrogates(shingle) ? stripSurrogates(shingle) : shingle), 8);
      for (var position = 0; position < 64; position += 1) {
        var bit = (digest[7 - (position >> 3)] >> (position & 7)) & 1;
        columns[position] += bit ? weight : -weight;
      }
    });
    var out = new Uint8Array(8);
    for (var p = 0; p < 64; p += 1) {
      if (columns[p] > 0) out[7 - (p >> 3)] |= 1 << (p & 7);
    }
    return MT.bytes.toHex(out);
  }

  function stripSurrogates(text) {
    return MT.bytes.utf8Decode(utf8Replace(text), true);
  }

  function hammingDistance(left, right) {
    var a = MT.py.strip(left || "").toLowerCase();
    var b = MT.py.strip(right || "").toLowerCase();
    var width = 4 * Math.max(a.length, b.length, 16);
    if (!a || !b || a.length !== b.length) return width;
    if (!/^[0-9a-f_]+$/.test(a) || !/^[0-9a-f_]+$/.test(b)) return width;
    if (a.indexOf("_") >= 0 || b.indexOf("_") >= 0) return width;
    var total = 0;
    for (var i = 0; i < a.length; i += 1) {
      var value = parseInt(a[i], 16) ^ parseInt(b[i], 16);
      while (value) {
        total += value & 1;
        value >>= 1;
      }
    }
    return total;
  }

  function finalise(parsed, attachments) {
    try {
      var body = parsed.text_body || htmlToText(parsed.html_body);
      parsed.fuzzy = {
        simhash: body ? simhashHex(body) : "",
        tlsh: "",
        body_length: MT.py.length(body),
      };
    } catch (error) {
      if (MT.trace) MT.trace(error);
      parsed.charset_issues.push("body digest could not be computed");
    }
    return { email: parsed, attachments: attachments };
  }

  function isBlank(raw) {
    for (var i = 0; i < raw.length; i += 1) {
      var b = raw[i];
      if (b !== 32 && (b < 9 || b > 13)) return false;
    }
    return true;
  }

  function parseEmail(raw) {
    var bytes = raw || new Uint8Array(0);
    var parsed = {
      message_id: "",
      subject: "",
      date: null,
      sender: emptyAddress(),
      reply_to: [],
      return_path: emptyAddress(),
      to: [],
      cc: [],
      headers: [],
      text_body: "",
      html_body: "",
      has_html: false,
      attachments: [],
      raw_sha256: MT.platform.sha256(bytes),
      raw_md5: MT.platform.md5(bytes),
      raw_size: bytes.length,
      mailer: "",
      charset_issues: [],
      fuzzy: { simhash: "", tlsh: "", body_length: 0 },
    };
    if (isBlank(bytes)) {
      parsed.charset_issues.push("empty message");
      return finalise(parsed, []);
    }
    var msg = lenient(function () {
      return MT.message.parseBytes(bytes);
    }, null);
    if (msg === null) {
      parsed.charset_issues.push("message could not be parsed");
      return finalise(parsed, []);
    }

    var py = MT.py;
    var headers = [];
    lenient(function () {
      msg.items().forEach(function (pair) {
        headers.push({ name: String(pair[0]), value: decodeHeaderValue(pair[1]) });
      });
    }, null);
    parsed.headers = headers;
    parsed.message_id = py.strip(py.strip(py.strip(firstHeader(msg, "Message-ID")), "<>"));
    parsed.subject = firstHeader(msg, "Subject");
    parsed.date = parseDate(firstHeader(msg, "Date"));
    parsed.sender = parseAddress(firstHeader(msg, "From"));
    parsed.reply_to = parseAddressList(joinedHeaders(msg, "Reply-To"));
    parsed.return_path = parseAddress(firstHeader(msg, "Return-Path"));
    parsed.to = parseAddressList(joinedHeaders(msg, "To"));
    parsed.cc = parseAddressList(joinedHeaders(msg, "Cc"));
    parsed.mailer = firstHeader(msg, "X-Mailer") || firstHeader(msg, "User-Agent");
    if (!headers.length) parsed.charset_issues.push("no headers found");

    var textParts = [];
    var htmlParts = [];
    var attachments = [];
    var issues = parsed.charset_issues;
    var counter = 0;
    var limit = K()._MAX_PARTS;
    var mimetypes = MT.json("knowledge").mimetypes;
    walk(msg, 0, function (kind, part) {
      counter += 1;
      if (counter > limit) {
        issues.push("message has more MIME parts than the parser limit; remainder ignored");
        return false;
      }
      var ctype = contentType(part);
      var disposition = header(part, "Content-Disposition").toLowerCase();
      var filename = partFilename(part);
      var attached = py.strip(disposition).slice(0, 10) === "attachment";
      var data;
      if (kind === "rfc822") {
        data = embeddedMessageBytes(part);
        attachments.push({
          filename: filename || "forwarded-" + counter + ".eml",
          content_type: "message/rfc822",
          data: data,
          content_id: "",
          is_inline: false,
        });
        return true;
      }
      if (ctype === "text/plain" && !attached && !filename) {
        textParts.push(decodeText(part, issues, "text/plain"));
        return true;
      }
      if (ctype === "text/html" && !attached && !filename) {
        htmlParts.push(decodeText(part, issues, "text/html"));
        return true;
      }
      data = decodePayload(part);
      var contentId = py.strip(py.strip(py.strip(header(part, "Content-ID")), "<>"));
      var inline = py.strip(disposition).slice(0, 6) === "inline" || (Boolean(contentId) && ctype.slice(0, 6) === "image/");
      if (!filename) {
        var guessed = MT.own(mimetypes, ctype) ? mimetypes[ctype] : "";
        filename = "part-" + counter + (guessed || ".bin");
      }
      attachments.push({ filename: filename, content_type: ctype, data: data, content_id: contentId, is_inline: inline });
      return true;
    });

    var keep = function (piece) {
      return Boolean(piece);
    };
    parsed.text_body = py.strip(textParts.filter(keep).join("\n\n"));
    parsed.html_body = py.strip(htmlParts.filter(keep).join("\n\n"));
    parsed.has_html = Boolean(parsed.html_body);
    if (!parsed.text_body && parsed.html_body) parsed.text_body = htmlToText(parsed.html_body);
    if (!parsed.text_body && !parsed.html_body && !attachments.length && !msg.isMultipart()) {
      parsed.text_body = decodeText(msg, issues, "body");
    }
    parsed.attachments = attachments.map(basicMeta);
    return finalise(parsed, attachments);
  }

  MT.mime = {
    parseEmail: parseEmail,
    htmlToText: htmlToText,
    decodeHeaderValue: decodeHeaderValue,
    parseAddress: parseAddress,
    parseAddressList: parseAddressList,
    parseDate: parseDate,
    simhashHex: simhashHex,
    hammingDistance: hammingDistance,
    extension: extension,
    sanitizeFilename: sanitizeFilename,
    unfold: unfold,
    lenient: lenient,
  };
})(MT);
