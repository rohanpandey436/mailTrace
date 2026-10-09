var MT = MT || {};

(function (MT) {
  var SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

  function py() {
    return MT.py;
  }

  function K() {
    return MT.K("file_analyzer");
  }

  function knowledge() {
    return MT.K("knowledge");
  }

  function BadZip(message) {
    this.name = "BadZipFile";
    this.message = message;
  }
  BadZip.prototype = Object.create(Error.prototype);

  var crcTable = null;

  function crc32(bytes) {
    if (!crcTable) {
      crcTable = new Uint32Array(256);
      for (var n = 0; n < 256; n += 1) {
        var c = n;
        for (var k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        crcTable[n] = c >>> 0;
      }
    }
    var crc = 0xffffffff;
    for (var i = 0; i < bytes.length; i += 1) crc = crcTable[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }

  function u16(data, at) {
    return data[at] | (data[at + 1] << 8);
  }

  function u32(data, at) {
    return (data[at] | (data[at + 1] << 8) | (data[at + 2] << 16)) + data[at + 3] * 16777216;
  }

  function u64(data, at) {
    return u32(data, at) + u32(data, at + 4) * 4294967296;
  }

  function startsWith(data, at, text) {
    if (at < 0 || at + text.length > data.length) return false;
    for (var i = 0; i < text.length; i += 1) if (data[at + i] !== text.charCodeAt(i)) return false;
    return true;
  }

  function findLast(data, from, to, text) {
    for (var i = to - text.length; i >= from; i -= 1) if (startsWith(data, i, text)) return i;
    return -1;
  }

  function endRecord64(data, offset, record) {
    offset -= 20;
    if (offset < 0) return record;
    if (offset + 20 > data.length) throw new BadZip("Unknown I/O error");
    if (!startsWith(data, offset, "PK\x06\x07")) return record;
    var diskno = u32(data, offset + 4);
    var reloff = u64(data, offset + 8);
    var disks = u32(data, offset + 16);
    if (diskno !== 0 || disks > 1) throw new BadZip("zipfiles that span multiple disks are not supported");
    offset -= 56;
    if (reloff > offset) throw new BadZip("Corrupt zip64 end of central directory locator");
    var at = reloff;
    var extra = offset - reloff;
    if (at + 56 > data.length) throw new BadZip("Unknown I/O error");
    if (!startsWith(data, at, "PK\x06\x06") && reloff !== offset) {
      at = offset;
      extra = 0;
      if (at + 56 > data.length) throw new BadZip("Unknown I/O error");
    }
    if (!startsWith(data, at, "PK\x06\x06")) throw new BadZip("Zip64 end of central directory record not found");
    var sz = u64(data, at + 4);
    var dircount = u64(data, at + 24);
    var dircount2 = u64(data, at + 32);
    var dirsize = u64(data, at + 40);
    var diroffset = u64(data, at + 48);
    if (diroffset + dirsize !== reloff || sz + 12 !== 56 + extra) throw new BadZip("Corrupt zip64 end of central directory record");
    record.entriesThisDisk = dircount;
    record.entriesTotal = dircount2;
    record.size = dirsize;
    record.offset = diroffset;
    record.location = offset - extra;
    return record;
  }

  function endRecord(data) {
    var size = data.length;
    if (size < 22) return null;
    var at = size - 22;
    if (startsWith(data, at, "PK\x05\x06") && data[size - 2] === 0 && data[size - 1] === 0) {
      return endRecord64(data, at, {
        size: u32(data, at + 12),
        offset: u32(data, at + 16),
        commentSize: u16(data, at + 20),
        location: at,
      });
    }
    var maxCommentStart = Math.max(size - 65536 - 22, 0);
    var start = findLast(data, maxCommentStart, size, "PK\x05\x06");
    if (start < 0) return null;
    if (start + 22 > size) return null;
    return endRecord64(data, start, {
      size: u32(data, start + 12),
      offset: u32(data, start + 16),
      commentSize: u16(data, start + 20),
      location: start,
    });
  }

  function sanitizeName(name) {
    var nul = name.indexOf(String.fromCharCode(0));
    return nul >= 0 ? name.slice(0, nul) : name;
  }

  function decodeExtra(entry, extra, filenameCrc) {
    var rest = extra;
    while (rest.length >= 4) {
      var tp = u16(rest, 0);
      var ln = u16(rest, 2);
      if (ln + 4 > rest.length) throw new BadZip("Corrupt extra field");
      var data = rest.subarray(4, ln + 4);
      if (tp === 0x0001) {
        var at = 0;
        if (entry.fileSize === 0xffffffff) {
          if (at + 8 > data.length) throw new BadZip("Corrupt zip64 extra field. File size not found.");
          entry.fileSize = u64(data, at);
          at += 8;
        }
        if (entry.compressSize === 0xffffffff) {
          if (at + 8 > data.length) throw new BadZip("Corrupt zip64 extra field. Compress size not found.");
          entry.compressSize = u64(data, at);
          at += 8;
        }
        if (entry.headerOffset === 0xffffffff) {
          if (at + 8 > data.length) throw new BadZip("Corrupt zip64 extra field. Header offset not found.");
          entry.headerOffset = u64(data, at);
        }
      } else if (tp === 0x7075) {
        if (data.length < 5) throw new BadZip("Corrupt unicode path extra field (0x7075)");
        var version = data[0];
        var nameCrc = u32(data, 1);
        if (version === 1 && nameCrc === filenameCrc) {
          var unicodeName = MT.codecs.decode(data.subarray(5), "utf-8", "strict");
          if (unicodeName) entry.filename = sanitizeName(unicodeName);
        }
      }
      rest = rest.subarray(ln + 4);
    }
  }

  function readZip(data) {
    var record = endRecord(data);
    if (!record) throw new BadZip("File is not a zip file");
    var sizeCd = record.size;
    var offsetCd = record.offset;
    var concat = record.location - sizeCd - offsetCd;
    var startDir = offsetCd + concat;
    if (startDir < 0) throw new BadZip("Bad offset for central directory");
    var directory = data.subarray(startDir, startDir + sizeCd);
    var entries = [];
    var total = 0;
    var position = 0;
    while (total < sizeCd) {
      if (position + 46 > directory.length) throw new BadZip("Truncated central directory");
      if (!startsWith(directory, position, "PK\x01\x02")) throw new BadZip("Bad magic number for central directory");
      var extractVersion = directory[position + 6];
      var flags = u16(directory, position + 8);
      var compressSize = u32(directory, position + 20);
      var fileSize = u32(directory, position + 24);
      var nameLength = u16(directory, position + 28);
      var extraLength = u16(directory, position + 30);
      var commentLength = u16(directory, position + 32);
      var headerOffset = u32(directory, position + 42);
      var nameBytes = directory.subarray(position + 46, position + 46 + nameLength);
      var extra = directory.subarray(position + 46 + nameLength, position + 46 + nameLength + extraLength);
      var filename = flags & 0x800 ? MT.codecs.decode(nameBytes, "utf-8", "strict") : MT.codecs.decode(nameBytes, "cp437", "strict");
      var entry = {
        filename: sanitizeName(filename),
        flags: flags,
        compressSize: compressSize,
        fileSize: fileSize,
        headerOffset: headerOffset,
      };
      if (extractVersion > 63) throw new BadZip("zip file version " + extractVersion / 10);
      decodeExtra(entry, extra, crc32(nameBytes));
      entries.push(entry);
      total = total + 46 + nameLength + extraLength + commentLength;
      position = total;
    }
    return entries;
  }

  function zipEntries(data) {
    try {
      return readZip(data);
    } catch (error) {
      if (error instanceof BadZip || error instanceof MT.codecs.DecodeError) return null;
      throw error;
    }
  }

  function shannonEntropy(data) {
    var total = data.length;
    if (!total) return 0.0;
    var counts = new Array(256).fill(0);
    var order = [];
    for (var i = 0; i < total; i += 1) {
      var b = data[i];
      if (counts[b] === 0) order.push(b);
      counts[b] += 1;
    }
    var entropy = 0.0;
    for (var k = 0; k < order.length; k += 1) {
      var p = counts[order[k]] / total;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  function imageClaimMismatch(ext, magic) {
    if (K()._SNIFFABLE_IMAGE_EXTS.has(ext)) return !K()._IMAGE_MAGIC.has(magic);
    if (K()._IMAGE_EXTS.has(ext)) return Boolean(magic) && !K()._IMAGE_MAGIC.has(magic);
    return false;
  }

  function entropyEscalates(extension, magic, highEntropy) {
    if (!highEntropy || knowledge().EXECUTABLE_MAGIC.has(magic)) return false;
    if (K()._INCOMPRESSIBLE_EXTS.has(extension)) return true;
    if (K()._ZIP_CONTAINER_DOC_EXTS.has(extension)) return magic !== "ooxml" && magic !== "zip";
    return imageClaimMismatch(extension, magic);
  }

  function looksText(sample) {
    if (!sample.length) return false;
    var printable = 0;
    for (var i = 0; i < sample.length; i += 1) {
      var b = sample[i];
      if (b === 0) return false;
      if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) printable += 1;
    }
    return printable / sample.length > 0.9;
  }

  function isOoxml(data) {
    var entries = zipEntries(data);
    if (!entries) return false;
    return entries.some(function (entry) {
      return entry.filename === "[Content_Types].xml";
    });
  }

  function bytesIndexOf(haystack, needle, limit) {
    var end = (limit === undefined ? haystack.length : Math.min(limit, haystack.length)) - needle.length;
    outer: for (var i = 0; i <= end; i += 1) {
      for (var k = 0; k < needle.length; k += 1) if (haystack[i + k] !== needle[k]) continue outer;
      return i;
    }
    return -1;
  }

  function asciiLower(data) {
    var out = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i += 1) {
      var b = data[i];
      out[i] = b >= 65 && b <= 90 ? b + 32 : b;
    }
    return out;
  }

  function asciiLstrip(data) {
    var i = 0;
    while (i < data.length && (data[i] === 32 || (data[i] >= 9 && data[i] <= 13))) i += 1;
    return data.subarray(i);
  }

  function contains(data, text) {
    return bytesIndexOf(data, MT.bytes.fromLatin1(text)) >= 0;
  }

  function sniffMagic(data) {
    if (!data.length) return "";
    var head = data.subarray(0, 16);
    var magics = K()._MAGIC;
    for (var i = 0; i < magics.length; i += 1) {
      if (bytesIndexOf(head, magics[i][0], magics[i][0].length) === 0) return magics[i][1];
    }
    var zips = K()._ZIP_MAGICS;
    for (var z = 0; z < zips.length; z += 1) {
      if (bytesIndexOf(head, zips[z], zips[z].length) === 0) return isOoxml(data) ? "ooxml" : "zip";
    }
    if (data.length > 0x8006 && MT.bytes.toLatin1(data.subarray(0x8001, 0x8006)) === "CD001") return "iso";
    var sample = data.subarray(0, 2048);
    var stripped = asciiLower(asciiLstrip(sample));
    if (startsWith(stripped, 0, "#!")) return "script";
    if (contains(stripped, "<hta:application")) return "hta";
    if (startsWith(stripped, 0, "<!doctype html") || startsWith(stripped, 0, "<html") || contains(stripped, "<script") || contains(stripped, "<body")) return "html";
    if (startsWith(stripped, 0, "<?xml")) return contains(stripped, "<html") ? "html" : "xml";
    if (looksText(sample.subarray(0, 512))) {
      var markers = K()._SCRIPT_MARKERS;
      for (var m = 0; m < markers.length; m += 1) if (bytesIndexOf(stripped, markers[m]) >= 0) return "script";
      return "text";
    }
    return "";
  }

  function inspectZip(data) {
    var result = { members: [], encrypted: false, risky_members: [], has_vba: false, ok: false };
    var entries = zipEntries(data);
    if (!entries) return result;
    entries.slice(0, 500).forEach(function (info) {
      var name = info.filename;
      result.members.push(name);
      if (info.flags & 0x1) result.encrypted = true;
      var lowered = name.toLowerCase();
      if (lowered.endsWith("vbaproject.bin")) result.has_vba = true;
      var ext = lowered.indexOf(".") >= 0 ? py().rsplit(lowered, ".", 1).pop() : "";
      var risk = knowledge().RISKY_EXTENSIONS.get(ext);
      if ((risk === "critical" || risk === "high") && !lowered.endsWith("/")) result.risky_members.push(name);
    });
    result.ok = true;
    return result;
  }

  function oleHasMacros(data) {
    var markers = K()._OLE_VBA_MARKERS;
    return bytesIndexOf(data, markers[0]) >= 0 || (bytesIndexOf(data, markers[1]) >= 0 && bytesIndexOf(data, markers[2]) >= 0);
  }

  function worse(current, candidate) {
    return SEVERITY_ORDER[candidate] > SEVERITY_ORDER[current] ? candidate : current;
  }

  function extension(filename) {
    return MT.mime.extension(filename);
  }

  function analyzeAttachment(att, cfg) {
    var data = att.data || new Uint8Array(0);
    var filename = att.filename || "unnamed";
    var collapsed = py().re("\\s{2,}").sub(" ", filename);
    var ext = extension(collapsed);
    var magic = sniffMagic(data);
    var reasons = [];
    var risky = knowledge().RISKY_EXTENSIONS;
    var severity = risky.has(ext) ? risky.get(ext) : "low";
    var isArchive = knowledge().ARCHIVE_EXTENSIONS.has(ext) || K()._ARCHIVE_MAGIC.has(magic);
    var hasMacros = false;
    var mimeMismatch = false;
    var declared = (att.content_type || "").toLowerCase();
    var imageExts = K()._IMAGE_EXTS;
    var imageMagic = K()._IMAGE_MAGIC;
    var executableMagic = knowledge().EXECUTABLE_MAGIC;

    if (ext && (severity === "critical" || severity === "high")) reasons.push("." + ext + " files can execute code or scripts when opened");

    var parts = py().replaceAll(collapsed.toLowerCase(), " ", "").split(".");
    var riskOfExt = risky.get(ext);
    var doubleExtension = parts.length >= 3 && K()._DOCUMENT_EXTS.has(parts[parts.length - 2]) && (riskOfExt === "critical" || riskOfExt === "high");
    if (doubleExtension) {
      severity = worse(severity, "high");
      reasons.push("Double extension disguises a ." + ext + " file as a ." + parts[parts.length - 2] + " document");
    }

    if (executableMagic.has(magic)) {
      severity = "critical";
      reasons.push("File content is an executable (" + magic + ") regardless of its name");
      if (!K()._EXEC_EXTS.has(ext)) mimeMismatch = true;
    }
    var officeOpen = ["docx", "xlsx", "pptx", "docm", "xlsm", "pptm"];
    var officeOld = ["doc", "xls", "ppt"];
    if (
      (ext === "pdf" && magic && magic !== "pdf") ||
      (imageExts.has(ext) && magic && !imageMagic.has(magic) && ext !== "svg") ||
      (officeOpen.indexOf(ext) >= 0 && magic && magic !== "ooxml" && magic !== "zip") ||
      (officeOld.indexOf(ext) >= 0 && magic && ["ole", "rtf", "text", "xml", "html"].indexOf(magic) < 0) ||
      (ext === "zip" && magic && magic !== "zip" && magic !== "ooxml") ||
      (declared === "application/pdf" && magic && magic !== "pdf")
    ) {
      mimeMismatch = true;
    }
    if (mimeMismatch) {
      severity = worse(severity, "high");
      reasons.push("Declared as " + (declared || (ext ? "." + ext : "") || "unknown") + " but the content looks like " + magic);
    }

    var macroExts = ["docm", "xlsm", "pptm", "dotm", "xltm", "xlam"];
    if (magic === "ooxml" || (macroExts.indexOf(ext) >= 0 && (magic === "ooxml" || magic === "zip"))) {
      if (inspectZip(data).has_vba) hasMacros = true;
    } else if (magic === "ole" && oleHasMacros(data)) {
      hasMacros = true;
    }
    if (macroExts.indexOf(ext) >= 0 && !hasMacros) hasMacros = true;
    if (hasMacros) {
      severity = worse(severity, "high");
      reasons.push("Document contains VBA macros");
    } else if (knowledge().MACRO_EXTENSIONS.has(ext) && officeOld.indexOf(ext) >= 0) {
      reasons.push("Legacy Office format can carry macros; open only in Protected View");
    }

    if (isArchive && (magic === "zip" || magic === "ooxml" || magic === "") && (["zip", "jar", "apk"].indexOf(ext) >= 0 || magic === "zip")) {
      var inspection = inspectZip(data);
      if (inspection.ok) {
        if (inspection.risky_members.length) {
          severity = "critical";
          reasons.push("Archive contains executable content: " + inspection.risky_members.slice(0, 3).join(", "));
        }
        if (inspection.encrypted) {
          severity = worse(severity, "high");
          reasons.push("Password-protected archive: contents cannot be scanned by gateways");
        }
      }
    } else if (isArchive && ["rar", "7z", "iso", "cab"].indexOf(magic) >= 0) {
      severity = worse(severity, "medium");
      reasons.push(magic.toUpperCase() + " container hides its contents from most mail scanners");
    }

    if (magic === "hta") {
      severity = "critical";
      reasons.push("HTML Application (HTA) runs with full local privileges");
    } else if (magic === "html" || ["html", "htm", "shtml"].indexOf(ext) >= 0) {
      var lowered = asciiLower(data.subarray(0, 65536));
      if (contains(lowered, "<script") || contains(lowered, "<form") || contains(lowered, "password")) {
        severity = worse(severity, "high");
        reasons.push("HTML attachment contains script/form content (typical credential-phishing page)");
      }
    }
    if (magic === "script" && ["txt", "csv", "log", "md"].indexOf(ext) < 0) {
      severity = worse(severity, "high");
      reasons.push("Content contains shell/PowerShell/script commands");
    }

    var entropy = shannonEntropy(data);
    var highEntropy = entropy >= cfg.entropy_threshold;
    if (highEntropy) {
      var measured = "entropy " + py().fixed(entropy, 2) + " of a possible 8.00, above the " + py().fixed(cfg.entropy_threshold, 1) + " threshold";
      if (executableMagic.has(magic)) {
        severity = worse(severity, "critical");
        reasons.push(
          "Executable is packed or obfuscated (" +
            measured +
            "): the real code is unpacked only at run time, which is how malware hides from signature scanners",
        );
      } else if (entropyEscalates(ext, magic, highEntropy)) {
        severity = worse(severity, "high");
        var claimed;
        if (imageClaimMismatch(ext, magic)) claimed = "a ." + ext + " image, but the bytes carry no image header";
        else if (K()._ZIP_CONTAINER_DOC_EXTS.has(ext)) claimed = "a ." + ext + " file, and the bytes are not the document container that name implies";
        else claimed = "a ." + ext + " file, which stores its contents uncompressed";
        reasons.push(
          "Content is almost random (" +
            measured +
            ") for " +
            claimed +
            ": this indicates packing, encryption or an embedded payload rather than an ordinary document",
        );
      } else if (K()._NATURALLY_COMPRESSED_EXTS.has(ext) || K()._NATURALLY_COMPRESSED_MAGIC.has(magic) || isArchive) {
        var kind = magic ? magic.toUpperCase() : ext ? "." + ext : "this";
        reasons.push("High " + measured + ", which is expected for " + kind + " content because it is compressed by design");
      }
    }

    if (!data.length) reasons.push("Attachment is empty");

    if (att.is_inline && (imageMagic.has(magic) || imageExts.has(ext)) && !mimeMismatch) {
      severity = "info";
      reasons = [];
    }

    return {
      filename: filename,
      content_type: att.content_type,
      size: data.length,
      sha256: MT.platform.sha256(data),
      md5: MT.platform.md5(data),
      extension: ext,
      magic_type: magic,
      mime_mismatch: mimeMismatch,
      is_archive: isArchive,
      has_macros: hasMacros,
      double_extension: doubleExtension,
      shannon_entropy: py().round(entropy, 3),
      high_entropy: highEntropy,
      risk: severity,
      reasons: reasons,
    };
  }

  function finding(id, severity, title, detail, evidence) {
    return { id: id, module: "attachments", severity: severity, title: title, detail: detail, evidence: evidence };
  }

  function names(items) {
    return (
      items
        .slice(0, 4)
        .map(function (a) {
          return a.filename;
        })
        .join(", ") + (items.length > 4 ? " ..." : "")
    );
  }

  function analyzeAttachments(rawAttachments, cfg) {
    var metas = [];
    var inlineFlags = [];
    (rawAttachments || []).forEach(function (att) {
      try {
        metas.push(analyzeAttachment(att, cfg));
        inlineFlags.push(Boolean(att.is_inline));
      } catch (error) {
        if (MT.trace) MT.trace(error);
      }
    });
    var scored = metas.filter(function (m, index) {
      return !inlineFlags[index];
    });
    var severe = scored.filter(function (m) {
      return SEVERITY_ORDER[m.risk] >= SEVERITY_ORDER.high;
    });
    var riskValue = K()._RISK_VALUE;
    var top = 0;
    scored.forEach(function (m) {
      top = Math.max(top, riskValue.get(m.risk));
    });
    var score = Math.min(1.0, top + 0.05 * Math.max(0, severe.length - 1));

    var findings = [];
    if (severe.length) {
      var worst = severe[0];
      severe.forEach(function (m) {
        if (SEVERITY_ORDER[m.risk] > SEVERITY_ORDER[worst.risk]) worst = m;
      });
      findings.push(
        finding(
          "dangerous_attachment",
          worst.risk,
          "Dangerous attachment",
          names(severe) + ": " + (worst.reasons.length ? worst.reasons[0] : "high-risk file type") + ".",
          {
            files: severe.slice(0, 8).map(function (m) {
              return { filename: m.filename, sha256: m.sha256, risk: m.risk, reasons: m.reasons };
            }),
          },
        ),
      );
    }
    var macros = scored.filter(function (m) {
      return m.has_macros;
    });
    if (macros.length) {
      findings.push(
        finding("macro_document", "high", "Macro-enabled document", names(macros) + " carry VBA macros, the most common malware delivery mechanism in email.", {
          files: macros.map(function (m) {
            return m.filename;
          }),
        }),
      );
    }
    var archiveExec = scored.filter(function (m) {
      return (
        m.is_archive &&
        m.reasons.some(function (r) {
          return r.indexOf("executable content") >= 0;
        })
      );
    });
    if (archiveExec.length) {
      findings.push(
        finding("archive_with_executable", "critical", "Archive contains executable", names(archiveExec) + " wrap executable files inside an archive to evade gateway filters.", {
          files: archiveExec.map(function (m) {
            return { filename: m.filename, reasons: m.reasons };
          }),
        }),
      );
    }
    var mismatched = scored.filter(function (m) {
      return m.mime_mismatch;
    });
    if (mismatched.length) {
      findings.push(
        finding(
          "mime_mismatch",
          "high",
          "File content does not match its name/type",
          names(mismatched) + ": the bytes inside are a different format from what the name or MIME type claims.",
          {
            files: mismatched.map(function (m) {
              return { filename: m.filename, content_type: m.content_type, magic_type: m.magic_type };
            }),
          },
        ),
      );
    }
    var entropic = scored.filter(function (m) {
      return entropyEscalates(m.extension, m.magic_type, m.high_entropy);
    });
    if (entropic.length) {
      var lead = entropic[0];
      entropic.forEach(function (m) {
        if (m.shannon_entropy > lead.shannon_entropy) lead = m;
      });
      var others = entropic.filter(function (m) {
        return m !== lead;
      });
      var detail =
        lead.filename +
        " measures " +
        py().fixed(lead.shannon_entropy, 2) +
        " out of 8.00 on the Shannon entropy scale, above the " +
        py().fixed(cfg.entropy_threshold, 2) +
        " threshold. Files of this type normally hold readable, repetitive content, so bytes this close to random mean the file has been packed, encrypted or has a payload hidden inside it.";
      if (others.length) detail += " " + names(others) + " show the same pattern.";
      findings.push(
        finding("high_entropy_payload", "high", "High-entropy attachment", detail, {
          files: entropic.slice(0, 8).map(function (m) {
            return { filename: m.filename, entropy: m.shannon_entropy, type: m.magic_type || m.content_type || m.extension };
          }),
        }),
      );
    }
    var doubles = scored.filter(function (m) {
      return m.double_extension;
    });
    if (doubles.length) {
      findings.push(
        finding("double_extension", "high", "Double file extension", names(doubles) + " use a document extension to hide the real executable extension.", {
          files: doubles.map(function (m) {
            return m.filename;
          }),
        }),
      );
    }
    var encrypted = scored.filter(function (m) {
      return m.reasons.some(function (r) {
        return r.indexOf("Password-protected") >= 0;
      });
    });
    if (encrypted.length) {
      findings.push(
        finding("password_protected_archive", "high", "Password-protected archive", names(encrypted) + " cannot be inspected; attackers use encryption to bypass scanners.", {
          files: encrypted.map(function (m) {
            return m.filename;
          }),
        }),
      );
    }
    if (scored.length > 5) {
      findings.push(finding("many_attachments", "low", "Unusually many attachments", "The message carries " + scored.length + " attachments.", { count: scored.length }));
    }
    if (metas.length) {
      findings.push(
        finding("attachment_inventory", "info", "Attachment inventory", metas.length + " attachment(s): " + names(metas) + ".", {
          files: metas.map(function (m, index) {
            return {
              filename: m.filename,
              size: m.size,
              sha256: m.sha256,
              type: m.magic_type || m.content_type,
              entropy: m.shannon_entropy,
              inline: inlineFlags[index],
            };
          }),
        }),
      );
    }
    return { attachments: metas, score: score, findings: findings };
  }

  MT.files = {
    analyzeAttachment: analyzeAttachment,
    analyzeAttachments: analyzeAttachments,
    sniffMagic: sniffMagic,
    shannonEntropy: shannonEntropy,
    inspectZip: inspectZip,
    zipEntries: zipEntries,
    crc32: crc32,
    SEVERITY_ORDER: SEVERITY_ORDER,
  };
})(MT);
