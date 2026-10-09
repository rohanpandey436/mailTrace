var MT = MT || {};

(function (MT) {
  function BinasciiError(message) {
    this.name = "BinasciiError";
    this.message = message;
  }
  BinasciiError.prototype = Object.create(Error.prototype);

  var BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var base64Table = null;

  function table() {
    if (!base64Table) {
      base64Table = new Uint8Array(256).fill(255);
      for (var i = 0; i < BASE64.length; i += 1) base64Table[BASE64.charCodeAt(i)] = i;
    }
    return base64Table;
  }

  function a2bBase64(data, strict) {
    var lookup = table();
    var length = data.length;
    var out = new Uint8Array(Math.floor((length + 3) / 4) * 3);
    var position = 0;
    var quad = 0;
    var left = 0;
    var pads = 0;

    for (var i = 0; i < length; i += 1) {
      var ch = data[i];
      if (ch === 61) {
        pads += 1;
        if (quad >= 2 && quad + pads <= 4) continue;
        if (!strict) continue;
        if (quad === 1) break;
        throw new BinasciiError(quad === 0 && i === 0 ? "Leading padding not allowed" : "Excess padding not allowed");
      }
      var value = lookup[ch];
      if (value >= 64) {
        if (strict) throw new BinasciiError("Only base64 data is allowed");
        continue;
      }
      if (pads && strict) {
        throw new BinasciiError(quad + pads === 4 ? "Excess data after padding" : "Discontinuous padding not allowed");
      }
      pads = 0;
      if (quad === 0) {
        quad = 1;
        left = value;
      } else if (quad === 1) {
        quad = 2;
        out[position] = ((left << 2) | (value >> 4)) & 255;
        position += 1;
        left = value & 0x0f;
      } else if (quad === 2) {
        quad = 3;
        out[position] = ((left << 4) | (value >> 2)) & 255;
        position += 1;
        left = value & 0x03;
      } else {
        quad = 0;
        out[position] = ((left << 6) | value) & 255;
        position += 1;
        left = 0;
      }
    }
    if (quad === 1) {
      throw new BinasciiError(
        "Invalid base64-encoded string: number of data characters (" +
          (Math.floor(position / 3) * 4 + 1) +
          ") cannot be 1 more than a multiple of 4",
      );
    }
    if (quad !== 0 && quad + pads < 4) throw new BinasciiError("Incorrect padding");
    return out.slice(0, position);
  }

  function isHex(code) {
    return (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102);
  }

  function hexValue(code) {
    if (code <= 57) return code - 48;
    if (code <= 70) return code - 55;
    return code - 87;
  }

  function a2bQp(data, header) {
    var length = data.length;
    var out = new Uint8Array(length);
    var input = 0;
    var position = 0;
    while (input < length) {
      var ch = data[input];
      if (ch === 61) {
        input += 1;
        if (input >= length) break;
        var next = data[input];
        if (next === 10 || next === 13) {
          if (next !== 10) {
            while (input < length && data[input] !== 10) input += 1;
          }
          if (input < length) input += 1;
        } else if (next === 61) {
          out[position] = 61;
          position += 1;
          input += 1;
        } else if (input + 1 < length && isHex(next) && isHex(data[input + 1])) {
          out[position] = (hexValue(next) << 4) | hexValue(data[input + 1]);
          position += 1;
          input += 2;
        } else {
          out[position] = 61;
          position += 1;
        }
      } else if (header && ch === 95) {
        out[position] = 32;
        position += 1;
        input += 1;
      } else {
        out[position] = ch;
        position += 1;
        input += 1;
      }
    }
    return out.slice(0, position);
  }

  function a2bUu(data) {
    var index = 0;
    var remaining = data.length;
    var binLength = ((remaining > 0 ? data[0] : 0) - 32) & 63;
    index += 1;
    remaining -= 1;
    var out = new Uint8Array(binLength);
    var position = 0;
    var leftBits = 0;
    var leftChar = 0;
    var ch;
    while (binLength > 0) {
      ch = remaining > 0 ? data[index] : 0;
      if (ch === 10 || ch === 13 || remaining <= 0) {
        ch = 0;
      } else {
        if (ch < 32 || ch > 96) throw new BinasciiError("Illegal char");
        ch = (ch - 32) & 63;
      }
      leftChar = (leftChar << 6) | ch;
      leftBits += 6;
      if (leftBits >= 8) {
        leftBits -= 8;
        out[position] = (leftChar >> leftBits) & 255;
        position += 1;
        leftChar &= (1 << leftBits) - 1;
        binLength -= 1;
      }
      remaining -= 1;
      index += 1;
    }
    while (remaining > 0) {
      ch = data[index];
      index += 1;
      remaining -= 1;
      if (ch !== 32 && ch !== 96 && ch !== 10 && ch !== 13) throw new BinasciiError("Trailing garbage");
    }
    return out;
  }

  function padded(data, padding) {
    var out = new Uint8Array(data.length + padding);
    out.set(data, 0);
    for (var i = 0; i < padding; i += 1) out[data.length + i] = 61;
    return out;
  }

  function decodeB(encoded) {
    var padError = encoded.length % 4;
    try {
      return a2bBase64(padError ? padded(encoded, 4 - padError) : encoded, true);
    } catch (first) {
      if (!(first instanceof BinasciiError)) throw first;
    }
    try {
      return a2bBase64(encoded, false);
    } catch (second) {
      if (!(second instanceof BinasciiError)) throw second;
    }
    try {
      return a2bBase64(padded(encoded, 2), false);
    } catch (third) {
      if (!(third instanceof BinasciiError)) throw third;
    }
    return encoded;
  }

  function splitLines(data) {
    var lines = [];
    var start = 0;
    var i = 0;
    var length = data.length;
    while (i < length) {
      var ch = data[i];
      if (ch === 10 || ch === 13) {
        lines.push(data.subarray(start, i));
        if (ch === 13 && i + 1 < length && data[i + 1] === 10) i += 1;
        i += 1;
        start = i;
      } else {
        i += 1;
      }
    }
    if (start < length) lines.push(data.subarray(start, length));
    return lines;
  }

  function startsWith(data, text) {
    if (data.length < text.length) return false;
    for (var i = 0; i < text.length; i += 1) if (data[i] !== text.charCodeAt(i)) return false;
    return true;
  }

  function stripBytes(data, codes) {
    var start = 0;
    var end = data.length;
    while (start < end && codes.indexOf(data[start]) >= 0) start += 1;
    while (end > start && codes.indexOf(data[end - 1]) >= 0) end -= 1;
    return data.subarray(start, end);
  }

  var OCTAL_SPACE = [32, 9, 10, 13, 11, 12];

  function isOctalInteger(data) {
    var text = MT.bytes.toLatin1(stripBytes(data, OCTAL_SPACE));
    return /^[+-]?(?:0[oO]_?)?[0-7]+(?:_[0-7]+)*$/.test(text);
  }

  function ValueError(message) {
    this.name = "ValueError";
    this.message = message;
  }
  ValueError.prototype = Object.create(Error.prototype);

  function decodeUu(encoded) {
    var lines = splitLines(encoded);
    var index = 0;
    var begun = false;
    while (index < lines.length) {
      var line = lines[index];
      index += 1;
      if (startsWith(line, "begin ")) {
        var rest = line.subarray(6);
        var space = rest.indexOf(32);
        var mode = space < 0 ? rest : rest.subarray(0, space);
        if (isOctalInteger(mode)) {
          begun = true;
          break;
        }
      }
    }
    if (!begun) throw new ValueError("`begin` line not found");
    var decoded = [];
    while (index < lines.length) {
      var current = lines[index];
      index += 1;
      if (!current.length) throw new ValueError("Truncated input");
      var bare = stripBytes(current, [32, 9, 13, 10, 12]);
      if (bare.length === 3 && bare[0] === 101 && bare[1] === 110 && bare[2] === 100) break;
      var piece;
      try {
        piece = a2bUu(current);
      } catch (error) {
        if (!(error instanceof BinasciiError)) throw error;
        var nbytes = Math.floor((((current[0] - 32) & 63) * 4 + 5) / 3);
        piece = a2bUu(current.subarray(0, nbytes));
      }
      decoded.push(piece);
    }
    return MT.bytes.concat(decoded);
  }

  var IV = [
    0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
    0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
  ];

  var SIGMA = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  ];

  var v = new Uint32Array(32);
  var m = new Uint32Array(32);

  function add(a, b) {
    var low = v[a] + v[b];
    var high = v[a + 1] + v[b + 1];
    if (low >= 0x100000000) high += 1;
    v[a] = low;
    v[a + 1] = high;
  }

  function addWord(a, low0, high0) {
    var low = v[a] + low0;
    var high = v[a + 1] + high0;
    if (low >= 0x100000000) high += 1;
    v[a] = low;
    v[a + 1] = high;
  }

  function mix(a, b, c, d, x, y) {
    add(a, b);
    addWord(a, m[x], m[x + 1]);
    var low = v[d] ^ v[a];
    var high = v[d + 1] ^ v[a + 1];
    v[d] = high;
    v[d + 1] = low;

    add(c, d);
    low = v[b] ^ v[c];
    high = v[b + 1] ^ v[c + 1];
    v[b] = (low >>> 24) ^ (high << 8);
    v[b + 1] = (high >>> 24) ^ (low << 8);

    add(a, b);
    addWord(a, m[y], m[y + 1]);
    low = v[d] ^ v[a];
    high = v[d + 1] ^ v[a + 1];
    v[d] = (low >>> 16) ^ (high << 16);
    v[d + 1] = (high >>> 16) ^ (low << 16);

    add(c, d);
    low = v[b] ^ v[c];
    high = v[b + 1] ^ v[c + 1];
    v[b] = (high >>> 31) ^ (low << 1);
    v[b + 1] = (low >>> 31) ^ (high << 1);
  }

  function compress(state, block, counter, last) {
    var i;
    for (i = 0; i < 16; i += 1) {
      v[i] = state[i];
      v[i + 16] = IV[i];
    }
    v[24] ^= counter >>> 0;
    v[25] ^= Math.floor(counter / 0x100000000) >>> 0;
    if (last) {
      v[28] = ~v[28];
      v[29] = ~v[29];
    }
    for (i = 0; i < 32; i += 1) {
      var at = i * 4;
      m[i] = (block[at] | (block[at + 1] << 8) | (block[at + 2] << 16) | (block[at + 3] << 24)) >>> 0;
    }
    for (var round = 0; round < 12; round += 1) {
      var s = round * 16;
      mix(0, 8, 16, 24, SIGMA[s] * 2, SIGMA[s + 1] * 2);
      mix(2, 10, 18, 26, SIGMA[s + 2] * 2, SIGMA[s + 3] * 2);
      mix(4, 12, 20, 28, SIGMA[s + 4] * 2, SIGMA[s + 5] * 2);
      mix(6, 14, 22, 30, SIGMA[s + 6] * 2, SIGMA[s + 7] * 2);
      mix(0, 10, 20, 30, SIGMA[s + 8] * 2, SIGMA[s + 9] * 2);
      mix(2, 12, 22, 24, SIGMA[s + 10] * 2, SIGMA[s + 11] * 2);
      mix(4, 14, 16, 26, SIGMA[s + 12] * 2, SIGMA[s + 13] * 2);
      mix(6, 8, 18, 28, SIGMA[s + 14] * 2, SIGMA[s + 15] * 2);
    }
    for (i = 0; i < 16; i += 1) state[i] ^= v[i] ^ v[i + 16];
  }

  function blake2b(data, digestSize) {
    var size = digestSize || 64;
    if (size < 1 || size > 64) throw new ValueError("digest_size must be between 1 and 64 bytes");
    var state = new Uint32Array(16);
    for (var i = 0; i < 16; i += 1) state[i] = IV[i];
    state[0] ^= 0x01010000 ^ size;
    var block = new Uint8Array(128);
    var length = data.length;
    var offset = 0;
    while (length - offset > 128) {
      block.set(data.subarray(offset, offset + 128));
      offset += 128;
      compress(state, block, offset, false);
    }
    block.fill(0);
    block.set(data.subarray(offset, length));
    compress(state, block, length, true);
    var out = new Uint8Array(size);
    for (var j = 0; j < size; j += 1) out[j] = (state[j >> 2] >>> (8 * (j & 3))) & 255;
    return out;
  }

  MT.binascii = {
    a2bBase64: a2bBase64,
    a2bQp: a2bQp,
    a2bUu: a2bUu,
    decodeB: decodeB,
    decodeUu: decodeUu,
    splitLines: splitLines,
    blake2b: blake2b,
    Error: BinasciiError,
    ValueError: ValueError,
  };
})(MT);
