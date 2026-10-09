var MT = MT || {};

(function (MT) {
  if (typeof Utilities === "undefined") return;

  var HEX = "0123456789abcdef";

  function toUnsigned(list) {
    var out = new Uint8Array(list.length);
    for (var i = 0; i < list.length; i += 1) out[i] = list[i] & 0xff;
    return out;
  }

  function toSigned(bytes) {
    var out = new Array(bytes.length);
    for (var i = 0; i < bytes.length; i += 1) out[i] = bytes[i] > 127 ? bytes[i] - 256 : bytes[i];
    return out;
  }

  function hex(list) {
    var out = "";
    for (var i = 0; i < list.length; i += 1) {
      var value = list[i] & 0xff;
      out += HEX.charAt(value >> 4) + HEX.charAt(value & 15);
    }
    return out;
  }

  function digest(algorithm, bytes) {
    return hex(Utilities.computeDigest(algorithm, toSigned(bytes)));
  }

  function decodeWith(bytes, labels, lossy) {
    for (var i = 0; i < labels.length; i += 1) {
      var text;
      try {
        text = Utilities.newBlob(toSigned(bytes)).getDataAsString(labels[i]);
      } catch (error) {
        continue;
      }
      if (lossy || text.indexOf("�") < 0) return text;
      return null;
    }
    return null;
  }

  MT.platform = {
    name: "apps-script",
    gunzip: function (bytes) {
      return toUnsigned(Utilities.ungzip(Utilities.newBlob(toSigned(bytes), "application/x-gzip")).getBytes());
    },
    sha256: function (bytes) {
      return digest(Utilities.DigestAlgorithm.SHA_256, bytes);
    },
    md5: function (bytes) {
      return digest(Utilities.DigestAlgorithm.MD5, bytes);
    },
    decode: function (bytes, labels) {
      return decodeWith(bytes, labels, false);
    },
    decodeLossy: function (bytes, labels) {
      return decodeWith(bytes, labels, true);
    },
    toUnsigned: toUnsigned,
    toSigned: toSigned,
    hex: hex,
  };
})(MT);
