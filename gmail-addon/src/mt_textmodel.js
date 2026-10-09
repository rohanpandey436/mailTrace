var MT = MT || {};

(function (MT) {
  var model = null;

  function readDoubles(bytes, offset, length) {
    var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    var out = new Float64Array(length);
    for (var i = 0; i < length; i += 1) out[i] = view.getFloat64((offset + i) * 8, true);
    return out;
  }

  function load() {
    if (model) return model;
    var meta = MT.json("text_model_meta");
    var bytes = MT.blob("text_model_weights");
    var layout = meta.layout;
    var read = function (name) {
      return readDoubles(bytes, layout[name][0], layout[name][1]);
    };
    var wordVocabulary = new Map();
    meta.vocabulary_word.forEach(function (term, index) {
      wordVocabulary.set(term, index);
    });
    var charVocabulary = new Map();
    meta.vocabulary_char.forEach(function (term, index) {
      charVocabulary.set(term, index);
    });
    model = {
      version: meta.version,
      labels: meta.labels,
      classes: meta.classes,
      nWord: meta.n_word,
      nChar: meta.n_char,
      wordVocabulary: wordVocabulary,
      charVocabulary: charVocabulary,
      wordTerms: meta.vocabulary_word,
      idfWord: read("idf_word"),
      idfChar: read("idf_char"),
      coef: read("coef"),
      intercept: read("intercept"),
      expectedWord: read("expected_word"),
      tokenPattern: MT.py.re(meta.word.token_pattern),
      wordNgram: meta.word.ngram_range,
      charNgram: meta.char.ngram_range,
      whitespace: MT.py.re("\\s\\s+"),
    };
    return model;
  }

  function wordNgrams(tokens, range) {
    var minN = range[0];
    var maxN = range[1];
    var out = tokens.slice();
    var start = minN === 1 ? 2 : minN;
    if (minN !== 1) out = [];
    var total = tokens.length;
    for (var n = start; n <= Math.min(maxN, total); n += 1) {
      for (var i = 0; i + n <= total; i += 1) out.push(tokens.slice(i, i + n).join(" "));
    }
    return out;
  }

  function charWbNgrams(text, range, whitespace) {
    var normalized = whitespace.sub(" ", text);
    var minN = range[0];
    var maxN = range[1];
    var out = [];
    MT.py.split(normalized).forEach(function (word) {
      var w = MT.py.points(" " + word + " ");
      var length = w.length;
      for (var n = minN; n <= maxN; n += 1) {
        var offset = 0;
        out.push(w.slice(offset, offset + n).join(""));
        while (offset + n < length) {
          offset += 1;
          out.push(w.slice(offset, offset + n).join(""));
        }
        if (offset === 0) break;
      }
    });
    return out;
  }

  function vectorize(features, vocabulary, idf) {
    var counts = new Map();
    features.forEach(function (feature) {
      var index = vocabulary.get(feature);
      if (index === undefined) return;
      counts.set(index, (counts.get(index) || 0) + 1);
    });
    var indices = Array.from(counts.keys()).sort(function (a, b) {
      return a - b;
    });
    var values = indices.map(function (index) {
      return (Math.log(counts.get(index)) + 1.0) * idf[index];
    });
    var sum = 0.0;
    values.forEach(function (value) {
      sum += value * value;
    });
    var norm = Math.sqrt(sum);
    if (norm > 0) {
      values = values.map(function (value) {
        return value / norm;
      });
    }
    return { indices: indices, values: values };
  }

  function transform(text) {
    var m = load();
    var lowered = text.toLowerCase();
    var tokens = m.tokenPattern.findall(lowered);
    var word = vectorize(wordNgrams(tokens, m.wordNgram), m.wordVocabulary, m.idfWord);
    var chars = vectorize(charWbNgrams(lowered, m.charNgram, m.whitespace), m.charVocabulary, m.idfChar);
    return { word: word, chars: chars };
  }

  function decision(features) {
    var m = load();
    var width = m.nWord + m.nChar;
    var scores = [];
    for (var c = 0; c < m.classes.length; c += 1) {
      var base = c * width;
      var total = 0.0;
      var i;
      for (i = 0; i < features.word.indices.length; i += 1) total += features.word.values[i] * m.coef[base + features.word.indices[i]];
      for (i = 0; i < features.chars.indices.length; i += 1) total += features.chars.values[i] * m.coef[base + m.nWord + features.chars.indices[i]];
      scores.push(total + m.intercept[c]);
    }
    return scores;
  }

  function softmax(scores) {
    var max = Math.max.apply(null, scores);
    var shifted = scores.map(function (s) {
      return Math.exp(s - max);
    });
    var sum = 0.0;
    shifted.forEach(function (s) {
      sum += s;
    });
    return shifted.map(function (s) {
      return s / sum;
    });
  }

  function predict(text) {
    var m = load();
    var features = transform(text || "");
    var probabilities = softmax(decision(features));
    var probs = {};
    m.labels.forEach(function (label) {
      probs[label] = 0.0;
    });
    m.classes.forEach(function (cls, index) {
      probs[cls] = probabilities[index];
    });
    var best = null;
    m.labels.forEach(function (label) {
      if (best === null || probs[label] > probs[best]) best = label;
    });
    return { label: best, probabilities: probs, features: features };
  }

  function contributions(text, label, features) {
    var m = load();
    var index = m.classes.indexOf(label);
    if (index < 0) throw new Error("unknown class " + label);
    var word = features ? features.word : transform(text || "").word;
    var base = index * (m.nWord + m.nChar);
    var items = word.indices.map(function (column, position) {
      return [m.wordTerms[column], m.coef[base + column] * (word.values[position] - m.expectedWord[column])];
    });
    return MT.py.sorted(items, function (item) {
      return -Math.abs(item[1]);
    });
  }

  function shapValues(text, label, topK, features) {
    var items;
    try {
      items = contributions(text, label, features);
    } catch (error) {
      if (MT.trace) MT.trace(error);
      return [];
    }
    return topK <= 0 ? items : items.slice(0, topK);
  }

  function explain(text, label, topK, features) {
    var items;
    try {
      items = contributions(text, label, features);
    } catch (error) {
      if (MT.trace) MT.trace(error);
      return [];
    }
    return items
      .filter(function (item) {
        return item[1] > 0;
      })
      .map(function (item) {
        return item[0];
      })
      .slice(0, topK === undefined ? 8 : topK);
  }

  MT.textmodel = {
    load: load,
    transform: transform,
    predict: predict,
    shapValues: shapValues,
    explain: explain,
    wordNgrams: wordNgrams,
    charWbNgrams: charWbNgrams,
    version: function () {
      return load().version;
    },
  };
})(MT);
