"use strict";

const { load, fixture, Report } = require("./harness");

function codePointIndex(text, unitIndex) {
  let count = 0;
  for (let i = 0; i < unitIndex; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) i += 1;
    }
    count += 1;
  }
  return count;
}

function run() {
  const MT = load();
  const py = MT.py;
  const vectors = fixture("py_vectors.json");
  const reports = [];

  const numbers = new Report("numbers format like Python");
  for (const item of vectors.numbers) {
    item.fixed.forEach((expected, places) => numbers.equal(py.fixed(item.value, places), expected, `fixed(${item.value}, ${places})`));
    numbers.equal(py.signedFixed(item.value, 3), item.signed3, `signedFixed(${item.value})`);
    item.round.forEach((expected, places) => numbers.ok(Object.is(py.round(item.value, places), expected) || py.round(item.value, places) === expected, `round(${item.value}, ${places}) expected ${expected} got ${py.round(item.value, places)}`));
    numbers.equal(py.roundInt(item.value), item.round_int === 0 ? 0 : item.round_int, `roundInt(${item.value})`);
    numbers.equal(py.repr(item.value), item.repr, `repr(${item.value})`);
    numbers.equal(py.scientific(item.value, 3), item.sci3, `scientific(${item.value})`);
  }
  reports.push(numbers);

  const utf8 = new Report("utf-8 decoding like Python");
  for (const item of vectors.utf8) {
    const raw = MT.bytes.fromBase64(item.raw);
    let strict = null;
    try {
      strict = MT.bytes.utf8Decode(raw, false);
    } catch (error) {
      strict = null;
    }
    utf8.equal(strict, item.strict, `strict ${item.raw}`);
    const replaced = Array.from(MT.bytes.utf8Decode(raw, true)).map((ch) => ch.codePointAt(0));
    utf8.equal(replaced, item.replace, `replace ${item.raw}`);
    if (item.strict !== null) utf8.equal(MT.bytes.toBase64(MT.bytes.utf8Encode(item.strict)), item.raw, `encode ${item.raw}`);
  }
  reports.push(utf8);

  const strings = new Report("string helpers like Python");
  for (const item of vectors.strings) {
    const text = item.text;
    const label = JSON.stringify(text);
    strings.equal(py.strip(text), item.strip, `strip ${label}`);
    strings.equal(py.lstrip(text), item.lstrip, `lstrip ${label}`);
    strings.equal(py.rstrip(text), item.rstrip, `rstrip ${label}`);
    strings.equal(py.strip(text, " ,;"), item.strip_chars, `strip chars ${label}`);
    strings.equal(py.split(text), item.split, `split ${label}`);
    strings.equal(py.split(text, null, 1), item.split1, `split maxsplit ${label}`);
    strings.equal(py.split(text, ","), item.split_comma, `split comma ${label}`);
    strings.equal(py.split(text, ",", 1), item.split_comma1, `split comma 1 ${label}`);
    strings.equal(py.rsplit(text, ",", 1), item.rsplit_comma1, `rsplit comma 1 ${label}`);
    strings.equal(py.partition(text, "="), item.partition, `partition ${label}`);
    strings.equal(py.rpartition(text, ","), item.rpartition, `rpartition ${label}`);
    strings.equal(py.count(text, "a"), item.count_a, `count ${label}`);
    strings.equal(text.toLowerCase(), item.lower, `lower ${label}`);
    strings.equal(py.title(text), item.title, `title ${label}`);
    strings.equal(py.capitalize(text), item.capitalize, `capitalize ${label}`);
    strings.equal(py.length(text), item.length, `length ${label}`);
    strings.equal(py.isAlnum(text), item.isalnum, `isalnum ${label}`);
    strings.equal(py.isAlpha(text), item.isalpha, `isalpha ${label}`);
    strings.equal(py.slice(text, 0, 5), item.slice, `slice ${label}`);
    strings.equal(py.joinWords(text), item.join_words, `join words ${label}`);
  }
  reports.push(strings);

  if (MT.html && MT.html.unescape) {
    const entities = new Report("html.unescape like Python");
    for (const item of vectors.entities) {
      entities.equal(MT.html.unescape(item.text), item.unescape, `unescape ${JSON.stringify(item.text)}`);
    }
    reports.push(entities);
  }

  const regex = new Report("exported patterns match like Python");
  for (const group of vectors.regex) {
    for (const entry of group.patterns) {
      let pattern;
      try {
        pattern = MT.RX(entry.module, entry.name);
      } catch (error) {
        regex.ok(false, `${entry.module}.${entry.name} does not compile: ${error.message}`);
        continue;
      }
      const expected = new Map(entry.results.map((result) => [result.text, result.matches]));
      group.texts.forEach((text, index) => {
        const found = pattern.finditer(text).slice(0, 40).map((match) => [
          codePointIndex(text, match.start),
          codePointIndex(text, match.end),
          match[0],
        ]);
        regex.equal(found, expected.get(index) || [], `${entry.module}.${entry.name} on text ${index}`);
      });
    }
  }
  reports.push(regex);

  return reports.map((report) => report.finish()).every(Boolean);
}

if (require.main === module) process.exit(run() ? 0 : 1);

module.exports = { run };
