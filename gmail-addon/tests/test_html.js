"use strict";

const { load, fixture, Report } = require("./harness");

function record(MT, html) {
  const events = [];
  let error = "";
  try {
    MT.html.parse(html, {
      starttag(tag, attrs) {
        events.push(["s", tag, attrs.map((pair) => [pair[0], pair[1]])]);
      },
      endtag(tag) {
        events.push(["e", tag]);
      },
      data(text) {
        events.push(["d", text]);
      },
    });
  } catch (failure) {
    error = failure.name || "Error";
  }
  return { events, error };
}

function run() {
  const MT = load();
  const vectors = fixture("html_vectors.json");
  const reports = [];

  const events = new Report("HTML parser events like Python");
  for (const item of vectors) {
    const actual = record(MT, item.html);
    events.equal(actual.events, item.events, `events for ${JSON.stringify(item.html).slice(0, 200)}`);
    events.equal(Boolean(actual.error), Boolean(item.error), `error state for ${JSON.stringify(item.html).slice(0, 200)}`);
  }
  reports.push(events);

  if (MT.mime && MT.mime.htmlToText) {
    const text = new Report("html_to_text like Python");
    for (const item of vectors) {
      text.equal(MT.mime.htmlToText(item.html), item.text, `text of ${JSON.stringify(item.html).slice(0, 200)}`);
    }
    reports.push(text);
  }

  if (MT.urls && MT.urls.extractUrls) {
    const links = new Report("extract_urls like Python");
    for (const item of vectors) {
      links.equal(MT.urls.extractUrls("", item.html), item.links, `links of ${JSON.stringify(item.html).slice(0, 200)}`);
    }
    reports.push(links);
  }

  return reports.map((report) => report.finish()).every(Boolean);
}

if (require.main === module) process.exit(run() ? 0 : 1);

module.exports = { run };
