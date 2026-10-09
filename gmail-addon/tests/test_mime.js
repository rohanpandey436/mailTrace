"use strict";

const { load, fixture, Report, differences } = require("./harness");

function run(filter) {
  const MT = load();
  const vectors = fixture("parsed_vectors.json");
  const traced = [];
  MT.trace = (error) => {
    if (error && /^(TypeError|ReferenceError|RangeError|SyntaxError)$/.test(error.name)) traced.push(error);
  };

  const headers = new Report("header values, addresses and dates like Python");
  for (const item of vectors.headers) {
    if (filter && filter !== "headers") break;
    const label = JSON.stringify(item.text).slice(0, 160);
    headers.equal(MT.mime.decodeHeaderValue(item.text), item.decoded, `decode ${label}`);
    if (!item.parseaddr.error) headers.equal(MT.address.parseaddr(item.text), item.parseaddr, `parseaddr ${label}`);
    if (!item.getaddresses.error) headers.equal(MT.address.getaddresses([item.text]), item.getaddresses, `getaddresses ${label}`);
    headers.equal(MT.mime.parseAddress(item.text), item.address, `parse_address ${label}`);
    headers.equal(MT.mime.parseAddressList(item.text), item.addresses, `parse_address_list ${label}`);
    headers.equal(MT.mime.parseDate(item.text), item.date, `date ${label}`);
  }

  const emails = new Report("parsed emails like Python");
  for (const item of vectors.emails) {
    if (filter && filter !== "emails" && !item.name.includes(filter)) continue;
    const raw = MT.bytes.fromBase64(item.raw);
    let result;
    try {
      result = MT.mime.parseEmail(raw);
    } catch (error) {
      emails.ok(false, `${item.name}: parseEmail threw ${error.name}: ${error.message}\n${error.stack}`);
      continue;
    }
    const found = differences(result.email, item.parsed, 0, "", [], 6);
    const attachments = result.attachments.map((att) => ({
      filename: att.filename,
      content_type: att.content_type,
      size: att.data.length,
      sha256: MT.platform.sha256(att.data),
      content_id: att.content_id,
      is_inline: att.is_inline,
    }));
    differences(attachments, item.raw_attachments, 0, "raw_attachments", found, 6);
    emails.ok(found.length === 0, `${item.name}:\n      ${found.join("\n      ")}`);
  }
  const results = [headers.finish(15), emails.finish(15)];
  if (traced.length) {
    console.log(`     ${traced.length} unexpected JavaScript error(s) were swallowed, first: ${traced[0].stack}`);
    return false;
  }
  return results.every(Boolean);
}

if (require.main === module) process.exit(run(process.argv[2]) ? 0 : 1);

module.exports = { run };
