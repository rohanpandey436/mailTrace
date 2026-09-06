// SPDX-License-Identifier: MIT
//
// RFC 5322 / RFC 2046 structural dissection.
//
// Scope, stated plainly
// --------------------
// This dissector answers exactly one question: *where are the bytes?*  It
// splits a raw message into header name/value pairs and body-part byte ranges,
// walking multipart boundaries and stopping at embedded message/rfc822 parts.
// It deliberately does NOT interpret those bytes: no RFC 2047 word decoding,
// no RFC 2231 parameter collapsing, no charset handling, no address parsing.
// Those live in Python (backend/app/core/parser.py), where the standard
// library already does them correctly and where the cost is negligible.
//
// Byte-for-byte compatibility with CPython's email.feedparser is a hard
// requirement, because the Python side swaps this dissection in underneath an
// otherwise unchanged pipeline.  The line-splitting rule, the header/body
// separator rule, the boundary-matching grammar and the "the newline before a
// boundary belongs to the boundary" rule below are all transcribed from
// CPython's Lib/email/feedparser.py so the two agree.  Anything this parser is
// not confident it reproduces exactly sets `Dissection::ok = false`, and the
// caller then runs the pure-Python parser instead.  Declining is always safe;
// being wrong is not.
#ifndef MAILTRACE_MIME_HPP
#define MAILTRACE_MIME_HPP

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace mailtrace {

enum class NodeKind {
    Leaf,             ///< Ordinary body part; `body` holds its raw, still-encoded bytes.
    Container,        ///< multipart/* with a usable boundary; see `children`.
    EmbeddedMessage,  ///< message/rfc822; `body` holds the raw nested message.
};

struct HeaderField {
    std::string name;   ///< Everything before the first ':' on the line, unmodified.
    std::string value;  ///< Unfolded per CPython's compat32 header_source_parse.
};

struct Node {
    NodeKind kind = NodeKind::Leaf;
    std::string content_type;  ///< Lower-cased, parameters stripped. Informational.
    std::string boundary;      ///< Container only; the unquoted boundary in use.
    std::string body;          ///< Raw bytes; empty for containers.
    std::vector<HeaderField> headers;
    std::vector<Node> children;  ///< Container only.

    bool trim_last = false;
};

struct Dissection {
    bool ok = false;      ///< False => the caller must fall back to its own parser.
    std::string reason;   ///< Why `ok` is false; empty when ok.
    Node root;
};

[[nodiscard]] Dissection dissect(std::string_view raw);

[[nodiscard]] std::string decode_base64(std::string_view data);

[[nodiscard]] std::string decode_quoted_printable(std::string_view data);

[[nodiscard]] std::string decode_transfer_encoding(std::string_view data, std::string_view encoding);

/// First header with `name` (ASCII case-insensitive), or nullptr.
[[nodiscard]] const HeaderField* find_header(const std::vector<HeaderField>& headers,
                                             std::string_view name) noexcept;

[[nodiscard]] bool header_parameter(std::string_view header_value, std::string_view name,
                                    std::string& out);

}  // namespace mailtrace

#endif  // MAILTRACE_MIME_HPP
