// SPDX-License-Identifier: MIT
//
// See include/mailtrace/parser.hpp for the scope and the compatibility contract.
//
// Every function here works on std::string_view slices of the caller's buffer
// and indexes only after a bounds test, so a truncated or hostile message can
// terminate the walk early but cannot read out of range.  There is no `new`,
// no `delete` and no owning raw pointer anywhere in this file.
#include "mailtrace/parser.hpp"

#include <algorithm>
#include <cstdint>
#include <utility>

namespace mailtrace {
namespace {

constexpr std::size_t kMaxDepth = 30;

constexpr std::size_t kMaxNodes = 2000;

constexpr std::string_view kAsciiSpace = " \t\n\r\f\v";

[[nodiscard]] constexpr char lower_ascii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

[[nodiscard]] std::string to_lower_ascii(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(lower_ascii(c));
    }
    return out;
}

[[nodiscard]] bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (lower_ascii(a[i]) != lower_ascii(b[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string_view rstrip(std::string_view s, std::string_view chars) noexcept {
    std::size_t end = s.size();
    while (end > 0 && chars.find(s[end - 1]) != std::string_view::npos) {
        --end;
    }
    return s.substr(0, end);
}

[[nodiscard]] std::string_view lstrip(std::string_view s, std::string_view chars) noexcept {
    std::size_t begin = 0;
    while (begin < s.size() && chars.find(s[begin]) != std::string_view::npos) {
        ++begin;
    }
    return s.substr(begin);
}

[[nodiscard]] std::string_view strip(std::string_view s, std::string_view chars) noexcept {
    return lstrip(rstrip(s, chars), chars);
}

[[nodiscard]] bool starts_with(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

[[nodiscard]] std::size_t line_end(std::string_view s, std::size_t pos) noexcept {
    while (pos < s.size()) {
        const char c = s[pos];
        if (c == '\n') {
            return pos + 1;
        }
        if (c == '\r') {
            return (pos + 1 < s.size() && s[pos + 1] == '\n') ? pos + 2 : pos + 1;
        }
        ++pos;
    }
    return s.size();
}

[[nodiscard]] std::size_t trailing_eol_length(std::string_view line) noexcept {
    if (line.size() >= 2 && line[line.size() - 2] == '\r' && line[line.size() - 1] == '\n') {
        return 2;
    }
    if (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
        return 1;
    }
    return 0;
}

[[nodiscard]] bool is_header_block_line(std::string_view line) noexcept {
    if (line.empty()) {
        return false;
    }
    if (line[0] == ' ' || line[0] == '\t') {
        return true;
    }
    if (starts_with(line, "From ")) {
        return true;
    }
    std::size_t i = 0;
    while (i < line.size()) {
        const auto c = static_cast<unsigned char>(line[i]);
        if ((c >= 0x21u && c <= 0x39u) || (c >= 0x3bu && c <= 0x7eu)) {
            ++i;
            continue;
        }
        break;
    }
    return i < line.size() && line[i] == ':';
}

/// feedparser's NLCRE.match(line): the line *is* just a terminator.
[[nodiscard]] bool is_blank_line(std::string_view line) noexcept {
    return !line.empty() && (line[0] == '\r' || line[0] == '\n');
}

struct BoundaryMatch {
    bool matched = false;
    bool is_end = false;
};

[[nodiscard]] BoundaryMatch match_boundary(std::string_view line, std::string_view separator) noexcept {
    BoundaryMatch result;
    if (separator.empty() || !starts_with(line, separator)) {
        return result;
    }
    std::size_t i = separator.size();
    bool is_end = false;
    if (i + 1 < line.size() && line[i] == '-' && line[i + 1] == '-') {
        is_end = true;
        i += 2;
    }
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) {
        ++i;
    }
    if (i < line.size()) {
        if (line[i] == '\r') {
            i += (i + 1 < line.size() && line[i + 1] == '\n') ? 2 : 1;
        } else if (line[i] == '\n') {
            i += 1;
        }
    }
    if (i == line.size() || (line.size() - i == 1 && line[i] == '\n')) {
        result.matched = true;
        result.is_end = is_end;
    }
    return result;
}

[[nodiscard]] std::size_t find_region_end(std::string_view body, std::size_t pos,
                                          const std::vector<std::string>& separators) noexcept {
    while (pos < body.size()) {
        const std::size_t end = line_end(body, pos);
        const std::string_view line = body.substr(pos, end - pos);
        for (const std::string& separator : separators) {
            if (match_boundary(line, separator).matched) {
                return pos;
            }
        }
        pos = end;
    }
    return body.size();
}

void replace_all(std::string& text, std::string_view needle, std::string_view replacement) {
    if (needle.empty()) {
        return;
    }
    std::size_t pos = text.find(needle);
    while (pos != std::string::npos) {
        text.replace(pos, needle.size(), replacement);
        pos = text.find(needle, pos + replacement.size());
    }
}

/// email.utils.unquote
[[nodiscard]] std::string unquote(std::string_view value) {
    if (value.size() > 1 && value.front() == '"' && value.back() == '"') {
        std::string inner(value.substr(1, value.size() - 2));
        replace_all(inner, "\\\\", "\\");
        replace_all(inner, "\\\"", "\"");
        return inner;
    }
    if (value.size() > 1 && value.front() == '<' && value.back() == '>') {
        return std::string(value.substr(1, value.size() - 2));
    }
    return std::string(value);
}

[[nodiscard]] std::vector<std::string_view> split_parameters(std::string_view value) {
    std::vector<std::string_view> segments;
    std::size_t start = 0;
    bool in_quotes = false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const char c = value[i];
        if (in_quotes && c == '\\') {
            ++i;  // skip the escaped character; the bounds test above re-runs
            continue;
        }
        if (c == '"') {
            in_quotes = !in_quotes;
            continue;
        }
        if (c == ';' && !in_quotes) {
            segments.push_back(value.substr(start, i - start));
            start = i + 1;
        }
    }
    segments.push_back(value.substr(start));
    return segments;
}

}  // namespace

const HeaderField* find_header(const std::vector<HeaderField>& headers, std::string_view name) noexcept {
    for (const HeaderField& field : headers) {
        if (iequals(field.name, name)) {
            return &field;  // Message.get() returns the first match.
        }
    }
    return nullptr;
}

bool header_parameter(std::string_view header_value, std::string_view name, std::string& out) {
    const std::vector<std::string_view> segments = split_parameters(header_value);
    for (std::size_t i = 1; i < segments.size(); ++i) {
        const std::string_view segment = segments[i];
        const std::size_t equals = segment.find('=');
        if (equals == std::string_view::npos) {
            if (iequals(strip(segment, kAsciiSpace), name)) {
                out.clear();
                return true;
            }
            continue;
        }
        if (!iequals(strip(segment.substr(0, equals), kAsciiSpace), name)) {
            continue;
        }
        out = unquote(strip(segment.substr(equals + 1), kAsciiSpace));
        return true;
    }
    return false;
}

namespace {

[[nodiscard]] bool boundary_parameter(std::string_view content_type, std::string& out) {
    std::string value;
    if (!header_parameter(content_type, "boundary", value)) {
        return false;
    }
    value = unquote(value);
    out = std::string(rstrip(value, kAsciiSpace));
    return true;
}

[[nodiscard]] std::string content_type_of(const std::vector<HeaderField>& headers,
                                          std::string_view default_type) {
    const HeaderField* field = find_header(headers, "content-type");
    if (field == nullptr) {
        return std::string(default_type);
    }
    std::string_view value(field->value);
    const std::size_t semicolon = value.find(';');
    if (semicolon != std::string_view::npos) {
        value = value.substr(0, semicolon);
    }
    std::string ctype = to_lower_ascii(strip(value, kAsciiSpace));
    if (std::count(ctype.begin(), ctype.end(), '/') != 1) {
        return "text/plain";
    }
    return ctype;
}

[[nodiscard]] std::string_view main_type_of(std::string_view content_type) noexcept {
    const std::size_t slash = content_type.find('/');
    return (slash == std::string_view::npos) ? content_type : content_type.substr(0, slash);
}

struct Context {
    bool declined = false;
    std::string reason;
    std::size_t nodes = 0;

    void decline(std::string why) {
        if (!declined) {
            declined = true;
            reason = std::move(why);
        }
    }
};

Node parse_node(std::string_view region, std::string_view default_type,
                const std::vector<std::string>& ancestors, std::size_t depth, Context& ctx);

[[nodiscard]] std::size_t parse_header_block(std::string_view region, std::vector<HeaderField>& out,
                                             Context& ctx) {
    std::vector<std::string_view> lines;
    std::size_t pos = 0;
    while (pos < region.size()) {
        const std::size_t end = line_end(region, pos);
        const std::string_view line = region.substr(pos, end - pos);
        if (!is_header_block_line(line)) {
            if (is_blank_line(line)) {
                pos = end;
            }
            break;
        }
        if (starts_with(line, "From ")) {
            ctx.decline("unix-from line inside a header block");
            return region.size();
        }
        lines.push_back(line);
        pos = end;
    }
    const std::size_t body_start = pos;

    std::size_t i = 0;
    while (i < lines.size()) {
        const std::string_view first = lines[i];
        if (first[0] == ' ' || first[0] == '\t') {
            ctx.decline("header block opens with a continuation line");
            return region.size();
        }
        const std::size_t colon = first.find(':');
        if (colon == std::string_view::npos) {
            ctx.decline("header line without a colon");
            return region.size();
        }
        if (colon == 0) {
            ctx.decline("header line with an empty name");
            return region.size();
        }
        HeaderField field;
        field.name.assign(first.substr(0, colon));
        std::string joined(first.substr(colon + 1));
        std::size_t j = i + 1;
        while (j < lines.size() && (lines[j][0] == ' ' || lines[j][0] == '\t')) {
            joined.append(lines[j]);
            ++j;
        }
        field.value.assign(rstrip(lstrip(std::string_view(joined), " \t\r\n"), "\r\n"));
        out.push_back(std::move(field));
        i = j;
    }
    return body_start;
}

[[nodiscard]] bool split_multipart(Node& node, std::string_view boundary,
                                   const std::vector<std::string>& ancestors, std::size_t depth,
                                   Context& ctx) {
    const std::string separator = "--" + std::string(boundary);
    std::vector<std::string> active(ancestors);
    active.push_back(separator);

    const std::string_view body(node.body);
    const std::string child_default_type =
        (node.content_type == "multipart/digest") ? "message/rfc822" : "text/plain";

    std::size_t pos = 0;
    bool saw_start_boundary = false;

    while (pos < body.size()) {
        const std::size_t end = line_end(body, pos);
        const BoundaryMatch match = match_boundary(body.substr(pos, end - pos), separator);
        if (!match.matched) {
            if (saw_start_boundary) {
                ctx.decline("boundary scan desynchronised");
                return false;
            }
            pos = end;  // preamble line
            continue;
        }
        if (match.is_end) {
            break;  // closing boundary; the epilogue is not needed
        }
        saw_start_boundary = true;
        pos = end;

        while (pos < body.size()) {
            const std::size_t next = line_end(body, pos);
            if (!match_boundary(body.substr(pos, next - pos), separator).matched) {
                break;
            }
            pos = next;
        }

        const std::size_t child_end = find_region_end(body, pos, active);
        Node child = parse_node(body.substr(pos, child_end - pos), child_default_type, active, depth + 1, ctx);
        if (ctx.declined) {
            return false;
        }

        if (child.kind == NodeKind::Leaf && main_type_of(child.content_type) != "multipart") {
            const std::size_t eol = trailing_eol_length(child.body);
            if (eol != 0) {
                child.body.resize(child.body.size() - eol);
            }
        } else if (child.kind == NodeKind::EmbeddedMessage) {
            child.trim_last = true;
        }

        node.children.push_back(std::move(child));
        pos = child_end;
    }

    if (!saw_start_boundary) {
        ctx.decline("multipart start boundary never appears");
        return false;
    }
    return true;
}

Node parse_node(std::string_view region, std::string_view default_type,
                const std::vector<std::string>& ancestors, std::size_t depth, Context& ctx) {
    Node node;
    if (ctx.declined) {
        return node;
    }
    if (depth > kMaxDepth) {
        ctx.decline("message nested deeper than the native depth limit");
        return node;
    }
    if (++ctx.nodes > kMaxNodes) {
        ctx.decline("more MIME parts than the native node limit");
        return node;
    }

    const std::size_t body_start = parse_header_block(region, node.headers, ctx);
    if (ctx.declined) {
        return node;
    }
    node.body.assign(region.substr(body_start));
    node.content_type = content_type_of(node.headers, default_type);

    if (node.content_type == "message/rfc822") {
        node.kind = NodeKind::EmbeddedMessage;
        return node;
    }
    if (main_type_of(node.content_type) == "message") {
        ctx.decline("message/* part other than message/rfc822");
        return node;
    }
    if (main_type_of(node.content_type) != "multipart") {
        node.kind = NodeKind::Leaf;
        return node;
    }

    const HeaderField* content_type_header = find_header(node.headers, "content-type");
    std::string boundary;
    if (content_type_header == nullptr || !boundary_parameter(content_type_header->value, boundary)) {
        node.kind = NodeKind::Leaf;
        return node;
    }
    if (boundary.empty()) {
        ctx.decline("multipart boundary parameter is empty");
        return node;
    }

    if (!split_multipart(node, boundary, ancestors, depth, ctx)) {
        return node;  // ctx has been declined; the caller discards this tree
    }

    node.kind = NodeKind::Container;
    node.boundary = std::move(boundary);
    node.body.clear();
    node.body.shrink_to_fit();
    return node;
}

}  // namespace

Dissection dissect(std::string_view raw) {
    Dissection result;
    Context ctx;
    const std::vector<std::string> no_ancestors;
    result.root = parse_node(raw, "text/plain", no_ancestors, 0, ctx);
    if (ctx.declined) {
        result.ok = false;
        result.reason = ctx.reason;
        result.root = Node{};
        return result;
    }
    result.ok = true;
    return result;
}

namespace {

[[nodiscard]] constexpr int base64_value(unsigned char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

[[nodiscard]] constexpr int hex_value(unsigned char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

}  // namespace

std::string decode_base64(std::string_view data) {
    std::size_t symbols = 0;
    for (const char raw_char : data) {
        if (base64_value(static_cast<unsigned char>(raw_char)) >= 0) {
            ++symbols;
        }
    }
    if (symbols % 4 == 1) {
        std::string verbatim;
        verbatim.reserve(data.size());
        for (const char raw_char : data) {
            if (raw_char != '\r' && raw_char != '\n') {
                verbatim.push_back(raw_char);
            }
        }
        return verbatim;
    }

    std::string out;
    out.reserve(symbols / 4 * 3 + 3);

    std::uint32_t accumulator = 0;
    int collected = 0;
    for (const char raw_char : data) {
        const int value = base64_value(static_cast<unsigned char>(raw_char));
        if (value < 0) {
            continue;  // padding, newlines and junk are all simply ignored
        }
        accumulator = (accumulator << 6) | static_cast<std::uint32_t>(value);
        if (++collected == 4) {
            out.push_back(static_cast<char>((accumulator >> 16) & 0xffu));
            out.push_back(static_cast<char>((accumulator >> 8) & 0xffu));
            out.push_back(static_cast<char>(accumulator & 0xffu));
            accumulator = 0;
            collected = 0;
        }
    }
    if (collected == 2) {
        out.push_back(static_cast<char>((accumulator >> 4) & 0xffu));
    } else if (collected == 3) {
        out.push_back(static_cast<char>((accumulator >> 10) & 0xffu));
        out.push_back(static_cast<char>((accumulator >> 2) & 0xffu));
    }
    return out;
}

std::string decode_quoted_printable(std::string_view data) {
    std::string out;
    out.reserve(data.size());

    std::size_t i = 0;
    while (i < data.size()) {
        if (data[i] != '=') {
            out.push_back(data[i]);
            ++i;
            continue;
        }
        ++i;
        if (i >= data.size()) {
            break;  // a trailing '=' is dropped
        }
        if (data[i] == '\n' || data[i] == '\r') {
            if (data[i] != '\n') {
                while (i < data.size() && data[i] != '\n') {
                    ++i;
                }
            }
            if (i < data.size()) {
                ++i;
            }
            continue;
        }
        if (data[i] == '=') {
            out.push_back('=');  // "==" from a broken encoder
            ++i;
            continue;
        }
        if (i + 1 < data.size()) {
            const int hi = hex_value(static_cast<unsigned char>(data[i]));
            const int lo = hex_value(static_cast<unsigned char>(data[i + 1]));
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        // Not an escape at all: emit the '=' and re-examine the byte after it.
        out.push_back('=');
    }
    return out;
}

std::string decode_transfer_encoding(std::string_view data, std::string_view encoding) {
    const std::string normalised = to_lower_ascii(std::string(strip(encoding, kAsciiSpace)));
    if (normalised == "base64") {
        return decode_base64(data);
    }
    if (normalised == "quoted-printable") {
        return decode_quoted_printable(data);
    }
    return std::string(data);
}

}  // namespace mailtrace
