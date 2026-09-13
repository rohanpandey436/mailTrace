#ifndef MAILTRACE_MIME_HPP
#define MAILTRACE_MIME_HPP

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace mailtrace {

enum class NodeKind {
    Leaf,
    Container,
    EmbeddedMessage,
};

struct HeaderField {
    std::string name;
    std::string value;
};

struct Node {
    NodeKind kind = NodeKind::Leaf;
    std::string content_type;
    std::string boundary;
    std::string body;
    std::vector<HeaderField> headers;
    std::vector<Node> children;

    bool trim_last = false;
};

struct Dissection {
    bool ok = false;
    std::string reason;
    Node root;
};

[[nodiscard]] Dissection dissect(std::string_view raw);

[[nodiscard]] std::string decode_base64(std::string_view data);

[[nodiscard]] std::string decode_quoted_printable(std::string_view data);

[[nodiscard]] std::string decode_transfer_encoding(std::string_view data, std::string_view encoding);

[[nodiscard]] const HeaderField* find_header(const std::vector<HeaderField>& headers,
                                             std::string_view name) noexcept;

[[nodiscard]] bool header_parameter(std::string_view header_value, std::string_view name,
                                    std::string& out);

}

#endif
