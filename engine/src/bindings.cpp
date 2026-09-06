// SPDX-License-Identifier: MIT
//
// pybind11 surface of the MailTrace parse engine.
//
// Two entry points, with different jobs:
//
//   dissect(raw)        Structural only.  This is what
//                       backend/app/core/parser.py consumes: header
//                       name/value pairs and raw body byte ranges, with the
//                       tree shape CPython's email.feedparser would produce.
//                       It performs no decoding at all, so the Python side can
//                       finish the job with the standard library and get a
//                       provably identical result to the pure-Python path.
//
//   parse_message(raw)  The convenience view described on the pitch deck:
//                       bodies and attachment blobs already transfer-decoded,
//                       with filenames, content types, SHA-256 and entropy.
//                       Nothing in the MailTrace backend calls this; it exists
//                       for CLI use, benchmarks and other embedders.
//
// Byte strings are handed back as `bytes`, never `str`.  A message is a byte
// stream; deciding what encoding a header is in is Python's job here.
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "mailtrace/entropy.hpp"
#include "mailtrace/parser.hpp"
#include "mailtrace/sha256.hpp"

namespace py = pybind11;

namespace {

#ifndef MAILTRACE_ENGINE_VERSION
#define MAILTRACE_ENGINE_VERSION "1.0.0"
#endif
constexpr const char* kVersion = MAILTRACE_ENGINE_VERSION;

constexpr int kDissectSchema = 1;

[[nodiscard]] const char* kind_name(mailtrace::NodeKind kind) noexcept {
    switch (kind) {
        case mailtrace::NodeKind::Container:
            return "container";
        case mailtrace::NodeKind::EmbeddedMessage:
            return "rfc822";
        case mailtrace::NodeKind::Leaf:
            break;
    }
    return "leaf";
}

[[nodiscard]] py::dict node_to_dict(const mailtrace::Node& node) {
    py::list headers;
    for (const mailtrace::HeaderField& field : node.headers) {
        headers.append(py::make_tuple(py::bytes(field.name), py::bytes(field.value)));
    }

    py::list children;
    for (const mailtrace::Node& child : node.children) {
        children.append(node_to_dict(child));
    }

    py::dict out;
    out["kind"] = kind_name(node.kind);
    out["content_type"] = py::bytes(node.content_type);
    out["boundary"] = py::bytes(node.boundary);
    out["body"] = py::bytes(node.body);
    out["trim_last"] = node.trim_last;
    out["headers"] = std::move(headers);
    out["children"] = std::move(children);
    return out;
}

[[nodiscard]] py::dict dissect_binding(const std::string& raw) {
    mailtrace::Dissection dissection;
    {
        py::gil_scoped_release release;
        dissection = mailtrace::dissect(raw);
    }

    py::dict out;
    out["schema"] = kDissectSchema;
    out["ok"] = dissection.ok;
    out["reason"] = dissection.reason;
    out["root"] = dissection.ok ? node_to_dict(dissection.root) : py::dict();
    return out;
}

struct FlatPart {
    const mailtrace::Node* node = nullptr;
    bool embedded = false;
};

void flatten(const mailtrace::Node& node, std::vector<FlatPart>& out, std::size_t depth) {
    if (depth > 40) {
        return;
    }
    if (node.kind == mailtrace::NodeKind::EmbeddedMessage) {
        out.push_back(FlatPart{&node, true});
        return;
    }
    if (node.kind == mailtrace::NodeKind::Container) {
        for (const mailtrace::Node& child : node.children) {
            flatten(child, out, depth + 1);
        }
        return;
    }
    out.push_back(FlatPart{&node, false});
}

[[nodiscard]] std::string header_value(const mailtrace::Node& node, std::string_view name) {
    const mailtrace::HeaderField* field = mailtrace::find_header(node.headers, name);
    return field == nullptr ? std::string() : field->value;
}

[[nodiscard]] std::string part_filename(const mailtrace::Node& node) {
    std::string value;
    if (mailtrace::header_parameter(header_value(node, "content-disposition"), "filename", value)) {
        return value;
    }
    if (mailtrace::header_parameter(header_value(node, "content-type"), "name", value)) {
        return value;
    }
    return std::string();
}

[[nodiscard]] py::dict parse_message_binding(const std::string& raw, bool decode) {
    mailtrace::Dissection dissection;
    std::string digest;
    double entropy = 0.0;
    {
        py::gil_scoped_release release;
        dissection = mailtrace::dissect(raw);
        digest = mailtrace::sha256_hex(raw);
        entropy = mailtrace::shannon_entropy(raw);
    }

    py::dict out;
    out["ok"] = dissection.ok;
    out["reason"] = dissection.reason;
    out["size"] = raw.size();
    out["sha256"] = digest;
    out["entropy"] = entropy;
    out["content_type"] = py::bytes(dissection.ok ? dissection.root.content_type : std::string());

    py::list headers;
    py::list text_parts;
    py::list html_parts;
    py::list attachments;

    if (dissection.ok) {
        for (const mailtrace::HeaderField& field : dissection.root.headers) {
            headers.append(py::make_tuple(py::bytes(field.name), py::bytes(field.value)));
        }

        std::vector<FlatPart> parts;
        flatten(dissection.root, parts, 0);
        for (const FlatPart& part : parts) {
            const mailtrace::Node& node = *part.node;
            const std::string disposition = header_value(node, "content-disposition");
            const std::string filename = part_filename(node);
            const std::string transfer_encoding = header_value(node, "content-transfer-encoding");
            const std::string body = (decode && !part.embedded)
                                         ? mailtrace::decode_transfer_encoding(node.body, transfer_encoding)
                                         : node.body;

            const bool is_attachment =
                part.embedded || !filename.empty() ||
                mailtrace::find_header(node.headers, "content-disposition") != nullptr;
            if (!is_attachment && node.content_type == "text/plain") {
                text_parts.append(py::bytes(body));
                continue;
            }
            if (!is_attachment && node.content_type == "text/html") {
                html_parts.append(py::bytes(body));
                continue;
            }

            py::dict attachment;
            attachment["filename"] = py::bytes(filename);
            attachment["content_type"] = py::bytes(node.content_type);
            attachment["content_id"] = py::bytes(header_value(node, "content-id"));
            attachment["disposition"] = py::bytes(disposition);
            attachment["transfer_encoding"] = py::bytes(transfer_encoding);
            attachment["size"] = body.size();
            attachment["sha256"] = mailtrace::sha256_hex(body);
            attachment["entropy"] = mailtrace::shannon_entropy(body);
            attachment["data"] = py::bytes(body);
            attachments.append(std::move(attachment));
        }
    }

    out["headers"] = std::move(headers);
    out["text_parts"] = std::move(text_parts);
    out["html_parts"] = std::move(html_parts);
    out["attachments"] = std::move(attachments);
    return out;
}

}  // namespace

PYBIND11_MODULE(mailtrace_engine, m) {
    m.doc() =
        "MailTrace C++20 parse engine: RFC 5322 / RFC 2046 dissection, SHA-256 and Shannon entropy.\n"
        "Optional: backend/app/core/parser.py falls back to a pure-Python parser when this module "
        "is not importable, and both paths produce identical results.";

    m.attr("__version__") = kVersion;
    m.attr("DISSECT_SCHEMA") = kDissectSchema;
    // "openssl" or "builtin"; see mailtrace/sha256.hpp.
    m.attr("SHA256_BACKEND") = mailtrace::sha256_backend();

    m.def("dissect", &dissect_binding, py::arg("raw"),
          "Structural dissection of a raw message.  Returns\n"
          "{'schema': int, 'ok': bool, 'reason': str, 'root': node} where a node is\n"
          "{'kind': 'leaf'|'container'|'rfc822', 'content_type': bytes, 'boundary': bytes,\n"
          " 'body': bytes, 'trim_last': bool, 'headers': [(bytes, bytes)], 'children': [node]}.\n"
          "No decoding is performed.  ok=False means the caller must use its own parser.");

    m.def("parse_message", &parse_message_binding, py::arg("raw"), py::arg("decode") = true,
          "Convenience view: decoded bodies and attachment blobs with filenames,\n"
          "content types, SHA-256 and entropy.  Not used by the MailTrace backend.");

    m.def(
        "sha256", [](const std::string& data) { return mailtrace::sha256_hex(data); }, py::arg("data"),
        "Lower-case hex SHA-256 of a byte string (FIPS 180-4).  Computed by OpenSSL's "
        "EVP_Digest or by the bundled implementation; SHA256_BACKEND says which.");

    m.def(
        "shannon_entropy", [](const std::string& data) { return mailtrace::shannon_entropy(data); },
        py::arg("data"), "Shannon entropy of a byte string in bits/byte, 0.0 to 8.0.");

    m.def(
        "decode_base64", [](const std::string& data) { return py::bytes(mailtrace::decode_base64(data)); },
        py::arg("data"), "base64 decode, tolerant of junk and missing padding.");

    m.def(
        "decode_quoted_printable",
        [](const std::string& data) { return py::bytes(mailtrace::decode_quoted_printable(data)); },
        py::arg("data"), "quoted-printable decode, matching Python's quopri.decodestring.");
}
