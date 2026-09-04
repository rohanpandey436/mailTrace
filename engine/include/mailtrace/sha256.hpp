// SPDX-License-Identifier: MIT
//
// FIPS 180-4 SHA-256, implemented from the specification.
//
// The pitch deck's tech-stack slide lists OpenSSL for this.  A self-contained
// ~150 line implementation is used instead so that the extension builds on any
// C++20 toolchain with no external library, no headers to locate and no ABI to
// match.  SHA-256 is a fully specified, fixed algorithm; there is no security
// benefit to linking a large TLS library just to obtain it, and every build
// environment that lacks a correctly configured OpenSSL would otherwise lose
// the whole engine.  See engine/README.md for the same note in prose.
#ifndef MAILTRACE_SHA256_HPP
#define MAILTRACE_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace mailtrace {

/// Streaming SHA-256.  Copyable, no owning pointers, nothing to free.
class Sha256 {
  public:
    static constexpr std::size_t kDigestSize = 32;
    static constexpr std::size_t kBlockSize = 64;

    using Digest = std::array<std::uint8_t, kDigestSize>;

    Sha256() noexcept;

    /// Absorb `len` bytes.  `data` may be null only when `len` is zero.
    void update(const std::uint8_t* data, std::size_t len) noexcept;
    void update(std::string_view data) noexcept;

    /// Finish on a *copy* of the state, so the object stays usable.
    [[nodiscard]] Digest digest() const noexcept;

    /// Lower-case hex rendering of `digest()`.
    [[nodiscard]] std::string hex() const;

    static std::string to_hex(const Digest& digest);

  private:
    void compress(const std::uint8_t* block) noexcept;
    void finalize() noexcept;

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, kBlockSize> buffer_{};
    std::size_t buffered_{0};
    std::uint64_t length_bits_{0};
};

/// One-shot convenience wrapper: lower-case hex SHA-256 of a byte range.
[[nodiscard]] std::string sha256_hex(const std::uint8_t* data, std::size_t len);
[[nodiscard]] std::string sha256_hex(std::string_view data);

}  // namespace mailtrace

#endif  // MAILTRACE_SHA256_HPP
