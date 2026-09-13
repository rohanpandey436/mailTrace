#ifndef MAILTRACE_SHA256_HPP
#define MAILTRACE_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace mailtrace {

class Sha256 {
  public:
    static constexpr std::size_t kDigestSize = 32;
    static constexpr std::size_t kBlockSize = 64;

    using Digest = std::array<std::uint8_t, kDigestSize>;

    Sha256() noexcept;

    void update(const std::uint8_t* data, std::size_t len) noexcept;
    void update(std::string_view data) noexcept;

    [[nodiscard]] Digest digest() const noexcept;

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

[[nodiscard]] const char* sha256_backend() noexcept;

[[nodiscard]] std::string sha256_hex(const std::uint8_t* data, std::size_t len);
[[nodiscard]] std::string sha256_hex(std::string_view data);

}

#endif
