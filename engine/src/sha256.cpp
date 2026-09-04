// SPDX-License-Identifier: MIT
//
// FIPS 180-4 SHA-256.  Straight transcription of the specification; the only
// deviations from the pseudo-code are the use of fixed-size std::array storage
// (no allocation, no raw pointers to own) and a copy-on-finalize digest() so a
// Sha256 can be queried without being consumed.
#include "mailtrace/sha256.hpp"

#include <cstring>

namespace mailtrace {
namespace {

// FIPS 180-4 section 4.2.2: first 32 bits of the fractional parts of the cube
// roots of the first 64 primes.
constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t value, unsigned bits) noexcept {
    // `bits` is always 1..31 at every call site below, so the UB-prone
    // shift-by-32 case cannot arise.
    return (value >> bits) | (value << (32u - bits));
}

[[nodiscard]] constexpr std::uint32_t big_endian_word(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

constexpr char kHexDigits[] = "0123456789abcdef";

}  // namespace

Sha256::Sha256() noexcept {
    // FIPS 180-4 section 5.3.3: fractional parts of the square roots of the
    // first eight primes.
    state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
              0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
}

void Sha256::compress(const std::uint8_t* block) noexcept {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = big_endian_word(block + i * 4);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t choose = (e & f) ^ (~e & g);
        const std::uint32_t temp1 = h + s1 + choose + kRoundConstants[i] + w[i];
        const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const std::uint8_t* data, std::size_t len) noexcept {
    if (data == nullptr || len == 0) {
        return;
    }
    length_bits_ += static_cast<std::uint64_t>(len) * 8u;

    if (buffered_ != 0) {
        const std::size_t want = kBlockSize - buffered_;
        const std::size_t take = (len < want) ? len : want;
        std::memcpy(buffer_.data() + buffered_, data, take);
        buffered_ += take;
        data += take;
        len -= take;
        if (buffered_ < kBlockSize) {
            return;
        }
        compress(buffer_.data());
        buffered_ = 0;
    }

    while (len >= kBlockSize) {
        compress(data);
        data += kBlockSize;
        len -= kBlockSize;
    }

    if (len != 0) {
        std::memcpy(buffer_.data(), data, len);
        buffered_ = len;
    }
}

void Sha256::update(std::string_view data) noexcept {
    update(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

void Sha256::finalize() noexcept {
    const std::uint64_t bits = length_bits_;

    // Append 0x80, then zeroes, then the 64-bit big-endian bit length.
    buffer_[buffered_++] = static_cast<std::uint8_t>(0x80u);
    if (buffered_ > kBlockSize - 8) {
        while (buffered_ < kBlockSize) {
            buffer_[buffered_++] = static_cast<std::uint8_t>(0x00u);
        }
        compress(buffer_.data());
        buffered_ = 0;
    }
    while (buffered_ < kBlockSize - 8) {
        buffer_[buffered_++] = static_cast<std::uint8_t>(0x00u);
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
        buffer_[buffered_++] = static_cast<std::uint8_t>((bits >> shift) & 0xffu);
    }
    compress(buffer_.data());
    buffered_ = 0;
}

Sha256::Digest Sha256::digest() const noexcept {
    Sha256 copy(*this);
    copy.finalize();

    Digest out{};
    for (std::size_t i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<std::uint8_t>((copy.state_[i] >> 24) & 0xffu);
        out[i * 4 + 1] = static_cast<std::uint8_t>((copy.state_[i] >> 16) & 0xffu);
        out[i * 4 + 2] = static_cast<std::uint8_t>((copy.state_[i] >> 8) & 0xffu);
        out[i * 4 + 3] = static_cast<std::uint8_t>(copy.state_[i] & 0xffu);
    }
    return out;
}

std::string Sha256::to_hex(const Digest& digest) {
    std::string out;
    out.resize(digest.size() * 2);
    for (std::size_t i = 0; i < digest.size(); ++i) {
        out[i * 2 + 0] = kHexDigits[(digest[i] >> 4) & 0x0fu];
        out[i * 2 + 1] = kHexDigits[digest[i] & 0x0fu];
    }
    return out;
}

std::string Sha256::hex() const { return to_hex(digest()); }

std::string sha256_hex(const std::uint8_t* data, std::size_t len) {
    Sha256 hasher;
    hasher.update(data, len);
    return hasher.hex();
}

std::string sha256_hex(std::string_view data) {
    return sha256_hex(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

}  // namespace mailtrace
