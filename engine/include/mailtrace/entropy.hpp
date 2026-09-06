// SPDX-License-Identifier: MIT
//
// Shannon entropy over the 256-symbol byte alphabet, in bits per byte.
#ifndef MAILTRACE_ENTROPY_HPP
#define MAILTRACE_ENTROPY_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mailtrace {

[[nodiscard]] double shannon_entropy(const std::uint8_t* data, std::size_t len) noexcept;
[[nodiscard]] double shannon_entropy(std::string_view data) noexcept;

}  // namespace mailtrace

#endif  // MAILTRACE_ENTROPY_HPP
