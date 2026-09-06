// SPDX-License-Identifier: MIT
#include "mailtrace/entropy.hpp"

#include <array>
#include <cmath>

namespace mailtrace {

double shannon_entropy(const std::uint8_t* data, std::size_t len) noexcept {
    if (data == nullptr || len == 0) {
        return 0.0;
    }

    std::array<std::size_t, 256> counts{};
    for (std::size_t i = 0; i < len; ++i) {
        ++counts[data[i]];
    }

    const double total = static_cast<double>(len);
    double entropy = 0.0;
    for (std::size_t symbol = 0; symbol < counts.size(); ++symbol) {
        if (counts[symbol] == 0) {
            continue;
        }
        const double p = static_cast<double>(counts[symbol]) / total;
        entropy -= p * std::log2(p);
    }

    // Clamp away the last ulp so callers can rely on the documented range.
    if (entropy < 0.0) {
        return 0.0;
    }
    if (entropy > 8.0) {
        return 8.0;
    }
    return entropy;
}

double shannon_entropy(std::string_view data) noexcept {
    return shannon_entropy(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

}  // namespace mailtrace
