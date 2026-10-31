// Local modification, 2026-10-30. GPL-3.0-or-later.
#pragma once
#include <cstdint>
namespace personal {
constexpr uint64_t donationMillis(double percent) { return static_cast<uint64_t>(percent * 60000.0); }
constexpr uint64_t normalMillis(double percent) { return static_cast<uint64_t>((100.0 - percent) * 60000.0); }
}
