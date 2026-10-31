// Local modification, 2026-10-30. GPL-3.0-or-later.
#pragma once
#include <cstdint>
namespace personal {
// This personal build never allocates work to developer donation, even when an
// older JSON/CLI configuration requests a nonzero value.
constexpr double donationPercent(double) { return 0.0; }
constexpr uint64_t donationMillis(double) { return 0; }
constexpr uint64_t normalMillis(double) { return 100 * 60000; }
}
