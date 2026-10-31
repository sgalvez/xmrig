// SPDX-License-Identifier: GPL-3.0-or-later
// Fake platform only; tests include the unchanged production OclGovernor.h.
#pragma once
#include <atomic>
#include <chrono>
#include <string>
#include <vector>
#include <mutex>
#include <cstdio>
#include "backend/opencl/wrappers/AdlHealth.h"
#define XMRIG_FEATURE_ADL
extern std::mutex testLogMutex;
extern std::vector<std::string> testLogLines;
template<typename... Args> void testLog(const char *format, Args... args) {
    char buffer[2048];
    std::snprintf(buffer, sizeof(buffer), format, args...);
    std::lock_guard<std::mutex> lock(testLogMutex);
    testLogLines.emplace_back(buffer);
}
#define LOG_INFO(...) testLog(__VA_ARGS__)
namespace xmrig {
enum { OCL_VENDOR_AMD=1 };
struct Chrono {
    static uint64_t steadyMSecs() { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
};
struct Nonce {
    enum { OPENCL=1 };
    static std::atomic<bool> stopped;
    static uint64_t sequence(int) { return stopped ? 0 : 1; }
    static bool isPaused() { return false; }
};
struct TestThread {
    unsigned duty=25, batch=65536;
    unsigned gpuDuty() const { return duty; }
    unsigned intensity() const { return batch; }
};
struct TestTopology {
    std::string id="03:00.0";
    std::string toString() const { return id; }
};
struct OclDevice {
    TestTopology pci;
    int vendorId() const { return OCL_VENDOR_AMD; }
    unsigned index() const { return 1; }
    TestTopology topology() const { return pci; }
};
struct OclLaunchData { TestThread thread; OclDevice device; };
struct AdlLib {
    static std::atomic<int> hotspot;
    static AdlHealth health(const OclDevice &) {
        AdlHealth s; s.edge=50; s.hotspot=hotspot; s.polled=Chrono::steadyMSecs(); return s;
    }
};
}
