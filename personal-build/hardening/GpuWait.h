/* Copyright (c) 2026 Sebastian Galvez. SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef XMRIG_PERSONAL_GPU_WAIT_H
#define XMRIG_PERSONAL_GPU_WAIT_H

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#   ifndef NOMINMAX
#       define NOMINMAX
#   endif
#   include <windows.h>
#endif

namespace xmrig { namespace personal {

// One timer per GPU, used only while holding its governor mutex. No busy spin,
// process priority changes, global timer-resolution changes or APC callbacks.
class GpuWait {
public:
    explicit GpuWait(bool precise) : m_precise(precise)
    {
#       ifdef _WIN32
        if (precise) {
            // CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, Windows 10 1803+.
            m_timer = CreateWaitableTimerExW(nullptr, nullptr, 0x00000002,
                                           TIMER_MODIFY_STATE | SYNCHRONIZE);
            if (!m_timer) { throw std::runtime_error("GPU high-resolution timer unavailable"); }
        }
#       endif
    }
    ~GpuWait()
    {
#       ifdef _WIN32
        if (m_timer) { CloseHandle(m_timer); }
#       endif
    }
    GpuWait(const GpuWait &) = delete;
    GpuWait &operator=(const GpuWait &) = delete;

    static uint64_t nowUs()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }
    const char *source() const
    {
        if (!m_precise) { return "legacy-sleep"; }
#       ifdef _WIN32
        return "waitable-high-resolution";
#       else
        return "steady-sleep";
#       endif
    }
    void sleep(uint64_t microseconds)
    {
        if (!microseconds || microseconds > 50000) { throw std::invalid_argument("GPU wait must be 1..50000 us"); }
        if (!m_precise) {
            std::this_thread::sleep_for(std::chrono::milliseconds((microseconds + 999) / 1000));
            return;
        }
#       ifdef _WIN32
        LARGE_INTEGER due;
        due.QuadPart = -static_cast<LONGLONG>(microseconds * 10); // Relative 100 ns units.
        if (!SetWaitableTimer(m_timer, &due, 0, nullptr, nullptr, FALSE) ||
            WaitForSingleObject(m_timer, static_cast<DWORD>((microseconds + 999) / 1000 + 100)) != WAIT_OBJECT_0) {
            throw std::runtime_error("GPU high-resolution timer wait failed");
        }
#       else
        std::this_thread::sleep_for(std::chrono::microseconds(microseconds));
#       endif
    }
private:
    const bool m_precise;
#   ifdef _WIN32
    HANDLE m_timer = nullptr;
#   endif
};

// A bounded, phase-specific observation window. Batch time includes driver calls
// and synchronization; it is not a hardware GPU-utilization counter.
struct GpuTiming {
    uint64_t started = 0, batches = 0, batchUs = 0, maxBatchUs = 0;
    uint64_t sleepCalls = 0, requestedUs = 0, actualUs = 0, maxSleepUs = 0;
    void batch(uint64_t duration)
    {
        ++batches; batchUs += duration;
        if (duration > maxBatchUs) { maxBatchUs = duration; }
    }
    void slept(uint64_t requested, uint64_t actual)
    {
        ++sleepCalls; requestedUs += requested; actualUs += actual;
        if (actual > maxSleepUs) { maxSleepUs = actual; }
    }
};
}}
#endif
