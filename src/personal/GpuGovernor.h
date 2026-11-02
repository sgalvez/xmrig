/* Copyright (c) 2026 Sebastian Galvez. SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef XMRIG_PERSONAL_GPU_GOVERNOR_H
#define XMRIG_PERSONAL_GPU_GOVERNOR_H

#include <algorithm>
#include <cstdint>
#include <stdexcept>

namespace xmrig {
namespace personal {

// All times are monotonic milliseconds. -1 denotes unavailable, never 0 C.
struct ThermalSample {
    int edge = -1;
    int hotspot = -1;
    int memory = -1;
    uint64_t polled = 0;
};

class GpuGovernor {
public:
    enum class State { Running, Cooling, Fault };

    explicit GpuGovernor(unsigned maximum) : m_maximum(maximum), m_duty(maximum)
    {
        if (maximum < 5 || maximum > 100) {
            throw std::invalid_argument("gpu-duty-percent must be 5..100 (or 0 to disable)");
        }
    }

    void sample(const ThermalSample &s, uint64_t now)
    {
        if (m_state == State::Fault) { return; }
        if (s.polled > now || now - s.polled > 2000 ||
            s.edge <= 0 || s.hotspot <= 0 || s.edge > 150 || s.hotspot > 150 ||
            s.memory > 150 || (m_hadMemory && s.memory <= 0)) {
            fault("sensor-missing-or-stale");
            return;
        }
        m_hadMemory |= s.memory > 0;
        // User policy: any available sensor at 80 C pauses submissions.
        // Thermal pauses recover automatically; invalid telemetry remains a fault.
        if (s.edge >= 80 || s.hotspot >= 80 || s.memory >= 80) {
            m_state = State::Cooling;
            m_reason = s.edge >= 80 ? "edge-temperature" : s.hotspot >= 80 ? "hotspot-temperature" : "memory-temperature";
            m_duty = 5;
            return;
        }
        const bool cool = s.edge <= 60 && s.hotspot <= 60 && s.memory <= 60;
        if (m_state == State::Cooling) {
            if (!cool) { return; }
            m_state = State::Running;
            m_reason = "none";
            m_adjusted = now;
        }
        // Regulation while running is separate from recovery after a thermal halt.
        // Leave 5 C below the fixed 80 C cutoff; recover load at <=70 C so
        // ordinary memory temperatures (61..65 C) cannot latch a low duty forever.
        if ((s.edge >= 75 || s.hotspot >= 75 || s.memory >= 75) && now - m_adjusted >= 1000) {
            m_duty = std::max(5U, m_duty > 5 ? m_duty - 5 : 5U);
            m_reason = s.edge >= 75 ? "edge-throttling" : s.hotspot >= 75 ? "hotspot-throttling" : "memory-throttling";
            m_adjusted = now;
        }
        else if (s.edge <= 70 && s.hotspot <= 70 && s.memory <= 70 && now - m_adjusted >= 5000 && m_duty < m_maximum) {
            ++m_duty;
            m_reason = m_duty < m_maximum ? "recovering-duty" : "none";
            m_adjusted = now;
        }
    }

    // Charge each completed GPU batch; wait BEFORE the next batch so results
    // can be submitted immediately. Shared by every worker on the same GPU.
    void completed(uint64_t started, uint64_t ended)
    {
        const uint64_t busy = ended > started ? ended - started : 1;
        m_next = ended + (busy * (100 - m_duty) + m_duty - 1) / m_duty;
    }
    bool ready(uint64_t now) const { return m_state == State::Running && now >= m_next; }
    // Do not round a short duty-budget wait up to a fixed 50 ms per DAG batch.
    uint64_t waitMs(uint64_t now) const
    {
        if (m_state != State::Running) { return 50; }
        return m_next > now ? std::min<uint64_t>(50, m_next - now) : 1;
    }
    // Fine budget uses a separate monotonic microsecond clock. Keep the legacy
    // millisecond path intact for controlled comparisons with the same binary.
    void completedUs(uint64_t started, uint64_t ended)
    {
        const uint64_t busy = ended > started ? ended - started : 1;
        m_nextUs = ended + (busy * (100 - m_duty) + m_duty - 1) / m_duty;
    }
    bool readyUs(uint64_t now) const { return m_state == State::Running && now >= m_nextUs; }
    uint64_t waitUs(uint64_t now) const
    {
        if (m_state != State::Running) { return 50000; }
        return m_nextUs > now ? std::min<uint64_t>(50000, m_nextUs - now) : 1;
    }
    unsigned duty() const { return m_duty; }
    unsigned effectiveDuty() const { return m_state == State::Running ? m_duty : 0; }
    unsigned maximum() const { return m_maximum; }
    State state() const { return m_state; }
    const char *reason() const { return m_reason; }
    const char *name() const
    {
        return m_state == State::Fault ? "fault" : m_state == State::Cooling ? "cooling" : "running";
    }
    void fault(const char *reason) { m_state = State::Fault; m_reason = reason; }

private:
    unsigned m_maximum;
    unsigned m_duty;
    uint64_t m_next = 0;
    uint64_t m_nextUs = 0;
    uint64_t m_adjusted = 0;
    bool m_hadMemory = false;
    State m_state = State::Running;
    const char *m_reason = "none";
};
}
}
#endif
