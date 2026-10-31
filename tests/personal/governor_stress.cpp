// SPDX-License-Identifier: GPL-3.0-or-later
// Deterministic synthetic telemetry: no miner, GPU, network or drivers.
#include "personal/GpuGovernor.h"
#include <cassert>
#include <cstdint>
#include <iostream>
using xmrig::personal::GpuGovernor;
using xmrig::personal::ThermalSample;
static uint32_t rng = 0x9070;
static uint32_t next() { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; }
int main()
{
    uint64_t samples = 0, pauses = 0, resumes = 0;
    for (unsigned cap = 5; cap <= 100; ++cap) {
        GpuGovernor g(cap);
        uint64_t now = 1000;
        for (unsigned i = 0; i < 10000; ++i) {
            now += 1 + next() % 2000;
            ThermalSample s;
            s.edge = 25 + next() % 61; s.hotspot = 25 + next() % 66;
            s.memory = 25 + next() % 66; s.polled = now;
            const auto before = g.state();
            g.sample(s, now); ++samples;
            assert(g.state() != GpuGovernor::State::Fault);
            assert(g.duty() >= 5 && g.duty() <= cap);
            if (s.edge >= 80 || s.hotspot >= 80 || s.memory >= 80) {
                assert(g.state() == GpuGovernor::State::Cooling && !g.ready(now));
            }
            if (g.state() == GpuGovernor::State::Cooling) {
                assert(g.effectiveDuty() == 0 && !g.ready(now));
                if (before != g.state()) ++pauses;
            }
            if (before == GpuGovernor::State::Cooling && g.state() == GpuGovernor::State::Running) {
                assert(s.edge <= 60 && s.hotspot <= 60 && s.memory <= 60);
                ++resumes;
            }
            if (g.ready(now)) {
                const uint64_t work = 1 + next() % 20;
                g.completed(now, now + work);
                now += work;
                const uint64_t deadline = now + work * 20;
                while (!g.ready(now) && now <= deadline) now += g.waitMs(now);
                assert(g.ready(now)); // Waiting for duty budget cannot deadlock.
            }
        }
        ThermalSample invalid; invalid.edge = 30; invalid.hotspot = 40;
        invalid.memory = 40; invalid.polled = now - 2001;
        g.sample(invalid, now);
        assert(g.state() == GpuGovernor::State::Fault && !g.ready(now));
        invalid.polled = ++now;
        g.sample(invalid, now);
        assert(g.state() == GpuGovernor::State::Fault && !g.ready(now));
    }
    assert(pauses > 10000 && resumes > 10000);
    std::cout << samples << " synthetic samples; " << pauses << " pauses; " << resumes
              << " resumes; duty/hysteresis/latching contracts OK\n";
}
