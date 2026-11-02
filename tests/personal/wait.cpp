// SPDX-License-Identifier: GPL-3.0-or-later
#include "personal/GpuWait.h"
#include <cassert>
#include <iostream>
#include <thread>
using xmrig::personal::GpuWait;
using xmrig::personal::GpuTiming;
int main()
{
    for (bool precise : {false, true}) {
        GpuWait timer(precise);
        uint64_t total=0, requested=0;
        for (unsigned i=0;i<20;++i) {
            const uint64_t us = precise ? 500 : 1000;
            const auto start=GpuWait::nowUs();
            timer.sleep(us);
            const auto elapsed=GpuWait::nowUs()-start;
            assert(elapsed >= us); // No early return / busy-spin admission.
            assert(elapsed < 1000000); // Bounded, with generous CI scheduling tolerance.
            total+=elapsed; requested+=us;
        }
        std::cout << timer.source() << " requested_us=" << requested << " actual_us=" << total << '\n';
        for (uint64_t invalid : {0ULL, 50001ULL}) {
            bool threw=false;
            try { timer.sleep(invalid); } catch (const std::invalid_argument &) { threw=true; }
            assert(threw);
        }
    }
    GpuTiming timing;
    timing.batch(350); timing.batch(500); timing.slept(250,400); timing.slept(150,200);
    assert(timing.batches==2 && timing.batchUs==850 && timing.maxBatchUs==500);
    assert(timing.sleepCalls==2 && timing.requestedUs==400 && timing.actualUs==600 && timing.maxSleepUs==400);
}
