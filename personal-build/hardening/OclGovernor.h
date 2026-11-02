/* Copyright (c) 2026 Sebastian Galvez. SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef XMRIG_PERSONAL_OCL_GOVERNOR_H
#define XMRIG_PERSONAL_OCL_GOVERNOR_H

#include "personal/GpuGovernor.h"
#include "personal/GpuWait.h"
#include "backend/opencl/OclLaunchData.h"
#include "backend/opencl/wrappers/AdlHealth.h"
#ifdef XMRIG_FEATURE_ADL
#include "backend/opencl/wrappers/AdlLib.h"
#endif
#include "base/io/log/Log.h"
#include "base/tools/Chrono.h"
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <string>

namespace xmrig {
namespace personal {

struct OclGovernor {
    explicit OclGovernor(unsigned duty, bool preciseWait) : policy(duty), precise(preciseWait), timer(preciseWait) {}
    std::mutex mutex;
    GpuGovernor policy;
    const bool precise;
    GpuWait timer;
    GpuTiming timing;
    std::string timingPhase;
    ThermalSample last;
    uint64_t logged = 0;
    uint32_t dagDone = 0, dagTotal = 0;
    std::string loggedPhase;
    GpuGovernor::State loggedState = GpuGovernor::State::Running;

    static std::shared_ptr<OclGovernor> acquire(const OclLaunchData &data)
    {
        const auto duty = data.thread.gpuDuty();
        if (duty && data.device.vendorId() != OCL_VENDOR_AMD) {
            throw std::runtime_error("GPU governor requires AMD edge and hotspot telemetry");
        }
        if (duty && data.thread.intensity() > 65536) {
            throw std::runtime_error("Governed KAWPOW requires intensity <= 65536 to bound search batches");
        }
        static std::mutex registryMutex;
        // Keep faults latched even when a job/profile recreates the workers.
        static std::map<std::string, std::shared_ptr<OclGovernor>> registry;
        static std::map<std::string, unsigned> profiles;
        std::lock_guard<std::mutex> lock(registryMutex);
        const std::string pci(data.device.topology().toString().data());
        const auto profile = profiles.find(pci);
        if (profile != profiles.end() && profile->second != duty) {
            throw std::runtime_error("Conflicting GPU duty profiles: restart miner to change policy");
        }
        profiles[pci] = duty;
        if (!duty) { return {}; }
        auto &entry = registry[pci];
        if (!entry) { entry = std::make_shared<OclGovernor>(duty, data.thread.gpuPreciseWait()); }
        if (entry->policy.maximum() != duty || entry->precise != data.thread.gpuPreciseWait()) {
            throw std::runtime_error("Conflicting GPU duty profiles: restart miner to change policy");
        }
        return entry;
    }

    void before(const OclLaunchData &data, const char *phase)
    {
        for (;;) {
            if (!Nonce::sequence(Nonce::OPENCL)) { throw std::runtime_error("GPU governor cancelled"); }
            uint64_t now = Chrono::steadyMSecs();
            uint64_t nowUs = GpuWait::nowUs();
            if (timingPhase != phase) {
                timing = GpuTiming(); timing.started = nowUs; timingPhase = phase;
            }
            if (!last.polled || now - last.polled >= 250) {
                AdlHealth health;
#               ifdef XMRIG_FEATURE_ADL
                health = AdlLib::health(data.device);
#               endif
                last.edge = health.edge;
                last.hotspot = health.hotspot;
                last.memory = health.memory;
                last.polled = health.polled;
                now = Chrono::steadyMSecs();
                policy.sample(last, now);
            }
            // Report transitions immediately; a short thermal halt must not be
            // hidden by the one-second heartbeat (UI and trial clocks use it).
            if (!logged || loggedPhase != phase || loggedState != policy.state() || now - logged >= 1000 || policy.state() == GpuGovernor::State::Fault) {
                LOG_INFO("gpu-governor {\"v\":1,\"gpu\":%u,\"pci\":\"%s\",\"state\":\"%s\",\"reason\":\"%s\",\"phase\":\"%s\",\"duty_percent\":%u,\"edge_c\":%s,\"hotspot_c\":%s,\"memory_c\":%s,\"dag_done\":%u,\"dag_total\":%u}",
                         data.device.index(), data.device.topology().toString().data(), policy.name(), policy.reason(), phase, policy.effectiveDuty(),
                         AdlHealth::number(last.edge).c_str(), AdlHealth::number(last.hotspot).c_str(), AdlHealth::number(last.memory).c_str(), dagDone, dagTotal);
                logged = now;
                loggedPhase = phase;
                loggedState = policy.state();
            }
            if (policy.state() == GpuGovernor::State::Fault) { throw std::runtime_error(policy.reason()); }
            const bool paused = Nonce::isPaused();
            nowUs = GpuWait::nowUs();
            if (nowUs - timing.started >= 5000000) {
                LOG_INFO("gpu-timing {\"v\":1,\"gpu\":%u,\"pci\":\"%s\",\"phase\":\"%s\",\"timer\":\"%s\",\"duty_percent\":%u,\"window_us\":%llu,\"batches\":%llu,\"batch_us\":%llu,\"max_batch_us\":%llu,\"sleep_calls\":%llu,\"sleep_requested_us\":%llu,\"sleep_actual_us\":%llu,\"max_sleep_us\":%llu}",
                         data.device.index(), data.device.topology().toString().data(), phase, timer.source(), policy.effectiveDuty(),
                         static_cast<unsigned long long>(nowUs - timing.started), static_cast<unsigned long long>(timing.batches),
                         static_cast<unsigned long long>(timing.batchUs), static_cast<unsigned long long>(timing.maxBatchUs),
                         static_cast<unsigned long long>(timing.sleepCalls), static_cast<unsigned long long>(timing.requestedUs),
                         static_cast<unsigned long long>(timing.actualUs), static_cast<unsigned long long>(timing.maxSleepUs));
                timing = GpuTiming(); timing.started = nowUs;
            }
            nowUs = GpuWait::nowUs();
            now = Chrono::steadyMSecs();
            if ((precise ? policy.readyUs(nowUs) : policy.ready(now)) && !paused) { return; }
            const uint64_t requested = paused ? 50000 : precise ? policy.waitUs(nowUs) : policy.waitMs(now) * 1000;
            const uint64_t sleepStarted = GpuWait::nowUs();
            try { timer.sleep(requested); }
            catch (...) { policy.fault("gpu-wait-timer-failed"); throw; }
            timing.slept(requested, GpuWait::nowUs() - sleepStarted);
        }
    }
};

// Serialize GPU submissions, not unrelated GPUs. Queue completion must happen
// before this scope ends. Exceptions latch a fault and prohibit further work.
class GpuBatch {
public:
    GpuBatch(const std::shared_ptr<OclGovernor> &governor, const OclLaunchData &data, const char *phase) : m_governor(governor)
    {
        if (!m_governor) { return; }
        m_lock = std::unique_lock<std::mutex>(m_governor->mutex, std::defer_lock);
        while (!m_lock.try_lock()) {
            if (!Nonce::sequence(Nonce::OPENCL)) { throw std::runtime_error("GPU governor cancelled"); }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        m_governor->before(data, phase);
        m_started = Chrono::steadyMSecs();
        m_startedUs = GpuWait::nowUs();
    }
    ~GpuBatch()
    {
        if (m_governor && !m_completed) { m_governor->policy.fault("gpu-batch-failed"); }
    }
    void progress(uint32_t done, uint32_t total)
    {
        if (m_governor) { m_governor->dagDone = std::min(done, total); m_governor->dagTotal = total; }
    }
    void complete()
    {
        if (m_governor) {
            const uint64_t endedUs = GpuWait::nowUs();
            m_governor->timing.batch(endedUs - m_startedUs);
            if (m_governor->precise) { m_governor->policy.completedUs(m_startedUs, endedUs); }
            else { m_governor->policy.completed(m_started, Chrono::steadyMSecs()); }
        }
        m_completed = true;
    }
private:
    std::shared_ptr<OclGovernor> m_governor;
    std::unique_lock<std::mutex> m_lock;
    uint64_t m_started = 0;
    uint64_t m_startedUs = 0;
    bool m_completed = false;
};
}
}
#endif
