/* Copyright (c) 2026 Sebastian Galvez. SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef XMRIG_PERSONAL_OCL_GOVERNOR_H
#define XMRIG_PERSONAL_OCL_GOVERNOR_H

#include "personal/GpuGovernor.h"
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
    explicit OclGovernor(unsigned duty) : policy(duty) {}
    std::mutex mutex;
    GpuGovernor policy;
    ThermalSample last;
    uint64_t logged = 0;

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
        if (!entry) { entry = std::make_shared<OclGovernor>(duty); }
        if (entry->policy.maximum() != duty) {
            throw std::runtime_error("Conflicting GPU duty profiles: restart miner to change policy");
        }
        return entry;
    }

    void before(const OclLaunchData &data, const char *phase)
    {
        for (;;) {
            if (!Nonce::sequence(Nonce::OPENCL)) { throw std::runtime_error("GPU governor cancelled"); }
            uint64_t now = Chrono::steadyMSecs();
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
            if (!logged || now - logged >= 1000 || policy.state() == GpuGovernor::State::Fault) {
                LOG_INFO("gpu-governor {\"v\":1,\"gpu\":%u,\"pci\":\"%s\",\"state\":\"%s\",\"reason\":\"%s\",\"phase\":\"%s\",\"duty_percent\":%u,\"edge_c\":%s,\"hotspot_c\":%s,\"memory_c\":%s}",
                         data.device.index(), data.device.topology().toString().data(), policy.name(), policy.reason(), phase, policy.effectiveDuty(),
                         AdlHealth::number(last.edge).c_str(), AdlHealth::number(last.hotspot).c_str(), AdlHealth::number(last.memory).c_str());
                logged = now;
            }
            if (policy.state() == GpuGovernor::State::Fault) { throw std::runtime_error(policy.reason()); }
            if (policy.ready(now) && !Nonce::isPaused()) { return; }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
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
    }
    ~GpuBatch()
    {
        if (m_governor && !m_completed) { m_governor->policy.fault("gpu-batch-failed"); }
    }
    void complete()
    {
        if (m_governor) { m_governor->policy.completed(m_started, Chrono::steadyMSecs()); }
        m_completed = true;
    }
private:
    std::shared_ptr<OclGovernor> m_governor;
    std::unique_lock<std::mutex> m_lock;
    uint64_t m_started = 0;
    bool m_completed = false;
};
}
}
#endif
