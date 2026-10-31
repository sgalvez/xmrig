// SPDX-License-Identifier: GPL-3.0-or-later
#include "personal/GpuGovernor.h"
#include "backend/opencl/wrappers/AdlHealth.h"
#include <cassert>
#include <iostream>
using xmrig::personal::GpuGovernor;
using xmrig::personal::ThermalSample;
static ThermalSample sample(int edge, int hotspot, int memory, uint64_t time)
{
    ThermalSample s; s.edge=edge; s.hotspot=hotspot; s.memory=memory; s.polled=time; return s;
}
int main()
{
    GpuGovernor g(25);
    g.sample(sample(50,55,-1,100),100);
    assert(g.ready(100));
    g.completed(100,200);
    assert(!g.ready(499)); assert(g.ready(500)); // 100 ms work + 300 ms sleep = 25%.
    g.sample(sample(61,66,-1,2000),2000);
    assert(g.duty()==20);
    g.sample(sample(65,80,-1,3000),3000);
    assert(g.state()==GpuGovernor::State::Cooling && !g.ready(3000));
    assert(g.effectiveDuty()==0);
    g.sample(sample(50,61,-1,7999),7999);
    assert(!g.ready(7999));
    g.sample(sample(50,59,-1,8000),8000);
    assert(g.ready(8000));
    g.sample(sample(55,80,-1,9000),9000);
    assert(g.state()==GpuGovernor::State::Cooling);
    g.sample(sample(30,40,-1,10000),10000);
    assert(g.ready(10000)); // Thermal halt resumes without recreating the GPU.
    for (int channel=0; channel<3; ++channel) {
        GpuGovernor h(25);
        auto s=sample(50,55,55,10);
        if(channel==0) s.edge=80;
        if(channel==1) s.hotspot=80;
        if(channel==2) s.memory=80;
        h.sample(s,10);
        assert(h.state()==GpuGovernor::State::Cooling && h.effectiveDuty()==0);
        h.sample(sample(60,60,61,20),20);
        assert(!h.ready(20)); // Every available sensor must cool, not only hotspot.
        h.sample(sample(60,60,60,30),30);
        assert(h.ready(30) && h.duty()==5);
        h.sample(s,40); // Repeated heating/cooling cycles keep working.
        assert(!h.ready(40));
        h.sample(sample(60,60,60,50),50);
        assert(h.ready(50));
    }
    GpuGovernor warm(25);
    warm.sample(sample(79,79,79,1),1);
    assert(warm.ready(1)); // No earlier 70/75 C pause remains.
    GpuGovernor missing(25);
    missing.sample(sample(-1,55,-1,1),1);
    assert(missing.state()==GpuGovernor::State::Fault);
    missing.sample(sample(50,55,55,2),2);
    assert(!missing.ready(2)); // Sensor faults do not auto-resume.
    GpuGovernor stale(25);
    stale.sample(sample(50,55,-1,1),2002);
    assert(stale.state()==GpuGovernor::State::Fault);
    GpuGovernor lost(25);
    lost.sample(sample(50,55,60,1),1);
    lost.sample(sample(50,55,-1,2),2);
    assert(lost.state()==GpuGovernor::State::Fault);
    for (unsigned duty=5; duty<=100; ++duty) {
        GpuGovernor h(duty);
        uint64_t now=1, busy=0;
        for(int i=0;i<100;++i) {
            while(!h.ready(now)) ++now;
            h.completed(now,now+7); now+=7; busy+=7;
            while(!h.ready(now)) ++now;
        }
        assert(busy*100 <= (now-1)*duty);
    }
    for (unsigned duty : {0U,4U,101U}) {
        bool threw=false;
        try { GpuGovernor invalid(duty); } catch(const std::invalid_argument &) { threw=true; }
        assert(threw);
    }
    AdlHealth health;
    const auto empty=health.json(1,"03:00.0");
    assert(empty.find("\"hotspot_c\":null")!=std::string::npos);
    assert(empty.find("\"power_w\":null")!=std::string::npos);
    health.rpmValid=true; // Supported zero RPM is different from unavailable.
    assert(health.json(1,"03:00.0").find("\"fan_rpm\":0")!=std::string::npos);
    std::cout << "governor: duty budgets, hysteresis, cutoff, missing sensors and telemetry OK\n";
}
