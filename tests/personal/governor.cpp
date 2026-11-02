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
    AdlHealth power;
    power.setPower(true, 217, true, 150);
    assert(power.powerValid && power.power == 217 && std::string(power.powerScope) == "board");
    assert(power.json(1, "03:00.0").find("\"power_source\":\"adl-pmlog-board\"") != std::string::npos);
    power.setPower(false, 217, true, 42);
    assert(power.power == 42 && std::string(power.powerScope) == "asic");
    power.setPower(true, 0, false, 42);
    assert(power.powerValid && power.power == 0); // Supported zero differs from missing.
    power.setPower(true, -1, false, 42);
    assert(!power.powerValid && power.json(1, "03:00.0").find("\"power_w\":null") != std::string::npos);
    power.setPower(true, 99999, true, -1);
    assert(!power.powerValid);
    power.setPower(false, 217, false, 42);
    assert(!power.powerValid && std::string(power.powerScope) == "unavailable");
    GpuGovernor g(25);
    g.sample(sample(50,55,-1,100),100);
    assert(g.ready(100));
    g.completed(100,200);
    assert(!g.ready(499)); assert(g.ready(500)); // 100 ms work + 300 ms sleep = 25%.
    g.sample(sample(61,75,-1,2000),2000);
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
    GpuGovernor shortBatch(25);
    shortBatch.sample(sample(35,37,60,100),100);
    shortBatch.completed(100,101);
    assert(shortBatch.waitMs(101)==3 && !shortBatch.ready(103) && shortBatch.ready(104));
    // A small DAG batch should not pay a minimum 50 ms delay thousands of times.
    uint64_t simulated=1000;
    for (int i=0;i<6000;++i) {
        shortBatch.completed(simulated,simulated+1);
        simulated+=1;
        while(!shortBatch.ready(simulated)) simulated+=shortBatch.waitMs(simulated);
    }
    assert(simulated==25000); // 6000 * (1 ms work + 3 ms wait), not 306 seconds.
    shortBatch.sample(sample(35,37,80,simulated),simulated);
    assert(shortBatch.waitMs(simulated)==50 && !shortBatch.ready(simulated));
    GpuGovernor warm(25);
    warm.sample(sample(79,79,79,1),1);
    assert(warm.ready(1)); // No earlier 70/75 C pause remains.
    for (int channel=0; channel<3; ++channel) {
        GpuGovernor load(60);
        load.sample(sample(38,42,65,5000),5000);
        assert(load.duty()==60); // Normal VRAM temperature does not throttle.
        auto hot=sample(38,42,65,6000);
        if(channel==0) hot.edge=75;
        if(channel==1) hot.hotspot=75;
        if(channel==2) hot.memory=75;
        load.sample(hot,6000);
        assert(load.duty()==55 && load.state()==GpuGovernor::State::Running);
        load.sample(sample(38,42,71,11000),11000);
        assert(load.duty()==55); // Hold the 70..75 C regulation band.
        for(uint64_t t=16000;t<=36000;t+=5000) load.sample(sample(38,42,65,t),t);
        assert(load.duty()==60); // Recover at 65 C without requiring <=60 C.
        load.sample(sample(38,42,65,41000),41000);
        assert(load.duty()==60); // Never exceed the configured ceiling.
        load.sample(sample(38,42,80,42000),42000);
        load.sample(sample(38,42,65,48000),48000);
        assert(load.effectiveDuty()==0); // A real halt still requires <=60 C.
    }
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
