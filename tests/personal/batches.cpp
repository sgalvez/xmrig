// SPDX-License-Identifier: GPL-3.0-or-later
#include "test-runtime.h"
#include "personal/OclGovernor.h"
#include <cassert>
#include <iostream>
std::atomic<bool> xmrig::Nonce::stopped{false};
std::atomic<int> xmrig::AdlLib::hotspot{55};
using namespace xmrig;
using namespace xmrig::personal;
int main()
{
    OclLaunchData a, b;
    b.device.pci.id="04:00.0";
    auto shared=OclGovernor::acquire(a);
    assert(shared==OclGovernor::acquire(a));
    assert(shared!=OclGovernor::acquire(b));
    a.thread.duty=0;
    bool rejected=false;
    try { OclGovernor::acquire(a); } catch(const std::runtime_error &) { rejected=true; }
    assert(rejected);
    a.thread.duty=25; a.thread.batch=65537;
    rejected=false;
    try { OclGovernor::acquire(a); } catch(const std::runtime_error &) { rejected=true; }
    assert(rejected);
    a.thread.batch=65536;
    std::atomic<int> inside{0};
    auto run=[&]() {
        for(int i=0;i<5;++i) {
            GpuBatch budget(shared,a,i%2 ? "search" : "dag");
            assert(inside.fetch_add(1)==0);
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
            assert(inside.fetch_sub(1)==1);
            budget.complete();
        }
    };
    std::thread t1(run), t2(run);
    t1.join(); t2.join();
    // An exception after admission latches the shared GPU, including new workers.
    try { GpuBatch failed(shared,a,"dag"); throw std::runtime_error("fake queue failure"); }
    catch(const std::runtime_error &) {}
    assert(OclGovernor::acquire(a)->policy.state()==GpuGovernor::State::Fault);
    for (const char *phase : {"dag", "search"}) {
        OclLaunchData c;
        c.device.pci.id=std::string("thermal-")+phase;
        auto thermal=OclGovernor::acquire(c);
        AdlLib::hotspot=80;
        std::atomic<bool> admitted{false};
        std::thread cooler([&]() {
            try { GpuBatch budget(thermal,c,phase); admitted=true; budget.complete(); }
            catch(const std::runtime_error &) {}
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        assert(!admitted); // No kernel submission while halted.
        AdlLib::hotspot=60;
        const auto deadline=Chrono::steadyMSecs()+2000;
        while(!admitted && Chrono::steadyMSecs()<deadline) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if(!admitted) Nonce::stopped=true;
        cooler.join();
        assert(admitted); // Same controller resumes DAG/search after cooling.
    }
    AdlLib::hotspot=55;
    auto cancellable=OclGovernor::acquire(b);
    cancellable->policy.completed(0,Chrono::steadyMSecs()+60000);
    bool cancelled=false;
    std::thread waiter([&]() {
        try { GpuBatch batch(cancellable,b,"dag"); }
        catch(const std::runtime_error &) { cancelled=true; }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    const auto start=Chrono::steadyMSecs();
    Nonce::stopped=true;
    waiter.join();
    assert(cancelled && Chrono::steadyMSecs()-start<1000);
    std::cout << "GPU batches: shared budget, serialization, bounds, fault latch and cancellation OK\n";
}
