# Duty timing and observability

The governor previously rounded each work batch and pause to integer
milliseconds and used `std::this_thread::sleep_for`. With small KAWPOW batches,
60% and 75% can request identical pauses. Windows scheduling can also turn a
1 ms pause into approximately 15.6 ms. The latter is a hypothesis until the
miner itself reports its requested and actual wait durations.

Governed OpenCL threads now default to `gpu-precise-wait: true`. The budget
uses monotonic microseconds and Windows uses an unnamed, non-inheritable,
auto-reset high-resolution waitable timer, one per serialized GPU governor.
No global timer resolution, thread priority, busy polling or spin loop is used.
On systems without the Windows high-resolution API the precise mode fails
before any batch is admitted. Timer setup/wait failures prevent further work.

`gpu-precise-wait: false` retains the previous budget and sleep implementation
for controlled comparisons. It has the same thermal limits. A profile cannot
change timing modes without restarting and the wrapper validates the new
binary, load and timing mode together before continuous mining.

Every five seconds, `gpu-timing` reports the GPU/PCI address, phase, selected
timer, elapsed window, batch count, batch time, maximum batch time, requested
and actual sleep time and maximum observed sleep. Counters reset by phase so
DAG preparation cannot be confused with search. Batch time includes CPU and
driver calls and queue completion; it is not a hardware utilization counter.
The log is bounded to one summary per window instead of one line per kernel.

All available temperature sensors still pause submissions at 80 C, resume at
60 C and regulate load from 75 C. Sleep requests remain bounded to 50 ms and
the Windows wait has a finite failure timeout. Cancellation is checked on each
iteration. Hash correctness and pool acceptance must be tested on real hardware
after any timing change; a synthetic test does not establish those properties.

Windows API references:

- [CreateWaitableTimerExW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createwaitabletimerexw)
- [SetWaitableTimer](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setwaitabletimer)
- [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
