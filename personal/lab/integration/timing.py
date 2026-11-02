"""Read-only summary of native batch and sleep observations, never hardware utilization."""
from decimal import Decimal, InvalidOperation


def number(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        value = Decimal(str(value))
        return value if value.is_finite() and 0 <= value <= 2**63-1 and value == value.to_integral_value() else None
    except InvalidOperation:
        return None


def presentation(miner, now, active):
    sample = miner.get('timing')
    stamp = number(miner.get('timing_updated'))
    if not active or not isinstance(sample, dict) or stamp is None or not 0 <= now-float(stamp) <= 20:
        return {'available': False}
    phase, source = sample.get('phase'), sample.get('timer')
    if phase not in ('dag', 'search') or source not in ('legacy-sleep', 'steady-sleep', 'waitable-high-resolution'):
        return {'available': False}
    fields = ('window_us', 'batches', 'batch_us', 'sleep_calls', 'sleep_requested_us', 'sleep_actual_us')
    values = {key: number(sample.get(key)) for key in fields}
    if any(value is None for value in values.values()):
        return {'available': False}
    elapsed, batches, busy, calls, requested, actual = (values[key] for key in fields)
    if not 0 < elapsed <= 120000000 or busy+actual > elapsed+1000:
        return {'available': False}
    return dict(available=True, phase=phase, source=source,
                updated=float(stamp), window_seconds=f'{elapsed/1000000:.1f}',
                batches=str(batches), batch_ms=f'{busy/batches/1000:.3f}' if batches else None,
                sleep_requested_ms=f'{requested/calls/1000:.3f}' if calls else None,
                sleep_actual_ms=f'{actual/calls/1000:.3f}' if calls else None,
                batch_percent=f'{busy/elapsed*100:.1f}', sleep_percent=f'{actual/elapsed*100:.1f}')
