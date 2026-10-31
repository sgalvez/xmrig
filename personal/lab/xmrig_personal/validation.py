"""Validate a bounded GPU trial against the user's public pool worker."""
import math
import re
import time
from .storage import read_json, write_json


class ValidationError(ValueError):
    pass

ENGINE = 'XMRig'
COMMIT = '778ef0f43cd5d2e989f117298d2ab1c159b671e8'
POLICY = 'rvn-governor-4'
MINING_PROFILE = 'rx9070xt-duty25-halt80-resume60-search300-nodonate-v4'


def validate_record(config, probe, build, gpu, now):
    if not isinstance(probe, dict) or probe.get('completed') is not True or probe.get('error'):
        raise ValidationError('La prueba no terminó correctamente. Revisa logs; no se habilita el arranque permanente.')
    if build.get('engine') != ENGINE or build.get('commit') != COMMIT or build.get('security_policy') != POLICY or not re.fullmatch(r'[a-f0-9]{64}', build.get('sha256', '')):
        raise ValidationError('Compilación no identificada.')
    expected = {'engine': ENGINE, 'sha256': build['sha256'], 'security_policy': POLICY, 'mining_profile': MINING_PROFILE, 'gpu_id': gpu,
                'address': config['address'], 'worker': config['worker'], 'pool': config['pool']}
    if any(probe.get(k) != v for k, v in expected.items()):
        raise ValidationError('La prueba corresponde a otra GPU, compilación o configuración.')
    start, end = probe.get('started'), probe.get('ended')
    active, cooling = probe.get('active_seconds'), probe.get('cooling_seconds')
    search, preparation = probe.get('search_seconds'), probe.get('preparation_seconds')
    observed, search_started = probe.get('observed_seconds'), probe.get('search_started')
    numbers = (start, end, active, cooling, search, preparation, observed, search_started, now)
    if (any(isinstance(n, bool) or not isinstance(n, (int, float)) or not math.isfinite(n) for n in numbers)
            or not (0 <= now-end <= 600 and 295 <= search <= 420 and cooling >= 0 and 0 <= preparation <= 900
                    and start <= search_started <= end and search <= end-search_started+2)
            or abs(active - (search+preparation)) > 0.1
            or abs(observed - (active+cooling)) > 0.1
            or abs((end-start) - observed) > 5):
        raise ValidationError('La prueba está vencida o sus tiempos no acreditan cinco minutos de búsqueda después del DAG. Revisa el registro de prueba.')
    worker = probe.get('probe_worker', '')
    if not re.fullmatch(r'probe-[a-f0-9]{20}', worker):
        raise ValidationError('Worker temporal inválido.')
    return expected


def validate_probe(config, probe, build, gpu, pool, now):
    expected = validate_record(config, probe, build, gpu, now)
    start, end = probe['search_started'], probe['ended']
    worker = probe['probe_worker']
    candidates = pool.get('workers', {}).get('list', [])
    for entry in candidates:
        try:
            share = float(entry.get('lastShareTime', 0))
        except (ValueError, TypeError):
            continue
        if entry.get('name') == worker and start <= share <= end + 10 and share <= now:
            return {**expected, 'verified': True, 'verified_at': now, 'method': 'RavenMiner worker lastShareTime',
                    'probe_worker': worker, 'last_share': share}
    raise ValidationError('RavenMiner aún no confirma una share del worker de prueba; no se habilita el arranque permanente.')


def confirm(runtime, config, gpu, build_path, fetch, sleep=time.sleep, clock=time.time):
    probe = read_json(runtime / 'xmrig-probe.json')
    build = read_json(build_path)
    # A malformed/expired trial cannot become valid by polling the pool again.
    validate_record(config, probe, build, gpu, clock())
    last_error = None
    for attempt in range(5):
        try:
            pool = fetch(config['address'])  # Fresh request, never the dashboard cache.
            record = validate_probe(config, probe, build, gpu, pool, clock())
            write_json(runtime / 'xmrig-validation.json', record)
            return record
        except (ValidationError, OSError, ValueError) as error:
            last_error = error
        if attempt < 4:
            print('Esperando confirmación del worker temporal en RavenMiner…', flush=True)
            sleep(15)
    raise ValidationError(str(last_error))
