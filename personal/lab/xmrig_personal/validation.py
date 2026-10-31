"""Validate a bounded GPU trial against the user's public pool worker."""
import math
import re
import time
from .storage import read_json, write_json


class ValidationError(ValueError):
    pass

ENGINE = 'XMRig'
COMMIT = 'e04811e6121020302ab58f71909137dced3ac33b'
POLICY = 'rvn-governor-2'
MINING_PROFILE = 'rx9070xt-duty25-halt80-resume60-v2'


def validate_probe(config, probe, build, gpu, pool, now):
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
    numbers = (start, end, active, cooling, now)
    if (any(isinstance(n, bool) or not isinstance(n, (int, float)) or not math.isfinite(n) for n in numbers)
            or not (0 <= now-end <= 600 and 295 <= active <= 420 and cooling >= 0)
            or abs((end-start) - (active+cooling)) > 5):
        raise ValidationError('La prueba es antigua o no acredita cinco minutos sin pausa térmica; repite mine-test.')
    worker = probe.get('probe_worker', '')
    if not re.fullmatch(r'probe-[a-f0-9]{20}', worker):
        raise ValidationError('Worker temporal inválido.')
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
