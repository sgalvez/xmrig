"""Explain already-filtered monitoring data without controlling hardware."""
from decimal import Decimal, InvalidOperation


def number(value):
    try:
        n = Decimal(str(value))
        return n if n.is_finite() else None
    except InvalidOperation:
        return None


def seconds(value):
    n = number(value)
    if n is None or n < 0:
        return 'sin dato'
    m, s = divmod(int(n), 60)
    return f'{m} min {s:02d} s'


def explain(data):
    t, m, p = (data.get(k, {}) for k in ('telemetry', 'miner', 'pool'))
    active = m.get('process') == 'Activo' and not data.get('stale')
    state, phase = t.get('governor_state'), t.get('governor_phase')
    cooling = active and state == 'cooling' and number(t.get('duty_percent')) == 0
    labels = {'dag': 'Preparando memoria (DAG)', 'search': 'Buscando soluciones'}
    phase_label = labels.get(phase, 'Sin fase reciente')
    control_label = {'cooling': 'Enfriando', 'running': 'En marcha', 'fault': 'Fallo'}.get(state, 'Sin lectura reciente')
    summary = data.get('title', 'Esperando datos')
    work = 'Sin confirmación reciente de trabajo del pool.'
    next_step = 'Comprueba el estado del minero antes de iniciar otra sesión.'
    thermal = 'Temperaturas sin lectura reciente; no se pueden evaluar.'
    values = [(label, number(t.get(key))) for label, key in
              (('GPU', 'edge_c'), ('Hotspot', 'hotspot_c'), ('Memoria', 'memory_c'))]
    known = [(label, n) for label, n in values if n is not None]
    if known:
        thermal = ' / '.join(f'{label} {n:g} °C' for label, n in known) + ' · pausa a 80 °C'
    if cooling:
        summary = 'ENFRIANDO · minería en pausa'
        blockers = [(label, n) for label, n in known if n > 60]
        if blockers:
            thermal = 'Para reanudar: ' + '; '.join(f'{label} {n:g} → 60 °C (bajar {n-60:g} °C)' for label, n in blockers)
        elif len(known) < 2:
            thermal = 'Faltan lecturas para comprobar el enfriamiento.'
        else:
            thermal = 'Lecturas disponibles <=60 °C; esperando confirmación del control.'
        work = 'No se envía trabajo nuevo a la GPU. El proceso sigue vivo.'
        next_step = 'Reanuda automáticamente con todos los sensores disponibles <=60 °C; Ctrl+C en la sesión detiene.'
    elif active and state == 'running' and phase == 'dag':
        summary = 'PREPARANDO · todavía sin minería productiva'
        work = 'Construyendo el DAG, la memoria de trabajo para KAWPOW. Recibir jobs no confirma shares.'
        next_step = 'Espera a que termine la preparación; después deben aparecer velocidad y shares.'
    elif active and state == 'running' and phase == 'search':
        summary = 'MINANDO · comprobando trabajo en el pool'
        local = number(t.get('hashrate_10s_hs'))
        work = f'GPU: {local/1000000:.6f} MH/s en los últimos 10 s.' if local is not None else 'Buscando soluciones; aún sin velocidad local reciente.'
        next_step = 'Una share aceptada acredita trabajo; el cobro llega después, según el pool.'
    elif active and state is None:
        work = 'Proceso activo; falta un latido reciente del control GPU para conocer su fase.'
        next_step = 'Espera la siguiente lectura. Un proceso abierto no confirma minería.'
    share = p.get('last_share_age')
    if active and share is not None:
        work += ' Última share del pool: hace ' + seconds(share) + '.'
    elif active and p.get('fresh'):
        work += ' Sin share registrada para este worker en la consulta disponible.'
    fan = number(t.get('fan_rpm'))
    if fan is None:
        fan_note = 'Ventiladores: sin lectura reciente; no equivale a 0 RPM.'
    elif fan == 0:
        fan_note = 'Ventiladores: 0 RPM informados. Contrasta con AMD; puede ser Zero RPM, no prueba una avería.'
        if cooling:
            next_step = 'Revisa refrigeración en AMD: el control espera enfriamiento, pero informa ventiladores a 0 RPM.'
    else:
        fan_note = f'Ventiladores: {fan:g} RPM informados; comprueba que la temperatura vaya bajando.'
    trial = 'Sesión continua · Ctrl+C en la sesión de minería detiene la GPU.'
    if m.get('trial'):
        elapsed = number(m.get('active_seconds'))
        if elapsed is None:
            trial = 'Prueba: esperando contador de tiempo activo.'
        else:
            remaining = max(Decimal(0), 300-elapsed)
            trial = f'Prueba: {min(elapsed,300):.0f}/300 s sin pausa · faltan {remaining:.0f} s activos · enfriando {seconds(m.get("cooling_seconds"))}.'
            if remaining == 0:
                trial += ' Pendiente de validación del pool.'
    if not active:
        trial = 'Sesión detenida o sin verificar; los contadores anteriores no indican actividad.'
    # Security and identity warnings take precedence over thermal interpretation.
    if data.get('state') == 'warning' or not active:
        summary = data.get('title', 'Sin estado actual')
        next_step = data.get('detail', next_step)
    return dict(summary=summary, work=work, thermal=thermal, fan=fan_note, trial=trial,
                next_step=next_step, phase=phase_label, control=control_label,
                payment='Share = trabajo aceptado → saldo del pool → pago recibido en la billetera. Son etapas distintas.')
