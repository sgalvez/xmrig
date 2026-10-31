"""Read-only terminal workstation. Receives the same public DTO as the web panel."""
import copy
import textwrap
from .insights import explain
import curses
import re
import sys
import threading
import time
import unicodedata
from collections import deque
from datetime import datetime
from decimal import Decimal, InvalidOperation

AMBER, CYAN, GREEN, RED, DIM, WHITE = range(1, 7)


def clean(value):
    value = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(value))
    return ''.join(c for c in value if c.isprintable())


def clip(value, width):
    out, used = [], 0
    for c in clean(value):
        size = 0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in 'WF' else 1
        if used + size > max(0, width):
            break
        out.append(c)
        used += size
    return ''.join(out)


def decimal(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        n = Decimal(str(value))
        return n if n.is_finite() else None
    except InvalidOperation:
        return None


def rate(value):
    n = decimal(value)
    return '--' if n is None else f'{n / 1000000:.6f} MH/s'


def unit(value, suffix):
    return '--' if value is None else f'{value} {suffix}'


def duration(seconds):
    if seconds is None:
        return '--'
    seconds = max(0, int(seconds))
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    return f'{h:02d}:{m:02d}:{s:02d}'


def row(label, value, width=60):
    value = clean('--' if value is None or value == 'no disponible' else value)
    return clip(label, max(0, width - len(value) - 2)).ljust(max(1, width - len(value))) + value


def current(snapshot, now):
    """A frozen snapshot must lose its live indicators as wall time advances."""
    data = copy.deepcopy(snapshot)
    stamp = decimal(data.get('updated'))
    old = stamp is None or not 0 <= now - float(stamp) <= 45
    data['stale'] = old
    if old and not data.get('loading'):
        data.update(state='warning', title='LECTURA ANTIGUA / SIN CONEXIÓN',
                    detail='R para consultar. Los valores anteriores no confirman actividad actual.')
        data['telemetry'] = {}
        data['miner'] = {**data.get('miner', {}), 'process': 'Sin verificar'}
        data['node'] = {**data.get('node', {}), 'status': 'Sin lectura actual'}
    elif stamp is not None:
        t = data.get('telemetry', {})
        for timestamp, limit, keys in (
                ('sample_time', 35, ('hashrate_10s_hs','hashrate_60s_hs','hashrate_15m_hs')),
                ('governor_time', 5, ('governor_state','governor_phase','duty_percent','dag_done','dag_total')),
                ('sensor_time', 30, ('temperature','edge_c','hotspot_c','memory_c','sensor_source','power_w','fan_rpm','core_mhz','memory_mhz'))):
            sample = decimal(t.get(timestamp))
            if sample is None or not 0 <= now - float(sample) <= limit:
                for key in keys: t[key] = None
    pool = data.get('pool', {})
    checked = decimal(pool.get('sample_time'))
    if old or checked is None or not 0 <= now - float(checked) <= 90:
        for key in ('hashrate', 'hashrate_hs', 'cleared', 'pending', 'minimum', 'last_share_age'):
            pool[key] = None
        pool["fresh"] = False
    data["insight"] = explain(data)
    return data


class History:
    def __init__(self):
        self.gpu = deque(maxlen=90)
        self.pool = deque(maxlen=90)

    def add(self, data):
        if data.get('stale'):
            return
        telemetry, pool = data.get('telemetry', {}), data.get('pool', {})
        for history, stamp, raw in ((self.gpu, telemetry.get('sample_time'), telemetry.get('hashrate_10s_hs')),
                                     (self.pool, pool.get('sample_time'), pool.get('hashrate_hs'))):
            n, timestamp = decimal(raw), decimal(stamp)
            if n is not None and timestamp is not None and timestamp > 0 and (not history or timestamp > history[-1][0]):
                history.append((timestamp, n))


def spark(history, width):
    values = [n for _, n in list(history)[-max(1, width):]]
    if not values:
        return 'Sin lecturas todavía', '--'
    lo, hi = min(values), max(values)
    bars = '▁▂▃▄▅▆▇█'
    graph = ''.join(bars[3 if hi == lo else min(7, int((n-lo) * 7 / (hi-lo)))] for n in values)
    return graph, f'mín {rate(lo)}  máx {rate(hi)}'


class Poller:
    """One reader at a time; keyboard and drawing never wait for the network."""
    def __init__(self, reader, interval=5):
        self.reader, self.interval = reader, interval
        self.lock = threading.Lock()
        self.wake, self.stop = threading.Event(), threading.Event()
        self.data = {'loading': True, 'title': 'CONSULTANDO TU EQUIPO', 'state': 'waiting'}
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.thread.start()

    def refresh(self):
        self.wake.set()

    def get(self):
        with self.lock:
            return copy.deepcopy(self.data)

    def close(self):
        self.stop.set()
        self.wake.set()

    def _loop(self):
        while not self.stop.is_set():
            self.wake.clear()
            try:
                result = self.reader()
            except Exception as error:
                result = {'title': 'CONSULTA NO DISPONIBLE', 'state': 'warning',
                          'detail': clean(error)[:180], 'alerts': [clean(error)[:180]]}
            with self.lock:
                self.data = result
            self.wake.wait(self.interval)


class Screen:
    def __init__(self, window, colors=True):
        self.window, self.colors = window, colors
        self.height, self.width = window.getmaxyx()

    def put(self, y, x, value, color=WHITE, width=None, bold=False):
        if y < 0 or x < 0 or y >= self.height or x >= self.width:
            return
        width = min(self.width - x - (1 if y == self.height-1 else 0), width if width is not None else self.width)
        if width <= 0:
            return
        attributes = (curses.color_pair(color) if self.colors else 0) | (curses.A_BOLD if bold else 0)
        try:
            self.window.addstr(y, x, clip(value, width), attributes)
        except curses.error:
            pass  # A resize may happen between getmaxyx() and writing.

    def panel(self, y, x, h, w, title, rows):
        if h < 3 or w < 4:
            return
        self.put(y, x, '+' + '-' * (w - 2) + '+', DIM, w)
        self.put(y, x + 2, ' ' + title + ' ', AMBER, w - 4, True)
        for i in range(1, h - 1):
            self.put(y+i, x, '|', DIM, 1)
            self.put(y+i, x+w-1, '|', DIM, 1)
        self.put(y+h-1, x, '+' + '-' * (w - 2) + '+', DIM, w)
        for i, item in enumerate(rows[:h-2]):
            text, color = item if isinstance(item, tuple) else (item, WHITE)
            self.put(y+i+1, x+2, text, color, w-4)


def money_rows(data, width):
    wallet = data.get('wallet', {})
    return [(row('DISPONIBLE', wallet.get('available'), width), CYAN),
            row('Unidades mínimas', wallet.get('units'), width),
            row('Sin confirmar', wallet.get('pending'), width),
            row('Inmaduro', wallet.get('immature'), width),
            ('LECTURA ANTERIOR: nodo sin verificar' if data.get('stale') else 'PROVISIONAL: nodo sin sincronizar' if wallet.get('provisional', True) else 'Saldo confirmado por el nodo', AMBER if data.get('stale') or wallet.get('provisional', True) else GREEN),
            ('1 unidad = 0.00000001 RVN', DIM)]


def gpu_rows(data, width):
    t, miner = data.get('telemetry', {}), data.get('miner', {})
    insight = data.get('insight', {})
    return [(row('LOCAL / 10s', rate(t.get('hashrate_10s_hs')), width), CYAN),
            row('Media 60s', rate(t.get('hashrate_60s_hs')), width),
            row('Media 15min', rate(t.get('hashrate_15m_hs')), width),
            (row('GPU / hotspot', unit(t.get('edge_c'), 'C') + ' / ' + unit(t.get('hotspot_c'), 'C'), width), RED if (decimal(t.get('hotspot_c')) or 0) >= 75 else WHITE),
            row('Consumo / fan', unit(t.get('power_w'), 'W') + ' / ' + unit(t.get('fan_rpm'), 'RPM'), width),
            row('Memoria / actividad', unit(t.get('memory_c'), 'C') + ' / ' + unit(t.get('duty_percent'), '%'), width),
            row('Control / fase', insight.get('control', '--') + ' / ' + ('DAG' if t.get('governor_phase') == 'dag' else 'Búsqueda' if t.get('governor_phase') == 'search' else '--'), width),
            row('GPU / PID', str(miner.get('gpu', '--')) + ' / ' + str(miner.get('pid', '--')), width)]


def pool_rows(data, width):
    p, t = data.get('pool', {}), data.get('telemetry', {})
    return [(row('WORKER / 5min', p.get('hashrate'), width), CYAN),
            row('Última share', duration(p.get('last_share_age')) + ' atrás' if p.get('last_share_age') is not None else 'Sin registro reciente', width),
            row('Liquidado', p.get('cleared'), width),
            row('Madurando', p.get('pending'), width),
            row('Umbral pago', p.get('minimum'), width),
            row('Log: acept. / rechaz.', str(t.get('accepted') if t.get('accepted') is not None else '--') + ' / ' + str(t.get('rejected') if t.get('rejected') is not None else '--'), width),
            ('El log puede incluir donación', DIM),
            (row('Consulta pool', duration(p.get('age')) + ' atrás', width), DIM)]


def node_rows(data, width):
    n = data.get('node', {})
    return [(row('CADENA', n.get('status'), width), CYAN),
            row('Progreso', n.get('percent'), width),
            row('Bloques', n.get('blocks'), width),
            row('Cabeceras', n.get('headers'), width),
            row('Conexiones', n.get('connections'), width),
            ('Core / Docker · mainnet RVN', DIM)]


def render(window, raw, history, now, page='overview', scroll=0, colors=True):
    s = Screen(window, colors)
    window.erase()
    data = current(raw, now)
    history.add(data)
    h, w = s.height, s.width
    s.put(0, 0, ' XMRIG / PERSONAL   RVN · KAWPOW · RX 9070 XT', AMBER, max(1,w-22), True)
    s.put(0, max(0,w-20), datetime.fromtimestamp(now).strftime('%d/%m %H:%M:%S'), DIM)
    color = GREEN if data.get('state') == 'working' else RED if data.get('state') == 'warning' else AMBER
    s.put(1, 1, clean(data.get('insight', {}).get('summary', data.get('title', 'SIN DATOS'))).upper(), color, w-2, True)
    s.put(2, 1, '[1] RESUMEN   [2/L] LOGS   [3] MOVIMIENTOS   [4] GUÍA   [R] CONSULTAR   [Q] SALIR', DIM)
    footer = 'Solo lectura · Q cierra la consola, la GPU sigue · Pool cada 60s · Datos cada 5s'
    s.put(h-1, 1, footer, AMBER, w-2)
    if w < 80 or h < 24:
        s.put(4,1,'Amplía la terminal a 80 columnas × 24 filas (ideal: 140 × 40).',AMBER)
        for i, line in enumerate(money_rows(data, max(20,w-4))[:4]):
            text, color = line if isinstance(line,tuple) else (line,WHITE)
            s.put(6+i,1,text,color)
        window.refresh()
        return
    if page == 'logs':
        logs = data.get('logs', [])
        size = h-7
        end = max(0,len(logs)-scroll)
        lines = logs[max(0,end-size):end] or ['Todavía no hay registros.']
        s.panel(4,0,h-5,w,'REGISTRO XMRIG · PgUp/PgDn · puede incluir mensajes anteriores', lines)
    elif page == 'guide':
        insight = data.get('insight', {})
        lines = []
        for label, key in (('AHORA', 'summary'), ('REFRIGERACIÓN', 'thermal'), ('VENTILADORES', 'fan'),
                           ('TRABAJO', 'work'), ('PRUEBA', 'trial'), ('SIGUIENTE PASO', 'next_step'), ('COBROS', 'payment')):
            lines += [(label, CYAN)] + textwrap.wrap(insight.get(key, ''), w-4) + ['']
        lines += textwrap.wrap('DAG: memoria de trabajo que prepara la GPU antes de buscar soluciones. MH/s: millones de intentos por segundo. Share: resultado que valida el pool; no es un pago. Actividad: porcentaje de tiempo permitido por nuestro control, no utilización medida por AMD.', w-4)
        s.panel(4,0,h-5,w,'ESTADO EXPLICADO / PgUp-PgDn',lines[scroll:])
    elif page == 'transactions':
        txs = data.get('transactions', [])
        lines = [('MOVIMIENTOS DE LA BILLETERA / últimas entradas disponibles', AMBER)]
        if not txs:
            lines.append('Sin movimientos disponibles en la lectura del nodo.')
        for tx in txs:
            lines += [(f"{tx.get('category','?').upper()}  {tx.get('amount','--')}  CONF: {tx.get('confirmations','--')}", CYAN),
                      ('TXID ' + tx.get('txid','--'), DIM), '']
        lines += [('Las shares y el saldo del pool todavía no son fondos recibidos.',AMBER)]
        s.panel(4,0,h-5,w,'BILLETERA RVN', lines)
    else:
        insight = data.get('insight', {})
        explanation = []
        for key, color in (('thermal', AMBER), ('fan', AMBER), ('work', WHITE), ('trial', CYAN), ('next_step', GREEN)):
            explanation.extend((line, color) for line in textwrap.wrap(insight.get(key, ''), max(20,w-4)))
        explanation_height = min(len(explanation)+2, 9 if h >= 34 else 8)
        s.panel(4,0,explanation_height,w,'QUÉ ESTÁ PASANDO / SIGUIENTE PASO',explanation)
        top = 4 + explanation_height
        if w >= 132 and h >= 34:
            sizes = [w//3, w//3, w-2*(w//3)]
            x = 0
            for title, maker, size in zip(('01 GPU / LOCAL','02 RAVENMINER / PPLNS','03 BILLETERA / RVN'),
                                          (gpu_rows,pool_rows,money_rows),sizes):
                s.panel(top,x,10,size,title,maker(data,size-4)); x += size
            top += 10
            left = w//2
            s.panel(top,0,8,left,'04 NODO / SINCRONIZACIÓN',node_rows(data,left-4))
            miner=data.get('miner',{})
            session = [('Motor: '+str(miner.get('engine','--')),CYAN),
                       'Worker: '+str(miner.get('worker') or data.get('worker','--')),
                       'Cobro: '+str(data.get('address','--')),
                       'Modo: '+('PRUEBA: 300 s de búsqueda, sin DAG' if miner.get('trial') else 'SESIÓN NORMAL'),
                       'Proceso: '+str(miner.get('process','Sin verificar')),
                       ('Pausa >=80 C / reanuda todos <=60 C',DIM)]
            s.panel(top,left,8,w-left,'05 SESIÓN',session)
            top += 8
        else:
            left = w//2
            s.panel(top,0,9,left,'GPU / LOCAL',gpu_rows(data,left-4))
            s.panel(top,left,9,w-left,'RAVENMINER / PPLNS',pool_rows(data,w-left-4))
            top += 9
            if h-top >= 9:
                s.panel(top,0,8,left,'BILLETERA / RVN',money_rows(data,left-4))
                s.panel(top,left,8,w-left,'NODO',node_rows(data,w-left-4))
                top += 8
        if h-top >= 12:
            left=w//2
            for x,size,title,points in ((0,left,'HISTORIA GPU / media 10s',history.gpu),(left,w-left,'HISTORIA POOL / media 5min',history.pool)):
                graph, bounds = spark(points,size-4)
                s.panel(top,x,5,size,title,[(graph,CYAN),(bounds,DIM),('Muestras recibidas durante esta consola',DIM)])
            top += 5
        messages = [(data.get('insight', {}).get('payment', ''), CYAN)]
        for alert in data.get('alerts', [])[:2]:
            messages.append((alert, AMBER))
        messages += [(line, DIM) for line in data.get('logs', [])[-max(1,h-top-5):]]
        if not messages:
            messages = [('Esperando telemetría y registros del minero.',DIM)]
        if h-top >= 4:
            s.panel(top,0,h-top-1,w,'EVENTOS / [2] VER REGISTRO',messages)
    window.refresh()


def run(reader):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('La consola requiere una terminal interactiva. Para texto: python3 raven.py snapshot')
    poller = Poller(reader)
    poller.start()
    def app(window):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        colors = curses.has_colors()
        if colors:
            curses.start_color()
            try:
                curses.use_default_colors()
                background=-1
            except curses.error:
                background=curses.COLOR_BLACK
            for pair, foreground in ((AMBER,curses.COLOR_YELLOW),(CYAN,curses.COLOR_CYAN),(GREEN,curses.COLOR_GREEN),
                                      (RED,curses.COLOR_RED),(DIM,curses.COLOR_BLUE),(WHITE,curses.COLOR_WHITE)):
                curses.init_pair(pair,foreground,background)
        window.keypad(True)
        window.timeout(250)
        history, page, scroll = History(), 'overview', 0
        while True:
            render(window,poller.get(),history,time.time(),page,scroll,colors)
            key=window.getch()
            if key in (ord('q'),ord('Q'),27): break
            if key in (ord('r'),ord('R')): poller.refresh()
            if key==ord('1'): page,scroll='overview',0
            if key in (ord('2'),ord('l'),ord('L')): page,scroll='logs',0
            if key==ord('3'): page,scroll='transactions',0
            if key==ord('4'): page,scroll='guide',0
            if key==curses.KEY_PPAGE: scroll=min(60,scroll+10)
            if key==curses.KEY_NPAGE: scroll=max(0,scroll-10)
    try:
        curses.wrapper(app)
    except KeyboardInterrupt:
        pass
    finally:
        poller.close()
    print('Consola cerrada. La minería sigue por separado; para detenerla: python3 raven.py mine-stop')
