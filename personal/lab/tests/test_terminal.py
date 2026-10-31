import copy
import sys
import threading
import unittest
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from xmrig_personal.terminal import History, Poller, clip, current, render, spark


def fixture():
    return {'updated':1000, 'state':'working', 'title':'Trabajo reciente registrado por el pool',
            'detail':'Datos sintéticos para pruebas, no minería real.',
            'miner':{'engine':'XMRig 6.26.0','process':'Activo','gpu':'2','pid':'1234','uptime':345,'trial':False,'worker':'test-worker'},
            'telemetry':{'hashrate_10s_hs':'35000000','hashrate_60s_hs':'34500000','hashrate_15m_hs':None,
                         'edge_c':'55','hotspot_c':'65','memory_c':None,
                         'governor_state':'running','governor_phase':'search','duty_percent':'25','governor_time':998,
                         'temperature':'65','power_w':'220','fan_rpm':'1800','core_mhz':'2100','memory_mhz':'1400',
                         'sample_time':995,'sensor_time':998,'accepted':'12','rejected':'0'},
            'pool':{'hashrate':'34.000000 MH/s','hashrate_hs':'34000000','sample_time':990,
                    'last_share_age':8,'age':10,'cleared':'0.000000000001 RVN','pending':'0.002000000000 RVN','minimum':'10.00000000 RVN'},
            'wallet':{'available':'0.00000001 RVN','units':'1','pending':'0.00000000 RVN','immature':'0.00000000 RVN','provisional':False},
            'node':{'status':'Sincronizado','percent':'100.0000000000%','blocks':'4000000','headers':'4000000','connections':'8'},
            'address':'R'+'A'*33,'worker':'test-worker', 'alerts':[],
            'logs':['[TEST] opencl accepted (12/0)', '[TEST] No representan actividad real'],
            'transactions':[{'category':'receive','amount':'0.00000001 RVN','confirmations':'3','txid':'a'*64}]}


class Canvas:
    def __init__(self,height,width):
        self.height,self.width=height,width
        self.erase()
    def getmaxyx(self): return self.height,self.width
    def erase(self): self.rows=[[' ']*self.width for _ in range(self.height)]
    def refresh(self): pass
    def addstr(self,y,x,text,attributes):
        for char in text:
            size=0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in 'WF' else 1
            if x+size>self.width or y>=self.height: raise AssertionError('Canvas overflow')
            if size: self.rows[y][x]=char
            x+=size
    def text(self): return '\n'.join(''.join(row) for row in self.rows)


class TerminalTests(unittest.TestCase):
    def test_render_at_small_and_large_sizes_and_all_pages(self):
        for h,w in ((15,60),(24,80),(30,100),(40,140),(50,200)):
            for page in ('overview','logs','transactions'):
                with self.subTest(size=(h,w),page=page):
                    canvas=Canvas(h,w)
                    render(canvas,fixture(),History(),1000,page,colors=False)
                    self.assertIn('XMRIG',canvas.text())

    def test_precision_and_distinct_gpu_pool_wallet_metrics(self):
        canvas=Canvas(40,140)
        render(canvas,fixture(),History(),1000,colors=False)
        text=canvas.text()
        for expected in ('35.000000 MH/s','34.000000 MH/s','0.000000000001 RVN','0.00000001 RVN','65 C','220 W','25 %','running / search'):
            self.assertIn(expected,text)

    def test_elapsed_time_removes_live_metrics_without_new_snapshot(self):
        source=fixture()
        recent=current(source,1031)
        self.assertIsNone(recent['telemetry']['hashrate_10s_hs'])
        self.assertIsNone(recent['telemetry']['temperature'])
        self.assertIsNone(recent['telemetry']['hotspot_c'])
        self.assertIsNone(recent['telemetry']['duty_percent'])
        self.assertIsNone(recent['telemetry']['governor_state'])
        old=current(source,1100)
        self.assertEqual(old['state'],'warning')
        self.assertEqual(old['miner']['process'],'Sin verificar')
        self.assertEqual(old['telemetry'],{})
        self.assertIsNone(old['pool']['hashrate'])
        self.assertEqual(source['state'],'working') # Rendering does not mutate shared input.

    def test_history_deduplicates_cached_samples_and_preserves_zero(self):
        h=History()
        data=fixture()
        for _ in range(5): h.add(data)
        self.assertEqual(len(h.pool),1)
        self.assertEqual(len(h.gpu),1)
        data['telemetry'].update(sample_time=1005,hashrate_10s_hs='0')
        h.add(data)
        self.assertEqual(len(h.gpu),2)
        self.assertIn('0.000000 MH/s',spark(h.gpu,40)[1])
        h.add(current(data,1200))
        self.assertEqual(len(h.gpu),2)

    def test_untrusted_terminal_control_sequences_are_not_printed(self):
        self.assertEqual(clip('\x1b[2Jsecret\x07',20),'secret')
        self.assertEqual(clip('界界x',3),'界')

    def test_one_pending_reader_does_not_block_ui_access(self):
        entered,release=threading.Event(),threading.Event()
        calls=[]
        def reader():
            calls.append(1); entered.set(); release.wait(2)
            return fixture()
        p=Poller(reader)
        p.start()
        try:
            self.assertTrue(entered.wait(1))
            p.refresh(); p.refresh()
            self.assertTrue(p.get()['loading'])
            self.assertEqual(len(calls),1)
        finally:
            p.close(); release.set(); p.thread.join(2)
        self.assertFalse(p.thread.is_alive())
