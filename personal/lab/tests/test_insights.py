import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from xmrig_personal.insights import explain


def fixture():
    return {'state':'waiting','title':'Prueba','miner':{'process':'Activo','trial':True,'active_seconds':62,'cooling_seconds':138},
            'telemetry':{'governor_state':'cooling','governor_phase':'dag','duty_percent':'0',
                         'edge_c':'57','hotspot_c':'59','memory_c':'78','fan_rpm':'0'},
            'pool':{'fresh':True,'last_share_age':None}}


class InsightTests(unittest.TestCase):
    def test_paused_memory_explains_remaining_degrees_and_trial(self):
        s=explain(fixture())
        self.assertIn('Memoria 78 → 60 °C (bajar 18 °C)',s['thermal'])
        self.assertIn('62/300',s['trial'])
        self.assertIn('238 s activos',s['trial'])
        self.assertIn('2 min 18 s',s['trial'])
        self.assertIn('0 RPM',s['fan'])
        self.assertIn('No se envía trabajo',s['work'])

    def test_preparing_dag_does_not_claim_productive_mining(self):
        d=fixture();d['telemetry'].update(governor_state='running',duty_percent='5')
        self.assertIn('PREPARANDO',explain(d)['summary'])
        self.assertIn('Recibir jobs no confirma shares',explain(d)['work'])

    def test_missing_fan_and_old_pool_are_not_zero_or_no_shares(self):
        d=fixture();d['telemetry']['fan_rpm']=None;d['pool']['fresh']=False
        self.assertIn('sin lectura',explain(d)['fan'])
        self.assertNotIn('Sin share registrada',explain(d)['work'])

    def test_stopped_and_warning_override_thermal_summary(self):
        d=fixture();d['miner']['process']='Detenido';d['title']='Minero detenido'
        self.assertEqual(explain(d)['summary'],'Minero detenido')
        self.assertIn('detenida',explain(d)['trial'])
        d=fixture();d.update(state='warning',title='Bloqueo',detail='Revisar')
        self.assertEqual(explain(d)['summary'],'Bloqueo')
        self.assertEqual(explain(d)['next_step'],'Revisar')

    def test_all_cool_waits_for_governor_not_guessed_resume(self):
        d=fixture();d['telemetry']['memory_c']='60'
        self.assertIn('esperando confirmación',explain(d)['thermal'])
        self.assertIn('ENFRIANDO',explain(d)['summary'])
