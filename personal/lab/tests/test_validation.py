import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from xmrig_personal.validation import COMMIT, POLICY, MINING_PROFILE, ValidationError, confirm, validate_probe
from xmrig_personal.storage import read_json, write_json


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(address='R'+'A'*33, worker='test', pool='stratum.ravenminer.com:13838')
        self.build = dict(engine='XMRig', commit=COMMIT, security_policy=POLICY, sha256='a'*64)
        self.probe = dict(mining_profile=MINING_PROFILE, engine='XMRig', security_policy=POLICY, sha256='a'*64, gpu_id=2, **self.config,
                          completed=True, started=1000, ended=1300, active_seconds=300, cooling_seconds=0, search_seconds=300, preparation_seconds=0,
                          observed_seconds=300, search_started=1000, error=None,
                          probe_worker='probe-'+'b'*20)
        self.pool = {'workers': {'list': [{'name': self.probe['probe_worker'], 'lastShareTime':1250}]}}

    def validate(self):
        return validate_probe(self.config, self.probe, self.build, 2, self.pool, 1320)

    def test_fresh_share_of_unique_probe_worker_validates_exact_build_and_gpu(self):
        result = self.validate()
        self.assertTrue(result['verified'])
        self.assertEqual(result['sha256'], self.build['sha256'])
        self.assertEqual(result['gpu_id'], 2)
        self.assertEqual(result['address'], self.config['address'])

    def test_other_workers_donation_and_old_shares_cannot_validate(self):
        for entry in ({'name':'donate', 'lastShareTime':1250},
                      {'name':'test','lastShareTime':1250},
                      {'name':self.probe['probe_worker'],'lastShareTime':999},
                      {'name':self.probe['probe_worker'],'lastShareTime':1400}):
            with self.subTest(entry=entry):
                self.pool['workers']['list'] = [entry]
                with self.assertRaises(ValidationError): self.validate()

    def test_error_incomplete_or_wrong_identity_never_validates(self):
        original = copy.deepcopy(self.probe)
        for key, value in (('mining_profile','old'),('error','GPU error'),('security_policy','old'),('completed',False),('sha256','b'*64),
                           ('gpu_id',0),('address','R'+'B'*33),('worker','other'),
                           ('pool','other'),('started',1200),('ended',900)):
            with self.subTest(key=key):
                self.probe = {**original,key:value}
                with self.assertRaises(ValidationError): self.validate()

    def test_long_cooling_wait_does_not_consume_trial(self):
        self.probe.update(ended=4900, active_seconds=300, cooling_seconds=3600, observed_seconds=3900)
        result = validate_probe(self.config, self.probe, self.build, 2, self.pool, 4920)
        self.assertTrue(result['verified'])

    def test_pause_only_missing_or_nonfinite_timing_cannot_validate(self):
        original = self.probe.copy()
        for changes in ({'active_seconds':0, 'cooling_seconds':300},
                        {'active_seconds':None}, {'active_seconds':True},
                        {'active_seconds':float('nan')}, {'ended':float('inf')},
                        {'cooling_seconds':-1}, {'cooling_seconds':300}):
            with self.subTest(changes=changes):
                self.probe = {**original, **changes}
                with self.assertRaises(ValidationError): self.validate()

    def test_dag_time_is_separate_from_search_and_validates_fractional_clock(self):
        self.probe.update(ended=1419.4, active_seconds=419.4, preparation_seconds=119.1,
                          search_seconds=300.3, search_started=1119, observed_seconds=419.4)
        result=validate_probe(self.config,self.probe,self.build,2,self.pool,1430)
        self.assertTrue(result['verified'])

    def test_preparation_only_and_legacy_drifting_clock_never_validate(self):
        for changes in ({'preparation_seconds':300,'search_seconds':0},
                        {'ended':1319}, {'search_started':None}, {'observed_seconds':301}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                validate_probe(self.config,{**self.probe,**changes},self.build,2,self.pool,1330)

    def test_invalid_clock_is_not_retried_as_pool_delay(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            write_json(root/'xmrig-probe.json',{**self.probe,'ended':1319})
            write_json(root/'build.json',self.build)
            fetch,sleep=Mock(),Mock()
            with self.assertRaises(ValidationError): confirm(root,self.config,2,root/'build.json',fetch,sleep,lambda:1330)
            fetch.assert_not_called();sleep.assert_not_called()

    def test_only_success_writes_validation_and_no_dashboard_cache_is_used(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            write_json(root/'xmrig-probe.json', self.probe)
            write_json(root/'build.json', self.build)
            fetch=Mock(side_effect=[{'workers':{'list':[]}}, self.pool])
            sleep=Mock()
            confirm(root,self.config,2,root/'build.json',fetch,sleep,lambda:1320)
            self.assertEqual(fetch.call_count,2)
            sleep.assert_called_once_with(15)
            self.assertTrue(read_json(root/'xmrig-validation.json')['verified'])

    def test_failed_pool_never_writes_validation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            write_json(root/'xmrig-probe.json', self.probe)
            write_json(root/'build.json', self.build)
            with self.assertRaises(ValidationError):
                confirm(root,self.config,2,root/'build.json',Mock(side_effect=OSError('offline')),Mock(),lambda:1320)
            self.assertFalse((root/'xmrig-validation.json').exists())
