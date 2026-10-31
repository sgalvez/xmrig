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
                          completed=True, started=1000, ended=1300, error=None,
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
