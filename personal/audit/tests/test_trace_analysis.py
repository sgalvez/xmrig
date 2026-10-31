import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('trace_analysis',Path(__file__).resolve().parents[1]/'analyze-trace.py')
analysis=importlib.util.module_from_spec(spec);spec.loader.exec_module(analysis)


class TraceTests(unittest.TestCase):
    def test_process_scope_children_pid_reuse_and_unsuccessful_access(self):
        def row(pid,name,op,path='',detail='',status='SUCCESS'):
            return dict(zip(('PID','Process Name','Operation','Path','Detail','Result'),(pid,name,op,path,detail,status)))
        rows=[row('1','xmrig.exe','Process Start',detail='Parent PID: 42, Command line: "C:\\XmrigAudit\\abc\\input\\xmrig.exe" --help, Current directory: C:\\fixture'),
              row('1','xmrig.exe','Process Create','C:\\Windows\\System32\\conhost.exe','PID: 2, Command line: conhost'),
              row('2','conhost.exe','Process Start','C:\\Windows\\System32\\conhost.exe'),
              row('1','xmrig.exe','CreateFile','C:\\Users\\x\\Login Data',status='ACCESS DENIED'),
              row('2','conhost.exe','WriteFile','C:\\console.log'),
              row('1','xmrig.exe','TCP Connect','local -> remote',status='TIMEOUT'),
              row('1','xmrig.exe','Process Exit',detail='Exit Status: 2'),
              row('1','unrelated.exe','Process Start','C:\\unrelated.exe'),
              row('1','unrelated.exe','WriteFile','C:\\unrelated.log')]
        summary=analysis.summarize(rows,{'run_id':'abc','phases':[{'pid':1}]})
        self.assertEqual(summary['operations']['WriteFile'],1)
        self.assertEqual(summary['sensitive_path_leads'][0]['Result'],'ACCESS DENIED')
        self.assertEqual(summary['network_events'][0]['result'],'TIMEOUT')
        self.assertEqual(summary['verdict'],'not_assessed')

    def test_no_executed_sample_is_not_a_clean_verdict(self):
        summary=analysis.summarize([],{'run_id':'empty','phases':[]})
        self.assertEqual(summary['observed_sample_pids'],[])
        self.assertEqual(summary['verdict'],'not_assessed')


if __name__=='__main__': unittest.main()
