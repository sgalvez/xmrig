"""Exercise the actual policy and pool setters without executing a miner."""
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def patched(path):
    changes = json.loads((ROOT / 'personal-build/hardening/changes.json').read_text())
    return next(c for c in changes if c['path'] == path)['replacements'][0][1]


@unittest.skipUnless(shutil.which('g++'), 'Requires a C++ compiler')
class DonationTests(unittest.TestCase):
    def test_nonzero_and_invalid_inputs_cannot_enable_donation_or_proxy(self):
        pools = patched('src/base/net/stratum/Pools.cpp')
        begin = pools.index('void xmrig::Pools::setDonateLevel(')
        end = pools.index('void xmrig::Pools::setRetries(', begin)
        setters = pools[begin:end]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'policy.cpp'
            binary = Path(directory) / 'test'
            source.write_text('''#include "DonationPolicy.h"
#include <cassert>
#include <limits>
namespace xmrig {
class Pools {
public:
    enum ProxyDonate {PROXY_DONATE_NONE, PROXY_DONATE_AUTO, PROXY_DONATE_ALWAYS};
    double m_donateLevel = 99;
    ProxyDonate m_proxyDonate = PROXY_DONATE_ALWAYS;
    void setDonateLevel(double);
    void setProxyDonate(int);
};
}
''' + setters + '''
int main() {
    xmrig::Pools p;
    for (double value : {0.0, 0.5, 1.0, 99.0, -1.0,
                         std::numeric_limits<double>::quiet_NaN(),
                         std::numeric_limits<double>::infinity()}) {
        p.setDonateLevel(value);
        assert(p.m_donateLevel == 0.0);
        assert(personal::donationMillis(value) == 0);
        assert(personal::normalMillis(value) == 6000000);
    }
    for (int value : {0, 1, 2, -1, 999}) {
        p.setProxyDonate(value);
        assert(p.m_proxyDonate == xmrig::Pools::PROXY_DONATE_NONE);
    }
}
'''.replace('int main()', '#include <initializer_list>\nint main()'))
            subprocess.run(['g++', '-std=c++11', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(ROOT / 'personal-build/hardening'), str(source), '-o', str(binary)],
                           check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, timeout=10)

    def test_engine_has_no_donation_strategy_and_ignores_server_redirection(self):
        cmake = patched('CMakeLists.txt')
        network = patched('src/net/Network.cpp')
        self.assertNotIn('DonateStrategy', cmake)
        self.assertNotIn('m_donate', network)
        self.assertNotIn('DonateStrategy', network)
        client = patched('src/base/net/stratum/Client.cpp')
        redirect = client.split('strcmp(method, "client.reconnect")')[1].split('if (id.IsInt64())')[0]
        self.assertNotIn('setPoolUrl', redirect)
        self.assertNotIn('reconnect()', redirect)
        self.assertIn('return;', redirect)
        self.assertEqual(json.loads(patched('src/config.json'))['pools'], [])


class OutputPrivacyTests(unittest.TestCase):
    def test_ascii_and_utf16_donation_endpoints_fail_without_running_output(self):
        spec = importlib.util.spec_from_file_location('verify_privacy', ROOT / 'personal-build/verify_privacy.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.exe'
            for endpoint in module.FORBIDDEN:
                for data in (endpoint.upper(), endpoint.decode().encode('utf-16le')):
                    path.write_bytes(b'not an executable' + data)
                    with self.assertRaises(ValueError):
                        module.verify(path)

if __name__ == "__main__":
    unittest.main()
