"""Reject donation endpoints in build output; inspect bytes only, never execute."""
from pathlib import Path
import sys

FORBIDDEN = (b'donate.v2.xmrig.com', b'donate.ssl.xmrig.com', b'benchmark.xmrig.com')


def verify(path):
    data = Path(path).read_bytes().lower()
    for endpoint in FORBIDDEN:
        if endpoint in data or endpoint.decode().encode('utf-16le') in data:
            raise ValueError('Destino no permitido en el ejecutable: ' + endpoint.decode())
    # Structural source/compilation checks complement this limited strings check;
    # absence of literals does not prove absence of all possible network traffic.
    print('No se encontraron destinos de donacion/benchmark en el ejecutable.')


if __name__ == '__main__':
    verify(sys.argv[1])
