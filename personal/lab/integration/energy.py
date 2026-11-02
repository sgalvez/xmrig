"""Whole-card session energy estimates. Never represent these as wall consumption."""
import argparse
import json
import os
from decimal import Decimal, InvalidOperation
from pathlib import Path


def number(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        n = Decimal(str(value))
        return n if n.is_finite() and n >= 0 else None
    except InvalidOperation:
        return None


def tariff(value):
    value = number(value)
    if value is None or not 0 < value <= 100000:
        raise ValueError('Indica una tarifa final positiva en CLP/kWh, incluidos cargos variables e impuestos.')
    return value


def presentation(miner, config):
    result = dict(scope='board', kwh=None, average_w=None, measured_seconds=None,
                  coverage_percent=None, cost_clp=None, tariff_clp_kwh=None,
                  started=miner.get('started'), updated=miner.get('updated'))
    try:
        rate = tariff(config.get('clp_per_kwh'))
        result['tariff_clp_kwh'] = str(rate)
    except (ValueError, AttributeError):
        rate = None
    kwh, seconds, observed = (number(miner.get(key)) for key in
                              ('energy_kwh', 'energy_measured_seconds', 'observed_seconds'))
    if (miner.get('engine') != 'XMRig' or miner.get('energy_scope') != 'board' or
            kwh is None or seconds is None or seconds <= 0 or observed is None or observed <= 0 or
            seconds > observed + 5 or kwh * 3600000 / seconds > 2000):
        return result
    result.update(kwh=f'{kwh:.8f}', average_w=f'{kwh * 3600000 / seconds:.1f}',
                  measured_seconds=f'{seconds:.1f}',
                  coverage_percent=f'{min(Decimal(100), seconds / observed * 100):.1f}',
                  cost_clp=f'{kwh * rate:.4f}' if rate is not None else None)
    return result


def main():
    parser = argparse.ArgumentParser(description='Configura el costo variable final por kWh. No modifica minería ni pagos.')
    parser.add_argument('--clp-per-kwh', required=True, help='CLP/kWh con cargos variables e impuestos; usa punto decimal')
    args = parser.parse_args()
    try:
        value = tariff(args.clp_per_kwh)
    except ValueError as error:
        parser.error(str(error))
    root = Path(__file__).resolve().parent / '.runtime'
    root.mkdir(exist_ok=True, mode=0o700)
    path = root / 'energy-tariff.json'
    temp = root / f'energy-tariff.{os.getpid()}.tmp'
    try:
        with temp.open('x') as f:
            json.dump({'clp_per_kwh': str(value)}, f)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    print(f'Tarifa configurada: {value} CLP/kWh. El costo mostrado corresponde solo a la tarjeta durante los intervalos medidos.')


if __name__ == '__main__':
    main()
