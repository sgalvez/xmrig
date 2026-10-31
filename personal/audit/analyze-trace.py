"""Stream a Procmon CSV; summarize evidence, never produce an antivirus verdict."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import ntpath
from pathlib import Path
import re


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    text = path.read_text(encoding='utf-8-sig')
    return json.loads(text) if text.strip() else None


def summarize(rows, result):
    roots = {str(p['pid']) for p in result.get('phases', []) if p.get('pid') is not None}
    sample = ('C:\\XmrigAudit\\' + result['run_id'] + '\\input\\xmrig.exe').lower()
    active, seen = {}, set()
    counts, writes, registry, modules, network = (Counter() for _ in range(5))
    children, exits, sensitive = [], [], []
    count = 0
    for row in rows:
        count += 1
        pid, name, op, path = (row[k] for k in ('PID', 'Process Name', 'Operation', 'Path'))
        name = name.lower()
        if op == 'Process Start':
            # Procmon 4.x places the command line in Detail and leaves Path empty.
            command = re.search(r'Command line: (?:"([^"]+)"|([^ ,]+))', row['Detail'])
            executable = (command.group(1) or command.group(2)) if command else path
            if pid in roots and name == 'xmrig.exe' and executable.lower() == sample:
                active[pid] = name
                seen.add(pid)
            elif active.get(pid) != name:
                active.pop(pid, None)  # Do not follow a reused PID.
        if active.get(pid) != name:
            continue
        counts[op] += 1
        detail, status = row['Detail'], row['Result']
        if op == 'Process Create' and status == 'SUCCESS':
            match = re.search(r'\bPID: (\d+)', detail)
            children.append({'parent_pid': pid, 'path': path, 'detail': detail})
            if match:
                active[match[1]] = ntpath.basename(path).lower()
        if op == 'Process Exit':
            exits.append({'pid': pid, 'name': name, 'detail': detail})
            active.pop(pid, None)
        if op.startswith(('TCP ', 'UDP ')):
            network[(op, path, status)] += 1
        if op == 'Load Image':
            modules[path] += 1
        if op in ('WriteFile', 'SetDispositionInformationFile', 'SetRenameInformationFile'):
            writes[(op, path, status)] += 1
        if op in ('RegSetValue', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue', 'RegRenameKey'):
            registry[(op, path, status)] += 1
        lower = path.lower()
        # Leads for manual review, including unsuccessful reads. Not malware labels.
        if any(marker in lower for marker in ('\\login data', '\\wallet.dat', '\\credentials\\',
                 '\\windows\\system32\\config\\sam', '\\windows\\system32\\config\\security')):
            sensitive.append({k: row[k] for k in ('PID', 'Operation', 'Path', 'Result', 'Detail')})
    def records(counter):
        return [{'operation': op, 'path': path, 'result': status, 'count': n}
                for (op, path, status), n in sorted(counter.items())]
    return {'total_rows': count, 'expected_sample_pids': sorted(roots), 'observed_sample_pids': sorted(seen),
            'unobserved_sample_pids': sorted(roots - seen),
            'operations': dict(counts), 'children': children, 'exits': exits, 'network_events': records(network),
            'file_mutations': records(writes), 'registry_mutations': records(registry),
            'loaded_images': dict(modules), 'sensitive_path_leads': sensitive,
            'scope': 'sample processes and observed descendants; OS work can be attributed to their process context',
            'verdict': 'not_assessed'}


def environment_delta(directory, kind, keys, fields):
    before, after = (load(directory / f'{phase}-{kind}.json') for phase in ('before', 'after'))
    def indexed(items):
        if items is None:
            return {}
        if isinstance(items, dict):
            items = [items]
        return {tuple(str(item.get(k)) for k in keys): {k: item.get(k) for k in fields} for item in items}
    before, after = indexed(before), indexed(after)
    return [{'key': list(k), 'before': before.get(k), 'after': after.get(k)}
            for k in sorted(before.keys() | after.keys()) if before.get(k) != after.get(k)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output_directory', type=Path)
    args = parser.parse_args()
    directory = args.output_directory
    result = load(directory / 'result.json')
    with (directory / 'trace.csv').open(encoding='utf-8-sig', newline='') as stream:
        summary = summarize(csv.DictReader(stream), result)
    summary.update(run_id=result['run_id'], sample_sha256=result['sample_sha256'],
                   trace_sha256=sha256(directory / 'trace.csv'), result_sha256=sha256(directory / 'result.json'),
                   defender_after=load(directory / 'after-defender.json'))
    summary['environment_changes'] = {
        'services': environment_delta(directory, 'services', ('Name',), ('Name', 'StartMode', 'PathName')),
        'tasks': environment_delta(directory, 'tasks', ('TaskPath', 'TaskName'), ('TaskPath', 'TaskName')),
        'autorun': environment_delta(directory, 'autorun', ('path',), ('path', 'value'))}
    summary['limitations'] = [
        'No external network/cloud reputation or physical GPU. Unreached paths remain untested.',
        'Scheduled-task comparison detects added/removed names, not modifications of task actions.',
        'Registry writes in BAM and NTFS metadata writes may be OS bookkeeping, not persistence.',
        'An elevated sample could tamper with its guest observer. This is not independent certification.']
    target = directory.parent / 'trace-summary.json'
    target.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'summary': str(target), 'rows': summary['total_rows'],
                      'sample_processes': len(summary['observed_sample_pids']),
                      'children': len(summary['children']), 'verdict': summary['verdict']}))


if __name__ == '__main__':
    main()
