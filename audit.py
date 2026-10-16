#!/usr/bin/env python3
"""Limited static YAML security checker: proof of work, not a production scanner."""
import argparse
import json
import re
from pathlib import Path

CHECKS = [
    ('K8S_PRIVILEGED', r'(?m)^\s*privileged:\s*true\s*(?:#.*)?$', 'high', 'Privileged container enabled'),
    ('K8S_ROOT', r'(?m)^\s*runAsNonRoot:\s*false\s*(?:#.*)?$', 'medium', 'Container explicitly permits root'),
    ('K8S_HOST_NETWORK', r'(?m)^\s*hostNetwork:\s*true\s*(?:#.*)?$', 'high', 'Pod shares host network'),
    ('K8S_ALLOW_PRIV_ESC', r'(?m)^\s*allowPrivilegeEscalation:\s*true\s*(?:#.*)?$', 'high', 'Privilege escalation enabled'),
]
ACTION_PATTERN = re.compile(r'(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)')
SHA_PIN = re.compile(r'@[a-fA-F0-9]{40}$')


def scan_text(text, name):
    findings = []
    for code, pattern, severity, message in CHECKS:
        for match in re.finditer(pattern, text):
            findings.append(dict(file=name, line=text.count('\n', 0, match.start()) + 1,
                                 severity=severity, rule=code, message=message))
    if '.github/workflows/' in name.replace('\\', '/') or name.endswith('.workflow.yml'):
        for match in ACTION_PATTERN.finditer(text):
            action = match.group(1).strip('"\'')
            if action.startswith(('./', 'docker://')) or SHA_PIN.search(action):
                continue
            findings.append(dict(file=name, line=text.count('\n', 0, match.start()) + 1,
                                 severity='medium', rule='ACTIONS_UNPINNED',
                                 message='Action not pinned to full commit SHA: ' + action))
    return sorted(findings, key=lambda item: (item['line'], item['rule']))


def scan_path(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    files = [path] if path.is_file() else sorted(
        p for p in path.rglob('*') if p.is_file() and p.suffix.lower() in {'.yml', '.yaml'})
    findings = []
    for file in files:
        try:
            findings.extend(scan_text(file.read_text(encoding='utf-8'), file.as_posix()))
        except UnicodeDecodeError:
            continue
    return {'scanned_files': len(files), 'findings': findings,
            'counts': {severity: sum(f['severity'] == severity for f in findings)
                       for severity in ('high', 'medium')}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Audit selected Kubernetes and CI YAML risks')
    parser.add_argument('path')
    parser.add_argument('--fail-high', action='store_true')
    args = parser.parse_args()
    result = scan_path(args.path)
    print(json.dumps(result, indent=2))
    raise SystemExit(int(args.fail_high and result['counts']['high'] > 0))
