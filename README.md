# Deployment Guard

Small Python proof of work for selected Kubernetes and GitHub Actions security configuration checks. Built independently as a backend/DevSecOps demonstration, **not an audit of FractalBox's systems**.

## Run

```sh
python3 audit.py examples --fail-high
python3 -m unittest discover -v
```

The example files are intentionally insecure. The CLI prints JSON findings and exits with code 1 on high-severity findings when `--fail-high` is passed.

## Scope

- Kubernetes: `privileged: true`, `hostNetwork: true`, `allowPrivilegeEscalation: true`, `runAsNonRoot: false`
- GitHub Actions: external `uses:` entries not pinned to a 40-character commit SHA
- Sample CI workflow running unit tests and a demonstration scan

## Limitations

**Prototype, not a production security gate.** Regex-based line matching cannot interpret YAML structure, aliases, templates or inherited configuration, and may have false positives and false negatives. Production systems should use structural YAML parsing, contextual policies, policy-as-code tools (e.g., KubeLinter/Checkov), and actionlint. No third-party infrastructure is scanned.
