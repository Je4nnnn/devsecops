#!/usr/bin/env python3
import json
import os
import sys
from collections import Counter
from pathlib import Path

FAIL_SEVERITIES = {s.strip().upper() for s in os.getenv("TRIVY_FAIL_SEVERITIES", "CRITICAL,HIGH").split(",") if s.strip()}
IGNORE_IDS = {s.strip() for s in os.getenv("TRIVY_IGNORE_IDS", "").split(",") if s.strip()}


def iter_findings(data):
    for result in data.get("Results", []) or []:
        target = result.get("Target", "unknown")
        for vuln in result.get("Vulnerabilities", []) or []:
            yield {
                "type": "vulnerability",
                "target": target,
                "id": vuln.get("VulnerabilityID", "unknown"),
                "severity": (vuln.get("Severity") or "UNKNOWN").upper(),
                "package": vuln.get("PkgName", ""),
                "title": vuln.get("Title", ""),
            }
        for misconfig in result.get("Misconfigurations", []) or []:
            yield {
                "type": "misconfiguration",
                "target": target,
                "id": misconfig.get("ID", "unknown"),
                "severity": (misconfig.get("Severity") or "UNKNOWN").upper(),
                "package": misconfig.get("Type", ""),
                "title": misconfig.get("Title", ""),
            }
        for secret in result.get("Secrets", []) or []:
            yield {
                "type": "secret",
                "target": target,
                "id": secret.get("RuleID", "unknown"),
                "severity": (secret.get("Severity") or "UNKNOWN").upper(),
                "package": "",
                "title": secret.get("Title", ""),
            }


def main() -> int:
    if len(sys.argv) < 2:
        print("Uso: gate_trivy.py <reporte-json> [<reporte-json> ...]", file=sys.stderr)
        return 2

    failing = []
    totals = Counter()

    for report in sys.argv[1:]:
        path = Path(report)
        if not path.exists():
            print(f"GATE Trivy: falta reporte {path}", file=sys.stderr)
            return 1
        data = json.loads(path.read_text(encoding="utf-8"))
        for finding in iter_findings(data):
            totals[finding["severity"]] += 1
            if finding["id"] in IGNORE_IDS:
                print(f"GATE Trivy: hallazgo aceptado por excepcion {finding['id']} en {finding['target']}")
                continue
            if finding["severity"] in FAIL_SEVERITIES:
                failing.append((path.name, finding))

    print(f"GATE Trivy: severidades evaluadas para fallo: {', '.join(sorted(FAIL_SEVERITIES))}")
    print("GATE Trivy: resumen " + ", ".join(f"{k}={v}" for k, v in sorted(totals.items())) if totals else "GATE Trivy: sin hallazgos")

    if failing:
        print(f"GATE Trivy: FAIL, hallazgos bloqueantes={len(failing)}", file=sys.stderr)
        for report, finding in failing[:25]:
            print(
                f"- {report}: {finding['severity']} {finding['id']} "
                f"{finding['package']} {finding['target']} {finding['title']}".strip(),
                file=sys.stderr,
            )
        if len(failing) > 25:
            print(f"- ... {len(failing) - 25} hallazgos adicionales", file=sys.stderr)
        return 1

    print("GATE Trivy: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
