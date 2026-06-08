#!/usr/bin/env python3
import json
import os
import sys
from collections import Counter
from pathlib import Path

FAIL_RISKS = {s.strip().lower() for s in os.getenv("ZAP_FAIL_RISK_LEVELS", "High").split(",") if s.strip()}
RISK_BY_CODE = {"0": "informational", "1": "low", "2": "medium", "3": "high"}


def risk_name(alert):
    raw = str(alert.get("riskdesc") or alert.get("risk") or "").split("(", 1)[0].strip().lower()
    if raw:
        return raw
    return RISK_BY_CODE.get(str(alert.get("riskcode", "")), "unknown")


def iter_alerts(data):
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            yield alert


def main() -> int:
    if len(sys.argv) < 2:
        print("Uso: gate_zap.py <zap-json> [<zap-json> ...]", file=sys.stderr)
        return 2

    failing = []
    totals = Counter()

    for report in sys.argv[1:]:
        path = Path(report)
        if not path.exists():
            print(f"GATE ZAP: falta reporte {path}", file=sys.stderr)
            return 1
        data = json.loads(path.read_text(encoding="utf-8"))
        for alert in iter_alerts(data):
            risk = risk_name(alert)
            totals[risk] += 1
            if risk in FAIL_RISKS:
                failing.append((path.name, risk, alert))

    print(f"GATE ZAP: riesgos evaluados para fallo: {', '.join(sorted(FAIL_RISKS))}")
    print("GATE ZAP: resumen " + ", ".join(f"{k}={v}" for k, v in sorted(totals.items())) if totals else "GATE ZAP: sin alertas")

    if failing:
        print(f"GATE ZAP: FAIL, alertas bloqueantes={len(failing)}", file=sys.stderr)
        for report, risk, alert in failing[:25]:
            print(f"- {report}: {risk.upper()} {alert.get('alert', 'unknown')}", file=sys.stderr)
        if len(failing) > 25:
            print(f"- ... {len(failing) - 25} alertas adicionales", file=sys.stderr)
        return 1

    print("GATE ZAP: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
