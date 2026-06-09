#!/usr/bin/env python3
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


SONAR_URL = os.getenv("SONAR_SERVER_URL", "http://sonarqube:9000").rstrip("/")
SONAR_TOKEN = os.getenv("SONAR_TOKEN", "")
PROJECT_KEY = os.getenv("SONAR_PROJECT_KEY", "vuln-app")
GATE_NAME = os.getenv("SONAR_QUALITY_GATE_NAME", "DevSecOps CI Gate")
MIN_COVERAGE = os.getenv("SONAR_MIN_COVERAGE", "70")
REQUIRED_CONDITIONS = {
    "coverage": ("LT", MIN_COVERAGE),
    "duplicated_lines_density": ("GT", "3"),
    "new_maintainability_rating": ("GT", "1"),
    "new_reliability_rating": ("GT", "1"),
    "new_security_rating": ("GT", "1"),
}


def request(method, path, params=None, required=True):
    params = params or {}
    data = None
    url = f"{SONAR_URL}{path}"

    if method == "GET" and params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    elif method == "POST":
        data = urllib.parse.urlencode(params).encode("utf-8")

    req = urllib.request.Request(url, data=data, method=method)
    if SONAR_TOKEN:
        auth = base64.b64encode(f"{SONAR_TOKEN}:".encode("utf-8")).decode("ascii")
        req.add_header("Authorization", f"Basic {auth}")
    if method == "POST":
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if required:
            print(f"Sonar API {method} {path} fallo: HTTP {exc.code} {body}", file=sys.stderr)
            raise
        return {"_error": exc.code, "_body": body}


def get_gate():
    response = request("GET", "/api/qualitygates/show", {"name": GATE_NAME}, required=False)
    if "_error" in response:
        return None
    return response.get("qualityGate") or response


def ensure_gate():
    gate = get_gate()
    if gate:
        return gate
    request("POST", "/api/qualitygates/create", {"name": GATE_NAME})
    gate = get_gate()
    if not gate:
        raise RuntimeError(f"No fue posible crear o consultar el Quality Gate {GATE_NAME}")
    return gate


def condition_exists(gate, metric):
    return any(condition.get("metric") == metric for condition in gate.get("conditions", []) or [])


def condition_matches(condition):
    expected = REQUIRED_CONDITIONS.get(condition.get("metric"))
    if not expected:
        return False
    expected_op, expected_error = expected
    return condition.get("op") == expected_op and str(condition.get("error")) == str(expected_error)


def delete_condition(condition):
    condition_id = condition.get("id")
    if not condition_id:
        print(f"Sonar gate: condicion sin id no eliminada {condition}", file=sys.stderr)
        return
    request("POST", "/api/qualitygates/delete_condition", {"id": str(condition_id)})
    print(
        "Sonar gate: condicion eliminada "
        f"{condition.get('metric')} {condition.get('op')} {condition.get('error')}"
    )


def reconcile_conditions(gate):
    for condition in gate.get("conditions", []) or []:
        if not condition_matches(condition):
            delete_condition(condition)


def add_condition(gate, metric, op, error):
    if condition_exists(gate, metric):
        print(f"Sonar gate: condicion existente {metric}")
        return

    gate_id = str(gate.get("id") or "")
    params = {"metric": metric, "op": op, "error": str(error)}
    if gate_id:
        params["gateId"] = gate_id
        response = request("POST", "/api/qualitygates/create_condition", params, required=False)
        if "_error" not in response:
            print(f"Sonar gate: condicion agregada {metric} {op} {error}")
            return

    params.pop("gateId", None)
    params["gateName"] = GATE_NAME
    response = request("POST", "/api/qualitygates/create_condition", params, required=False)
    if "_error" in response:
        print(
            f"Sonar gate: no se pudo agregar {metric}; respuesta: {response.get('_body', '')}",
            file=sys.stderr,
        )
        raise RuntimeError(f"No se pudo agregar condicion {metric}")
    print(f"Sonar gate: condicion agregada {metric} {op} {error}")


def main():
    if not SONAR_TOKEN:
        print("SONAR_TOKEN no esta configurado", file=sys.stderr)
        return 2

    gate = ensure_gate()
    reconcile_conditions(gate)
    gate = get_gate()
    for metric, (op, error) in REQUIRED_CONDITIONS.items():
        add_condition(gate, metric, op, error)

    request("POST", "/api/qualitygates/select", {"projectKey": PROJECT_KEY, "gateName": GATE_NAME})
    print(f"Sonar gate: {GATE_NAME} asignado a {PROJECT_KEY}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
