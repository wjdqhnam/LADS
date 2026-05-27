from __future__ import annotations

import json
import os

from .sqli_analyzer import validate_sqli, detect_boolean_group, detect_orderby_group, detect_probe_group
from .xss_analyzer  import validate_xss
from .bac_analyzer  import validate_bac, detect_bac_group
from findings import (
    make_finding,
    MODULE_XSS, MODULE_SQLI, MODULE_BAC,
    XSS_CONFIRMED, SQLI_CONFIRMED, BAC_SUSPECTED_MEDIUM,
    HIGH,
)

__all__ = [
    "run", "validate",
    "validate_sqli", "validate_xss", "validate_bac",
    "detect_boolean_group", "detect_orderby_group", "detect_probe_group", "detect_bac_group",
]


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


def _derive_module_type(vt: str) -> tuple[str, str]:
    if "xss" in vt:
        return MODULE_XSS, XSS_CONFIRMED
    if "sqli" in vt or "sql" in vt:
        return MODULE_SQLI, SQLI_CONFIRMED
    if "bac" in vt or "broken_access" in vt or "auth" in vt:
        return MODULE_BAC, BAC_SUSPECTED_MEDIUM
    return MODULE_XSS, XSS_CONFIRMED


def _derive_category(vt: str, evidence: str) -> str:
    ev = evidence.lower()
    if "time" in ev:
        return "time_based"
    if "error" in ev or "db 에러" in ev:
        return "error_based"
    if "boolean" in ev:
        return "boolean"
    if any(x in vt for x in ("subject", "content", "comment")):
        return "stored"
    if "search" in vt or "reflected" in vt:
        return "reflected"
    return "unknown"


def _make_finding(r: dict, evidence: str) -> dict:
    meta = r.get("meta") or {}
    vt   = (meta.get("vuln_type") or "").lower()
    module, type_ = _derive_module_type(vt)
    category      = _derive_category(vt, evidence)

    f = make_finding(
        module=module,
        type=type_,
        category=category,
        url=r.get("url") or "",
        param=r.get("inject_param"),
        payload=r.get("payload") or "",
        status=r.get("status"),
        confidence=HIGH,
        evidence=evidence,
    )
    f["id"]          = r.get("id")
    f["point"]       = r.get("point")
    f["inject_mode"] = r.get("inject_mode")
    f["elapsed"]     = r.get("elapsed") or 0.0
    f["role"]        = meta.get("role")
    return f


def _validate_single(r: dict) -> tuple[bool, str]:
    vt = _vuln_type(r)
    if "xss" in vt:
        return validate_xss(r)
    if "sqli" in vt or "sql" in vt:
        return validate_sqli(r)
    if "bac" in vt or "broken_access" in vt or "auth" in vt:
        return validate_bac(r)

    ok, ev = validate_xss(r)
    if ok:
        return True, ev
    return validate_sqli(r)


def validate(results: list[dict], progress_callback=None) -> list[dict]:
    findings: list[dict] = []
    found_ids: set = set()
    total = len(results)

    for idx, r in enumerate(results):
        if progress_callback:
            progress_callback(idx + 1, total)
        if r.get("error") or not r.get("response_body"):
            continue
        ok, evidence = _validate_single(r)
        if ok:
            findings.append(_make_finding(r, evidence))
            found_ids.add(r.get("id"))

    # Phase 2: 그룹 분석
    for detector in [detect_boolean_group, detect_probe_group, detect_orderby_group, detect_bac_group]:
        for item in detector(results):
            r        = item["result"]
            evidence = item["evidence"]
            if r.get("id") in found_ids:
                continue
            findings.append(_make_finding(r, evidence))
            found_ids.add(r.get("id"))

    return findings


def run(
    input_file:  str = "results/execution_results.json",
    output_file: str = "results/findings.json",
    progress_callback=None,
) -> list[dict]:
    with open(input_file, encoding="utf-8") as f:
        results = json.load(f)

    findings = validate(results, progress_callback=progress_callback)

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    return findings
