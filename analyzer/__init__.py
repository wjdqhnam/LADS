from __future__ import annotations

from .sqli_analyzer import validate_sqli, detect_boolean_group, detect_orderby_group, detect_probe_group
from .xss_analyzer  import validate_xss
from .bac_analyzer  import validate_bac, detect_bac_group
from utilities import load_json, save_json
from findings import (
    make_finding,
    sqli_finding_from_verdict,
    MODULE_XSS, MODULE_SQLI, MODULE_BAC,
    XSS_VERIFIED, XSS_REFLECTED, XSS_STORED_REFLECTED, XSS_SUSPICIOUS,
    SQLI_CONFIRMED, SQLI_SUSPECTED, SQLI_CANDIDATE, BAC_SUSPECTED_MEDIUM,
    HIGH, MEDIUM, LOW,
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
        return MODULE_XSS, XSS_REFLECTED
    if "sqli" in vt or "sql" in vt:
        return MODULE_SQLI, SQLI_CANDIDATE
    if "bac" in vt or "broken_access" in vt or "auth" in vt:
        return MODULE_BAC, BAC_SUSPECTED_MEDIUM
    return MODULE_XSS, XSS_SUSPICIOUS


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


def _derive_sqli_type_confidence(evidence: str) -> tuple[str, str]:
    ev = evidence.lower()
    if "candidate" in ev:
        return SQLI_CANDIDATE, LOW
    if "suspected" in ev:
        return SQLI_SUSPECTED, MEDIUM
    if "(confirmed)" in ev or "union-based" in ev:
        return SQLI_CONFIRMED, HIGH
    if "time-based" in ev or "error-based" in ev:
        return SQLI_SUSPECTED, MEDIUM
    return SQLI_CANDIDATE, LOW


def _derive_xss_type_confidence(r: dict, evidence: str) -> tuple[str, str]:
    ev = evidence.lower()
    context = ((r.get("xss_context") or "")).lower()
    safe_contexts = ("textarea", "title", "comment", "style", "noscript", "safe_tag")

    if "verified" in ev or "playwright" in ev:
        return XSS_VERIFIED, HIGH
    if any(ctx in context for ctx in safe_contexts):
        return XSS_SUSPICIOUS, LOW
    if "payload" in ev or "페이로드" in ev:
        return XSS_REFLECTED, MEDIUM
    if "marker" in ev or "마커" in ev:
        return XSS_REFLECTED, MEDIUM
    return XSS_SUSPICIOUS, LOW


def _derive_type_confidence(module: str, type_: str, r: dict, evidence: str) -> tuple[str, str]:
    if module == MODULE_SQLI:
        return _derive_sqli_type_confidence(evidence)
    if module == MODULE_XSS:
        return _derive_xss_type_confidence(r, evidence)
    return type_, HIGH


def _make_finding(r: dict, evidence: str) -> dict:
    meta = r.get("meta") or {}
    vt   = (meta.get("vuln_type") or "").lower()
    module, type_ = _derive_module_type(vt)
    category      = _derive_category(vt, evidence)
    type_, confidence = _derive_type_confidence(module, type_, r, evidence)

    f = make_finding(
        module=module,
        type=type_,
        category=category,
        url=r.get("url") or "",
        param=r.get("inject_param"),
        payload=r.get("payload") or "",
        status=r.get("status"),
        confidence=confidence,
        evidence=evidence,
    )
    f["id"]          = r.get("id")
    f["point"]       = r.get("point")
    f["task_group_id"] = r.get("task_group_id")
    f["inject_mode"] = r.get("inject_mode")
    f["elapsed"]     = r.get("elapsed") or 0.0
    f["role"]        = meta.get("role")
    return f


def _validate_single(r: dict) -> tuple[bool, str]:
    vt = _vuln_type(r)
    if "xss" in vt:
        found, ev, *_ = validate_xss(r)
        return found, ev
    if "sqli" in vt or "sql" in vt:
        return validate_sqli(r)
    if "bac" in vt or "broken_access" in vt or "auth" in vt:
        return validate_bac(r)

    found, ev, *_ = validate_xss(r)
    if found:
        return True, ev
    return validate_sqli(r)


_XSS_TYPE_CATEGORY = {
    XSS_VERIFIED:         "verified",
    XSS_REFLECTED:        "reflected",
    XSS_STORED_REFLECTED: "stored",
    XSS_SUSPICIOUS:       "suspicious",
}


def _handle_xss(raw: tuple, r: dict, rid: str | None, findings: list[dict], found_ids: set) -> None:
    if rid in found_ids:
        return
    if not isinstance(raw, tuple) or not raw[0]:
        return
    evidence   = raw[1]
    xss_type   = raw[2]
    confidence = raw[3]
    xss_extra  = raw[4] if len(raw) > 4 else {}

    meta     = r.get("meta") or {}
    category = _XSS_TYPE_CATEGORY.get(xss_type, "unknown")

    f = make_finding(
        module=MODULE_XSS,
        type=xss_type,
        category=category,
        url=r.get("url") or "",
        param=r.get("inject_param"),
        payload=r.get("payload") or "",
        status=r.get("status"),
        confidence=confidence,
        evidence=evidence,
        extra=xss_extra or None,
    )
    f["id"]            = r.get("id")
    f["point"]         = r.get("point")
    f["task_group_id"] = r.get("task_group_id")
    f["inject_mode"]   = r.get("inject_mode")
    f["elapsed"]       = r.get("elapsed") or 0.0
    f["role"]          = meta.get("role")
    findings.append(f)
    if rid:
        found_ids.add(rid)


def _handle_sqli(raw, r: dict, rid: str | None, findings: list[dict], found_ids: set) -> None:
    if rid in found_ids:
        return
    if isinstance(raw, dict):
        finding = sqli_finding_from_verdict(raw)
        if finding:
            findings.append(finding)
            if rid:
                found_ids.add(rid)
    elif isinstance(raw, tuple) and raw[0]:
        findings.append(_make_finding(r, raw[1]))
        if rid:
            found_ids.add(rid)


def validate(results: list[dict], progress_callback=None) -> list[dict]:
    findings: list[dict] = []
    found_ids: set = set()
    total = len(results)

    for idx, r in enumerate(results):
        if progress_callback:
            progress_callback(idx + 1, total)
        if r.get("error") or not r.get("response_body"):
            continue

        vt = _vuln_type(r)
        if "sqli" in vt or "sql" in vt:
            _handle_sqli(validate_sqli(r), r, r.get("id"), findings, found_ids)
        elif "xss" in vt:
            _handle_xss(validate_xss(r), r, r.get("id"), findings, found_ids)
        else:
            ok, evidence = _validate_single(r)
            if ok:
                findings.append(_make_finding(r, evidence))
                found_ids.add(r.get("id"))

    for detector in [detect_boolean_group, detect_probe_group, detect_orderby_group, detect_bac_group]:
        for item in detector(results):
            if isinstance(item, dict) and "verdict" in item:
                _handle_sqli(item, item, item.get("id"), findings, found_ids)
                continue
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
    results = load_json(input_file, [])

    findings = validate(results, progress_callback=progress_callback)

    save_json(output_file, findings)

    return findings
