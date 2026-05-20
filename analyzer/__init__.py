from __future__ import annotations

import json
import os

from .sqli_analyzer import (
    validate_sqli,
    detect_boolean_group,
    detect_orderby_group,
)
from .xss_analyzer  import validate_xss
from .bac_analyzer  import validate_bac, detect_bac_group

__all__ = [
    "run", "validate",
    "validate_sqli", "validate_xss", "validate_bac",
    "detect_boolean_group", "detect_orderby_group", "detect_bac_group",
]


# ── 헬퍼 ─────────────────────────────────────────────────────────
def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


def _make_finding(r: dict, evidence: str) -> dict:
    meta = r.get("meta") or {}
    return {
        "id":          r.get("id"),
        "point":       r.get("point"),
        "url":         r.get("url"),
        "method":      r.get("method"),
        "param":       r.get("inject_param"),
        "payload":     r.get("payload") or "",
        "inject_mode": r.get("inject_mode"),
        "vuln_type":   meta.get("vuln_type"),
        "role":        meta.get("role"),   # ← BAC 결과 보고서에서 사용
        "status":      r.get("status"),
        "elapsed":     r.get("elapsed") or 0.0,
        "evidence":    evidence,
    }


# ── Phase 1: 단건 판정 라우팅 ────────────────────────────────────
def _validate_single(r: dict) -> tuple[bool, str]:
    """vuln_type 키워드 보고 적절한 단건 analyzer 로 라우팅."""
    vt = _vuln_type(r)
    if "xss" in vt:
        return validate_xss(r)
    if "sqli" in vt or "sql" in vt:
        return validate_sqli(r)
    if "bac" in vt or "broken_access" in vt or "auth" in vt:
        return validate_bac(r)

    # 타입 불명확 → XSS → SQLi 순서로 시도 (BAC는 형식이 달라 fallback 제외)
    ok, ev = validate_xss(r)
    if ok:
        return True, ev
    return validate_sqli(r)


# ── 메인 진입점 ──────────────────────────────────────────────────
def validate(results: list[dict], progress_callback=None) -> list[dict]:
    """
    executor 결과 리스트 → finding 리스트.
    Phase 1 (단건 분석) + Phase 2 (그룹 분석) 결합.
    """
    findings: list[dict] = []
    found_ids: set = set()
    total = len(results)

    # Phase 1: 단건 검사
    for idx, r in enumerate(results):
        if progress_callback:
            progress_callback(idx + 1, total)

        if r.get("error") or not r.get("response_body"):
            continue

        ok, evidence = _validate_single(r)
        if ok:
            findings.append(_make_finding(r, evidence))
            found_ids.add(r.get("id"))

    # Phase 2: 그룹 분석 (단건에서 못 잡은 케이스 보강)
    group_detectors = [
        detect_boolean_group,
        detect_orderby_group,   # 신규
        detect_bac_group,       # 신규
    ]

    for detector in group_detectors:
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
    """파일 입출력 진입점 — tasks.py 가 호출."""
    with open(input_file, encoding="utf-8") as f:
        results = json.load(f)

    findings = validate(results, progress_callback=progress_callback)

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    return findings