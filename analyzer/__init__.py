"""
analyzer 패키지 — 취약점 판정 진입점
─────────────────────────────────────
executor 결과(execution_results.json) → 취약 판정 → findings.json

Phase 1 (단건 판정)
    - validate_sqli  : Time / Error / Boolean(controls)
    - validate_xss   : 마커 노출 / 페이로드 반사 (HTML 인코딩 가드)
    - validate_bac   : 관리자 경로 비인가 접근

Phase 2 (그룹 분석)
    - detect_boolean_group : 동일 (point, param, url) 묶음에서
      TRUE/FALSE 페이로드 응답 길이 차이로 Boolean SQLi 판정

사용:
    from analyzer import run, validate
    findings = run("results/execution_results.json", "results/findings.json")
"""
from __future__ import annotations

import json
import os

from .sqli_analyzer import validate_sqli, detect_boolean_group
from .xss_analyzer  import validate_xss
from .bac_analyzer  import validate_bac

__all__ = [
    "run", "validate",
    "validate_sqli", "validate_xss", "validate_bac",
    "detect_boolean_group",
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

    # 타입 불명확 → XSS → SQLi 순서로 시도 (BAC 는 형식이 달라 fallback 제외)
    ok, ev = validate_xss(r)
    if ok:
        return True, ev
    return validate_sqli(r)


# ── 메인 진입점 ──────────────────────────────────────────────────
def validate(results: list[dict], progress_callback=None) -> list[dict]:
    """
    executor 결과 리스트 → finding 리스트.
    Phase 1 (단건 분석) + Phase 2 (그룹 Boolean) 결합.
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

    # Phase 2: 그룹 Boolean (단건에서 못 잡은 케이스 보강)
    for item in detect_boolean_group(results):
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
