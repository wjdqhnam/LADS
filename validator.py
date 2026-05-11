"""
Validator
─────────
executor 결과(execution_results.json) -> 취약 판정 -> findings 저장

역할 분리:
    Phase 1 (단건 판정)  → analyzer 모듈에 위임
        - error-based / time-based SQLi  → analyzer.sqli_analyzer
        - XSS 마커 / 페이로드 반사       → analyzer.xss_analyzer
    Phase 2 (그룹 분석)  → 본 모듈에서 직접 처리
        - Boolean SQLi: 동일 (point, param, url) 그룹 내
          TRUE/FALSE 페이로드 응답 길이 차이 ≥ 5% 이면 취약 판정

analyzer 와 마커/패턴 중복을 없애기 위해 단건 로직은 들고 있지 않다.
"""
from __future__ import annotations

import json
import os
import re
from collections import defaultdict

from analyzer.sqli_analyzer import validate_sqli
from analyzer.xss_analyzer  import validate_xss

# ── Boolean SQLi 그룹 분석 설정 ──────────────────────────────────
_BOOL_TRUE = re.compile(
    r"1=1|'1'\s*=\s*'1'|OR\s+1\b|OR\(1=1\)|AND\(1=1\)|or_true|and_true|paren_true",
    re.IGNORECASE,
)
_BOOL_FALSE = re.compile(
    r"1=2|'1'\s*=\s*'2'|AND\s+1=2|AND\(1=2\)|paren_false|and_false",
    re.IGNORECASE,
)
_BOOL_DIFF_THRESHOLD = 0.05   # 응답 길이 차이 임계값 (5%)


# ── 헬퍼 ─────────────────────────────────────────────────────────
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


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


# ── Phase 2: Boolean SQLi 그룹 분석 ──────────────────────────────
def _detect_boolean(results: list[dict]) -> list[dict]:
    """
    같은 (point, inject_param, url) 그룹 내에서
    TRUE/FALSE 조건 페이로드의 응답 길이를 비교해 Boolean SQLi 판정.
    """
    sqli_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r))
    ]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in sqli_results:
        key = (r.get("point"), r.get("inject_param"), r.get("url"))
        groups[key].append(r)

    findings: list[dict] = []

    for _key, group in groups.items():
        true_items, false_items = [], []
        for r in group:
            payload = r.get("payload") or ""
            if _BOOL_TRUE.search(payload):
                true_items.append(r)
            elif _BOOL_FALSE.search(payload):
                false_items.append(r)

        if not true_items or not false_items:
            continue

        avg_true  = sum(len(r["response_body"]) for r in true_items)  / len(true_items)
        avg_false = sum(len(r["response_body"]) for r in false_items) / len(false_items)
        max_len   = max(avg_true, avg_false, 1)
        diff      = abs(avg_true - avg_false) / max_len

        if diff < _BOOL_DIFF_THRESHOLD:
            continue

        direction = "true>false" if avg_true > avg_false else "true<false"
        evidence = (
            f"boolean_sqli: true_len={avg_true:.0f}, false_len={avg_false:.0f}, "
            f"diff={diff:.1%} ({direction})"
        )

        best = max(true_items, key=lambda r: len(r["response_body"]))
        findings.append(_make_finding(best, evidence))

    return findings


# ── Phase 1: 단건 판정 (analyzer 위임) ───────────────────────────
def _validate_single(r: dict) -> tuple[bool, str]:
    """vuln_type 에 따라 analyzer 함수로 라우팅."""
    vt = _vuln_type(r)
    if "xss" in vt:
        return validate_xss(r)
    if "sqli" in vt or "sql" in vt:
        return validate_sqli(r)
    # 타입 불명확 → XSS → SQLi 순으로 시도
    ok, ev = validate_xss(r)
    if ok:
        return True, ev
    return validate_sqli(r)


# ── 메인 진입점 ──────────────────────────────────────────────────
def validate(results: list[dict], progress_callback=None) -> list[dict]:
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

    # Phase 2: 그룹 boolean (단건에서 안 잡힌 케이스 보강)
    for bf in _detect_boolean(results):
        if bf["id"] not in found_ids:
            findings.append(bf)
            found_ids.add(bf["id"])

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