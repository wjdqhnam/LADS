"""
SQLi Analyzer
─────────────
단건 판정 (validate_sqli) + 그룹 단위 Boolean 판정 (detect_boolean_group)

단건:
    Time-based  : elapsed >= SLEEP_THRESHOLD
    Error-based : 응답 본문에 DB 에러 시그니처 노출
    Boolean(단건): test_result.controls 가 있는 경우 (true_len/false_len 비교)

그룹:
    Boolean(그룹): 같은 (point, inject_param, url) 묶음에서
                   TRUE/FALSE 페이로드 응답 길이 차이 >= 5% 이면 취약

이전 validator.py 의 _detect_boolean / _MYSQL_ERRORS 로직 흡수.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

# ── 공통 임계치 ──────────────────────────────────────────────────
SLEEP_THRESHOLD       = 4.5    # Time-based 판정 (초)
BOOL_SIGNAL_MIN       = 0.05   # 단건 Boolean(controls 기반) 신호 강도 (5%)
BOOL_GROUP_THRESHOLD  = 0.05   # 그룹 Boolean 응답 길이 차이 임계값 (5%)

# ── DB 에러 시그니처 ──────────────────────────────────────────────
DB_ERROR_KEYWORDS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "xpath syntax error",
    "extractvalue(",
    "updatexml(",
    "duplicate entry",
    "column count doesn't match",
    "the used select statements have a different number",
    "supplied argument is not a valid mysql",
    "division by zero",
    "unknown column",
    "table 'g5_",
)

# ── Boolean 그룹 분석용 페이로드 패턴 ────────────────────────────
_BOOL_TRUE = re.compile(
    r"1=1|'1'\s*=\s*'1'|OR\s+1\b|OR\(1=1\)|AND\(1=1\)|or_true|and_true|paren_true",
    re.IGNORECASE,
)
_BOOL_FALSE = re.compile(
    r"1=2|'1'\s*=\s*'2'|AND\s+1=2|AND\(1=2\)|paren_false|and_false",
    re.IGNORECASE,
)


# ── 입력 정규화 ──────────────────────────────────────────────────
def _extract_response(test_result: dict) -> dict:
    """executor flat / 기존 nested 형식 모두 받아 통일된 dict 로 변환."""
    if "response" in test_result and isinstance(test_result["response"], dict):
        r = test_result["response"]
        return {
            "body":    (r.get("body") or "").lower(),
            "elapsed": float(r.get("elapsed") or 0.0),
            "length":  int(r.get("length") or 0),
            "status":  r.get("status"),
        }
    body = test_result.get("response_body") or ""
    return {
        "body":    body.lower(),
        "elapsed": float(test_result.get("elapsed") or 0.0),
        "length":  int(test_result.get("length") or 0),
        "status":  test_result.get("status"),
    }


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


# ── 개별 판정 함수 ────────────────────────────────────────────────
def _check_time_based(elapsed: float) -> Optional[str]:
    if elapsed >= SLEEP_THRESHOLD:
        return f"Time-based SQLi (응답 지연 {elapsed:.2f}s >= {SLEEP_THRESHOLD}s)"
    return None


def _check_error_based(body: str) -> Optional[str]:
    for sig in DB_ERROR_KEYWORDS:
        if sig in body:
            return f"Error-based SQLi (DB 에러 노출: '{sig}')"
    return None


def _check_boolean_based(length: int, controls: dict) -> Optional[str]:
    """단건에 controls(true_len, false_len)가 같이 들어온 경우 사용."""
    true_len  = controls.get("true_len")
    false_len = controls.get("false_len")
    if true_len is None or false_len is None:
        return None
    span = abs(true_len - false_len)
    if span == 0:
        return None
    dist_true  = abs(length - true_len)
    dist_false = abs(length - false_len)
    if dist_true >= dist_false:
        return None
    signal = (dist_false - dist_true) / max(span, 1)
    if signal >= BOOL_SIGNAL_MIN:
        return f"Boolean-based SQLi (signal {signal:.1%})"
    return None


# ── 단건 메인 진입점 ─────────────────────────────────────────────
def validate_sqli(test_result: dict) -> tuple[bool, str]:
    """단일 executor 결과 dict → (취약 여부, 사유)."""
    if not test_result:
        return False, "검증 불가 (입력 없음)"

    resp = _extract_response(test_result)
    if not resp["body"] and resp["elapsed"] == 0.0:
        return False, "검증 불가 (응답 데이터 누락)"

    msg = _check_time_based(resp["elapsed"])
    if msg: return True, msg

    msg = _check_error_based(resp["body"])
    if msg: return True, msg

    controls = test_result.get("controls") or {}
    msg = _check_boolean_based(resp["length"], controls)
    if msg: return True, msg

    return False, "안전함 (SQLi 시그니처 미검출)"


# ── 그룹 단위 Boolean 분석 ───────────────────────────────────────
def detect_boolean_group(results: list[dict]) -> list[dict]:
    """
    여러 executor 결과를 (point, inject_param, url) 으로 묶어
    TRUE/FALSE 페이로드 응답 길이 차이로 Boolean SQLi 판정.

    반환: 취약으로 판정된 [{result, evidence}] 형태의 dict 리스트
          (호출자가 finding 포맷으로 변환해 사용)
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

    detected: list[dict] = []

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

        if diff < BOOL_GROUP_THRESHOLD:
            continue

        direction = "true>false" if avg_true > avg_false else "true<false"
        evidence = (
            f"boolean_sqli: true_len={avg_true:.0f}, false_len={avg_false:.0f}, "
            f"diff={diff:.1%} ({direction})"
        )

        best = max(true_items, key=lambda r: len(r["response_body"]))
        detected.append({"result": best, "evidence": evidence})

    return detected
