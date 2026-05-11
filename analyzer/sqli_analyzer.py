"""
단건:
    Time-based  : elapsed >= SLEEP_THRESHOLD
    Error-based : 응답 본문에 DB 에러 시그니처 노출

그룹:
    Boolean(그룹): 같은 (point, inject_param, url, ) 묶음에서 TRUE/FALSE 페이로드 응답 길이 차이 >= 5% 이면 취약
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

# 공통 임계치
SLEEP_THRESHOLD       = 4.5    # Time-based 판정 (초)
BOOL_SIGNAL_MIN       = 0.05   # 단건 Boolean(controls 기반) 신호 강도 (5%)
BOOL_GROUP_THRESHOLD  = 0.05   # 그룹 Boolean 응답 길이 차이 임계값 (5%)

# DB 에러 시그니처
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

# ---
# Boolean 그룹 분석용 페이로드 패턴
# ---
_BOOL_TRUE = re.compile(
    r"1=1|'1'\s*=\s*'1'|OR\s+1\b|OR\(1=1\)|AND\(1=1\)", # family field 값 제거
    re.IGNORECASE,
)
_BOOL_FALSE = re.compile(
    r"1=2|'1'\s*=\s*'2'|AND\s+1=2|AND\(1=2\)|",         # family field 값 제거
    re.IGNORECASE,
)


# 입력 정규화 : executor flat / 기존 nested 형식 모두 받아 통일된 dict 로 변환
def _extract_response(test_result: dict) -> dict:
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


# ---
#  개별 판정 함수
# ---
def _check_time_based(elapsed: float) -> Optional[str]:
    if elapsed >= SLEEP_THRESHOLD:
        return f"Time-based SQLi (응답 지연 {elapsed:.2f}s >= {SLEEP_THRESHOLD}s)"
    return None

def _check_error_based(body: str) -> Optional[str]:
    for sig in DB_ERROR_KEYWORDS:
        if sig in body:
            return f"Error-based SQLi (DB 에러 노출: '{sig}')"
    return None


# 단일 executor 결과 dict -> (취약 여부, 사유)
def validate_sqli(test_result: dict) -> tuple[bool, str]:
    if not test_result:
        return False, "검증 불가 (입력 없음)"

    resp = _extract_response(test_result)
    if not resp["body"] and resp["elapsed"] == 0.0:
        return False, "검증 불가 (응답 데이터 누락)"

    msg = _check_time_based(resp["elapsed"])
    if msg: return True, msg

    msg = _check_error_based(resp["body"])
    if msg: return True, msg

    return False, "안전함 (SQLi 시그니처 미검출)"


# 그룹 단위 Boolean 분석 
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
        key = (r.get("point"), r.get("inject_param"), r.get("url"), r.get("inject_mode")) # inject_mode 포함: 모드 분리해서 동일한 컨텐츠끼리만 비교하도록
        groups[key].append(r)
        '''
        추가 설명: 이해됐으면 지워도 됨
        페이로드 단독 전송(replace)랑 기본값에 붙여 전송(replace)를 같은 그룹으로 묶을 경우, 응답 길이 차이 원인이 불분명.
        -> 해당 모드들을 분리 할 수 있도록 inject_mode 추가
        '''
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

        avg_true  = sum(len(r.get("length")) for r in true_items)  / len(true_items)
        avg_false = sum(len(r.get("length")) for r in false_items) / len(false_items)
        max_len   = max(avg_true, avg_false, 1)
        diff      = abs(avg_true - avg_false) / max_len

        if diff < BOOL_GROUP_THRESHOLD:
            continue

        direction = "true>false" if avg_true > avg_false else "true<false"
        evidence = (
            f"boolean_sqli: true_len={avg_true:.0f}, false_len={avg_false:.0f}, "
            f"diff={diff:.1%} ({direction})"
        )

        best = max(true_items, key=lambda r: len(r.get("length")))
        detected.append({"result": best, "evidence": evidence})

    return detected
