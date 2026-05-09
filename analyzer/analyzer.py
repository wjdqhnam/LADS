"""
Analyzer — 통합 진입점
──────────────────────
executor.py 가 만든 실행 결과(execution_results.json)를 입력으로 받아
취약점별 analyzer (sqli_analyzer / xss_analyzer / bac_analyzer)에 라우팅하고
findings 리스트를 만들어 저장한다.

이전에는 fuzzer/validator.py 가 마커 매칭 / 시간 임계 검사를 직접 들고 있었지만,
이 모듈은 진짜 판정 로직을 *_analyzer.py 에 위임한다.
validator.py 는 호환을 위해 이 모듈의 run() 을 다시 export 만 한다.

사용법:
    from analyzer import run
    findings = run(input_file="results/execution_results.json",
                   output_file="results/findings.json")
"""
from __future__ import annotations

import json
import os
from typing import Callable, Optional

from sqli_analyzer import validate_sqli
from xss_analyzer  import validate_xss
from bac_analyzer  import validate_bac


# ── 라우팅 테이블 ────────────────────────────────────────────────
# meta.vuln_type 키워드 → 사용할 analyzer 함수
_ROUTERS: list[tuple[tuple[str, ...], Callable[[dict], tuple[bool, str]]]] = [
    (("sqli", "sql"),                  validate_sqli),
    (("xss",),                         validate_xss),
    (("bac", "broken_access", "auth"), validate_bac),
]


def _route(vuln_type: str) -> Optional[Callable[[dict], tuple[bool, str]]]:
    vt = (vuln_type or "").lower()
    for keys, fn in _ROUTERS:
        if any(k in vt for k in keys):
            return fn
    return None


# ── 단일 결과 분석 ───────────────────────────────────────────────
def analyze_one(result: dict) -> Optional[dict]:

    # executor 단계에서 이미 실패한 케이스는 skip
    if result.get("error"):
        return None
    if not (result.get("response_body") or (result.get("response") or {}).get("body")):
        return None

    meta      = result.get("meta") or {}
    vuln_type = (meta.get("vuln_type") or result.get("vuln_type") or "").lower()

    fn = _route(vuln_type)
    if fn is None:
        # 타입 불명확 → SQLi → XSS → BAC 순으로 보수적으로 시도
        for trial in (validate_sqli, validate_xss, validate_bac):
            ok, evidence = trial(result)
            if ok:
                fn = trial
                break
        else:
            return None
    else:
        ok, evidence = fn(result)
        if not ok:
            return None

    return {
        "id":          result.get("id"),
        "point":       result.get("point"),
        "url":         result.get("url"),
        "method":      result.get("method"),
        "param":       result.get("inject_param"),
        "payload":     result.get("payload"),
        "inject_mode": result.get("inject_mode"),
        "vuln_type":   vuln_type or fn.__name__.replace("validate_", ""),
        "status":      result.get("status"),
        "elapsed":     result.get("elapsed"),
        "evidence":    evidence,
    }


# ── 일괄 분석 ────────────────────────────────────────────────────
def analyze(results: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for r in results:
        f = analyze_one(r)
        if f is not None:
            findings.append(f)
    return findings


# ── 파이프라인 진입점 (validator.run 대체) ───────────────────────
def run(
    input_file:  str = "results/execution_results.json",
    output_file: str = "results/findings.json",
) -> list[dict]:
    with open(input_file, encoding="utf-8") as f:
        results = json.load(f)

    findings = analyze(results)

    parent = os.path.dirname(output_file)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    return findings