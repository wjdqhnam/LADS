"""
findings.py - 공통 findings 스키마 정의

모든 모듈(SQLi, XSS, BAC, Misconfig)이 이 포맷으로 결과를 저장한다.
"""

from __future__ import annotations
from typing import Optional
import json
import os

# findings 저장 경로
FINDINGS_FILE = os.getenv("FINDINGS_FILE", "results/findings.json")

# ── type 상수 ──────────────────────────────────────────────
# SQLi
SQLI_CONFIRMED       = "SQLI_CONFIRMED"

# XSS
XSS_CONFIRMED        = "XSS_CONFIRMED"

# BAC
BAC_SUSPECTED_LOW    = "BAC_SUSPECTED_LOW"
BAC_SUSPECTED_MEDIUM = "BAC_SUSPECTED_MEDIUM"
BAC_SUSPECTED_HIGH   = "BAC_SUSPECTED_HIGH"
IDOR_SUSPECTED       = "IDOR_SUSPECTED"

# Misconfig
MISCONFIG_CONFIRMED  = "MISCONFIG_CONFIRMED"
MISCONFIG_WARNING    = "MISCONFIG_WARNING"

# ── confidence 상수 ────────────────────────────────────────
HIGH   = "high"
MEDIUM = "medium"
LOW    = "low"

# ── module 상수 ───────────────────────────────────────────
MODULE_SQLI     = "sqli"
MODULE_XSS      = "xss"
MODULE_BAC      = "bac"
MODULE_MISCONFIG = "misconfig"


def make_finding(
    module:     str,
    type:       str,
    category:   str,
    url:        str,
    confidence: str,
    evidence:   str,
    param:      Optional[str] = None,
    payload:    Optional[str] = None,
    status:     Optional[int] = None,
    extra:      Optional[dict] = None,
) -> dict:
    """
    공통 finding 딕셔너리 생성.

    Args:
        module:     sqli / xss / bac / misconfig
        type:       SQLI_CONFIRMED, BAC_SUSPECTED_LOW 등
        category:   error_based / reflected / admin_area / git_exposure 등
        url:        요청 URL
        confidence: high / medium / low
        evidence:   판정 근거 문자열
        param:      취약 파라미터 (없으면 None)
        payload:    사용한 페이로드 (없으면 None)
        status:     HTTP 응답 코드 (없으면 None)
        extra:      모듈별 추가 정보 (없으면 None)

    Returns:
        finding dict
    """
    finding = {
        "module":     module,
        "type":       type,
        "category":   category,
        "url":        url,
        "param":      param,
        "payload":    payload,
        "status":     status,
        "confidence": confidence,
        "evidence":   evidence,
    }
    if extra:
        finding["extra"] = extra
    return finding


# ── 모듈별 헬퍼 ───────────────────────────────────────────

def sqli_finding(
    category:  str,
    url:       str,
    param:     str,
    payload:   str,
    status:    int,
    evidence:  str,
    confidence: str = HIGH,
) -> dict:
    """SQLi finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_SQLI,
        type=SQLI_CONFIRMED,
        category=category,
        url=url,
        param=param,
        payload=payload,
        status=status,
        confidence=confidence,
        evidence=evidence,
    )


def xss_finding(
    category:  str,
    url:       str,
    param:     str,
    payload:   str,
    status:    int,
    evidence:  str,
    confidence: str = HIGH,
) -> dict:
    """XSS finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_XSS,
        type=XSS_CONFIRMED,
        category=category,
        url=url,
        param=param,
        payload=payload,
        status=status,
        confidence=confidence,
        evidence=evidence,
    )


def bac_finding(
    type:      str,
    category:  str,
    url:       str,
    status:    int,
    evidence:  str,
    confidence: str,
    param:     Optional[str] = None,
    extra:     Optional[dict] = None,
) -> dict:
    """BAC finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_BAC,
        type=type,
        category=category,
        url=url,
        param=param,
        payload=None,
        status=status,
        confidence=confidence,
        evidence=evidence,
        extra=extra,
    )


def misconfig_finding(
    type:      str,
    category:  str,
    url:       str,
    status:    int,
    evidence:  str,
    confidence: str = HIGH,
    extra:     Optional[dict] = None,
) -> dict:
    """Misconfig finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_MISCONFIG,
        type=type,
        category=category,
        url=url,
        param=None,
        payload=None,
        status=status,
        confidence=confidence,
        evidence=evidence,
        extra=extra,
    )


# ── 저장/로드 ─────────────────────────────────────────────

def save_findings(findings: list[dict], path: str = FINDINGS_FILE) -> None:
    """findings 리스트를 JSON 파일로 저장"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)


def load_findings(path: str = FINDINGS_FILE) -> list[dict]:
    """findings JSON 파일 로드. 없으면 빈 리스트 반환"""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def append_findings(new_findings: list[dict], path: str = FINDINGS_FILE) -> None:
    """기존 findings에 새 결과를 추가하고 저장"""
    existing = load_findings(path)
    existing.extend(new_findings)
    save_findings(existing, path)


# ── 사용 예시 ─────────────────────────────────────────────
if __name__ == "__main__":
    examples = [
        sqli_finding(
            category="error_based",
            url="/bbs/search.php",
            param="stx",
            payload="a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))#",
            status=200,
            evidence="xpath syntax error found in response",
        ),
        xss_finding(
            category="reflected",
            url="/bbs/search.php",
            param="stx",
            payload='" onmouseover=alert(1) x="',
            status=200,
            evidence="onmouseover=alert found unencoded in response",
        ),
        bac_finding(
            type=BAC_SUSPECTED_MEDIUM,
            category="admin_area",
            url="/adm/",
            status=200,
            confidence=MEDIUM,
            evidence="user session accessed admin-like path without login/denied response",
            extra={"role": "user", "session": "user"},
        ),
        misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category="git_exposure",
            url="/.git/config",
            status=200,
            evidence="response contains [core] and repositoryformatversion",
        ),
    ]

    for f in examples:
        print(json.dumps(f, ensure_ascii=False, indent=2))
