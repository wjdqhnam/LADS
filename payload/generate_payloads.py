import json
import argparse
import sys
import os
from dotenv import load_dotenv
load_dotenv()

# 직접 실행(python generate_payloads.py) 시 LADS 루트를 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from .llm_client import LLMClient
    from .context_builder import SYSTEM_PROMPT, build_prompt
    from .payload_parser import clean as parse_clean
except ImportError:
    # 직접 실행 시 절대경로 import
    from llm_client import LLMClient
    from context_builder import SYSTEM_PROMPT, build_prompt
    from payload_parser import clean as parse_clean

from payload_filter import filter_payloads, deduplicate, report as filter_report



INPUT_POINTS = [

    # XSS 타겟
    {
        "name":    "xss_wr_subject",
        "url":     "http://34.68.27.120:8081/bbs/write_update.php",
        "method":  "POST",
        "param":   "wr_subject",
        "type":    "stored_xss",
        "note":    "게시글 제목 - 홈/상세/관리자 3곳 반영, script 차단",
        "vuln_types": ["xss_subject"],
    },
    {
        "name":    "xss_wr_content",
        "url":     "http://34.68.27.120:8081/bbs/write_update.php",
        "method":  "POST",
        "param":   "wr_content",
        "type":    "stored_xss",
        "note":    "게시글 본문 - img/a/b/p 허용, script 차단, 이벤트핸들러 우회 필요",
        "vuln_types": ["xss_content"],
    },
    {
        "name":    "xss_search_stx",
        "url":     "http://34.68.27.120:8081/bbs/search.php",
        "method":  "GET",
        "param":   "stx",
        "type":    "reflected_xss",
        "note":    "검색창 stx - value='' 속성 반영, onfocus=alert(1)→onfocusalert1 필터",
        "vuln_types": ["xss_search"],
    },
    {
        "name":    "xss_qalist_stx",
        "url":     "http://34.68.27.120:8081/bbs/board.php",
        "method":  "GET",
        "param":   "stx",
        "type":    "reflected_xss",
        "note":    "Q&A 게시판 검색창 - board.php?bo_table=qa, search.php와 동일 stx 패턴",
        "vuln_types": ["xss_search"],
    },
    {
        "name":    "xss_comment",
        "url":     "http://34.68.27.120:8081/bbs/write_comment_update.php",
        "method":  "POST",
        "param":   "wr_content",
        "type":    "stored_xss",
        "note":    "댓글 본문 - http:// URL만 <a href> 변환, javascript: 차단",
        "vuln_types": ["xss_comment"],
    },

    # SQLi 타겟
    {
        "name":    "sqli_search_sfl",
        "url":     "http://34.68.27.120:8081/bbs/search.php",
        "method":  "GET",
        "param":   "sfl",
        "type":    "string",
        "db":      "MySQL",
        "note":    "검색 필드 선택자 - SQL WHERE {sfl} LIKE '...' 직접 연결",
        "vuln_types": ["sqli_field"],
    },
    {
        "name":    "sqli_search_sst",
        "url":     "http://34.68.27.120:8081/bbs/search.php",
        "method":  "GET",
        "param":   "sst",
        "type":    "string",
        "db":      "MySQL",
        "note":    "정렬 컬럼 - ORDER BY {sst} 직접 연결, intval 없음",
        "vuln_types": ["sqli_orderby"],
    },
    {
        "name":    "sqli_search_stx",
        "url":     "http://34.68.27.120:8081/bbs/search.php",
        "method":  "GET",
        "param":   "stx",
        "type":    "string",
        "db":      "MySQL",
        "note":    "검색 키워드 - INSTR(LOWER(col),LOWER(stx)) 컨텍스트, PHP 공백분리 → 페이로드 공백금지, a'))))...# 패턴",
        "vuln_types": ["sqli_string"],
    },
    {
        "name":    "sqli_login_mb_id",
        "url":     "http://34.68.27.120:8081/bbs/login_check.php",
        "method":  "POST",
        "param":   "mb_id",
        "type":    "string",
        "db":      "MySQL",
        "note":    "로그인 아이디 - 문자열 컨텍스트, 인증 우회 목표",
        "vuln_types": ["sqli_login"],
    },
    {
        "name":    "sqli_qalist_sfl",
        "url":     "http://34.68.27.120:8081/bbs/board.php",
        "method":  "GET",
        "param":   "sfl",
        "type":    "string",
        "db":      "MySQL",
        "note":    "Q&A 게시판 검색 필드 선택자 - board.php?bo_table=qa, search.php sfl과 동일 패턴",
        "vuln_types": ["sqli_field"],
    },
]

COUNT = 5  # 타입당 페이로드 수


def run(out_file: str = "results/payloads_llm.json"):
    print(f"\n{'='*60}")
    print(f"  Gnuboard5 Payload Generator v2")
    print(f"  Target: http://34.68.27.120:8081/")
    print(f"{'='*60}\n")

    client = LLMClient()
    all_results = {}

    for point in INPUT_POINTS:
        pname = point["name"]
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
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)

    # Step 7에서 사용할 입력 지점 메타 저장
    meta_out = os.getenv("PAYLOADS_META_FILE", "results/payloads_llm_meta.json")
    os.makedirs(os.path.dirname(meta_out) or ".", exist_ok=True)
    with open(meta_out, "w", encoding="utf-8") as f:
        json.dump(INPUT_POINTS, f, ensure_ascii=False, indent=2)

    all_records = [
        r
        for point_data in all_results.values()
        for records in point_data.values()
        for r in records
    ]
    total = len(all_records)

    print(f"{'='*60}")
    print(f"  저장 완료 -> {out_file}")
    print(f"  총 페이로드: {total}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="results/payloads_llm.json")
    args = parser.parse_args()
    run(args.out)
    try:
        from pause_on_exit import pause_if_enabled
        pause_if_enabled()
    except Exception:
        pass
