"""
bac/checker.py
BAC 전체 파이프라인 진입점

흐름:
  1. LLM 질의 → CMS별 접근 제어 정보 수집
  2. candidate_extractor → 테스트 후보 목록 생성
  3. session_manager → 세션 구성 (guest / member / admin)
  4. comparator → 세션별 응답 비교 + 판정
  5. findings.json에 저장
"""
from __future__ import annotations

import json
import os

from bac.prompt_builder import build_bac_prompt, BAC_SYSTEM_PROMPT, parse_bac_response, summarize
from bac.candidate_extractor import extract_candidates
from bac.session_manager import SessionManager, GUEST, MEMBER, ADMIN
from bac.comparator import compare_all
from findings import append_findings


def run(
    base_url: str,
    cms_name: str = "Unknown CMS",
    run_dir: str = ".",
    output_file: str = "results/findings.json",
    crawled_urls: list[str] = None,
    login_url: str = "/bbs/login_check.php",
    max_candidates: int = 200,
    progress_callback=None,
    append: bool = True,
) -> list[dict]:
    """
    BAC 전체 파이프라인 실행.

    Args:
        base_url:       타깃 기본 URL
        cms_name:       CMS 이름/버전
        run_dir:        현재 런 디렉토리 (auth_cookies.json 위치)
        output_file:    결과 저장 경로
        crawled_urls:   크롤러 발견 URL 목록
        login_url:      로그인 처리 URL
        max_candidates: 최대 테스트 후보 수
        progress_callback: (done, total) → None
        append:         True면 기존 findings에 추가

    Returns:
        이번 실행에서 발견된 findings list
    """
    from payload.llm_client import LLMClient

    print(f"[BAC] start → {base_url} ({cms_name})")

    # ── 1. LLM 질의 ──────────────────────────────────────────────────────────
    print("[BAC] LLM 질의 중 ...")
    prompt = build_bac_prompt(
        cms_name=cms_name,
        base_url=base_url,
        crawled_urls=crawled_urls,
    )

    llm    = LLMClient()
    raw    = llm.generate(prompt=prompt, system=BAC_SYSTEM_PROMPT, temperature=0.3)
    bac_data = parse_bac_response(raw)

    if not bac_data:
        print("[BAC] LLM 응답 파싱 실패 — 기본 후보만으로 진행")
        bac_data = {}

    summarize(bac_data)

    # ── 2. 후보 추출 ─────────────────────────────────────────────────────────
    candidates = extract_candidates(
        bac_data=bac_data,
        base_url=base_url,
        crawled_urls=crawled_urls,
    )

    if not candidates:
        print("[BAC] 테스트 후보 없음 — 종료")
        return []

    # ── 3. 세션 구성 ─────────────────────────────────────────────────────────
    sm = SessionManager.from_run(
        base_url=base_url,
        run_dir=run_dir,
        login_url=login_url,
    )
    sessions = sm.get_sessions([GUEST, MEMBER, ADMIN])

    # ── 4. 비교 + 판정 ───────────────────────────────────────────────────────
    findings = compare_all(
        candidates=candidates,
        sessions=sessions,
        progress_callback=progress_callback,
        max_candidates=max_candidates,
    )

    # ── 5. 저장 ──────────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    if append:
        append_findings(findings, output_file)
    else:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)

    confirmed = sum(1 for f in findings if "HIGH" in f.get("type", ""))
    suspected = len(findings) - confirmed
    print(f"[BAC] done: total={len(findings)}, high={confirmed}, suspected={suspected}")

    return findings


if __name__ == "__main__":
    import sys
    from dotenv import load_dotenv
    load_dotenv()

    target   = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081"
    cms      = sys.argv[2] if len(sys.argv) > 2 else "Gnuboard5 5.3.2.8"
    run_dir  = sys.argv[3] if len(sys.argv) > 3 else "."

    results = run(
        base_url=target,
        cms_name=cms,
        run_dir=run_dir,
        output_file="results/bac_findings.json",
        append=False,
    )

    print(f"\n총 {len(results)}개 발견")
    for f in results:
        print(f"  [{f['type']:25s}] [{f['confidence']:6s}] {f['url']}")
        print(f"    → {f['evidence']}")
