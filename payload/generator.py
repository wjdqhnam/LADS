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

COUNT = 7  # 타입당 페이로드 수


def _slug(url: str) -> str:
    path = urlparse(url).path.rstrip("/")
    name = path.split("/")[-1] if path else "root"
    return re.sub(r"[^a-zA-Z0-9]", "_", name)[:20] or "ep"


# targets.json의 injectable 파라미터에서 INPUT_POINTS 형식의 포인트 목록 생성
def build_points_from_targets(targets: list[dict]) -> list[dict]:
    points: list[dict] = []
    seen: set[str] = set()

    for target in targets:
        url = target.get("action") or target.get("source_url", "")
        method = (target.get("method") or "GET").upper()
        url_lower = url.lower()
        is_login = any(k in url_lower for k in ("login", "signin", "auth"))
        slug = _slug(url)

        all_params = target.get("params", [])
        injectable = [p for p in all_params if p.get("injectable")]

        for param in injectable:
            pname = param["name"]
            pname_lower = pname.lower()
            key = f"{method}:{url}:{pname}"
            if key in seen:
                continue
            seen.add(key)

            base_params = {
                p["name"]: str(p.get("default_value") or "")
                for p in all_params
                if p["name"] != pname and p.get("default_value")
            }

            common = dict(
                url=url,
                method=method,
                param=pname,
                base_params=base_params,
                db="MySQL",
                note=f"동적 발견 - {method} {url}",
            )

            # SQLi 포인트
            if is_login:
                sqli_type = "sqli_login"
            elif any(k in pname_lower for k in ("sst", "order", "sort")):
                sqli_type = "sqli_orderby"
            elif any(k in pname_lower for k in ("sfl", "field", "col")):
                sqli_type = "sqli_field"
            else:
                sqli_type = "sqli_string"

            points.append({
                "name": f"sqli_{slug}_{pname}",
                "type": "string",
                "vuln_types": [sqli_type],
                **common,
            })

            # XSS 포인트 (패스워드 필드 제외, 로그인 폼 제외)
            if is_login or any(k in pname_lower for k in ("password", "passwd", "pw")):
                continue

            if method == "GET":
                xss_type = "xss_search"
            elif any(k in pname_lower for k in ("subject", "title")):
                xss_type = "xss_subject"
            elif "comment" in url_lower or "reply" in url_lower:
                xss_type = "xss_comment"
            else:
                xss_type = "xss_content"

            points.append({
                "name": f"xss_{slug}_{pname}",
                "type": "stored_xss" if method == "POST" else "reflected_xss",
                "vuln_types": [xss_type],
                **common,
            })

    return points


def run(out_file: str = "results/payloads_llm.json", progress_callback=None, targets_file: str | None = None):

    print(f"\n{'='*60}")
    print(f"  Payload Generator")
    print(f"{'='*60}\n")

    if not targets_file or not os.path.exists(targets_file):
        print(f"[ERROR] targets_file 없음: {targets_file}")
        print("[ERROR] 크롤링을 먼저 실행하세요.")
        return

    with open(targets_file, encoding="utf-8") as f:
        targets_data = json.load(f)

    points = build_points_from_targets(targets_data)
    if not points:
        print("[ERROR] injectable 파라미터 없음 — targets.json을 확인하세요.")
        return

    print(f"  입력점: {len(points)}개 (targets.json 기반)\n")

    client = LLMClient()
    all_results = {}
    total_points = len(points)

    for idx, point in enumerate(points):
        pname = point["name"]
        if progress_callback:
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
                parsed          = parse_clean(raw)
                filtered, rejected = filter_payloads(parsed)
                records         = deduplicate(filtered)
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

    # probe 단계에서 사용할 입력 지점 메타 저장
    meta_out = os.getenv("PAYLOADS_META_FILE", "results/payloads_llm_meta.json")
    os.makedirs(os.path.dirname(meta_out) or ".", exist_ok=True)
    with open(meta_out, "w", encoding="utf-8") as f:
        json.dump(points, f, ensure_ascii=False, indent=2)

    all_records = [
        r
        for point_data in all_results.values()
        for records in point_data.values()
        for r in records
    ]
    total = len(all_records)

    print(f"{'='*60}")
    print(f"  저장 완료  -> {out_file}")
    print(f"  메타 저장  -> {meta_out}")
    print(f"  총 페이로드: {total}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="results/payloads_llm.json")
    parser.add_argument("--targets", default=None)
    args = parser.parse_args()
    run(args.out, targets_file=args.targets)
