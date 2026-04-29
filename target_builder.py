import json
import re
import sys
import os
from urllib.parse import urlparse

INPUT_FILE  = os.getenv("CRAWL_RESULT",  "crawl_result.json")
OUTPUT_FILE = os.getenv("TARGETS_FILE",  "targets.json")

# 인젝션 제외: CSRF/nonce 류 필드명
CSRF_RE = re.compile(r"(csrf|token|nonce|_token|authenticity|captcha)", re.IGNORECASE)

# 인젝션 제외: 의미 없는 버튼/파일 타입
SKIP_TYPES = {"submit", "button", "reset", "image", "file"}


# --- 헬퍼 

def _injectable(name: str, field_type: str) -> bool:
    if field_type in SKIP_TYPES:
        return False
    if CSRF_RE.search(name):
        return False
    return True


def _base_url(url: str) -> str:
    return urlparse(url)._replace(query="", fragment="").geturl()


def _form_sig(action: str, method: str, names: list[str]) -> str:
    return f"{method}:{action}:{','.join(sorted(names))}"


def _url_sig(base: str, names: list[str]) -> str:
    return f"GET:{base}:{','.join(sorted(names))}"


# --- 핵심 분석
def build_targets(pages: list[dict]) -> list[dict]:
    targets: list[dict] = []
    seen:    set[str]   = set()
    tid = 0

    for page in pages:
        source = page["url"]

        # 1. URL 쿼리 파라미터
        qp = page.get("query_params", {})
        if qp:
            base = _base_url(source)
            params = [
                {
                    "name":          name,
                    "field_type":    "url_param",
                    "default_value": vals[0] if vals else "",
                    "options":       [],
                    "injectable":    True,
                }
                for name, vals in qp.items()
            ]
            sig = _url_sig(base, [p["name"] for p in params])
            if sig not in seen:
                seen.add(sig)
                tid += 1
                targets.append({
                    "id":         f"url_{tid:04d}",
                    "type":       "url_param",
                    "source_url": source,
                    "action":     base,
                    "method":     "GET",
                    "enctype":    "application/x-www-form-urlencoded",
                    "params":     params,
                })

        # 2. HTML Form
        for form in page.get("forms", []):
            params = []
            for f in form.get("fields", []):
                if f["field_type"] in SKIP_TYPES:
                    continue
                params.append({
                    "name":          f["name"],
                    "field_type":    f["field_type"],
                    "default_value": f.get("value", ""),
                    "options":       f.get("options", []),
                    "injectable":    _injectable(f["name"], f["field_type"]),
                })

            if not params:
                continue

            sig = _form_sig(form["action"], form["method"],
                            [p["name"] for p in params])
            if sig not in seen:
                seen.add(sig)
                tid += 1
                targets.append({
                    "id":         f"form_{tid:04d}",
                    "type":       "form",
                    "source_url": source,
                    "action":     form["action"],
                    "method":     form["method"],
                    "enctype":    form.get("enctype", "application/x-www-form-urlencoded"),
                    "params":     params,
                })

    return targets


# --- 요약 출력

def print_summary(targets: list[dict]) -> None:
    url_t  = [t for t in targets if t["type"] == "url_param"]
    form_t = [t for t in targets if t["type"] == "form"]
    post_t = [t for t in form_t  if t["method"] == "POST"]
    get_t  = [t for t in form_t  if t["method"] == "GET"]

    total_injectable = sum(
        sum(1 for p in t["params"] if p["injectable"])
        for t in targets
    )

    sep = "=" * 60
    print(f"\n{sep}")
    print("공격 표면 분석 결과")
    print(sep)
    print(f"총 타겟                : {len(targets)}")
    print(f"  URL 파라미터 타겟    : {len(url_t)}")
    print(f"  Form 타겟            : {len(form_t)}")
    print(f"    POST form          : {len(post_t)}")
    print(f"    GET form           : {len(get_t)}")
    print(f"주입 가능 파라미터 합계: {total_injectable}")
    print()

    for t in targets:
        inj = [p["name"] for p in t["params"] if p["injectable"]]
        skip = [p["name"] for p in t["params"] if not p["injectable"]]
        print(f"  [{t['id']}] {t['method']} {t['action']}")
        if inj:
            print(f"           inject : {inj}")
        if skip:
            print(f"           skip   : {skip}")



if __name__ == "__main__":
    try:
        with open(INPUT_FILE, encoding="utf-8") as f:
            pages = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] {INPUT_FILE} 없음 — 먼저 crawler.py를 실행하세요.", file=sys.stderr)
        sys.exit(1)

    targets = build_targets(pages)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)

    print(f"저장 완료: {OUTPUT_FILE}  ({len(targets)}개 타겟)")
    print_summary(targets)
    try:
        from pause_on_exit import pause_if_enabled
        pause_if_enabled()
    except Exception:
        pass