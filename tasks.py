import json
import os

TASK_LABELS = {
    "crawl":    "크롤링 및 타깃 구성",
    "payload":  "페이로드 생성",
    "probe":    "주입 테스트 준비",
    "execute":  "퍼징 실행",
    "validate": "취약점 판정",
    "misconfig": "설정 오류 점검",
    "all":      "전체 진단",
}


# 역할별 크롤 결과를 URL 기준으로 병합하고 accessible_by(어떤 역할에서 접근 가능한지) 태깅
def _merge_crawl_results(role_pages: dict[str, list[dict]]) -> list[dict]:
    from urllib.parse import urlparse

    def _form_sig(form: dict) -> str:
        path = urlparse(form.get("action", "")).path or form.get("action", "")
        method = form.get("method", "GET").upper()
        names = sorted(f["name"] for f in form.get("fields", []) if f.get("name"))
        return f"{method}:{path}:{','.join(names)}"

    url_map: dict[str, dict] = {}

    for role, pages in role_pages.items():
        for page in pages:
            url = page["url"]
            status = page.get("status_code", 0)

            if url not in url_map:
                url_map[url] = {**page, "accessible_by": []}

            # 해당 역할이 200으로 접근 가능한 경우 기록
            if status == 200 and role not in url_map[url]["accessible_by"]:
                url_map[url]["accessible_by"].append(role)

            # 해당 역할에서만 보이는 새 폼 추가 (폼 시그니처 기준 중복 제거)
            existing_sigs = {_form_sig(f) for f in url_map[url].get("forms", [])}
            for form in page.get("forms", []):
                sig = _form_sig(form)
                if sig not in existing_sigs:
                    url_map[url].setdefault("forms", []).append(form)
                    existing_sigs.add(sig)

    return list(url_map.values())


def _task_crawl(run_path_fn, target_url, emit_progress=None):
    from dataclasses import asdict
    from crawl.auth import login_all_roles
    from crawl.crawler import Crawler
    from crawl.target_builder import build_targets

    def _prog(n):
        if emit_progress: emit_progress(n)

    crawl_file   = run_path_fn("crawl_result.json")
    targets_file = run_path_fn("targets.json")

    # 역할별 세션 쿠키 획득
    role_sessions = login_all_roles(base_url=target_url)
    acquired = [r for r in role_sessions if role_sessions[r] or r == "guest"]
    print(f"[CRAWL] roles to crawl: {acquired}")

    for role, cookies in role_sessions.items():
        with open(run_path_fn(f"auth_cookies_{role}.json"), "w", encoding="utf-8") as f:
            json.dump(cookies, f, ensure_ascii=False, indent=2)

    # 역할별 크롤 실행
    role_pages: dict[str, list[dict]] = {}
    n_roles = max(len(role_sessions), 1)
    prog_per_role = 18 // n_roles

    for i, (role, cookies) in enumerate(role_sessions.items()):
        print(f"[CRAWL] [{role}] start: {target_url}")
        crawler = Crawler(target_url, init_cookies=cookies)

        base = i * prog_per_role
        def _crawl_progress(done, total, _base=base):
            _prog(_base + int(done / max(total, 1) * prog_per_role))

        crawler.crawl(progress_callback=_crawl_progress)
        crawler.summary()
        role_pages[role] = [asdict(r) for r in crawler.results]
        print(f"[CRAWL] [{role}] pages={len(crawler.results)}")

    _prog(18)

    # 병합 및 accessible_by 태깅
    merged_pages = _merge_crawl_results(role_pages)
    print(f"[CRAWL] merged: {len(merged_pages)} unique pages")

    os.makedirs(os.path.dirname(crawl_file) or ".", exist_ok=True)
    with open(crawl_file, "w", encoding="utf-8") as f:
        json.dump(merged_pages, f, ensure_ascii=False, indent=2)
    print(f"[CRAWL] saved: {crawl_file}")

    # 이후 단계(BAC 등)가 auth_cookies.json 하나만 참조하므로 가장 높은 권한 세션으로 유지
    main_cookies = role_sessions.get("member") or role_sessions.get("admin") or {}
    if main_cookies:
        with open(run_path_fn("auth_cookies.json"), "w", encoding="utf-8") as f:
            json.dump(main_cookies, f, ensure_ascii=False, indent=2)
        print(f"[CRAWL] auth cookies saved: {len(main_cookies)} cookies")

    _prog(20)

    targets = build_targets(merged_pages)
    with open(targets_file, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)
    print(f"[CRAWL] targets saved: {targets_file} ({len(targets)})")


def _task_payload(payloads_file, emit_progress=None):
    from payload.generator import run as generate_run

    def _prog(n):
        if emit_progress: emit_progress(n)

    os.makedirs("results", exist_ok=True)
    print(f"[PAYLOAD] generate: {payloads_file}")
    generate_run(out_file=payloads_file)
    _prog(30)


def _task_probe(run_path_fn, payloads_file, payloads_meta_file, emit_progress=None):
    from probe.strategy import build_tasks

    def _prog(n):
        if emit_progress: emit_progress(n)

    targets_file    = run_path_fn("targets.json")
    probe_tasks_file = run_path_fn("probe_tasks.json")

    if not os.path.exists(payloads_file):
        print(f"[ERROR] missing payload file: {payloads_file}")
        return
    if not os.path.exists(payloads_meta_file):
        print(f"[WARN] missing payload meta file: {payloads_meta_file}")
        return

    with open(payloads_meta_file, encoding="utf-8") as f:
        points_meta = json.load(f)
    with open(payloads_file, encoding="utf-8") as f:
        payloads = json.load(f)

    targets = None
    if os.path.exists(targets_file):
        with open(targets_file, encoding="utf-8") as f:
            targets = json.load(f)

    base_cookies: dict = {}
    cookies_file = run_path_fn("auth_cookies.json")
    if os.path.exists(cookies_file):
        with open(cookies_file, encoding="utf-8") as f:
            base_cookies = json.load(f)
        print(f"[PROBE] auth cookies loaded: {len(base_cookies)} cookies")
    else:
        print("[PROBE] no auth cookies — requests will be unauthenticated")

    tasks = build_tasks(points_meta, payloads, targets, base_cookies=base_cookies)
    with open(probe_tasks_file, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)
    print(f"[PROBE] tasks saved: {probe_tasks_file} ({len(tasks)})")
    _prog(35)


def _task_execute(run_path_fn, emit_progress=None):
    from probe.executor import execute

    def _prog(n):
        if emit_progress: emit_progress(n)

    probe_tasks_file = run_path_fn("probe_tasks.json")
    exec_file       = run_path_fn("execution_results.json")

    if not os.path.exists(probe_tasks_file):
        print(f"[ERROR] missing probe task file: {probe_tasks_file}")
        return

    with open(probe_tasks_file, encoding="utf-8") as f:
        tasks = json.load(f)

    def _execute_progress(done, total):
        _prog(35 + int(done / max(total, 1) * 55))

    print(f"[EXEC] start: {len(tasks)} tasks")
    results = execute(tasks, timeout=10, delay=0.0, output_file=exec_file, progress_callback=_execute_progress)
    ok      = sum(1 for r in results if r.get("error") is None)
    timeout = sum(1 for r in results if r.get("error") == "timeout")
    err     = sum(1 for r in results if r.get("error") and r.get("error") != "timeout")
    print(f"[EXEC] done: ok={ok}, timeout={timeout}, error={err}")
    _prog(90)


def _task_validate(run_path_fn, emit_progress=None):
    from analyzer import run as validate_run

    def _prog(n):
        if emit_progress: emit_progress(n)

    exec_file     = run_path_fn("execution_results.json")
    findings_file = run_path_fn("findings.json")

    if not os.path.exists(exec_file):
        print(f"[ERROR] missing execution result file: {exec_file}")
        return

    def _validate_progress(done, total):
        _prog(90 + int(done / max(total, 1) * 10))

    findings = validate_run(input_file=exec_file, output_file=findings_file, progress_callback=_validate_progress)
    xss_cnt  = sum(1 for f in findings if "xss" in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sql" in (f.get("vuln_type") or "").lower())
    print(f"[VALIDATE] done: findings={len(findings)}, xss={xss_cnt}, sqli={sqli_cnt}")
    _prog(100)


def _task_misconfig(run_path_fn, target_url, emit_progress=None):
    from misconfig.checker import run as misconfig_run

    def _prog(n):
        if emit_progress: emit_progress(n)

    findings_file = run_path_fn("findings.json")

    print(f"[MISCONFIG] target: {target_url}")
    findings = misconfig_run(
        base_url=target_url,
        output_file=findings_file,
        progress_callback=lambda done, total: _prog(int(done / max(total, 1) * 100)),
        append=True,
    )
    confirmed = sum(1 for f in findings if f.get("type") == "MISCONFIG_CONFIRMED")
    warnings  = sum(1 for f in findings if f.get("type") == "MISCONFIG_WARNING")
    print(f"[MISCONFIG] confirmed={confirmed}, warning={warnings}")
    _prog(100)


def _task_all(run_path_fn, target_url, payloads_file, payloads_meta_file, skip_crawl=False, emit_progress=None):
    def _prog(n):
        if emit_progress: emit_progress(n)

    _prog(2)

    if skip_crawl:
        print("[CRAWL] 이전 크롤링 결과 재사용")
        _prog(20)
    else:
        _task_crawl(run_path_fn, target_url, emit_progress)
        _prog(20)

    if not os.path.exists(run_path_fn("crawl_result.json")):
        print("[ERROR] 크롤링 결과 파일 없음 — 스캔 중단")
        return

    if os.path.exists(payloads_file):
        try:
            with open(payloads_file, encoding="utf-8") as _f:
                _cnt = len(json.load(_f))
        except Exception:
            _cnt = 0
        print(f"[PAYLOAD] 기존 페이로드 재사용 ({_cnt}개) — 새로 생성하려면 파일 삭제 후 재스캔")
        _prog(30)
    else:
        _task_payload(payloads_file, emit_progress)
        _prog(30)

    if not os.path.exists(payloads_file):
        print("[ERROR] 페이로드 파일 없음 — 스캔 중단")
        return

    _task_probe(run_path_fn, payloads_file, payloads_meta_file, emit_progress)
    _prog(35)

    if not os.path.exists(run_path_fn("probe_tasks.json")):
        print("[ERROR] 퍼징 작업 파일 없음 — 스캔 중단")
        return

    _task_execute(run_path_fn, emit_progress)
    _prog(90)

    if not os.path.exists(run_path_fn("execution_results.json")):
        print("[ERROR] 실행 결과 파일 없음 — 스캔 중단")
        return

    _task_validate(run_path_fn, emit_progress)
    _prog(95)

    _task_misconfig(run_path_fn, target_url, emit_progress)
    _prog(100)
