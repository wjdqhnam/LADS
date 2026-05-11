import json
import os

TASK_LABELS = {
    "crawl":    "크롤링 및 타깃 구성",
    "payload":  "페이로드 생성",
    "fuzz":     "퍼징 전략 수립",
    "execute":  "퍼징 실행",
    "validate": "취약점 판정",
    "misconfig": "설정 오류 점검",
    "all":      "전체 진단",
}


def _task_crawl(run_path_fn, target_url, emit_progress=None):
    from crawl.crawler import Crawler
    from crawl.target_builder import build_targets, print_summary

    def _prog(n):
        if emit_progress: emit_progress(n)

    crawl_file   = run_path_fn("crawl_result.json")
    targets_file = run_path_fn("targets.json")

    print(f"[CRAWL] start: {target_url}")
    crawler = Crawler(target_url)

    def _crawl_progress(done, total):
        _prog(int(done / max(total, 1) * 20))

    crawler.crawl(progress_callback=_crawl_progress)
    crawler.save(crawl_file)
    crawler.summary()
    _prog(20)

    if crawler.auth_cookies:
        cookies_file = run_path_fn("auth_cookies.json")
        with open(cookies_file, "w", encoding="utf-8") as f:
            json.dump(crawler.auth_cookies, f, ensure_ascii=False, indent=2)
        print(f"[CRAWL] auth cookies saved: {len(crawler.auth_cookies)} cookies")
    else:
        print("[CRAWL] no auth cookies (anonymous crawl)")

    with open(crawl_file, encoding="utf-8") as f:
        pages = json.load(f)
    targets = build_targets(pages)
    with open(targets_file, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)
    print(f"[CRAWL] targets saved: {targets_file} ({len(targets)})")
    print_summary(targets)


def _task_payload(payloads_file, emit_progress=None):
    from payload.generator import run as generate_run

    def _prog(n):
        if emit_progress: emit_progress(n)

    os.makedirs("results", exist_ok=True)
    print(f"[PAYLOAD] generate: {payloads_file}")
    generate_run(out_file=payloads_file)
    _prog(30)


def _task_fuzz(run_path_fn, payloads_file, payloads_meta_file, emit_progress=None):
    from fuzzer.strategy import build_tasks

    def _prog(n):
        if emit_progress: emit_progress(n)

    targets_file    = run_path_fn("targets.json")
    fuzz_tasks_file = run_path_fn("fuzz_tasks.json")

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
        print(f"[FUZZ] auth cookies loaded: {len(base_cookies)} cookies")
    else:
        print("[FUZZ] no auth cookies — requests will be unauthenticated")

    tasks = build_tasks(points_meta, payloads, targets, base_cookies=base_cookies)
    with open(fuzz_tasks_file, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)
    print(f"[FUZZ] tasks saved: {fuzz_tasks_file} ({len(tasks)})")
    _prog(35)


def _task_execute(run_path_fn, emit_progress=None):
    from fuzzer.executor import execute

    def _prog(n):
        if emit_progress: emit_progress(n)

    fuzz_tasks_file = run_path_fn("fuzz_tasks.json")
    exec_file       = run_path_fn("execution_results.json")

    if not os.path.exists(fuzz_tasks_file):
        print(f"[ERROR] missing fuzz task file: {fuzz_tasks_file}")
        return

    with open(fuzz_tasks_file, encoding="utf-8") as f:
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

    _task_fuzz(run_path_fn, payloads_file, payloads_meta_file, emit_progress)
    _prog(35)

    if not os.path.exists(run_path_fn("fuzz_tasks.json")):
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
