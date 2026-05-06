import importlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path


_DEPS = {
    "flask": "flask",
    "python-dotenv": "dotenv",
    "requests": "requests",
    "beautifulsoup4": "bs4",
    "lxml": "lxml",
    "openai": "openai",
}

for _pkg, _mod in _DEPS.items():
    try:
        importlib.import_module(_mod)
    except ImportError:
        print(f"[INSTALL] {_pkg} installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", _pkg, "-q"])
del _pkg, _mod

from dotenv import load_dotenv
from flask import Flask, Response, redirect, render_template, request

load_dotenv()


BASE_URL = os.getenv("TARGET_URL", "http://34.68.27.120:8081")
TARGET_URL_2 = os.getenv("TARGET_URL_2", "http://34.68.27.120:8080")
CMS_NAME = "Gnuboard5 5.3.2.8"
PAYLOADS_FILE = os.getenv("PAYLOADS_FILE", "results/payloads_llm.json")
PAYLOADS_META_FILE = os.getenv("PAYLOADS_META_FILE", "results/payloads_llm_meta.json")
RUNS_DIR = "runs"

_TARGETS = [
    {"key": "primary", "name": "Gnuboard5 (8081)", "url": BASE_URL, "version": CMS_NAME},
    {"key": "secondary", "name": "Gnuboard5 (8080)", "url": TARGET_URL_2, "version": "Test Env"},
]
_active_target_key = "primary"
_current_run_id: str | None = None

app = Flask(__name__)
_task_lock = threading.Lock()
_thread_local = threading.local()


_DBG_LOG_DIR = Path(__file__).parent / "log"
_DBG_LOG_DIR.mkdir(exist_ok=True)
_DBG_LOG_PATH = _DBG_LOG_DIR / "debug-3194ca.log"
_DBG_BUILD_ID = os.getenv("LADS_BUILD_ID") or datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]


def _dbg(hypothesis_id: str, message: str, data: dict | None = None) -> None:
    try:
        payload = {
            "sessionId": "3194ca",
            "runId": _current_run_id or "startup",
            "hypothesisId": hypothesis_id,
            "location": "app.py",
            "message": message,
            "data": data or {},
            "timestamp": int(time.time() * 1000),
        }
        with _DBG_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _make_run_id() -> str:
    return datetime.now().strftime("run_%Y%m%d_%H%M%S")


def _init_run() -> None:
    global _current_run_id
    os.makedirs(RUNS_DIR, exist_ok=True)
    existing = sorted(
        [
            d for d in os.listdir(RUNS_DIR)
            if os.path.isdir(os.path.join(RUNS_DIR, d)) and d.startswith("run_")
        ],
        reverse=True,
    )
    if existing:
        _current_run_id = existing[0]
    else:
        _current_run_id = _make_run_id()
        os.makedirs(os.path.join(RUNS_DIR, _current_run_id), exist_ok=True)


def _run_path(filename: str, run_id: str | None = None) -> str:
    return os.path.join(RUNS_DIR, run_id or _current_run_id or "default", filename)


def _active_url() -> str:
    target = next((t for t in _TARGETS if t["key"] == _active_target_key), _TARGETS[0])
    return target["url"]


def _emit_progress(pct: int) -> None:
    q = getattr(_thread_local, "log_queue", None)
    if q is not None:
        q.put(f"__PROGRESS__{max(0, min(100, int(pct)))}")


class _RoutingStream:
    def __init__(self, original):
        self._orig = original

    def write(self, text):
        q = getattr(_thread_local, "log_queue", None)
        if q is not None:
            stripped = text.rstrip("\n")
            if stripped:
                q.put(stripped)
        else:
            self._orig.write(text)

    def flush(self):
        self._orig.flush()

    def __getattr__(self, name):
        return getattr(self._orig, name)


sys.stdout = _RoutingStream(sys.__stdout__)


def _task_crawl():
    from crawler import Crawler
    from target_builder import build_targets, print_summary

    crawl_file = _run_path("crawl_result.json")
    targets_file = _run_path("targets.json")
    target_url = _active_url()

    print(f"[CRAWL] start: {target_url}")
    crawler = Crawler(target_url)

    def _crawl_progress(done: int, total: int) -> None:
        _emit_progress(int(done / max(total, 1) * 20))

    crawler.crawl(progress_callback=_crawl_progress)
    crawler.save(crawl_file)
    crawler.summary()
    _emit_progress(20)

    if crawler.auth_cookies:
        cookies_file = _run_path("auth_cookies.json")
        with open(cookies_file, "w", encoding="utf-8") as f:
            json.dump(crawler.auth_cookies, f, ensure_ascii=False, indent=2)
        print(f"[CRAWL] auth cookies saved: {len(crawler.auth_cookies)} cookies")
    else:
        print("[CRAWL] no auth cookies (anonymous crawl)")

    print(f"[CRAWL] build targets: {crawl_file}")
    with open(crawl_file, encoding="utf-8") as f:
        pages = json.load(f)
    targets = build_targets(pages)
    with open(targets_file, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)
    print(f"[CRAWL] targets saved: {targets_file} ({len(targets)})")
    print_summary(targets)


def _task_payload():
    from payload.generate_payloads import run as generate_run

    os.makedirs("results", exist_ok=True)
    print(f"[PAYLOAD] generate: {PAYLOADS_FILE}")
    generate_run(out_file=PAYLOADS_FILE)
    _emit_progress(30)


def _task_scan():
    import scanner

    scan_out = _run_path("scan_results.json")
    targets_file = _run_path("targets.json")
    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] missing payload file: {PAYLOADS_FILE}")
        return

    old_argv = sys.argv[:]
    argv = ["scanner.py", "--payloads", PAYLOADS_FILE, "--out", scan_out]
    if os.path.exists(targets_file):
        argv += ["--targets", targets_file]
    sys.argv = argv
    try:
        scanner.main()
    except SystemExit as exc:
        if exc.code and exc.code != 0:
            print(f"[ERROR] scanner exit code: {exc.code}")
    finally:
        sys.argv = old_argv


def _task_fuzz():
    from fuzzer.fuzzing_strategy import build_tasks

    targets_file = _run_path("targets.json")
    fuzz_tasks_file = _run_path("fuzz_tasks.json")
    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] missing payload file: {PAYLOADS_FILE}")
        return
    if not os.path.exists(PAYLOADS_META_FILE):
        print(f"[WARN] missing payload meta file: {PAYLOADS_META_FILE}")
        return

    with open(PAYLOADS_META_FILE, encoding="utf-8") as f:
        points_meta = json.load(f)
    with open(PAYLOADS_FILE, encoding="utf-8") as f:
        payloads = json.load(f)
    targets = None
    if os.path.exists(targets_file):
        with open(targets_file, encoding="utf-8") as f:
            targets = json.load(f)

    base_cookies: dict = {}
    cookies_file = _run_path("auth_cookies.json")
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
    _emit_progress(35)


def _task_execute():
    from fuzzer.executor import execute

    fuzz_tasks_file = _run_path("fuzz_tasks.json")
    exec_file = _run_path("execution_results.json")
    if not os.path.exists(fuzz_tasks_file):
        print(f"[ERROR] missing fuzz task file: {fuzz_tasks_file}")
        return

    with open(fuzz_tasks_file, encoding="utf-8") as f:
        tasks = json.load(f)

    def _execute_progress(done: int, total: int) -> None:
        _emit_progress(35 + int(done / max(total, 1) * 55))

    print(f"[EXEC] start: {len(tasks)} tasks")
    results = execute(tasks, timeout=10, delay=0.0, output_file=exec_file, progress_callback=_execute_progress)
    ok = sum(1 for r in results if r.get("error") is None)
    timeout = sum(1 for r in results if r.get("error") == "timeout")
    err = sum(1 for r in results if r.get("error") and r.get("error") != "timeout")
    print(f"[EXEC] done: ok={ok}, timeout={timeout}, error={err}")
    _emit_progress(90)


def _task_validate():
    from fuzzer.validator import run as validate_run

    exec_file = _run_path("execution_results.json")
    findings_file = _run_path("findings.json")
    if not os.path.exists(exec_file):
        print(f"[ERROR] missing execution result file: {exec_file}")
        return

    def _validate_progress(done: int, total: int) -> None:
        _emit_progress(90 + int(done / max(total, 1) * 10))

    findings = validate_run(input_file=exec_file, output_file=findings_file, progress_callback=_validate_progress)
    xss_cnt = sum(1 for f in findings if "xss" in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sql" in (f.get("vuln_type") or "").lower())
    print(f"[VALIDATE] done: findings={len(findings)}, xss={xss_cnt}, sqli={sqli_cnt}")
    _emit_progress(100)


def _task_all(skip_crawl: bool = False):
    _emit_progress(2)

    # Step 1: Crawling
    if skip_crawl:
        print("[CRAWL] 이전 크롤링 결과 재사용")
        _emit_progress(20)
    else:
        _task_crawl()
        _emit_progress(20)

    # Prerequisite: crawl result must exist
    if not os.path.exists(_run_path("crawl_result.json")):
        print("[ERROR] 크롤링 결과 파일 없음 — 스캔 중단")
        return

    # Step 2: Payload — reuse LLM payloads if already generated (API cost)
    if os.path.exists(PAYLOADS_FILE):
        try:
            with open(PAYLOADS_FILE, encoding="utf-8") as _f:
                _cnt = len(json.load(_f))
        except Exception:
            _cnt = 0
        print(f"[PAYLOAD] 기존 페이로드 재사용 ({_cnt}개) — 새로 생성하려면 파일 삭제 후 재스캔")
        _emit_progress(30)
    else:
        _task_payload()
        _emit_progress(30)

    # Prerequisite: payload file must exist
    if not os.path.exists(PAYLOADS_FILE):
        print("[ERROR] 페이로드 파일 없음 — 스캔 중단")
        return

    # Step 3: Fuzz task generation
    _task_fuzz()
    _emit_progress(35)

    # Prerequisite: fuzz tasks must exist
    if not os.path.exists(_run_path("fuzz_tasks.json")):
        print("[ERROR] 퍼징 작업 파일 없음 — 스캔 중단")
        return

    # Step 4: Execute
    _task_execute()
    _emit_progress(90)

    # Prerequisite: execution results must exist
    if not os.path.exists(_run_path("execution_results.json")):
        print("[ERROR] 실행 결과 파일 없음 — 스캔 중단")
        return

    # Step 5: Validate
    _task_validate()
    _emit_progress(100)


_TASK_FUNCS = {
    "crawl": _task_crawl,
    "payload": _task_payload,
    "scan": _task_scan,
    "fuzz": _task_fuzz,
    "execute": _task_execute,
    "validate": _task_validate,
    "all": _task_all,
}

_TASK_LABELS = {
    "crawl": "크롤링 및 타깃 구성",
    "payload": "페이로드 생성",
    "scan": "스캔 실행",
    "fuzz": "퍼징 전략 수립",
    "execute": "퍼징 실행",
    "validate": "취약점 판정",
    "all": "전체 진단",
}


@app.route("/stream/<task>")
def stream_task(task):
    if task not in _TASK_FUNCS:
        return "알 수 없는 태스크", 404

    skip_crawl = request.args.get("skip_crawl") == "1"
    q = queue.Queue()

    def run_in_thread():
        acquired = _task_lock.acquire(blocking=False)
        if not acquired:
            q.put("[WARN] 다른 태스크가 실행 중입니다.")
            q.put(None)
            return
        _thread_local.log_queue = q
        try:
            if task == "all":
                _task_all(skip_crawl=skip_crawl)
            else:
                _TASK_FUNCS[task]()
        except Exception as exc:
            q.put(f"[ERROR] {type(exc).__name__}: {exc}")
        finally:
            _thread_local.log_queue = None
            _task_lock.release()
            q.put(None)

    threading.Thread(target=run_in_thread, daemon=True).start()

    def generate():
        label = _TASK_LABELS.get(task, task)
        yield f"data: [{label}] 시작\n\n"
        while True:
            try:
                msg = q.get(timeout=2)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            if msg is None:
                yield f"data: [{label}] 완료\n\n"
                yield "data: __DONE__\n\n"
                break
            safe = msg.replace("\n", " ")
            yield f"data: {safe}\n\n"

    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _list_runs() -> list[dict]:
    if not os.path.exists(RUNS_DIR):
        return []
    runs = []
    for d in sorted(os.listdir(RUNS_DIR), reverse=True):
        full = os.path.join(RUNS_DIR, d)
        if not os.path.isdir(full) or not d.startswith("run_"):
            continue
        files = set(os.listdir(full))
        try:
            ts = datetime.strptime(d, "run_%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = d
        findings_cnt = 0
        if "findings.json" in files:
            try:
                with open(os.path.join(full, "findings.json"), encoding="utf-8") as f:
                    findings_cnt = len(json.load(f))
            except Exception:
                pass
        runs.append({
            "id": d,
            "ts": ts,
            "is_current": d == _current_run_id,
            "has_crawl": "crawl_result.json" in files,
            "has_exec": "execution_results.json" in files,
            "has_findings": "findings.json" in files,
            "findings_cnt": findings_cnt,
        })
    return runs


def _get_file_status():
    return [
        ("크롤링 결과", os.path.exists(_run_path("crawl_result.json"))),
        ("타깃 목록", os.path.exists(_run_path("targets.json"))),
        ("페이로드", os.path.exists(PAYLOADS_FILE)),
        ("퍼징 작업", os.path.exists(_run_path("fuzz_tasks.json"))),
        ("실행 결과", os.path.exists(_run_path("execution_results.json"))),
        ("취약점 결과", os.path.exists(_run_path("findings.json"))),
    ]


def _get_quick_summary():
    scan_file = _run_path("scan_results.json")
    if not os.path.exists(scan_file):
        return None
    try:
        with open(scan_file, encoding="utf-8") as f:
            results = json.load(f)
        total = len(results)
        vulns = sum(1 for r in results if r.get("vulnerable"))
        return {"total": total, "vulns": vulns, "rate": vulns / max(total, 1) * 100}
    except Exception:
        return None


def _get_exec_summary():
    exec_file = _run_path("execution_results.json")
    if not os.path.exists(exec_file):
        return None
    try:
        with open(exec_file, encoding="utf-8") as f:
            results = json.load(f)
        total = len(results)
        ok = sum(1 for r in results if r.get("error") is None)
        timeout = sum(1 for r in results if r.get("error") == "timeout")
        return {"total": total, "ok": ok, "timeout": timeout}
    except Exception:
        return None


def _get_pipeline_steps():
    checks = [
        ("crawl", "크롤러", "travel_explore", os.path.exists(_run_path("crawl_result.json")) and os.path.exists(_run_path("targets.json"))),
        ("payload", "페이로드", "psychology", os.path.exists(PAYLOADS_FILE)),
        ("fuzz", "퍼징 전략", "pest_control", os.path.exists(_run_path("fuzz_tasks.json"))),
        ("execute", "실행기", "terminal", os.path.exists(_run_path("execution_results.json"))),
        ("validate", "분석기", "analytics", os.path.exists(_run_path("findings.json"))),
    ]
    active_assigned = False
    steps = []
    for key, label, icon, complete in checks:
        state = "complete" if complete else "pending"
        if not complete and not active_assigned:
            state = "active"
            active_assigned = True
        steps.append({"key": key, "label": label, "icon": icon, "state": state})
    return steps


def _get_pipeline_progress():
    steps = _get_pipeline_steps()
    complete = sum(1 for step in steps if step["state"] == "complete")
    total = max(len(steps), 1)
    return {"complete": complete, "total": total, "percent": int(round(complete / total * 100))}


def _get_target_envs():
    result = []
    for target in _TARGETS:
        is_active = target["key"] == _active_target_key
        result.append({
            "name": target["name"],
            "key": target["key"],
            "url": target["url"],
            "version": target["version"],
            "is_active": is_active,
            "status": "active" if is_active else "standby",
            "status_label": "스캔 대상" if is_active else "대기 중",
            "last_scanned": _current_run_id or "-" if is_active else "-",
        })
    return result


@app.route("/")
def index():
    _dbg("H2", "GET /", {"buildId": _DBG_BUILD_ID})
    return render_template(
        "index.html",
        cms_name=CMS_NAME,
        base_url=_active_url(),
        file_status=_get_file_status(),
        pipeline_steps=_get_pipeline_steps(),
        pipeline_progress=_get_pipeline_progress(),
        summary=_get_quick_summary(),
        exec_summary=_get_exec_summary(),
        targets=_get_target_envs(),
        current_run=_current_run_id or "",
    )


@app.route("/results")
def results_page():
    scan_file = _run_path("scan_results.json")
    if not os.path.exists(scan_file):
        return render_template("results.html", results=None, total=0, n_vuln=0, rate=0.0)
    try:
        with open(scan_file, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500
    total = len(results)
    n_vuln = sum(1 for r in results if r.get("vulnerable"))
    rate = n_vuln / max(total, 1) * 100
    return render_template("results.html", results=results, total=total, n_vuln=n_vuln, rate=rate)


@app.route("/findings")
def findings_page():
    run_id = request.args.get("run") or _current_run_id
    findings_file = _run_path("findings.json", run_id=run_id)
    if not os.path.exists(findings_file):
        return render_template("findings.html", findings=None, xss_cnt=0, sqli_cnt=0, run_id=run_id, current_run=_current_run_id)
    try:
        with open(findings_file, encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500
    xss_cnt = sum(1 for f in findings if "xss" in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sql" in (f.get("vuln_type") or "").lower())
    return render_template("findings.html", findings=findings, xss_cnt=xss_cnt, sqli_cnt=sqli_cnt, run_id=run_id, current_run=_current_run_id)


@app.route("/exec_results")
def exec_results_page():
    run_id = request.args.get("run") or _current_run_id
    exec_file = _run_path("execution_results.json", run_id=run_id)
    if not os.path.exists(exec_file):
        return render_template("exec_results.html", results=None, total=0, ok=0, timeout=0, err=0, run_id=run_id, current_run=_current_run_id)
    try:
        with open(exec_file, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500
    total = len(results)
    ok = sum(1 for r in results if r.get("error") is None)
    timeout = sum(1 for r in results if r.get("error") == "timeout")
    err = sum(1 for r in results if r.get("error") and r.get("error") != "timeout")
    return render_template("exec_results.html", results=results, total=total, ok=ok, timeout=timeout, err=err, run_id=run_id, current_run=_current_run_id)


@app.route("/targets")
def targets_page():
    return render_template("targets.html", targets=_get_target_envs())


@app.route("/settings/target", methods=["POST"])
def set_target():
    global _active_target_key
    key = request.form.get("key")
    if any(t["key"] == key for t in _TARGETS):
        _active_target_key = key
    return redirect("/targets")


@app.route("/runs")
def runs_page():
    return render_template("runs.html", runs=_list_runs(), current_run=_current_run_id)


@app.route("/runs/new", methods=["POST"])
def new_run():
    global _current_run_id
    _current_run_id = _make_run_id()
    os.makedirs(os.path.join(RUNS_DIR, _current_run_id), exist_ok=True)
    return redirect("/")


@app.route("/runs/set/<run_id>", methods=["POST"])
def set_run(run_id):
    global _current_run_id
    if os.path.isdir(os.path.join(RUNS_DIR, run_id)):
        _current_run_id = run_id
    return redirect("/runs")


@app.route("/runs/delete/<run_id>", methods=["POST"])
def delete_run(run_id):
    import shutil

    global _current_run_id
    run_dir = os.path.join(RUNS_DIR, run_id)
    if os.path.isdir(run_dir) and run_id.startswith("run_"):
        shutil.rmtree(run_dir)
        if _current_run_id == run_id:
            _init_run()
    return redirect("/runs")


if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    _init_run()
    print("LADS dashboard: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
