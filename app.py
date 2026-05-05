import importlib
import os
import re
import subprocess
import sys
import time
import hashlib
import uuid
from datetime import datetime


# ── 의존성 자동 설치 ──────────────────────────────────────────────
_DEPS = {
    "flask":         "flask",
    "python-dotenv": "dotenv",
    "requests":      "requests",
    "beautifulsoup4":"bs4",
    "lxml":          "lxml",
    "openai":        "openai",
}

for _pkg, _mod in _DEPS.items():
    try:
        importlib.import_module(_mod)
    except ImportError:
        print(f"[INSTALL] {_pkg} 설치 중...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", _pkg, "-q"])
del _pkg, _mod


import json
import queue
import threading
from pathlib import Path

from flask import Flask, Response, render_template, request
from dotenv import load_dotenv

load_dotenv()


# ── 설정 ─────────────────────────────────────────────────────────
BASE_URL           = os.getenv("TARGET_URL",        "http://34.68.27.120:8081")
TARGET_URL_2       = os.getenv("TARGET_URL_2",      "http://34.68.27.120:8080")
CMS_NAME           = "Gnuboard5 5.3.2.8"
PAYLOADS_FILE      = os.getenv("PAYLOADS_FILE",     "results/payloads_llm.json")
SCAN_RESULTS_FILE  = os.getenv("SCAN_RESULTS_FILE", "results/scan_results_llm.json")
PAYLOADS_META_FILE = os.getenv("PAYLOADS_META_FILE","results/payloads_llm_meta.json")
RUNS_DIR           = "runs"
_TARGETS = [
    {"key": "primary",   "name": "Gnuboard5 (8081)", "url": BASE_URL,    "version": CMS_NAME},
    {"key": "secondary", "name": "Gnuboard5 (8080)", "url": TARGET_URL_2, "version": "Test Env"},
]
_active_target_key: str = "primary"

# ── Run 관리 ──────────────────────────────────────────────────────
_current_run_id: str | None = None


def _make_run_id() -> str:
    return datetime.now().strftime("run_%Y%m%d_%H%M%S")


def _init_run():
    global _current_run_id
    os.makedirs(RUNS_DIR, exist_ok=True)
    existing = sorted(
        [d for d in os.listdir(RUNS_DIR)
         if os.path.isdir(os.path.join(RUNS_DIR, d)) and d.startswith("run_")],
        reverse=True,
    )
    if existing:
        _current_run_id = existing[0]
    else:
        _current_run_id = _make_run_id()
        os.makedirs(os.path.join(RUNS_DIR, _current_run_id), exist_ok=True)


def _run_path(filename: str) -> str:
    return os.path.join(RUNS_DIR, _current_run_id or "default", filename)


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
            "id":          d,
            "ts":          ts,
            "is_current":  d == _current_run_id,
            "has_crawl":   "crawl_result.json"      in files,
            "has_exec":    "execution_results.json"  in files,
            "has_findings":"findings.json"           in files,
            "findings_cnt": findings_cnt,
        })
    return runs

app = Flask(__name__)
_task_lock    = threading.Lock()
_thread_local = threading.local()


# #region agent log
_DBG_LOG_PATH = Path(__file__).with_name("debug-3194ca.log")
_DBG_BUILD_ID = os.getenv("LADS_BUILD_ID") or datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]


def _dbg(hypothesis_id: str, message: str, data: dict | None = None) -> None:
    try:
        payload = {
            "sessionId": "3194ca",
            "runId": "pre-fix",
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


def _tmpl_fingerprint() -> str:
    try:
        template_dir = Path(__file__).with_name("templates")
        static_js = Path(__file__).with_name("static").joinpath("js", "app.js")
        chunks = []
        for path in sorted(template_dir.glob("*.html")):
            chunks.append(path.read_text(encoding="utf-8"))
        if static_js.exists():
            chunks.append(static_js.read_text(encoding="utf-8"))
        s = "\n".join(chunks).encode("utf-8", errors="ignore")
        return hashlib.sha256(s).hexdigest()[:12]
    except Exception:
        return "unknown"


_dbg(
    "H1",
    "startup",
    {
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "file": str(Path(__file__).resolve()),
        "mtime": int(Path(__file__).stat().st_mtime),
        "buildId": _DBG_BUILD_ID,
    },
)
# #endregion agent log


# ── stdout 라우팅 스트림 ──────────────────────────────────────────
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


# ── 태스크 함수 ───────────────────────────────────────────────────

def _emit_progress(pct: int) -> None:
    q = getattr(_thread_local, "log_queue", None)
    if q is not None:
        q.put(f"__PROGRESS__{max(0, min(100, pct))}")


def _active_url() -> str:
    t = next((t for t in _TARGETS if t["key"] == _active_target_key), _TARGETS[0])
    return t["url"]


def _task_crawl():
    from crawler import Crawler
    from target_builder import build_targets, print_summary

    crawl_file   = _run_path("crawl_result.json")
    targets_file = _run_path("targets.json")
    target_url   = _active_url()

    print(f"크롤링 시작: {target_url}")
    crawler = Crawler(target_url)

    def _crawl_progress(done: int, total: int) -> None:
        pct = int(done / max(total, 1) * 20)  # 크롤링 구간: 0~20%
        _emit_progress(pct)

    crawler.crawl(progress_callback=_crawl_progress)
    crawler.save(crawl_file)
    crawler.summary()

    print(f"타겟 구성 시작: {crawl_file}")
    with open(crawl_file, encoding="utf-8") as f:
        pages = json.load(f)
    targets = build_targets(pages)

    with open(targets_file, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)

    print(f"타겟 구성 완료: {targets_file} ({len(targets)}개)")
    print_summary(targets)


def _task_payload():
    from payload.generate_payloads import run as generate_run

    os.makedirs("results", exist_ok=True)
    print(f"LLM 페이로드 생성 시작 (출력: {PAYLOADS_FILE})")

    def _payload_progress(done: int, total: int) -> None:
        pct = 20 + int(done / max(total, 1) * 10)  # 페이로드 구간: 20~30%
        _emit_progress(pct)

    generate_run(out_file=PAYLOADS_FILE, progress_callback=_payload_progress)


def _task_scan():
    import scanner

    targets_file = _run_path("targets.json")
    scan_out     = _run_path("scan_results.json")

    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] {PAYLOADS_FILE} 없음. 페이로드를 먼저 생성하세요.")
        return

    old_argv = sys.argv[:]
    argv_list = ["scanner.py", "--payloads", PAYLOADS_FILE, "--out", scan_out]
    if os.path.exists(targets_file):
        argv_list += ["--targets", targets_file]

    sys.argv = argv_list
    try:
        scanner.main()
    except SystemExit as e:
        if e.code and e.code != 0:
            print(f"[ERROR] 스캐너 종료: exit code {e.code}")
    finally:
        sys.argv = old_argv


def _task_fuzz():
    from fuzzer.fuzzing_strategy import build_tasks

    targets_file    = _run_path("targets.json")
    fuzz_tasks_file = _run_path("fuzz_tasks.json")

    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] {PAYLOADS_FILE} 없음. 페이로드 생성을 먼저 실행하세요.")
        return

    if not os.path.exists(PAYLOADS_META_FILE):
        print(f"[WARN] {PAYLOADS_META_FILE} 없음.")
        return

    with open(PAYLOADS_META_FILE, encoding="utf-8") as f:
        points_meta = json.load(f)

    with open(PAYLOADS_FILE, encoding="utf-8") as f:
        payloads = json.load(f)

    targets = None
    if os.path.exists(targets_file):
        with open(targets_file, encoding="utf-8") as f:
            targets = json.load(f)

    print(f"meta={len(points_meta)} payload_points={len(payloads)}")

    def _fuzz_progress(done: int, total: int) -> None:
        pct = 30 + int(done / max(total, 1) * 5)  # 스캔작업 구간: 30~35%
        _emit_progress(pct)

    tasks = build_tasks(points_meta, payloads, targets, progress_callback=_fuzz_progress)

    with open(fuzz_tasks_file, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)

    replace_ = sum(1 for t in tasks if t.get("inject_mode") == "replace")
    append_  = sum(1 for t in tasks if t.get("inject_mode") == "append")
    print(f"완료: {len(tasks)} 태스크 → {fuzz_tasks_file}")
    print(f"mode → replace: {replace_}, append: {append_}")


def _task_execute():
    from fuzzer.executor import execute

    fuzz_tasks_file = _run_path("fuzz_tasks.json")
    exec_file       = _run_path("execution_results.json")

    if not os.path.exists(fuzz_tasks_file):
        print(f"[ERROR] {fuzz_tasks_file} 없음. 전략 수립을 먼저 실행하세요.")
        return

    with open(fuzz_tasks_file, encoding="utf-8") as f:
        tasks = json.load(f)

    total_tasks = len(tasks)
    print(f"{total_tasks} 요청 실행 시작")

    def _on_progress(done: int, total: int) -> None:
        # executor 진행률(0~100%) → 전체 파이프라인 35~90% 구간에 매핑
        pct = 35 + int(done / max(total, 1) * 55)
        _emit_progress(pct)
        if done % max(total // 10, 1) == 0 or done == total:
            print(f"  [{done}/{total}] {int(done/max(total,1)*100)}% 완료")

    results = execute(tasks, timeout=10, delay=0.0, output_file=exec_file, progress_callback=_on_progress)

    ok      = sum(1 for r in results if r["error"] is None)
    timeout = sum(1 for r in results if r["error"] == "timeout")
    err     = sum(1 for r in results if r["error"] and r["error"] != "timeout")
    print(f"완료: 성공 {ok} / 타임아웃 {timeout} / 오류 {err} → {exec_file}")


def _task_validate():
    from fuzzer.validator import run as validate_run

    exec_file     = _run_path("execution_results.json")
    findings_file = _run_path("findings.json")

    if not os.path.exists(exec_file):
        print(f"[ERROR] {exec_file} 없음. 퍼징 실행을 먼저 하세요.")
        return

    print(f"분석 중: {exec_file}")

    def _validate_progress(done: int, total: int) -> None:
        pct = 90 + int(done / max(total, 1) * 10)  # 결과분석 구간: 90~100%
        _emit_progress(pct)

    findings = validate_run(input_file=exec_file, output_file=findings_file, progress_callback=_validate_progress)

    xss_cnt  = sum(1 for f in findings if "xss"  in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sqli" in (f.get("vuln_type") or "").lower())

    print(f"완료: 취약점 {len(findings)}개 발견 → {findings_file}")
    print(f"XSS: {xss_cnt}개  /  SQLi: {sqli_cnt}개")
    for f in findings:
        print(f"  [{f['vuln_type']:20s}] {f['point']} | {f['payload'][:50]} | {f['evidence']}")


def _task_all(skip_crawl: bool = False):
    """전체 DAST 파이프라인: 크롤링 → 페이로드 → 스캔 작업 생성 → 활성 스캔 → 결과 분석"""
    _emit_progress(2)

    if skip_crawl:
        print("[건너뜀] 크롤링 재사용")
        _emit_progress(20)
    else:
        _task_crawl()
        _emit_progress(20)

    if not os.path.exists(PAYLOADS_FILE):
        print("[INFO] 페이로드 파일 없음 — 자동 생성 시작")
        _task_payload()
    else:
        print(f"[건너뜀] 페이로드 재사용: {PAYLOADS_FILE}")
    _emit_progress(30)

    _task_fuzz()
    _emit_progress(35)

    _task_execute()   # 내부에서 35→90% 구간 실시간 emit
    _emit_progress(90)

    _task_validate()
    _emit_progress(100)


_TASK_FUNCS = {
    "crawl"   : _task_crawl,
    "payload" : _task_payload,
    "scan"    : _task_scan,
    "fuzz"    : _task_fuzz,
    "execute" : _task_execute,
    "validate": _task_validate,
    "all"     : _task_all,
}

_TASK_LABELS = {
    "crawl"   : "크롤링",
    "payload" : "페이로드 준비",
    "scan"    : "스캔 실행",
    "fuzz"    : "스캔 작업 생성",
    "execute" : "활성 스캔",
    "validate": "결과 분석",
    "all"     : "전체 진단",
}


# ── SSE 라우트 ────────────────────────────────────────────────────


@app.route("/stream/<task>")
def stream_task(task):
    if task not in _TASK_FUNCS:
        return "알 수 없는 태스크", 404

    skip_crawl = request.args.get("skip_crawl") == "1"

    q = queue.Queue()

    def run_in_thread():
        acquired = _task_lock.acquire(blocking=False)
        if not acquired:
            q.put("[WARN] 다른 태스크가 실행 중입니다. 완료 후 다시 시도하세요.")
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
            if msg.startswith("__PROGRESS__"):
                yield f"data: {msg}\n\n"
                continue
            safe = msg.replace("\n", " ")
            yield f"data: {safe}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── 상태 헬퍼 ─────────────────────────────────────────────────────

def _get_file_status():
    return [
        ("크롤링 결과", os.path.exists(_run_path("crawl_result.json"))),
        ("타겟 목록",   os.path.exists(_run_path("targets.json"))),
        ("페이로드",    os.path.exists(PAYLOADS_FILE)),
        ("퍼징 작업",   os.path.exists(_run_path("fuzz_tasks.json"))),
        ("실행 결과",   os.path.exists(_run_path("execution_results.json"))),
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
        total   = len(results)
        ok      = sum(1 for r in results if r.get("error") is None)
        timeout = sum(1 for r in results if r.get("error") == "timeout")
        return {"total": total, "ok": ok, "timeout": timeout}
    except Exception:
        return None


def _get_file_status():
    return [
        ("크롤링 결과", os.path.exists(_run_path("crawl_result.json"))),
        ("타깃 목록",   os.path.exists(_run_path("targets.json"))),
        ("페이로드",    os.path.exists(PAYLOADS_FILE)),
        ("퍼징 작업",   os.path.exists(_run_path("fuzz_tasks.json"))),
        ("실행 결과",   os.path.exists(_run_path("execution_results.json"))),
        ("취약점 결과", os.path.exists(_run_path("findings.json"))),
    ]


def _get_pipeline_steps():
    checks = [
        ("crawl",    "크롤링",          "travel_explore", os.path.exists(_run_path("crawl_result.json")) and os.path.exists(_run_path("targets.json"))),
        ("payload",  "페이로드 준비",  "psychology",     os.path.exists(PAYLOADS_FILE)),
        ("fuzz",     "스캔 작업 생성", "build",          os.path.exists(_run_path("fuzz_tasks.json"))),
        ("execute",  "활성 스캔",      "radar",          os.path.exists(_run_path("execution_results.json"))),
        ("validate", "결과 분석",      "analytics",      os.path.exists(_run_path("findings.json"))),
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


def _get_target_envs():
    result = []
    for t in _TARGETS:
        is_active = t["key"] == _active_target_key
        result.append({
            "name":         t["name"],
            "key":          t["key"],
            "url":          t["url"],
            "version":      t["version"],
            "is_active":    is_active,
            "status":       "active" if is_active else "standby",
            "status_label": "스캔 대상" if is_active else "대기 중",
            "last_scanned": _current_run_id or "-" if is_active else "-",
        })
    return result


# ── placeholder (하위 호환) ────────────────────────────────────────
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




def _get_pipeline_progress():
    steps = _get_pipeline_steps()
    complete = sum(1 for step in steps if step["state"] == "complete")
    total = max(len(steps), 1)
    percent = int(round(complete / total * 100))
    return {"complete": complete, "total": total, "percent": percent}


@app.route("/")
def index():
    # #region agent log
    _dbg(
        "H2",
        "GET /",
        {
            "pid": os.getpid(),
            "buildId": _DBG_BUILD_ID,
            "tmplFp": _tmpl_fingerprint(),
            "ua": (request.headers.get("User-Agent") or "")[:120],
            "addr": request.remote_addr,
        },
    )
    # #endregion agent log
    return render_template(
        "index.html",
        cms_name     = CMS_NAME,
        base_url     = BASE_URL,
        file_status  = _get_file_status(),
        pipeline_steps = _get_pipeline_steps(),
        pipeline_progress = _get_pipeline_progress(),
        summary      = _get_quick_summary(),
        exec_summary = _get_exec_summary(),
        targets      = _get_target_envs(),
        current_run  = _current_run_id or "",
    )


@app.route("/__debug_build")
def __debug_build():
    # #region agent log
    _dbg("H3", "GET /__debug_build", {"pid": os.getpid(), "buildId": _DBG_BUILD_ID, "tmplFp": _tmpl_fingerprint()})
    # #endregion agent log
    return {
        "pid": os.getpid(),
        "buildId": _DBG_BUILD_ID,
        "tmplFp": _tmpl_fingerprint(),
        "file": str(Path(__file__).resolve()),
    }


@app.route("/results")
def results_page():
    if not os.path.exists(SCAN_RESULTS_FILE):
        return render_template("results.html", results=None, total=0, n_vuln=0, rate=0.0)
    try:
        with open(SCAN_RESULTS_FILE, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500

    total  = len(results)
    n_vuln = sum(1 for r in results if r.get("vulnerable"))
    rate   = n_vuln / max(total, 1) * 100
    return render_template("results.html", results=results, total=total, n_vuln=n_vuln, rate=rate)


@app.route("/findings")
def findings_page():
    run_id = request.args.get("run") or _current_run_id
    findings_file = os.path.join(RUNS_DIR, run_id or "default", "findings.json") if run_id else _run_path("findings.json")
    if not os.path.exists(findings_file):
        return render_template("findings.html", findings=None, xss_cnt=0, sqli_cnt=0, run_id=run_id, current_run=_current_run_id)
    try:
        with open(findings_file, encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500
    xss_cnt  = sum(1 for f in findings if "xss"  in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sqli" in (f.get("vuln_type") or "").lower())
    return render_template("findings.html", findings=findings, xss_cnt=xss_cnt, sqli_cnt=sqli_cnt, run_id=run_id, current_run=_current_run_id)


@app.route("/exec_results")
def exec_results_page():
    run_id = request.args.get("run") or _current_run_id
    exec_file = os.path.join(RUNS_DIR, run_id or "default", "execution_results.json") if run_id else _run_path("execution_results.json")
    if not os.path.exists(exec_file):
        return render_template("exec_results.html", results=None, total=0, ok=0, timeout=0, err=0, run_id=run_id, current_run=_current_run_id)
    try:
        with open(exec_file, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500
    total   = len(results)
    ok      = sum(1 for r in results if r.get("error") is None)
    timeout = sum(1 for r in results if r.get("error") == "timeout")
    err     = sum(1 for r in results if r.get("error") and r.get("error") != "timeout")
    return render_template("exec_results.html", results=results, total=total, ok=ok, timeout=timeout, err=err, run_id=run_id, current_run=_current_run_id)


@app.route("/runs")
def runs_page():
    runs = _list_runs()
    return render_template("runs.html", runs=runs, current_run=_current_run_id)


@app.route("/targets")
def targets_page():
    return render_template("targets.html", targets=_get_target_envs())


@app.route("/runs/new", methods=["POST"])
def new_run():
    global _current_run_id
    _current_run_id = _make_run_id()
    os.makedirs(os.path.join(RUNS_DIR, _current_run_id), exist_ok=True)
    from flask import redirect
    return redirect("/")


@app.route("/runs/set/<run_id>", methods=["POST"])
def set_run(run_id):
    global _current_run_id
    if os.path.isdir(os.path.join(RUNS_DIR, run_id)):
        _current_run_id = run_id
    from flask import redirect
    return redirect("/runs")


@app.route("/runs/delete/<run_id>", methods=["POST"])
def delete_run(run_id):
    import shutil
    from flask import redirect
    run_dir = os.path.join(RUNS_DIR, run_id)
    if os.path.isdir(run_dir) and run_id.startswith("run_"):
        shutil.rmtree(run_dir)
        global _current_run_id
        if _current_run_id == run_id:
            runs = sorted(
                [d for d in os.listdir(RUNS_DIR)
                 if os.path.isdir(os.path.join(RUNS_DIR, d)) and d.startswith("run_")],
                reverse=True,
            )
            _current_run_id = runs[0] if runs else _make_run_id()
            if not runs:
                os.makedirs(os.path.join(RUNS_DIR, _current_run_id), exist_ok=True)
    return redirect("/runs")


@app.route("/settings/target", methods=["POST"])
def set_target():
    global _active_target_key
    from flask import redirect
    key = request.form.get("key", "")
    if any(t["key"] == key for t in _TARGETS):
        _active_target_key = key
    return redirect("/")


@app.route("/runs/delete-all", methods=["POST"])
def delete_all_runs():
    import shutil
    from flask import redirect
    global _current_run_id
    if os.path.exists(RUNS_DIR):
        for d in os.listdir(RUNS_DIR):
            full = os.path.join(RUNS_DIR, d)
            if os.path.isdir(full) and d.startswith("run_") and d != _current_run_id:
                shutil.rmtree(full)
    return redirect("/runs")


_COMMON_HEAD = ""
_MENU_SCRIPT = ""


def _nav(title=""):
    return ""


_RUNS_HTML = """\
<!DOCTYPE html>
<html lang="ko">
<head>
  <title>LADS - 실행 이력</title>
""" + _COMMON_HEAD + """
</head>
<body>
""" + _nav("실행 이력") + """
<main class="page-shell-wide">
  <section class="mb-4">
    <div class="eyebrow">진단 기록</div>
    <h1 class="page-title">실행 이력</h1>
    <p class="page-subtitle">저장된 진단 기록을 확인하고, 현재 사용할 실행 기록을 선택합니다.</p>
    <form method="POST" action="/runs/new" class="mt-3">
      <button class="btn btn-primary">새 실행 생성</button>
    </form>
  </section>
  {% if not runs %}
  <div class="empty-state">아직 실행 이력이 없습니다.</div>
  {% else %}
  <section class="section-card">
    <div class="card-header">실행 목록</div>
    <div class="table-responsive">
      <table class="table align-middle">
        <thead><tr><th>실행 ID</th><th>시작 시각</th><th>크롤링</th><th>실행</th><th>취약점</th><th>상태</th><th>관리</th></tr></thead>
        <tbody>
        {% for r in runs %}
          <tr class="{% if r.is_current %}safe-row{% endif %}">
            <td><code>{{ r.id }}</code></td>
            <td>{{ r.ts }}</td>
            <td>{% if r.has_crawl %}<span class="badge bg-success">있음</span>{% else %}<span class="badge bg-secondary">없음</span>{% endif %}</td>
            <td>{% if r.has_exec %}<span class="badge bg-success">있음</span>{% else %}<span class="badge bg-secondary">없음</span>{% endif %}</td>
            <td>{% if r.has_findings %}<span class="badge bg-danger">{{ r.findings_cnt }}건</span>{% else %}<span class="badge bg-secondary">없음</span>{% endif %}</td>
            <td>{% if r.is_current %}<span class="badge bg-dark">현재</span>{% endif %}</td>
            <td><div class="d-flex gap-2 flex-wrap">
              {% if not r.is_current %}<form method="POST" action="/runs/set/{{ r.id }}"><button class="btn btn-outline-dark btn-sm">선택</button></form>{% endif %}
              <a href="/findings?run={{ r.id }}" class="btn btn-outline-success btn-sm">결과</a>
              {% if not r.is_current %}<form method="POST" action="/runs/delete/{{ r.id }}" onsubmit="return confirm('이 실행 기록을 삭제할까요?')"><button class="btn btn-outline-danger btn-sm">삭제</button></form>{% endif %}
            </div></td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </section>
  {% endif %}
</main>
""" + _MENU_SCRIPT + """
</body>
</html>
"""


# ── 서버 시작 ─────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    _init_run()
    print(f"LADS 대시보드 시작: http://localhost:5000")
    print(f"타겟: {BASE_URL}  |  현재 실행: {_current_run_id}")
    # debug=True(또는 FLASK_DEBUG=1): 코드·템플릿 변경 시 자동 재시작·반영. 배포 시 FLASK_DEBUG=0 권장.
    _flask_debug = os.environ.get("FLASK_DEBUG", "1").strip().lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=5000, debug=_flask_debug, threaded=True)
