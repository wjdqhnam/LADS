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

from flask import Flask, Response, render_template_string, request
from dotenv import load_dotenv

load_dotenv()


# ── 설정 ─────────────────────────────────────────────────────────
BASE_URL           = os.getenv("TARGET_URL",        "http://34.68.27.120:8081")
CMS_NAME           = "Gnuboard5 5.3.2.8"
PAYLOADS_FILE      = os.getenv("PAYLOADS_FILE",     "results/payloads_llm.json")
SCAN_RESULTS_FILE  = os.getenv("SCAN_RESULTS_FILE", "results/scan_results_llm.json")
PAYLOADS_META_FILE = os.getenv("PAYLOADS_META_FILE","results/payloads_llm_meta.json")
RUNS_DIR           = "runs"

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
        s = (_COMMON_HEAD + _MAIN_HTML + _RESULTS_HTML + _EXEC_HTML).encode("utf-8", errors="ignore")
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

def _task_crawl():
    from crawler import Crawler
    from target_builder import build_targets, print_summary

    crawl_file   = _run_path("crawl_result.json")
    targets_file = _run_path("targets.json")

    print(f"크롤링 시작: {BASE_URL}")
    crawler = Crawler(BASE_URL)
    crawler.crawl()
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
    generate_run(out_file=PAYLOADS_FILE)


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
    tasks = build_tasks(points_meta, payloads, targets)

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

    print(f"{len(tasks)} 태스크 실행 시작")
    results = execute(tasks, timeout=10, delay=0.0, output_file=exec_file)

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
    findings = validate_run(input_file=exec_file, output_file=findings_file)

    xss_cnt  = sum(1 for f in findings if "xss"  in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sqli" in (f.get("vuln_type") or "").lower())

    print(f"완료: 취약점 {len(findings)}개 발견 → {findings_file}")
    print(f"XSS: {xss_cnt}개  /  SQLi: {sqli_cnt}개")
    for f in findings:
        print(f"  [{f['vuln_type']:20s}] {f['point']} | {f['payload'][:50]} | {f['evidence']}")


def _task_all(skip_crawl: bool = False, skip_payload: bool = False):
    if skip_crawl:
        print(f"[건너뜀] 크롤링 재사용")
    else:
        _task_crawl()

    if skip_payload:
        print(f"[건너뜀] 페이로드 생성 — {PAYLOADS_FILE} 재사용")
    else:
        _task_payload()

    _task_scan()


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
    "crawl"   : "Crawl & Map",
    "payload" : "Generate Payloads",
    "scan"    : "Run Scan",
    "fuzz"    : "Plan Fuzzing",
    "execute" : "Execute Fuzzing",
    "validate": "Validate Findings",
    "all"     : "Full Pipeline",
}


# ── SSE 라우트 ────────────────────────────────────────────────────

@app.route("/stream/<task>")
def stream_task(task):
    if task not in _TASK_FUNCS:
        return "알 수 없는 태스크", 404

    skip_crawl   = request.args.get("skip_crawl")   == "1"
    skip_payload = request.args.get("skip_payload") == "1"

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
                _task_all(skip_crawl=skip_crawl, skip_payload=skip_payload)
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

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── 상태 헬퍼 ─────────────────────────────────────────────────────

def _get_file_status():
    return [
        ("crawl_result.json",      os.path.exists(_run_path("crawl_result.json"))),
        ("targets.json",           os.path.exists(_run_path("targets.json"))),
        ("payloads_llm.json",      os.path.exists(PAYLOADS_FILE)),
        ("fuzz_tasks.json",        os.path.exists(_run_path("fuzz_tasks.json"))),
        ("execution_results.json", os.path.exists(_run_path("execution_results.json"))),
        ("findings.json",          os.path.exists(_run_path("findings.json"))),
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


# ── HTML 템플릿 ───────────────────────────────────────────────────

from ui_templates import _COMMON_HEAD, _MAIN_HTML, _RESULTS_HTML, _EXEC_HTML, _FINDINGS_HTML


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
    return render_template_string(
        _MAIN_HTML,
        cms_name     = CMS_NAME,
        base_url     = BASE_URL,
        file_status  = _get_file_status(),
        summary      = _get_quick_summary(),
        exec_summary = _get_exec_summary(),
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
        return render_template_string(_RESULTS_HTML, results=None, total=0, n_vuln=0, rate=0.0)
    try:
        with open(SCAN_RESULTS_FILE, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500

    total  = len(results)
    n_vuln = sum(1 for r in results if r.get("vulnerable"))
    rate   = n_vuln / max(total, 1) * 100
    return render_template_string(_RESULTS_HTML, results=results, total=total, n_vuln=n_vuln, rate=rate)


@app.route("/findings")
def findings_page():
    findings_file = _run_path("findings.json")
    if not os.path.exists(findings_file):
        return render_template_string(_FINDINGS_HTML, findings=None, xss_cnt=0, sqli_cnt=0)
    try:
        with open(findings_file, encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500
    xss_cnt  = sum(1 for f in findings if "xss"  in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sqli" in (f.get("vuln_type") or "").lower())
    return render_template_string(_FINDINGS_HTML, findings=findings, xss_cnt=xss_cnt, sqli_cnt=sqli_cnt)


@app.route("/exec_results")
def exec_results_page():
    exec_file = _run_path("execution_results.json")
    if not os.path.exists(exec_file):
        return render_template_string(_EXEC_HTML, results=None, total=0, ok=0, timeout=0, err=0)
    try:
        with open(exec_file, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500
    total   = len(results)
    ok      = sum(1 for r in results if r.get("error") is None)
    timeout = sum(1 for r in results if r.get("error") == "timeout")
    err     = sum(1 for r in results if r.get("error") and r.get("error") != "timeout")
    return render_template_string(_EXEC_HTML, results=results, total=total, ok=ok, timeout=timeout, err=err)


@app.route("/runs")
def runs_page():
    runs = _list_runs()
    return render_template_string(_RUNS_HTML, runs=runs, current_run=_current_run_id)


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


_RUNS_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <title>LADS - Run History</title>
""" + _COMMON_HEAD + """
</head>
<body>
<nav class="navbar app-nav px-3 py-3">
  <div class="container-fluid">
    <a class="d-flex align-items-center gap-2" href="/"><span class="brand-mark">LD</span><span class="brand-title">LADS</span></a>
    <span class="text-secondary ms-3 me-auto">Run History</span>
    <a href="/" class="btn btn-outline-dark btn-sm me-2">Dashboard</a>
    <form method="POST" action="/runs/new" style="display:inline"><button class="btn btn-primary btn-sm">New Run</button></form>
  </div>
</nav>
<main class="page-shell-wide">
  <section class="mb-4">
    <div class="eyebrow">Assessment Archive</div>
    <h1 class="page-title">Run History</h1>
    <p class="page-subtitle">Review saved assessment runs, switch the active run, or remove obsolete records.</p>
  </section>
  {% if not runs %}
  <div class="empty-state">No run history is available yet.</div>
  {% else %}
  <section class="section-card">
    <div class="card-header">Assessment Runs</div>
    <div class="table-responsive">
      <table class="table align-middle">
        <thead><tr><th>Run ID</th><th>Started</th><th>Crawl</th><th>Execution</th><th>Findings</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
        {% for r in runs %}
          <tr class="{% if r.is_current %}safe-row{% endif %}">
            <td><code>{{ r.id }}</code></td>
            <td>{{ r.ts }}</td>
            <td>{% if r.has_crawl %}<span class="badge bg-success">Ready</span>{% else %}<span class="badge bg-secondary">Missing</span>{% endif %}</td>
            <td>{% if r.has_exec %}<span class="badge bg-success">Ready</span>{% else %}<span class="badge bg-secondary">Missing</span>{% endif %}</td>
            <td>{% if r.has_findings %}<span class="badge bg-danger">{{ r.findings_cnt }}</span>{% else %}<span class="badge bg-secondary">None</span>{% endif %}</td>
            <td>{% if r.is_current %}<span class="badge bg-dark">Active</span>{% endif %}</td>
            <td><div class="d-flex gap-2 flex-wrap">
              {% if not r.is_current %}<form method="POST" action="/runs/set/{{ r.id }}"><button class="btn btn-outline-dark btn-sm">Select</button></form>{% endif %}
              <a href="/findings?run={{ r.id }}" class="btn btn-outline-success btn-sm">Findings</a>
              {% if not r.is_current %}<form method="POST" action="/runs/delete/{{ r.id }}" onsubmit="return confirm('Delete this run?')"><button class="btn btn-outline-danger btn-sm">Delete</button></form>{% endif %}
            </div></td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </section>
  {% endif %}
</main>
</body>
</html>
"""


# ── 서버 시작 ─────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    _init_run()
    print(f"LADS 대시보드 시작: http://localhost:5000")
    print(f"타겟: {BASE_URL}  |  현재 실행: {_current_run_id}")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
