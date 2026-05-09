import importlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime


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
from tasks import (
    _task_crawl as _crawl_impl,
    _task_payload as _payload_impl,
    _task_fuzz as _fuzz_impl,
    _task_execute as _execute_impl,
    _task_validate as _validate_impl,
    _task_all as _all_impl,
    TASK_LABELS as _TASK_LABELS,
)

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

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
# 개발 중 템플릿/정적 파일이 "안 바뀌는" 문제 방지용 설정.
# - debug가 꺼져 있어도 templates 변경이 즉시 반영되도록 함
# - 정적 파일 캐시를 줄여(0초) 새로고침 시 바로 반영되도록 함
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.jinja_env.auto_reload = True
_task_lock = threading.Lock()
_thread_local = threading.local()




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
    _crawl_impl(_run_path, _active_url(), _emit_progress)


def _task_payload():
    _payload_impl(PAYLOADS_FILE, _emit_progress)


def _task_fuzz():
    _fuzz_impl(_run_path, PAYLOADS_FILE, PAYLOADS_META_FILE, _emit_progress)


def _task_execute():
    _execute_impl(_run_path, _emit_progress)


def _task_validate():
    _validate_impl(_run_path, _emit_progress)


def _task_all(skip_crawl: bool = False):
    _all_impl(_run_path, _active_url(), PAYLOADS_FILE, PAYLOADS_META_FILE, skip_crawl=skip_crawl, emit_progress=_emit_progress)


_TASK_FUNCS = {
    "crawl":    _task_crawl,
    "payload":  _task_payload,
    "fuzz":     _task_fuzz,
    "execute":  _task_execute,
    "validate": _task_validate,
    "all":      _task_all,
}


@app.route("/stream/<task>")
def stream_task(task):
    if task not in _TASK_FUNCS:
        return "알 수 없는 태스크", 404

    skip_crawl = request.args.get("skip_crawl") == "1"
    q = queue.Queue()

    # 전체 스캔(all)이고 크롤링도 새로 하는 경우 → 새 런 자동 생성
    if task == "all" and not skip_crawl:
        global _current_run_id
        _current_run_id = _make_run_id()
        os.makedirs(os.path.join(RUNS_DIR, _current_run_id), exist_ok=True)

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
    print("index")
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
    return redirect("/findings")


@app.route("/findings")
def findings_page():
    run_id = request.args.get("run") or _current_run_id
    findings_file = _run_path("findings.json", run_id=run_id)
    exec_file = _run_path("execution_results.json", run_id=run_id)

    findings = []
    if os.path.exists(findings_file):
        try:
            with open(findings_file, encoding="utf-8") as f:
                findings = json.load(f)
        except Exception as exc:
            return f"결과 파일 읽기 오류: {exc}", 500

    xss_cnt = sum(1 for f in findings if "xss" in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sql" in (f.get("vuln_type") or "").lower())

    all_results = []
    safe_cnt = 0
    if os.path.exists(exec_file):
        try:
            findings_by_id = {f.get("id"): f for f in findings}
            with open(exec_file, encoding="utf-8") as f:
                exec_results = json.load(f)
            for r in exec_results:
                hit = findings_by_id.get(r.get("id"))
                r["_vulnerable"] = hit is not None
                r["_evidence"] = hit.get("evidence", "") if hit else ""
                r["_vuln_type"] = hit.get("vuln_type", "") if hit else (r.get("meta") or {}).get("vuln_type", "")
            all_results = exec_results
            safe_cnt = sum(1 for r in all_results if not r.get("_vulnerable") and not r.get("error"))
        except Exception:
            pass

    return render_template(
        "findings.html",
        findings=findings,
        xss_cnt=xss_cnt,
        sqli_cnt=sqli_cnt,
        safe_cnt=safe_cnt,
        all_results=all_results,
        run_id=run_id,
        current_run=_current_run_id,
    )


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


@app.route("/runs/<run_id>")
def run_detail(run_id):
    run_dir = os.path.join(RUNS_DIR, run_id)
    if not os.path.isdir(run_dir):
        return "존재하지 않는 런입니다.", 404

    try:
        ts = datetime.strptime(run_id, "run_%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts = run_id

    files = set(os.listdir(run_dir))

    findings, xss_cnt, sqli_cnt = [], 0, 0
    if "findings.json" in files:
        try:
            with open(os.path.join(run_dir, "findings.json"), encoding="utf-8") as f:
                findings = json.load(f)
            xss_cnt = sum(1 for fi in findings if "xss" in (fi.get("vuln_type") or "").lower())
            sqli_cnt = sum(1 for fi in findings if "sql" in (fi.get("vuln_type") or "").lower())
        except Exception:
            pass

    exec_results, exec_ok, exec_timeout, exec_err = [], 0, 0, 0
    if "execution_results.json" in files:
        try:
            with open(os.path.join(run_dir, "execution_results.json"), encoding="utf-8") as f:
                exec_results = json.load(f)
            exec_ok = sum(1 for r in exec_results if r.get("error") is None)
            exec_timeout = sum(1 for r in exec_results if r.get("error") == "timeout")
            exec_err = sum(1 for r in exec_results if r.get("error") and r.get("error") != "timeout")
        except Exception:
            pass

    return render_template(
        "run_detail.html",
        run_id=run_id,
        ts=ts,
        is_current=(run_id == _current_run_id),
        has_crawl="crawl_result.json" in files,
        has_targets="targets.json" in files,
        has_payload=os.path.exists(PAYLOADS_FILE),
        has_fuzz="fuzz_tasks.json" in files,
        has_exec="execution_results.json" in files,
        has_findings="findings.json" in files,
        findings=findings,
        xss_cnt=xss_cnt,
        sqli_cnt=sqli_cnt,
        exec_results=exec_results,
        exec_total=len(exec_results),
        exec_ok=exec_ok,
        exec_timeout=exec_timeout,
        exec_err=exec_err,
        current_run=_current_run_id,
    )


@app.route("/runs/set/<run_id>", methods=["POST"])
def set_run(run_id):
    global _current_run_id
    if os.path.isdir(os.path.join(RUNS_DIR, run_id)):
        _current_run_id = run_id
    return redirect(f"/runs/{run_id}")


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
    _dev = os.getenv("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=_dev,
        use_reloader=True,
        threaded=True,
    )
