from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def _base_url(url: str) -> str:
    return urlparse(url)._replace(query="", fragment="").geturl()


def _guess_location(method: str) -> str:
    return "body" if method.upper() == "POST" else "query"


def _get_baseline_records(point_name: str, vuln_types: list[str]) -> list[dict]:
    """point 이름 기반으로 baseline 페이로드 레코드 반환."""
    vtype = vuln_types[0] if vuln_types else "generic"
    records: list[dict] = []

    if "xss" in point_name:
        from baseline.xss import get_all as xss_get_all
        for bp in xss_get_all():
            records.append({
                "vtype": vtype,
                "type": bp.get("type"),
                "family": "baseline_" + (bp.get("family") or ""),
                "payload": bp.get("payload"),
            })

    elif "sqli" in point_name:
        from baseline.sqli import (
            get_by_sql_context,
            get_all as sqli_get_all,
        )
        if "sfl" in point_name:
            baseline = get_by_sql_context("field_selector", "INSANE")
        elif "sst" in point_name:
            baseline = get_by_sql_context("orderby", "INSANE")
        elif "login" in point_name:
            baseline = get_by_sql_context("auth", "INSANE")
        else:
            baseline = get_by_sql_context("like_string", "INSANE")

        for bp in baseline:
            records.append({
                "vtype": vtype,
                "type": bp.get("type"),
                "family": "baseline_" + (bp.get("family") or ""),
                "payload": bp.get("payload"),
            })

    return records


def build_tasks(
    points_meta: Any,
    payloads: Any,
    targets: Any | None = None,
    base_cookies: dict | None = None,
    progress_callback=None,
) -> list[dict]:
    """points + LLM payloads + baseline payloads -> fuzz task list."""

    if not points_meta or not payloads:
        return []

    target_index: dict[tuple[str, str], dict] = {}
    if isinstance(targets, list):
        for t in targets:
            if not isinstance(t, dict):
                continue
            action = t.get("action")
            method = (t.get("method") or "").upper()
            if action and method:
                target_index[(method, _base_url(str(action)))] = t

    out: list[dict] = []
    tid = 0

    if not isinstance(points_meta, list):
        return []

    total_points = len(points_meta)
    for idx, p in enumerate(points_meta):
        if not isinstance(p, dict):
            continue

        name = p.get("name")
        url = p.get("url")
        method = (p.get("method") or "GET").upper()
        param = p.get("param")
        if not (name and url and param):
            continue

        point_payloads = payloads.get(name) if isinstance(payloads, dict) else None
        if not isinstance(point_payloads, dict):
            continue

        inject_location = _guess_location(method)

        base_params: dict[str, Any] = {}
        t = target_index.get((method, _base_url(str(url))))
        if isinstance(t, dict):
            for pr in t.get("params", []) or []:
                if not isinstance(pr, dict):
                    continue
                n = pr.get("name")
                if not n or n == param:
                    continue
                base_params[str(n)] = pr.get("default_value", "")

        if progress_callback:
            progress_callback(idx + 1, total_points)

        # ── payload 중복 제거용 집합 (point별로 초기화) ──
        used_payloads: set[str] = set()

        def _emit(payload: str, vtype: str, rec_type: str | None, family: str | None) -> None:
            nonlocal tid
            if not payload or payload in used_payloads:
                return
            used_payloads.add(payload)
            meta = {"vuln_type": vtype, "type": rec_type, "family": family}
            for mode in ("replace", "append"):
                out.append({
                    "id": f"t{tid:06d}_{mode[0]}",
                    "point": name,
                    "url": url,
                    "method": method,
                    "inject_location": inject_location,
                    "inject_param": param,
                    "inject_mode": mode,
                    "base_params": base_params,
                    "base_cookies": base_cookies or {},
                    "payload": payload,
                    "meta": meta,
                })
                tid += 1

        # 1. LLM 페이로드
        for vtype, records in point_payloads.items():
            if not isinstance(records, list):
                continue
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                _emit(rec.get("payload"), vtype, rec.get("type"), rec.get("family"))

        # 2. Baseline 페이로드 (LLM과 중복 제외)
        vuln_types = p.get("vuln_types") or []
        for rec in _get_baseline_records(name, vuln_types):
            _emit(rec.get("payload"), rec["vtype"], rec.get("type"), rec.get("family"))

    return out
