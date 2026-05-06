from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse

XSS_CONTEXT_HINT: Dict[str, str] = {
    "attr_value":    '→ " onmouseover=alert(1) x=" 계열 우선',
    "attr_href":     '→ javascript:alert(1) 계열 우선',
    "script":        '→ ";alert(1);// 계열 우선',
    "body":          '→ <img src=x onerror=alert(1)> 계열 우선',
    "html_comment":  '→ --> <script>alert(1)</script> <!-- 계열 우선',
    "stx_filtered":  '→ backtick / entity 인코딩 우선',
    "url_redirect":  '→ javascript:alert(1) 또는 외부 URL 우선',
    "none":          '→ 반사 없음 (필터링됨)',
    "unknown":       '→ 컨텍스트 불명확',
}


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

    # (method, base_url) → {param_name: best_default_value}
    # 같은 URL 엔트리가 여러 개일 때 덮어쓰지 않고, 비어있는 값보다 채워진 값을 우선
    from collections import defaultdict
    target_params: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    if isinstance(targets, list):
        for t in targets:
            if not isinstance(t, dict):
                continue
            action = t.get("action")
            method = (t.get("method") or "").upper()
            if not (action and method):
                continue
            key = (method, _base_url(str(action)))
            for pr in t.get("params", []) or []:
                if not isinstance(pr, dict):
                    continue
                n = pr.get("name")
                v = str(pr.get("default_value") or "")
                if not n:
                    continue
                # 이미 채워진 값이 있으면 유지, 없으면 v로 채움
                existing = target_params[key].get(n, "")
                # 비어있으면 무조건 채움, 채워져 있으면 || 없는 단순 값 우선
                if not existing and v:
                    target_params[key][n] = v
                elif existing and v and "||" in existing and "||" not in v:
                    target_params[key][n] = v

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

        # 기본 파라미터(기본값) 구성: targets.json 기반으로 같은 endpoint를 찾아 채움
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

        for vtype, records in point_payloads.items():
            if not isinstance(records, list):
                continue
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                payload = rec.get("payload")
                if not payload:
                    continue

                meta = {"vuln_type": vtype, "type": rec.get("type"), "family": rec.get("family")}

                for mode in ("replace", "append"):
                    out.append(
                        {
                            "id": f"t{tid:06d}_{mode[0]}",
                            "point": name,
                            "url": url,
                            "method": method,
                            "inject_location": inject_location,
                            "inject_param": param,
                            "inject_mode": mode,
                            "base_params": base_params,
                            "payload": payload,
                            "meta": meta,
                        }
                    )
                    tid += 1

    return out
