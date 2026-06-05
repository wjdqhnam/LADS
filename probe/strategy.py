from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse
from payload.baseline.xss import get_all as xss_get_all
from payload.baseline.sqli import get_by_sql_context

_DESTRUCTIVE_SQL_RE = re.compile(
    r"\b(drop|delete|update|insert|alter|truncate|create|replace|rename|grant|revoke)\b",
    re.IGNORECASE,
)

SKIP_OPERATORS = {"and", "or", "move"}
SKIP_FIELD_TYPES = {"checkbox", "radio"}


def _is_destructive_payload(payload: str) -> bool:
    if not payload:
        return False
    return bool(_DESTRUCTIVE_SQL_RE.search(payload))


def _base_url(url: str) -> str:
    return urlparse(url)._replace(query="", fragment="").geturl()


def _guess_location(method: str) -> str:
    return "body" if method.upper() == "POST" else "query"


def _should_skip(name: str, value: str, field_type: str) -> bool:
    if field_type in SKIP_FIELD_TYPES:
        return True
    v = str(value).strip()
    if re.match(r"^\d+$", v):
        return True
    if len(v) == 1:
        return True
    if v.lower() in SKIP_OPERATORS:
        return True
    return False


def _infer_types(field_type: str, action_url: str, param_name: str) -> list[str]:
    if "login_check" in action_url:
        if param_name in ("mb_id", "mb_password"):
            return ["sqli_login"]
    if field_type == "password":
        return ["sqli_login"]
    if field_type in ("text", "input", "email"):
        return ["sqli_string", "xss_search"]
    if field_type == "url_param":
        return ["sqli_string"]
    if field_type == "textarea":
        return ["xss_content"]
    if field_type == "select":
        return ["sqli_field"]
    if field_type == "hidden":
        return ["sqli_string"]
    return ["sqli_string"]


def _flatten_by_type(payloads: dict) -> dict[str, list]:
    result: dict[str, list] = {}
    seen: dict[str, set] = {}
    for point_data in payloads.values():
        if not isinstance(point_data, dict):
            continue
        for vtype, records in point_data.items():
            if not isinstance(records, list):
                continue
            result.setdefault(vtype, [])
            seen.setdefault(vtype, set())
            for r in records:
                if not isinstance(r, dict):
                    continue
                payload = r.get("payload")
                if payload and payload not in seen[vtype]:
                    seen[vtype].add(payload)
                    result[vtype].append(r)
    return result


def _get_baseline_records_by_type(vtype: str) -> list[dict]:
    records: list[dict] = []
    if "xss" in vtype:
        for bp in xss_get_all():
            records.append({
                "vtype": vtype,
                "type": bp.get("type"),
                "family": "baseline_" + (bp.get("family") or ""),
                "payload": bp.get("payload"),
            })
    elif "sqli" in vtype:
        ctx_map = {
            "sqli_field":   "field_selector",
            "sqli_orderby": "orderby",
            "sqli_login":   "auth",
        }
        ctx = ctx_map.get(vtype, "like_string")
        for bp in get_by_sql_context(ctx, "INSANE"):
            records.append({
                "vtype": vtype,
                "type": bp.get("type"),
                "family": "baseline_" + (bp.get("family") or ""),
                "payload": bp.get("payload"),
                "bool_side": bp.get("bool_side"),
            })
    return records


def build_tasks(
    payloads: Any,
    targets: Any | None = None,
    base_cookie: dict | None = None,
    progress_callback=None,
) -> list[dict]:
    if not payloads or not targets:
        return []

    flat = _flatten_by_type(payloads)

    out: list[dict] = []
    tid = 0
    seen_combos: set[tuple] = set()
    total = len(targets) if isinstance(targets, list) else 0

    for idx, target in enumerate(targets or []):
        if not isinstance(target, dict):
            continue

        action = target.get("action", "")
        method = (target.get("method") or "GET").upper()
        inject_location = _guess_location(method)
        all_params = target.get("params") or []

        if progress_callback:
            progress_callback(idx + 1, total)

        for param in all_params:
            if not isinstance(param, dict):
                continue
            if not param.get("injectable"):
                continue

            name = param.get("name", "")
            value = str(param.get("default_value") or "")
            field_type = param.get("field_type", "")

            if not name:
                continue
            if _should_skip(name, value, field_type):
                continue

            combo = (method, _base_url(action), name)
            if combo in seen_combos:
                continue
            seen_combos.add(combo)

            vuln_types = _infer_types(field_type, action, name)
            if not vuln_types:
                continue

            base_params = {
                p["name"]: str(p.get("default_value") or "")
                for p in all_params
                if isinstance(p, dict) and p.get("name") and p["name"] != name
            }

            used_payloads: set[str] = set()
            point_label = f"{_base_url(action).split('/')[-1]}_{name}"

            def _emit(payload: str, vtype: str, rec_type, family, bool_side=None, _label=point_label) -> None:
                nonlocal tid
                if not payload or payload in used_payloads:
                    return
                if _is_destructive_payload(payload):
                    print(f"[PROBE] skipped destructive payload: point={_label}")
                    return
                used_payloads.add(payload)
                out.append({
                    "id": f"t{tid:06d}_r",
                    "point": _label,
                    "url": action,
                    "method": method,
                    "inject_location": inject_location,
                    "inject_param": name,
                    "inject_mode": "replace",
                    "base_params": base_params,
                    "base_cookies": base_cookie or {},
                    "base_value": value,
                    "payload": payload,
                    "enctype": target.get("enctype", ""),
                    "meta": {"vuln_type": vtype, "type": rec_type, "family": family, "bool_side": bool_side},
                })
                tid += 1

            for vtype in vuln_types:
                for rec in flat.get(vtype, []):
                    if isinstance(rec, dict):
                        _emit(rec.get("payload"), vtype, rec.get("type"), rec.get("family"), rec.get("bool_side"))
                for rec in _get_baseline_records_by_type(vtype):
                    _emit(rec.get("payload"), vtype, rec.get("type"), rec.get("family"), rec.get("bool_side"))

    return out
