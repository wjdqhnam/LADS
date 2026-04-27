# MySQL / 워드프레스 / 그누보드 대표 DB 에러 키워드
DB_ERROR_KEYWORDS = [
    "sql syntax", "mysql_fetch", "database error", 
    "warning: mysql", "unclosed quotation mark",
    "extractvalue", "updatexml"
]

def validate_sqli(test_result):
    response = test_result.get("response", {})
    controls = test_result.get("controls", {})
    body = response.get("body", "").lower()
    
    elapsed = response.get("elapsed", 0.0)
    length = response.get("length", 0)
    true_len = controls.get("true_len")
    false_len = controls.get("false_len")
    
    # 1.Time-based 판정
    if elapsed >= 4.5:
        return True, f"Time-based SQLi 성공 (응답 지연: {elapsed}초)"

    # 2.Boolean-based 판정
    if true_len and false_len and (true_len != false_len):
        if abs(length - true_len) < 50: 
            return True, f"Boolean-based SQLi 성공 (참 응답 길이 {true_len}와 일치)"

    # 3.Error-based 판정
    for error in DB_ERROR_KEYWORDS:
        if error in body:
            return True, f"Error-based SQLi 성공 (DB 에러 노출: {error})"

    return False, "안전함 (SQLi 방어됨)"