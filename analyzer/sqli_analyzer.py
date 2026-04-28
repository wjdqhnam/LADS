# MySQL / 워드프레스 / 그누보드 상세 DB 에러 키워드 (scanner.py의 MYSQL_ERRORS 통합)
DB_ERROR_KEYWORDS = [
    "you have an error in your sql syntax", "warning: mysql", "xpath syntax error",
    "extractvalue(", "updatexml(", "duplicate entry", "column count doesn't match",
    "the used select statements have a different number", "supplied argument is not a valid mysql",
    "division by zero", "unknown column", "table 'g5_"
]

def validate_sqli(test_result):
    response = test_result.get("response", {})
    controls = test_result.get("controls", {})
    body = response.get("body", "").lower()
    
    elapsed = response.get("elapsed", 0.0)
    length = response.get("length", 0)
    
    # 1. Time-based 판정 (Double-check 개념 도입)
    # scanner.py의 SLEEP_THRESHOLD(4.5) 기준 사용
    if elapsed >= 4.5:
        # 실제 환경에서는 여기서 정상 요청(ctrl_false)의 elapsed와 비교하는 로직이 권장됨
        return True, f"Time-based SQLi 성공 (응답 지연: {elapsed}초)"

    # 2. Error-based 판정
    for error in DB_ERROR_KEYWORDS:
        if error in body:
            return True, f"Error-based SQLi 성공 (DB 에러 노출: {error})"

    # 3. Boolean-based 판정 (신호 강도 분석 적용)
    true_len = controls.get("true_len")
    false_len = controls.get("false_len")
    
    if true_len is not None and false_len is not None:
        ctrl_span = abs(true_len - false_len)
        if ctrl_span > 0:
            dist_true = abs(length - true_len)
            dist_false = abs(length - false_len)
            
            # 참(True) 조건 응답에 훨씬 가까울 때만 성공으로 판정
            if dist_true < dist_false:
                signal = (dist_false - dist_true) / max(ctrl_span, 1)
                if signal >= 0.05: # scanner.py의 BOOL_SIGNAL_MIN 기준
                    return True, f"Boolean-based SQLi 성공 (Signal: {signal:.1%})"

    return False, "안전함 (SQLi 방어됨)"