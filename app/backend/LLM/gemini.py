import os
import json
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()


def generate_pdf_summary(analysis: dict) -> str:
    """PDF 분석 결과를 Gemini로 요약 - 개선된 프롬프트"""
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    
    script_output = analysis.get("script_output", "")
    file_name = analysis.get("file_name", "unknown")
    
    system_msg = types.Part.from_text(text=(
        "당신은 PDF 문서 보안 분석 전문가입니다.\n"
        "입력은 PDF 파일 정적 분석 도구의 실행 결과입니다.\n"
        "\n"
        "**중요: 정상 파일과 악성 파일을 정확히 구분하세요!**\n"
        "- 정상 문서: JavaScript나 자동실행이 **전혀 없거나 1~2개만** 존재하는 경우 → LOW (0~30점)\n"
        "- 의심 문서: 자동실행/스크립트가 **3~5개** 존재하는 경우 → MEDIUM (40~60점)\n"
        "- 위험 문서: 다수의 자동실행(**6개 이상**) 및 악성 패턴이 명확한 경우 → HIGH (70~100점)\n"
        "\n"
        "응답은 반드시 유효한 JSON 형식이어야 합니다:\n"
        "{\n"
        '  "summary": "간결한 한국어 핵심 요약(1~3문장)",\n'
        '  "risk_score": 0~100 사이의 숫자,\n'
        '  "risk_level": "low" 또는 "medium" 또는 "high",\n'
        '  "reasons": ["근거1", "근거2", "근거3"],\n'
        '  "recommended_actions": ["조치1", "조치2"]\n'
        "}\n"
        "\n"
        "요구사항:\n"
        "1) summary: 한국어로 간결한 요약(1~3문장)\n"
        "2) risk_score: 위험도를 0~100 숫자로 **보수적으로** 평가\n"
        "   - 키워드 1~2개: 0~30점 (LOW)\n"
        "   - 키워드 3~5개: 40~60점 (MEDIUM)\n"
        "   - 키워드 6개 이상: 70~100점 (HIGH)\n"
        "3) risk_level: 위험도에 따라 \"low\"(39 이하), \"medium\"(40~69), \"high\"(70 이상)\n"
        "4) reasons: **실제로 발견된** 위험 요인만 명시 (최대 3개)\n"
        "5) recommended_actions: 구체적인 권장 조치 2개 이상\n"
        "\n"
        "반드시 JSON 형식으로만 응답하세요."
    ))
    
    user_msg = types.Part.from_text(text=f"파일명: {file_name}\n\n분석 결과:\n{script_output}")
    
    config = types.GenerateContentConfig(
        temperature=0.2,  # 더 일관성 있는 응답
        max_output_tokens=2048,
        system_instruction=[system_msg],
    )
    
    try:
        chunks = []
        for chunk in client.models.generate_content_stream(
            model="models/gemini-flash-latest",
            contents=[types.Content(role="user", parts=[user_msg])],
            config=config,
        ):
            if getattr(chunk, "text", None):
                chunks.append(chunk.text)
        
        full_response = "".join(chunks).strip()
        return _extract_json_from_response(full_response)
        
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            return _fallback_quota_exceeded()
        else:
            return _fallback_error(error_msg)


def generate_pe_summary(analysis: dict) -> str:
    """PE(실행파일) 분석 결과를 Gemini로 요약 - 개선된 프롬프트"""
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    
    script_output = analysis.get("script_output", "")
    file_name = analysis.get("file_name", "unknown")
    
    system_msg = types.Part.from_text(text=(
        "당신은 실행파일(PE) 악성코드 분석 전문가입니다.\n"
        "입력은 EXE/DLL 파일 정적 분석 도구의 실행 결과입니다.\n"
        "\n"
        "**중요: 정상 파일과 악성 파일을 정확히 구분하세요!**\n"
        "- 정상 실행파일: 엔트로피 < 7.0, 정상 API만 사용 → LOW (0~35점)\n"
        "- 의심 실행파일: 엔트로피 7.0~7.5 또는 일부 의심 API → MEDIUM (40~65점)\n"
        "- 위험 실행파일: 엔트로피 > 7.5 + 다수 악성 API + 패킹 → HIGH (70~100점)\n"
        "\n"
        "응답은 반드시 유효한 JSON 형식이어야 합니다:\n"
        "{\n"
        '  "summary": "간결한 한국어 핵심 요약(1~3문장)",\n'
        '  "risk_score": 0~100 사이의 숫자,\n'
        '  "risk_level": "low" 또는 "medium" 또는 "high",\n'
        '  "reasons": ["근거1", "근거2", "근거3"],\n'
        '  "recommended_actions": ["조치1", "조치2"]\n'
        "}\n"
        "\n"
        "요구사항:\n"
        "1) summary: 한국어로 간결한 요약(1~3문장)\n"
        "2) risk_score: 위험도를 0~100 숫자로 **보수적으로** 평가\n"
        "3) risk_level: 위험도에 따라 \"low\"(39 이하), \"medium\"(40~69), \"high\"(70 이상)\n"
        "4) reasons: **실제로 발견된** 위험 요인만 명시 (최대 3개)\n"
        "5) recommended_actions: 구체적인 권장 조치 2개 이상\n"
        "\n"
        "반드시 JSON 형식으로만 응답하세요."
    ))
    
    user_msg = types.Part.from_text(text=f"파일명: {file_name}\n\n분석 결과:\n{script_output}")
    
    config = types.GenerateContentConfig(
        temperature=0.2,
        max_output_tokens=2048,
        system_instruction=[system_msg],
    )
    
    try:
        chunks = []
        for chunk in client.models.generate_content_stream(
            model="models/gemini-flash-latest",
            contents=[types.Content(role="user", parts=[user_msg])],
            config=config,
        ):
            if getattr(chunk, "text", None):
                chunks.append(chunk.text)
        
        full_response = "".join(chunks).strip()
        return _extract_json_from_response(full_response)
        
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            return _fallback_quota_exceeded()
        else:
            return _fallback_error(error_msg)


def generate_zip_summary(analysis: dict) -> str:
    """ZIP 파일 분석 결과를 Gemini로 요약 - 개선된 프롬프트"""
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    
    script_output = analysis.get("script_output", "")
    file_name = analysis.get("file_name", "unknown")
    
    system_msg = types.Part.from_text(text=(
        "당신은 압축 파일 보안 분석 전문가입니다.\n"
        "입력은 ZIP 파일 구조 분석 도구의 실행 결과입니다.\n"
        "\n"
        "**중요: 정상 파일과 악성 파일을 정확히 구분하세요!**\n"
        "- 정상 압축파일: 일반 문서/이미지만, 압축률 정상 → LOW (0~30점)\n"
        "- 의심 압축파일: 실행파일 1~2개 또는 압축률 100~200배 → MEDIUM (40~60점)\n"
        "- 위험 압축파일: Zip Bomb(압축률 200배 이상) 또는 다수 실행파일 → HIGH (70~100점)\n"
        "\n"
        "응답은 반드시 유효한 JSON 형식이어야 합니다:\n"
        "{\n"
        '  "summary": "간결한 한국어 핵심 요약(1~3문장)",\n'
        '  "risk_score": 0~100 사이의 숫자,\n'
        '  "risk_level": "low" 또는 "medium" 또는 "high",\n'
        '  "reasons": ["근거1", "근거2", "근거3"],\n'
        '  "recommended_actions": ["조치1", "조치2"]\n'
        "}\n"
        "\n"
        "요구사항:\n"
        "1) summary: 한국어로 간결한 요약(1~3문장)\n"
        "2) risk_score: 위험도를 0~100 숫자로 **보수적으로** 평가\n"
        "3) risk_level: 위험도에 따라 \"low\"(39 이하), \"medium\"(40~69), \"high\"(70 이상)\n"
        "4) reasons: **실제로 발견된** 위험 요인만 명시 (최대 3개)\n"
        "5) recommended_actions: 구체적인 권장 조치 2개 이상\n"
        "\n"
        "반드시 JSON 형식으로만 응답하세요."
    ))
    
    user_msg = types.Part.from_text(text=f"파일명: {file_name}\n\n분석 결과:\n{script_output}")
    
    config = types.GenerateContentConfig(
        temperature=0.2,
        max_output_tokens=2048,
        system_instruction=[system_msg],
    )
    
    try:
        chunks = []
        for chunk in client.models.generate_content_stream(
            model="models/gemini-flash-latest",
            contents=[types.Content(role="user", parts=[user_msg])],
            config=config,
        ):
            if getattr(chunk, "text", None):
                chunks.append(chunk.text)
        
        full_response = "".join(chunks).strip()
        return _extract_json_from_response(full_response)
        
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            return _fallback_quota_exceeded()
        else:
            return _fallback_error(error_msg)


def generate_office_summary(analysis: dict) -> str:
    """MS Office/HWP 분석 결과를 Gemini로 요약 - 개선된 프롬프트"""
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    
    script_output = analysis.get("script_output", "")
    file_name = analysis.get("file_name", "unknown")
    
    system_msg = types.Part.from_text(text=(
        "당신은 문서 악성코드 분석 전문가입니다.\n"
        "입력은 oletools 기반 MS Office/HWP 파일 분석 도구의 실행 결과입니다.\n"
        "\n"
        "**중요: 정상 파일과 악성 파일을 정확히 구분하세요!**\n"
        "- 정상 문서: 매크로 없거나 Auto 키워드 1~2개만 → LOW (0~30점)\n"
        "- 의심 문서: AutoExec + 외부연결 or 난독화 일부 → MEDIUM (40~65점)\n"
        "- 위험 문서: AutoExec + 외부실행 + 난독화 + 다수 의심 키워드 → HIGH (70~100점)\n"
        "\n"
        "응답은 반드시 유효한 JSON 형식이어야 합니다:\n"
        "{\n"
        '  "summary": "간결한 한국어 핵심 요약(1~3문장)",\n'
        '  "risk_score": 0~100 사이의 숫자,\n'
        '  "risk_level": "low" 또는 "medium" 또는 "high",\n'
        '  "reasons": ["근거1", "근거2", "근거3"],\n'
        '  "recommended_actions": ["조치1", "조치2"]\n'
        "}\n"
        "\n"
        "요구사항:\n"
        "1) summary: 한국어로 간결한 요약(1~3문장)\n"
        "2) risk_score: 위험도를 0~100 숫자로 **보수적으로** 평가\n"
        "3) risk_level: 위험도에 따라 \"low\"(39 이하), \"medium\"(40~69), \"high\"(70 이상)\n"
        "4) reasons: **실제로 발견된** 위험 요인만 명시 (최대 3개)\n"
        "5) recommended_actions: 구체적인 권장 조치 2개 이상\n"
        "\n"
        "제한: 매크로 원문이나 민감 데이터는 절대 포함하지 마세요. 반드시 JSON 형식으로만 응답하세요."
    ))
    
    user_msg = types.Part.from_text(text=f"파일명: {file_name}\n\n분석 결과:\n{script_output}")
    
    config = types.GenerateContentConfig(
        temperature=0.2,
        max_output_tokens=2048,
        system_instruction=[system_msg],
    )
    
    try:
        chunks = []
        for chunk in client.models.generate_content_stream(
            model="models/gemini-flash-latest",
            contents=[types.Content(role="user", parts=[user_msg])],
            config=config,
        ):
            if getattr(chunk, "text", None):
                chunks.append(chunk.text)
        
        full_response = "".join(chunks).strip()
        return _extract_json_from_response(full_response)
        
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            return _fallback_quota_exceeded()
        else:
            return _fallback_error(error_msg)


def _extract_json_from_response(response: str) -> str:
    """응답에서 JSON 추출"""
    import re
    
    if not response:
        return _fallback_response()
    
    # 마크다운 코드 블록에서 추출
    json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
    if json_match:
        return json_match.group(1).strip()
    
    # 직접 파싱 시도
    try:
        json.loads(response)
        return response
    except Exception:
        pass
    
    # JSON 객체 추출 시도
    json_match = re.search(r'(\{[\s\S]*\})', response)
    if json_match:
        return json_match.group(1).strip()
    
    # 실패 시 기본 응답
    return _fallback_response()


def _fallback_response() -> str:
    """분석 실패 시 기본 응답"""
    return json.dumps({
        "summary": "분석 결과를 생성하지 못했습니다.",
        "risk_score": 0,
        "risk_level": "low",
        "reasons": [],
        "recommended_actions": []
    }, ensure_ascii=False)


def _fallback_quota_exceeded() -> str:
    """할당량 초과 시 응답"""
    return json.dumps({
        "summary": "Gemini API 할당량이 초과되었습니다. 잠시 후 다시 시도해주세요.",
        "risk_score": 0,
        "risk_level": "low",
        "reasons": ["API 할당량 초과로 AI 분석을 수행할 수 없습니다"],
        "recommended_actions": [
            "정적 분석 결과를 참고하세요",
            "1분 후 다시 시도하거나 API 키를 업그레이드하세요"
        ]
    }, ensure_ascii=False)


def _fallback_error(error_msg: str) -> str:
    """일반 오류 시 응답"""
    return json.dumps({
        "summary": "AI 분석 중 오류가 발생했습니다.",
        "risk_score": 0,
        "risk_level": "low",
        "reasons": [f"오류: {error_msg[:100]}"],
        "recommended_actions": ["정적 분석 결과를 참고하세요"]
    }, ensure_ascii=False)