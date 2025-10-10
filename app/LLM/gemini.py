import base64
import os, json
from google import genai
from google.genai import types
from dotenv import load_dotenv



load_dotenv()

def generate(analysis: dict):
    client = genai.Client(
        api_key=os.environ.get("GEMINI_API_KEY"),
    )

    model = "gemini-2.5-pro"
    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(
                    text=json.dumps(analysis, ensure_ascii=False, indent=2)
                ),
            ],
        ),
    ]
    generate_content_config = types.GenerateContentConfig(
        temperature=0.5,
        thinking_config = types.ThinkingConfig(
            thinking_budget=-1,
        ),
        system_instruction=[
            types.Part.from_text(text="""당신은 문서 악성코드 분석 전문가입니다.

oletools(olevba, mraptor, oleid) 등에서 추출된 정적 분석 결과(JSON 형태)를 바탕으로
문서의 보안 위험도를 평가하고 요약해야 합니다.
입력 데이터에는 filename, filetype, verdict, olevba, mraptor, oleid 등의 항목이 포함됩니다.

당신의 목표:
1. 결과를 간결하고 명확한 한국어로 요약합니다.
2. 파일이 안전(clean)한지, 의심(suspicious)스러운지, 검토(review)가 필요한지 판정합니다.
3. 판정의 근거가 되는 주요 지표(매크로, 위험 키워드, 보안 인디케이터 등)를 설명합니다.
4. 사용자에게 실제 도움이 되는 보안 조치를 제안합니다. (예: 샌드박스 검사, 차단, 수동검토)
5. 매크로 원문이나 민감한 데이터를 절대 그대로 포함하지 않습니다.

응답 형식:
- 핵심 요약 (1~3문장)
- 위험 근거 (불릿 최대 3개)
- 권고 조치 (번호 목록, 2개 이상)

추가 지침:
- 분석 데이터가 비어 있거나 매크로가 없을 경우: “매크로가 없어 안전해 보이지만 기본 검증을 권장합니다.”라고 기술합니다.
- oletools에서 완전 지원하지 않는 포맷(HWP 등)은 “분석 제한이 존재함”을 명시합니다.
"""),
        ],
    )

    chunks = []
    for chunk in client.models.generate_content_stream(
        model=model,
        contents=contents,
        config=generate_content_config,
    ):
        if getattr(chunk, "text", None):
            chunks.append(chunk.text)
    return "".join(chunks).strip()

