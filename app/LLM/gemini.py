import os
import json
import re
from collections import Counter
from google import genai
from google.genai import types

AUTOEXEC_KEYS = {"AutoOpen", "Document_Open", "Workbook_Open", "AutoExec", "AutoExit"}
EXTERNAL_KEYS = {"Shell", "WScript.Shell", "CreateObject", "Run", "Exec"}
OBFUSC_KEYS = {"Chr", "Val", "String$", "Replace", "Xor", "StrReverse", "Split", "Join"}
URL_RE = re.compile(r"https?://[^\s'\"<>]{6,}", re.IGNORECASE)
B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")

def _top_n(counter: Counter, n=10):
    return [{"keyword": k, "count": int(c)} for k, c in counter.most_common(n)]

def _extract_cli_snippets(analysis_root: dict) -> str:
    cli = analysis_root.get("analysis", {})
    texts = []
    for sect in ("oledir", "oleobj", "olemap", "oletimes"):
        out = (cli.get(sect) or {}).get("stdout") or ""
        if out:
            texts.append(out[:50_000])
    return "\n".join(texts)

def build_llm_payload_from_analysis(analysis: dict) -> dict:
    root = analysis or {}
    body = root.get("analysis", {})
    fname = body.get("file")
    vba = body.get("olevba") or {}
    has_macros = bool(vba.get("has_macros"))
    macros = vba.get("macros") or []
    keywords_in = vba.get("keywords") or []
    macro_count = len(macros)
    total_vba_bytes = sum(m.get("code_size", 0) for m in macros)
    kw_counter = Counter()
    for k in keywords_in:
        kw = (k.get("keyword") or "").strip()
        cnt = int(k.get("count") or 1)
        if kw:
            kw_counter[kw] += cnt
    autoexec_detected = any(k in kw_counter for k in AUTOEXEC_KEYS)
    external_exec_found = any(k in kw_counter for k in EXTERNAL_KEYS)
    obfuscation_signals = [k for k in kw_counter if k in OBFUSC_KEYS]
    top_keywords = _top_n(kw_counter, n=10)
    cli_text = _extract_cli_snippets(root)
    urls = list(dict.fromkeys(URL_RE.findall(cli_text)))[:10]
    b64s = list(dict.fromkeys(B64_RE.findall(cli_text)))[:5]
    embedded_lines = []
    oleobj_out = (body.get("oleobj") or {}).get("stdout") or ""
    for line in oleobj_out.splitlines():
        if any(x in line for x in ("Class", "Format", "Type", "Embedded", "Package")):
            embedded_lines.append(line.strip())
    embedded_lines = embedded_lines[:8]
    score = 0
    if has_macros: score += 25
    if autoexec_detected: score += 30
    if external_exec_found: score += 25
    score += min(20, len(obfuscation_signals) * 5)
    score += min(10, len(urls) * 2)
    score = max(0, min(100, score))
    level = "low" if score < 40 else "medium" if score < 70 else "high"
    meta = body.get("metadata") or {}
    detected_kind = "ole" if meta.get("is_ole") else "unknown"
    return {
        "file": fname,
        "detected_kind": detected_kind,
        "macros": {
            "has_macros": has_macros,
            "macro_count": macro_count,
            "total_vba_size": total_vba_bytes,
            "autoexec_detected": autoexec_detected,
            "external_exec_detected": external_exec_found,
            "top_keywords": top_keywords,
            "obfuscation_signals": obfuscation_signals[:10],
        },
        "indicators": {
            "urls": urls,
            "base64_suspects": b64s,
            "embedded_object_lines": embedded_lines,
        },
        "risk": {"score": score, "level": level},
        "summary_hint": "정적 분석 근거만 사용해서 위험도를 평가하고, 핵심 근거와 조치를 간결히 제시하세요. 매크로 원문/민감 데이터는 절대 포함하지 마세요."
    }

def generate(analysis: dict) -> str:
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    payload = build_llm_payload_from_analysis(analysis)
    system_msg = types.Part.from_text(text=(
        "당신은 문서 악성코드 분석 전문가입니다.\n"
        "입력은 oletools 기반 정적 분석 요약(JSON)입니다.\n"
        "목표:\n"
        "1) 간결한 한국어 핵심 요약(1~3문장)\n"
        "2) 위험 판정: clean/suspicious/review 중 하나 제시\n"
        "3) 근거 3개 이내(자동실행/외부실행/난독화/URL/임베디드 등)\n"
        "4) 권고 조치(2개 이상)\n"
        "제한: 매크로 원문이나 민감 데이터는 절대 포함하지 마세요."
    ))
    user_msg = types.Part.from_text(text=json.dumps(payload, ensure_ascii=False, indent=2))
    config = types.GenerateContentConfig(
        temperature=0.3,
        max_output_tokens=800,
        system_instruction=[system_msg],
    )
    try:
        chunks = []
        for chunk in client.models.generate_content_stream(
            model="gemini-2.5-pro",
            contents=[types.Content(role="user", parts=[user_msg])],
            config=config,
        ):
            if getattr(chunk, "text", None):
                chunks.append(chunk.text)
        return "".join(chunks).strip() or "분석 결과를 생성하지 못했습니다."
    except Exception as e:
        return f"[LLM 오류] {e}"
