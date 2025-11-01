import sys
import os
import subprocess
import olefile
from oletools import oleid, olevba


def run_command_tool(command_name, filepath):
    command = [sys.executable, "-m", f"oletools.{command_name}", filepath]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
        stdout, stderr = process.communicate()

        return {
            "tool": command_name,
            "ok": process.returncode == 0,
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
        }
    except Exception as e:
        return {"tool": command_name, "ok": False, "error": str(e)}


def analyze_oleid(filepath):
    try:
        oid = oleid.OleID(filepath)
        indicators = oid.check()
        return [
            {
                "id": i.id,
                "name": i.name,
                "value": i.value,
                "description": i.description,
            }
            for i in indicators
        ]
    except Exception as e:
        return {"error": f"oleid 분석 오류: {e}"}


def analyze_metadata(filepath):
    try:
        if not olefile.isOleFile(filepath):
            return {"is_ole": False, "summary": None, "doc_summary": None}

        ole = olefile.OleFileIO(filepath)
        summary, doc_summary = {}, {}

        if ole.exists("SummaryInformation"):
            props = ole.getproperties("SummaryInformation")
            summary = {str(k): str(v) for k, v in props.items()}
        if ole.exists("DocumentSummaryInformation"):
            props = ole.getproperties("DocumentSummaryInformation")
            doc_summary = {str(k): str(v) for k, v in props.items()}
        ole.close()

        return {"is_ole": True, "summary": summary, "doc_summary": doc_summary}

    except Exception as e:
        return {"error": f"메타데이터 분석 오류: {e}"}


def analyze_olevba(filepath):
    if filepath.lower().endswith(".hwp"):
        return {"is_hwp": True, "has_macros": False, "macros": []}

    vba_parser = None
    try:
        vba_parser = olevba.VBA_Parser(filepath)
        has_macros = vba_parser.detect_vba_macros()

        result = {
            "is_hwp": False,
            "has_macros": has_macros,
            "macros": [],
            "keywords": [],
        }

        if has_macros:
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                result["macros"].append(
                    {
                        "filename": filename,
                        "stream_path": stream_path,
                        "vba_filename": vba_filename,
                        "code_size": len(vba_code),
                    }
                )


            for keyword, description, count in vba_parser.analyze_macros():
                if count > 0:
                    result["keywords"].append(
                        {"keyword": keyword, "description": description, "count": count}
                    )
        return result
    except Exception as e:
        return {"error": f"olevba 분석 오류: {e}"}
    finally:
        if vba_parser:
            vba_parser.close()



def analyze_file(filepath):
    if not os.path.exists(filepath):
        return {"ok": False, "error": f"파일을 찾을 수 없습니다: {filepath}"}

    filename = os.path.basename(filepath)
    result = {
        "file": filename,
        "oleid": analyze_oleid(filepath),
        "metadata": analyze_metadata(filepath),
        "olevba": analyze_olevba(filepath),
        "oledir": run_command_tool("oledir", filepath),
        "olemap": run_command_tool("olemap", filepath),
        "oletimes": run_command_tool("oletimes", filepath),
        "oleobj": run_command_tool("oleobj", filepath),
    }

    return {"ok": True, "analysis": result}
