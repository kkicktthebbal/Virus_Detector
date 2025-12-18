"""
통합 파일 분석 모듈
원본 Analyze_*.py 스크립트를 실행하고 결과를 반환합니다.
"""
import os
import sys
import subprocess
from typing import Dict, Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def analyze_pdf(filepath: str) -> Dict[str, Any]:
    """PDF 파일을 Analyze_PDF.py로 분석"""
    script_path = os.path.join(BASE_DIR, "Analyze_PDF.py")
    
    try:
        result = subprocess.run(
            [sys.executable, script_path, filepath],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        return {
            "file_type": "pdf",
            "file_name": os.path.basename(filepath),
            "script_output": result.stdout,
            "script_error": result.stderr if result.returncode != 0 else None,
            "returncode": result.returncode
        }
    except Exception as e:
        return {
            "file_type": "pdf",
            "file_name": os.path.basename(filepath),
            "error": f"분석 중 예외 발생: {str(e)}"
        }


def analyze_pe(filepath: str) -> Dict[str, Any]:
    """PE(실행파일)를 Analyze_PE.py로 분석"""
    script_path = os.path.join(BASE_DIR, "Analyze_PE.py")
    
    try:
        result = subprocess.run(
            [sys.executable, script_path, filepath],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        return {
            "file_type": "pe",
            "file_name": os.path.basename(filepath),
            "script_output": result.stdout,
            "script_error": result.stderr if result.returncode != 0 else None,
            "returncode": result.returncode
        }
    except Exception as e:
        return {
            "file_type": "pe",
            "file_name": os.path.basename(filepath),
            "error": f"분석 중 예외 발생: {str(e)}"
        }


def analyze_zip(filepath: str) -> Dict[str, Any]:
    """ZIP 파일을 Analyze_ZIP.py로 분석"""
    script_path = os.path.join(BASE_DIR, "Analyze_ZIP.py")
    
    try:
        result = subprocess.run(
            [sys.executable, script_path, filepath],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        return {
            "file_type": "zip",
            "file_name": os.path.basename(filepath),
            "script_output": result.stdout,
            "script_error": result.stderr if result.returncode != 0 else None,
            "returncode": result.returncode
        }
    except Exception as e:
        return {
            "file_type": "zip",
            "file_name": os.path.basename(filepath),
            "error": f"분석 중 예외 발생: {str(e)}"
        }


def analyze_mshwp(filepath: str) -> Dict[str, Any]:
    """MS Office/HWP 파일을 MSHWP_Analysis.py로 분석"""
    script_path = os.path.join(BASE_DIR, "MSHWP_Analysis.py")
    
    try:
        result = subprocess.run(
            [sys.executable, script_path, filepath],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        return {
            "file_type": "office_hwp",
            "file_name": os.path.basename(filepath),
            "script_output": result.stdout,
            "script_error": result.stderr if result.returncode != 0 else None,
            "returncode": result.returncode
        }
    except Exception as e:
        return {
            "file_type": "office_hwp",
            "file_name": os.path.basename(filepath),
            "error": f"분석 중 예외 발생: {str(e)}"
        }


def analyze_file(filepath: str) -> Dict[str, Any]:
    """
    파일 확장자를 확인하고 적절한 분석 스크립트를 실행합니다.
    """
    if not os.path.exists(filepath):
        return {"error": "파일을 찾을 수 없습니다", "filepath": filepath}
    
    ext = os.path.splitext(filepath)[1].lower()
    
    # 파일 타입별 분석
    if ext == '.pdf':
        return analyze_pdf(filepath)
    elif ext in ['.exe', '.dll', '.sys']:
        return analyze_pe(filepath)
    elif ext == '.zip':
        return analyze_zip(filepath)
    elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.hwp']:
        return analyze_mshwp(filepath)
    else:
        return {
            "error": "지원하지 않는 파일 형식입니다",
            "file_name": os.path.basename(filepath),
            "extension": ext,
            "supported_types": [".pdf", ".exe", ".dll", ".zip", ".doc", ".docx", 
                              ".xls", ".xlsx", ".ppt", ".pptx", ".hwp"]
        }