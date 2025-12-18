import os
import json
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Form
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse

# 통합 파일 분석 모듈 import
from backend.analyze.file_analyzer import analyze_file

# Gemini 분석 함수들 import
from backend.LLM.gemini import (
    generate_pdf_summary,
    generate_pe_summary,
    generate_zip_summary,
    generate_office_summary
)

router = APIRouter(
    prefix="/scan"
)

templates = Jinja2Templates(directory="templates")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "file")

# 업로드 디렉토리 생성
os.makedirs(UPLOAD_DIR, exist_ok=True)


@router.get("/office-hwp", response_class=HTMLResponse)
def office_hwp_page(request: Request):
    """MS Office/HWP 스캔 페이지"""
    return templates.TemplateResponse("ms3.html", {"request": request})


@router.get("/pdf", response_class=HTMLResponse)
def pdf_page(request: Request):
    """PDF 스캔 페이지"""
    return templates.TemplateResponse("pdf_scan.html", {"request": request})


@router.get("/executable", response_class=HTMLResponse)
def executable_page(request: Request):
    """실행파일 스캔 페이지"""
    return templates.TemplateResponse("exe_scan.html", {"request": request})


@router.get("/zip", response_class=HTMLResponse)
def zip_page(request: Request):
    """ZIP 파일 스캔 페이지"""
    return templates.TemplateResponse("zip_scan.html", {"request": request})


@router.post("/ms")
async def scan_ms(request: Request, file: UploadFile = File(...)):
    """MS Office/HWP 파일 스캔 API"""
    save_path = os.path.join(UPLOAD_DIR, file.filename)
    content = await file.read()
    
    with open(save_path, "wb") as f:
        f.write(content)
    
    # 파일 분석
    analysis_result = analyze_file(save_path)
    
    # Gemini를 통한 요약 생성
    llm_summary = None
    if "error" not in analysis_result:
        try:
            llm_summary = generate_office_summary(analysis_result)
        except Exception as e:
            llm_summary = json.dumps({
                "summary": f"LLM 분석 실패: {str(e)}",
                "risk_score": 0,
                "risk_level": "low",
                "reasons": [],
                "recommended_actions": []
            }, ensure_ascii=False)
    
    return {
        "file": file.filename,
        "analysis": analysis_result,
        "llm_summary": llm_summary
    }


@router.post("/pdf")
async def scan_pdf(request: Request, file: UploadFile = File(...)):
    """PDF 파일 스캔 API"""
    save_path = os.path.join(UPLOAD_DIR, file.filename)
    content = await file.read()
    
    with open(save_path, "wb") as f:
        f.write(content)
    
    # 파일 분석
    analysis_result = analyze_file(save_path)
    
    # Gemini를 통한 요약 생성
    llm_summary = None
    if "error" not in analysis_result:
        try:
            llm_summary = generate_pdf_summary(analysis_result)
        except Exception as e:
            llm_summary = json.dumps({
                "summary": f"LLM 분석 실패: {str(e)}",
                "risk_score": 0,
                "risk_level": "low",
                "reasons": [],
                "recommended_actions": []
            }, ensure_ascii=False)
    
    return {
        "file": file.filename,
        "analysis": analysis_result,
        "llm_summary": llm_summary
    }


@router.post("/executable")
async def scan_executable(request: Request, file: UploadFile = File(...)):
    """실행파일(EXE/DLL) 스캔 API"""
    save_path = os.path.join(UPLOAD_DIR, file.filename)
    content = await file.read()
    
    with open(save_path, "wb") as f:
        f.write(content)
    
    # 파일 분석
    analysis_result = analyze_file(save_path)
    
    # Gemini를 통한 요약 생성
    llm_summary = None
    if "error" not in analysis_result:
        try:
            llm_summary = generate_pe_summary(analysis_result)
        except Exception as e:
            llm_summary = json.dumps({
                "summary": f"LLM 분석 실패: {str(e)}",
                "risk_score": 0,
                "risk_level": "low",
                "reasons": [],
                "recommended_actions": []
            }, ensure_ascii=False)
    
    return {
        "file": file.filename,
        "analysis": analysis_result,
        "llm_summary": llm_summary
    }


@router.post("/zip")
async def scan_zip(request: Request, file: UploadFile = File(...)):
    """ZIP 파일 스캔 API"""
    save_path = os.path.join(UPLOAD_DIR, file.filename)
    content = await file.read()
    
    with open(save_path, "wb") as f:
        f.write(content)
    
    # 파일 분석
    analysis_result = analyze_file(save_path)
    
    # Gemini를 통한 요약 생성
    llm_summary = None
    if "error" not in analysis_result:
        try:
            llm_summary = generate_zip_summary(analysis_result)
        except Exception as e:
            llm_summary = json.dumps({
                "summary": f"LLM 분석 실패: {str(e)}",
                "risk_score": 0,
                "risk_level": "low",
                "reasons": [],
                "recommended_actions": []
            }, ensure_ascii=False)
    
    return {
        "file": file.filename,
        "analysis": analysis_result,
        "llm_summary": llm_summary
    }


@router.post("/analyze")
async def scan_any_file(request: Request, file: UploadFile = File(...)):
    """
    범용 파일 스캔 API
    확장자를 자동으로 감지하여 적절한 분석 수행
    """
    save_path = os.path.join(UPLOAD_DIR, file.filename)
    content = await file.read()
    
    with open(save_path, "wb") as f:
        f.write(content)
    
    # 파일 분석
    analysis_result = analyze_file(save_path)
    
    # 파일 타입에 따라 적절한 Gemini 분석 수행
    llm_summary = None
    if "error" not in analysis_result:
        try:
            file_type = analysis_result.get("file_type")
            
            if file_type == "pdf":
                llm_summary = generate_pdf_summary(analysis_result)
            elif file_type == "pe":
                llm_summary = generate_pe_summary(analysis_result)
            elif file_type == "zip":
                llm_summary = generate_zip_summary(analysis_result)
            elif file_type == "office_hwp":
                llm_summary = generate_office_summary(analysis_result)
                
        except Exception as e:
            llm_summary = json.dumps({
                "summary": f"LLM 분석 실패: {str(e)}",
                "risk_score": 0,
                "risk_level": "low",
                "reasons": [],
                "recommended_actions": []
            }, ensure_ascii=False)
    
    response = {
        "file": file.filename,
        "analysis": analysis_result
    }
    
    if llm_summary:
        response["llm_summary"] = llm_summary
    
    return response