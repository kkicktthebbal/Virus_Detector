import os
import subprocess
import json
import sys

from fastapi import APIRouter, UploadFile, File 
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from app.LLM.gemini import generate
from fastapi.responses import HTMLResponse
from Info_Maker.Malicious_Analysis_fun import analyze_file

router = APIRouter(
    prefix = "/scan"
)

templates = Jinja2Templates(directory="templates")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "file")
@router.get("/office-hwp", response_class=HTMLResponse)
def index_page(request: Request):
        return templates.TemplateResponse("ms.html", {"request": request})


@router.post("/ms")
async def scan_ms(requset: Request, file: UploadFile = File(...)):

    save_path = os.path.join(UPLOAD_DIR, file.filename)
    content = await file.read()
    
    with open(save_path, "wb") as f:
        f.write(content)
    
    analysis_result = analyze_file(save_path)

    llm_summary = generate(analysis_result)

    return {
        "file": file.filename,
        "analysis": analysis_result,
        "llm_summary": llm_summary
    }