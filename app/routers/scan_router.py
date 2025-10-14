import os
import subprocess
import json
import sys

from fastapi import APIRouter, UploadFile, File 
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from app.LLM.gemini import generate
from fastapi.responses import HTMLResponse

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
    
    # 찬후님 다시 해줘요
    result = subprocess.run(
    [sys.executable, "-m", "oletools.olevba", "--json", save_path],
    capture_output=True,
    text=False,      
    check=True
    )

    raw = result.stdout or result.stderr or b""
    out = raw.decode("utf-8", errors="replace")
    analysis = json.loads(out)
    # 여기까지


    llm_summary = generate(analysis)

    return {
        "file": file.filename,
        "analysis": analysis,
        "llm_summary": llm_summary
    }