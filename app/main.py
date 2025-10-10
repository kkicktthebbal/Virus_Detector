from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from app.routers import scan_router

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
def index_page(request: Request):
        return templates.TemplateResponse("index.html", {"request": request})

app.include_router(scan_router.router)
