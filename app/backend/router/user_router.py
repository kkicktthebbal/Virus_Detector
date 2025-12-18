from fastapi import APIRouter, Depends, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from app.backend.schema.user_schema import LocalUserCreate
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.backend.service.user_service import create_local_user, local_login
from itsdangerous import URLSafeSerializer
from app.config import SECRET_KEY 
 
router = APIRouter(
     prefix="/api"
)
templates = Jinja2Templates(directory="templates")

serializer = URLSafeSerializer(SECRET_KEY)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
        return templates.TemplateResponse("/login.html", {"request": request})

@router.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
        return templates.TemplateResponse("signup.html", {"request": request})

@router.post("/signup_user")
def pcreate_user(schema: LocalUserCreate, db : Session = Depends(get_db)):
    create_local_user(db, schema)
    response = RedirectResponse(url="/index.html", status_code=303)
    return response


@router.post("/login")
def loginProc(request: Request, user_id: str = Form(...), password: str = Form(...), db : Session = Depends(get_db)):
    user = local_login(db, user_id, password)
    if user:
        cookie_value = serializer.dumps(user_id)
        response = RedirectResponse(url="/index.html", status_code=303)
        response.set_cookie(key="session", value=cookie_value, httponly=True)
        return response
    else:
        return templates.TemplateResponse("/login.html", {"request": request, "error": "아이디 또는 비밀번호가 틀렸습니다."})


@router.post("/logout")
async def logout(response: Response):
    response = RedirectResponse(url="/index.html", status_code=303)
    response.delete_cookie("session")
    return response