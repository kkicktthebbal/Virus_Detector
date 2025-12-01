from fastapi import FastAPI, Request, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from app.routers import scan_router, user_router, oauth_router
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
def index_page(request: Request, db: Session = Depends(get_db)):
    cookie = request.cookies.get("session")
    user = None
    if cookie:
        try:
            user_id = oauth_router.serializer.loads(cookie)
            user = db.query(User).filter(User.user_id == user_id).first()
        except Exception as e:
            user = None

    return templates.TemplateResponse("index.html", {"request": request, "user": user})

app.include_router(scan_router.router)
app.include_router(user_router.router)
app.include_router(oauth_router.router)