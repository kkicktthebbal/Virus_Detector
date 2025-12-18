from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.backend.service.user_service import create_or_get_social_user
from app.backend.schema.user_schema import SocialUserCreate
from itsdangerous import URLSafeSerializer
import httpx
import secrets
from app.config import (
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
    GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_REDIRECT_URI,
    SECRET_KEY
)

router = APIRouter(prefix="/auth")
serializer = URLSafeSerializer(SECRET_KEY)

oauth_states = {}


@router.get("/api/google")
async def google_login():
    state = secrets.token_urlsafe(32)
    oauth_states[state] = True
    
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={GOOGLE_REDIRECT_URI}&"
        f"response_type=code&"
        f"scope=openid email profile&"
        f"state={state}"
    )
    return RedirectResponse(google_auth_url)


@router.get("/google/callback")
async def google_callback(request: Request, code: str, state: str, db: Session = Depends(get_db)):
    if state not in oauth_states:
        return RedirectResponse(url="/login.html?error=invalid_state")
    
    del oauth_states[state]
    
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": GOOGLE_REDIRECT_URI,
            }
        )
        
        if token_response.status_code != 200:
            return RedirectResponse(url="/login.html?error=token_failed")
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        
        user_response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if user_response.status_code != 200:
            return RedirectResponse(url="/login.html?error=user_info_failed")
        
        user_data = user_response.json()
    
    social_user_schema = SocialUserCreate(
        provider="google",
        social_id=user_data["id"],
        name=user_data.get("name", ""),
        email=user_data.get("email", "")
    )
    
    user = create_or_get_social_user(db, social_user_schema)
    
    cookie_value = serializer.dumps(user.user_id)
    response = RedirectResponse(url="/index.html", status_code=303)
    response.set_cookie(key="session", value=cookie_value, httponly=True)
    
    return response


@router.get("/github")
async def github_login():
    state = secrets.token_urlsafe(32)
    oauth_states[state] = True
    
    github_auth_url = (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"redirect_uri={GITHUB_REDIRECT_URI}&"
        f"scope=read:user user:email&"
        f"state={state}"
    )
    return RedirectResponse(github_auth_url)


@router.get("/github/callback")
async def github_callback(request: Request, code: str, state: str, db: Session = Depends(get_db)):
    if state not in oauth_states:
        return RedirectResponse(url="/login.html?error=invalid_state")
    
    del oauth_states[state]
    
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": GITHUB_REDIRECT_URI,
            },
            headers={"Accept": "application/json"}
        )
        
        if token_response.status_code != 200:
            return RedirectResponse(url="/login.html?error=token_failed")
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        
        user_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
        )
        
        if user_response.status_code != 200:
            return RedirectResponse(url="/login.html?error=user_info_failed")
        
        user_data = user_response.json()
        
        email = user_data.get("email")
        if not email:
            email_response = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json"
                }
            )
            if email_response.status_code == 200:
                emails = email_response.json()
                primary_email = next((e for e in emails if e.get("primary")), None)
                if primary_email:
                    email = primary_email.get("email", "")
    
    social_user_schema = SocialUserCreate(
        provider="github",
        social_id=str(user_data["id"]),
        name=user_data.get("name") or user_data.get("login", ""),
        email=email or ""
    )
    
    user = create_or_get_social_user(db, social_user_schema)
    
    cookie_value = serializer.dumps(user.user_id)
    response = RedirectResponse(url="/index.html", status_code=303)
    response.set_cookie(key="session", value=cookie_value, httponly=True)
    
    return response