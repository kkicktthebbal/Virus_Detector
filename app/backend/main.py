from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.backend.router import scan_router, user_router, oauth_router
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.backend.model.user import User
import os
from app.core.database import Base, engine

app = FastAPI(
    title="SafeScan API",
    description="Malware Detection & Analysis API",
    version="1.0.0"
)

# ==========================================
# CORS 설정 - CloudFront 도메인 허용
# ==========================================
origins = [
    "http://localhost:3000",
    "http://localhost:8080",
    "https://d2atpnajyyx47s.cloudfront.net",  # CloudFront 도메인
    "https://virusscan.click",                 # 커스텀 도메인
    "https://www.virusscan.click"
]

# 환경변수로 추가 CORS origin 설정
if os.getenv("CORS_ORIGINS"):
    additional_origins = os.getenv("CORS_ORIGINS").split(",")
    origins.extend([origin.strip() for origin in additional_origins])

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# ==========================================
# Health Check 엔드포인트
# ==========================================

@app.get("/health")
def health_check():
    """Internal ALB Health Check 엔드포인트 (기존 호환성)"""
    return {
        "status": "healthy",
        "service": "safescan-api",
        "version": "1.0.0"
    }

@app.get("/api/health")
def api_health_check():
    """API Health Check 엔드포인트"""
    return {
        "status": "healthy",
        "service": "safescan-api",
        "version": "1.0.0"
    }

@app.get("/api/health/deep")
def deep_health_check(db: Session = Depends(get_db)):
    """데이터베이스 연결 확인"""
    try:
        db.execute("SELECT 1")
        return {
            "status": "healthy",
            "database": "connected"
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "database": "disconnected",
                "error": str(e)
            }
        )

# ==========================================
# 루트 엔드포인트
# ==========================================

@app.get("/")
def root():
    """API 정보 반환"""
    return {
        "service": "SafeScan API",
        "version": "1.0.0",
        "status": "running",
        "frontend": "https://d2atpnajyyx47s.cloudfront.net",
        "endpoints": {
            "health": "/api/health",
            "api_me": "/api/me",
            "scan_pdf": "/api/scan/pdf",
            "scan_exe": "/api/scan/executable",
            "scan_zip": "/api/scan/zip",
            "scan_ms": "/api/scan/ms",
            "auth_google": "/api/auth/google",
            "auth_github": "/api/auth/github",
            "login": "/api/login",
            "logout": "/api/logout",
            "signup": "/api/signup_user"
        }
    }

# 라우터 등록
app.include_router(scan_router.router)
app.include_router(user_router.router)
app.include_router(oauth_router.router)

@app.on_event("startup")
async def startup_event():
    print("=" * 70)
    print("SafeScan API Server Started")
    print(f"CORS Origins: {origins}")
    print("All API endpoints now use /api prefix")
    print("=" * 70)

@app.on_event("shutdown")
async def shutdown_event():
    print("SafeScan API Server Shutdown")
    
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)