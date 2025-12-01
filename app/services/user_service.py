from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.schemas.user_schema import LocalUserCreate, SocialUserCreate
from app.models.user import User
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_local_user(db : Session, schema : LocalUserCreate):
    hashed_password = hash_password(schema.password)
    new_user = User(user_id = schema.user_id,
                    password = hashed_password,
                    name = schema.name,
                    email = schema.email)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

def local_login(db: Session, user_id: str, password: str):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

def create_or_get_social_user(db: Session, schema: SocialUserCreate):
    user_id = f"{schema.provider}_{schema.social_id}"
    
    user = db.query(User).filter(User.user_id == user_id).first()
    
    if not user:
        new_user = User(
            user_id=user_id,
            password=None,
            name=schema.name,
            email=schema.email
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    
    return user