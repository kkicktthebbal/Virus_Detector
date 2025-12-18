from sqlalchemy import Column, Integer, String
from app.core.database import Base

class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(20), nullable=False, default="local")
    social_id = Column(String(100), nullable=True)
    user_id = Column(String(150), nullable=True, unique=True, index=True)
    password = Column(String(255), nullable=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), nullable=True, index=True)