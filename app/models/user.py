from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base

class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    provider = Column(String, default="local")
    social_id = Column(String, nullable=True)
    user_id = Column(String, nullable=True, unique=True)
    password = Column(String, nullable=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=True)