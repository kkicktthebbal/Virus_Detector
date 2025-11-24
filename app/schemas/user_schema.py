from pydantic import BaseModel, field_validator

class LocalUserCreate(BaseModel):
    user_id : str
    password : str
    check_password : str
    name : str
    email : str
    @field_validator('check_password')
    def password_match(cls, v, info):
        if v != info.data['password']:
            raise ValueError('Passwords do not match')
        return v
    
class SocialUserCreate(BaseModel):
    provider : str
    social_id : str
    name : str
    email : str
    

