from pydantic import BaseModel, EmailStr, Field, field_validator


class Token(BaseModel):
    """JWT token response schema."""
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Decoded token data schema."""
    user_id: int | None = None


class LoginRequest(BaseModel):
    """Login request schema."""
    email: EmailStr
    password: str


class LDAPLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("username")
    @classmethod
    def strip_username(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("username must not be blank")
        return value


class OIDCProviderInfo(BaseModel):
    """Public-facing information about a configured OIDC provider."""
    name: str
    display_name: str
    login_url: str
