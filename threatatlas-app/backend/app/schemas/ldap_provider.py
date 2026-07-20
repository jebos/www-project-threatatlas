import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_ATTRIBUTE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9;-]{0,127}$")


class LDAPProviderBase(BaseModel):
    name: str = Field(..., description="URL-safe provider slug")
    display_name: str = Field(..., min_length=1, max_length=128)
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(default=636, ge=1, le=65535)
    encryption: Literal["plain", "start_tls", "simple_tls"] = "simple_tls"
    verify_cert: bool = True
    bind_dn: str = Field(..., min_length=1, max_length=1024)
    user_base_dn: str = Field(..., min_length=1, max_length=1024)
    user_filter: str = Field(default="(uid={username})", min_length=3, max_length=1024)
    username_attribute: str = Field(default="uid", min_length=1, max_length=128)
    email_attribute: str = Field(default="mail", min_length=1, max_length=128)
    display_name_attribute: str = Field(default="cn", min_length=1, max_length=128)
    active_directory: bool = False
    auto_create_users: bool = True
    is_enabled: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip().lower()
        if not _NAME_RE.match(value):
            raise ValueError("name must be lowercase letters, digits, '-' or '_', and start with a letter or digit")
        return value

    @field_validator("host", "bind_dn", "user_base_dn", "display_name")
    @classmethod
    def strip_required(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be blank")
        return value

    @field_validator("user_filter")
    @classmethod
    def validate_filter(cls, value: str) -> str:
        value = value.strip()
        if value.count("{username}") != 1:
            raise ValueError("user_filter must contain exactly one {username} placeholder")
        return value

    @field_validator("username_attribute", "email_attribute", "display_name_attribute")
    @classmethod
    def validate_attribute(cls, value: str) -> str:
        value = value.strip()
        if not _ATTRIBUTE_RE.match(value):
            raise ValueError("invalid LDAP attribute name")
        return value


class LDAPProviderCreate(LDAPProviderBase):
    bind_password: str = Field(..., min_length=1, max_length=2048)


class LDAPProviderUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    encryption: Literal["plain", "start_tls", "simple_tls"] | None = None
    verify_cert: bool | None = None
    bind_dn: str | None = Field(default=None, min_length=1, max_length=1024)
    bind_password: str | None = Field(default=None, min_length=1, max_length=2048)
    user_base_dn: str | None = Field(default=None, min_length=1, max_length=1024)
    user_filter: str | None = Field(default=None, min_length=3, max_length=1024)
    username_attribute: str | None = Field(default=None, min_length=1, max_length=128)
    email_attribute: str | None = Field(default=None, min_length=1, max_length=128)
    display_name_attribute: str | None = Field(default=None, min_length=1, max_length=128)
    active_directory: bool | None = None
    auto_create_users: bool | None = None
    is_enabled: bool | None = None

    @field_validator("host", "bind_dn", "user_base_dn", "display_name")
    @classmethod
    def strip_optional(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("value must not be blank")
        return value

    @field_validator("user_filter")
    @classmethod
    def validate_filter(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if value.count("{username}") != 1:
            raise ValueError("user_filter must contain exactly one {username} placeholder")
        return value

    @field_validator("username_attribute", "email_attribute", "display_name_attribute")
    @classmethod
    def validate_attribute(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _ATTRIBUTE_RE.match(value):
            raise ValueError("invalid LDAP attribute name")
        return value


class LDAPProviderRead(LDAPProviderBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class LDAPProviderInfo(BaseModel):
    name: str
    display_name: str


class LDAPConnectionTest(BaseModel):
    success: bool
    message: str
