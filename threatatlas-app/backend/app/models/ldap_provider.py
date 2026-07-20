from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.sql import func

from app.database import Base


class LDAPProviderConfig(Base):
    """LDAP or Active Directory provider configured at runtime."""

    __tablename__ = "ldap_providers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, index=True, nullable=False)
    display_name = Column(String(128), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False, default=636)
    encryption = Column(String(16), nullable=False, default="simple_tls")
    verify_cert = Column(Boolean, nullable=False, default=True)
    bind_dn = Column(String(1024), nullable=False)
    bind_password_encrypted = Column(String(2048), nullable=False)
    user_base_dn = Column(String(1024), nullable=False)
    user_filter = Column(String(1024), nullable=False, default="(uid={username})")
    username_attribute = Column(String(128), nullable=False, default="uid")
    email_attribute = Column(String(128), nullable=False, default="mail")
    display_name_attribute = Column(String(128), nullable=False, default="cn")
    active_directory = Column(Boolean, nullable=False, default=False)
    auto_create_users = Column(Boolean, nullable=False, default=True)
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
