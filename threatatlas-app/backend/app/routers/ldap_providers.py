"""Admin CRUD and connection checks for LDAP identity providers."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.auth.permissions import require_admin
from app.auth.secrets import encrypt_secret
from app.database import get_db
from app.models import LDAPProviderConfig, User as UserModel
from app.schemas.ldap_provider import (
    LDAPConnectionTest,
    LDAPProviderCreate,
    LDAPProviderRead,
    LDAPProviderUpdate,
)
from app.services.ldap_auth import LDAPUnavailableError, test_ldap_connection

router = APIRouter(prefix="/ldap/providers", tags=["ldap"])


@router.get("", response_model=list[LDAPProviderRead])
def list_providers(
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(current_user)
    return db.query(LDAPProviderConfig).order_by(LDAPProviderConfig.id).all()


@router.post("", response_model=LDAPProviderRead, status_code=status.HTTP_201_CREATED)
def create_provider(
    payload: LDAPProviderCreate,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(current_user)
    data = payload.model_dump(exclude={"bind_password"})
    provider = LDAPProviderConfig(
        **data,
        bind_password_encrypted=encrypt_secret(payload.bind_password),
    )
    db.add(provider)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"LDAP provider with name '{payload.name}' already exists",
        )
    db.refresh(provider)
    return provider


@router.put("/{provider_id}", response_model=LDAPProviderRead)
def update_provider(
    provider_id: int,
    payload: LDAPProviderUpdate,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(current_user)
    provider = db.query(LDAPProviderConfig).filter(LDAPProviderConfig.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="LDAP provider not found")

    data = payload.model_dump(exclude_unset=True)
    new_password = data.pop("bind_password", None)
    if new_password:
        provider.bind_password_encrypted = encrypt_secret(new_password)
    for field, value in data.items():
        setattr(provider, field, value)
    db.commit()
    db.refresh(provider)
    return provider


@router.post("/{provider_id}/test", response_model=LDAPConnectionTest)
def test_provider(
    provider_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(current_user)
    provider = db.query(LDAPProviderConfig).filter(LDAPProviderConfig.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="LDAP provider not found")
    try:
        test_ldap_connection(provider)
    except LDAPUnavailableError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return LDAPConnectionTest(success=True, message="LDAP bind and user base query succeeded")


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(
    provider_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(current_user)
    provider = db.query(LDAPProviderConfig).filter(LDAPProviderConfig.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="LDAP provider not found")
    linked_users = db.query(UserModel).filter(UserModel.ldap_provider == provider.name).count()
    if linked_users:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"LDAP provider has {linked_users} linked user(s); disable it instead of deleting it"
            ),
        )
    db.delete(provider)
    db.commit()
