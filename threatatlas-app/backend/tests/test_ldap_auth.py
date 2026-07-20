from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.password import get_password_hash
from app.auth.secrets import decrypt_secret, encrypt_secret
from app.models import LDAPProviderConfig, User
from app.services.ldap_auth import LDAPAuthenticationError, LDAPIdentity, LDAPUnavailableError


def _provider(db: Session, **overrides) -> LDAPProviderConfig:
    values = {
        "name": "corp",
        "display_name": "Corporate Directory",
        "host": "ldap.example.test",
        "port": 636,
        "encryption": "simple_tls",
        "verify_cert": True,
        "bind_dn": "cn=service,dc=example,dc=test",
        "bind_password_encrypted": encrypt_secret("bind-secret"),
        "user_base_dn": "ou=people,dc=example,dc=test",
        "user_filter": "(uid={username})",
        "username_attribute": "uid",
        "email_attribute": "mail",
        "display_name_attribute": "cn",
        "active_directory": False,
        "auto_create_users": True,
        "is_enabled": True,
    }
    values.update(overrides)
    provider = LDAPProviderConfig(**values)
    db.add(provider)
    db.flush()
    return provider


def _identity(email: str = "alice@example.com") -> LDAPIdentity:
    return LDAPIdentity(
        dn="uid=alice,ou=people,dc=example,dc=test",
        username="alice",
        email=email,
        full_name="Alice Directory",
    )


def test_admin_can_create_provider_without_exposing_password(
    client: TestClient,
    db: Session,
    admin_headers: dict,
):
    response = client.post(
        "/api/ldap/providers",
        headers=admin_headers,
        json={
            "name": "corp",
            "display_name": "Corporate Directory",
            "host": "ldap.example.test",
            "port": 636,
            "encryption": "simple_tls",
            "verify_cert": True,
            "bind_dn": "cn=service,dc=example,dc=test",
            "bind_password": "bind-secret",
            "user_base_dn": "ou=people,dc=example,dc=test",
            "user_filter": "(uid={username})",
        },
    )

    assert response.status_code == 201
    assert "bind_password" not in response.json()
    stored = db.query(LDAPProviderConfig).filter_by(name="corp").one()
    assert stored.bind_password_encrypted != "bind-secret"
    assert decrypt_secret(stored.bind_password_encrypted) == "bind-secret"


def test_non_admin_cannot_manage_providers(client: TestClient, user_headers: dict):
    response = client.get("/api/ldap/providers", headers=user_headers)
    assert response.status_code == 403


def test_public_provider_list_contains_only_enabled(client: TestClient, db: Session):
    _provider(db)
    _provider(db, name="disabled", display_name="Disabled", is_enabled=False)

    response = client.get("/api/auth/ldap/providers")

    assert response.status_code == 200
    assert response.json() == [{"name": "corp", "display_name": "Corporate Directory"}]


def test_admin_can_test_directory_connection(
    client: TestClient,
    db: Session,
    admin_headers: dict,
):
    provider = _provider(db)
    with patch("app.routers.ldap_providers.test_ldap_connection") as connection_test:
        response = client.post(f"/api/ldap/providers/{provider.id}/test", headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["success"] is True
    connection_test.assert_called_once_with(provider)


def test_provider_with_linked_users_cannot_be_deleted(
    client: TestClient,
    db: Session,
    admin_headers: dict,
):
    provider = _provider(db)
    db.add(
        User(
            email="alice@example.com",
            username="alice",
            hashed_password=None,
            full_name="Alice Directory",
            is_active=True,
            role="standard",
            ldap_provider=provider.name,
            ldap_dn="uid=alice,ou=people,dc=example,dc=test",
        )
    )
    db.flush()

    response = client.delete(f"/api/ldap/providers/{provider.id}", headers=admin_headers)

    assert response.status_code == 409
    assert "disable it instead" in response.json()["detail"]
    assert db.get(LDAPProviderConfig, provider.id) is not None


def test_ldap_login_creates_and_links_user(client: TestClient, db: Session):
    _provider(db)
    with patch("app.routers.auth.authenticate_ldap_user", return_value=_identity()):
        response = client.post(
            "/api/auth/ldap/corp/login",
            json={"username": "alice", "password": "Directory-Password1!"},
        )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    user = db.query(User).filter_by(email="alice@example.com").one()
    assert user.username == "alice"
    assert user.full_name == "Alice Directory"
    assert user.hashed_password is None
    assert user.ldap_provider == "corp"
    assert user.ldap_dn == _identity().dn


def test_ldap_login_links_existing_local_user_and_disables_local_password_login(
    client: TestClient,
    db: Session,
):
    _provider(db)
    db.add(
        User(
            email="alice@example.com",
            username="alice-local",
            hashed_password=get_password_hash("Local-Password1!"),
            full_name="Alice Local",
            is_active=True,
            role="standard",
        )
    )
    db.flush()
    with patch("app.routers.auth.authenticate_ldap_user", return_value=_identity()):
        ldap_response = client.post(
            "/api/auth/ldap/corp/login",
            json={"username": "alice", "password": "Directory-Password1!"},
        )

    local_response = client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": "Local-Password1!"},
    )
    assert ldap_response.status_code == 200
    assert local_response.status_code == 401, local_response.text


def test_ldap_login_does_not_replace_a_different_linked_identity(
    client: TestClient,
    db: Session,
):
    _provider(db)
    original_dn = "uid=original,ou=people,dc=example,dc=test"
    user = User(
        email="alice@example.com",
        username="alice",
        hashed_password=None,
        full_name="Original Alice",
        is_active=True,
        role="admin",
        ldap_provider="corp",
        ldap_dn=original_dn,
    )
    db.add(user)
    db.flush()

    with patch("app.routers.auth.authenticate_ldap_user", return_value=_identity()):
        response = client.post(
            "/api/auth/ldap/corp/login",
            json={"username": "alice", "password": "Directory-Password1!"},
        )

    assert response.status_code == 409
    db.refresh(user)
    assert user.ldap_dn == original_dn
    assert user.full_name == "Original Alice"


def test_ldap_login_respects_auto_create_setting(client: TestClient, db: Session):
    _provider(db, auto_create_users=False)
    with patch("app.routers.auth.authenticate_ldap_user", return_value=_identity()):
        response = client.post(
            "/api/auth/ldap/corp/login",
            json={"username": "alice", "password": "Directory-Password1!"},
        )

    assert response.status_code == 403
    assert db.query(User).filter_by(email="alice@example.com").first() is None


def test_ldap_login_returns_generic_authentication_failure(client: TestClient, db: Session):
    _provider(db)
    with patch(
        "app.routers.auth.authenticate_ldap_user",
        side_effect=LDAPAuthenticationError("Invalid LDAP username or password"),
    ):
        response = client.post(
            "/api/auth/ldap/corp/login",
            json={"username": "alice", "password": "wrong"},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid LDAP username or password"


def test_ldap_outage_returns_service_unavailable(client: TestClient, db: Session):
    _provider(db)
    with patch(
        "app.routers.auth.authenticate_ldap_user",
        side_effect=LDAPUnavailableError("Could not bind to the configured LDAP directory"),
    ):
        response = client.post(
            "/api/auth/ldap/corp/login",
            json={"username": "alice", "password": "Directory-Password1!"},
        )

    assert response.status_code == 503
