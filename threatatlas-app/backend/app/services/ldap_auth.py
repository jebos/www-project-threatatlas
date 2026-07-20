import ssl
from dataclasses import dataclass

from ldap3 import AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND, BASE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from pydantic import EmailStr, TypeAdapter, ValidationError

from app.auth.secrets import decrypt_secret
from app.models import LDAPProviderConfig


_EMAIL_ADAPTER = TypeAdapter(EmailStr)


class LDAPAuthenticationError(Exception):
    """Credentials or directory identity data are invalid."""


class LDAPUnavailableError(Exception):
    """The configured directory cannot be reached or queried."""


@dataclass(frozen=True)
class LDAPIdentity:
    dn: str
    username: str
    email: str
    full_name: str


def _server(provider: LDAPProviderConfig) -> Server:
    tls = Tls(
        validate=ssl.CERT_REQUIRED if provider.verify_cert else ssl.CERT_NONE,
        version=ssl.PROTOCOL_TLS_CLIENT,
    )
    return Server(
        provider.host,
        port=provider.port,
        use_ssl=provider.encryption == "simple_tls",
        tls=tls,
        connect_timeout=10,
    )


def _auto_bind(provider: LDAPProviderConfig):
    return AUTO_BIND_TLS_BEFORE_BIND if provider.encryption == "start_tls" else AUTO_BIND_NO_TLS


def _first(attributes: dict, name: str) -> str | None:
    value = attributes.get(name)
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _directory_connection(provider: LDAPProviderConfig) -> Connection:
    try:
        return Connection(
            _server(provider),
            user=provider.bind_dn,
            password=decrypt_secret(provider.bind_password_encrypted),
            auto_bind=_auto_bind(provider),
            receive_timeout=10,
            raise_exceptions=True,
        )
    except (LDAPException, OSError, RuntimeError) as exc:
        raise LDAPUnavailableError("Could not bind to the configured LDAP directory") from exc


def test_ldap_connection(provider: LDAPProviderConfig) -> None:
    connection = _directory_connection(provider)
    try:
        if not connection.search(provider.user_base_dn, "(objectClass=*)", BASE, attributes=[]):
            raise LDAPUnavailableError("LDAP user base DN is not readable")
    except LDAPException as exc:
        raise LDAPUnavailableError("LDAP user base DN query failed") from exc
    finally:
        connection.unbind()


def authenticate_ldap_user(provider: LDAPProviderConfig, username: str, password: str) -> LDAPIdentity:
    if not password:
        raise LDAPAuthenticationError("Invalid LDAP username or password")

    directory = _directory_connection(provider)
    try:
        escaped_username = escape_filter_chars(username.strip())
        user_filter = provider.user_filter.replace("{username}", escaped_username)
        attributes = {
            provider.username_attribute,
            provider.email_attribute,
            provider.display_name_attribute,
        }
        if provider.active_directory:
            attributes.add("userAccountControl")

        found = directory.search(
            provider.user_base_dn,
            user_filter,
            SUBTREE,
            attributes=sorted(attributes),
            size_limit=2,
        )
        if not found or len(directory.entries) != 1:
            raise LDAPAuthenticationError("Invalid LDAP username or password")

        entry = directory.entries[0]
        values = entry.entry_attributes_as_dict
        if provider.active_directory:
            user_account_control = _first(values, "userAccountControl")
            if user_account_control and int(user_account_control) & 2:
                raise LDAPAuthenticationError("LDAP account is disabled")

        email = _first(values, provider.email_attribute)
        directory_username = _first(values, provider.username_attribute) or username.strip()
        full_name = _first(values, provider.display_name_attribute) or directory_username
        try:
            normalized_email = str(_EMAIL_ADAPTER.validate_python(email))
        except ValidationError:
            raise LDAPAuthenticationError("LDAP account has no valid email attribute")

        try:
            user_connection = Connection(
                _server(provider),
                user=entry.entry_dn,
                password=password,
                auto_bind=_auto_bind(provider),
                receive_timeout=10,
                raise_exceptions=True,
            )
        except (LDAPException, OSError) as exc:
            raise LDAPAuthenticationError("Invalid LDAP username or password") from exc
        else:
            user_connection.unbind()

        return LDAPIdentity(
            dn=entry.entry_dn,
            username=directory_username,
            email=normalized_email,
            full_name=full_name,
        )
    except LDAPAuthenticationError:
        raise
    except (LDAPException, OSError, ValueError) as exc:
        raise LDAPUnavailableError("LDAP search failed") from exc
    finally:
        directory.unbind()
