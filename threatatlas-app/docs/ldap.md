# LDAP and Active Directory authentication

ThreatAtlas can authenticate users directly against one or more LDAP-compatible
directories, including Microsoft Active Directory. Provider configuration is
stored in the database and managed by administrators under **Settings → SSO &
SCIM → LDAP / Active Directory**. The service-account password is encrypted at
rest with the application `SECRET_KEY` and is never returned by the API.

## Authentication flow

1. ThreatAtlas binds with the configured service account.
2. It searches exactly one user below the configured user base. The supplied
   username is escaped before insertion into the LDAP filter.
3. ThreatAtlas creates a separate LDAP connection and binds as the discovered
   user with the submitted password.
4. The directory email is linked to an existing ThreatAtlas user or creates a
   new standard user when **Auto-create users** is enabled.
5. ThreatAtlas issues its normal short-lived JWT. The LDAP password is never
   stored.

After an existing local account is linked to LDAP, its local password login is
disabled. This prevents an unmanaged local credential from bypassing directory
deactivation. Keep at least one separate local administrator as a break-glass
account.

## Active Directory example

| Setting | Example |
|---|---|
| Host | `ad.example.internal` |
| Port | `636` |
| Encryption | `simple_tls` (LDAPS) |
| Service bind DN | `CN=svc-threatatlas,OU=Service Accounts,DC=example,DC=internal` |
| User base DN | `OU=Users,DC=example,DC=internal` |
| User filter | `(sAMAccountName={username})` |
| Username attribute | `sAMAccountName` |
| Email attribute | `mail` or `userPrincipalName` |
| Display-name attribute | `displayName` |
| Active Directory checks | Enabled |

When Active Directory checks are enabled, accounts with the disabled bit in
`userAccountControl` cannot sign in. ThreatAtlas does not resolve AD trusts; the
configured directory must be able to find the user below the selected base DN.

Use LDAPS or STARTTLS with certificate verification in every non-test
environment. Plain LDAP transmits both the service credential and user password
without transport encryption.

## Users, groups, and roles

Direct LDAP handles authentication and just-in-time user creation. Continue to
use ThreatAtlas' SCIM 2.0 endpoint when directory groups and lifecycle changes
must be provisioned automatically. Newly SCIM-created groups start as
`read_only`; an administrator assigns their ThreatAtlas role once after the
first synchronization.

## Local Docker test directory

The optional overlay starts an isolated OpenLDAP directory containing `alice`
and `bob`:

```bash
docker compose -f docker-compose.yml -f docker-compose.ldap-test.yml up -d ldap-test
```

Test provider values:

| Setting | Value |
|---|---|
| Host from the backend container | `ldap-test` |
| Port | `389` |
| Encryption | `plain` |
| Verify certificate | Off |
| Service bind DN | `cn=threatatlas-bind,dc=example,dc=test` |
| Service bind password | `Bind-Password1!` |
| User base DN | `ou=People,dc=example,dc=test` |
| User filter | `(uid={username})` |
| Username / email / display attributes | `uid` / `mail` / `cn` |

The test login is `alice` / `Directory-Password1!`. These credentials are for
the disposable local test directory only.
