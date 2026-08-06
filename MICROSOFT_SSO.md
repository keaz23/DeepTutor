# Microsoft Entra ID SSO

DeepTutor can use Microsoft Entra ID (Azure AD) instead of its built-in
username/password accounts. The browser is redirected to Microsoft, while
DeepTutor validates the returned ID token and creates its normal `dt_token`
session cookie. Microsoft access and refresh tokens are never stored by
DeepTutor. The authorization-code flow uses PKCE (S256) automatically.

## Entra app registration

1. In Microsoft Entra ID, create a **Web** app registration for DeepTutor.
2. Add this redirect URI (using your public DeepTutor frontend URL):
   `https://your-deeptutor.example/api/v1/auth/microsoft/callback`
3. Create a client secret and record the tenant ID, application (client) ID,
   and secret value.

Use a single-tenant registration for an organization-only deployment. The
configured tenant is also enforced while validating the ID token.

## Configure DeepTutor

Set the following process environment variables (prefer your deployment's
secret store for the client secret), then restart DeepTutor:

```text
AUTH_ENABLED=true
AUTH_PROVIDER=microsoft
AUTH_COOKIE_SECURE=true
MICROSOFT_TENANT_ID=<directory-tenant-id>
MICROSOFT_CLIENT_ID=<application-client-id>
MICROSOFT_CLIENT_SECRET=<client-secret-value>
MICROSOFT_REDIRECT_URI=https://your-deeptutor.example/api/v1/auth/microsoft/callback
# Optional comma-separated Entra object IDs that should be DeepTutor admins:
MICROSOFT_ADMIN_OBJECT_IDS=<object-id-1>,<object-id-2>
```

The same values can be stored in `data/user/settings/auth.json`, but keep
`microsoft_client_secret` in environment or secret-management configuration
when deploying. Every signed-in Entra user is a normal DeepTutor user unless
their Entra object ID is in `MICROSOFT_ADMIN_OBJECT_IDS`.

When Microsoft SSO is enabled, DeepTutor disables its credential login and
self-registration endpoints. `/register` redirects to the Microsoft sign-in
page so old bookmarks continue to work.
