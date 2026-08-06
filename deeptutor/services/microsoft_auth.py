"""Microsoft Entra ID (Azure AD) OpenID Connect helpers.

This module intentionally exchanges and validates the Entra ID token on the
server.  The browser receives only DeepTutor's own session cookie.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import logging
from typing import Any
from urllib.parse import urlencode

import httpx
from jose import JWTError, jwk, jwt
from jose.exceptions import JWKError

from deeptutor.services.config import load_auth_settings

logger = logging.getLogger(__name__)


class MicrosoftAuthError(RuntimeError):
    """A safe-to-display Microsoft sign-in failure."""

    def __init__(self, message: str, *, code: str = "microsoft_error") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MicrosoftIdentity:
    username: str
    user_id: str
    role: str


def _settings() -> dict[str, Any]:
    return load_auth_settings()


def configured() -> bool:
    settings = _settings()
    return bool(
        settings["microsoft_tenant_id"]
        and settings["microsoft_client_id"]
        and settings["microsoft_client_secret"]
        and settings["microsoft_redirect_uri"]
    )


def _authority(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0"


def _openid_configuration_url(tenant_id: str) -> str:
    """Return Entra's OIDC discovery endpoint for a tenant.

    Authorization and token requests use the ``/oauth2/v2.0`` authority,
    whereas OIDC discovery is published under ``/v2.0`` (without ``oauth2``).
    """
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"


def pkce_challenge(verifier: str) -> str:
    """Return the RFC 7636 S256 challenge for an authorization-code verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _json_response(response: httpx.Response, *, source: str) -> dict[str, Any]:
    """Decode an Entra JSON response without exposing its contents in logs."""
    try:
        payload = response.json()
    except ValueError as exc:
        logger.warning(
            "Microsoft %s response was not JSON (status=%s; content_type=%r; bytes=%s)",
            source,
            response.status_code,
            response.headers.get("content-type"),
            len(response.content),
        )
        raise MicrosoftAuthError(
            "Microsoft returned an invalid response.", code="invalid_microsoft_response"
        ) from exc
    if not isinstance(payload, dict):
        logger.warning(
            "Microsoft %s response was not a JSON object (status=%s; content_type=%r)",
            source,
            response.status_code,
            response.headers.get("content-type"),
        )
        raise MicrosoftAuthError(
            "Microsoft returned an invalid response.", code="invalid_microsoft_response"
        )
    return payload


def authorization_url(*, state: str, nonce: str, code_challenge: str) -> str:
    settings = _settings()
    if not configured():
        raise MicrosoftAuthError("Microsoft SSO has not been configured.")
    query = urlencode(
        {
            "client_id": settings["microsoft_client_id"],
            "response_type": "code",
            "redirect_uri": settings["microsoft_redirect_uri"],
            "response_mode": "query",
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{_authority(settings['microsoft_tenant_id'])}/authorize?{query}"


async def authenticate_callback(*, code: str, nonce: str, code_verifier: str) -> MicrosoftIdentity:
    """Exchange an authorization code and validate its signed ID token."""
    settings = _settings()
    if not configured():
        raise MicrosoftAuthError("Microsoft SSO has not been configured.")
    authority = _authority(settings["microsoft_tenant_id"])
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                f"{authority}/token",
                data={
                    "client_id": settings["microsoft_client_id"],
                    "client_secret": settings["microsoft_client_secret"],
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": settings["microsoft_redirect_uri"],
                    "code_verifier": code_verifier,
                },
            )
            response.raise_for_status()
            token_payload = _json_response(response, source="token")
            id_token = str(token_payload.get("id_token") or "")
            if not id_token:
                raise MicrosoftAuthError("Microsoft did not return an ID token.")
            discovery_response = await client.get(
                _openid_configuration_url(settings["microsoft_tenant_id"])
            )
            discovery_response.raise_for_status()
            discovery = _json_response(discovery_response, source="OpenID discovery")
            jwks_response = await client.get(str(discovery["jwks_uri"]))
            jwks_response.raise_for_status()
            jwks = _json_response(jwks_response, source="JWKS")
    except MicrosoftAuthError:
        raise
    except httpx.HTTPStatusError as exc:
        error_code = "token_exchange_failed"
        error_codes: list[object] = []
        trace_id = ""
        correlation_id = ""
        description = ""
        try:
            error_payload = exc.response.json()
            error_code = str(error_payload.get("error") or error_code)
            error_codes = list(error_payload.get("error_codes") or [])
            trace_id = str(error_payload.get("trace_id") or "")
            correlation_id = str(error_payload.get("correlation_id") or "")
            description = str(error_payload.get("error_description") or "")
        except ValueError:
            pass
        # Entra's error payload identifies the configuration problem (for
        # example, an expired secret) without containing the submitted secret.
        # Keep the token response itself out of logs.
        logger.warning(
            "Microsoft token exchange failed (%s; codes=%s; trace_id=%s; "
            "correlation_id=%s): %s%s",
            error_code,
            error_codes,
            trace_id,
            correlation_id,
            exc,
            f" Detail: {description}" if description else "",
        )
        raise MicrosoftAuthError(
            "Microsoft sign-in could not be completed.", code=error_code
        ) from exc
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        logger.warning("Microsoft token exchange failed: %s", exc)
        raise MicrosoftAuthError("Microsoft sign-in could not be completed.") from exc

    try:
        header = jwt.get_unverified_header(id_token)
        key_data = next(key for key in jwks["keys"] if key.get("kid") == header.get("kid"))
        claims = jwt.decode(
            id_token,
            # Entra's JWKS keys commonly omit an ``alg`` member.  Its ID
            # tokens are RS256-signed, so supply that trusted algorithm
            # explicitly rather than asking python-jose to infer it from the
            # key payload.
            jwk.construct(key_data, algorithm="RS256"),
            # Entra ID publishes RSA signing keys for ID tokens. Do not select
            # the verifier from attacker-controlled JWT header metadata.
            algorithms=["RS256"],
            audience=settings["microsoft_client_id"],
            issuer=f"https://login.microsoftonline.com/{settings['microsoft_tenant_id']}/v2.0",
            options={"verify_at_hash": False},
        )
        if not all(claims.get(key) for key in ("exp", "iat", "sub", "nonce")):
            raise MicrosoftAuthError("Microsoft returned an incomplete identity token.")
    except (JWTError, JWKError, KeyError, StopIteration, ValueError) as exc:
        logger.warning("Microsoft ID token validation failed: %s", exc)
        raise MicrosoftAuthError(
            "Microsoft returned an invalid identity token.", code="invalid_identity_token"
        ) from exc

    if claims.get("nonce") != nonce:
        raise MicrosoftAuthError("Microsoft sign-in nonce validation failed.", code="invalid_nonce")
    object_id = str(claims.get("oid") or claims.get("sub") or "")
    username = str(
        claims.get("preferred_username") or claims.get("email") or claims.get("upn") or object_id
    )
    if not object_id or not username:
        raise MicrosoftAuthError(
            "Microsoft did not provide a usable account identity.", code="invalid_identity"
        )
    admins = set(settings["microsoft_admin_object_ids"])
    role = "admin" if object_id in admins else "user"
    return MicrosoftIdentity(username=username, user_id=f"aad_{object_id}", role=role)
