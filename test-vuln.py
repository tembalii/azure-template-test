from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from hashlib import sha256
from typing import Any
from urllib.parse import urlencode
from urllib.parse import urlparse

import sentry_sdk
import structlog
from boltons import strutils
from flask import Flask
from flask import current_app
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import request
from flask_jwt_extended import create_access_token
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.errors import OneLogin_Saml2_Error
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import Forbidden
from werkzeug.exceptions import NotFound
from werkzeug.wrappers import Request

from semgrep_app.constants import HOSTNAME
from semgrep_app.controllers.auth import admin_required
from semgrep_app.controllers.auth import login_exempt
from semgrep_app.controllers.auth import login_optional
from semgrep_app.databases import db
from semgrep_app.foundations.auth.common import SamlParams
from semgrep_app.foundations.auth.errors import SamlBadRequest
from semgrep_app.foundations.auth.models.auth_provider import AuthProvider
from semgrep_app.foundations.auth.models.auth_provider import DeploymentAuthProvider
from semgrep_app.foundations.auth.models.db_user import DbUser
from semgrep_app.foundations.auth.models.organization import Organization
from semgrep_app.foundations.auth.schemas import SsoSettings
from semgrep_app.foundations.auth.schemas import ValidationError
from semgrep_app.foundations.auth.services import sso as sso_service
from semgrep_app.foundations.auth.services.identity import IdentityService
from semgrep_app.foundations.auth.types import ClientIdentity
from semgrep_app.foundations.unsorted.models.deployment_feature import DeploymentFeature
from semgrep_app.models.sso_creation_token import SsoCreationToken
from semgrep_app.oso_rbac import UserPermissions
from semgrep_app.saas.models.deployment import Deployment
from semgrep_app.saas.services.provision_deployment import provision_deployment
from semgrep_app.saas.types import AuthProviderType
from semgrep_app.saas.types import JsonObject
from semgrep_app.singletons import sso_setup_controller
from semgrep_app.types import ApiResponse
from semgrep_app.types import DeploymentIdentity
from semgrep_app.types import DeploymentSource
from semgrep_app.util.requests import get_request_json_object
from semgrep_app.util.requests import typed_get

logger = structlog.get_logger()


def saml_prepare_flask_request(request: Request) -> Mapping[str, Any]:
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        "https": "off" if current_app.config["DEBUG"] else "on",
        "http_host": HOSTNAME,
        "server_port": 3000 if current_app.config["DEBUG"] else 443,
        "script_name": request.path,
        "get_data": request.args.copy(),
        "lowercase_urlencoding": True,
        # nosem: ssc-7042d4b4-9651-42bb-a31b-23a054554fca
        "post_data": request.form.copy(),
    }


def _is_relative_path(url_path: str) -> bool:
    # A valid, relative url path ONLY has ParseResult.path
    url_result = urlparse(url_path)
    return (
        url_result.path.startswith("/")
        and not url_result.scheme
        and not url_result.netloc
        and not url_result.query
        and not url_result.fragment
    )


def init_app(app: Flask) -> None:
    @app.route("/api/auth/sso/sso-tokens", methods=["POST"])
    @admin_required()
    def generate_sso_token(identity: ClientIdentity, user: DbUser) -> ApiResponse:
        """
        Generates a token than can be used to create a new SSO
        deployment linked to a given email domain.

        Must have an `email` key in the request body. The email domain
        will be extracted from this email.

        If "send_invite" is in the body and is set to true, the given
        email address will be emailed with an invite link.

        Optionally can have "expires_at" in the body, with the UTC timestamp in seconds
        for the intended expiration date. This date can be at most
        4 weeks in the future---if the requested date is after this, the expiration
        date will be set to the maximum allowed date.
        """
        request_body = get_request_json_object()
        email = typed_get("email", request_body, str)
        send_email = typed_get("send_invite", request_body, bool, allow_none=True)
        expires_at_str = typed_get("expires_at", request_body, str, allow_none=True)

        expires_at = None
        if expires_at_str is not None:
            expires_at = datetime.fromtimestamp(float(expires_at_str), tz=UTC)

        email_domain = email.split("@")[1]
        # check that no provider exists for this email domain
        if AuthProvider.email_domain_exists(email_domain):
            raise BadRequest("SSO already configured for this email domain")

        (secret, db_token) = SsoCreationToken.create(
            email if send_email else None, email_domain, identity, expires_at=expires_at
        )
        if send_email:
            sso_setup_controller.send_sso_invite_email(
                email, secret, email_domain, db_token.expires_at
            )

        db.session.commit()

        return jsonify(token=secret)

    @app.route("/api/auth/sso/sso-tokens/<int:token_id>", methods=["DELETE"])
    @admin_required()
    def revoke_sso_token(
        token_id: int, identity: ClientIdentity, user: DbUser
    ) -> ApiResponse:
        """
        Revoke the SSO token with the given id. This will
        prevent the token from being redeemed in the future.
        """
        SsoCreationToken.revoke_by_id(token_id)

        db.session.commit()

        return jsonify({})

    @app.route("/api/auth/sso/sso-tokens", methods=["GET"])
    @admin_required()
    def get_generated_sso_tokens(identity: ClientIdentity, user: DbUser) -> ApiResponse:
        """
        Returns the set of generated SSO tokens.

        Params:
        - `since`: returns all tokens generated since this UTC timestamp (in seconds).
            if not specified, returns all tokens generated in the last 5 weeks.
        """
        since_str = request.args.get("since", None)
        since = None
        if since_str is not None:
            since = datetime.fromtimestamp(float(since_str))
        else:
            since = datetime.utcnow() - timedelta(days=35)

        tokens, has_more = SsoCreationToken.get_tokens_since(since)

        return jsonify(tokens=[t.as_dict() for t in tokens], has_more=has_more)

    @app.route("/api/auth/sso/sso-token-domains", methods=["GET"])
    @login_exempt
    def verify_sso_token() -> ApiResponse:
        """
        Given an SSO token, verifies that it is valid and, if so,
        returns the associated email domain.

        Takes the query parameter `t` with the SSO token.

        If invalid, returns a 400 error.
        """
        token = request.args.get("t")
        if not token:
            raise BadRequest("Invalid token")

        db_token = SsoCreationToken.find_by_token_str(token)
        if db_token is None:
            raise BadRequest("Invalid token")

        return jsonify({"email_domain": db_token.email_domain})

    @app.route("/api/auth/sso/sso-deployments", methods=["POST"])
    @login_exempt
    def create_sso_deployment() -> ApiResponse:
        """
        This creates a new auth provider for a deployment that does not
        yet exist. It takes a deployment name as well as all the auth provider
        information, and creates a deployment with that auth provider
        linked to it.

        Takes the token authorizing the creation in the post body under the key
        `token`.
        """
        request_body = get_request_json_object()
        token = typed_get("token", request_body, str)

        # this comes first to avoid revealing information to
        # anyone with an invalid token
        db_token = SsoCreationToken.find_by_token_str(token)
        if db_token is None:
            # verify that the token exists
            raise NotFound

        deployment_name = typed_get("deployment_name", request_body, str)
        try:
            # We allow all base URLs here because these tokens are generated manually by r2c admins,
            # and the alternative is DB surgery to create SSO providers for nonstandard base URLs.
            #
            # The risk is primarily SSRF if a malicious base URL is entered. Since this is available
            # only to customers expressly approved by r2c, we chose to accept this risk.
            settings = SsoSettings.from_json(
                request_body, dangerously_allow_all_base_urls=True
            )
        except ValidationError as e:
            raise BadRequest(str(e))

        if db_token.email_domain != settings.email_domain:
            # and that the authorized domain matches the requested domain
            raise BadRequest("Invalid email domain")

        # check that this email domain has not been used
        if AuthProvider.email_domain_exists(settings.email_domain):
            raise BadRequest("SSO already configured for this email domain")

        auth_provider = AuthProvider.create(
            settings.provider_type,
            settings.provider_name,
            settings.display_name,
            settings.base_url,
            settings.email_domain,
            settings.extra,
        )

        # use a 9-digit hash of the deployment name + email address as the id
        source_id = (
            -1
            * int(
                sha256(
                    (deployment_name + settings.email_domain).encode("utf-8")
                ).hexdigest(),
                16,
            )
            % 10**9
        )
        org_ident = DeploymentIdentity(
            source_id, deployment_name, DeploymentSource.simple
        )
        # safe to use this here because we are not adding access to any deployments
        org = Organization._unsafe_create_without_identity(deployment_name)

        name_slug: str = strutils.slugify(deployment_name, ascii=True).decode(
            "ascii", "ignore"
        )
        new_deployment = Deployment(
            name=org_ident.name,
            name_slug=name_slug,
            source_id=org_ident.source_id,
            source_type=org_ident.source_type,
            auth_providers=[auth_provider],
            organization=org,
        )
        db.session.add(new_deployment)

        provision_deployment(None, new_deployment)

        db_token.redeem()  # don't allow the token to be used again

        db.session.commit()

        return jsonify({})

    @app.route("/api/auth/provider", methods=["POST"])
    @app.route("/api/auth/providers", methods=["POST"])
    def create_and_link_auth_provider(identity: ClientIdentity) -> ApiResponse:
        """This function is used to create or update an AuthProvider for SSO"""
        request_body = get_request_json_object()

        try:
            settings = SsoSettings.from_json(request_body)
        except ValidationError as e:
            raise BadRequest(str(e))

        if settings.deployment_id is None:
            raise BadRequest("cannot link auth provider with empty deployment_id")

        # Update data tables
        deployment = Deployment.find(
            settings.deployment_id,
            identity,
            rbac_required_permissions=[UserPermissions.panel_settings],
        )

        auth_provider = sso_service.upsert_sso(deployment, settings)
        db.session.commit()
        return jsonify(
            status="created",
            provider_name=auth_provider.provider_name,
            id=auth_provider.id,
        )

    @app.route(
        "/api/auth/deployments/<int:deployment_id>/providers/<provider_type_name>",
        methods=["DELETE"],
    )
    def delete_auth_provider(
        identity: ClientIdentity, deployment_id: int, provider_type_name: str
    ) -> ApiResponse:
        """
        This function is used to delete an AuthProvider
        (e.g. to delete github auth after successfully adding SSO)
        """
        STRING_TO_PROVIDER_TYPE_MAP = {
            "gitlab": AuthProviderType.gitlab,
            "github": AuthProviderType.github,
            "saml2": AuthProviderType.saml2,
            "openid": AuthProviderType.openid,
        }
        if provider_type_name in STRING_TO_PROVIDER_TYPE_MAP:
            provider_type = STRING_TO_PROVIDER_TYPE_MAP[provider_type_name]
        else:
            raise BadRequest(
                "Expected 'provider_type' to be in [openid, saml2, github, gitlab]"
            )
        deployment = Deployment.find(
            deployment_id,
            identity,
            rbac_required_permissions=[UserPermissions.panel_settings],
        )

        delete_count = DeploymentAuthProvider.remove_by_type(deployment, provider_type)
        db.session.commit()
        return jsonify(status="200", num_deletes=delete_count)

    @app.route(
        "/api/auth/deployments/<int:deployment_id>/providers/<provider_type_name>",
        methods=["GET"],
    )
    def get_auth_provider(
        identity: ClientIdentity, deployment_id: int, provider_type_name: str
    ) -> ApiResponse:
        deployment = Deployment.find(
            deployment_id,
            identity,
            rbac_required_permissions=[UserPermissions.panel_settings],
        )

        if provider_type_name == "openid":
            provider_type = AuthProviderType.openid
        elif provider_type_name == "saml2":
            provider_type = AuthProviderType.saml2
        else:
            raise NotFound(f"Provider type called {provider_type_name} not supported")
        auth_provider = DeploymentAuthProvider.get_by_type(deployment, provider_type)
        if auth_provider is None:
            return jsonify(hasSso=False)
        else:
            return jsonify(hasSso=True, settings=auth_provider.as_safe_dict())

    @login_exempt
    @app.route("/api/auth/saml/login/<provider_name>")
    def saml_login(provider_name: str) -> ApiResponse:
        return_path = request.args.get("return_path", "/orgs/-")
        if not _is_relative_path(return_path):
            return_path = f"{HOSTNAME}/orgs/-"
            logger.warning(
                f"Invalid return path provided. Redirecting to {return_path}"
            )
        auth_provider = AuthProvider.find_by_provider_name(provider_name)
        saml_settings = auth_provider.get_saml_settings()
        base_path = "http://localhost:3000" if current_app.config.get("DEBUG") else ""
        if saml_settings is None:
            return redirect(
                f"{base_path}/auth/saml/finish?error=BadRequest&providerName={provider_name}&desc={provider_name} does not appear to be configured correctly with saml settings. Please contact support@semgrep.com"
            )
        req = saml_prepare_flask_request(request)
        auth = OneLogin_Saml2_Auth(req, saml_settings)
        return redirect(auth.login(return_path, force_authn=True))

    @login_exempt
    @app.route("/api/auth/saml/<provider_name>", methods=["GET", "POST"])
    def saml_authenticate(provider_name: str) -> ApiResponse:
        auth_provider = AuthProvider.find_by_provider_name(provider_name)
        saml_settings = auth_provider.get_saml_settings()
        base_path = "http://localhost:3000" if current_app.config.get("DEBUG") else ""
        if saml_settings is None:
            return redirect(
                f"{base_path}/auth/saml/finish?error=BadRequest&providerName={provider_name}&desc={provider_name} does not appear to be configured correctly with saml settings. Please contact support@semgrep.com"
            )
        req = saml_prepare_flask_request(request)

        try:
            auth_provider = AuthProvider.find_by_provider_name(provider_name)
            original_identity, _ = IdentityService(auth_provider).authenticate_saml(
                req, saml_settings
            )

            relay_state = req.get("post_data", {}).get("RelayState")
            default_relay_state = "/orgs/-/"  # Default landing

            identity = IdentityService.authorize(original_identity)
            logger.info("saml_auth.authorized", identity=identity.as_dict())
            state = f"-{relay_state or default_relay_state}"

            params = urlencode(
                {
                    "state": state,
                    "token": create_access_token(identity=identity.as_dict()),
                }
            )

            return redirect(f"{base_path}/auth/saml/finish?{params}")
        except SamlBadRequest as e:
            return redirect(
                f"{base_path}/auth/saml/finish?error=BadRequest&providerName={provider_name}&desc={e.desc}"
            )

    @login_exempt
    @app.route("/api/auth/saml/<provider_name>/metadata")
    def saml_metadata(provider_name: str) -> ApiResponse:
        auth_provider = AuthProvider.find_by_provider_name(provider_name)
        saml_settings = auth_provider.get_saml_settings()
        base_path = "http://localhost:3000" if current_app.config.get("DEBUG") else ""
        if saml_settings is None:
            return redirect(
                f"{base_path}/auth/saml/finish?error=BadRequest&providerName={provider_name}&desc={provider_name} does not appear to be configured correctly with saml settings. Please contact support@semgrep.com"
            )

        req = saml_prepare_flask_request(request)
        auth = OneLogin_Saml2_Auth(req, saml_settings)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if len(errors) == 0:
            resp = make_response(metadata, 200)
            resp.headers["Content-Type"] = "text/xml"
        else:
            resp = make_response(", ".join(errors), 500)
        return resp