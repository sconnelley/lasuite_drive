"""Drive core authentication views."""

import logging
from django.conf import settings
from django.contrib import auth
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponseRedirect
from django.urls import reverse
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

from lasuite.oidc_login.views import (
    OIDCAuthenticationCallbackView as LaSuiteOIDCAuthenticationCallbackView,
    OIDCAuthenticationRequestView as LaSuiteOIDCAuthenticationRequestView,
    OIDCLogoutView as LaSuiteOIDCLogoutView,
)

from core.authentication.exceptions import EmailNotAlphaAuthorized


def get_api_prefix():
    """Extract API prefix from API_VERSION (e.g., 'drive' from 'drive/v1.0')."""
    api_version = getattr(settings, "API_VERSION", "v1.0")
    if '/' in api_version:
        return api_version.split('/')[0]
    return ""


class OIDCAuthenticationRequestView(LaSuiteOIDCAuthenticationRequestView):
    """
    Custom view for initiating OIDC authentication.
    Prepends API prefix from API_VERSION to the redirect_uri when constructing the authorization URL.
    """

    def get(self, request):
        """Override to prepend API prefix to redirect_uri."""
        api_prefix = get_api_prefix()
        
        # Call the parent method to get the redirect URL
        response = super().get(request)
        
        # If we have a prefix and the response is a redirect to the OIDC provider
        if api_prefix and isinstance(response, HttpResponseRedirect):
            # Get the redirect URL
            redirect_url = response.url
            
            # Parse the redirect URL
            parsed = urlparse(redirect_url)
            
            # Parse query parameters
            query_params = parse_qs(parsed.query)
            
            # Modify redirect_uri if present
            if "redirect_uri" in query_params:
                redirect_uri = query_params["redirect_uri"][0]
                # Prepend the API prefix to the redirect_uri
                # e.g., /api/v1.0/callback/ -> /api/drive/v1.0/callback/
                if redirect_uri.startswith("/api/"):
                    # Extract version from API_VERSION (e.g., "v1.0" from "drive/v1.0")
                    api_version = getattr(settings, "API_VERSION", "v1.0")
                    version_part = api_version.split('/')[-1] if '/' in api_version else api_version
                    # Replace /api/{version}/ with /api/{prefix}/{version}/
                    new_redirect_uri = redirect_uri.replace(
                        f"/api/{version_part}/", f"/api/{api_prefix}/{version_part}/", 1
                    )
                    query_params["redirect_uri"] = [new_redirect_uri]
            
            # Reconstruct the URL with modified query parameters
            new_query = urlencode(query_params, doseq=True)
            new_parsed = parsed._replace(query=new_query)
            new_url = urlunparse(new_parsed)
            
            # Return a new HttpResponseRedirect with the modified URL
            return HttpResponseRedirect(new_url)
        
        return response


class OIDCAuthenticationCallbackView(LaSuiteOIDCAuthenticationCallbackView):
    """
    Custom view for handling the authentication callback from the OpenID Connect (OIDC) provider.
    Handles the callback after authentication from the identity provider (OP).
    Verifies the state parameter and performs necessary authentication actions.
    """

    def get(self, request):
        try:
            return super().get(request)
        except EmailNotAlphaAuthorized:
            return HttpResponseRedirect(self.failure_url + "?auth_error=alpha")


class OIDCLogoutView(LaSuiteOIDCLogoutView):
    """
    Custom logout view that prepends API prefix from API_VERSION to logout callback URL.
    Also handles GET requests (frontend uses window.location.replace for logout).
    """

    def get(self, request):
        """Handle GET requests for logout (frontend uses window.location.replace)."""
        # Call the parent's get method if it exists, otherwise use post logic
        if hasattr(super(), 'get'):
            return super().get(request)
        # If parent doesn't have get, use post logic
        return self.post(request)

    def construct_oidc_logout_url(self, request):
        """Override to prepend API prefix to logout callback URL."""
        from django.utils import crypto
        from mozilla_django_oidc.utils import absolutify
        
        oidc_logout_endpoint = self.get_settings("OIDC_OP_LOGOUT_ENDPOINT")
        if not oidc_logout_endpoint:
            return self.redirect_url

        reverse_url = reverse("oidc_logout_callback")
        
        # Get the API prefix from API_VERSION
        api_prefix = get_api_prefix()
        
        # Prepend the prefix to the logout callback URL if configured
        if api_prefix and reverse_url.startswith("/api/"):
            # Extract version from API_VERSION
            api_version = getattr(settings, "API_VERSION", "v1.0")
            version_part = api_version.split('/')[-1] if '/' in api_version else api_version
            # Replace /api/{version}/ with /api/{prefix}/{version}/
            reverse_url = reverse_url.replace(
                f"/api/{version_part}/", f"/api/{api_prefix}/{version_part}/", 1
            )
        
        id_token = request.session.get("oidc_id_token", None)
        if not id_token:
            return self.redirect_url

        query = {
            "id_token_hint": id_token,
            "state": crypto.get_random_string(self.get_settings("OIDC_STATE_SIZE", 32)),
            "post_logout_redirect_uri": absolutify(request, reverse_url),
        }

        # Store state in session (matching mozilla-django-oidc pattern)
        if "oidc_states" not in request.session:
            request.session["oidc_states"] = {}
        request.session["oidc_states"][query["state"]] = {}
        request.session.save()

        return f"{oidc_logout_endpoint}?{urlencode(query)}"


class OIDCLogoutCallbackView(LaSuiteOIDCLogoutView):
    """
    Custom logout callback view that handles the callback after logout from Keycloak.
    Verifies the state parameter and performs necessary logout actions.
    Note: Inherits from LaSuiteOIDCLogoutView to access redirect_url property.
    """

    http_method_names = ["get"]

    def get(self, request):
        """Handle the logout callback from Keycloak."""
        # If user is not authenticated, redirect to logout URL
        if not request.user.is_authenticated:
            return HttpResponseRedirect(self.redirect_url)

        # Verify state parameter
        state = request.GET.get("state")
        if state not in request.session.get("oidc_states", {}):
            msg = "OIDC callback state not found in session `oidc_states`!"
            raise SuspiciousOperation(msg)

        # Clear state from session
        del request.session["oidc_states"][state]
        request.session.save()

        # Perform Django logout for current app (Drive)
        auth.logout(request)

        # Also clear session in Docs backend for shared logout
        # This ensures logging out of one app logs out of both
        try:
            # Get session cookies from request
            docs_session_id = request.COOKIES.get('docs_sessionid')
            if docs_session_id:
                # Make internal request to Docs backend to clear its session
                # Use Railway internal DNS: docs-backend.railway.internal
                docs_backend_url = getattr(settings, 'DOCS_BACKEND_INTERNAL_URL', 
                                          'http://docs-backend.railway.internal:8000')
                docs_logout_url = f"{docs_backend_url}/api/docs/v1.0/internal-logout/"
                
                # Create POST request with the Docs session cookie
                logout_data = b''  # Empty body for POST
                logout_req = Request(docs_logout_url, data=logout_data, method='POST')
                logout_req.add_header('Cookie', f'docs_sessionid={docs_session_id}')
                
                # Add internal secret header for authentication
                internal_secret = getattr(settings, 'INTERNAL_LOGOUT_SECRET', None)
                if internal_secret:
                    logout_req.add_header('X-Internal-Logout-Secret', internal_secret)
                
                # Add any other headers that might be needed
                logout_req.add_header('Content-Type', 'application/json')
                logout_req.add_header('X-Forwarded-Proto', 'https')
                logout_req.add_header('Host', request.get_host())
                
                # Make the request (fire and forget - don't wait for response)
                try:
                    urlopen(logout_req, timeout=2)
                except URLError as e:
                    # Log but don't fail - this is best-effort cross-app logout
                    logger.warning(f"Failed to clear Docs session during logout: {e}")
        except Exception as e:
            # Log but don't fail - this is best-effort cross-app logout
            logger.warning(f"Error clearing Docs session during logout: {e}")

        # Redirect to final logout URL
        return HttpResponseRedirect(self.redirect_url)


class InternalLogoutView(LaSuiteOIDCLogoutView):
    """
    Internal logout endpoint for cross-app session clearing.
    Accepts a session cookie and clears it. Protected by internal secret.
    """
    
    http_method_names = ["post"]
    
    def post(self, request):
        """Clear session for internal logout requests."""
        # Verify internal secret (protect against external abuse)
        internal_secret = getattr(settings, 'INTERNAL_LOGOUT_SECRET', None)
        if internal_secret:
            provided_secret = request.headers.get('X-Internal-Logout-Secret')
            if provided_secret != internal_secret:
                from django.http import HttpResponseForbidden
                return HttpResponseForbidden("Invalid internal logout secret")
        
        # Clear session if user is authenticated
        if request.user.is_authenticated:
            auth.logout(request)
        
        from django.http import JsonResponse
        return JsonResponse({"status": "ok"})
