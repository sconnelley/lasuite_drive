"""URL configuration for the core app."""

from django.conf import settings
from django.urls import include, path, re_path

from lasuite.oidc_login.urls import urlpatterns as oidc_urls
from rest_framework.routers import DefaultRouter

from core.api import viewsets
from core.external_api import viewsets as external_api_viewsets
from core.authentication.views import (
    OIDCAuthenticationRequestView,
    OIDCLogoutView,
    OIDCLogoutCallbackView,
    InternalLogoutView,
)

# - Main endpoints
router = DefaultRouter()
router.register("items", viewsets.ItemViewSet, basename="items")
router.register("users", viewsets.UserViewSet, basename="users")

# - Routes nested under a item
item_related_router = DefaultRouter()
item_related_router.register(
    "accesses",
    viewsets.ItemAccessViewSet,
    basename="item_accesses",
)
item_related_router.register(
    "invitations",
    viewsets.InvitationViewset,
    basename="invitations",
)

sdk_relay_router = DefaultRouter()
sdk_relay_router.register(
    "sdk-relay/events",
    viewsets.SDKRelayEventViewset,
    basename="sdk_relay_events",
)

# - Resource server routes
external_api_router = DefaultRouter()
external_api_router.register(
    "items",
    external_api_viewsets.ResourceServerItemViewSet,
    basename="resource_server_items",
)
external_api_router.register(
    "users",
    external_api_viewsets.ResourceServerUserViewSet,
    basename="resource_server_users",
)


# Filter OIDC URLs to replace authenticate and logout views with custom ones
filtered_oidc_urls = []
for url_pattern in oidc_urls:
    # Check if this is the authenticate or logout URL pattern
    url_str = str(url_pattern.pattern)
    url_name = getattr(url_pattern, "name", None)
    
    # Replace authenticate view
    if url_name == "oidc_authentication" or "authenticate" in url_str:
        # Replace with our custom view
        filtered_oidc_urls.append(
            path("authenticate/", OIDCAuthenticationRequestView.as_view(), name="oidc_authentication")
        )
    # Replace logout view
    elif url_name == "oidc_logout" or (hasattr(url_pattern, "name") and "logout" in str(url_name)):
        # Replace with our custom view
        filtered_oidc_urls.append(
            path("logout/", OIDCLogoutView.as_view(), name="oidc_logout")
        )
    # Skip logout callback from lasuite - we'll add our own
    elif url_name == "oidc_logout_callback" or "logout-callback" in url_str:
        # Skip the default logout callback, we'll add our own below
        continue
    else:
        # Keep other OIDC URLs as-is
        filtered_oidc_urls.append(url_pattern)

# Add logout callback URL with correct name
filtered_oidc_urls.append(
    path("logout-callback/", OIDCLogoutCallbackView.as_view(), name="oidc_logout_callback")
)

# Add internal logout endpoint for cross-app session clearing
filtered_oidc_urls.append(
    path("internal-logout/", InternalLogoutView.as_view(), name="internal_logout")
)

urlpatterns = [
    path(
        f"api/{settings.API_VERSION}/",
        include(
            [
                *router.urls,
                *filtered_oidc_urls,
                re_path(
                    r"^items/(?P<resource_id>[0-9a-z-]*)/",
                    include(item_related_router.urls),
                ),
                *sdk_relay_router.urls,
            ]
        ),
    ),
    path(f"api/{settings.API_VERSION}/config/", viewsets.ConfigView.as_view()),
]


if settings.OIDC_RESOURCE_SERVER_ENABLED:
    urlpatterns.append(
        path(
            f"external_api/{settings.API_VERSION}/",
            include(
                [
                    *external_api_router.urls,
                ]
            ),
        )
    )
