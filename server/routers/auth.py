"""Authentication endpoints."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from dao.user_dao import UserDAO
from database.connection import get_config_db
from services.auth_service import AuthService

router = APIRouter()


class GoogleAuthRequest(BaseModel):
    """Request body for `POST /auth/google`."""

    id_token: str = Field(description="Google-issued ID token from the client-side OAuth flow.")


class TokenResponse(BaseModel):
    """Response body containing a signed application JWT."""

    access_token: str = Field(description="Signed application JWT, used as a bearer token.")
    token_type: str = Field(default="bearer", description="Always `bearer`.")


def get_auth_service(db: AsyncSession = Depends(get_config_db)) -> AuthService:
    """Build an `AuthService` wired to the `ares_config` database.

    Args:
        db: Async session bound to `ares_config`, injected by FastAPI.

    Returns:
        A ready-to-use `AuthService`.
    """
    return AuthService(UserDAO(db))


@router.post(
    "/google",
    response_model=TokenResponse,
    summary="Log in with Google",
    responses={401: {"description": "Invalid or expired Google token"}},
)
async def google_login(
    body: GoogleAuthRequest, auth_service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    """Verify a Google ID token, upsert the user, and issue an application JWT.

    On first login for a given Google account, a `User` row is created;
    on subsequent logins, `last_login` is refreshed.
    """
    access_token = await auth_service.authenticate_with_google(body.id_token)
    return TokenResponse(access_token=access_token)
