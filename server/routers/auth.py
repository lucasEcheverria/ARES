"""Authentication endpoints."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from dao.user_dao import UserDAO
from database.connection import get_config_db
from services.auth_service import AuthService

router = APIRouter()


class GoogleAuthRequest(BaseModel):
    """Request body for `POST /auth/google`."""

    id_token: str


class TokenResponse(BaseModel):
    """Response body containing a signed application JWT."""

    access_token: str
    token_type: str = "bearer"


def get_auth_service(db: AsyncSession = Depends(get_config_db)) -> AuthService:
    """Build an `AuthService` wired to the `ares_config` database.

    Args:
        db: Async session bound to `ares_config`, injected by FastAPI.

    Returns:
        A ready-to-use `AuthService`.
    """
    return AuthService(UserDAO(db))


@router.post("/google", response_model=TokenResponse)
async def google_login(
    body: GoogleAuthRequest, auth_service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    """Authenticate a user via a Google ID token and issue an application JWT.

    Args:
        body: Request payload containing the Google `id_token`.
        auth_service: Injected `AuthService`.

    Returns:
        A `TokenResponse` with the signed JWT.
    """
    access_token = await auth_service.authenticate_with_google(body.id_token)
    return TokenResponse(access_token=access_token)
