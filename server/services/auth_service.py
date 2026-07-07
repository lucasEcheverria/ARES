"""Business logic for Google authentication and JWT issuance."""

import datetime

from fastapi import HTTPException, status
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from jose import jwt

from config import settings
from dao.user_dao import UserDAO
from models.user import User


class AuthService:
    """Verifies Google identities and issues application JWTs."""

    def __init__(self, user_dao: UserDAO) -> None:
        """Initialize the service.

        Args:
            user_dao: DAO used to upsert users in `ares_config.users`.
        """
        self._user_dao = user_dao

    async def authenticate_with_google(self, id_token: str) -> str:
        """Verify a Google ID token, upsert the user, and issue a JWT.

        Args:
            id_token: The Google-issued ID token from the client-side OAuth flow.

        Returns:
            A signed JWT string.

        Raises:
            HTTPException: 401 if the Google token is invalid or expired.
        """
        try:
            payload = google_id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
                id_token, google_requests.Request(), settings.google_client_id
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired Google token",
            ) from exc

        user_id: str = payload["sub"]
        email: str = payload["email"]
        name: str = payload["name"]
        picture: str | None = payload.get("picture")

        user = await self._user_dao.get_by_id(user_id)
        if user is None:
            user = await self._get_or_create_user(user_id, email, name, picture)
        else:
            await self._user_dao.update_last_login(user_id)

        return self._issue_jwt(user_id, email)

    async def _get_or_create_user(
        self, user_id: str, email: str, name: str, picture: str | None
    ) -> User:
        """Create a user on first login.

        Args:
            user_id: Google `sub` claim.
            email: User's email address.
            name: User's display name.
            picture: URL to the user's profile picture.

        Returns:
            The newly created `User`.
        """
        return await self._user_dao.create(
            {"id": user_id, "email": email, "name": name, "picture": picture}
        )

    def _issue_jwt(self, user_id: str, email: str) -> str:
        """Sign a JWT for an authenticated user.

        Args:
            user_id: Google `sub` claim, stored as the `sub` JWT claim.
            email: User's email address, stored as the `email` JWT claim.

        Returns:
            The signed JWT string.
        """
        expire = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            minutes=settings.jwt_expire_minutes
        )
        payload = {"sub": user_id, "email": email, "exp": expire}
        token: str = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        return token
