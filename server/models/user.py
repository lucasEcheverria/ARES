"""ORM model for `ares_config.users`."""

import datetime

from sqlalchemy import DateTime, String, Text, func, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class ConfigBase(DeclarativeBase):
    """Declarative base for models living in the `ares_config` database."""


class User(ConfigBase):
    """A user authenticated via Google OAuth.

    Attributes:
        id: Google OAuth `sub` claim — stable unique identifier per account.
        email: User's email address, unique.
        name: User's display name.
        picture: URL to the user's profile picture.
        created_at: Timestamp of first login.
        last_login: Timestamp of the most recent login.
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    picture: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    last_login: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=func.now(),
    )
