import bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column


db = SQLAlchemy()


class User(db.Model):
    """Application user with a bcrypt password hash."""

    id: Mapped[int] = mapped_column(primary_key=True)
    login: Mapped[str] = mapped_column(
        String(50), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)

    def set_password(self, password: str) -> None:
        password_bytes = password.encode("utf-8")
        if len(password_bytes) < 8:
            raise ValueError("Password must contain at least 8 bytes.")
        if len(password_bytes) > 72:
            raise ValueError("Password must not exceed 72 bytes for bcrypt.")

        self.password_hash = bcrypt.hashpw(
            password_bytes,
            bcrypt.gensalt(),
        ).decode("utf-8")

    def check_password(self, password: str) -> bool:
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"),
                self.password_hash.encode("utf-8"),
            )
        except ValueError:
            return False


class Note(db.Model):
    """A short user note stored after potentially unsafe HTML is escaped."""

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id"), nullable=False, index=True
    )
    content: Mapped[str] = mapped_column(String(500), nullable=False)
