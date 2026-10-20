import os
import re
import secrets
from html import escape
from pathlib import Path
from typing import Optional

import click
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)

from models import Note, User, db


LOGIN_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


def _load_or_create_jwt_secret(instance_path: str) -> str:
    """Load a persistent local secret without storing it in source control."""
    environment_secret = os.getenv("JWT_SECRET_KEY")
    if environment_secret:
        return environment_secret

    secret_path = Path(instance_path) / "jwt-secret.txt"
    secret_path.parent.mkdir(parents=True, exist_ok=True)

    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()

    secret = secrets.token_urlsafe(48)
    secret_path.write_text(secret, encoding="utf-8")
    return secret


def create_app(test_config: Optional[dict] = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_mapping(
        SQLALCHEMY_DATABASE_URI="sqlite:///work1.db",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        JWT_SECRET_KEY=_load_or_create_jwt_secret(app.instance_path),
    )

    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    JWTManager(app)

    with app.app_context():
        db.create_all()

    @app.get("/")
    def home():
        return jsonify(
            message="Work 1 Secure REST API",
            status="running",
        )

    @app.post("/auth/login")
    def login():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="A JSON request body is required."), 400

        login_value = payload.get("login")
        password = payload.get("password")
        if not isinstance(login_value, str) or not isinstance(password, str):
            return jsonify(error="Login and password must be strings."), 400

        login_value = login_value.strip()
        if not LOGIN_PATTERN.fullmatch(login_value) or not password:
            return jsonify(error="Invalid login or password."), 401

        user = db.session.scalar(
            db.select(User).where(User.login == login_value)
        )
        if user is None or not user.check_password(password):
            return jsonify(error="Invalid login or password."), 401

        token = create_access_token(identity=str(user.id))
        return jsonify(
            {
                "access_token": token,
                "token_type": "Bearer",
                "user": {"id": user.id, "login": user.login},
            }
        )

    @app.get("/api/data")
    @jwt_required()
    def get_protected_data():
        user_id = int(get_jwt_identity())
        user = db.session.get(User, user_id)
        if user is None:
            return jsonify(error="User no longer exists."), 401

        return jsonify(
            message="You have accessed protected data.",
            user={"id": user.id, "login": user.login},
            data=[
                {"id": 1, "value": "Work 1 protected example"},
                {"id": 2, "value": "JWT authentication is active"},
            ],
        )

    @app.post("/api/notes")
    @jwt_required()
    def create_note():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="A JSON request body is required."), 400

        content = payload.get("content")
        if not isinstance(content, str):
            return jsonify(error="Content must be a string."), 400

        content = content.strip()
        if not content:
            return jsonify(error="Content must not be empty."), 400
        if len(content) > 500:
            return jsonify(error="Content must not exceed 500 characters."), 400

        user_id = int(get_jwt_identity())
        user = db.session.get(User, user_id)
        if user is None:
            return jsonify(error="User no longer exists."), 401

        note = Note(user_id=user.id, content=escape(content, quote=True))
        db.session.add(note)
        db.session.commit()

        return jsonify(
            message="Note created.",
            note={"id": note.id, "content": note.content},
        ), 201

    @app.cli.command("create-user")
    @click.argument("login_value")
    @click.password_option(prompt="Password", confirmation_prompt=True)
    def create_user(login_value: str, password: str) -> None:
        """Create a local user without exposing the password in source code."""
        login_value = login_value.strip()
        if not LOGIN_PATTERN.fullmatch(login_value):
            raise click.ClickException(
                "Login must be 3-50 characters and use only letters, numbers, "
                "periods, underscores, or hyphens."
            )

        existing_user = db.session.scalar(
            db.select(User).where(User.login == login_value)
        )
        if existing_user is not None:
            raise click.ClickException("A user with that login already exists.")

        user = User(login=login_value)
        try:
            user.set_password(password)
        except ValueError as error:
            raise click.ClickException(str(error)) from error

        db.session.add(user)
        db.session.commit()
        click.echo(f"Created user: {login_value}")

    return app


if __name__ == "__main__":
    create_app().run()
