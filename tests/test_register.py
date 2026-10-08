from fastapi.testclient import TestClient
from sqlmodel import Session, select

from src.models import User
from src.schemas import RegisterRequest
from src.service.register import register_user


def test_register_form_renders(client: TestClient):
    response = client.get("/register")

    assert response.status_code == 200
    assert '<form method="post" action="/register">' in response.text


def test_register_creates_user_and_redirects(client: TestClient, session: Session):
    response = client.post(
        "/register",
        data={"email": "new@example.com", "password": "a-long-password"},
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/verify"

    user = session.exec(select(User).where(User.email == "new@example.com")).one()
    assert user.username == "new@example.com"
    assert user.verified is False
    assert user.hashed_password != "a-long-password"


def test_register_rejects_invalid_email(client: TestClient, session: Session):
    response = client.post(
        "/register",
        data={"email": "not-an-email", "password": "a-long-password"},
    )

    assert response.status_code == 400
    assert "Enter a valid email" in response.text
    assert session.exec(select(User)).all() == []


def test_register_rejects_short_password(client: TestClient, session: Session):
    response = client.post(
        "/register",
        data={"email": "new@example.com", "password": "short"},
    )

    assert response.status_code == 400
    assert session.exec(select(User)).all() == []


def test_register_rejects_overlong_password(client: TestClient, session: Session):
    response = client.post(
        "/register",
        data={"email": "new@example.com", "password": "a" * 129},
    )

    assert response.status_code == 400
    assert session.exec(select(User)).all() == []


def test_register_existing_email_returns_same_user(session: Session):
    data = RegisterRequest(email="dup@example.com", password="a-long-password")

    first_id = register_user(data, session)
    second_id = register_user(data, session)

    assert first_id == second_id
    assert len(session.exec(select(User)).all()) == 1
