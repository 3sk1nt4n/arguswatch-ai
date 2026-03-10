"""Tests for auth.py - JWT, RBAC, user management."""
import os
import pytest

os.environ["AUTH_DISABLED"] = "false"
os.environ["ADMIN_USER"] = "testadmin"
os.environ["ADMIN_PASSWORD"] = "testpass123"

from arguswatch.auth import (
    authenticate_user, create_user, delete_user, list_users,
    create_access_token, verify_token, pwd_context,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        hashed = pwd_context.hash("mypassword")
        assert pwd_context.verify("mypassword", hashed)
        assert not pwd_context.verify("wrongpassword", hashed)

    def test_hash_is_unique(self):
        h1 = pwd_context.hash("same")
        h2 = pwd_context.hash("same")
        assert h1 != h2  # bcrypt uses random salt


class TestTokens:
    def test_create_and_verify(self):
        token, expires = create_access_token("alice", "analyst")
        assert isinstance(token, str)
        assert expires > 0
        user = verify_token(token)
        assert user.username == "alice"
        assert user.role == "analyst"

    def test_invalid_token_raises(self):
        with pytest.raises(Exception):
            verify_token("this.is.not.a.valid.jwt")

    def test_token_contains_role(self):
        token, _ = create_access_token("bob", "admin")
        user = verify_token(token)
        assert user.role == "admin"


class TestUserManagement:
    def test_bootstrap_admin(self):
        user = authenticate_user("testadmin", "testpass123")
        assert user is not None
        assert user.role == "admin"

    def test_wrong_password(self):
        user = authenticate_user("testadmin", "wrongpassword")
        assert user is None

    def test_nonexistent_user(self):
        user = authenticate_user("nobody", "anything")
        assert user is None

    def test_create_user(self):
        ok = create_user("analyst1", "pass456", "analyst")
        assert ok is True
        user = authenticate_user("analyst1", "pass456")
        assert user is not None
        assert user.role == "analyst"

    def test_create_duplicate_fails(self):
        create_user("dupeuser", "pass", "viewer")
        ok = create_user("dupeuser", "otherpass", "admin")
        assert ok is False

    def test_list_users(self):
        users = list_users()
        assert len(users) >= 1
        assert any(u["username"] == "testadmin" for u in users)
        assert all("hashed_password" not in u for u in users)

    def test_delete_user(self):
        create_user("todelete", "pass", "viewer")
        ok = delete_user("todelete")
        assert ok is True
        assert authenticate_user("todelete", "pass") is None

    def test_cannot_delete_last_admin(self):
        # testadmin is the only admin
        ok = delete_user("testadmin")
        assert ok is False
