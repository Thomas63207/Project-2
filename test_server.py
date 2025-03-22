import pytest
import requests
import sqlite3
import datetime
import os

BASE_URL = "http://127.0.0.1:8080"
DB_NAME = "totally_not_my_privateKeys.db"

@pytest.fixture(scope="module")
def setup_db():
    """Ensure a fresh DB for tests."""
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
    import server  # Triggers init_db()
    yield

def test_home(setup_db):
    """Test if the home route is accessible."""
    response = requests.get(f"{BASE_URL}/")
    assert response.status_code == 200
    assert response.text == "JWKS Server is running!"

def test_auth_valid_jwt(setup_db):
    """Test if /auth returns a valid JWT token."""
    response = requests.post(f"{BASE_URL}/auth")
    assert response.status_code == 200
    data = response.json()
    assert "jwt" in data
    token = data["jwt"]
    assert isinstance(token, str) and len(token) > 0

def test_auth_expired_jwt(setup_db):
    """Test if /auth?expired=true returns a JWT."""
    response = requests.post(f"{BASE_URL}/auth?expired=true")
    assert response.status_code == 200
    data = response.json()
    assert "jwt" in data

def test_auth_no_valid_keys(setup_db):
    """Test /auth fallback when no valid keys exist."""
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
        conn.commit()
    response = requests.post(f"{BASE_URL}/auth")
    assert response.status_code == 200
    assert "jwt" in response.json()

def test_jwks_contains_valid_keys(setup_db):
    """Test if JWKS endpoint contains valid keys."""
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data and isinstance(data["keys"], list)
    if data["keys"]:
        key = data["keys"][0]
        assert "kid" in key
        assert "kty" in key and key["kty"] == "RSA"
        assert "n" in key
        assert "e" in key and key["e"] == "AQAB"

def test_jwks_excludes_expired_keys(setup_db):
    """Test if JWKS only returns non-expired keys."""
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    current_time = int(datetime.datetime.utcnow().timestamp())
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        for key in data["keys"]:
            cursor.execute("SELECT exp FROM keys WHERE kid = ?", (int(key["kid"]),))
            exp = cursor.fetchone()[0]
            assert exp > current_time

def test_jwks_all_expired(setup_db):
    """Test JWKS returns empty list when all keys are expired."""
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("UPDATE keys SET exp = ? WHERE exp > ?", 
                     (int(datetime.datetime.utcnow().timestamp()) - 3600, int(datetime.datetime.utcnow().timestamp())))
        conn.commit()
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.json() == {"keys": []}

def test_database_stores_keys(setup_db):
    """Test if keys are stored in the database."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
    assert count >= 2  # Pre-loaded keys

def test_database_has_expired_key(setup_db):
    """Test if an expired key exists in the DB."""
    current_time = int(datetime.datetime.utcnow().timestamp())
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (current_time,))
        count = cursor.fetchone()[0]
    assert count > 0