from flask import Flask, jsonify, request
import jwt
import sqlite3
import datetime
import time
import traceback
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

DB_NAME = "totally_not_my_privateKeys.db"

# Initialize SQLite Database
def init_db():
    retries = 5
    for attempt in range(retries):
        try:
            with sqlite3.connect(DB_NAME, timeout=10) as conn:
                cursor = conn.cursor()
                cursor.execute("DROP TABLE IF EXISTS keys")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS keys (
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL
                    )
                """)
                private_key_expired = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                private_key_valid = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                expired_pem = private_key_expired.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                valid_pem = private_key_valid.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                now = datetime.datetime.utcnow()
                expired_time = int((now - datetime.timedelta(days=1)).timestamp())  # 24 hours ago
                valid_time = int((now + datetime.timedelta(hours=1)).timestamp())
                cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, expired_time))
                cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (valid_pem, valid_time))
                conn.commit()
                cursor.execute("SELECT kid, exp FROM keys")
                keys = cursor.fetchall()
                print("DB initialized. Keys:", [(k[0], datetime.datetime.fromtimestamp(k[1]).isoformat()) for k in keys])
                return
        except sqlite3.OperationalError as e:
            print(f"DB error on attempt {attempt + 1}/{retries}: {e}")
            if "database is locked" in str(e) and attempt < retries - 1:
                time.sleep(1)
            else:
                raise
    raise Exception("Failed to initialize DB after retries.")

init_db()  # Run at startup

@app.route("/")
def home():
    return "JWKS Server is running!"

@app.route("/.well-known/jwks.json")
def jwks():
    current_time = int(datetime.datetime.utcnow().timestamp())
    try:
        with sqlite3.connect(DB_NAME, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (current_time,))
            rows = cursor.fetchall()

        print(f"JWKS fetched {len(rows)} valid keys: {[row[0] for row in rows]}")
        valid_keys = []
        for row in rows:
            kid, key_pem, exp = row
            try:
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()
                n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
                e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
                valid_keys.append({"kid": str(kid), "kty": "RSA", "use": "sig", "n": n, "e": e})
            except Exception as e:
                print(f"Error processing key {kid}: {e}")
                continue
        print(f"JWKS returning: {valid_keys}")
        return jsonify({"keys": valid_keys})
    except Exception as e:
        print(f"JWKS endpoint failed: {e}\n{traceback.format_exc()}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/auth", methods=["POST"])
def auth():
    expired = request.args.get('expired', 'false') == 'true'
    current_time = int(datetime.datetime.utcnow().timestamp())

    with sqlite3.connect(DB_NAME, timeout=10) as conn:
        cursor = conn.cursor()
        if expired:
            cursor.execute("SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", (current_time,))
        else:
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (current_time,))
        row = cursor.fetchone()

    if not row:
        print("No key found in DB—using fallback.")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        exp_time = (datetime.datetime.utcnow() - datetime.timedelta(hours=1)) if expired else (datetime.datetime.utcnow() + datetime.timedelta(hours=1))
        with sqlite3.connect(DB_NAME, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, int(exp_time.timestamp())))
            conn.commit()
            cursor.execute("SELECT kid FROM keys WHERE key = ? AND exp = ?", (key_pem, int(exp_time.timestamp())))
            kid = cursor.fetchone()[0]
    else:
        kid, key_pem = row
        print(f"Using key {kid} from DB.")

    private_key = serialization.load_pem_private_key(key_pem, password=None)
    exp_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)) if not expired else (datetime.datetime.utcnow() - datetime.timedelta(seconds=10))
    payload = {"exp": int(exp_time.timestamp()), "iat": int(datetime.datetime.utcnow().timestamp())}
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={"kid": str(kid)})

    print(f"Returning JWT with kid={kid}: {token}")
    return jsonify({"jwt": token})

if __name__ == '__main__':
    app.run(debug=True, port=8080)