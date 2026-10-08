import hashlib


def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()


users = {
    "alice": {
        "password_hash": hash_password(
            "Cyber123!"
        )
    }
}

print(users["alice"])