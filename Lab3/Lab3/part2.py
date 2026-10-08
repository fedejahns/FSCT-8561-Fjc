import hashlib


def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()


def verify_password(password, stored_hash):
    entered_hash = hash_password(password)

    if entered_hash == stored_hash:
        return True
    else:
        return False


stored_hash = hash_password("Cyber123!")

print(
    verify_password(
        "Cyber123!",
        stored_hash
    )
)

print(
    verify_password(
        "WrongPassword",
        stored_hash
    )
)