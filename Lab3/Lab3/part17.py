import socket
import hashlib
import pyotp

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

HOST = "127.0.0.1"
PORT = 12345

MAX_FAILED_ATTEMPTS = 3

alice_secret = pyotp.random_base32()

users = {
    "alice": {
        "password_hash": hash_password("Cyber123!"),
        "totp_secret": alice_secret
    }
}

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Authentication server waiting...")
print("Alice TOTP secret:", alice_secret)

client_socket, client_address = server_socket.accept()
print("Connected by:", client_address)

password_verified = False
authenticated_user = None
failed_attempts = 0
blocked = False

while True:
    data = client_socket.recv(1024)

    if not data:
        break

    message = data.decode()
    parts = message.split("|")

    if parts[0] == "AUTH":
        print("Received AUTH request")
    elif parts[0] == "OTP":
        print("Received OTP request")

    if blocked:
        client_socket.sendall(
            b"AUTH_BLOCKED|Authentication blocked due to too many failed attempts."
        )
        continue

    if parts[0] == "AUTH":

        if len(parts) != 3:
            client_socket.sendall(b"ERROR|Invalid AUTH format")
            continue

        username = parts[1]
        password = parts[2]

        if username not in users:
            password_verified = False
            authenticated_user = None
            client_socket.sendall(b"ACCESS_DENIED")
            continue

        submitted_hash = hash_password(password)

        if submitted_hash == users[username]["password_hash"]:
            password_verified = True
            authenticated_user = username
            client_socket.sendall(b"OTP_REQUIRED")

        else:
            failed_attempts += 1
            password_verified = False
            authenticated_user = None

            print(
                f"Failed authentication attempt "
                f"{failed_attempts}/{MAX_FAILED_ATTEMPTS}"
            )

            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                blocked = True
                client_socket.sendall(
                    b"ACCESS_DENIED|Too many failed attempts. Authentication blocked."
                )
            else:
                client_socket.sendall(b"ACCESS_DENIED")

    elif parts[0] == "OTP":

        if len(parts) != 2:
            client_socket.sendall(b"ERROR|Invalid OTP format")
            continue

        if not password_verified:
            client_socket.sendall(b"ERROR|Password required first")
            continue

        otp = parts[1]

        secret = users[authenticated_user]["totp_secret"]
        totp = pyotp.TOTP(secret)

        if totp.verify(otp):
            failed_attempts = 0
            client_socket.sendall(b"ACCESS_GRANTED")
            print("Authentication successful.")
            print("Failed-attempt counter reset.")

        else:
            failed_attempts += 1
            password_verified = False
            authenticated_user = None

            print(
                f"Failed authentication attempt "
                f"{failed_attempts}/{MAX_FAILED_ATTEMPTS}"
            )

            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                blocked = True
                client_socket.sendall(
                    b"ACCESS_DENIED|Too many failed attempts. Authentication blocked."
                )
            else:
                client_socket.sendall(b"ACCESS_DENIED")

    else:
        client_socket.sendall(b"ERROR|Unknown command")

client_socket.close()
server_socket.close()

print("Server closed")