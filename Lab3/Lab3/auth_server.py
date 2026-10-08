import socket
import hashlib
import pyotp


def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()


HOST = "127.0.0.1"
PORT = 12345

alice_secret = pyotp.random_base32()

users = {
    "alice": {
        "password_hash": hash_password("Cyber123!"),
        "totp_secret": alice_secret
    }
}


server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Authentication server waiting...")
print("Alice TOTP secret:", alice_secret)

client_socket, client_address = server_socket.accept()

print("Connected by:", client_address)

password_verified = False
authenticated_user = None


while True:

    data = client_socket.recv(1024)

    if not data:
        break

    message = data.decode()

    print("Received:", message)

    parts = message.split("|")


    if parts[0] == "AUTH":

        if len(parts) != 3:
            client_socket.send(
                "ERROR|Invalid AUTH format".encode()
            )
            continue

        username = parts[1]
        password = parts[2]

        if username not in users:
            client_socket.send(
                "ACCESS_DENIED".encode()
            )
            continue

        submitted_hash = hash_password(password)

        if submitted_hash == users[username]["password_hash"]:

            password_verified = True
            authenticated_user = username

            client_socket.send(
                "OTP_REQUIRED".encode()
            )

        else:
            client_socket.send(
                "ACCESS_DENIED".encode()
            )


    elif parts[0] == "OTP":

        if len(parts) != 2:
            client_socket.send(
                "ERROR|Invalid OTP format".encode()
            )
            continue

        if not password_verified:
            client_socket.send(
                "ERROR|Password required first".encode()
            )
            continue

        otp = parts[1]

        secret = users[
            authenticated_user
        ]["totp_secret"]

        totp = pyotp.TOTP(secret)

        if totp.verify(otp):
            client_socket.send(
                "ACCESS_GRANTED".encode()
            )
        else:
            client_socket.send(
                "ACCESS_DENIED".encode()
            )


    else:
        client_socket.send(
            "ERROR|Unknown command".encode()
        )


client_socket.close()
server_socket.close()

print("Server closed")