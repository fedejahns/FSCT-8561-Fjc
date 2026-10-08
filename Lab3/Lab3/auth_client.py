import socket
from getpass import getpass


HOST = "127.0.0.1"
PORT = 12345


client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

try:
    client_socket.connect((HOST, PORT))

    print("Connected to authentication server.")

    username = input("Username: ")
    password = getpass("Password: ")

    auth_message = (
        "AUTH|" + username + "|" + password
    )

    client_socket.send(
        auth_message.encode()
    )

    response = client_socket.recv(1024).decode()

    print("Server:", response)

    if response == "OTP_REQUIRED":

        otp = input("OTP: ")

        otp_message = "OTP|" + otp

        client_socket.send(
            otp_message.encode()
        )

        final_response = (
            client_socket.recv(1024).decode()
        )

        print("Server:", final_response)

finally:
    client_socket.close()
    print("Connection closed.")