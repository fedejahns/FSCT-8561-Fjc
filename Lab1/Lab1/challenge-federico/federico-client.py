import socket
import threading

HOST = "127.0.0.1"
PORT = 12345

goodbye_received = threading.Event()


def receive_messages():
    while True:
        try:
            response = client_socket.recv(1024)

            if not response:
                print("\nServer disconnected")
                break

            decoded_response = response.decode()

            print(
                "\nServer:",
                decoded_response
            )

            if decoded_response == "OK|Goodbye":
                goodbye_received.set()
                break

        except OSError:
            break


client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client_socket.connect((HOST, PORT))

print("Connected to server")

username = input(
    "Enter your username: "
)

hello_message = "HELLO|" + username

client_socket.sendall(
    hello_message.encode()
)

response = client_socket.recv(1024)

print(
    "Server:",
    response.decode()
)

receiver_thread = threading.Thread(
    target=receive_messages,
    daemon=True
)

receiver_thread.start()

while True:
    message = input(
        "Enter message or type EXIT to leave: "
    )

    if message.upper() == "EXIT":
        client_socket.sendall(
            "EXIT|".encode()
        )

        goodbye_received.wait(timeout=2)

        break

    protocol_message = (
        "MSG|" + message
    )

    try:
        client_socket.sendall(
            protocol_message.encode()
        )

    except OSError:
        print(
            "Unable to send message. "
            "Server connection was lost."
        )

        break

client_socket.close()

print("Disconnected")