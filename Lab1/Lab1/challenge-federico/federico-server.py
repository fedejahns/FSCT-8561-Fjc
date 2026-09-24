import socket
import threading

HOST = "127.0.0.1"
PORT = 12345

clients = {}
clients_lock = threading.Lock()


def broadcast(sender_socket, username, message):
    outgoing_message = username + ": " + message

    with clients_lock:
        connected_clients = list(clients.keys())

    for client_socket in connected_clients:
        if client_socket != sender_socket:
            try:
                client_socket.sendall(
                    outgoing_message.encode()
                )
            except OSError:
                pass


def handle_client(client_socket, client_address):
    username = None

    print("Connected by:", client_address)

    try:
        while True:
            data = client_socket.recv(1024)

            if not data:
                print(
                    username or client_address,
                    "disconnected unexpectedly"
                )
                break

            message = data.decode()

            print("Received:", message)

            if "|" not in message:
                client_socket.sendall(
                    "ERROR|Invalid command format".encode()
                )
                continue

            command, content = message.split("|", 1)

            if command == "HELLO":
                if content == "":
                    client_socket.sendall(
                        "ERROR|Username required".encode()
                    )
                else:
                    username = content

                    with clients_lock:
                        clients[client_socket] = username

                    print("Username:", username)

                    client_socket.sendall(
                        ("OK|Hello " + username).encode()
                    )

            elif command == "MSG":
                if username is None:
                    client_socket.sendall(
                        "ERROR|HELLO required first".encode()
                    )

                elif content == "":
                    client_socket.sendall(
                        "ERROR|Message cannot be empty".encode()
                    )

                elif len(content) > 200:
                    client_socket.sendall(
                        "ERROR|Message too long".encode()
                    )

                else:
                    print(
                        username + " says:",
                        content
                    )

                    broadcast(
                        client_socket,
                        username,
                        content
                    )

                    client_socket.sendall(
                        "OK|Message sent".encode()
                    )

            elif command == "EXIT":
                client_socket.sendall(
                    "OK|Goodbye".encode()
                )

                print(
                    username,
                    "disconnected normally"
                )

                break

            else:
                client_socket.sendall(
                    "ERROR|Unknown command".encode()
                )

    except ConnectionResetError:
        print(
            username or client_address,
            "connection reset unexpectedly"
        )

    except OSError:
        print(
            username or client_address,
            "connection closed"
        )

    finally:
        with clients_lock:
            clients.pop(client_socket, None)

        client_socket.close()

        print(
            "Connection closed:",
            client_address
        )


server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server_socket.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server_socket.bind((HOST, PORT))
server_socket.listen()

print("Multi-client server is running...")
print("Waiting for clients...")

while True:
    client_socket, client_address = (
        server_socket.accept()
    )

    client_thread = threading.Thread(
        target=handle_client,
        args=(
            client_socket,
            client_address
        )
    )

    client_thread.start()

    print(
        "Active clients:",
        threading.active_count() - 1
    )