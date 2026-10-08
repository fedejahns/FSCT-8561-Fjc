import socket

HOST = "127.0.0.1"
PORT = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

for attempt in range(1, 4):
    sock.sendall(b"AUTH|alice|WrongPassword")

    response = sock.recv(1024).decode()

    print(f"Attempt {attempt}: {response}")

sock.sendall(b"AUTH|alice|Cyber123!")

response = sock.recv(1024).decode()

print("Attempt 4:", response)

sock.close()