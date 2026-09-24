import socketio

sio = socketio.Client()

sio.connect("http://127.0.0.1:5000")

print("Connected to Socket.IO server for Federicos lab1")

username = input("Enter your username: ")

response = sio.call(
    "hello",
    {"username": username}
)

print(
    "Server:",
    response["status"] + "|" + response["message"]
)


while True:

    message = input(
        "Enter message or type EXIT to leave: "
    )

    if message.upper() == "EXIT":

        response = sio.call(
            "exit",
            {}
        )

        print(
            "Server:",
            response["status"] + "|" + response["message"]
        )

        break

    response = sio.call(
        "message",
        {"text": message}
    )

    print(
        "Server:",
        response["status"] + "|" + response["message"]
    )


sio.disconnect()

print("Disconnected")