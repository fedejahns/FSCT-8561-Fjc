import socketio
sio = socketio.Client()


@sio.event
def connect():
    print("Connection established, socket.io Federico A01375432")


@sio.event
def disconnect():
    print("Disconnected from server")


sio.connect("http://localhost:8080")

sio.emit("message", {"data": "my_data"})

sio.wait()