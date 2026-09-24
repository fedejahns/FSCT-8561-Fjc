from flask import Flask, request
from flask_socketio import SocketIO

app = Flask(__name__)
sio = SocketIO(app)

users = {}


@sio.on("connect")
def handle_connect():
    print("Client connected:", request.sid)


@sio.on("hello")
def handle_hello(data):

    username = data.get("username", "")

    if username == "":
        return {
            "status": "ERROR",
            "message": "Username required"
        }

    users[request.sid] = username

    print("Username:", username)

    return {
        "status": "OK",
        "message": "Hello " + username
    }


@sio.on("message")
def handle_message(data):

    username = users.get(request.sid)

    if username is None:
        return {
            "status": "ERROR",
            "message": "HELLO required first"
        }

    text = data.get("text", "")

    if text == "":
        return {
            "status": "ERROR",
            "message": "Message cannot be empty"
        }

    if len(text) > 200:
        return {
            "status": "ERROR",
            "message": "Message too long"
        }

    print(username + " says:", text)

    return {
        "status": "OK",
        "message": "Message received from " + username
    }


@sio.on("exit")
def handle_exit():

    username = users.pop(request.sid, None)

    print(username, "requested disconnect")

    return {
        "status": "OK",
        "message": "Goodbye"
    }


@sio.on("disconnect")
def handle_disconnect():

    username = users.pop(request.sid, None)

    print("Client disconnected:", username)


if __name__ == "__main__":
    sio.run(
        app,
        host="127.0.0.1",
        port=5000,
        allow_unsafe_werkzeug=True
    )