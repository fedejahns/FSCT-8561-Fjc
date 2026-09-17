from aiohttp import web
import socketio

socket_io = socketio.AsyncServer(async_mode="aiohttp")

app = web.Application()
socket_io.attach(app)


async def index(request):
    return web.Response(
        text="Federico class Lab0 socketio",
        content_type="text/html"
    )


@socket_io.on("message")
async def print_message(socket_id, data):
    print("Socket ID:", socket_id)
    print("Data:", data)


app.router.add_get("/", index)


if __name__ == "__main__":
    web.run_app(app)