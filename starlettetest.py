from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse
from starlette.websockets import WebSocket
from starlette.routing import Route, Mount, WebSocketRoute

import os
import asyncio
import asyncio_redis


def get_template():
    with open(os.path.join(os.path.dirname(__file__), "starlettetest.html")) as tf:
        template = tf.read()
    return template


REDIS_CHANNEL = "foobar"


async def homepage(request):
    ws_scheme = "wss"
    if request["scheme"] == "http":
        ws_scheme = "ws"
    return HTMLResponse(get_template() % (ws_scheme, request.headers["host"]))


async def chat_endpoint(websocket: WebSocket):
    """
    Relay websocket messages to redis channel and vice versa.
    """
    await websocket.accept()

    connection = await redis_connect()
    subscriber = await redis_subscribe()
    await subscriber.subscribe([REDIS_CHANNEL])

    async def left():
        while True:
            event = await websocket.receive()
            if event["type"] != "websocket.receive":  # disconnect?
                print("done receiving", event)
                break
            msg = event["text"]
            msg = event["text"]
            await connection.publish(REDIS_CHANNEL, msg)
        raise StopIteration()  # to cancel the wait

    async def right():
        while True:
            print("getting a redis message")
            msg = await subscriber.next_published()
            print("redis msg", msg)
            if msg:
                await websocket.send_text(msg.value)

    loop = asyncio.get_event_loop()

    try:
        # no default Starlette exception printing?
        tasks = loop.create_task(right()), loop.create_task(left())
        print("tasking", tasks)
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except:
        import traceback

        traceback.print_exc()
    finally:
        for task in tasks:
            print("cancel", task)
            task.cancel()


async def redis_connect():
    return await asyncio_redis.Connection.create(host="localhost", port=6379)


async def redis_subscribe():
    connection = await redis_connect()
    subscriber = await connection.start_subscribe()
    return subscriber


app = Starlette(
    debug=True,
    routes=[Route("/", homepage), WebSocketRoute("/foobar/", chat_endpoint)],
)

import sys


UNINTERESTING_FUNCS = set(("asgi_scope_http",))


def trace_calls_and_returns(frame, event, arg):
    co = frame.f_code
    func_name = co.co_name
    if func_name == "write":
        # Ignore write() calls from print statements
        return
    line_no = frame.f_lineno
    filename = co.co_filename
    if not (
        "starlette" in filename
        or filename.startswith("/Users/daniel/prog/uwsgi/plugins/cffi/")
    ):
        return
    if event == "call":
        print("Call to %s on line %s of %s" % (func_name, line_no, filename))
        return trace_calls_and_returns
    elif event == "return":
        print("%s => %s" % (func_name, arg))
    elif event == "line" and func_name not in UNINTERESTING_FUNCS:
        print("%s:%s of %s" % (func_name, line_no, filename))
    # else:
    #     print(event)
    return


# sys.settrace(trace_calls_and_returns)
