from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse
from starlette.websockets import WebSocket
from starlette.routing import Route, Mount, WebSocketRoute

import string

import os
import asyncio
import asyncio_redis
import sniffio

import inspect
import signal

# pypy 7.3.3-beta0 doesn't have warn_on_full_buffer
try:
    argspec = inspect.getfullargspec(signal.set_wakeup_fd)
    if not "warn_on_full_buffer" in argspec.kwonlyargs:
        import trio._core._wakeup_socketpair

        trio._core._wakeup_socketpair.HAVE_WARN_ON_FULL_BUFFER = False
except TypeError:  # CPython
    pass


def get_template():
    with open(os.path.join(os.path.dirname(__file__), "starlettetest.html")) as tf:
        template = tf.read()
    return string.Template(template)


REDIS_CHANNEL = "foobar"


async def homepage(request):
    ws_scheme = "wss"
    if request["scheme"] == "http":
        ws_scheme = "ws"
    return HTMLResponse(
        get_template().substitute(
            protocol=ws_scheme,
            path=request.headers["host"],
            async_library=ASYNC_LIBRARY
        )
    )


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
            await connection.publish(REDIS_CHANNEL, msg)
        raise StopIteration()  # to cancel the wait

    async def right():
        try:
            while True:
                print("getting a redis message")
                msg = await subscriber.next_published()
                print("redis msg", msg)
                if msg:
                    await websocket.send_text(msg.value)
                    if msg.value == "8k":
                        # maybe switch contexts?
                        await websocket.send_text("k" * 65536)
        except:
            import traceback

            traceback.print_exc()
            raise

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


app_to_wrap = Starlette(
    debug=True,
    routes=[Route("/", homepage), WebSocketRoute("/foobar/", chat_endpoint)],
)


async def app(scope, receive, send):
    global ASYNC_LIBRARY
    ASYNC_LIBRARY = sniffio.current_async_library()
    if sniffio.current_async_library() == "trio":
        import trio_asyncio

        async with trio_asyncio.open_loop() as loop:
            # async part of your main program here
            receive_ = trio_asyncio.trio_as_aio(receive)
            send_ = trio_asyncio.trio_as_aio(send)
            await trio_asyncio.aio_as_trio(app_to_wrap)(scope, receive_, send_)
    else:
        await app_to_wrap(scope, receive, send)


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
