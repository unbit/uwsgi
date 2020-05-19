#!./uwsgi --http-socket :9090 --asyncio 100 --module tests.websockets_chat_asyncio --greenlet
import uwsgi
import asyncio
import asyncio_redis
import time
import greenlet


class GreenFuture(asyncio.Future):
    def __init__(self):
        super().__init__()
        self.greenlet = greenlet.getcurrent()
        self.add_done_callback(lambda f: f.greenlet.switch())

    def result(self):
        while True:
            if self.done():
                return super().result()
            self.greenlet.parent.switch()


@asyncio.coroutine
def redis_open(f):
    print("ro a")
    connection = yield from asyncio_redis.Connection.create(host="localhost", port=6379)
    print("ro b")
    f.set_result(connection)
    print("ro c")
    f.greenlet.switch()
    print("ro d")


@asyncio.coroutine
def redis_subscribe(f):
    print("rs a")
    connection = yield from asyncio_redis.Connection.create(host="localhost", port=6379)
    print("rs b")
    subscriber = yield from connection.start_subscribe()
    print("rs c")
    yield from subscriber.subscribe(["foobar"])
    print("rs d")
    f.set_result(subscriber)
    print("rs e")
    f.greenlet.switch()
    print("rs f")


def ws_recv_msg(g):
    print("ws_recv_msg")
    g.has_ws_msg = True
    g.switch()


@asyncio.coroutine
def redis_wait(subscriber, f):
    reply = yield from subscriber.next_published()
    f.set_result(reply.value)
    f.greenlet.switch()


@asyncio.coroutine
def redis_publish(connection, msg):
    yield from connection.publish("foobar", msg)


def application(env, sr):
    ws_scheme = "ws"
    if "HTTPS" in env or env["wsgi.url_scheme"] == "https":
        ws_scheme = "wss"

    if env["PATH_INFO"] == "/":
        sr("200 OK", [("Content-Type", "text/html; charset=UTF-8")])
        output = """
    <html>
      <head>
          <script language="Javascript">
            var s = new WebSocket("%s://%s/foobar/");
            s.onopen = function() {
              alert("connected !!!");
              s.send("ciao");
            };
            s.onmessage = function(e) {
                var bb = document.getElementById('blackboard')
                var html = bb.innerHTML;
                bb.innerHTML = html + '<br/>' + e.data;
            };

            s.onerror = function(e) {
                        alert(e);
                }

        s.onclose = function(e) {
                alert("connection closed");
        }

            function invia() {
              var value = document.getElementById('testo').value;
              s.send(value);
            }
          </script>
     </head>
    <body>
        <h1>WebSocket</h1>
        <input type="text" id="testo"/>
        <input type="button" value="invia" onClick="invia();"/>
        <div id="blackboard" style="width:640px;height:480px;background-color:black;color:white;border: solid 2px red;overflow:auto">
        </div>
    </body>
    </html>
        """ % (
            ws_scheme,
            env["HTTP_HOST"],
        )

        return [output.encode("utf-8")]
    elif env["PATH_INFO"] == "/favicon.ico":
        sr("200 OK", [("Content-Type", "image/x-icon")])
        return [b""]

    elif env["PATH_INFO"] == "/foobar/":
        uwsgi.websocket_handshake(
            env["HTTP_SEC_WEBSOCKET_KEY"], env.get("HTTP_ORIGIN", "")
        )
        print("websockets...")
        # a future for waiting for redis connection
        f = GreenFuture()
        asyncio.Task(redis_subscribe(f))
        # the result() method will switch greenlets if needed
        subscriber = f.result()

        # open another redis connection for publishing messages
        f0 = GreenFuture()
        t = asyncio.Task(redis_open(f0))
        connection = f0.result()

        myself = greenlet.getcurrent()
        myself.has_ws_msg = False
        # start monitoring websocket events
        fd = uwsgi.connection_fd()
        print("add reader", fd)
        asyncio.get_event_loop().add_reader(fd, ws_recv_msg, myself)

        # add a 4 seconds timer to manage ping/pong
        asyncio.get_event_loop().call_later(4, ws_recv_msg, myself)

        # add a coroutine for redis messages
        f = GreenFuture()
        asyncio.Task(redis_wait(subscriber, f))

        # switch again
        f.greenlet.parent.switch()

        msgs = []

        def circuitbreaker(msg):
            """
            Stop if the last n messages are ''
            """
            msgs[0:0] = [msg]
            if len(msgs) > 5:
                msgs.pop()
            print(msgs)
            if all(m == b"" for m in msgs):
                raise SystemExit(1)

        while True:
            # any redis message in the queue ?
            print("chat loop")
            if f.done():
                print("f.done")
                msg = f.result()
                uwsgi.websocket_send(("[%s] %s" % (time.time(), msg)).encode("utf-8"))
                # restart coroutine
                f = GreenFuture()
                asyncio.Task(redis_wait(subscriber, f))
            if myself.has_ws_msg:
                print("has_ws_msg")
                myself.has_ws_msg = False
                msg = uwsgi.websocket_recv_nb()
                print("msg is", msg)
                circuitbreaker(msg)
                if msg:
                    asyncio.Task(redis_publish(connection, msg.decode("utf-8")))
            # switch again
            f.greenlet.parent.switch()
