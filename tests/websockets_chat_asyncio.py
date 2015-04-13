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
    connection = yield from asyncio_redis.Connection.create(host='localhost', port=6379)
    f.set_result(connection)
    f.greenlet.switch()


@asyncio.coroutine
def redis_subscribe(f):
    connection = yield from asyncio_redis.Connection.create(host='localhost', port=6379)
    subscriber = yield from connection.start_subscribe()
    yield from subscriber.subscribe(['foobar'])
    f.set_result(subscriber)
    f.greenlet.switch()


def ws_recv_msg(g):
    g.has_ws_msg = True
    g.switch()


@asyncio.coroutine
def redis_wait(subscriber, f):
    reply = yield from subscriber.next_published()
    f.set_result(reply.value)
    f.greenlet.switch()


@asyncio.coroutine
def redis_publish(connection, msg):
    yield from connection.publish('foobar', msg.decode('utf-8'))


def application(env, sr):

    ws_scheme = 'ws'
    if 'HTTPS' in env or env['wsgi.url_scheme'] == 'https':
        ws_scheme = 'wss'

    if env['PATH_INFO'] == '/':
        sr('200 OK', [('Content-Type', 'text/html')])
        return ("""
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
        """ % (ws_scheme, env['HTTP_HOST'])).encode()
    elif env['PATH_INFO'] == '/favicon.ico':
        return b""
    elif env['PATH_INFO'] == '/foobar/':
        uwsgi.websocket_handshake()
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
        asyncio.get_event_loop().add_reader(uwsgi.connection_fd(), ws_recv_msg, myself)

        # add a 4 seconds timer to manage ping/pong
        asyncio.get_event_loop().call_later(4, ws_recv_msg, myself)

        # add a coroutine for redis messages
        f = GreenFuture()
        asyncio.Task(redis_wait(subscriber, f))

        # switch again
        f.greenlet.parent.switch()

        while True:
            # any redis message in the queue ?
            if f.done():
                msg = f.result()
                uwsgi.websocket_send("[%s] %s" % (time.time(), msg))
                # restart coroutine
                f = GreenFuture()
                asyncio.Task(redis_wait(subscriber, f))
            if myself.has_ws_msg:
                myself.has_ws_msg = False
                msg = uwsgi.websocket_recv_nb()
                if msg:
                    asyncio.Task(redis_publish(connection, msg))
            # switch again
            f.greenlet.parent.switch()
