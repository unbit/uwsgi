#!./uwsgi --http-socket :9090  --http-raw-body --gevent 100 --module tests.websockets_chat_2
import uwsgi
import time

import gevent
from gevent.queue import Queue

class ClientManager(object):
    clients = set()

    @classmethod
    def add(cls, client):
        cls.clients.add(client)

    @classmethod
    def remove(cls, client):
        cls.clients.remove(client)

    @classmethod
    def count(cls):
        return len(cls.clients)

    @classmethod
    def broadcast(cls, data):
        data = "{0} {1}".format(time.time(), data)
        def do_broadcast():
            for c in cls.clients:
                c.send(data)

        gevent.spawn(do_broadcast)


class Client(object):
    def __init__(self):
        self.ctx = None
        self.send_queue = Queue()
        self.jobs = []


    def _recv_job(self):
        while True:
            data = uwsgi.websocket_recv(request_context=self.ctx)
            self.on_data(data)

    def _send_job(self):
        while True:
            data = self.send_queue.get()
            uwsgi.websocket_send(data, request_context=self.ctx)

    def _exit(self, *args):
        for j in self.jobs:
            j.unlink(self._exit)

        gevent.killall(self.jobs)
        ClientManager.remove(self)
        self.on_exit()


    def on_data(self, data):
        print "GOT: {0}".format(data)
        ClientManager.broadcast(data)


    def on_exit(self):
        print "bye bye..."


    def send(self, data):
        self.send_queue.put(data)


    def start(self):
        uwsgi.websocket_handshake()
        self.ctx = uwsgi.request_context()

        ClientManager.add(self)

        self.jobs.extend([
            gevent.spawn(self._recv_job),
            gevent.spawn(self._send_job),
        ])

        for j in self.jobs:
            j.link(self._exit)

        gevent.joinall(self.jobs)




def application(env, sr):

    ws_scheme = 'ws'
    if 'HTTPS' in env or env['wsgi.url_scheme'] == 'https':
        ws_scheme = 'wss'

    if env['PATH_INFO'] == '/':
        sr('200 OK', [('Content-Type', 'text/html')])
        return """
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
        """ % (ws_scheme, env['HTTP_HOST'])
    elif env['PATH_INFO'] == '/favicon.ico':
        return ""
    elif env['PATH_INFO'] == '/foobar/':
        print "websockets..."
        client = Client()
        client.start()

        return ""

