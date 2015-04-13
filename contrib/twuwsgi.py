from twisted.internet import defer, protocol, reactor
from twisted.protocols import basic
from twisted.web2 import http, resource, responsecode, stream

import struct


class uWSGIClientResource(resource.LeafResource):

    def __init__(self, app='', port=3030, host='localhost'):
        resource.LeafResource.__init__(self)
        self.host = host
        self.port = port
        self.app = app

    def renderHTTP(self, request):
        return uWSGI(request, self.app, self.host, self.port)


def uWSGI(request, app, host, port):
    if request.stream.length is None:
        return http.Response(responsecode.LENGTH_REQUIRED)

    request.uwsgi_app = app
    factory = uWSGIClientProtocolFactory(request)
    reactor.connectTCP(host, port, factory)
    return factory.deferred


class uWSGIClientProtocol(basic.LineReceiver):

    def __init__(self, request, deferred):
        self.request = request
        self.deferred = deferred
        self.stream = stream.ProducerStream()
        self.response = http.Response(stream=self.stream)
        self.status_parsed = None

    def build_uwsgi_var(self, key, value):
        return struct.pack('<H', len(key)) + key + struct.pack('<H', len(value)) + value

    def connectionMade(self):
        print(self.request.__dict__)
        # reset response parser
        self.status_parsed = None
        # build header and vars
        vars = ''

        if self.request.stream.length:
                vars += self.build_uwsgi_var('CONTENT_LENGTH', str(self.request.stream.length))

        for hkey, hval in self.request.headers.getAllRawHeaders():
                # use a list, probably it will be extended
                if hkey.lower() not in ('content-type'):
                        vars += self.build_uwsgi_var('HTTP_' + hkey.upper().replace('-', '_'), ','.join(hval))
                else:
                        vars += self.build_uwsgi_var(hkey.upper().replace('-', '_'), ','.join(hval))

        vars += self.build_uwsgi_var('REQUEST_METHOD', self.request.method)
        vars += self.build_uwsgi_var('SCRIPT_NAME', self.request.uwsgi_app)
        vars += self.build_uwsgi_var('PATH_INFO', self.request.path[len(self.request.uwsgi_app):])
        vars += self.build_uwsgi_var('QUERY_STRING', self.request.querystring)
        vars += self.build_uwsgi_var('SERVER_NAME', self.request.host)
        vars += self.build_uwsgi_var('SERVER_PORT', str(self.request.port))
        vars += self.build_uwsgi_var('SERVER_PROTOCOL', self.request.scheme.upper() + '/' + str(self.request.clientproto[0]) + '.' + str(self.request.clientproto[1]))

        vars += self.build_uwsgi_var('REQUEST_URI', self.request.uri)
        vars += self.build_uwsgi_var('REMOTE_ADDR', self.request.remoteAddr.host)

        self.transport.write(struct.pack('<BHB', 0, len(vars), 0))
        self.transport.write(vars)

        # send request data
        stream.StreamProducer(self.request.stream).beginProducing(self.transport)

    def lineReceived(self, line):
        if self.status_parsed is None:
                self.response.code = line.split(' ', 2)[1]
                self.status_parsed = True
                return

        # end of headers
        if line == '':
            self.setRawMode()
            self.deferred.callback(self.response)
            self.response = None
            return

        name, value = line.split(':', 1)
        value = value.strip()

        self.response.headers.addRawHeader(name, value)

    def rawDataReceived(self, data):
        self.stream.write(data)

    def connectionLost(self, reason):
        self.stream.finish()


class uWSGIClientProtocolFactory(protocol.ClientFactory):

    protocol = uWSGIClientProtocol
    noisy = False  # Make Factory shut up

    def __init__(self, request):
        self.request = request
        self.deferred = defer.Deferred()

    def buildProtocol(self, addr):
        return self.protocol(self.request, self.deferred)

    def clientConnectionFailed(self, connector, reason):
        self.sendFailureResponse(reason)

    def sendFailureResponse(self, reason):
        response = http.Response(code=responsecode.BAD_GATEWAY, stream=str(reason.value))
        self.deferred.callback(response)
