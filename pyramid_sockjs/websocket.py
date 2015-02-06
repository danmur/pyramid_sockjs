import re
import base64
import struct
from hashlib import md5, sha1
from socket import SHUT_RDWR
from pyramid.httpexceptions import HTTPBadRequest, HTTPMethodNotAllowed


KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SUPPORTED_VERSIONS = ('13', '8', '7')


def init_websocket(request):
    environ = request.environ

    if request.method != "GET":
        request.response.status = 405
        request.response.headers = (('Allow','GET'),)
        return request.response

    if 'websocket' not in environ.get('HTTP_UPGRADE', '').lower():
        return HTTPBadRequest('Can "Upgrade" only to "WebSocket".')

    if 'upgrade' not in environ.get('HTTP_CONNECTION', '').lower():
        return HTTPBadRequest('"Connection" must be "Upgrade".')

    version = environ.get("HTTP_SEC_WEBSOCKET_VERSION")
    if not version or version not in SUPPORTED_VERSIONS:
        return HTTPBadRequest('Unsupported WebSocket version.')

    environ['wsgi.websocket_version'] = 'hybi-%s' % version

    # check client handshake for validity
    protocol = environ.get('SERVER_PROTOCOL','')
    if not protocol.startswith("HTTP/"):
        return HTTPBadRequest('Protocol is not HTTP')

    if not (environ.get('GATEWAY_INTERFACE','').endswith('/1.1') or \
              protocol.endswith('/1.1')):
        return HTTPBadRequest('HTTP/1.1 is required')

    key = environ.get("HTTP_SEC_WEBSOCKET_KEY")
    if not key or len(base64.b64decode(key)) != 16:
        return HTTPBadRequest('HTTP_SEC_WEBSOCKET_KEY is invalid key')

    # get socket object
    socket = environ.get('gunicorn.socket', None)
    if socket is None:
        socket = environ.get('gevent.socket', None)
        if socket is None:
            return HTTPBadRequest("socket object is not available")
        environ['gunicorn.socket'] = socket

    headers = [
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Accept", base64.b64encode(sha1(key + KEY).digest()))]
    request.response.headers = headers
    request.response.status = '101 Switching Protocols'

    environ['wsgi.websocket'] = WebSocketHybi(socket, environ)


def get_key_value(key_value):
    key_number = int(re.sub("\\D", "", key_value))
    spaces = re.subn(" ", "", key_value)[1]

    if key_number % spaces != 0:
        raise Exception(
            "key_number %d is not an intergral multiple of spaces %d",
            key_number, spaces)
    else:
        return key_number / spaces
