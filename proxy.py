import re
from collections.abc import Callable
from mitmproxy import http
import json
import zlib

class Host:
    GATEWAY = 'gateway.discord.gg'
    DISCORD = 'canary.discord.com'
    SENTRY = 'sentry.io'

_js_replaces: list[tuple[bytes, bytes]] = []
_html_replaces: list[tuple[bytes, bytes]] = []
_js_regexes: list[tuple[bytes, bytes]] = []
_html_regexes: list[tuple[bytes, bytes]] = []

_clientbound_js: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []
_clientbound_html: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []
_clientbound_http: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []
_serverbound_http: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []
_clientbound_gateway: list[Callable[[dict], dict]] = []
_serverbound_gateway: list[Callable[[dict], dict]] = []

# TODO: Optimize replace system, current one takes a long time to load a site
def js_replace(old: bytes, new: bytes):
    _js_replaces.append((old, new))
def html_replace(old: bytes, new: bytes):
    _html_replaces.append((old, new))

def js_regex(pattern: bytes, replace: bytes):
    _js_regexes.append((pattern, replace))
def html_regex(pattern: bytes, replace: bytes):
    _html_regexes.append((pattern, replace))


def clientbound_js(callback: Callable[[http.HTTPFlow], http.HTTPFlow]):
    _clientbound_js.append(callback)
    return callback
def clientbound_html(callback: Callable[[http.HTTPFlow], http.HTTPFlow]):
    _clientbound_html.append(callback)
    return callback
def clientbound_http(callback: Callable[[http.HTTPFlow], http.HTTPFlow]):
    _clientbound_http.append(callback)
    return callback
def serverbound_http(callback: Callable[[http.HTTPFlow], http.HTTPFlow]):
    _serverbound_http.append(callback)
    return callback
def clientbound_gateway(callback: Callable[[bytes], bytes]):
    _clientbound_gateway.append(callback)
    return callback
def serverbound_gateway(callback: Callable[[bytes], bytes]):
    _serverbound_gateway.append(callback)
    return callback

def request(flow: http.HTTPFlow) -> None:
    for callback in _serverbound_http:
        flow = callback(flow)
        if not flow:
            return

def response(flow: http.HTTPFlow) -> None:
    for callback in _clientbound_http:
        flow = callback(flow)
        if not flow:
            return

    if flow.request.pretty_host == Host.DISCORD and flow.response and flow.response.content:
        # TODO: Parse <script> tags and determine javascript files from script src instead of .js file extension
        if flow.request.path.endswith('.js'):
            # JS patches
            for old,new in _js_replaces:
                flow.response.content = flow.response.content.replace(old, new)
            for pattern,replace in _js_regexes:
                flow.response.content = re.sub(pattern, replace, flow.response.content)
            for callback in _clientbound_js:
                flow = callback(flow)
                if not flow:
                    return

        elif 'html' in flow.response.headers.get('content-type', 'html'):
            # HTML patches
            for old,new in _html_replaces:
                flow.response.content = flow.response.content.replace(old, new)
            for pattern,replace in _html_regexes:
                flow.response.content = re.sub(pattern, replace, flow.response.content)
            for callback in _clientbound_html:
                flow = callback(flow)
                if not flow:
                    return

# Log websocket activity
zlib_buffer = bytearray()
deinflator = zlib.compressobj()
inflator = zlib.decompressobj()
Z_SYNC_FLUSH = b'\x00\x00\xff\xff'

def websocket_message(flow: http.HTTPFlow):
    global zlib_buffer
    assert flow.websocket is not None

    if flow.request.pretty_host != Host.GATEWAY:
        return

    message = flow.websocket.messages[-1]
    content = message.content

    if not message.from_client:
        # Server -> Client messages are compressed
        zlib_buffer.extend(content)

        if len(content) < 4 or content[-4:] != Z_SYNC_FLUSH:
            # Don't send message to client yet, wait for full data first
            flow.websocket.messages[-1].drop()
            return

        # TODO: Fails after initial websocket dies
        content = inflator.decompress(zlib_buffer)
        zlib_buffer = bytearray()

    j = json.loads(content)

    if message.from_client:
        for callback in _serverbound_gateway:
            j = callback(j)
            if not j:
                flow.websocket.messages[-1].drop()
                return

        flow.websocket.messages[-1].content = json.dumps(j).encode('utf-8')
    else:
        for callback in _clientbound_gateway:
            j = callback(j)
            if not j:
                flow.websocket.messages[-1].drop()
                return

        # Send modified data to client
        flow.websocket.messages[-1].content = deinflator.compress(json.dumps(j).encode('utf-8')) + deinflator.flush(zlib.Z_SYNC_FLUSH)
