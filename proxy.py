import re
from collections.abc import Callable
from mitmproxy import http
import json
import zlib

class Host:
    GATEWAY = 'gateway.discord.gg'
    DISCORD = 'canary.discord.com'
    SENTRY = 'sentry.io'

zlib_buffer = bytearray()
deflator = zlib.compressobj()
inflator = zlib.decompressobj()
Z_SYNC_FLUSH = b'\x00\x00\xff\xff'

_js_replaces: list[tuple[bytes, bytes]] = []
_html_replaces: list[tuple[bytes, bytes]] = []
_js_regexes: list[tuple[bytes, bytes]] = []
_html_regexes: list[tuple[bytes, bytes]] = []

_clientbound_js: list[Callable[[http.HTTPFlow], http.HTTPFlow | None]] = []
_clientbound_html: list[Callable[[http.HTTPFlow], http.HTTPFlow | None]] = []
_clientbound_http: list[Callable[[http.HTTPFlow], http.HTTPFlow | None]] = []
_serverbound_http: list[Callable[[http.HTTPFlow], http.HTTPFlow | None]] = []
_clientbound_gateway: list[Callable[[dict], dict | None]] = []
_serverbound_gateway: list[Callable[[dict], dict | None]] = []

# TODO: Optimize replace system, current one takes a long time to load a site
def js_replace(old: bytes, new: bytes):
    _js_replaces.append((old, new))
def html_replace(old: bytes, new: bytes):
    _html_replaces.append((old, new))

def js_regex(pattern: bytes, replace: bytes):
    _js_regexes.append((pattern, replace))
def html_regex(pattern: bytes, replace: bytes):
    _html_regexes.append((pattern, replace))


def clientbound_js(callback: Callable[[http.HTTPFlow], http.HTTPFlow | None]):
    _clientbound_js.append(callback)
    return callback
def clientbound_html(callback: Callable[[http.HTTPFlow], http.HTTPFlow | None]):
    _clientbound_html.append(callback)
    return callback
def clientbound_http(callback: Callable[[http.HTTPFlow], http.HTTPFlow | None]):
    _clientbound_http.append(callback)
    return callback
def serverbound_http(callback: Callable[[http.HTTPFlow], http.HTTPFlow | None]):
    _serverbound_http.append(callback)
    return callback
def clientbound_gateway(callback: Callable[[dict], dict | None]):
    _clientbound_gateway.append(callback)
    return callback
def serverbound_gateway(callback: Callable[[dict], dict | None]):
    _serverbound_gateway.append(callback)
    return callback

def is_api(flow: http.HTTPFlow) -> bool:
    return flow.request.pretty_host == Host.DISCORD and flow.request.path.startswith('/api/')

# Core callbacks

# Remove script hashes
html_regex(rb'nonce="[^"]+?"', b'')
html_regex(rb'integrity="[^"]+?"', b'')

# Remove CSP
@clientbound_http
def remove_csp(flow: http.HTTPFlow) -> http.HTTPFlow | None:
    if flow.response and 'content-security-policy' in flow.response.headers:
        del flow.response.headers['content-security-policy']
    return flow

# Block sentry.io tracking
@serverbound_http
def block_sentry(flow: http.HTTPFlow) -> http.HTTPFlow | None:
    if flow.request.pretty_host == Host.SENTRY:
        return None
    return flow

# Block discord tracking
@serverbound_http
def block_science(flow: http.HTTPFlow) -> http.HTTPFlow | None:
    if is_api(flow) and flow.request.path.endswith('/science'):
        return None
    return flow

# Mitmproxy hooks

def request(flow: http.HTTPFlow) -> None:
    for callback in _serverbound_http:
        flow = callback(flow) # type: ignore
        if not flow:
            return

def response(flow: http.HTTPFlow) -> None:
    for callback in _clientbound_http:
        flow = callback(flow) # type: ignore
        if not flow:
            return

    if flow.response and flow.request.pretty_host == Host.DISCORD:
        # TODO: Parse <script> tags and determine javascript files from script src instead of .js file extension
        if flow.request.path.endswith('.js'):
            # JS patches
            if flow.response.content:
                for old,new in _js_replaces:
                    flow.response.content = flow.response.content.replace(old, new)
                for pattern,replace in _js_regexes:
                    flow.response.content = re.sub(pattern, replace, flow.response.content)
            for callback in _clientbound_js:
                flow = callback(flow) # type: ignore
                if not flow:
                    return

        elif flow.response and 'html' in flow.response.headers.get('content-type', 'html'):
            # HTML patches
            if flow.response.content:
                for old,new in _html_replaces:
                    flow.response.content = flow.response.content.replace(old, new)
                for pattern,replace in _html_regexes:
                    flow.response.content = re.sub(pattern, replace, flow.response.content)
            for callback in _clientbound_html:
                flow = callback(flow) # type: ignore
                if not flow:
                    return

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
            # Wait for full data before sending anything to the client
            flow.websocket.messages[-1].drop()
            return

        # FIXME: Fails after initial websocket dies. Is buffer/socket state not cleared properly?
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

        # Compress and send modified data to client
        flow.websocket.messages[-1].content = deflator.compress(json.dumps(j).encode('utf-8')) + deflator.flush(zlib.Z_SYNC_FLUSH)
