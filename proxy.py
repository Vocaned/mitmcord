import re
from collections.abc import Callable
from mitmproxy import http
import asyncio
import zlib

class Host:
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
_clientbound_gateway: list[Callable[[bytes], bytes]] = []
_serverbound_gateway: list[Callable[[bytes], bytes]] = []

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

async def request(flow: http.HTTPFlow) -> None:
    for callback in _serverbound_http:
        flow = callback(flow)
        if not flow:
            return

async def response(flow: http.HTTPFlow) -> None:
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
inflator = zlib.decompressobj()

def websocket_message(flow: http.HTTPFlow):
    """NOTE: For now gateway events are read-only"""
    global zlib_buffer
    assert flow.websocket is not None  # make type checker happy

    message = flow.websocket.messages[-1]
    content = message.content

    if not content.startswith(b'{'):
        zlib_buffer.extend(content)

        if len(content) < 4 or content[-4:] != b'\x00\x00\xff\xff':
            return

        content = inflator.decompress(zlib_buffer)
        zlib_buffer = bytearray()

    if message.from_client:
        for callback in _serverbound_gateway:
            content = callback(content)
            if not content:
                return
    else:
        for callback in _clientbound_gateway:
            content = callback(content)
            if not content:
                return


    # TODO: is this ever needed???
    #if not content.startswith(b'{'):
    #    if not content.startswith(b'\x78\x9c'):
    #        content = b'\x78\x9c' + content
    #
    #    content = zlib.decompress(content)
