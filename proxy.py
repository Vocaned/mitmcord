import re
from collections.abc import Callable
from mitmproxy import http
import asyncio

class Host:
    DISCORD = 'canary.discord.com'
    SENTRY = 'sentry.io'

_js_replaces: list[tuple[bytes, bytes]] = []
_html_replaces: list[tuple[bytes, bytes]] = []
_js_regexes: list[tuple[bytes, bytes]] = []
_html_regexes: list[tuple[bytes, bytes]] = []

_js_callbacks: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []
_html_callbacks: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []
_response_callbacks: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []
_request_callbacks: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []

def js_replace(old: bytes, new: bytes):
    _js_replaces.append((old, new))
def html_replace(old: bytes, new: bytes):
    _html_replaces.append((old, new))

def js_regex(pattern: bytes, replace: bytes):
    _js_regexes.append((pattern, replace))
def html_regex(pattern: bytes, replace: bytes):
    _html_regexes.append((pattern, replace))


def register_js(callback: Callable[[http.HTTPFlow], http.HTTPFlow]):
    _js_callbacks.append(callback)
    return callback
def register_html(callback: Callable[[http.HTTPFlow], http.HTTPFlow]):
    _html_callbacks.append(callback)
    return callback
def register_response(callback: Callable[[http.HTTPFlow], http.HTTPFlow]):
    _response_callbacks.append(callback)
    return callback
def register_request(callback: Callable[[http.HTTPFlow], http.HTTPFlow]):
    _request_callbacks.append(callback)
    return callback


async def request(flow: http.HTTPFlow) -> None:
    for callback in _request_callbacks:
        flow = callback(flow)
        if not flow:
            return

async def response(flow: http.HTTPFlow) -> None:
    for callback in _response_callbacks:
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
            for callback in _js_callbacks:
                flow = callback(flow)
                if not flow:
                    return

        elif 'html' in flow.response.headers.get('content-type', 'html'):
            # HTML patches
            for old,new in _html_replaces:
                flow.response.content = flow.response.content.replace(old, new)
            for pattern,replace in _html_regexes:
                flow.response.content = re.sub(pattern, replace, flow.response.content)
            for callback in _html_callbacks:
                flow = callback(flow)
                if not flow:
                    return
