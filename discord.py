import re
from mitmproxy import http
from collections.abc import Callable

class Host:
    DISCORD = 'canary.discord.com'
    SENTRY = '...'


_js_replaces: list[tuple[bytes, bytes]] = []
_html_replaces: list[tuple[bytes, bytes]] = []
_js_regexes: list[tuple[bytes, bytes]] = []
_html_regexes: list[tuple[bytes, bytes]] = []

_js_callbacks: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []
_html_callbacks: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []
_generic_callbacks: list[Callable[[http.HTTPFlow], http.HTTPFlow]] = []

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
def register(callback: Callable[[http.HTTPFlow], http.HTTPFlow]):
    _generic_callbacks.append(callback)
    return callback

#def request(flow: http.HTTPFlow) -> None:
#    # Remove zlib compression from discord gateway
#    if flow.request.pretty_host == 'gateway.discord.gg':
#        del flow.request.query['compress']

def response(flow: http.HTTPFlow) -> None:
    for callback in _generic_callbacks:
        flow = callback(flow)
        if not flow:
            return

    if flow.request.pretty_host == Host.DISCORD and flow.response and flow.response.content:
        # Example patching /profile API
        if 'users/832258414603534380/profile' in flow.request.path:
            #flow.response.content = flow.response.content.replace(
            #    b'"profile_themes_experiment_bucket": 1',
            #    b'"profile_themes_experiment_bucket": 100'
            #)
            #print(flow.response.content)
            ...


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

        elif '.' not in flow.request.path:
            # HTML patches
            for old,new in _html_replaces:
                flow.response.content = flow.response.content.replace(old, new)
            for pattern,replace in _html_regexes:
                flow.response.content = re.sub(pattern, replace, flow.response.content)
            for callback in _html_callbacks:
                flow = callback(flow)
                if not flow:
                    return


# TODO: spoof staff and enable other dev options buttons

# Remove script hashes
html_regex(rb'nonce="[^"]+?"', b'')
html_regex(rb'integrity="[^"]+?"', b'')

# Use staging client
html_replace(b"RELEASE_CHANNEL: 'canary'", b"RELEASE_CHANNEL: 'staging'")

# Enable devtools
js_replace(b"devToolsEnabled:!1", b"devToolsEnabled:!0")
js_replace(b"displayTools:!1",    b"displayTools:!0")
js_replace(b"showDevWidget:!1",   b"showDevWidget:!0")

# Remove CSP
@register
def remove_csp(flow: http.HTTPFlow) -> http.HTTPFlow:
    if 'content-security-policy' in flow.response.headers:
        del flow.response.headers['content-security-policy']
    return flow

# Block sentry.io tracking
@register
def block_sentry(flow: http.HTTPFlow) -> http.HTTPFlow:
    if flow.request.pretty_host == Host.SENTRY:
        return None
    return flow
