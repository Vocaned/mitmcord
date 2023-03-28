from proxy import *
import zlib
import logging


# TODO: spoof staff and enable other dev options buttons

# Remove script hashes
html_regex(rb'nonce="[^"]+?"', b'')
html_regex(rb'integrity="[^"]+?"', b'')

# Use staging client
html_replace(b"RELEASE_CHANNEL: 'canary'", b"RELEASE_CHANNEL: 'staging'")

# Enable devtools
js_replace(b'devToolsEnabled:!1', b'devToolsEnabled:!0')
js_replace(b'displayTools:!1',    b'displayTools:!0')
js_replace(b'showDevWidget:!1',   b'showDevWidget:!0')

# Remove CSP
@register_response
def remove_csp(flow: http.HTTPFlow) -> http.HTTPFlow:
    if 'content-security-policy' in flow.response.headers:
        del flow.response.headers['content-security-policy']
    return flow

# Block sentry.io tracking
@register_response
def block_sentry(flow: http.HTTPFlow) -> http.HTTPFlow:
    if flow.request.pretty_host == Host.SENTRY:
        return None
    return flow


# Log websocket activity
zlib_buffer = bytearray()
inflator = zlib.decompressobj()

def websocket_message(flow: http.HTTPFlow):
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
        logging.info('Sent WS: %r', content)
    else:
        logging.info('Recv WS: %r', content)

    if not content.startswith(b'{'):
        if not content.startswith(b'\x78\x9c'):
            content = b'\x78\x9c' + content

        content = zlib.decompress(content)

        logging.info(content)
