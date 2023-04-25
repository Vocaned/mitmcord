from proxy import *
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
@clientbound_http
def remove_csp(flow: http.HTTPFlow) -> http.HTTPFlow:
    if 'content-security-policy' in flow.response.headers:
        del flow.response.headers['content-security-policy']
    return flow

# Block sentry.io tracking
@serverbound_http
def block_sentry(flow: http.HTTPFlow) -> http.HTTPFlow:
    if flow.request.pretty_host == Host.SENTRY:
        return None
    return flow

@clientbound_http
def fake_pomelo(flow: http.HTTPFlow) -> http.HTTPFlow:
    if '/api/v9/users/' in flow.request.path:
        flow.response.content = re.sub(rb'"discriminator": .+?,', b'"discriminator": "0",', flow.response.content)

@clientbound_gateway
def log_clientbound_gateway(content: bytes) -> bytes:
    logging.info('Recv: ' + content.decode())

@serverbound_gateway
def log_serverbound_gateway(content: bytes) -> bytes:
    logging.info('Sent: ' + content.decode())