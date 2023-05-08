from proxy import *
import logging

# TODO: spoof staff and enable other dev options buttons

# TODO: reset callbacks on hot-reload. Currently leaves duplicates

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
def fake_pomelo_http(flow: http.HTTPFlow) -> http.HTTPFlow:
    if '/api/v9/users/' in flow.request.path:
        flow.response.content = re.sub(rb'"discriminator": .+?,', b'"discriminator": "0",', flow.response.content)
    return flow

@clientbound_gateway
def fake_pomelo_gateway(event: dict) -> dict:
    if 't' not in event or event['t'] != 'PRESENCE_UPDATE':
        return event

    if 'discriminator' in event['d']['user']:
        event['d']['user']['discriminator'] = '0'

    return event

#@clientbound_gateway
def log_clientbound_gateway(event: dict) -> dict:
    logging.info('Recv: %s', event)

    return event

#@serverbound_gateway
def log_serverbound_gateway(event: dict) -> dict:
    logging.info('Sent: %s', event)

    return event