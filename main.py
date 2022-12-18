import re
from proxy import *


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

# TODO: Kills discord client performance, client cant keep up with gateway events and eventually loses connection
#@register_request
def uncompress_gateway(flow: http.HTTPFlow) -> http.HTTPFlow:
    # Remove zlib compression from discord gateway
    if flow.request.pretty_host == 'gateway.discord.gg':
        del flow.request.query['compress']
