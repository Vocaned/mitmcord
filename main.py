from proxy import *
import logging

# TODO: reset callbacks on hot-reload. Currently leaves duplicates

# Use staging client
html_replace(b"RELEASE_CHANNEL: 'canary'", b"RELEASE_CHANNEL: 'staging'")

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