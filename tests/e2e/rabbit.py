import base64
import json
from urllib import request

import settings

BINDING = '/bindings/%2F/e/{}/q/{}'
EXCHANGE_PATH = '/exchanges/%2F/{}'
QUEUE_PATH = '/queues/%2F/{}'
QUEUE_GET = '/queues/%2F/{}/get'


def call(method, path, body=None):
    token = base64.b64encode(
        f'{settings.RABBIT_USER}:{settings.RABBIT_PASSWORD}'.encode(),
    ).decode()
    upload = request.Request(
        f'{settings.RABBIT_API}{path}',
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={
            'Authorization': f'Basic {token}',
            'Content-Type': 'application/json',
        },
    )
    with request.urlopen(upload) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


def bind(exchange, queue):
    call('PUT', EXCHANGE_PATH.format(exchange), {
        'type': 'x-consistent-hash', 'durable': True,
    })
    call('PUT', QUEUE_PATH.format(queue), {'durable': True})
    call('POST', BINDING.format(exchange, queue), {'routing_key': '1'})


def delete(queue):
    call('DELETE', QUEUE_PATH.format(queue))


def first_message(queue):
    messages = call('POST', QUEUE_GET.format(queue), {
        'count': 1, 'ackmode': 'ack_requeue_false', 'encoding': 'base64',
    })
    if not messages:
        return None
    return base64.b64decode(messages[0]['payload'])
