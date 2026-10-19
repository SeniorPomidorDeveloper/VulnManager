import hashlib
import re
from email.utils import formatdate
from http import HTTPStatus

from aiohttp import web

import settings

LOCATION_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    '</LocationConstraint>'
)
NO_SUCH_KEY_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Error><Code>NoSuchKey</Code>'
    '<Message>The specified key does not exist.</Message>'
    '<Key>{key}</Key></Error>'
)
CONTENT_RANGE = 'bytes {start}-{stop}/{size}'
RANGE_RE = re.compile(r'bytes=(\d+)-(\d*)')
XML = 'application/xml'
BINARY = 'application/octet-stream'


class S3Mock:
    def __init__(self):
        self.blobs = {}
        self.requested = []

    def put(self, key, body):
        self.blobs[key] = body

    def serve(self, request):
        if 'location' in request.query:
            return web.Response(text=LOCATION_XML, content_type=XML)
        key = request.path.removeprefix(f'/{settings.BUCKET}/')
        self.requested.append(key)
        if key not in self.blobs:
            return _not_found(key)
        return _object(request, self.blobs[key])


def _not_found(key):
    return web.Response(
        text=NO_SUCH_KEY_XML.format(key=key),
        status=HTTPStatus.NOT_FOUND,
        content_type=XML,
    )


def _byte_range(header, size):
    matched = RANGE_RE.fullmatch(header)
    if not matched:
        return None
    stop = int(matched[2]) if matched[2] else size - 1
    return int(matched[1]), stop


def _slice(body, byte_range):
    start, stop = byte_range
    headers = {
        'Content-Range': CONTENT_RANGE.format(
            start=start, stop=stop, size=len(body),
        ),
    }
    return HTTPStatus.PARTIAL_CONTENT, headers, body[start:stop + 1]


def _etag(body):
    return ''.join(('"', hashlib.md5(body).hexdigest(), '"'))


def _object(request, body):
    status, extra, payload = HTTPStatus.OK, {}, body
    byte_range = _byte_range(request.headers.get('Range', ''), len(body))
    if byte_range:
        status, extra, payload = _slice(body, byte_range)
    headers = {
        'ETag': _etag(body),
        'Last-Modified': formatdate(usegmt=True),
        'Accept-Ranges': 'bytes',
    } | extra
    return web.Response(
        body=payload, status=status, headers=headers, content_type=BINARY,
    )
