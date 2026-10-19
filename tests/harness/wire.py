LENGTH_DELIMITED = 2
VARINT_MASK = 0x7F
VARINT_MORE = 0x80
VARINT_BITS = 7
TAG_BITS = 3
TAG_TYPE_MASK = 7


def _varint(number):
    chunks = bytearray()
    while number > VARINT_MASK:
        chunks.append(number & VARINT_MASK | VARINT_MORE)
        number >>= VARINT_BITS
    chunks.append(number)
    return bytes(chunks)


def _field(number, body):
    payload = body.encode() if isinstance(body, str) else body
    tag = number << TAG_BITS | LENGTH_DELIMITED
    return _varint(tag) + _varint(len(payload)) + payload


def encode_scope(scope):
    return b''.join(
        _field(number, part)
        for number, part in enumerate(scope, start=1)
    )


def report_received(job_id, raw_key, scope, tool, scan_id):
    return b''.join((
        _field(1, raw_key),
        _field(2, encode_scope(scope)),
        _field(3, tool),
        _field(4, scan_id),
        _field(5, job_id),
    ))


def import_completed_message(run_id, scope, tool, scan_id):
    return b''.join((
        _field(1, run_id),
        _field(2, encode_scope(scope)),
        _field(3, tool),
        _field(4, scan_id),
    ))
