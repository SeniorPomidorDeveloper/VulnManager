from wire import (
    LENGTH_DELIMITED,
    TAG_BITS,
    TAG_TYPE_MASK,
    VARINT_BITS,
    VARINT_MASK,
    VARINT_MORE,
)


def _read_varint(message, position):
    number = 0
    shift = 0
    while True:
        byte = message[position]
        position += 1
        number |= (byte & VARINT_MASK) << shift
        shift += VARINT_BITS
        if not byte & VARINT_MORE:
            return number, position


def decode_fields(message):
    fields = {}
    position = 0
    while position < len(message):
        tag, position = _read_varint(message, position)
        assert tag & TAG_TYPE_MASK == LENGTH_DELIMITED
        length, position = _read_varint(message, position)
        fields[tag >> TAG_BITS] = message[position:position + length]
        position += length
    return fields


def import_completed(message):
    fields = decode_fields(message)
    scope = decode_fields(fields[2])
    return {
        'import_run_id': fields[1].decode(),
        'scope': tuple(scope[number].decode() for number in (1, 2, 3)),
        'tool': fields[3].decode(),
        'scan_id': fields[4].decode(),
    }
