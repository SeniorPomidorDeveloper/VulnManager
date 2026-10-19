import asyncio
import functools
import typing

import aio_pika

import waiting

BINDING_WEIGHT = '1'
CONSISTENT_HASH = 'x-consistent-hash'


class Topology(typing.NamedTuple):
    input_exchange: str
    input_queue: str
    output_exchange: str = ''

    @property
    def retry_queue(self):
        return f'{self.input_queue}.retry'

    @property
    def dead_queue(self):
        return f'{self.input_queue}.dead'


class Broker:
    def __init__(self, channel, topology, input_exchange, output):
        self._channel = channel
        self.topology = topology
        self._input = input_exchange
        self.output = output

    async def publish(self, payload, routing_key):
        message = aio_pika.Message(
            payload,
            message_id=routing_key,
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        )
        await self._input.publish(message, routing_key=routing_key)

    async def get(self, queue):
        message = await waiting.until(functools.partial(queue.get, fail=False))
        await message.ack()
        return message

    async def queue(self, name):
        return await self._channel.get_queue(name, ensure=True)


async def _consumer_count(connection, topology):
    channel = await connection.channel()
    try:
        queue = await channel.get_queue(topology.input_queue, ensure=True)
    except aio_pika.exceptions.ChannelNotFoundEntity:
        return 0
    finally:
        await channel.close()
    return queue.declaration_result.consumer_count


async def _bind_output(channel, topology):
    if not topology.output_exchange:
        return None
    exchange = await channel.declare_exchange(
        topology.output_exchange, CONSISTENT_HASH, durable=True,
    )
    output = await channel.declare_queue(exclusive=True, auto_delete=True)
    await output.bind(exchange, routing_key=BINDING_WEIGHT)
    return output


async def _purge_dead_letters(channel, topology):
    names = (topology.retry_queue, topology.dead_queue)
    queues = await asyncio.gather(*(
        channel.get_queue(name, ensure=True) for name in names
    ))
    await asyncio.gather(*(queue.purge() for queue in queues))


async def open_broker(connection, topology):
    await waiting.until(
        functools.partial(_consumer_count, connection, topology),
    )
    channel = await connection.channel()
    output = await _bind_output(channel, topology)
    await _purge_dead_letters(channel, topology)
    input_exchange = await channel.get_exchange(topology.input_exchange)
    return Broker(channel, topology, input_exchange, output)
