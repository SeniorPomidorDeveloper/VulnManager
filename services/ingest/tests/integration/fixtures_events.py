import aio_pika
import pytest

import settings


@pytest.fixture(autouse=True)
async def event_queue(amqp_url, service_client):
    connection = await aio_pika.connect_robust(amqp_url)
    async with connection:
        channel = await connection.channel()
        queue = await channel.declare_queue(exclusive=True, auto_delete=True)
        await queue.bind(
            settings.EXCHANGE, routing_key=settings.EXCHANGE_BINDING_WEIGHT,
        )
        yield queue
