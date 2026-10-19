ACK_METRIC = 'vulnmanager_normalize_messages_total{verdict="ack"}'


async def acked_messages(service_client):
    response = await service_client.get('/metrics')
    for line in response.text.splitlines():
        if line.startswith(ACK_METRIC):
            return int(float(line.split()[-1]))
    return 0


async def acked_equals(service_client, expected):
    return await acked_messages(service_client) == expected
