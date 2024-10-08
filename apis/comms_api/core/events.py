from comms_api.models.events import StatefulEvents, StatelessEvents
from wazuh.core.engine import get_engine_client
from wazuh.core.indexer import get_indexer_client


async def create_stateful_events(events: StatefulEvents) -> dict:
    """Post new events to the indexer.
    
    Parameters
    ----------
    events : StatefulEvents
        Stateful events list.
    
    Returns
    -------
    dict
        Dictionary with the indexer response.
    """
    async with get_indexer_client() as indexer_client:
        return await indexer_client.events.create(events)


async def send_stateless_events(events: StatelessEvents) -> None:
    """Send new events to the engine.
    
    Parameters
    ----------
    events : StatelessEvents
        Stateless events list.
    """
    async with get_engine_client() as engine_client:
        await engine_client.events.send(events.events)
