from starlette.responses import StreamingResponse
import json
import asyncio
from asyncio import Queue
from typing import Dict, Any, AsyncGenerator
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

file_changes: Dict[int, Queue] = {}

async def event_stream(file_id: int) -> AsyncGenerator[str, None]:
    if file_id not in file_changes:
        file_changes[file_id] = asyncio.Queue()
    queue = file_changes[file_id]
    logger.info(f"Starting stream for file {file_id}, queue size: {queue.qsize()}")

    try:
        while True:
            logger.info(f"Waiting for event in queue for file {file_id}, current size: {queue.qsize()}")
            change = await queue.get()
            event = f"data: {json.dumps(change)}\n\n"
            logger.info(f"Attempting to send event for file {file_id} to client: {event.strip()}")
            queue.task_done()
            yield event  # Отправляем событие построчно
    except Exception as e:
        logger.error(f"Error in event stream for file {file_id}: {e}")
        yield f"data: Error in stream: {e}\n\n"

async def notify_file_change(file_id: int, diff_data: Dict[str, Any]):
    if file_id not in file_changes:
        file_changes[file_id] = asyncio.Queue()
    try:
        if not isinstance(diff_data, dict) or 'diff' not in diff_data:
            logger.error(f"Invalid diff data for file {file_id}: {diff_data}")
            return
        await file_changes[file_id].put(diff_data)
        logger.info(f"Successfully added diff event to queue for file {file_id}, queue size: {file_changes[file_id].qsize()}")
    except Exception as e:
        logger.error(f"Error adding diff event to queue for file {file_id}: {e}")