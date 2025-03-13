from starlette.responses import StreamingResponse
import json
import asyncio
from asyncio import Queue
from typing import Dict, Any, AsyncGenerator, List
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Словарь для хранения очередей подписчиков по file_id
file_subscribers: Dict[int, List[Queue]] = {}

async def event_stream(file_id: int) -> AsyncGenerator[str, None]:
    """
    Генератор событий SSE для отправки обновлений всем подписчикам файла.
    Поддерживает подключение нескольких клиентов и очищает ресурсы при отключении.
    """
    # Создаём новую очередь для этого клиента
    queue = asyncio.Queue(maxsize=100)  # Ограничение размера очереди
    if file_id not in file_subscribers:
        file_subscribers[file_id] = []
    file_subscribers[file_id].append(queue)
    logger.info(f"Client subscribed to file {file_id}, total subscribers: {len(file_subscribers[file_id])}")

    try:
        while True:
            try:
                # Ожидаем событие или тайм-аут для отправки пинга
                change = await asyncio.wait_for(queue.get(), timeout=30.0)
                event = f"event: update\ndata: {json.dumps(change)}\n\n"
                logger.info(f"Sending event for file {file_id}: {event.strip()}")
                queue.task_done()
                yield event
            except asyncio.TimeoutError:
                # Отправляем пинг, чтобы поддерживать соединение с клиентом
                yield "event: ping\ndata: keepalive\n\n"
                logger.debug(f"Sent ping to client for file {file_id}")
    except asyncio.CancelledError:
        # Клиент отключился, удаляем его очередь
        if queue in file_subscribers[file_id]:
            file_subscribers[file_id].remove(queue)
        logger.info(f"Client unsubscribed from file {file_id}, remaining: {len(file_subscribers[file_id])}")
        if not file_subscribers[file_id]:
            del file_subscribers[file_id]  # Удаляем ключ, если подписчиков больше нет
            logger.info(f"Cleaned up subscribers for file {file_id}")
        raise
    except Exception as e:
        logger.error(f"Error in event stream for file {file_id}: {e}")
        yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"

async def notify_file_change(file_id: int, diff_data: Dict[str, Any]):
    """
    Уведомляет всех подписчиков файла об изменении, добавляя diff в их очереди.
    Обрабатывает переполнение очередей и валидирует данные.
    """
    if file_id not in file_subscribers or not file_subscribers[file_id]:
        logger.debug(f"No subscribers for file {file_id}, skipping notification")
        return

    try:
        # Валидация входных данных
        if not isinstance(diff_data, dict) or 'diff' not in diff_data:
            logger.error(f"Invalid diff data for file {file_id}: {diff_data}")
            return

        # Отправляем событие всем подписчикам
        subscriber_count = len(file_subscribers[file_id])
        dropped = 0
        for queue in file_subscribers[file_id]:
            try:
                await queue.put(diff_data)
            except asyncio.QueueFull:
                dropped += 1
                logger.warning(f"Queue full for a subscriber of file {file_id}, event dropped")

        logger.info(f"Notified {subscriber_count - dropped}/{subscriber_count} subscribers for file {file_id}")
        if dropped > 0:
            logger.warning(f"Dropped events for {dropped} subscribers due to full queues")
    except Exception as e:
        logger.error(f"Error notifying subscribers for file {file_id}: {e}")