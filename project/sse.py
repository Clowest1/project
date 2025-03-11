from fastapi.responses import StreamingResponse
import json
import asyncio
from asyncio import Queue
from typing import Dict

# Глобальное хранилище очередей для изменений файлов
file_changes: Dict[int, Queue] = {}

async def event_stream(file_id: int):
    if file_id not in file_changes:
        file_changes[file_id] = Queue()
    queue = file_changes[file_id]
    async def event_generator():
        try:
            while True:
                change = await queue.get()
                yield f"data: {json.dumps(change)}\n\n"
                queue.task_done()
        except asyncio.CancelledError:
            # Очистка при завершении соединения
            if queue.empty() and file_id in file_changes:
                del file_changes[file_id]
            raise
    return StreamingResponse(event_generator(), media_type="text/event-stream")

def notify_file_change(file_id: int, content: str):
    if file_id in file_changes:
        asyncio.create_task(file_changes[file_id].put({"file_id": file_id, "content": content}))