from __future__ import annotations

import asyncio
import logging
from asyncio import Task
from asyncio.events import AbstractEventLoop
from typing import List, Coroutine

_LOGGER = logging.getLogger(__name__)


class Taskable:
    """Mixin class for objects that can be run as tasks."""

    def __init__(self, loop: AbstractEventLoop = None):
        if loop is not None:
            self._loop = loop
        else:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        self._tasks = []

    @property
    def tasks(self) -> List[Coroutine]:
        """Returns the outstanding tasks waiting completion."""
        return self._tasks

    def _task_done_callback(self, task):
        if task.exception():
            _LOGGER.exception("Uncaught exception", exc_info=task.exception())
        self._tasks.remove(task)

    def _create_task(self, coro) -> Task:
        """Create and track tasks that are being created for events."""
        task = self._loop.create_task(coro)
        self._tasks.append(task)
        task.add_done_callback(self._task_done_callback)
        return task

