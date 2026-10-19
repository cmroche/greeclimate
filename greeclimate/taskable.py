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

    def _cancel_tasks(self) -> None:
        """Cancel only this owner's work, excluding the executing task."""
        current = asyncio.current_task(loop=self._loop)
        for task in tuple(self._tasks):
            if task is not current and not task.done():
                task.cancel()

    def _task_done_callback(self, task):
        if task in self._tasks:
            self._tasks.remove(task)
        if not task.cancelled() and (exc := task.exception()) is not None:
            _LOGGER.error("Uncaught exception", exc_info=exc)

    def _create_task(self, coro) -> Task:
        """Create and track tasks that are being created for events."""
        task = self._loop.create_task(coro)
        self._tasks.append(task)
        task.add_done_callback(self._task_done_callback)
        return task

