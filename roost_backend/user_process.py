import asyncio
import base64
import functools
import logging
import multiprocessing as mp
import os
import signal

from asgiref.sync import sync_to_async
import channels.consumer
import channels.layers
import channels.utils
import django
import django.apps
from django.conf import settings
import setproctitle

_LOGGER = logging.getLogger(__name__)


class Manager:
    """This class is used by an outside caller to start and stop the set
    of user processes."""
    def __init__(self):
        self._proc = None
        self._stop_event = None

    def start(self):
        if self._proc:
            if self._proc.is_alive():
                # Alive and well; nothing to do.
                return
            # Clean up after an unexpectedly dead process.
            self.stop()
        self._stop_event = mp.Event()
        self._proc = mp.Process(target=Overseer, args=(self._stop_event,))
        self._proc.start()

    def stop(self):
        ret = False
        if self._proc and self._proc.is_alive():
            ret = True
            self._stop_event.set()
            self._proc.join()

        self._proc = None
        self._stop_event = None
        return ret


class Overseer:
    """This class is forked by the Manager class. It is responsible for
    forking off the individual user processes and restarting them if
    necessary, as well as for telling them to stop upon from request
    the Manager."""
    # TODO: make this more async
    # TODO: hook into channels layer to alert about new/deleted users.
    def __init__(self, stop_event, start=True):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        self.stop_event = stop_event
        self.pid = os.getpid()
        self.user_tasks = {}
        self.user_process_stop_events = {}
        if start:
            self.start()

    def __str__(self):
        return f'Overseer<{self.pid}>'

    def start(self):
        if not settings.configured:
            django.setup()
        setproctitle.setproctitle(f'roost:UPO/{self.pid}')
        user_qs = django.apps.apps.get_model('roost_backend', 'User').objects.all()
        self.user_tasks = {
            principal: None
            for principal in user_qs.values_list('principal', flat=True)
        }
        _LOGGER.debug('%s starting...', self)
        asyncio.run(self.oversee())

    async def oversee(self):
        for princ, task in self.user_tasks.items():
            if task is None:
                self.user_tasks[princ] = asyncio.create_task(self.user_process_watcher(princ))

        await asyncio.wait([task for task in self.user_tasks.values() if task is not None])

    async def user_process_watcher(self, principal):
        while not self.stop_event.is_set():
            proc = mp.Process(target=UserProcess, args=(principal, self.stop_event))
            proc.start()
            await sync_to_async(proc.join)()


class UserProcess:
    """
    Kerberos and zephyr are not particularly threadsafe, so each user
    will have their own process.
    """

    def __init__(self, principal, stop_event, start=True):
        self.principal = principal
        self.group_name = self.principal_to_group_name(principal)
        self.stop_event = stop_event
        self.channel_layer = None
        self.channel_name = None
        self.channel_receive = None
        if start:
            self.start()

    def __str__(self):
        return f'UserProcess<{self.principal}>'

    @staticmethod
    def principal_to_group_name(principal):
        b64_principal = base64.b64encode(principal.encode("utf-8")).decode("ascii")
        return f'PRINC_{b64_principal.strip("=")}'

    def start(self):
        setproctitle.setproctitle(f'UP/{self.principal}')
        asyncio.run(self.run())

    async def run(self):
        channel_task = asyncio.create_task(self.channel_layer_handler())
        zephyr_task = asyncio.create_task(self.zephyr_handler())
        await sync_to_async(self.stop_event.wait)()
        channel_task.cancel()
        zephyr_task.cancel()

    async def channel_layer_handler(self):
        _LOGGER.debug('faux channel layer handler started.')
        try:
            # Initialize channel layer.
            self.channel_layer = channels.layers.get_channel_layer()
            self.channel_name = await self.channel_layer.new_channel()
            self.channel_receive = functools.partial(self.channel_layer.receive, self.channel_name)

            # Subscribe to groups
            await self.channel_layer.group_add(self.group_name, self.channel_name)

            # Wait for and dispatch messages until we get cancelled.
            while True:
                try:
                    await channels.utils.await_many_dispatch([self.channel_receive], self.dispatch)
                except ValueError as exc:
                    _LOGGER.error('Dispatch failed: %s', exc)
        except asyncio.CancelledError:
            _LOGGER.debug('faux channel layer handler cancelled.')
        finally:
            _LOGGER.debug('faux channel layer handler done.')

    async def dispatch(self, message):
        # Let's use the same dispatching mechanism that django channels consumers use.
        handler_name = channels.consumer.get_handler_name(message)
        handler = getattr(self, handler_name, None)

        if handler:
            await handler(message)
        else:
            raise ValueError(f'No handler for message type "{message["type"]}"')

    # Start of Channel Layer message handlers
    async def test(self, message):
        print(message)
    # End message handlers

    async def zephyr_handler(self):
        _LOGGER.debug('faux zephyr handler started.')
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            _LOGGER.debug('faux zephyr handler cancelled.')
        finally:
            _LOGGER.debug('faux zephyr handler done.')
