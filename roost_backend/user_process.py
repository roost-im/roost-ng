import asyncio
import functools
import logging
import multiprocessing as mp
import os
import signal

from asgiref.sync import sync_to_async, async_to_sync
import channels.consumer
import channels.layers
import channels.utils
import django
import django.apps
from django.conf import settings
import setproctitle

from . import utils

_LOGGER = logging.getLogger(__name__)


class _ChannelLayerMixin:
    """This mixin can be used to add Django Channels Layers support to a class.  To ues it, inherit
    from it and define a property `group_names` of no arguments that returns a list of groups
    to subscribe to. Then start a task to run the `channel_layer_handler`, cancel it when you
    want to stop. This may be worth extracting to a utility module.
    """
    def __init__(self):
        self.channel_layer = None
        self.channel_name = None
        self.channel_receive = None

    @property
    def group_names(self):
        raise NotImplementedError()

    async def channel_layer_handler(self):
        try:
            # Initialize channel layer.
            self.channel_layer = channels.layers.get_channel_layer()
            self.channel_name = await self.channel_layer.new_channel()
            self.channel_receive = functools.partial(self.channel_layer.receive, self.channel_name)

            # Subscribe to groups
            for group_name in self.group_names:
                await self.channel_layer.group_add(group_name, self.channel_name)

            # Wait for and dispatch messages until we get cancelled.
            while True:
                try:
                    await channels.utils.await_many_dispatch([self.channel_receive], self.dispatch)
                except ValueError as exc:
                    _LOGGER.error('Dispatch failed: %s', exc)
        except asyncio.CancelledError:
            pass

    async def dispatch(self, message):
        # Let's use the same dispatching mechanism that django channels consumers use.
        handler_name = channels.consumer.get_handler_name(message)
        handler = getattr(self, handler_name, None)

        if handler:
            await handler(message)
        else:
            raise ValueError(f'No handler for message type "{message["type"]}"')


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


class Overseer(_ChannelLayerMixin):
    """This class is forked by the Manager class. It is responsible for
    forking off the individual user processes and restarting them if
    necessary, as well as for telling them to stop upon from request
    the Manager."""
    # TODO: make this more async
    # TODO: hook into channels layer to alert about new/deleted users.
    def __init__(self, stop_event, start=True):
        super().__init__()
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

    @property
    def group_names(self):
        return ['UP_OVERSEER']

    def start(self):
        if not settings.configured:
            django.setup()
        setproctitle.setproctitle('roost:OVERSEER')
        user_qs = django.apps.apps.get_model('roost_backend', 'User').objects.all()
        self.user_tasks = {
            principal: None
            for principal in user_qs.values_list('principal', flat=True)
        }
        _LOGGER.debug('%s starting...', self)
        async_to_sync(self.oversee)()

    async def oversee(self):
        channel_task = asyncio.create_task(self.channel_layer_handler())
        for princ, task in self.user_tasks.items():
            if task is None:
                self.user_tasks[princ] = asyncio.create_task(self.user_process_watcher(princ))

        # We could just wait for the async tasks to finish, but then
        # we would not be waiting on any tasks for users created after
        # start-up, once we handle dynamic user creation.
        await sync_to_async(self.stop_event.wait, thread_sensitive=True)()
        await asyncio.wait([task for task in self.user_tasks.values() if task is not None])
        channel_task.cancel()

    async def user_process_watcher(self, principal):
        while not self.stop_event.is_set():
            proc = mp.Process(target=UserProcess, args=(principal, self.stop_event))
            proc.start()
            await sync_to_async(proc.join, thread_sensitive=True)()

    # Start of Channel Layer message handlers
    async def add_user(self, message):
        # {'type': 'add_user', 'principal': '<principal of new user>'}
        # Spawns user process for user if not already running.
        princ = message['principal']
        if princ not in self.user_tasks:
            self.user_tasks[princ] = asyncio.create_task(self.user_process_watcher(princ))
    # End message handlers


class UserProcess(_ChannelLayerMixin):
    """
    Kerberos and zephyr are not particularly threadsafe, so each user
    will have their own process.
    """

    def __init__(self, principal, stop_event, start=True):
        super().__init__()
        self.principal = principal
        self.stop_event = stop_event
        if start:
            self.start()

    def __str__(self):
        return f'UserProcess<{self.principal}>'

    def _initialize_memory_ccache(self):
        utils.kerberos.initialize_memory_ccache(self.principal)

    def _add_credential_to_ccache(self, creds):
        utils.kerberos.add_credential_to_ccache(creds)


    @property
    def group_names(self):
        return [utils.principal_to_group_name(self.principal)]

    def start(self):
        setproctitle.setproctitle(f'roost:{self.principal}')
        self._initialize_memory_ccache()
        async_to_sync(self.run)()

    async def run(self):
        channel_task = asyncio.create_task(self.channel_layer_handler())
        zephyr_task = asyncio.create_task(self.zephyr_handler())
        await sync_to_async(self.stop_event.wait, thread_sensitive=True)()
        channel_task.cancel()
        zephyr_task.cancel()

    # Start of Channel Layer message handlers
    async def test(self, message):
        print(self.principal, 'test', message)

    async def zwrite(self, message):
        print(self.principal, 'zwrite', message['message'])
        reply_channel = message.get('_reply_to')
        if reply_channel is not None:
            await self.channel_layer.send(reply_channel, {'ack': 'stubbed'})

    async def subscribe(self, message):
        print(self.principal, 'subscribe', message)

    async def unsubscribe(self, message):
        print(self.principal, 'unsubscribe', message)

    async def inject_credentials(self, message):
        self._add_credential_to_ccache(message['creds'])
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
