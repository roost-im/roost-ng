import asyncio
import base64
import functools
import logging
import multiprocessing as mp
import os
import random
import select
import signal

from asgiref.sync import sync_to_async, async_to_sync
import channels.consumer
from channels.db import database_sync_to_async
import channels.layers
import channels.utils
import django
import django.apps
from django.core.exceptions import AppRegistryNotReady
from django.db import IntegrityError, transaction
from djangorestframework_camel_case.util import underscoreize
import setproctitle
import zephyr
import _zephyr

from . import utils

_LOGGER = logging.getLogger(__name__)


class _MPDjangoSetupMixin:
    """This mixin runs django.setup() on __init__. It is to be used by classes that are
    mp.Process targets."""
    # pylint: disable=too-few-public-methods

    def __init__(self):
        try:
            django.apps.apps.check_models_ready()
        except AppRegistryNotReady:
            django.setup()
        super().__init__()


class _ChannelLayerMixin:
    """This mixin can be used to add Django Channels Layers support to a class.  To ues it, inherit from
    it and define a member `groups` or property `groups` of no arguments that returns an iterable of
    groups to subscribe to. Then start a task to run the `channel_layer_handler`, cancel it when you
    want to stop. This may be worth extracting to a utility module."""

    def __init__(self):
        super().__init__()
        self.channel_layer = None
        self.channel_name = None
        self.channel_receive = None

    @property
    def groups(self):
        raise NotImplementedError()

    async def channel_layer_resubscribe(self):
        try:
            while True:
                for group_name in self.groups:
                    await self.channel_layer.group_add(group_name, self.channel_name)
                await asyncio.sleep(self.channel_layer.group_expiry / 2)
        except asyncio.CancelledError:
            for group_name in self.groups:
                await self.channel_layer.group_discard(group_name, self.channel_name)
            raise

    async def channel_layer_handler(self):
        # Initialize channel layer.'
        self.channel_layer = channels.layers.get_channel_layer()
        self.channel_name = await self.channel_layer.new_channel()
        self.channel_receive = functools.partial(self.channel_layer.receive, self.channel_name)

        # Subscribe to groups
        asyncio.create_task(self.channel_layer_resubscribe())
        await asyncio.sleep(0)

        # wait for and dispatch messages until we get cancelled.
        while not self.stop_event.is_set():
            try:
                await channels.utils.await_many_dispatch([self.channel_receive], self.dispatch)
            except ValueError as exc:
                _LOGGER.error('Dispatch failed: %s', exc)

    async def dispatch(self, message):
        # Let's use the same dispatching mechanism that django channels consumers use.
        handler_name = channels.consumer.get_handler_name(message)
        handler = getattr(self, handler_name, None)

        if handler:
            await handler(message)
        else:
            raise ValueError(f'No handler for message type "{message["type"]}"')


class _ZephyrProcessMixin(_ChannelLayerMixin):
    """This mixin contains the core zephyr support for the User Processes and Server Process."""

    def __init__(self):
        super().__init__()
        # Event to indicate that zephyr has been initialized
        self.z_initialized = mp.Event()
        # Lock to be used around non-threadsafe bits of libzephyr.
        self.zephyr_lock = None
        self.resync_event = None
        self.waiting_for_acks = {}

    @property
    def principal(self):
        raise NotImplementedError()

    @property
    def log_prefix(self):
        return self.principal

    def get_subs_qs(self):
        raise NotImplementedError()

    def _initialize_memory_ccache(self):
        utils.kerberos.initialize_memory_ccache(self.principal)

    def _add_credential_to_ccache(self, creds):
        utils.kerberos.add_credential_to_ccache(creds, self.principal)
        self.zinit()
        self.resync_event.set()

    @staticmethod
    def _have_valid_zephyr_creds():
        return utils.kerberos.have_valid_zephyr_creds(_zephyr.realm())

    def zinit(self):
        if self.z_initialized.is_set():
            return

        _LOGGER.debug('[%s] zinit...', self.log_prefix)
        zephyr.init()
        self.z_initialized.set()

    @database_sync_to_async
    def get_subs_to_resync(self):
        subs_qs = self.get_subs_qs()
        return set(subs_qs.values_list('class_key', 'instance_key', 'zrecipient'))

    async def resync_handler(self):
        _LOGGER.debug('[%s] resync task started.', self.log_prefix)
        zsub = None
        try:
            while True:
                await self.resync_event.wait()
                self.resync_event.clear()
                _LOGGER.debug('[%s] resync task triggered.', self.log_prefix)
                if not self._have_valid_zephyr_creds():
                    _LOGGER.debug('[%s] resync skipped due to lack of credentials.', self.log_prefix)
                    continue

                if zsub is None:
                    zsub = zephyr.Subscriptions()

                async with self.zephyr_lock:
                    zsub.resync()

                subs = await self.get_subs_to_resync()
                for sub in subs:
                    async with self.zephyr_lock:
                        zsub.add(sub)
        except asyncio.CancelledError:
            _LOGGER.debug('[%s] resync task cancelled.', self.log_prefix)
            raise

    async def zephyr_handler(self):
        self.zephyr_lock = asyncio.Lock()
        self.resync_event = asyncio.Event()
        asyncio.create_task(self.resync_handler())
        _LOGGER.debug('[%s] zephyr handler started.', self.log_prefix)
        try:
            await self.load_user_data()

            # No need to start looking for incoming messages until we have initialized zephyr.
            await sync_to_async(self.z_initialized.wait)()
            _LOGGER.debug('[%s] zephyr handler now receiving...', self.log_prefix)
            while True:
                _LOGGER.debug('[%s] zephyr handler loop start...', self.log_prefix)
                async with self.zephyr_lock:
                    # Since we're calling this non-blocking, not bothering to wrap and await.
                    notice = zephyr.receive()

                if notice is None:
                    _LOGGER.debug('[%s] wating on FD...', self.log_prefix)
                    # ZGetFD() returns a global variable, does not do other things with the
                    # library.  No lock required.
                    await sync_to_async(select.select)([_zephyr.getFD()], [], [])
                    _LOGGER.debug('[%s] data on FD...', self.log_prefix)
                    continue

                _LOGGER.debug('[%s] got: %s, %s', self.log_prefix, notice, notice.kind)

                if notice.kind == zephyr.ZNotice.Kind.hmack:
                    # Ignore HM Acks
                    continue
                if notice.kind in (zephyr.ZNotice.Kind.servnak,
                                   zephyr.ZNotice.Kind.servack):
                    # TODO: maybe do something different for servnak?
                    key = utils.notice_to_zuid_key(notice)
                    ack_reply_channel = self.waiting_for_acks.pop(key, None)
                    if ack_reply_channel:
                        await self.channel_layer.send(ack_reply_channel, {
                            'ack': notice.fields[0].decode('utf-8')
                        })
                    continue
                if notice.opcode.lower() == 'ping':
                    # Ignoring pings
                    continue
                # This appears to be an incoming message.
                msg = django.apps.apps.get_model('roost_backend', 'Message').from_notice(notice)
                _LOGGER.debug('%s', msg)
                await database_sync_to_async(msg.save)()
        except asyncio.CancelledError:
            _LOGGER.debug('[%s] zephyr handler cancelled.', self.log_prefix)
            raise
        finally:
            _LOGGER.debug('[%s] zephyr handler done.', self.log_prefix)

    @database_sync_to_async
    def _load_user_data(self):
        if self.principal is None:
            # Server process
            obj = django.apps.apps.get_model('roost_backend', 'ServerProcessState').load()
            return obj.data
        obj = django.apps.apps.get_model('roost_backend', 'UserProcessState').objects.filter(
            user__principal=self.principal).first()
        if obj:
            return obj.data
        return None

    async def load_user_data(self):
        data = await self._load_user_data()
        if data:
            if 'session_data' in data:
                # If we have session data, reinitialize libzephyr with it.
                session_data = base64.b64decode(data['session_data'])
                try:
                    async with self.zephyr_lock:
                        zephyr.init(session_data=session_data)
                    self.z_initialized.set()
                except OSError:
                    pass
            if 'kerberos_data' in data and data['kerberos_data']:
                # If we have credentials, inject them into our ccache.
                # This will also initialize libzephyr if there was no session data.
                # TODO: filter out expired credentials?
                # TODO: support importing a list of credentials.
                await database_sync_to_async(self._add_credential_to_ccache)(data['kerberos_data'])
        if self.principal is None:
            # The server process always has credentials; if we did not load state, initialize things now.
            await sync_to_async(self.zinit)()
            self.resync_event.set()

    @database_sync_to_async
    def _save_user_data(self, data):
        if self.principal is None:
            obj = django.apps.apps.get_model('roost_backend', 'ServerProcessState').load()
            if 'kerberos_data' in data:
                del data['kerberos_data']
            obj.data = data
            obj.save()
        else:
            ups = django.apps.apps.get_model('roost_backend', 'UserProcessState')
            try:
                with transaction.atomic():
                    ups.objects.update_or_create(user_id=self.uid, defaults={
                        'data': data,
                    })
            except IntegrityError:
                _LOGGER.debug('[%s] saving user data failed; user deleted?', self.log_prefix)
                return
        _LOGGER.debug('[%s] saving user data done.', self.log_prefix)

    async def save_user_data(self):
        # TODO: support exporting multiple credentials.
        if not self.z_initialized.is_set():
            return

        _LOGGER.debug('[%s] saving user data...', self.log_prefix)

        async with self.zephyr_lock:
            zephyr_session = _zephyr.dumpSession()
            zephyr_realm = _zephyr.realm()
        data = {
            'session_data': base64.b64encode(zephyr_session).decode('ascii'),
            'kerberos_data': underscoreize(utils.kerberos.get_zephyr_creds_dict(zephyr_realm)),
        }

        for _ in range(4):
            try:
                await self._save_user_data(data)
                break
            except django.db.utils.OperationalError:
                _LOGGER.warning('[%s] saving user data failed, trying again...', self.log_prefix)
                await asyncio.sleep(random.random())  # jitter
        else:
            _LOGGER.error('[%s] saving user data failed, giving up.', self.log_prefix)

    # Start of Channel Layer message handlers
    async def zwrite(self, message):
        await sync_to_async(self.zinit)()
        msg_args = message['message']
        reply_channel = message.pop('_reply_to', None)

        notice_args = {
            k: v.encode()
            for k, v in msg_args.items()
        }

        if notice_args['recipient'].startswith(b'*'):
            notice_args['recipient'] = notice_args['recipient'][1:]
        notice_args['cls'] = notice_args.pop('class')

        notice = zephyr.ZNotice(**notice_args)

        async with self.zephyr_lock:
            await sync_to_async(notice.send)()
            if reply_channel is not None:
                # Doing this under the lock ensures that we put the reply_channel in the dict before
                # we can process any ACK.
                self.waiting_for_acks[utils.notice_to_zuid_key(notice)] = reply_channel

        msg = django.apps.apps.get_model('roost_backend', 'Message').from_notice(notice, is_outgoing=True)
        _LOGGER.debug('%s', msg)
        if msg.is_personal:
            # Only save outbound personals.
            # TODO: re-evaluate this decision.
            await database_sync_to_async(msg.save)()

    async def resync_subscriptions(self, _message):
        self.resync_event.set()
    # End message handlers


class Manager:
    """This class is used by an outside caller to start and stop the set
    of user processes."""
    def __init__(self, enabled=True):
        self._proc = None
        self._stop_event = None
        self._enabled = enabled

    def __enter__(self):
        if self._enabled:
            self.start()

    def __exit__(self, exc_type, exc_value, traceback):
        if self._enabled:
            self.stop()

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
        if self._proc:
            if self._proc.is_alive():
                ret = True
                self._stop_event.set()
            self._proc.join()

        self._proc = None
        self._stop_event = None
        return ret


class Overseer(_MPDjangoSetupMixin, _ChannelLayerMixin):
    """This class is forked by the Manager class. It is responsible for
    forking off the individual user processes and restarting them if
    necessary, as well as for telling them to stop upon from request
    the Manager."""
    # TODO: make this more async
    # TODO: hook into channels layer to alert about new/deleted users.
    groups = ['OVERSEER']

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

    def start(self):
        setproctitle.setproctitle('roost:OVERSEER')
        async_to_sync(self.oversee)()

    @database_sync_to_async
    def get_users(self):
        # pylint: disable=no-self-use
        return list(django.apps.apps.get_model('roost_backend', 'User').objects.all().values_list('id', 'principal'))

    async def oversee(self):
        _LOGGER.debug('[OVERSEER] starting...')
        channel_task = asyncio.create_task(self.channel_layer_handler())
        asyncio.create_task(self.server_process_watcher())
        user_list = await self.get_users()
        for (uid, principal) in user_list:
            self.user_tasks[principal] = asyncio.create_task(self.user_process_watcher(principal, uid))

        # We could just wait for the async tasks to finish, but then
        # we would not be waiting on any tasks for users created after
        # start-up, once we handle dynamic user creation.
        _LOGGER.debug('[OVERSEER] waiting for stop event...')
        await sync_to_async(self.stop_event.wait, thread_sensitive=True)()
        _LOGGER.debug('[OVERSEER] received stop event...')
        tasks = [task for task in self.user_tasks.values() if task is not None]
        if tasks:
            await asyncio.wait(tasks)
        channel_task.cancel()
        try:
            await channel_task
        except asyncio.CancelledError:
            pass
        _LOGGER.debug('[OVERSEER] done.')

    async def server_process_watcher(self):
        while not self.stop_event.is_set():
            proc = mp.Process(target=ServerSubscriber, args=(self.stop_event,))
            proc.start()
            await sync_to_async(proc.join, thread_sensitive=True)()

    async def user_process_watcher(self, principal, uid):
        while not self.stop_event.is_set():
            proc = mp.Process(target=UserSubscriber, args=(principal, uid, self.stop_event))
            proc.start()
            await sync_to_async(proc.join, thread_sensitive=True)()

    # Start of Channel Layer message handlers
    async def add_user(self, message):
        # {'type': 'add_user', 'principal': '<principal of new user>'}
        # Spawns user process for user if not already running.
        princ = message['principal']
        uid = message['uid']

        if princ not in self.user_tasks:
            self.user_tasks[princ] = asyncio.create_task(self.user_process_watcher(princ, uid))

    async def del_user(self, message):
        # {'type': 'del_user', 'principal': '<principal of deleted user>'}
        # Kills user process for user if running.
        princ = message['principal']
        task = self.user_tasks.pop(princ, None)
        if task:
            task.cancel()
    # End message handlers


class UserSubscriber(_MPDjangoSetupMixin, _ZephyrProcessMixin):
    """Kerberos and zephyr are not particularly threadsafe, so each user
    will have their own process."""

    def __init__(self, principal, uid, stop_event, start=True):
        super().__init__()
        self._principal = principal
        self.uid = uid
        self.stop_event = stop_event
        if start:
            self.start()

    def __str__(self):
        return f'UserSubscriber<{self.principal}>'

    @property
    def groups(self):
        # The _ChannelLayerMixin requires us to define this.
        return [utils.principal_to_user_subscriber_group_name(self.principal)]

    @property
    def principal(self):
        # The _ZephyrProcessMixin requires us to define this.
        return self._principal

    def get_subs_qs(self):
        # The _ZephyrProcessMixin requires us to define this.
        subs_qs = django.apps.apps.get_model('roost_backend', 'Subscription').objects.all()
        subs_qs = subs_qs.filter(user__principal=self.principal, zrecipient=self.principal)
        return subs_qs

    def start(self):
        _LOGGER.debug('%s starting...', self)
        setproctitle.setproctitle(f'roost:{self.principal}')
        self._initialize_memory_ccache()
        async_to_sync(self.run)()

    async def run(self):
        zephyr_task = asyncio.create_task(self.zephyr_handler())
        channel_task = asyncio.create_task(self.channel_layer_handler())
        while self.channel_layer is None:
            await asyncio.sleep(0)
        # Announce our activation.
        _LOGGER.debug('[%s] announcing activation...', self.log_prefix)
        await self.channel_layer.send(utils.principal_to_user_subscriber_announce_channel(self.principal), {
            'type': 'announce_user_subscriber',
            'principal': self.principal,
        })
        _LOGGER.debug('[%s] announced.', self.log_prefix)
        await sync_to_async(self.stop_event.wait, thread_sensitive=True)()
        zephyr_task.cancel()
        channel_task.cancel()
        try:
            await zephyr_task
        except asyncio.CancelledError:
            pass
        try:
            await channel_task
        except asyncio.CancelledError:
            pass

    # Start of Channel Layer message handlers
    async def inject_credentials(self, message):
        await database_sync_to_async(self._add_credential_to_ccache)(message['creds'])

    async def have_valid_credentials(self, message):
        reply_channel = message.pop('_reply_to')
        valid_creds = await sync_to_async(self._have_valid_zephyr_creds)()
        await self.channel_layer.send(reply_channel, {'valid': valid_creds})
    # End message handlers


class ServerSubscriber(_MPDjangoSetupMixin, _ZephyrProcessMixin):
    """Like the UserSubscriber, but for shared subscriptions."""

    def __init__(self, stop_event, start=True):
        super().__init__()
        self.uid = None
        self.stop_event = stop_event
        if start:
            self.start()

    def __str__(self):
        return 'ServerSubscriber'

    # The _ChannelLayerMixin requires us to define this.
    groups = ['ROOST_SERVER_PROCESS']

    @property
    def principal(self):
        # The _ZephyrProcessMixin requires us to define this.
        return None

    @property
    def log_prefix(self):
        return 'ServerSubscriber'

    def get_subs_qs(self):
        # The _ZephyrProcessMixin requires us to define this.
        subs_qs = django.apps.apps.get_model('roost_backend', 'Subscription').objects.all()
        subs_qs = subs_qs.filter(zrecipient='')
        return subs_qs

    def start(self):
        _LOGGER.debug('%s starting...', self)
        setproctitle.setproctitle('roost:server_subscriber')
        utils.kerberos.initialize_memory_ccache_from_client_keytab()
        async_to_sync(self.run)()

    async def run(self):
        zephyr_task = asyncio.create_task(self.zephyr_handler())
        channel_task = asyncio.create_task(self.channel_layer_handler())
        await sync_to_async(self.stop_event.wait, thread_sensitive=True)()
        zephyr_task.cancel()
        channel_task.cancel()
        try:
            await zephyr_task
        except asyncio.CancelledError:
            pass
        try:
            await channel_task
        except asyncio.CancelledError:
            pass
