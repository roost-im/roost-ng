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
from django.core.exceptions import AppRegistryNotReady
import setproctitle

from . import utils

_LOGGER = logging.getLogger(__name__)


class _MPDjangoSetupMixin:
    """This mixin runs django.setup() on __init__. It is to be used by classes that are
    mp.Process targets.
    """
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
    want to stop. This may be worth extracting to a utility module.
    """
    def __init__(self):
        super().__init__()
        self.channel_layer = None
        self.channel_name = None
        self.channel_receive = None

    @property
    def groups(self):
        raise NotImplementedError()

    async def channel_layer_handler(self):
        try:
            # Initialize channel layer.
            self.channel_layer = channels.layers.get_channel_layer()
            self.channel_name = await self.channel_layer.new_channel()
            self.channel_receive = functools.partial(self.channel_layer.receive, self.channel_name)

            # Subscribe to groups
            for group_name in self.groups:
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


class _ZephyrProcessMixin:
    def __init__(self):
        super().__init__()
        # Event to indicate that zephyr has been initialized
        self.z_initialized = mp.Event()
        # Lock to be used around non-threadsafe bits of libzephyr.
        self.zephyr_lock = mp.Lock()

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
        self.resync_subs()

    @staticmethod
    def _have_valid_zephyr_creds():
        return utils.kerberos.have_valid_zephyr_creds(_zephyr.realm())

    def zinit(self):
        if self.z_initialized.is_set():
            return

        _LOGGER.debug('[%s] zinit...', self.log_prefix)
        zephyr.init()
        self.z_initialized.set()

    def resync_subs(self):
        if not self.z_initialized.is_set():
            return

        _LOGGER.debug('[%s] zinit done, subscribing...', self.log_prefix)
        zsub = zephyr.Subscriptions()
        if self.principal is not None:
            # Don't unsub when destroying the Subscriptions object so we can use dump/loadSession.
            # Only relevant for user process (with has principal)
            zsub.cleanup = False
        zsub.resync()

        subs_qs = self.get_subs_qs()

        for sub in set(subs_qs.values_list('class_key', 'instance_key', 'zrecipient')):
            _LOGGER.debug(' %s', sub)
            with self.zephyr_lock:
                zsub.add(sub)

        _LOGGER.debug('[%s] %s', self.log_prefix, zsub)
        # TODO: check for extra subs and get rid of them.

        _LOGGER.debug('[%s] subscribing done.', self.log_prefix)

    async def zephyr_handler(self):
        _LOGGER.debug('[%s] zephyr handler started.', self.log_prefix)
        try:
            await self.load_user_data()

            # No need to start looking for incoming messages until we have initialized zephyr.
            await sync_to_async(self.z_initialized.wait)()
            _LOGGER.debug('[%s] zephyr handler now receiving...', self.log_prefix)
            while True:
                with self.zephyr_lock:
                    # Since we're calling this non-blocking, not bothering to wrap and await.
                    notice = zephyr.receive()

                if notice is None:
                    _LOGGER.debug('[%s] wating on FD...', self.log_prefix)
                    # ZGetFD() returns a global variable, does not do other things with the
                    # library.  No lock required.
                    await sync_to_async(select.select)([_zephyr.getFD()], [], [])
                    _LOGGER.debug('[%s] data on FD...', self.log_prefix)
                    continue

                _LOGGER.debug('%s, %s', notice, notice.kind)

                if notice.kind in (zephyr.ZNotice.Kind.servnak,
                                   zephyr.ZNotice.Kind.servack,
                                   zephyr.ZNotice.Kind.hmack):
                    # It would be cool to send ACK/NAKs to the user,
                    # but it is not clear what roost actually sent back,
                    # and no client actually did more than log it.
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
            await self.save_user_data()
        finally:
            _LOGGER.debug('[%s] zephyr handler done.', self.log_prefix)

    @database_sync_to_async
    def load_user_data(self):
        if self.principal is None:
            # Nothing to do for server process
            return
        obj = django.apps.apps.get_model('roost_backend', 'UserProcessState').objects.filter(
            user__principal=self.principal).first()
        if obj:
            data = json.loads(obj.data)
            if 'session_data' in data:
                # If we have session data, reinitialize libzephyr with it.
                session_data = base64.b64decode(data['session_data'])
                with self.zephyr_lock:
                    zephyr.init(session_data=session_data)
                self.z_initialized.set()
            if 'kerberos_data' in data and data['kerberos_data']:
                # If we have credentials, inject them into our ccache.
                # This will also initialize libzephyr if there was no session data.
                # TODO: filter out expired credentials?
                # TODO: support importing a list of credentials.
                self._add_credential_to_ccache(data['kerberos_data'])
            # obj.delete()

    @database_sync_to_async
    def save_user_data(self):
        if self.principal is None:
            if not self._have_valid_zephyr_creds():
                utils.kerberos.initialize_memory_ccache_from_client_keytab()
            with self.zephyr_lock:
                _zephyr.cancelSubs()
            # Nothing to do for server process
            return
        # TODO: support exporting multiple credentials.
        if not self.z_initialized.is_set():
            return

        _LOGGER.debug('[%s] saving user data...', self.log_prefix)

        ups = django.apps.apps.get_model('roost_backend', 'UserProcessState')
        with self.zephyr_lock:
            zephyr_session = _zephyr.dumpSession()
            zephyr_realm = _zephyr.realm()
        data = {
            'session_data': base64.b64encode(zephyr_session).decode('ascii'),
            'kerberos_data': underscoreize(utils.kerberos.get_zephyr_creds_dict(zephyr_realm)),
        }

        try:
            with transaction.atomic():
                ups.objects.update_or_create(user_id=self.uid, defaults={
                    'data': json.dumps(data),
                })
            _LOGGER.debug('[%s] saving user data done.', self.log_prefix)
        except IntegrityError:
            _LOGGER.debug('[%s] saving user data failed; user deleted?', self.log_prefix)


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
        if self._proc and self._proc.is_alive():
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
    groups = ['UP_OVERSEER']

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


class UserProcess(_MPDjangoSetupMixin, _ChannelLayerMixin):
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
    def groups(self):
        # The _ChannelLayerMixin requires us to define this.
        return [utils.principal_to_user_process_group_name(self.principal)]

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
