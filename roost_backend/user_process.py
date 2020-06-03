import asyncio
import ctypes
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

import contrib.roost_python.krb5 as k5
import contrib.roost_python.krb5_ctypes as kc

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
        setproctitle.setproctitle(f'roost:OVERSEER')
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
        # Repoint to a new, in-memory credential cache.
        os.environ['KRB5CCNAME'] = 'MEMORY:'
        ctx = k5.Context()
        ccache = ctx.cc_default()
        ccache.init_name(self.principal)

    @staticmethod
    def _add_credential_to_ccache(creds):
        # pylint: disable=protected-access, too-many-locals
        # all this should be abstracted away somewhere else.
        # This may be leaky. Consider kdestroy/re-init/re-ping zephyr servers.
        def json_name_bits_to_princ(ctx, realm, name):
            principal = ctx.build_principal(realm, name['name_string'])
            principal._handle.contents.type = name['name_type']
            return principal

        def flags_to_int(flags):
            assert len(flags) == 32
            assert set(flags).issubset({0, 1})
            ret = 0
            for flag in flags:
                ret = (ret << 1) | flag
            return ret

        ctx = k5.Context()
        ccache = ctx.cc_default()
        kcreds = kc.krb5_creds()
        kcreds.magic = -1760647408  # KV5M_PRINCIPAL

        # Extract and massage the principals
        server = json_name_bits_to_princ(ctx, creds['srealm'], creds['sname'])
        client = json_name_bits_to_princ(ctx, creds['crealm'], creds['cname'])
        tkt_server = json_name_bits_to_princ(ctx,
                                             creds['ticket']['realm'],
                                             creds['ticket']['sname'])
        kcreds.client = client._handle
        kcreds.server = server._handle

        # Prep the keyblock
        p_keyblock = kc.krb5_keyblock_ptr()
        key = creds['key']
        keydata = key['keyvalue']
        kc.krb5_init_keyblock(ctx._handle, key['keytype'], len(keydata), ctypes.byref(p_keyblock))
        ctypes.memmove(p_keyblock.contents.contents, keydata, len(keydata))
        kcreds.keyblock = p_keyblock.contents

        # set the times
        kcreds.times.authtime = creds['authtime'] // 1000
        kcreds.times.starttime = creds['starttime'] // 1000
        kcreds.times.endtime = creds['endtime'] // 1000
        kcreds.times.renew_till = creds['renew_till'] // 1000
        kcreds.is_skey = False

        # This makes roost's python sad. Add a null check there before dereferencing.
        # Also, we're ignoring any addresses that may be in the tickets. Fix that.
        # kcreds.addresses = ctypes.POINTER(krb5_address_ptr)()

        # Parse the flags back into an int
        kcreds.ticket_flags = flags_to_int(creds['flags'])
        # Create a krb5_ticket...
        jtkt = creds['ticket']
        ktkt = kc.krb5_ticket()
        ktkt.magic = -1760647411  # KV5M_TICKET
        ktkt.server = tkt_server._handle
        ktkt.enc_part = kc.krb5_enc_data()
        ktkt.enc_part.magic = -1760647418  # KV5M_ENC_DATA
        ktkt.enc_part.enctype = jtkt['enc_part']['etype']
        ktkt.enc_part.kvno = jtkt['enc_part']['kvno']
        ktkt.enc_part.ciphertext = kc.krb5_data()
        ktkt.enc_part.ciphertext.magic = -1760647422  # KV5M_DATA
        tkt_ciphertext = jtkt['enc_part']['cipher']
        ktkt.enc_part.ciphertext.length = len(tkt_ciphertext)
        ktkt.enc_part.ciphertext.data = (ctypes.c_char * len(tkt_ciphertext))(*tkt_ciphertext)

        # ...and be sad that we have to reach into krb5 internals to put it into the krb5_creds struct.
        p_tkt_data = kc.krb5_data_ptr()
        k5.encode_krb5_ticket(ctypes.byref(ktkt), ctypes.byref(p_tkt_data))
        kcreds.ticket = p_tkt_data.contents

        # and finally, store the new cred in the ccache.
        k5.krb5_cc_store_cred(ctx._handle, ccache._handle, kcreds)

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
