import functools

from django.db import transaction
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from . import models, serializers, utils


@receiver(post_save, sender=models.Message)
def message_post_processing(sender, instance, created, **_kwargs):
    # pylint: disable=unused-argument
    if not created:
        return
    users = []
    if instance.is_personal:
        if instance.is_outgoing:
            users.append(models.User.objects.get(principal=instance.sender))
        else:
            users.append(models.User.objects.get(principal=instance.recipient))
    elif not instance.is_outgoing:
        users.extend(sub.user for sub in
                     models.Subscription.objects.filter(
                         class_key=instance.class_key,
                         instance_key__in=(instance.instance_key, '*'),
                         zrecipient=instance.recipient))

    if users:
        instance.users.add(*users)
        payload = serializers.MessageSerializer(instance).data
        for user in users:
            user.send_to_user_sockets({
                'type': 'incoming_message',
                'message': {
                    'id': instance.id,
                    'payload': payload,
                }
            })


@receiver(post_save, sender=models.Subscription)
def resync_subscriber_on_subscription_save(sender, instance, created, **_kwargs):
    # pylint: disable=unused-argument
    if not created:
        return

    user = instance.user
    group = 'ROOST_SERVER_PROCESS'
    if instance.zrecipient == user.principal:
        # personal; send to user process
        group = utils.principal_to_user_subscriber_group_name(user.principal)

    transaction.on_commit(functools.partial(
        utils.send_to_group,
        group,
        {'type': 'resync_subscriptions'}))


@receiver(post_delete, sender=models.Subscription)
def resync_subscriber_on_subscription_delete(sender, instance, **_kwargs):
    # pylint: disable=unused-argument
    user = instance.user
    if not user:
        return

    group = 'ROOST_SERVER_PROCESS'
    if instance.zrecipient == user.principal:
        # personal; send to user process
        group = utils.principal_to_user_subscriber_group_name(user.principal)

    transaction.on_commit(functools.partial(
        utils.send_to_group,
        group,
        {'type': 'resync_subscriptions'}))


@receiver(post_save, sender=models.User)
def start_new_user_subscriber(sender, instance, created, **_kwargs):
    # pylint: disable=unused-argument
    if created:
        utils.send_to_group('OVERSEER', {
            'type': 'add_user',
            'principal': instance.principal,
        })


@receiver(post_delete, sender=models.User)
def resync_subscriber_on_user_delete(sender, instance, **_kwargs):
    # pylint: disable=unused-argument
    utils.send_to_group('OVERSEER', {
        'type': 'del_user',
        'principal': instance.principal,
    })
