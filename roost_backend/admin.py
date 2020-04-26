from django.contrib import admin

from roost_backend import models

# Register your models here.


@admin.decorators.register(models.User)
class UserAdmin(admin.ModelAdmin):
    pass


@admin.decorators.register(models.Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    pass


@admin.decorators.register(models.Message)
class MessageAdmin(admin.ModelAdmin):
    pass
