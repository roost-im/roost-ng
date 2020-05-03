from django.urls import path

from . import views

urlpatterns = [
    # Roost's API did not have trailing slashes.
    path('auth', views.AuthView.as_view()),
    path('ping', views.PingView.as_view()),
    path('info', views.InfoView.as_view()),
    path('subscriptions', views.SubscriptionView.as_view()),
    path('subscribe', views.SubscribeView.as_view()),
    path('unsubscribe', views.UnsubscribeView.as_view()),
    path('messages', views.MessageView.as_view()),
    path('bytime', views.MessageByTimeView.as_view()),
    path('zephyrcreds', views.ZephyrCredsView.as_view()),
    path('zwrite', views.ZWriteView.as_view()),
]
