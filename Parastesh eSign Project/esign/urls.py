from django.urls import path
from esign import views

urlpatterns = [
    path('instantiation_page/', views.instantiation_page , name='instantiation_page'),
    path('' , views.signupView , name='signup'),
    path('signin/' , views.signinView , name='signin'),
    path('get_access_token/', views.get_access_token, name='get_access_token'),
    path('get_signing_url/', views.signing, name='get_signing_url'),
    path('sign_completed/', views.sign_completed, name='sign_completed'),
    path('get_access_code/', views.get_consent, name='get_consent'),
]
