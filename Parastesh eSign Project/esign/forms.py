from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Contract

class SigningForm(forms.ModelForm):
    class Meta:
        model = Contract
        fields = "__all__"


class SignUpForm(UserCreationForm):
    class Meta:
        model=User
        fields=('username' , 'password1' , 'password2')
