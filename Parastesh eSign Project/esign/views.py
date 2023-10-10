from .forms import SigningForm, SignUpForm
from .models import Contract

from django.contrib.auth import login , authenticate
from django.contrib.auth.models import Group , User
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required

from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.urls import reverse

import os
import requests
import base64
import math
import jwt
from time import time

from docusign_esign import (
    EnvelopesApi,
    EnvelopeDefinition,
    Signer,
    SignHere,
    Tabs,
    Recipients,
    FullName,
    Date,
    Text
    )
from docusign_esign.models import Document, RecipientViewRequest
from docusign_esign.client.api_client import ApiClient



def signupView(request):
    if request.method=='POST':
        form=SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            username=form.cleaned_data.get('username')
            signup_user=User.objects.get(username=username)
            customer_group=Group.objects.get(name='Customers')
            customer_group.user_set.add(signup_user)
            login(request, signup_user)
    else:
        form=SignUpForm()
    return render(request , 'esign/signup.html' , {'form':form})


def signinView(request):
    if request.method=='POST':
        form=AuthenticationForm(data=request.POST)
        if form.is_valid():
            username=request.POST['username']
            password=request.POST['password']
            user=authenticate(username=username , password=password)
            if user is not None:
                login(request , user)
                return redirect('instantiation_page')
            else:
                return redirect('signup')
    else:
        form=AuthenticationForm()
    return render(request , 'esign/signin.html' , {'form':form})


@login_required
def instantiation_page(request):
    form = SigningForm()
    if request.method == 'POST':
        form = SigningForm(request.POST, request.FILES)
        if form.is_valid():
            signing = form.save()
            signing.save()
            request.session['signing_id'] = signing.id
            return get_consent(request)
    return render(request, 'esign/instantiation_page.html', {'form': form})



# 1 Obtain your OAuth token
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUTHORIZE_URL = 'https://account-d.docusign.com/oauth/auth'
OAUTH_HOST_NAME = 'account-d.docusign.com'

CLIENT_ID = 'b1a7ad61-3be3-49c1-af27-0860d031103b'
CLIENT_SECRET = '0cebed34-5b18-470f-b96b-f40b44d72da5'
ACCOUNT_ID = '4a3f4aee-4db6-455a-8476-7267e9157c59'
USER_ID = '121d10b7-71ac-4bf2-be24-6f312d5d9d3b'

SCOPES = ['signature']

PRIVATE_KEY_PATH = os.path.join(BASE_DIR, 'private_key_file', 'private.key')



# 1-1 Before making any API calls, get user’s consent for the app to impersonate them.
def get_consent(request):
    """Get user consent"""
    consent_url = "{0}?response_type=code&scope={1}&client_id={2}&redirect_uri={3}".format(
        AUTHORIZE_URL,
        SCOPES,
        CLIENT_ID,
        request.build_absolute_uri(reverse('get_access_token'))
        )
    return HttpResponseRedirect(consent_url)



def get_access_token(request):
    # 1-2 Create JWT
    """Request JWT User Token"""
    
    with open(PRIVATE_KEY_PATH, 'rb') as private_key_file:
        private_key = private_key_file.read()

    now = math.floor(time())
    expires_in = 1
    later = now + (expires_in * 10000000)
    claim = {
             "iss": CLIENT_ID,
             "sub": USER_ID,
             "iat": now,
             "exp": later,
             "aud": OAUTH_HOST_NAME,
             "scope": "signature"
            }
    token = jwt.encode(payload=claim, key=private_key, algorithm='RS256')
    url = f"https://{OAUTH_HOST_NAME}/oauth/token"
    # 1-3 Obtain the access token
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    post_params = {"assertion": token, "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer"}

    r = requests.post(url, headers=headers, data=post_params)
    response = r.json()

    request.session['access_token_session'] = response['access_token']

    access_url = "{0}?token={1}".format(
        reverse('get_signing_url'),
        response['access_token']
        )
    
    if not 'error' in response:
        return HttpResponseRedirect(access_url)
    
    return HttpResponse(response['error'])



def signing(request):

    # Form Info
    signing_id = request.session.get('signing_id')
    contract = Contract.objects.get(id=signing_id)
    signer1_name = contract.sender_name
    signer1_email = contract.sender_email
    signer2_email = contract.recipient_email
    signer2_name = contract.recipient_name
    document = contract.document

    if document:
        document_path = os.path.join(BASE_DIR, 'media', str(document))
        with open(document_path, 'rb') as file:
            content_bytes = file.read()
        doc1_b64 = base64.b64encode(content_bytes).decode('ascii')


    access_token = request.session.get('access_token_session')

    # 1-4 Get user's base URI
    """Get User Info method takes the accessToken to retrieve User Account Data."""
    resource_path = '/oauth/userinfo'
    headers = {"Authorization": "Bearer " + access_token}

    r = requests.get("https://" + OAUTH_HOST_NAME + resource_path, headers=headers)
    response = r.json() #it turned a response type file to a dictionary(print if you need)
    
    # 1-5 Use the access token to make an API call
    """API calls requirements"""
    api_client = ApiClient()
    user_info = response
    accounts = user_info['accounts']
    base_path = accounts[0]['base_uri']+f"/restapi"
    api_client.host = base_path
    api_client.set_default_header(
        header_name="Authorization",
        header_value=f"Bearer {access_token}"
        )

    # 2 Create the envelope definition
    """
        Create envelope definition
        Then send an email
        Then pass a url for get_access_token
        And open a sign_completed page
    """

    env = EnvelopeDefinition(
        email_subject = "Please sign this document",
        email_body = "Please sign the document via this signing link"
    )

    document1 = Document(
        document_base64 = doc1_b64, 
        name = 'contract document pdf', 
        file_extension='pdf', 
        document_id= "1"
    )

    env.documents = [document1]

    #signer recipient model
    # signer 1
    signer1 = Signer(
        email=signer1_email,
        name=signer1_name,
        recipient_id="1",
        routing_order="1", #delivery order
    )

    sign_here1 = SignHere(
		document_id='1',
        page_number='1',
        recipient_id='1',
        tab_label='SignHereTab',
        x_position='50',
        y_position='400'
	)

    full_name_tab1 = Text(
		document_id='1',
		page_number='1',
		recipient_id='1',
		tab_label='FullNameTab',
        name='Full Name',
		x_position='50',
        y_position='350',
        height='15',
        width='100'
	)

    date_tab1 = Date(
        document_id='1',
        page_number='1',
        recipient_id='1',
        tab_label='DateSignedTab',
        name='Date Signed',
        x_position='50',
        y_position='375',
        height='15',
        width='100'
    )

    # signer 2
    signer2 = Signer(
        email=signer2_email,
        name=signer2_name,
        recipient_id="2",
        routing_order="2",
    )
    
    sign_here2 = SignHere(
		document_id='1',
        page_number='1',
        recipient_id='2',
        tab_label='SignHereTab',
        x_position='400',
        y_position='400'
	)

    full_name_tab2 = FullName(
		document_id='1',
		page_number='1',
		recipient_id='2',
		tab_label='FullNameTab',
        name='Full Name',
		x_position='400',
        y_position='350',
        height='15',
        width='100'
	)

    date_tab2 = Date(
		document_id='1',
		page_number='1',
		recipient_id='2',
		tab_label='DateSignedTab',
        name='Date Signed',
		x_position='400',
        y_position='375',
        height='15',
        width='100'
	)

    signer1.tabs = Tabs(sign_here_tabs=[sign_here1], text_tabs=[full_name_tab1], date_tabs=[date_tab1])
    signer2.tabs = Tabs(sign_here_tabs=[sign_here2], text_tabs=[full_name_tab2], date_tabs=[date_tab2])

    recipients = Recipients(
        signers=[signer1, signer2],
        )
    env.recipients = recipients
    #Request the envelope. 'status' = to be sent , 'created' = to be drafted
    env.status = "sent"

    # 3 Create and send the envelope
    envelope_api = EnvelopesApi(api_client)
    results = envelope_api.create_envelope(ACCOUNT_ID, envelope_definition=env)
    envelope_id = results.envelope_id
    recipient_view_request = RecipientViewRequest(
        authentication_method='None',
        recipient_id='1',
        return_url=request.build_absolute_uri(reverse('sign_completed')),
        user_name=signer1_name,
        email=signer1_email
    )

    results = envelope_api.create_recipient_view(ACCOUNT_ID, envelope_id, recipient_view_request=recipient_view_request)

    return HttpResponseRedirect(results.url)



def sign_completed(request):
    return render(request, 'esign/sign_completed.html')



