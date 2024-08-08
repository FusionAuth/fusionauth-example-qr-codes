#tag::baseApplication[]
import json
import math
from os import environ as env
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request, make_response
import qrcode
import qrcode.image.svg
import requests
import threading
import time
from fusionauth.fusionauth_client import FusionAuthClient


ACCESS_TOKEN_COOKIE_NAME = "cb_access_token"
REFRESH_TOKEN_COOKIE_NAME = "cb_refresh_token"
USERINFO_COOKIE_NAME = "cb_userinfo"

ENV_FILE = find_dotenv('.env-flask')
if ENV_FILE:
  load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

#TODO
# need to finish up device grant when we have ngrok
# need to poll 
# need to have response that returns json redirect when the device grant is completed
# bounce to another flask route, which sets cookies, and then bounces to /
# test that the polling thread waits


oauth = OAuth(app)

oauth.register(
  "FusionAuth",
  client_id=env.get("CLIENT_ID"),
  client_secret=env.get("CLIENT_SECRET"),
  client_kwargs={
  ##  'verify': False,
    "scope": "openid email profile offline_access",
    'code_challenge_method': 'S256' # This enables PKCE
  },
  server_metadata_url=f'{env.get("ISSUER")}/.well-known/openid-configuration'
)

oauth.register(
  "FusionAuthMagicLink",
  client_id=env.get("CLIENT_ID"),
  client_secret=env.get("CLIENT_SECRET"),
  client_kwargs={
  ##  'verify': False,
    "scope": "openid email profile offline_access",
    'code_challenge_method': 'S256' # This enables PKCE
  },
  server_metadata_url=f'{env.get("ISSUER")}/.well-known/openid-configuration'
)

client = FusionAuthClient(env.get("API_KEY"), env.get("ISSUER"))

polling_data = {'content': '', 'code': '', 'interval': 5}
polling_lock = threading.Lock()
stop_event = threading.Event()
polling_thread = None

def poll_url(stop_event):
    print("starting polling")
    while not stop_event.is_set():
        with polling_lock:
            interval = polling_data['interval']
        try:
            print("in polling loop")
            print(polling_data['code'])
            data = {
              "client_id": env.get("CLIENT_ID"),
              "device_code": polling_data['code'],
              "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
            }

            device_token_url = env.get("ISSUER")+'/oauth2/token'
            print("polling token endpoint")
            print(device_token_url)
            response = requests.post(device_token_url, headers={},data=data)
            print(response.json())
            if response.status_code == 200:
              print("request posted")
              polling_data['content'] = response.json()
        except Exception as e:
            polling_data['content'] = f"Error: {e}"
        stop_event.wait(interval)


def get_logout_url():
  return env.get("ISSUER") + "/oauth2/logout?" + urlencode({"client_id": env.get("CLIENT_ID")},quote_via=quote_plus)

#tag::homeRoute[]
@app.route("/")
def home():
  if request.cookies.get(ACCESS_TOKEN_COOKIE_NAME, None) is not None:
    # In a real application, we would validate the token signature and expiration
    return redirect("/account")

  return render_template("home.html")
#end::homeRoute[]

@app.route("/device_grant_finished")
def device_grant_finished():
    print("device_grant_finished")
    content = ""
    with polling_lock:
      content = polling_data['content']
    try:
      if content != "":
        print("returning reload signal, stopping polling")
        stop_event.set() 
        if polling_thread != None:
          polling_thread.join()  # Wait for the thread to finish
        else:
          print("polling thread none?")
        return json.loads('{"reload":"true"}'), 200
    except Exception as e:
      content = ""


    return json.loads('{}'), 200

@app.route("/reload")
def reload():
    print("reload")
    content = ""
    with polling_lock:
      content = polling_data['content']
    try:
      # set the cookies, then refresh to /
      token = content
      userinfo = client.retrieve_user_info_from_access_token(token["access_token"]).success_response
      print(userinfo)
      token["userinfo"] = userinfo

      resp = make_response(redirect("/"))
      return process_token(token, resp)

    except Exception as e:
      content = ""
    # something has gone awry, but lets just send the user to / anyway. they won't be logged in
    return make_response(redirect("/"))

#tag::loginRoute[]
@app.route("/login")
def login():
  return oauth.FusionAuth.authorize_redirect(
    redirect_uri=url_for("callback", _scheme='https', _external=True)
  )
#end::loginRoute[]


#tag::callbackRoute[]
@app.route("/callback")
def callback():
  token = oauth.FusionAuth.authorize_access_token()
  resp = make_response(redirect("/"))

  return process_token(token, resp)

#end::callbackRoute[]

@app.route("/callbackMagic")
def callbackMagic():
  token = oauth.FusionAuthMagicLink.authorize_access_token()
  resp = make_response(redirect("/"))

  return process_token(token, resp)


#tag::logoutRoute[]
@app.route("/logout")
def logout():
  session.clear()

  resp = make_response(redirect("/"))
  resp.delete_cookie(ACCESS_TOKEN_COOKIE_NAME)
  resp.delete_cookie(REFRESH_TOKEN_COOKIE_NAME)
  resp.delete_cookie(USERINFO_COOKIE_NAME)

  return resp
#end::logoutRoute[]


#
# This is the logged in Account page.
#
#tag::accountRoute[]
@app.route("/account")
def account():
  access_token = request.cookies.get(ACCESS_TOKEN_COOKIE_NAME, None)
  refresh_token = request.cookies.get(REFRESH_TOKEN_COOKIE_NAME, None)

  if access_token is None:
    return redirect(get_logout_url())

  return render_template(
    "account.html",
    session=json.loads(request.cookies.get(USERINFO_COOKIE_NAME, None)),
    logoutUrl=get_logout_url())
#end::accountRoute[]

#
# This is the page displayed when you are logged out on your laptop but want to login with a QR code read by the phone
#
@app.route("/logged-out-qr-login")
def logged_out_qr_login():
  qr = qrcode.QRCode(image_factory=qrcode.image.svg.SvgPathImage)

  device_start_url = env.get("ISSUER") + '/oauth2/device_authorize'
  data = { 
    "client_id": env.get("CLIENT_ID"),
    "scope": "openid email profile offline_access",
  }
  response = requests.post(device_start_url,headers={},data=data)
  verification_url_complete = response.json()['verification_uri_complete']
  print(verification_url_complete)
  device_code = response.json()['device_code']
  print(device_code)

  with polling_lock:
    polling_data['code'] = device_code
  try:
    print("in lock")
    print(polling_data['code'])
  except Exception as e:
    print(f"Error: {e}")

  qr.add_data(verification_url_complete)
  qr.make(fit=True)
  qrimg = qr.make_image().to_string(encoding='unicode')
  return render_template(
    "logged-out-qr-login.html",
    qrimg=qrimg)

#
# This is the page displayed when you are logged in on your laptop but want to login using a QR code on your phone with device grant
#
@app.route("/logged-in-qr-login")
def logged_in_qr_login():
  return render_template(
    "logged-out-qr-login.html"
    )
#
# This is the page displayed when you are logged in on your laptop but want to login using a QR code on your phone with magic link
#
@app.route("/logged-in-qr-login-magic-link")
def logged_in_qr_login_magic_link():
  # this has the CSRF issue with the authlib. Depending on your library, you may be able to turn off CSRF protection.

  access_token = request.cookies.get(ACCESS_TOKEN_COOKIE_NAME, None)
  refresh_token = request.cookies.get(REFRESH_TOKEN_COOKIE_NAME, None)

  user = session["user"]

  if access_token is None:
    return redirect(get_logout_url())

  print(session.keys())
  
  st = 'abc'
  state = {}
  s = oauth.FusionAuthMagicLink.create_authorization_url(
    redirect_uri=url_for("callback", _scheme='https', _external=True)
  )
  print(s)
  state['redirect_uri'] = url_for("callbackMagic", _scheme='https', _external=True)
  state['client_id'] = env.get("CLIENT_ID")
  state['response_type'] = 'code'
  state['state'] = st
  passwordless_request = {
    'loginId': user["email"],
    'applicationId': env.get("CLIENT_ID"),
    'state': state
  }

  response = client.start_passwordless_login(passwordless_request)
  if response.error_response:
    print("in error")
    print(response.error_response)
  response_json = response.success_response
  code = response_json["code"]

  qr = qrcode.QRCode(image_factory=qrcode.image.svg.SvgPathImage)

  login_start_url = env.get("ISSUER") + '/oauth2/passwordless/' +code+ '?postMethod=true'

  qr.add_data(login_start_url)
  qr.make(fit=True)
  qrimg = qr.make_image().to_string(encoding='unicode')
  return render_template(
    "logged-in-qr-login-magic.html",
    qrimg=qrimg)


#
# Takes a dollar amount and converts it to change
#
#tag::makeChangeRoute[]
@app.route("/make-change", methods=['GET', 'POST'])
def make_change():
  access_token = request.cookies.get(ACCESS_TOKEN_COOKIE_NAME, None)
  refresh_token = request.cookies.get(REFRESH_TOKEN_COOKIE_NAME, None)

  if access_token is None:
    return redirect(get_logout_url())

  change = {
    "error": None
  }

  if request.method == 'POST':
    dollar_amt_param = request.form["amount"]

    try:
      if dollar_amt_param:
        dollar_amt = float(dollar_amt_param)

        nickels = int(dollar_amt / 0.05)
        pennies = math.ceil((dollar_amt - (0.05 * nickels)) / 0.01)

        change["total"] = format(dollar_amt, ",.2f")
        change["nickels"] = format(nickels, ",d")
        change["pennies"] = format(pennies, ",d")

    except ValueError:
      change["error"] = "Please enter a dollar amount"

  return render_template(
    "make-change.html",
    session=json.loads(request.cookies.get(USERINFO_COOKIE_NAME, None)),
    change=change,
    logoutUrl=get_logout_url())
#end::makeChangeRoute[]


def process_token(token, resp):

  resp.set_cookie(ACCESS_TOKEN_COOKIE_NAME, token["access_token"], max_age=token["expires_in"], httponly=True, samesite="Lax")
  resp.set_cookie(REFRESH_TOKEN_COOKIE_NAME, token["refresh_token"], max_age=token["expires_in"], httponly=True, samesite="Lax")
  resp.set_cookie(USERINFO_COOKIE_NAME, json.dumps(token["userinfo"]), max_age=token["expires_in"], httponly=False, samesite="Lax")
  session["user"] = token["userinfo"]

  return resp

if __name__ == "__main__":
  polling_thread = threading.Thread(target=poll_url, args=(stop_event,))
  polling_thread.daemon = True
  polling_thread.start()
  app.run(host="0.0.0.0", port=env.get("PORT", 5000))

