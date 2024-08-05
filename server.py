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

oauth = OAuth(app)

oauth.register(
  "FusionAuth",
  client_id=env.get("CLIENT_ID"),
  client_secret=env.get("CLIENT_SECRET"),
  client_kwargs={
    "scope": "openid email profile offline_access",
    'code_challenge_method': 'S256' # This enables PKCE
  },
  server_metadata_url=f'{env.get("ISSUER")}/.well-known/openid-configuration'
)

client = FusionAuthClient(env.get("API_KEY"), env.get("ISSUER"))

polling_data = {'content': '', 'url': 'https://api.example.com/data', 'interval': 10}
polling_lock = threading.Lock()

def poll_url():
    while True:
        with polling_lock:
            interval = polling_data['interval']
        try:
            token_url = env.get("ISSUER")
            data = {
              "client_id": env.get("CLIENT_ID"),
              "grant_type": "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
 
            }

            response = requests.get('http://localhost:9011/oauth2/token')
            if response.status_code == 200:
              print("request received")
              polling_data['content'] = response.text
        except Exception as e:
            polling_data['content'] = f"Error: {e}"
        time.sleep(interval)


if __name__ == "__main__":
  polling_thread = threading.Thread(target=poll_url, daemon=True)
  polling_thread.start()
  app.run(host="0.0.0.0", port=env.get("PORT", 5000))

def get_logout_url():
  return env.get("ISSUER") + "/oauth2/logout?" + urlencode({"client_id": env.get("CLIENT_ID")},quote_via=quote_plus)
#end::baseApplication[]


#tag::homeRoute[]
@app.route("/")
def home():
  if request.cookies.get(ACCESS_TOKEN_COOKIE_NAME, None) is not None:
    # In a real application, we would validate the token signature and expiration
    return redirect("/account")

  return render_template("home.html")
#end::homeRoute[]

@app.route("/device_grant_data")
def device_grant_data():
    content = "n/a"
    with polling_lock:
        content = polling_data['content']
    print(content)
    return ""
#end::homeRoute[]


#tag::loginRoute[]
@app.route("/login")
def login():
  return oauth.FusionAuth.authorize_redirect(
    redirect_uri=url_for("callback", _external=True)
  )
#end::loginRoute[]


#tag::callbackRoute[]
@app.route("/callback")
def callback():
  token = oauth.FusionAuth.authorize_access_token()

  resp = make_response(redirect("/"))

  resp.set_cookie(ACCESS_TOKEN_COOKIE_NAME, token["access_token"], max_age=token["expires_in"], httponly=True, samesite="Lax")
  resp.set_cookie(REFRESH_TOKEN_COOKIE_NAME, token["refresh_token"], max_age=token["expires_in"], httponly=True, samesite="Lax")
  resp.set_cookie(USERINFO_COOKIE_NAME, json.dumps(token["userinfo"]), max_age=token["expires_in"], httponly=False, samesite="Lax")
  session["user"] = token["userinfo"]

  return resp
#end::callbackRoute[]


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
  data = { "client_id": env.get("CLIENT_ID") }
  r = requests.post(device_start_url,headers={},data=data)
  verification_url_complete = r.json()['verification_uri_complete']
  qr.add_data(verification_url_complete)
  qr.make(fit=True)
  qrimg = qr.make_image(attrib={'class': 'some-css-class'}).to_string(encoding='unicode')
  return render_template(
    "logged-out-qr-login.html",
    qrimg=qrimg)

#
# This is the page displayed when you are logged in on your laptop but want to login using a QR code on your phone
#
@app.route("/logged-in-qr-login")
def logged_in_qr_login():
  access_token = request.cookies.get(ACCESS_TOKEN_COOKIE_NAME, None)
  refresh_token = request.cookies.get(REFRESH_TOKEN_COOKIE_NAME, None)

  user = session["user"]

  if access_token is None:
    return redirect(get_logout_url())

  passwordless_request = {
    'loginId': user["email"],
    'applicationId': env.get("CLIENT_ID")
  }

  response = client.start_passwordless_login(passwordless_request)
  if response.error_response:
    print("in error")
    print(response.error_response)
  response_json = response.success_response
  code = response_json["code"]

  qr = qrcode.QRCode(image_factory=qrcode.image.svg.SvgPathImage)

  login_start_url = env.get("ISSUER") + '/oauth2/passwordless/' +code+ ' ?postMethod=true'

  qr.add_data(login_start_url)
  qr.make(fit=True)
  qrimg = qr.make_image(attrib={'class': 'some-css-class'}).to_string(encoding='unicode')
  return render_template(
    "logged-in-qr-login.html",
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
