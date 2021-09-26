import requests
import msal
import json
import os
import jwt
from datetime import datetime

global tls_verify, aad_tenant, graph_uri
tls_verify = False
aad_tenant = "5ad90dc5-b02a-4f06-8f90-14d6bccf9282"
graph_uri = "https://graph.microsoft.com"

def get_vault_secret(path):
    vault_addr = "https://vault.teokyllc.internal:8200" + path
    r = requests.get(vault_addr, headers={"X-Vault-Token":os.getenv("VAULT_TOKEN")}, verify=tls_verify)
    to_json = json.loads(str(r.text))
    return to_json["data"]["data"]

def msgraph_auth(client_id, client_secret):
    global accessToken
    global requestHeaders
    global tokenExpiry
    tenantID = aad_tenant
    authority = 'https://login.microsoftonline.com/' + tenantID
    scope = ['https://graph.microsoft.com/.default']
    app = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential = client_secret)
    try:
        accessToken = app.acquire_token_silent(scope, account=None)
        if not accessToken:
            try:
                accessToken = app.acquire_token_for_client(scopes=scope)
                if accessToken['access_token']:
                    print('New access token retreived....')
                    requestHeaders = {'Authorization': 'Bearer ' + accessToken['access_token'], 'Content-type': 'application/json'}
                else:
                    print('Error aquiring authorization token. Check your tenantID, clientID and clientSecret.')
            except:
                pass 
        else:
            print('Token retreived from MSAL Cache....')

        decodedAccessToken = jwt.decode(accessToken['access_token'], verify=False)
        accessTokenFormatted = json.dumps(decodedAccessToken, indent=2)
        print('Decoded Access Token')
        print(accessTokenFormatted)

        # Token Expiry
        tokenExpiry = datetime.fromtimestamp(int(decodedAccessToken['exp']))
        print('Token Expires at: ' + str(tokenExpiry))
        return
    except Exception as err:
        print(err)

def msgraph_get_request(resource,requestHeaders):
    results = requests.get(resource, headers=requestHeaders).json()
    return results

def msgraph_post_request(resource, requestHeaders, payload):
    results = requests.post(resource, headers=requestHeaders, json=payload).json()
    return results

def get_sp(sp_id):
    url = graph_uri + "/v1.0/servicePrincipals/" + sp_id
    sp = msgraph_get_request(url, requestHeaders)
    return sp

def create_aad_app(app_name):
    url = graph_uri + "/v1.0/applications"
    payload = {"displayName": app_name}
    new_app = msgraph_post_request(url, requestHeaders, payload)
    return new_app["appId"]

def create_aad_sp(app_id):
    url = graph_uri + "/v1.0/servicePrincipals"
    payload = {"appId": app_id}
    new_sp = msgraph_post_request(url, requestHeaders, payload)
    return new_sp["id"]

def create_aad_sp_credential(app_id):
    url = graph_uri + "/beta/servicePrincipals/" + app_id + "/addPassword"
    payload = {"passwordCredential": {"displayName": "generated"}}
    new_credential = msgraph_post_request(url, requestHeaders, payload)
    return new_credential

def new_aad_sp(client_id, client_secret, app_name):
    msgraph_auth(client_id, client_secret)
    new_app = create_aad_app(app_name)
    new_sp = create_aad_sp(new_app)
    create_aad_sp_credential(new_sp)
    return get_sp(new_sp)
