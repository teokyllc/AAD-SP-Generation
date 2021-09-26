from flask import Flask, jsonify, request, render_template
import functions as f

app = Flask(__name__)
app.config["DEBUG"] = True

@app.route("/CreateSP", methods=["POST"])
def create_sp():
    app_name = str(request.json.get('app_name', ''))
    sp_secrets = f.get_vault_secret("/v1/secrets/data/azure")
    client_id = sp_secrets["sp-creator-client-id"]
    client_secret = sp_secrets["sp-creator-client-secret"]
    new_sp = f.new_aad_sp(client_id, client_secret, app_name)
    service_principal_name = new_sp["appDisplayName"]
    aad_app_id = new_sp["appId"]
    sp_client_id = new_sp["id"]
    sp_client_secret_data = f.create_aad_sp_credential(sp_client_id)
    sp_client_secret = sp_client_secret_data["secretText"]
    sp_client_secret_key_id = sp_client_secret_data["keyId"]
    f.write_vault_secret(service_principal_name, aad_app_id, sp_client_id, sp_client_secret, sp_client_secret_key_id)
    return new_sp

app.run(host='0.0.0.0')
