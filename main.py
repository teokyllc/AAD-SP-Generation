from flask import Flask, jsonify, request, render_template
import functions as f

app = Flask(__name__)
app.config["DEBUG"] = True

@app.route("/HealthCheck", methods=["GET"])
def health_check():
    return "Works"

@app.route("/CreateSP", methods=["POST"])
def create_sp():
    app_name = str(request.json.get('app_name', ''))
    sp_secrets = f.get_vault_secret("/v1/secrets/data/azure")
    client_id = sp_secrets["sp-creator-client-id"]
    client_secret = sp_secrets["sp-creator-client-secret"]
    new_sp = f.new_aad_sp(client_id, client_secret, app_name)
    return new_sp, 200

app.run(host='0.0.0.0')
